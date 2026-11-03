"""File intake (T13): text is extracted locally, metadata is never read, and the filename is scanned.

Fails closed: formats we cannot read as text (images, scans, unknown binaries) are refused, not guessed.
"""
import io
import re
import zipfile
from dataclasses import dataclass
from typing import List

from . import detect as D
from . import finance

MAX_BYTES = 5 * 1024 * 1024
MAX_XML_BYTES = 20 * 1024 * 1024  # a small zip can inflate hugely
MAX_PDF_PAGES = 500
MAX_TEXT_CHARS = 8_000_000
TEXT_SUFFIXES = (".txt", ".md", ".csv", ".tsv", ".json", ".log")


class Unreadable(RuntimeError):
    pass


@dataclass
class Document:
    name: str  # safe display name: personal detail in the original filename is dropped
    text: str
    notes: List[str]
    financial: str = ""  # why it was recognised as a financial document ("" = not); decided at intake, before any chunking
    summary: str = ""  # the only form of a financial document that may leave this computer (finance.sanitize); "" = none could be made
    source: str = ""  # for a retrieved passage: the file it came from


def safe_name(name: str) -> (str, bool):
    base = re.split(r"[\\/]", name)[-1]
    suffix = "." + base.rsplit(".", 1)[-1].lower() if "." in base else ""
    stem = base[: len(base) - len(suffix)]
    probe = re.sub(r"[_\-.]+", " ", stem)
    hit = D.detect(stem, use_presidio=False).sensitive or D.detect(probe).sensitive
    if hit:
        return f"document{suffix}", True
    return base, False


def _member(z: zipfile.ZipFile, name: str, limit: int = 0) -> bytes:
    """Read one archive member without trusting its declared size: stop at `limit` bytes (a zip bomb lies about its size)."""
    limit = limit or MAX_XML_BYTES
    with z.open(name) as fh:
        raw = fh.read(limit + 1)
    if len(raw) > limit:
        raise Unreadable("Document is too large once unpacked")
    return raw


def _docx_text(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if len(z.infolist()) > 2000:
            raise Unreadable("Document has too many parts")
        xml = _member(z, "word/document.xml").decode("utf-8", "ignore")  # docProps (author, company) is never opened
    return re.sub(r"<[^>]+>", " ", re.sub(r"</w:p>", "\n", xml))


def _xlsx_text(data: bytes) -> str:
    """Sheets as CSV text, read from the zip's XML only (no macros, no external links, no formulas evaluated)."""
    import csv
    import datetime
    import xml.etree.ElementTree as ET
    ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"

    def xml(z, name):
        raw = _member(z, name)
        if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw or raw[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in raw[:4]:  # any entity definition, anywhere; and wide encodings that would hide the markers
            raise Unreadable("Spreadsheet XML with entity definitions is refused")
        return ET.fromstring(raw)  # nosec B314: entity definitions are refused above, so no entity expansion is possible

    def col(ref):
        n = 0
        for ch in ref:
            if not ch.isalpha():
                break
            n = n * 26 + ord(ch.upper()) - 64
        return n - 1
    out = io.StringIO()
    w = csv.writer(out)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if sum(i.file_size for i in z.infolist()) > 4 * MAX_XML_BYTES or len(z.infolist()) > 200:
            raise Unreadable("Spreadsheet is too large once unpacked")
        names = z.namelist()
        shared = []
        if "xl/sharedStrings.xml" in names:
            shared = ["".join(t.text or "" for t in si.iter(ns + "t")) for si in xml(z, "xl/sharedStrings.xml").iter(ns + "si")]
        for sheet in sorted(n for n in names if n.startswith("xl/worksheets/sheet") and n.endswith(".xml"))[:5]:
            rows = 0
            date_cols = set()
            for row in xml(z, sheet).iter(ns + "row"):
                cells = {}
                for c in row.iter(ns + "c"):
                    v = c.find(ns + "v")
                    if c.get("t") == "inlineStr":
                        val = "".join(t.text or "" for t in c.iter(ns + "t"))
                    elif v is None or v.text is None:
                        continue
                    elif c.get("t") == "s":
                        val = shared[int(v.text)]
                    else:
                        val = v.text
                    cells[col(c.get("r", "A1"))] = val
                if not cells:
                    continue
                line = [cells.get(i, "") for i in range(max(cells) + 1)]
                if any("date" in x.lower() for x in line if isinstance(x, str)) and not date_cols:
                    date_cols = {i for i, x in enumerate(line) if "date" in x.lower()}
                elif date_cols:
                    for i in date_cols:  # Excel stores dates as day numbers
                        try:
                            n = float(line[i]) if i < len(line) else 0
                            if 20000 < n < 80000:
                                line[i] = (datetime.date(1899, 12, 30) + datetime.timedelta(days=int(n))).isoformat()
                        except ValueError:
                            pass
                w.writerow(line)
                rows += 1
                if rows > 200_000:
                    raise Unreadable("Spreadsheet has too many rows")
    return out.getvalue()


def _pdf_text(data: bytes, password: str = "") -> str:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:  # many "encrypted" PDFs only restrict printing/copying and open with an empty password
        try:
            ok = reader.decrypt(password)
        except Exception:
            raise Unreadable("Could not unlock the PDF")
        if not ok:
            raise Unreadable("Password needed" if not password else "Wrong PDF password")
    if len(reader.pages) > MAX_PDF_PAGES:
        raise Unreadable(f"PDF has more than {MAX_PDF_PAGES} pages")
    parts, total = [], 0
    for page in reader.pages:  # reader.metadata is never read
        t = page.extract_text() or ""
        total += len(t)
        if total > MAX_TEXT_CHARS:
            raise Unreadable("PDF holds more text than can be handled")
        parts.append(t)
    return "\n".join(parts)


def extract(name: str, data: bytes, password: str = "") -> Document:
    if len(data) > MAX_BYTES:
        raise Unreadable("File is too large")
    shown, renamed = safe_name(name)
    low = name.lower()
    notes = ["Filename contained personal detail and was replaced."] if renamed else []
    try:
        if low.endswith(TEXT_SUFFIXES):
            text = data.decode("utf-8")
        elif low.endswith(".pdf"):
            text = _pdf_text(data, password)
        elif low.endswith(".xlsx"):
            text = _xlsx_text(data)
        elif low.endswith(".docx"):
            text = _docx_text(data)
        else:
            raise Unreadable("Only text, CSV, XLSX, JSON, PDF with a text layer, and DOCX files are supported")
    except Unreadable:
        raise
    except Exception as exc:
        raise Unreadable(f"Could not read the file as text ({type(exc).__name__})")
    if not text.strip():
        raise Unreadable("No text found (scanned images are not supported)")
    notes.append("File metadata (author, company, dates) was not read.")
    reason = finance.classify(shown, text)
    summary = ""
    if reason:
        res = finance.sanitize(shown, text)
        summary = res.text if res.ok else ""
        notes.append("Recognised as a financial document: the cloud only ever gets a local summary of it." if summary else
                     "Recognised as a financial document that could not be summarised: it stays on this computer.")
    return Document(shown, text, notes, reason, summary)
