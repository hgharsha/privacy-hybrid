"""Reversible placeholders and the unmasker (PII-STANDARD.md, placeholder rules).

The map (placeholder -> real value) lives in memory only: it cannot be pickled, copied to a repr, or logged.
Tier 1 never gets a placeholder: mask() raises NeedsApproval and nothing is produced.
"""
import re
import unicodedata
from typing import Dict, List, Optional, Tuple

from . import detect as D

PH_RE = re.compile(r"\[([A-Z]+)_(\d+)\]")
MAX_MASKED_RATIO = 0.20
MIN_KNOWN_LEN = 4  # shorter values would match inside ordinary words
_KIND_TO_PH = {**D.PLACEHOLDER, "ZIP": "ADDRESS"}


class NeedsApproval(RuntimeError):
    """Fail closed: the request must not be sent. Carries kinds and counts only, never values."""

    def __init__(self, reason: str, kinds: Optional[Dict[str, int]] = None):
        super().__init__(reason)
        self.kinds = kinds or {}


def _norm(kind: str, value: str) -> str:
    """Key that makes format variants share one placeholder."""
    if kind in ("PHONE", "ACCOUNT", "TXN", "ID") and re.search(r"\d", value) and not re.search(r"[A-Za-z]{3}", value):
        digits = re.sub(r"\D", "", value)
        return digits[-10:] if kind == "PHONE" else digits
    if kind == "AMOUNT":
        digits = re.sub(r"[^\d.]", "", value).rstrip(".")
        return ("-" if re.match(r"\s*(?:[-\u2212\u2013]|\(.*\)\s*$)", value) or re.search(r"\bCR\b", value) else "") + digits if digits else value  # a debit and a credit of one value are different
    if kind == "PERSON":
        parts = [p for p in re.split(r"[\s,]+", value.casefold()) if p]
        return " ".join(sorted(parts))  # "SMITH, JON" == "Jon Smith"
    return re.sub(r"\s+", " ", value.casefold()).strip()


class Vault:
    def __init__(self, dictionary: Optional[Dict[str, str]] = None) -> None:
        self.dictionary = dict(dictionary or {})  # the user's own terms: value -> kind
        self._by_key: Dict[Tuple[str, str], str] = {}
        self._real: Dict[str, str] = {}
        self._count: Dict[str, int] = {}

    # The map must never leave memory by accident.
    def __repr__(self) -> str:
        return f"<Vault {len(self._real)} placeholders>"

    def __reduce__(self):
        raise TypeError("Vault cannot be pickled or saved")

    def __copy__(self):
        raise TypeError("Vault cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Vault cannot be copied")

    def __len__(self) -> int:
        return len(self._real)

    def placeholder(self, kind: str, value: str) -> str:
        prefix = _KIND_TO_PH[kind]
        key = (prefix, _norm(kind, value))
        if key not in self._by_key:
            n = self._count.get(prefix, 0) + 1
            self._count[prefix] = n
            self._by_key[key] = f"[{prefix}_{n}]"
            self._real[self._by_key[key]] = value
        return self._by_key[key]

    def mask(self, text: str, detection: Optional[D.Detection] = None, max_ratio: float = MAX_MASKED_RATIO,
             **detect_kw) -> Tuple[str, Dict[str, int]]:
        """Return (masked text, counts by placeholder type). Raises NeedsApproval instead of weakening anything."""
        detect_kw.setdefault("dictionary", self.dictionary)
        det = detection if detection is not None else D.detect(text, **detect_kw)
        if det.tier1:
            counts: Dict[str, int] = {}
            for e in det.tier1:
                counts[e.kind] = counts.get(e.kind, 0) + 1
            raise NeedsApproval("Tier 1 data found (never sent)", counts)
        # A place on its own is public; with an employer or birth date it identifies someone, so then it is masked.
        ents = [e for e in det.entities if e.tier <= D.TIER_FINANCIAL or det.quasi]
        # Text that already looks like one of our placeholders would confuse the unmasker: treat it as data.
        for m in PH_RE.finditer(text):
            if not any(e.start < m.end() and m.start() < e.end for e in ents):
                ents.append(D.Entity(m.start(), m.end(), "ID", 2, m.group(0), "literal"))
        ents.sort(key=lambda e: e.start)
        masked_chars = sum(e.end - e.start for e in ents)
        if text and masked_chars / len(text) > max_ratio:
            raise NeedsApproval(f"More than {int(max_ratio * 100)}% of the text is sensitive")
        out, pos, counts = [], 0, {}
        for e in ents:
            out.append(text[pos:e.start])
            out.append(self.placeholder(e.kind, e.text))
            counts[_KIND_TO_PH[e.kind]] = counts.get(_KIND_TO_PH[e.kind], 0) + 1
            pos = e.end
        out.append(text[pos:])
        return "".join(out), counts

    def leaks(self, text: str) -> int:
        """How many values this account is known to hold (ones masked earlier, and the user's own terms) still appear in `text`.

        A deterministic check that does not depend on any model: it ignores case, spacing, punctuation, zero-width characters and
        look-alike forms ("J.o-h n  S m i t h", full-width digits), so a value cannot slip out by being reformatted."""
        clean = "".join(c for c in unicodedata.normalize("NFKC", PH_RE.sub(" ", text)) if unicodedata.category(c) != "Cf").casefold()
        known = list(self._real.values()) + list(self.dictionary)
        found, seen = 0, set()
        for value in known:
            alnum = re.sub(r"[\W_]", "", unicodedata.normalize("NFKC", str(value)).casefold())
            if len(alnum) < MIN_KNOWN_LEN or alnum in seen or PH_RE.fullmatch(str(value).strip()):
                continue
            seen.add(alnum)
            pat = r"(?<![^\W_])" + r"[\W_]*".join(map(re.escape, alnum)) + r"(?![^\W_])"
            if re.search(pat, clean):
                found += 1
        return found

    def unmask(self, text: str) -> Tuple[str, List[str]]:
        """Restore known placeholders. Unknown ones are left as they are and reported, never guessed."""
        unknown: List[str] = []

        def sub(m: "re.Match[str]") -> str:
            ph = m.group(0)
            if ph in self._real:
                return self._real[ph]
            unknown.append(ph)
            return ph

        return PH_RE.sub(sub, text), unknown

    def stream(self) -> "StreamUnmasker":
        return StreamUnmasker(self)


class StreamUnmasker:
    """Unmask a streamed reply. Holds back text from '[' until ']' so a split placeholder is never half-shown."""
    MAX_HOLD = 24  # longest placeholder we expect, plus slack; a longer '[' run is literal text

    def __init__(self, vault: Vault) -> None:
        self._vault = vault
        self._buf = ""
        self.unknown: List[str] = []

    def feed(self, chunk: str) -> str:
        self._buf += chunk
        out = []
        while True:
            i = self._buf.find("[")
            if i < 0:
                out.append(self._buf)
                self._buf = ""
                break
            out.append(self._buf[:i])
            self._buf = self._buf[i:]
            j = self._buf.find("]")
            if j < 0:
                if len(self._buf) > self.MAX_HOLD:  # not a placeholder: release the '[' and rescan
                    out.append("[")
                    self._buf = self._buf[1:]
                    continue
                break
            candidate, self._buf = self._buf[:j + 1], self._buf[j + 1:]
            if PH_RE.fullmatch(candidate):
                text, unk = self._vault.unmask(candidate)
                self.unknown += unk
                out.append(text)
            else:  # '[' ... ']' that is not a placeholder: emit '[' and rescan the rest
                out.append("[")
                self._buf = candidate[1:] + self._buf
        return "".join(out)

    def flush(self) -> str:
        rest, self._buf = self._buf, ""
        return rest
