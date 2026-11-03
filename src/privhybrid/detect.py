"""Tiered PII detection (PII-STANDARD.md). Layers: regex + checksums, Presidio (NER), user dictionary.

Fails closed: any detector error raises DetectorError and the caller must not send anything.
The local-LLM second pass is a separate step (not here).
"""
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

TIER_BLOCK, TIER_PERSONAL, TIER_FINANCIAL = 1, 2, 3
# kind -> placeholder prefix. Tier 1 kinds have no placeholder: they stop the request.
PLACEHOLDER = {
    "PERSON": "PERSON", "PHONE": "PHONE", "EMAIL": "EMAIL", "ADDRESS": "ADDRESS", "DOB": "DOB", "ACCOUNT": "ACCOUNT",
    "ORG": "ORG", "ID": "ID", "URL": "URL", "PLACE": "ADDRESS", "AMOUNT": "AMOUNT", "DATE": "DATE", "MERCHANT": "MERCHANT", "TXN": "TXN",
    "GENDER": "GENDER", "TITLE": "TITLE", "MEDICAL": "MEDICAL", "SCORE": "SCORE",
}


class DetectorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Entity:
    start: int
    end: int
    kind: str
    tier: int
    text: str
    source: str  # regex | presidio | dictionary


@dataclass
class Detection:
    entities: List[Entity] = field(default_factory=list)
    quasi: List[str] = field(default_factory=list)

    @property
    def sensitive(self) -> List[Entity]:
        """Entities that are personal or financial on their own (tiers 1-3). PLACE (tier 4) only counts in a combination."""
        return [e for e in self.entities if e.tier <= TIER_FINANCIAL]

    @property
    def tier1(self) -> List[Entity]:
        return [e for e in self.entities if e.tier == TIER_BLOCK]


# --- checksums ------------------------------------------------------------------------------

def luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits][::-1]
    return len(d) >= 13 and (sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])) % 10 == 0


def aba_ok(digits: str) -> bool:
    if len(digits) != 9:
        return False
    d = [int(c) for c in digits]
    return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 == 0


def iban_ok(value: str) -> bool:
    v = re.sub(r"\s", "", value).upper()
    if not 15 <= len(v) <= 34:
        return False
    num = "".join(str(int(c, 36)) for c in v[4:] + v[:4])
    return int(num) % 97 == 1


def ssn_ok(digits: str) -> bool:
    if len(digits) != 9 or digits[3:5] == "00" or digits[5:] == "0000":
        return False
    if digits[0] == "9":  # 9xx numbers are ITINs: the middle group is 50-65, 70-88, 90-92 or 94-99
        return 50 <= int(digits[3:5]) <= 65 or 70 <= int(digits[3:5]) <= 88 or 90 <= int(digits[3:5]) <= 92 or 94 <= int(digits[3:5]) <= 99
    return digits[:3] not in ("000", "666")


# --- regex layer ----------------------------------------------------------------------------

def _ctx(words: str, window: int = 40) -> "re.Pattern[str]":
    return re.compile(rf"(?i)(?:{words})[^\n]{{0,{window}}}?")


def _ref_label(t: str, start: int) -> bool:
    """A nine-digit number right after a reference-style label is a TXN, not an SSN (the TXN rule masks it)."""
    return bool(re.search(r"(?i)(?:check|cheque|chk|ref|confirmation|trace|auth|invoice|order|po|routing|aba|acct|account)\s*(?:no|number|#)?\s*[:#]?\s*$", t[max(0, start - 25):start]))


NUM = r"[\d][\d \-]{6,}\d"
RULES = [
    # (kind, tier, pattern, group, validator)
    ("SSN", 1, re.compile(r"(?<![\d-])(\d{3}[- ]?\d{2}[- ]?\d{4})(?![\d-])"), 1, lambda m, t: ssn_ok(re.sub(r"\D", "", m.group(1))) and not _ref_label(t, m.start())),
    ("SSN", 1, re.compile(r"(?<!\d)(\d{3}[- ]?\d{2}[-\s]{1,3}\d{4})(?!\d)"), 1, lambda m, t: ssn_ok(re.sub(r"\D", "", m.group(1))) and not _ref_label(t, m.start())),
    ("CARD", 1, re.compile(r"(?<!\d)(\d(?:[ -]?\d){12,18})(?!\d)"), 1, lambda m, t: luhn_ok(re.sub(r"\D", "", m.group(1)))),
    ("CVV", 1, re.compile(r"(?i)\b(?:cvv2?|cvc|security code)\b\D{0,6}(\d{3,4})\b"), 1, None),
    ("SSN", 1, re.compile(r"(?i)\b(?:social security|ssn)\b[^.\n]{0,40}?((?:\b(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)\b[\s,.\-]*){9})"), 1, None),
    ("ROUTING", 1, re.compile(r"(?i)\b(?:routing|aba)\b\D{0,20}(\d{9})\b"), 1, lambda m, t: aba_ok(m.group(1))),
    ("BANKACCT", 1, re.compile(r"(?i)\b(?:acct|account)\b(?:\s*(?:no|number|num|#))?\D{0,12}(\d(?:[ -]?\d){7,16})\b"), 1, None),
    ("IBAN", 1, re.compile(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{1,5}){3,8})\b"), 1, lambda m, t: iban_ok(m.group(1))),
    ("GOVID", 1, re.compile(r"(?i)\b(?:passport|reisepass|passeport|pasaporte|passaporto|paspoort|personalausweis|ausweis|carte d'identit[eé]|dni|nie|nif|bsn|driver'?s? licen[cs]e|f[uü]hrerschein|permis de conduire|dl|ein|tin|tax id)\b(?:\s*(?:no\.?|number|num\.?|nr\.?|n[°º]|num[eé]ro|n[úu]mero|nummer|#))?\s*(?:is|was|ist|est|es|=)?[:\s)]*([A-Z0-9][A-Z0-9\-]{5,14})\b"),
     1, lambda m, t: any(c.isdigit() for c in m.group(1))),
    ("MEDID", 1, re.compile(r"(?i)\b(?:mrn|medical record|member id|policy (?:no|number|#)|insurance id)\b\s*[:#]?\s*([A-Z0-9\-]{5,20})\b"),
     1, lambda m, t: any(c.isdigit() for c in m.group(1))),
    ("SECRET", 1, re.compile(r"\b((?:sk|pk|ghp|gho|xox[bap]|AKIA|AIza)[-_A-Za-z0-9]{16,})\b"), 1, None),
    ("SECRET", 1, re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), 0, None),
    ("SECRET", 1, re.compile(r"(?i)\b(?:password|passwd|pwd|passcode|api[_ ]?key|secret|token)\b\s*[:=]\s*(\S{4,})"), 1, None),
    ("SECRET", 1, re.compile(r"(?i)\b(?:2fa|otp|verification|one[- ]time)\b[^\n]{0,20}?\b(\d{6,8})\b"), 1, None),
    ("SECRET", 1, re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 0, None),
    ("EMAIL", 2, re.compile(r"\b[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+\b"), 0, None),
    ("PHONE", 2, re.compile(r"(?<![\w.])(?:\+?1[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]\d{3}[\s.\-]\d{4}\b"), 0, None),
    ("PHONE", 2, re.compile(r"(?<!\w)\+\d{1,3}[\s.\-]?\d[\d\s.\-]{7,12}\d\b"), 0, None),
    ("DOB", 2, re.compile(r"(?i)\b(?:dob|d\.o\.b\.|date of birth|born(?: on)?|birthday)\b[:\s]*"
                          r"((?:\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4})|(?:\d{4}-\d{2}-\d{2})|(?:[A-Za-z]{3,9}\.? \d{1,2},? \d{4}))"), 1, None),
    ("ADDRESS", 2, re.compile(r"\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][\w.]*\s+){1,4}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|Ct|Court|Way|Pl|Place|Pkwy|Hwy"
                              r"|Close|Crescent|Cres|Terrace|Square|Gardens|Row|Walk|Grove|Mews|Parade|Rise|Hill|Park|Green)\b\.?"
                              r"(?:,?\s*(?:Apt|Unit|Suite|Ste|Flat|#)\s*\w+)?"), 0, None),
    # Street-first forms common outside the US: "12 rue de la Paix", "Hauptstrasse 5", "Calle Mayor 3"
    ("ADDRESS", 2, re.compile(r"(?i)\b(?:\d{1,4}[a-z]?,?\s+)?(?:rue|via|calle|avenida|avenue|plaza|piazza|rua)\s+(?:(?:de|del|della|la|le|los|las|da|do)\s+)*[A-Za-zÀ-ÿ'\-]+(?:\s+\d{1,4}[a-z]?)?"), 0, None),
    ("ADDRESS", 2, re.compile(r"\b[A-ZÄÖÜ][a-zäöüß]+(?:stra(?:ß|ss)e|weg|platz|allee|gasse)\s+\d{1,4}[a-z]?\b"), 0, None),
    ("ZIP", 2, re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b"), 0, None),  # UK postcode
    ("ZIP", 2, re.compile(r"\b[ABCEGHJ-NPRSTVXY]\d[A-CEGHJ-NPRSTV-Z][ -]?\d[A-CEGHJ-NPRSTV-Z]\d\b"), 0, None),  # Canadian postcode
    ("ZIP", 2, re.compile(r"(?<!\d)(\d{5})(?:-\d{4})?(?!\d)(?=\s*(?:$|[,.;:)\n]|USA|US\b))"), 0, None),
    ("ID", 2, re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), 0, lambda m, t: any(c.isdigit() for c in m.group(0)) and any(c.isalpha() for c in m.group(0))),
    ("ID", 2, re.compile(r"(?i)\b(?:username|user name|user id|customer (?:no|number|id)|member (?:no|number)|device id|customer #)\b\s*[:#]?\s*(\S{3,})"), 1, None),
    ("ID", 2, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0, lambda m, t: all(int(p) <= 255 for p in m.group(0).split("."))),
    ("URL", 2, re.compile(r"https?://[^\s]*(?:[?&](?:token|key|auth|sig|session)=|/(?:u|user|users|profile)/)[^\s]*"), 0, None),
    ("GENDER", 2, re.compile(r"(?i)\b(?:gender|sex)\b\s*[:=]\s*(male|female|non-?binary|m|f)\b"), 1, None),
    ("TITLE", 2, re.compile(r"(?i)\b(?:job title|title|position|occupation|role)\b\s*[:=]\s*([A-Za-z][\w &/\-]{2,40})"), 1, None),
    # Diagnoses and medication tied to a person are documented Tier 1 (PII-STANDARD): they stop the request. Only a labelled or "diagnosed with" form counts.
    ("MEDICAL", 1, re.compile(r"(?i)\b(?:diagnosed with|(?:diagnos[ie]s|medications?|conditions?)\s*[:=]|prescribed\s*:?\s*(?!by\b|in\b|for\b|to\b|a\b|the\b))\s*([A-Za-z][\w \-]{2,40})"), 1, None),
    ("SWIFT", 1, re.compile(r"\b(?i:swift|bic)\b\D{0,12}\b([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b"), 1, None),
    ("SCORE", 3, re.compile(r"(?i)\b(?:credit|fico|vantage)\s*score\b\D{0,12}(\d{3})\b"), 1, None),
    ("AMOUNT", 3, re.compile(r"(?<![\w])[-(]?[$₹€£]\s?\d[\d,]*(?:\.\d{1,2})?\)?|\b\d[\d,]*\.\d{2}\s?(?:USD|dollars)\b|\b\d{1,3}(?:,\d{3})+(?:\.\d{2})?\b"), 0, None),
    ("TXN", 3, re.compile(r"(?i)\b(?:check|cheque|chk|ref|confirmation|trace|auth)\s*(?:no|number|#)?\s*[:#]?\s*(\d{3,12})\b"), 1, None),
    ("DATE", 3, re.compile(r"\b(?:\d{1,2}/\d{1,2}(?:/\d{2,4})?|\d{4}-\d{2}-\d{2})\b"), 0, None),
]
TIER_OF = {"ZIP": 2}
NAME_CONTEXT = re.compile(r"\b(?i:name|payee|customer|account holder|dear|mr|mrs|ms|dr)\b\.?(?:[:\s]+(?i:is)\b)?[:\s]+((?:[A-Z][a-z]+(?:[ ,]+|$)){1,3})")


def _regex_layer(text: str) -> List[Entity]:
    out = []
    for kind, tier, pat, grp, check in RULES:
        for m in pat.finditer(text):
            if check is not None and not check(m, text):
                continue
            s, e = m.span(grp)
            if s == e:
                continue
            out.append(Entity(s, e, kind, tier, text[s:e], "regex"))
    out.extend(_card_windows(text, [x for x in out if x.kind == "CARD"]))
    for m in NAME_CONTEXT.finditer(text):
        s, e = m.span(1)
        out.append(Entity(s, e, "PERSON", 2, text[s:e].strip(" ,"), "regex"))
    return out


_DIGIT_RUN = re.compile(r"(?<!\d)\d{1,19}(?:[ -]\d{1,19})*(?!\d)")
_DIGIT_TOKEN = re.compile(r"\d+")


def _card_windows(text: str, found: List[Entity]) -> List[Entity]:
    """A card number next to other digits ("1500 4111 1111 1111 1111", a date before it) fails the whole-run Luhn check.
    Try every run of digit groups inside it; fail closed (a lucky Luhn match only stops a request that was safe)."""
    out: List[Entity] = []
    for run in _DIGIT_RUN.finditer(text):
        toks = [(run.start() + t.start(), run.start() + t.end()) for t in _DIGIT_TOKEN.finditer(run.group())]
        for i in range(len(toks)):
            digits, hit = "", None
            for j in range(i, len(toks)):  # stop once past 19 digits: a long column of numbers must stay cheap
                digits += text[toks[j][0]:toks[j][1]]
                if len(digits) > 19:
                    break
                if len(digits) >= 13 and luhn_ok(digits):
                    hit = j  # keep going: the longest valid window wins
            if hit is None:
                continue
            s, e = toks[i][0], toks[hit][1]  # every start is tried, so a chance match before the real card cannot hide it
            if not any(f.start <= s and e <= f.end for f in found + out):
                out.append(Entity(s, e, "CARD", 1, text[s:e], "regex"))
    return out


# --- presidio layer -------------------------------------------------------------------------

_PRESIDIO_MAP = {"PERSON": ("PERSON", 2), "ORGANIZATION": ("ORG", 2), "ORG": ("ORG", 2), "LOCATION": ("PLACE", 4),
                 "GPE": ("PLACE", 4), "NRP": None, "DATE_TIME": None}
# Names the NER model mistakes for people or organisations. Matched on the whole entity, NER hits only: the regex
# and dictionary layers are never filtered, so a number or an entry the user listed is still masked.
_NOT_PERSONAL = re.compile(
    r"(?i)(?:form\s+)?(?:w-?[2-9]g?|i-9|k-1|1040(?:-\w+)?|109[5-9](?:-\w+)?|ss-[48]|schedule\s+[a-z])"
    r"|claude|anthropic|chatgpt|openai|ollama|siri")
_analyzer = None


def _get_analyzer(model: str = "en_core_web_lg"):
    global _analyzer
    if _analyzer is None:
        try:
            import spacy.util
            if not spacy.util.is_package(model):  # Presidio would download it: no silent network access
                raise DetectorError(f"spaCy model {model} is not installed")
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            nlp = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": model}]}).create_engine()
            _analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
        except DetectorError:
            raise
        except (Exception, SystemExit) as exc:
            raise DetectorError(f"Presidio unavailable ({type(exc).__name__}: {exc})")
    return _analyzer


def _presidio_layer(text: str, model: str) -> List[Entity]:
    try:
        results = _get_analyzer(model).analyze(text=text, language="en", entities=None,
                                                score_threshold=0.4)
    except DetectorError:
        raise
    except Exception as exc:
        raise DetectorError(f"Presidio failed ({type(exc).__name__})")
    out = []
    for r in results:
        mapped = _PRESIDIO_MAP.get(r.entity_type)
        if mapped and not _NOT_PERSONAL.fullmatch(text[r.start:r.end].strip()):
            out.append(Entity(r.start, r.end, mapped[0], mapped[1], text[r.start:r.end], "presidio"))
    return out


# --- dictionary layer -----------------------------------------------------------------------

def load_dictionary(path: str) -> Dict[str, str]:
    """One entry per line: `KIND: value` (for example `PERSON: Jane Q Doe`). `#` starts a comment."""
    entries: Dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if ":" in line:
                    kind, value = (x.strip() for x in line.split(":", 1))
                    if value and kind.upper() in PLACEHOLDER:
                        entries[value] = kind.upper()
    except FileNotFoundError:
        pass
    except Exception as exc:
        raise DetectorError(f"Dictionary unreadable ({type(exc).__name__})")
    return entries


def _dictionary_layer(text: str, dictionary: Dict[str, str]) -> List[Entity]:
    out = []
    for value, kind in dictionary.items():
        for m in re.finditer(re.escape(value).replace(r"\ ", r"\s+"), text, flags=re.I):
            out.append(Entity(m.start(), m.end(), kind, 3 if kind in ("AMOUNT", "MERCHANT", "TXN") else 2, m.group(0), "dictionary"))
    return out


# --- combine --------------------------------------------------------------------------------

def _resolve(entities: List[Entity]) -> List[Entity]:
    """Drop overlaps: Tier 1 always wins; then an entry from the user's own dictionary (it says exactly what that text is); then lowest tier, longest, earliest."""
    keep: List[Entity] = []
    for e in sorted(entities, key=lambda x: (x.tier != 1, x.source != "dictionary", x.tier, -(x.end - x.start), x.start)):
        if not any(e.start < k.end and k.start < e.end for k in keep):
            keep.append(e)
    return sorted(keep, key=lambda x: x.start)


def _merge_names(text: str, entities: List[Entity]) -> List[Entity]:
    """Join neighbouring PERSON/ORG pieces ("SMITH" + ", " + "JON") so one name gets one placeholder."""
    out: List[Entity] = []
    for e in entities:
        p = out[-1] if out else None
        if p and p.kind == e.kind and e.kind in ("PERSON", "ORG") and p.tier == e.tier and re.fullmatch(r"[\s,]{1,2}", text[p.end:e.start]):
            out[-1] = Entity(p.start, e.end, p.kind, p.tier, text[p.start:e.end], p.source)
        else:
            out.append(e)
    return out


def _quasi(entities: List[Entity]) -> List[str]:
    kinds = {e.kind for e in entities}
    flags = []
    place = {"ADDRESS", "PLACE"} & kinds
    if "ZIP" in kinds and ({"DOB", "DATE"} & kinds):
        flags.append("zip+date")
    if "ZIP" in kinds and "GENDER" in kinds:
        flags.append("zip+gender")
    if place and "ORG" in kinds:
        flags.append("place+employer")
    if "DOB" in kinds and (place or "ZIP" in kinds):
        flags.append("dob+place")
    if "ORG" in kinds and "TITLE" in kinds:
        flags.append("title+employer")
    if "MEDICAL" in kinds and (place or "ZIP" in kinds):
        flags.append("medical+place")
    if "ZIP" in kinds and ({"ADDRESS", "PLACE"} & kinds):
        flags.append("city+zip")
    if "PERSON" in kinds and ({"AMOUNT", "ACCOUNT", "BANKACCT", "CARD", "TXN", "SCORE", "MERCHANT"} & kinds):
        flags.append("name+financial")
    return flags


def detect(text: str, dictionary: Optional[Dict[str, str]] = None, model: str = "en_core_web_lg",
           use_presidio: bool = True) -> Detection:
    try:
        found = _regex_layer(text)
        if use_presidio:
            found += _presidio_layer(text, model)
        found += _dictionary_layer(text, dictionary or {})
        entities = _merge_names(text, _resolve(found))
        return Detection(entities, _quasi(entities))
    except DetectorError:
        raise
    except Exception as exc:
        raise DetectorError(f"Detection failed ({type(exc).__name__})")


_DIGIT_WORDS = r"(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)"
_WATCH_SPELLED = re.compile(rf"\b(?:{_DIGIT_WORDS}[\s,.-]+){{5,}}{_DIGIT_WORDS}\b", re.I)
_WATCH_NUMBER = re.compile(r"(?<![\w.])\d(?:[\d\s-]*\d)?(?![\w])")
_WATCH_WORDS = re.compile(r"\b(?:social security|ssn|passport|routing number|account number|sort code|iban|swift code|tax id|password|passcode|pin code|security code|cvv|date of birth|maiden name)\b", re.I)


def watch_flags(text: str) -> List[str]:
    """Soft warnings on text that is about to leave: things the filter is not sure about (it cannot mask them, so a person must look).
    Returns short labels, never the matched text. Not a block: the user can still send after confirming."""
    out = []
    if _WATCH_SPELLED.search(text):
        out.append("digits spelled out as words")
    if any(sum(c.isdigit() for c in m.group(0)) >= 9 for m in _WATCH_NUMBER.finditer(text)):
        out.append("a long number that was not masked")
    found = sorted({m.group(0).lower() for m in _WATCH_WORDS.finditer(text)})
    if found:
        out.append("mentions: " + ", ".join(found[:4]))
    return out


_UNREADABLE = ((0x0590, 0x08FF), (0x0900, 0x0DFF), (0x0E00, 0x0EFF), (0x1100, 0x11FF), (0x3040, 0x30FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xAC00, 0xD7AF), (0xF900, 0xFAFF))  # Hebrew, Arabic, Indic, Thai, Hangul, kana, CJK


def unreadable_script_share(text: str) -> float:
    """Share of letters in scripts the English-trained name and address detection cannot read (Cyrillic and Greek are handled, so they are not counted)."""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if any(a <= ord(c) <= b for a, b in _UNREADABLE)) / len(letters)
