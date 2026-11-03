"""Financial documents (PII-STANDARD tier 3): recognised at intake, before any chunking, and reduced to a local, deterministic summary.

Nothing here calls a model. Transaction rows are parsed, totalled and thrown away; the summary holds only counts, totals, category shares and
month-level figures, and a category or month with fewer than MIN_CELL transactions is folded away so a single row's amount is never shown.
When a document looks financial but cannot be parsed into a summary, the caller keeps it on this computer (fail closed).
"""
import csv
import io
import re
from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Dict, List, Optional, Tuple

MIN_CELL = 3
MAX_ROWS = 200_000
MAX_LINE = 400
MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]

_CUR = re.compile(r"(?i)(₹|\$|€|£|\brs\.?|\binr\b|\busd\b|\beur\b|\bgbp\b)")
_AMT = re.compile(r"(?i)(?<![\w/.-])\(?-?(?:₹|\$|€|£|rs\.?|inr|usd|eur|gbp)?\s?-?\d[\d.,]{0,40}\d(?:\s?(?:cr|dr))?\)?(?![\w/])|(?<![\w/.-])\(?-?\d\)?(?![\w/])")
_DATE_TOK = re.compile(r"\b(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/. ](?:\d{1,2}|[A-Za-z]{3,9})[-/., ]+\d{2,4}|[A-Za-z]{3,9}\.? \d{1,2},? \d{4})\b")

HEADER_WORDS = {
    "date": ("date", "posted", "posting", "value dt", "txn date", "trans"),
    "desc": ("description", "narration", "particulars", "details", "memo", "payee", "merchant", "remarks", "name", "transaction", "reference"),
    "debit": ("debit", "withdrawal", "withdrawals", "dr", "paid out", "money out", "outflow"),
    "credit": ("credit", "deposit", "deposits", "cr", "paid in", "money in", "inflow"),
    "amount": ("amount", "amt", "value", "sum"),
    "balance": ("balance", "bal", "closing"),
}
CATEGORIES = [
    ("Healthcare", ("pharmacy", "drug", "hospital", "clinic", "medical", "dental", "doctor", "health", "apollo", "cvs", "walgreens", "lab")),
    ("Groceries", ("grocer", "supermarket", "market", "kroger", "walmart", "safeway", "whole foods", "bigbasket", "dmart", "costco", "aldi", "tesco")),
    ("Dining", ("restaurant", "cafe", "coffee", "starbucks", "pizza", "burger", "diner", "swiggy", "zomato", "bar ", "grill", "bistro")),
    ("Transport", ("uber", "lyft", "ola ", "fuel", "gas station", "petrol", "shell", "metro", "taxi", "parking", "toll", "airline", "railway")),
    ("Utilities", ("electric", "water", "internet", "broadband", "phone bill", "mobile", "utility", "airtel", "jio", "power", "gas bill")),
    ("Housing", ("rent", "mortgage", "landlord", "hoa", "property")),
    ("Insurance", ("insurance", "premium", "lic ", "geico", "allstate")),
    ("Shopping", ("amazon", "flipkart", "store", "shop", "mall", "ebay", "target", "retail")),
    ("Entertainment", ("netflix", "spotify", "cinema", "movie", "theatre", "game", "hotstar", "subscription")),
    ("Education", ("tuition", "school", "college", "university", "course")),
    ("Fees and interest", ("fee", "charge", "interest charged", "penalty", "overdraft")),
    ("Investments", ("mutual fund", "sip", "brokerage", "dividend", "etf", "stock", "securities", "invest")),
    ("Transfers", ("transfer", "neft", "imps", "upi", "zelle", "venmo", "wire", "atm", "cash withdrawal")),
    ("Income", ("salary", "payroll", "paycheck", "direct dep", "interest paid", "refund", "reimburse")),
]
FIN_KEYWORDS = ("statement period", "opening balance", "closing balance", "ending balance", "beginning balance", "account summary", "available balance",
                "transaction history", "withdrawal", "deposits", "debit", "credit card", "minimum payment", "payment due", "brokerage", "portfolio",
                "market value", "form 1099", "form w-2", "w-2", "1099-", "adjusted gross income", "taxable income", "tax return", "form 16", "itr-",
                "narration", "ifsc", "routing number", "account number", "net asset value", "holdings", "wages, tips", "total tax", "capital gains")
FIN_NAME = re.compile(r"(?i)(statement|transaction|bank|ledger|1099|w-?2|w-?4|tax|return|brokerage|portfolio|holdings|passbook|credit[-_ ]?card|expenses?|payslip|salary|invoice)")
TABLE_SUFFIXES = (".csv", ".tsv", ".xlsx")

# Unstructured financial notes (no table, no statement wording): recognised by what they talk about, not by filename or layout.
# STRONG terms are financial on their own: one mention is enough, even in a one-line note. WEAK terms are ordinary words that are only
# financial together with an amount or with another weak term, so "the salary of the project was discussed" alone is not flagged.
_STRONG = re.compile(r"(?i)(?<![\w])(?:401\s?\(?k\)?|403\s?\(?b\)?|457\s?\(?b\)?|(?:traditional |roth |rollover |sep |simple |inherited )?ira|roth|hsa|health savings account|fsa|529 plan|brokerage|"
                     r"mutual funds?|etfs?|index funds?|stocks?|bonds?|securities|shares of|portfolio|holdings|asset allocation|net worth|retirement (?:plan|account|savings|planning)|"
                     r"rmds?|required minimum distributions?|pension|annuity|tax returns?|tax transcripts?|tax refund|estimated tax|tax payments?|w-?2|1099|1040|form 16|itr-?\d|"
                     r"adjusted gross income|taxable income|capital gains?|dividends?|mortgage|home loan|auto loan|student loans?|credit card (?:balance|debt|statement)|"
                     r"account balances?|bank balance|checking account|savings account|fbar|fincen|fatca|foreign (?:financial |bank )?accounts?|offshore accounts?|"
                     r"routing number|iban|swift code|cost basis|unrealized gains?|vested|stock options?|rsus?|espp)(?![\w])")
_WEAK = re.compile(r"(?i)(?<![\w])(?:salary|wages?|compensation|bonus(?:es)?|income|earnings|paycheck|payroll|deposits?|withdrawals?|balance|loans?|debts?|liabilit(?:y|ies)|"
                   r"interest|savings|invest(?:ed|ment|ments|ing)?|funds?|assets?|equity|refunds?|tax(?:es)?|overdraft|credit limit|rent|premium|expenses?|budget)(?![\w])")
_MONEY = re.compile(r"(?i)(?:₹|\$|€|£|\brs\.?\s?|\binr\b|\busd\b|\beur\b|\bgbp\b)\s?\d|\b\d[\d,]*(?:\.\d+)?\s?(?:k|m|million|thousand|lakh|crore|usd|dollars|euros|inr|rupees)\b|\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b|\b\d+(?:\.\d+)?\s?%")


def concept_signals(text: str) -> str:
    """'' if the text does not talk about money matters; otherwise a short reason. Order-free and layout-free."""
    strong = {m.group(0).lower() for m in _STRONG.finditer(text)}
    if strong:
        return "financial topic"
    weak = {m.group(0).lower() for m in _WEAK.finditer(text)}
    money = bool(_MONEY.search(text))
    if weak and money:
        return "financial wording with amounts"
    if len(weak) >= 3:
        return "financial wording"
    return ""


@dataclass
class Row:
    amount: Decimal  # signed: income positive, spending negative
    month: Optional[Tuple[int, int]]
    desc: str
    balance: Optional[Decimal] = None


@dataclass
class Result:
    ok: bool
    text: str = ""
    rows: int = 0
    reason: str = ""


# --- numbers and dates -----------------------------------------------------------------------

def parse_amount(raw: str) -> Optional[Tuple[Decimal, str]]:
    """'1,23,456.78', '(24.50)', '-₹120', '1.234,56 EUR', '120.00 DR' -> (signed Decimal, currency code). None if not a number."""
    s = raw.strip()
    if not s:
        return None
    neg = s.startswith("(") and s.endswith(")") or "-" in s[:3] or bool(re.search(r"(?i)\bdr\b|dr$", s))
    cur = ""
    m = _CUR.search(s)
    if m:
        t = m.group(1).lower().rstrip(".")
        cur = {"₹": "INR", "$": "USD", "€": "EUR", "£": "GBP", "rs": "INR"}.get(t, t.upper())
    s = re.sub(r"(?i)₹|\$|€|£|\brs\.?|\binr\b|\busd\b|\beur\b|\bgbp\b|\bcr\b|\bdr\b|cr$|dr$|[()\s-]", "", s)
    if not s or not re.fullmatch(r"[\d.,]+", s):
        return None
    if "," in s and "." in s:
        dec = "," if s.rfind(",") > s.rfind(".") else "."
        s = s.replace("." if dec == "," else ",", "").replace(dec, ".")
    elif "," in s:
        s = s.replace(",", "") if re.fullmatch(r"\d{1,3}(?:,\d{2})*,\d{3}|\d{1,3}(?:,\d{3})+", s) else s.replace(",", ".")
    elif s.count(".") > 1 or re.fullmatch(r"\d{1,3}(?:\.\d{3})+", s) and s.count(".") > 1:
        s = s.replace(".", "")
    try:
        v = Decimal(s)
    except InvalidOperation:
        return None
    return (-v if neg else v), cur


def _date_parts(raw: str) -> Optional[Tuple[int, int, int]]:
    """(a, b, year) with the month position still unknown for numeric day/month forms: returns ('ymd')-resolved as (y, m, d) when unambiguous."""
    s = raw.strip()
    m = re.fullmatch(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[T ].*)?", s)
    if m:
        return int(m[1]), int(m[2]), int(m[3])
    m = re.fullmatch(r"(\d{1,2})[-/. ]([A-Za-z]{3,9})[-/., ]+(\d{2,4})", s)
    if m and m[2][:3].lower() in MONTHS:
        y = int(m[3]); y += 2000 if y < 100 else 0
        return y, MONTHS.index(m[2][:3].lower()) + 1, int(m[1])
    m = re.fullmatch(r"([A-Za-z]{3,9})\.? (\d{1,2}),? (\d{4})", s)
    if m and m[1][:3].lower() in MONTHS:
        return int(m[3]), MONTHS.index(m[1][:3].lower()) + 1, int(m[2])
    m = re.fullmatch(r"(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})", s)
    if m:
        y = int(m[3]); y += 2000 if y < 100 else 0
        return -y, int(m[1]), int(m[2])  # negative year: day/month order still to be decided for the whole file
    return None


def _months(dates: List[str], dayfirst_default: bool) -> List[Optional[Tuple[int, int]]]:
    parts = [_date_parts(d) for d in dates]
    first_gt12 = any(p and p[0] < 0 and p[1] > 12 for p in parts)
    second_gt12 = any(p and p[0] < 0 and p[2] > 12 for p in parts)
    dayfirst = True if first_gt12 else False if second_gt12 else dayfirst_default
    out = []
    for p in parts:
        if not p:
            out.append(None)
        elif p[0] > 0:
            out.append((p[0], p[1]) if 1 <= p[1] <= 12 else None)
        else:
            mo = p[2] if dayfirst else p[1]
            out.append((-p[0], mo) if 1 <= mo <= 12 else None)
    return out


# --- reading a table -------------------------------------------------------------------------

def _grid(name: str, text: str) -> List[List[str]]:
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return []
    sample = "\n".join(lines[:20])
    delim = max(",;\t|", key=lambda d: sample.count(d))
    if sample.count(delim) < 1:
        return []
    return [[c.strip() for c in row] for row in csv.reader(lines[:MAX_ROWS], delimiter=delim)]


def _is_date(c: str) -> bool:
    return _date_parts(c) is not None


def _header_map(row: List[str]) -> Dict[str, int]:
    found: Dict[str, int] = {}
    for i, cell in enumerate(row):
        c = cell.lower().strip()
        for key, words in HEADER_WORDS.items():
            if key not in found and any(c == w or c.startswith(w) or (len(w) > 3 and w in c) for w in words):
                found[key] = i
                break
    return found


def _table_rows(grid: List[List[str]]) -> Optional[Tuple[List[Row], str]]:
    if len(grid) < 1:
        return None
    hdr_i, cols = -1, {}
    for i, row in enumerate(grid[:30]):
        m = _header_map(row)
        if "date" in m and ({"amount", "debit", "credit"} & set(m)) and not any(_is_date(c) for c in row):
            hdr_i, cols = i, m
            break
    body = grid[hdr_i + 1:] if hdr_i >= 0 else grid
    width = max((len(r) for r in body), default=0)
    if hdr_i < 0:  # no header: find the columns from the data
        dcol = next((j for j in range(width) if sum(_is_date(r[j]) for r in body if j < len(r)) >= max(1, len(body) * 0.6)), None)
        acols = [j for j in range(width) if j != dcol and sum(parse_amount(r[j]) is not None and bool(re.search(r"\d", r[j])) for r in body if j < len(r)) >= max(1, len(body) * 0.6)]
        tcol = max((j for j in range(width) if j != dcol and j not in acols), default=None,
                   key=lambda j: sum(len(r[j]) for r in body if j < len(r)))
        if dcol is None or not acols:
            return None
        cols = {"date": dcol, "amount": acols[0], **({"balance": acols[1]} if len(acols) > 1 else {}), **({"desc": tcol} if tcol is not None else {})}
    cell = lambda r, k: r[cols[k]] if k in cols and cols[k] < len(r) else ""
    dates = [cell(r, "date") for r in body]
    amounts: List[Optional[Decimal]] = []
    cur = defaultdict(int)
    for r in body:
        v: Optional[Decimal] = None
        if "amount" in cols:
            p = parse_amount(cell(r, "amount")); v = p[0] if p else None
            if p and p[1]: cur[p[1]] += 1
        else:
            d, c = parse_amount(cell(r, "debit")), parse_amount(cell(r, "credit"))
            if d and d[0] or c and c[0]:
                v = (c[0] if c else Decimal(0)) - abs(d[0] if d else Decimal(0))
            for p in (d, c):
                if p and p[1]: cur[p[1]] += 1
        amounts.append(v)
    months = _months(dates, dayfirst_default=bool(cur.get("INR")))
    rows = []
    for r, amt, mo in zip(body, amounts, months):
        if amt is None:
            continue
        bal = parse_amount(cell(r, "balance"))
        rows.append(Row(amt, mo, cell(r, "desc").lower(), bal[0] if bal else None))
    return (rows, max(cur, key=cur.get) if cur else "") if rows else None


def _text_rows(text: str) -> Optional[Tuple[List[Row], str]]:
    raw: List[Tuple[str, Decimal, str, Optional[Decimal]]] = []
    cur = defaultdict(int)
    for line in text.splitlines()[:MAX_ROWS]:
        if len(line) > MAX_LINE:  # real statement rows are short; long lines would make the patterns slow
            continue
        m = _DATE_TOK.search(line)
        if not m:
            continue
        tail = line[m.end():]
        toks = [t for t in _AMT.finditer(tail) if re.search(r"[.,]|\d{3,}|[$₹€£]|(?i:cr|dr)", t.group(0)) or t.end() == len(tail.rstrip())]
        pars = [(t, parse_amount(t.group(0))) for t in toks]
        pars = [(t, p) for t, p in pars if p]
        if not pars:
            continue
        if len(pars) >= 2 and re.search(r"\d[.,]\d{2}(?: ?(?:cr|dr))?$", tail.strip(), re.I):
            (t1, a), (t2, b) = pars[-2], pars[-1]
            desc, amt, bal = tail[:t1.start()], a[0], b[0]
        else:
            t1, a = pars[-1]
            desc, amt, bal = tail[:t1.start()], a[0], None
        if a[1]: cur[a[1]] += 1
        raw.append((m.group(0), amt, desc.lower(), bal))
    if not raw:
        return None
    months = _months([r[0] for r in raw], dayfirst_default=bool(cur.get("INR")))
    rows, prev = [], None
    for (d, amt, desc, bal), mo in zip(raw, months):
        if amt > 0 and bal is not None and prev is not None and bal < prev:
            amt = -amt  # an unsigned amount that lowered the balance was spending
        elif amt > 0 and not any(w in desc for w in ("salary", "payroll", "deposit", "refund", "interest", "credit", "dividend", "transfer in", "reimburse")):
            amt = -amt  # unsigned and no sign from the balance: statements are mostly spending, so treat it as spending (stated in the docs)
        prev = bal if bal is not None else prev
        rows.append(Row(amt, mo, desc, bal))
    return rows, (max(cur, key=cur.get) if cur else "")


# --- classification --------------------------------------------------------------------------

def classify(name: str, text: str) -> str:
    """A reason string if the document looks financial, else ''. Conservative: a tabular file with dates and amounts, a financial
    filename, two or more statement phrases, or two dated amount lines all count. Length and the number of rows are not factors."""
    low, t = name.lower(), text.lower()
    reasons = []
    if FIN_NAME.search(low):
        reasons.append("filename")
    hits = sum(1 for k in FIN_KEYWORDS if k in t)
    if hits >= 2 or (hits >= 1 and reasons):
        reasons.append("statement wording")
    if low.endswith(TABLE_SUFFIXES) or "\n" in text and text.count(",") + text.count("\t") + text.count(";") >= 2:
        tab = _table_rows(_grid(name, text))
        if tab:
            reasons.append("transaction table")
    tr = _text_rows(text)
    if tr and (len(tr[0]) >= 2 or hits or reasons):
        reasons.append("dated amounts")
    if not reasons:
        topic = concept_signals(text)  # judged on the extracted content, so a generic filename cannot hide it
        if topic:
            reasons.append(topic)
    return ", ".join(reasons)


# --- summary ---------------------------------------------------------------------------------

def _category(desc: str, amt: Decimal) -> str:
    for cat, words in CATEGORIES:
        if any(w in desc + " " for w in words):
            if cat == "Income" and amt < 0:
                continue
            return cat
    return "Income (other)" if amt > 0 else "Other"


def _fmt(v: Decimal, cur: str, small: bool = False) -> str:
    """Aggregates are rounded to three significant figures and written in words ("12.7 thousand USD"), so they carry no cents and no
    exact figure, and read as a size, not a transaction. Files with fewer than five rows get two significant figures."""
    v = abs(v)
    sig = 2 if small else 3
    unit, div = ("", Decimal(1)) if v < 1000 else (" thousand", Decimal(1000)) if v < 1_000_000 else (" million", Decimal(1_000_000))
    x = v / div
    digits = max(0, sig - len(str(int(x))))
    x = x.quantize(Decimal(1).scaleb(-digits)) if digits else x.quantize(Decimal(1)) if len(str(int(x))) <= sig else x.quantize(Decimal(1), rounding="ROUND_DOWN")
    num = f"{x:f}".rstrip("0").rstrip(".") if "." in f"{x:f}" else f"{x:f}"
    return f"{num}{unit}{' ' + cur if cur else ''}"


def sanitize(name: str, text: str) -> Result:
    """Parse locally and return a summary that holds no transaction row. ok=False means: financial but unreadable, keep it local."""
    found = _table_rows(_grid(name, text)) if (name.lower().endswith(TABLE_SUFFIXES) or text.count(",") + text.count("\t") + text.count(";") >= 2) else None
    text_found = _text_rows(text)
    if text_found and (not found or len(text_found[0]) > len(found[0])):
        found = text_found
    if not found:
        return Result(False, reason="no transaction table could be read")
    rows, cur = found
    n = len(rows)
    small = n < 5
    income = sum((r.amount for r in rows if r.amount > 0), Decimal(0))
    spend = sum((-r.amount for r in rows if r.amount < 0), Decimal(0))
    out = ["Financial summary (computed on this computer; no individual transaction, merchant, date or account detail is included).",
           f"Transactions: {n}" + (f" ({_period(rows)})" if _period(rows) else "") + (f". Currency: {cur}." if cur else ".")]
    out.append(f"Total income: {_fmt(income, cur, small)}. Total spending: {_fmt(spend, cur, small)}. "
               f"Net: {'-' if income < spend else ''}{_fmt(income - spend, cur, small)}.")
    if n >= MIN_CELL:
        cats: Dict[str, List[Decimal]] = defaultdict(list)
        for r in rows:
            if r.amount < 0:
                cats[_category(r.desc, r.amount)].append(-r.amount)
        merged: Dict[str, List[Decimal]] = defaultdict(list)
        for c, vals in cats.items():
            merged[c if len(vals) >= MIN_CELL else "Other"] += vals
        if sum(len(v) for v in merged.values()) and spend:
            parts = [f"{c.lower()}: {_fmt(sum(v), cur, small)}, {round(100 * sum(v) / spend)}% of spending" for c, v in sorted(merged.items(), key=lambda kv: -sum(kv[1])) if len(v) >= MIN_CELL]
            if parts:
                out.append("Spending by category (lower-case labels): " + "; ".join(parts) + ".")
        months: Dict[Tuple[int, int], List[Decimal]] = defaultdict(list)
        for r in rows:
            if r.amount < 0 and r.month:
                months[r.month].append(-r.amount)
        shown = [f"{MONTHS[m - 1].title()} {y} {_fmt(sum(v), cur, small)}" for (y, m), v in sorted(months.items()) if len(v) >= MIN_CELL]
        if shown:
            out.append("Monthly spending: " + "; ".join(shown) + ".")
        last_bal = next((r.balance for r in reversed(rows) if r.balance is not None), None)
        if last_bal is not None:
            out.append(f"Closing balance: {'-' if last_bal < 0 else ''}{_fmt(last_bal, cur, small)}.")
    else:
        out.append("Too few transactions to break down without exposing individual ones.")
    return Result(True, "\n".join(out), n)


def _period(rows: List[Row]) -> str:
    ms = sorted({r.month for r in rows if r.month})
    if not ms:
        return ""
    f = lambda ym: f"{MONTHS[ym[1] - 1].title()} {ym[0]}"
    return f(ms[0]) if ms[0] == ms[-1] else f"{f(ms[0])} to {f(ms[-1])}"
