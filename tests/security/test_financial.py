"""Phase 2: financial documents are recognised at intake, summarised locally, and only the summary can reach a cloud service.
Every test checks the request body that actually arrived at the mock cloud service. Synthetic data only."""
import base64
import io
import json
import zipfile

import pytest

from privhybrid import finance
from tests.test_server import C, events

ROWS = [("2026-10-01", "ACME PHARMACY", "-24.50"), ("2026-10-02", "JOES CAFE", "-8.75"), ("2026-10-03", "ACME PHARMACY", "-41.20"),
        ("2026-10-04", "ACME PHARMACY", "-13.35"), ("2026-10-05", "ZEBRA GROCERS", "-187.64"), ("2026-10-06", "ZEBRA GROCERS", "-92.18"),
        ("2026-10-07", "ZEBRA GROCERS", "-64.93"), ("2026-10-08", "ORBIT PAYROLL", "2417.31")]
SECRETS = ["ACME", "JOES CAFE", "ZEBRA", "ORBIT", "24.50", "187.64", "92.18", "64.93", "2417.31", "2026-10-0"]


@pytest.fixture(autouse=True)
def user_says_yes(monkeypatch):
    """Financial material now always needs the user's yes (tests/security/test_preview.py covers the dialog itself); here the yes is automatic so
    these tests can inspect what then arrives at the mock cloud."""
    from privhybrid import pipeline
    real = pipeline.run
    monkeypatch.setattr(pipeline, "run", lambda *a, **kw: real(*a, **{**kw, "approve": kw.get("approve") and (lambda info: True)}))


def csv_text(rows=ROWS, header=True):
    return ("Date,Description,Amount\n" if header else "") + "\n".join(",".join(r) for r in rows) + "\n"


def xlsx_bytes(rows):
    def cell(r, c, v):
        return f'<c r="{chr(65 + c)}{r}" t="inlineStr"><is><t>{v}</t></is></c>'
    sheet = "".join(f'<row r="{i + 1}">' + "".join(cell(i + 1, j, v) for j, v in enumerate(row)) + "</row>" for i, row in enumerate(rows))
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("xl/worksheets/sheet1.xml", f'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{sheet}</sheetData></worksheet>')
    return b.getvalue()


def pdf_bytes(lines):
    stream = "BT /F1 10 Tf 40 760 Td 12 TL " + " ".join(f"({l}) Tj T*" for l in lines) + " ET"
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offs = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out)); out += f"{i} 0 obj\n{o}\nendobj\n".encode()
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode() + b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    return out + f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF".encode()


def upload(c, name, data):
    return c.req("POST", "/api/upload", {"name": name, "data": base64.b64encode(data).decode()})


def ask_cloud(c, q="Where does my money go? Summarise my spending."):
    return events(c.req("POST", "/api/chat", {"question": q, "mode": "claude", "remember": False})[1])


def sent(net):
    return json.dumps(net.cloud)


def assert_clean(net, extra=()):
    payload = sent(net)
    assert net.cloud, "nothing reached the mock cloud, so the test would prove nothing"
    for s in list(SECRETS) + list(extra):
        assert s not in payload, s


def signed_in(srv):
    c = C(srv)
    c.login()
    return c


# --- the intake decision ----------------------------------------------------------------------

@pytest.mark.parametrize("name,text", [
    ("t.csv", csv_text(ROWS[:2])),
    ("t.csv", "Date,Memo,Amount\n2026-10-01,CORNER SHOP,-3.10\n"),
    ("export.csv", csv_text(ROWS, header=False)),
    ("hdfc.csv", "Txn Date,Narration,Withdrawal Amt,Deposit Amt,Balance\n05/10/2026,UPI SWIGGY,450.00,,1,23,456.78\n"),
    ("stmt.txt", "Statement period Oct 2026\n10/01/2026 SAFEWAY STORE 12.50 1,000.00\n"),
])
def test_financial_is_recognised_whatever_the_size(name, text):
    assert finance.classify(name, text)


@pytest.mark.parametrize("name,text", [
    ("notes.txt", "Remember to buy milk and call the dentist on Tuesday."),
    ("recipe.csv", "Ingredient,Quantity\nflour,2 cups\nsugar,1 cup\n"),
])
def test_ordinary_files_are_not_swept_up(name, text):
    assert finance.classify(name, text) == ""


def test_unparseable_financial_document_has_no_summary_and_stays_local(srv, net):
    c = signed_in(srv)
    upload(c, "bank_statement.txt", b"Account statement. Opening balance and closing balance are shown. Withdrawal and deposits listed below as images.")
    ev = ask_cloud(c)
    assert ev[-1][0] == "needs_approval" and net.cloud == []


# --- what reaches the cloud --------------------------------------------------------------------

def test_two_row_csv(srv, net):
    c = signed_in(srv)
    upload(c, "tiny.csv", csv_text(ROWS[:2]).encode())
    assert ask_cloud(c)[-1][0] == "done"
    assert_clean(net)


def test_small_csv_with_decimal_amounts(srv, net):
    c = signed_in(srv)
    upload(c, "small.csv", csv_text(ROWS[:5]).encode())
    assert ask_cloud(c)[-1][0] == "done"
    assert_clean(net)


def test_large_statement_is_summarised_with_category_totals(srv, net):
    rows = [(f"2026-{1 + i % 9:02d}-{1 + i % 27:02d}", ("ACME PHARMACY", "ZEBRA GROCERS", "JOES CAFE")[i % 3], f"-{10 + i * 1.37:.2f}") for i in range(400)]
    c = signed_in(srv)
    upload(c, "big.csv", csv_text(rows).encode())
    assert ask_cloud(c)[-1][0] == "done"
    payload = sent(net)
    assert "Spending by category" in payload and "groceries" in payload
    assert_clean(net, extra=[r[2] for r in rows[:50]])


def test_xlsx_spreadsheet(srv, net):
    rows = [["Date", "Description", "Amount"]] + [list(r) for r in ROWS]
    c = signed_in(srv)
    assert upload(c, "ledger.xlsx", xlsx_bytes(rows))[0] == 200
    assert ask_cloud(c)[-1][0] == "done"
    assert_clean(net)


def test_pdf_financial_statement(srv, net):
    lines = ["Statement period Oct 2026"] + [f"10/{d[8:]}/2026 {m} {a.lstrip('-')} {1000 - 10 * i}.00" for i, (d, m, a) in enumerate(ROWS[:7])]
    c = signed_in(srv)
    assert upload(c, "statement.pdf", pdf_bytes(lines))[0] == 200
    assert ask_cloud(c)[-1][0] == "done"
    assert_clean(net)


def test_indian_rupees_and_day_first_dates(srv, net):
    text = "Txn Date,Narration,Withdrawal Amt,Deposit Amt,Balance\n" + "\n".join(
        f"{d:02d}/10/2026,UPI ZEBRA GROCERS {d},{d * 111}.37,,{900000 - d}.00" for d in range(13, 19)) + "\n"
    r = finance.sanitize("hdfc.csv", text)
    assert r.ok and r.rows >= 6 and "Oct 2026" in r.text
    c = signed_in(srv)
    upload(c, "hdfc.csv", text.encode())
    assert ask_cloud(c)[-1][0] == "done"
    payload = sent(net)
    for s in ("ZEBRA", "13/10/2026", "1443.37"):
        assert s not in payload


def test_european_amounts_and_negatives_parse():
    assert finance.parse_amount("1.234,56 €")[0] == finance.parse_amount("1,234.56")[0]
    assert finance.parse_amount("(24.50)")[0] < 0 and finance.parse_amount("-₹1,20,000.00")[0] < 0 and finance.parse_amount("120.00 DR")[0] < 0


def test_negative_amounts_count_as_spending():
    r = finance.sanitize("a.csv", csv_text(ROWS))
    assert "Total spending" in r.text and "Total income" in r.text and "groceries" in r.text


def test_merchant_names_without_labels(srv, net):
    c = signed_in(srv)
    upload(c, "export.csv", csv_text(ROWS, header=False).encode())
    assert ask_cloud(c)[-1][0] == "done"
    assert_clean(net)


def test_transactions_split_across_rag_chunks_never_go_out_as_chunks(srv, net):
    rows = [(f"2026-10-{1 + i % 28:02d}", "ZEBRA GROCERS" if i % 2 else "ACME PHARMACY", f"-{50 + i}.{i % 100:02d}") for i in range(300)]
    c = signed_in(srv)
    upload(c, "chunks.csv", csv_text(rows).encode())
    assert ask_cloud(c, "How much went on groceries?")[-1][0] == "done"
    payload = sent(net)
    assert payload.count("financial summary") == 1  # one summary, not one per retrieved passage
    for r in rows[:40]:
        assert r[2] not in payload
    assert_clean(net)


def test_the_wire_not_just_the_summary_function(srv, net):
    c = signed_in(srv)
    upload(c, "t.csv", csv_text().encode())
    ask_cloud(c)
    text = " ".join(m["content"] for m in net.cloud[0]["messages"])
    assert "summary" in text.lower() and "ACME" not in text
