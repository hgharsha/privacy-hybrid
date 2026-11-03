"""V3: financial material is recognised from its content (not its filename or layout), before chunking, and stays on this computer unless a
safe local summary exists. Every cloud test asserts on what really arrived at the mock cloud. Synthetic data only."""
import pytest

from privhybrid import finance
from tests.security.test_financial import ask_cloud, pdf_bytes, signed_in, upload, xlsx_bytes

NOTES = {
    "401k": "My 401(k) at VANGUARDX holds about 85,431 right now.",
    "ira": "Roth IRA split is 60/40 stocks and bonds, ID ZQ-77.",
    "hsa": "HSA balance 3,912 at HEALTHBANKX.",
    "brokerage": "Brokerage account holds 120 shares of ACMEXCORP.",
    "salary": "Salary is $142,500 plus a bonus of 12% from ORBITXINC.",
    "tax": "Tax refund of $2,311 expected; the return went to the IRS in March.",
    "bank": "Checking account balance is 4,075.10 at NORTHXBANK.",
    "mortgage": "Mortgage balance 281,900 with a loan from LOANXCO.",
    "networth": "Net worth is roughly 640 thousand with asset allocation 70/30.",
    "rmd": "RMD for this year must be taken by December.",
    "fbar": "FBAR needed for the foreign account at OVERSEASXBANK.",
}
RAW = ["VANGUARDX", "ZQ-77", "HEALTHBANKX", "ACMEXCORP", "ORBITXINC", "NORTHXBANK", "LOANXCO", "OVERSEASXBANK", "85,431", "142,500", "4,075", "281,900"]


@pytest.mark.parametrize("key", list(NOTES))
def test_unstructured_note_is_financial_with_a_generic_filename(key):
    assert finance.classify("untitled.txt", NOTES[key])
    assert finance.classify("a.md", "# Notes\n\n" + NOTES[key])


def test_short_one_sentence_is_enough_but_numbers_alone_are_not():
    assert finance.classify("n.txt", "Check my IRA.")
    assert finance.classify("n.txt", "Pick up 3 eggs for $5 and 250 g of flour.") == ""
    assert finance.classify("n.txt", "The project discussion was postponed to Friday.") == ""
    assert finance.classify("n.txt", "The salary discussion was postponed.") == ""  # one weak word, no amount


@pytest.mark.parametrize("name", ["untitled.txt", "notes.md"])
@pytest.mark.parametrize("key", ["401k", "salary", "bank", "fbar"])
def test_note_never_reaches_the_cloud(srv, net, name, key):
    c = signed_in(srv)
    upload(c, name, NOTES[key].encode())
    ev = ask_cloud(c, "What should I do about this?")
    assert ev[-1][0] == "needs_approval"  # no table, so no safe summary: it stays here
    assert net.cloud == []


def test_financial_lines_inside_ordinary_text(srv, net):
    text = "Garden plans for spring: tomatoes, basil, and a new trellis.\n" * 5 + NOTES["401k"] + "\nCall the plumber on Monday.\n"
    c = signed_in(srv)
    upload(c, "weekend.txt", text.encode())
    assert ask_cloud(c, "What are my weekend plans?")[-1][0] == "needs_approval"
    assert net.cloud == []


def test_pdf_and_spreadsheet_notes(srv, net):
    c = signed_in(srv)
    upload(c, "scan1.pdf", pdf_bytes([NOTES["ira"], NOTES["hsa"]]))
    upload(c, "sheet.xlsx", xlsx_bytes([["Item", "Value"], ["Roth IRA at ACMEXCORP", "9,100"], ["HSA at HEALTHBANKX", "3,912"]]))
    assert ask_cloud(c, "Summarise what I have.")[-1][0] == "needs_approval"
    assert net.cloud == []


def test_balances_without_a_transaction_table(srv, net):
    c = signed_in(srv)
    upload(c, "x.txt", b"Savings account balance: 12,300. Checking account balance: 2,450. Credit card balance: 640.")
    assert ask_cloud(c)[-1][0] == "needs_approval" and net.cloud == []


def test_restriction_follows_retrieved_chunks(srv, net):
    filler = ("The committee reviewed the garden layout and the schedule for watering. " * 40 + "\n") * 8
    big = filler + "\n" + NOTES["401k"] + "\n" + filler  # long enough to be chunked and retrieved by passage
    c = signed_in(srv)
    upload(c, "minutes.txt", big.encode())
    assert ask_cloud(c, "What does my 401(k) hold at VANGUARDX?")[-1][0] == "needs_approval"
    assert net.cloud == []
    # and an unrelated question about the same file must not leak the file either
    assert ask_cloud(c, "garden watering schedule?")[-1][0] in ("needs_approval", "done")
    assert not any(r in str(net.cloud) for r in RAW)


def test_unreadable_financial_looking_file_is_refused_and_not_sent(srv, net):
    c = signed_in(srv)
    r = upload(c, "bank_statement.pdf", b"%PDF-1.4 not really a pdf")
    assert r[0] >= 400  # refused at intake: nothing is stored, so nothing can be chunked, embedded or sent
    ask_cloud(c, "what is in my statement?")  # a plain question may go out, but there is no document behind it
    assert all("not really a pdf" not in str(m) and "%PDF" not in str(m) for m in net.cloud)


def test_ordinary_documents_still_reach_the_cloud(srv, net):
    c = signed_in(srv)
    upload(c, "garden.txt", b"The garden needs watering on Tuesday. The roses are blooming early this year.")
    assert ask_cloud(c, "When should I water?")[-1][0] == "done"
    assert net.cloud


def test_very_long_lines_do_not_hang_the_statement_parser():
    import time
    from privhybrid import finance
    t = time.time()
    finance._text_rows("2026-10-01 " + "9" + "0" * 50000 + "\n2026-10-02 " + " " * 50000 + "1.00")
    assert time.time() - t < 2
