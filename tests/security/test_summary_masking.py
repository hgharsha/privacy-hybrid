"""V3: what the cloud receives for a financial statement is checked at the wire: transaction-level data is absent and the safe aggregates survive
ordinary masking. Synthetic data only."""
import json

from tests.security.test_financial import ask_cloud, csv_text, signed_in, upload, user_says_yes  # noqa: F401 (autouse fixture)

MERCH = ("ACMEXPHARMACY", "ZEBRAXGROCERS", "JOESXCAFE")


def rows():
    out = []
    for i in range(60):
        out.append((f"2026-{9 + i % 2:02d}-{1 + i % 27:02d}", MERCH[i % 3] if i % 7 else "ORBITXPAYROLL", f"-{40 + i * 3}.{i % 100:02d}" if i % 7 else "2417.31"))
    return out


def wire(net):
    return " ".join(m["content"] for r in net.cloud for m in r["messages"])


def test_aggregates_survive_and_transactions_do_not(srv, net):
    r = rows()
    c = signed_in(srv)
    upload(c, "export.csv", csv_text(r).encode())
    assert ask_cloud(c, "Where does my money go?")[-1][0] == "done"
    text = wire(net)
    assert "Total income" in text and "Total spending" in text and "Net" in text  # totals
    assert "Sep 2026" in text and "Oct 2026" in text  # reporting period
    assert "Spending by category" in text and "% of spending" in text  # category totals
    assert "[AMOUNT" not in text and "[DATE" not in text and "[TXN" not in text  # not masked away into uselessness
    for x in MERCH + ("ORBITXPAYROLL", "2417.31", "2026-09-01", "2026-10-02"):
        assert x not in text, x
    for _, _, a in r[:30]:
        assert a not in text, a  # no individual row amount


def test_account_numbers_and_ids_in_a_statement_never_leave(srv, net):
    r = rows()
    body = "Account Number 4417123456789113\nSSN 078-05-1120\nDate,Description,Amount\n" + "\n".join(",".join(x) for x in r) + "\n"
    c = signed_in(srv)
    upload(c, "export.csv", body.encode())
    ev = ask_cloud(c, "Summarise my spending")
    text = wire(net)
    for x in ("4417123456789113", "078-05-1120"):
        assert x not in text
    assert ev[-1][0] in ("done", "needs_approval")


def test_a_summary_with_a_leak_is_not_sent(monkeypatch):
    """A summary is not trusted because it is called one: Tier 1 data inside it stops the send (pipeline check)."""
    from privhybrid import pipeline
    from privhybrid.ingest import Document
    from privhybrid.vault import NeedsApproval
    d = Document("s.csv", "x", [], "table", "Totals fine. Card 4111 1111 1111 1111 appeared.", "s.csv")
    try:
        pipeline.run("hi", [d], mode="claude", approve=lambda info: True)
        raise AssertionError("should have stopped")
    except NeedsApproval:
        pass
