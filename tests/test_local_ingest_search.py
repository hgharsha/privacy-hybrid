import io
import json
import zipfile

import pytest

from privhybrid import egress, ingest, local, providers
from privhybrid.vault import NeedsApproval, Vault

PAD = " The weather was mild and the report was short and clear." * 12


# --- local second pass -----------------------------------------------------------------------

def fake_ask(answer):
    return lambda profile, system, text, log=None: answer


def test_second_pass_keeps_only_real_leftovers():
    text = "Paid [AMOUNT_1]. Contact Dana Whitfield at 10 Example Street."
    out = local.second_pass(text, ask=fake_ask("- Dana Whitfield\n10 Example Street\n[AMOUNT_1]\nInvented Person\nNONE"))
    assert out == ["Dana Whitfield", "10 Example Street"]
    assert local.second_pass(text, ask=fake_ask("NONE")) == []


@pytest.mark.strict
def test_claude_route_requires_the_local_check(monkeypatch):
    sent = []
    monkeypatch.setattr(providers, "chat", lambda p, m, t=0: sent.append(m) or providers.Reply("ok", "claude_cli", "", "x"))
    msg = [{"role": "user", "content": "Plain public question about rates." + PAD}]
    with pytest.raises(NeedsApproval):
        egress.send("claude", msg, Vault())  # no checker: refuse
    assert sent == []
    egress.send("claude", msg, Vault(), checker=lambda t: [])
    assert len(sent) == 1


@pytest.mark.strict
def test_checker_hit_or_failure_blocks(monkeypatch):
    sent = []
    monkeypatch.setattr(providers, "chat", lambda p, m, t=0: sent.append(m) or providers.Reply("ok", "claude_cli", "", "x"))
    msg = [{"role": "user", "content": "Ask the neighbour Dana about it." + PAD}]
    with pytest.raises(NeedsApproval):
        egress.send("claude", msg, Vault(), checker=lambda t: ["Dana"])
    def boom(t):
        raise TimeoutError()
    with pytest.raises(NeedsApproval):
        egress.send("claude", msg, Vault(), checker=boom)
    assert sent == []


# --- query gate and search -------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "my balance of $4,250.00 vs savings rates",
    "rates for Maria Delgado-Whitfield",
    "mortgage rates for 100 Example Lane",
    "email jane.doe@example.com bank offers",
    "account 123456789012 interest",
    "ZIP 78701 DOB: 03/14/1985 rates",
    "explain [AMOUNT_1] growth",
    "x " * 150,
])
def test_query_gate_blocks_personal_detail(bad):
    with pytest.raises(NeedsApproval):
        egress.check_query(bad)


def test_query_gate_allows_generic():
    assert egress.check_query("current 5-year CD rates US banks") == "current 5-year CD rates US banks"


def test_search_refuses_non_local_and_blocked_queries(monkeypatch):
    called = []
    monkeypatch.setattr(providers, "open_local", lambda *a, **k: called.append(a))
    with pytest.raises(egress.EgressBlocked):
        egress.search("cd rates", base="http://searx.example.com")
    with pytest.raises(NeedsApproval):
        egress.search("rates for jane.doe@example.com")
    assert called == []


def test_search_parses_results(monkeypatch):
    body = json.dumps({"results": [{"title": "T", "url": "https://x.test", "content": "snippet"}] * 9}).encode()

    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): pass

    seen = []
    monkeypatch.setattr(providers, "open_local", lambda url, timeout=0: seen.append(url) or R(body))
    rows = egress.search("current 5-year CD rates", limit=3)
    assert len(rows) == 3 and rows[0]["title"] == "T" and "127.0.0.1:8888" in seen[0]


# --- file intake -----------------------------------------------------------------------------

def test_text_file_and_filename_scan():
    d = ingest.extract("report_for_123-45-6789.txt", b"hello world")
    assert d.name == "document.txt" and any("Filename" in n for n in d.notes)
    assert ingest.extract("jane.doe@example.com-statement.csv", b"a,b").name == "document.csv"
    assert ingest.extract("budget.csv", b"a,b\n1,2").name == "budget.csv"


def test_docx_text_and_metadata_not_read():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<w:p><w:t>Hello body</w:t></w:p>")
        z.writestr("docProps/core.xml", "<dc:creator>SECRET AUTHOR</dc:creator>")
    d = ingest.extract("note.docx", buf.getvalue())
    assert "Hello body" in d.text and "SECRET AUTHOR" not in d.text


@pytest.mark.parametrize("name,data", [("scan.png", b"\x89PNG"), ("blob.bin", b"\x00\x01"), ("empty.txt", b"   "),
                                       ("bad.pdf", b"not a pdf"), ("big.txt", b"x" * (ingest.MAX_BYTES + 1))])
def test_unreadable_files_are_refused(name, data):
    with pytest.raises(ingest.Unreadable):
        ingest.extract(name, data)


def test_docx_zip_bomb_refused(monkeypatch):
    monkeypatch.setattr(ingest, "MAX_XML_BYTES", 100)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", "<w:t>a</w:t>" * 100)
    with pytest.raises(ingest.Unreadable, match="too large"):
        ingest.extract("bomb.docx", buf.getvalue())
