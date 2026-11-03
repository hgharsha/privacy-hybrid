import pytest

from privhybrid import egress, pipeline, providers
from privhybrid.ingest import Document
from privhybrid.vault import NeedsApproval, Vault

PAD = " The weather was mild and the report was short and clear." * 12


class Script:
    """providers.chat stand-in. Replies depend on the call; everything sent is recorded."""

    def __init__(self):
        self.calls, self.cloud_fail = [], None

    def __call__(self, profile, messages, timeout=0):
        system = " ".join(m["content"] for m in messages if m["role"] == "system")
        self.calls.append((profile["provider"], messages))
        if profile["provider"] == "claude_cli":
            if self.cloud_fail:
                raise self.cloud_fail
            return providers.Reply("Reach [EMAIL_1] about it.", "claude_cli", "", "x")
        if "ONE short web search query" in system:
            text = "current 5-year CD rates"
        elif "check text for privacy" in system:
            text = "NONE"
        elif "Summarize this document" in system:
            text = "Summary: steady balances, one payroll deposit."
        else:
            text = "local answer"
        return providers.Reply(text, profile["provider"], profile.get("model", ""), "x")

    def sent_to(self, provider):
        return [m for p, m in self.calls if p == provider]


@pytest.fixture
def script(monkeypatch):
    s = Script()
    monkeypatch.setattr(providers, "chat", s)
    monkeypatch.setattr(egress, "search", lambda q, log=None, **k: [{"title": "Rates", "url": "https://x.test/r", "snippet": "4.5%"}])
    return s


def test_routing_rules():
    doc = [Document("a.csv", "x", [])]
    assert pipeline.classify("What is in this file?", doc) == "local"
    assert pipeline.classify("What are current CD rates?", []) == "public_fact"
    assert pipeline.classify("Compare my statement to current market rates", doc) == "public_fact"
    assert pipeline.classify("hello", [], mode="claude") == "claude"
    assert pipeline.classify("anything", doc, mode="local") == "local"


def test_local_route_keeps_everything_on_the_mac(script):
    doc = Document("s.txt", "Jane Doe, jane.doe@example.com, $4,250.00" + PAD, [])
    ans = pipeline.run("Summarise this", [doc], mode="local")
    assert ans.route == "local" and ans.text == "local answer"
    assert {p for p, _ in script.calls} == {"ollama"}


def test_public_fact_path_sends_only_a_generic_query_out(script):
    doc = Document("s.txt", "Jane Doe, jane.doe@example.com, balance $4,250.00" + PAD, [])
    ans = pipeline.run("How do my savings compare to current CD rates?", [doc])
    assert ans.route == "public_fact" and ans.sources == ["https://x.test/r"]
    assert {p for p, _ in script.calls} == {"ollama"}  # no cloud model involved


def test_empty_search_is_retried_then_flagged(script, monkeypatch):
    calls = []
    monkeypatch.setattr(egress, "search", lambda q, log=None: calls.append(q) or [])
    ans = pipeline.run("What are current CD rates?", [])
    assert len(calls) == 2 and any("found nothing" in n for n in ans.notices)


def test_untrusted_web_text_is_fenced(script):
    pipeline.run("What are current CD rates?", [])
    final = script.sent_to("ollama")[-1]
    assert any("untrusted" in m["content"] for m in final) and any("<web_results>" in m["content"] for m in final)


def test_claude_route_masks_checks_and_restores(script):
    doc = Document("s.txt", "Contact jane.doe@example.com about the account." + PAD, [])
    ans = pipeline.run("Who should I contact?", [doc], mode="claude")
    sent = str(script.sent_to("claude_cli"))
    assert "jane.doe@example.com" not in sent and "[EMAIL_1]" in sent
    assert "jane.doe@example.com" in ans.text
    assert "local privacy check passed" in ans.steps


def test_dense_document_is_summarized_before_cloud(script):
    dense = "Payroll $12,480.55 Rent $1,902.10 Food $87.43 Fuel $60.12 " * 80
    pipeline.run("Summarise spending", [Document("s.csv", dense, [])], mode="claude")
    assert any("Summary: steady" in str(m) for m in script.sent_to("claude_cli"))
    assert "12,480.55" not in str(script.sent_to("claude_cli"))


def test_cloud_failure_degrades_to_local_only(script):
    script.cloud_fail = providers.Unavailable("down")
    ans = pipeline.run("Who should I contact?", [Document("s.txt", "Contact jane.doe@example.com." + PAD, [])], mode="claude")
    assert ans.route == "local" and ans.notices and ans.text == "local answer"
    assert len(script.sent_to("claude_cli")) == 1  # one try, no retry


def test_tier1_in_a_file_stops_the_cloud_route(script):
    with pytest.raises(NeedsApproval):
        pipeline.run("Summarise", [Document("s.txt", "SSN 123-45-6789" + PAD, [])], mode="claude")
    assert script.sent_to("claude_cli") == []


def test_progress_reports_each_step_in_order(script):
    seen = []
    doc = Document("s.txt", "Contact jane.doe@example.com about the account." + PAD, [])
    ans = pipeline.run("Who should I contact?", [doc], mode="claude", progress=seen.append)
    assert seen == ans.steps and seen[0] == "route: claude" and seen[-1] == "restored values locally"


def test_local_check_flags_a_labelled_item_and_follows_the_configured_model(monkeypatch):
    from privhybrid import local
    seen = []

    def ask(profile, system, text, log=None):
        seen.append(profile["model"])
        return "Name: John Smith\nJohn Smith (employer)\nsomething not in the text"
    monkeypatch.setenv("PRIVHYBRID_CHECK_MODEL", "chosen:1")  # set after import: it must still be used
    assert local.second_pass("Please call John Smith tomorrow.", ask=ask) == ["Name: John Smith", "John Smith (employer)"]
    assert seen == ["chosen:1"]


def test_cloud_fallback_uses_the_configured_model_and_timeout(monkeypatch):
    calls = []

    def fake_send(route, messages, vault, profile=None, log=None, timeout=0, checker=None):
        calls.append((route, (profile or {}).get("model"), timeout))
        if route == "claude":
            raise providers.Unavailable("down")
        return egress.Result("ok", route) if hasattr(egress, "Result") else None
    monkeypatch.setenv("PRIVHYBRID_ANSWER_MODEL", "mine:2")
    monkeypatch.setattr(egress, "send", fake_send)
    egress.send_with_fallback("claude", [{"role": "user", "content": "hi"}], Vault(), timeout=33)
    assert calls[-1] == ("local", "mine:2", 33)


def test_check_model_repeating_a_placeholder_is_not_a_leak():
    from privhybrid import local
    ask = lambda profile, system, text, log=None: "Name: [PERSON_1]\nAmount ([AMOUNT_2])"
    assert local.second_pass("Call [PERSON_1] about [AMOUNT_2].", ask=ask) == []
