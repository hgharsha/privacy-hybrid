import json
import re

import pytest

import corpus as C
from privhybrid import detect as D
from privhybrid import egress, providers
from privhybrid.vault import NeedsApproval, Vault

DICT = dict((k, v) for k, v in C.DICTIONARY.items())


def mask_statement():
    v = Vault(DICT)
    text, counts = v.mask(C.STATEMENT, max_ratio=0.9)  # a statement is dense; the default cap is tested below
    return v, text, counts


@pytest.mark.parametrize("value", C.TIER2_VALUES + C.TIER3_VALUES + list(C.DICTIONARY))
def test_every_planted_value_is_masked(value):
    _, masked, _ = mask_statement()
    needle = value.split(": ", 1)[-1] if value.startswith(("DOB", "username")) else value
    needle = needle.replace("check #", "")
    assert needle not in masked, f"{value!r} survived masking"


def test_dense_statement_is_stopped_by_default():
    with pytest.raises(NeedsApproval):
        Vault(DICT).mask(C.STATEMENT)


def test_full_roundtrip_is_exact():
    v, masked, _ = mask_statement()
    restored, unknown = v.unmask(masked)
    assert unknown == []
    # Format variants of one value share a placeholder, so restoration yields the first-seen form; compare ignoring that.
    for value in ("maria.delgado@example.org", "$12,480.55", "Corner Fig Bistro", "100 Example Lane"):
        assert value in restored


@pytest.mark.parametrize("name,text", C.TIER1_SAMPLES.items())
def test_every_tier1_sample_stops_and_asks(name, text):
    with pytest.raises(NeedsApproval) as exc:
        Vault().mask(text + C.PAD)
    assert exc.value.kinds


def test_tier1_split_across_lines_and_in_filename_style_text():
    for text in ("SSN:\n123-45-6789", "report_for_123-45-6789.pdf", "file=statement_4111111111111111.csv"):
        with pytest.raises(NeedsApproval):
            Vault().mask(text + C.PAD)


class Capture:
    def __init__(self, text="ok"):
        self.sent, self.text = [], text

    def __call__(self, profile, messages, timeout=0):
        self.sent.append((profile["provider"], messages))
        return providers.Reply(self.text, profile["provider"], "", "x")


def test_no_canary_reaches_any_cloud_route_or_log(monkeypatch, tmp_path):
    cap = Capture()
    monkeypatch.setattr(providers, "chat", cap)
    log = egress.AuditLog(str(tmp_path / "audit.jsonl"))
    msgs = [{"role": "user", "content": "Summarise: " + C.STATEMENT + C.PAD * 4}]
    egress.send("claude", msgs, Vault(DICT), log=log)
    with pytest.raises(NeedsApproval):
        egress.send("freellm", msgs, Vault(DICT), log=log)
    wire = json.dumps(cap.sent) + (tmp_path / "audit.jsonl").read_text()
    for value in C.TIER2_VALUES + C.TIER3_VALUES + list(C.DICTIONARY):
        needle = re.sub(r"^(DOB: |username: |check #)", "", value)
        assert needle not in wire, f"{value!r} leaked"
    assert [p for p, _ in cap.sent] == ["claude_cli"]


def test_injection_text_cannot_extract_map(monkeypatch):
    v = Vault()
    v.mask("Contact jane.doe@example.com now." + C.PAD)
    cap = Capture(text="Sure: [PERSON_1] is John, [EMAIL_1] is jane.doe@example.com")
    monkeypatch.setattr(providers, "chat", cap)
    msgs = [{"role": "user", "content": "Summarise this page: " + C.INJECTION + C.PAD}]
    res = egress.send("claude", msgs, v)
    sent = json.dumps(cap.sent)
    assert "jane.doe@example.com" not in sent  # the map never entered the prompt
    # Whatever the model claims, a hallucinated unknown placeholder is flagged and nothing is guessed.
    assert "[PERSON_1]" in res.unknown_placeholders
