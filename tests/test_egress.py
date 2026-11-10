import os
import hashlib
import json
import socket

import pytest

from privhybrid import egress, providers
from privhybrid.vault import NeedsApproval, Vault

FILLER = " The weather was mild and the report was short and clear." * 12
PRIVATE = "Email jane.doe@example.com about the $4,250.00 deposit." + FILLER
CANARIES = ["jane.doe@example.com", "4,250.00", "123-45-6789", "4111 1111 1111 1111"]


class Fake:
    """Stands in for providers.chat and records exactly what would leave."""

    def __init__(self, text="ok", fail=None):
        self.sent, self.profiles, self.text, self.fail = [], [], text, fail

    def __call__(self, profile, messages, timeout=0):
        self.profiles.append(profile)
        if self.fail and profile["provider"] != "ollama":
            raise self.fail
        self.sent.append(messages)
        return providers.Reply(self.text, profile["provider"], profile.get("model", ""), "x")


@pytest.fixture
def fake(monkeypatch):
    f = Fake()
    monkeypatch.setattr(providers, "chat", f)
    return f


def wire(f):
    return json.dumps(f.sent)


def test_claude_gets_placeholders_only_and_reply_is_unmasked(fake):
    v = Vault()
    fake.text = "I would write to [EMAIL_1] and mention [AMOUNT_1] and [PERSON_7]."
    res = egress.send("claude", [{"role": "user", "content": PRIVATE}], v)
    for c in CANARIES:
        assert c not in wire(fake)
    assert "[EMAIL_1]" in wire(fake)
    assert "jane.doe@example.com" in res.text and "$4,250.00" in res.text
    assert res.unknown_placeholders == ["[PERSON_7]"]


def test_tier1_never_leaves_and_asks(fake):
    with pytest.raises(NeedsApproval):
        egress.send("claude", [{"role": "user", "content": "SSN 123-45-6789" + FILLER}], Vault())
    assert fake.sent == []


def test_freellm_only_generic_text(fake):
    egress.send("freellm", [{"role": "user", "content": "What are typical five year CD rates?"}], Vault())
    assert len(fake.sent) == 1
    for bad in (PRIVATE, "Explain [AMOUNT_1] growth", "Rates for ZIP 78701, DOB: 03/14/1985 holders"):
        with pytest.raises(NeedsApproval):
            egress.send("freellm", [{"role": "user", "content": bad}], Vault())
    assert len(fake.sent) == 1


def test_local_route_may_see_raw_text(fake):
    egress.send("local", [{"role": "user", "content": PRIVATE}], Vault())
    assert "jane.doe@example.com" in wire(fake)


@pytest.mark.parametrize("route,profile", [
    ("local", {"provider": "ollama", "model": "m", "base_url": "http://192.168.1.50:11434"}),
    ("freellm", {"provider": "freellmapi", "model": "auto", "base_url": "http://192.168.1.50:3001/v1"}),
    ("claude", {"provider": "openrouter", "model": "x"}),
    ("claude", {"provider": "anthropic", "model": "x", "api_key": "k"}),
    ("freellm", {"provider": "ollama", "model": "x"}),
])
def test_wrong_destination_refused(fake, route, profile):
    with pytest.raises(egress.EgressBlocked):
        egress.send(route, [{"role": "user", "content": "hello"}], Vault(), profile=profile)
    assert fake.sent == []


def test_unknown_route_refused(fake):
    with pytest.raises(egress.EgressBlocked):
        egress.send("openrouter", [{"role": "user", "content": "hi"}], Vault())


def test_fallback_is_local_only_and_never_retries_cloud(monkeypatch):
    f = Fake(text="local answer", fail=providers.Unavailable("down"))
    monkeypatch.setattr(providers, "chat", f)
    res = egress.send_with_fallback("claude", [{"role": "user", "content": PRIVATE}], Vault())
    assert res.degraded and res.route == "local" and "answered locally" in res.notice
    assert [p["provider"] for p in f.profiles] == ["claude_cli", "ollama"]  # one cloud try, then local


def test_fallback_does_not_swallow_approval(fake):
    with pytest.raises(NeedsApproval):
        egress.send_with_fallback("claude", [{"role": "user", "content": "SSN 123-45-6789" + FILLER}], Vault())


def test_audit_log_has_no_raw_values(fake, tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    log = egress.AuditLog(str(path))
    egress.send("claude", [{"role": "user", "content": PRIVATE}], Vault(), log=log)
    with pytest.raises(NeedsApproval):
        egress.send("claude", [{"role": "user", "content": "SSN 123-45-6789 4111 1111 1111 1111" + FILLER}], Vault(), log=log)
    data = path.read_text()
    for c in CANARIES + ["Email", "weather"]:
        assert c not in data
    rows = [json.loads(x) for x in data.splitlines()]
    assert [r["outcome"] for r in rows] == ["ok", "blocked"] and rows[0]["kinds"]["EMAIL"] == 1


def test_loopback_guard_blocks_other_hosts():
    with egress.loopback_only():
        s = socket.socket()
        with pytest.raises(egress.EgressBlocked):
            s.connect(("93.184.216.34", 80))
        with pytest.raises(egress.EgressBlocked):
            s.connect(("192.168.1.50", 11434))
        s.close()
    assert socket.socket.connect.__name__ == "connect"  # restored


def test_every_outbound_call_site_is_in_known_files():
    """Static check for T6: only providers.py (called from egress.send) may open connections; lockdown.py may start osascript."""
    import pathlib
    import re
    src = pathlib.Path(egress.__file__).parent
    pattern = re.compile(r"urlopen|subprocess\.|socket\.create_connection|requests\.|httpx\.|http\.client")
    offenders = {p.name for p in src.glob("*.py") if pattern.search(p.read_text(encoding="utf-8"))}
    assert offenders <= {"providers.py", "egress.py", "lockdown.py", "fsutil.py"}, offenders  # lockdown.py only starts /usr/bin/osascript, fsutil.py only runs icacls on Windows (no network), reviewed as T6-exempt


@pytest.mark.skipif(os.name == "nt", reason="mode bits do not exist on Windows; see test_windows_acl")
def test_log_dir_is_private(tmp_path):
    log = egress.AuditLog(str(tmp_path / "logs" / "audit.jsonl"))
    log.write(route="local")
    assert (tmp_path / "logs").stat().st_mode & 0o077 == 0


def test_audit_log_chain_shows_an_edited_line(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    log = egress.AuditLog(str(path))
    for i in range(4):
        log.write(route="local", n=i)
    assert egress.verify_chain(str(path)) is None
    lines = path.read_text().splitlines()
    lines[1] = lines[1].replace('"n": 1', '"n": 9')
    path.write_text("\n".join(lines) + "\n")
    assert egress.verify_chain(str(path)) == 3  # the line after the edited one no longer matches
    lines2 = [lines[0], lines[2], lines[3]]  # a deleted line
    path.write_text("\n".join(lines2) + "\n")
    assert egress.verify_chain(str(path)) == 2


@pytest.mark.skipif(os.name == "nt", reason="mode bits do not exist on Windows; see test_windows_acl")
def test_audit_log_rotates_and_keeps_the_chain(tmp_path, monkeypatch):
    path = tmp_path / "logs" / "audit.jsonl"
    monkeypatch.setattr(egress, "AUDIT_MAX_BYTES", 300)
    monkeypatch.setattr(egress, "AUDIT_KEEP", 2)
    log = egress.AuditLog(str(path))
    for i in range(40):
        log.write(route="local", n=i)
    archives = sorted(p for p in path.parent.iterdir() if p.name.startswith("audit.jsonl.") and p.name[12:].isdigit())
    assert 1 <= len(archives) <= 2  # rotated, and the oldest beyond the limit are gone
    assert path.stat().st_size < 600 and path.stat().st_mode & 0o077 == 0
    assert all(p.stat().st_mode & 0o077 == 0 for p in archives)
    assert egress.verify_chain(str(path)) is None
    first = json.loads(path.read_text().splitlines()[0])
    newest = max(archives, key=lambda p: int(p.name[12:]))
    assert first["prev"] == hashlib.sha256(newest.read_bytes().splitlines()[-1]).hexdigest()  # chain continues across the rotation


def test_refused_connection_is_unreachable_with_and_without_a_cancel_token():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    url = f"http://127.0.0.1:{port}/api/chat"
    for token in (None, providers.Cancel()):
        providers.ACTIVE.cancel = token
        try:
            with pytest.raises(providers.Unreachable):
                providers._post(url, {}, {}, 10, "Ollama")  # Windows reports a refused loopback connect after about 2s
        finally:
            providers.ACTIVE.cancel = None
