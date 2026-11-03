"""The generic cloud route: any OpenAI-compatible service gets the same masked text Claude would. Tested against a local mock service only;
real providers (ChatGPT, Grok, OpenRouter, ...) are NOT tested."""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from privhybrid import config, egress, keystore, pipeline, providers
from privhybrid.vault import Vault

SECRET_EMAIL = "jane.doe@example.com"
TEXT = "Please write to " + SECRET_EMAIL + " about the lease. " + "The weather was mild and the report was short and clear. " * 8


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    for k in ("PRIVHYBRID_CLOUD_PROVIDER", "PRIVHYBRID_CLOUD_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    store = {}

    def backend(op, uid, value):
        if op == "get":
            return store.get(uid)
        if op == "set":
            store[uid] = value
        else:
            store.pop(uid, None)
    monkeypatch.setattr(keystore, "_backend", backend)
    return store


@pytest.fixture
def mock(cfg):
    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.update(path=self.path, auth=self.headers.get("Authorization"), body=body)
            sent = body["messages"][-1]["content"]
            out = json.dumps({"choices": [{"message": {"content": "Reply about " + sent.split("write to ")[1].split(" ")[0]}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1", seen
    srv.shutdown()


def test_settings_validate_and_keep_the_key_out_of_the_config_file(cfg):
    with pytest.raises(ValueError):
        config.save({"cloud_provider": "openai_compat", "cloud_url": "http://api.example.com/v1", "cloud_model": "m"})  # plain http to the internet
    with pytest.raises(ValueError):
        config.save({"cloud_provider": "openai_compat", "cloud_url": "https://user:pw@api.example.com/v1", "cloud_model": "m"})
    with pytest.raises(ValueError):
        config.save({"cloud_provider": "openai_compat", "cloud_url": "https://api.example.com/v1"})  # no model
    config.save({"cloud_provider": "openai_compat", "cloud_url": "https://api.example.com/v1", "cloud_model": "some-model", "cloud_api_key": "sk-test-1234567890"})
    assert "sk-test" not in config.CONFIG_FILE.read_text()
    cur = config.current()
    assert cur["cloud_key_set"] is True and "sk-test" not in json.dumps(cur) and cur["cloud_label"] == "Cloud model (masked)"
    assert config.cloud_profile()["api_key"] == "sk-test-1234567890"
    config.save({"cloud_api_key_clear": True})
    assert config.current()["cloud_key_set"] is False


def test_default_is_claude(cfg):
    assert config.cloud_profile() == {"provider": "claude_cli", "model": ""} and config.cloud_label() == "Claude (masked)"


def test_masked_text_only_reaches_the_service_and_the_reply_is_restored(cfg, mock):
    url, seen = mock
    config.save({"cloud_provider": "openai_compat", "cloud_url": url, "cloud_model": "m1", "cloud_api_key": "sk-test-1234567890"})
    res = egress.send("claude", [{"role": "user", "content": TEXT}], Vault(), checker=lambda t: [])
    sent = json.dumps(seen["body"])
    assert SECRET_EMAIL not in sent and "[EMAIL_1]" in sent  # masked on the way out
    assert seen["auth"] == "Bearer sk-test-1234567890" and seen["path"] == "/v1/chat/completions" and seen["body"]["model"] == "m1"
    assert SECRET_EMAIL in res.text  # restored on the way back


def test_tier_1_never_reaches_the_service(cfg, mock):
    url, seen = mock
    config.save({"cloud_provider": "openai_compat", "cloud_url": url, "cloud_model": "m1", "cloud_api_key": "sk-test-1234567890"})
    with pytest.raises(Exception):
        egress.send("claude", [{"role": "user", "content": "My SSN is 123-45-6789. " + TEXT}], Vault(), checker=lambda t: [])
    assert seen == {}


def test_plain_http_to_a_remote_service_is_refused_at_send(cfg):
    with pytest.raises(egress.EgressBlocked):
        egress.send("claude", [{"role": "user", "content": TEXT}], Vault(), checker=lambda t: [],
                    profile={"provider": "openai_compat", "model": "m", "base_url": "http://api.example.com/v1", "api_key": "sk-test-1234567890"})


def test_a_cloud_name_that_resolves_to_a_private_address_is_refused(monkeypatch):
    prof = {"provider": "openai_compat", "model": "m", "base_url": "https://api.example.com/v1"}
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))])
    with pytest.raises(egress.EgressBlocked):
        with egress._cloud_access(prof):
            pass
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    with egress._cloud_access(prof):
        assert providers.PIN.target == (["93.184.216.34"], 443)  # this thread, this address, this port
    assert providers.PIN.target is None


def test_the_guard_allows_only_this_thread_this_address_and_this_port(monkeypatch):
    calls = []
    monkeypatch.setattr(socket.socket, "connect", lambda self, address: calls.append(address))  # no real network in the test
    prof = {"provider": "openai_compat", "model": "m", "base_url": "https://api.example.com/v1"}
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    with egress.loopback_only():
        s = socket.socket()
        with pytest.raises(egress.EgressBlocked):
            s.connect(("8.8.8.8", 443))  # some other address
        with egress._cloud_access(prof):
            s.connect(("93.184.216.34", 443))  # the vetted one
            with pytest.raises(egress.EgressBlocked):
                s.connect(("93.184.216.34", 22))  # same address, other port
            other = []
            t = threading.Thread(target=lambda: other.append(_blocked(s)))
            t.start(); t.join()
            assert other == [True]  # another thread gets nothing
        with pytest.raises(egress.EgressBlocked):
            s.connect(("93.184.216.34", 443))  # and nothing once the call is over
        s.close()
    assert calls == [("93.184.216.34", 443)]


def _blocked(sock):
    try:
        sock.connect(("93.184.216.34", 443))
        return False
    except egress.EgressBlocked:
        return True


def test_the_connection_goes_to_the_vetted_address_even_if_dns_changes(monkeypatch):
    seen = []

    def fake_create(addr, timeout=None, *a, **k):
        seen.append(addr)
        raise OSError("stop here")
    monkeypatch.setattr(providers.socket, "create_connection", fake_create)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])  # a later lookup would say loopback
    providers.PIN.target = (["93.184.216.34"], 443)
    try:
        with pytest.raises(providers.Unavailable):
            providers._post("https://api.example.com/v1/chat/completions", {}, {"x": 1}, 2, "cloud")
    finally:
        providers.PIN.target = None
    assert seen == [("93.184.216.34", 443)]


def test_a_redirect_is_never_followed_and_the_key_stays_put(cfg):
    hits = []

    class Target(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            hits.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
    target = HTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    class Redirect(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{target.server_address[1]}/steal")
            self.end_headers()
    red = HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=red.serve_forever, daemon=True).start()
    prof = {"provider": "openai_compat", "model": "m", "base_url": f"http://127.0.0.1:{red.server_address[1]}/v1", "api_key": "sk-test-1234567890"}
    try:
        with pytest.raises(providers.ProviderError):
            providers.chat(prof, [{"role": "user", "content": "hi"}], 5)
        assert hits == []  # the redirect target never saw the key or the text
    finally:
        red.shutdown(); target.shutdown()


def test_a_local_openai_compatible_service_needs_no_key(cfg, mock):
    url, seen = mock
    config.save({"cloud_provider": "openai_compat", "cloud_url": url, "cloud_model": "m1"})
    res = egress.send("claude", [{"role": "user", "content": TEXT}], Vault(), checker=lambda t: [])
    assert res.text.startswith("Reply") and seen["auth"] is None


def test_a_blocked_address_is_logged_and_falls_back_instead_of_crashing(cfg, monkeypatch, tmp_path):
    config.save({"cloud_provider": "openai_compat", "cloud_url": "https://api.example.com/v1", "cloud_model": "m", "cloud_api_key": "sk-test-1234567890"})
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))])
    log = egress.AuditLog(str(tmp_path / "a.jsonl"))
    with pytest.raises(providers.Unavailable):
        egress.send("claude", [{"role": "user", "content": TEXT}], Vault(), log=log, checker=lambda t: [])
    assert '"outcome": "blocked"' in (tmp_path / "a.jsonl").read_text()


def test_the_scheme_check_is_case_insensitive_and_shared(cfg):
    config.save({"cloud_provider": "openai_compat", "cloud_url": "HTTPS://api.example.com/v1", "cloud_model": "m"})
    assert egress.validate_cloud_url(config.cloud_profile()["base_url"])  # save and send agree
    with pytest.raises(egress.EgressBlocked):
        egress.validate_cloud_url("https://user:pw@api.example.com/v1")
    with pytest.raises(egress.EgressBlocked):
        egress.validate_cloud_url("https://api.example.com/v1?x=1")


def test_env_overrides_are_reported_and_a_blank_value_clears(cfg, monkeypatch):
    monkeypatch.setenv("PRIVHYBRID_CLOUD_API_KEY", "sk-from-env-1234567")
    assert config.current()["cloud_key_env"] is True and config.cloud_api_key() == "sk-from-env-1234567"
    monkeypatch.delenv("PRIVHYBRID_CLOUD_API_KEY")
    config.save({"cloud_provider": "openai_compat", "cloud_url": "https://api.example.com/v1", "cloud_model": "m"})
    config.save({"cloud_provider": "claude_cli", "cloud_url": "", "cloud_model": ""})
    assert config.current()["cloud_url"] == "" and config.current()["cloud_model"] == ""


def test_pipeline_adds_the_generic_warning_for_a_third_party_cloud(cfg, mock, monkeypatch):
    from privhybrid import local
    from privhybrid.ingest import Document
    url, seen = mock
    config.save({"cloud_provider": "openai_compat", "cloud_url": url, "cloud_model": "m1", "cloud_api_key": "sk-test-1234567890"})
    monkeypatch.setattr(local, "second_pass", lambda text, **k: [])
    ans = pipeline.run("Please write to " + SECRET_EMAIL + " about the lease.", [Document("n.txt", TEXT, [])], Vault(), mode="claude")
    assert pipeline.CLOUD_WARNING in ans.notices and "The cloud model answered" in ans.steps
    assert SECRET_EMAIL not in json.dumps(seen["body"])


def test_a_bad_port_is_refused_at_save_time(cfg):
    for url in ("https://api.example.com:99999/v1", "https://api.example.com:abc/v1"):
        with pytest.raises(ValueError):
            config.save({"cloud_provider": "openai_compat", "cloud_url": url, "cloud_model": "m"})


def test_changing_the_service_drops_the_saved_key(cfg):
    config.save({"cloud_provider": "openai_compat", "cloud_url": "https://api.provider-a.com/v1", "cloud_model": "m", "cloud_api_key": "sk-test-1234567890"})
    assert config.current()["cloud_key_set"] is True
    config.save({"cloud_url": "https://other.example.net/v1"})  # same save does not supply a key
    assert config.current()["cloud_key_set"] is False
    config.save({"cloud_url": "https://third.example.org/v1", "cloud_api_key": "sk-new-0987654321"})  # a new key with the new address is kept
    assert config.current()["cloud_key_set"] is True


def test_pinned_connection_tries_each_vetted_address_in_order(monkeypatch):
    tried = []

    def fake_create(addr, timeout=None, *a, **k):
        tried.append(addr[0])
        raise OSError("down")
    monkeypatch.setattr(providers.socket, "create_connection", fake_create)
    providers.PIN.target = (["2606:4700::1", "93.184.216.34"], 443)  # IPv6 first, no route: the IPv4 address is still tried
    try:
        with pytest.raises(providers.Unavailable):
            providers._post("https://api.example.com/v1/x", {}, {}, 2, "cloud")
    finally:
        providers.PIN.target = None
    assert tried == ["2606:4700::1", "93.184.216.34"]


def test_nested_guards_restore_the_real_connect(monkeypatch):
    before = socket.socket.connect
    with egress.loopback_only():
        with egress.loopback_only():
            pass
        assert socket.socket.connect is not before  # still guarded inside the outer block
    assert socket.socket.connect is before and socket.socket.connect_ex.__name__ == "connect_ex"


def test_a_misconfigured_cloud_address_falls_back_instead_of_erroring(cfg, monkeypatch):
    from privhybrid import local
    from privhybrid.ingest import Document
    monkeypatch.setenv("PRIVHYBRID_CLOUD_PROVIDER", "openai_compat")  # but no address or model saved
    monkeypatch.setattr(local, "second_pass", lambda text, **k: [])
    monkeypatch.setattr(pipeline, "_local", lambda *a, **k: type("R", (), {"text": "local answer"})())
    ans = pipeline.run("Who should I write to?", [Document("n.txt", TEXT, [])], Vault(), mode="claude")
    assert ans.route == "local" and ans.text == "local answer" and any("answered locally" in n for n in ans.notices)


def test_the_audit_row_names_the_host_but_not_the_key_or_path(cfg, mock, tmp_path):
    url, seen = mock
    config.save({"cloud_provider": "openai_compat", "cloud_url": url, "cloud_model": "m1", "cloud_api_key": "sk-test-1234567890"})
    log = egress.AuditLog(str(tmp_path / "a.jsonl"))
    egress.send("claude", [{"role": "user", "content": TEXT}], Vault(), log=log, checker=lambda t: [])
    row = (tmp_path / "a.jsonl").read_text()
    assert '"host": "127.0.0.1"' in row and "sk-test" not in row and "/v1" not in row


def test_a_key_saved_for_one_service_is_never_found_for_another(cfg):
    config.save({"cloud_provider": "openai_compat", "cloud_url": "http://localhost:1234/v1", "cloud_model": "m", "cloud_api_key": "sk-test-1234567890"})
    assert config.cloud_api_key() == "sk-test-1234567890"
    config.save({"cloud_url": "http://localhost:8080/v1"})  # same host, other port
    assert config.cloud_api_key() == "" and config.current()["cloud_key_set"] is False


def test_file_addresses_are_refused_for_local_lookups_and_the_ollama_setting(cfg):
    with pytest.raises(ValueError):
        providers.open_local("file:///etc/hosts", 2)
    with pytest.raises(ValueError):
        config.save({"ollama_url": "file://localhost/etc/hosts"})


def test_a_blocked_address_is_logged_once(cfg, monkeypatch, tmp_path):
    config.save({"cloud_provider": "openai_compat", "cloud_url": "https://api.example.com/v1", "cloud_model": "m", "cloud_api_key": "sk-test-1234567890"})
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))])
    log = egress.AuditLog(str(tmp_path / "a.jsonl"))
    with pytest.raises(providers.NotSent):
        egress.send("claude", [{"role": "user", "content": TEXT}], Vault(), log=log, checker=lambda t: [])
    assert len((tmp_path / "a.jsonl").read_text().splitlines()) == 1


def test_a_refused_address_says_nothing_was_sent_and_has_no_third_party_warning(cfg, monkeypatch):
    from privhybrid import local
    from privhybrid.ingest import Document
    monkeypatch.setenv("PRIVHYBRID_CLOUD_PROVIDER", "openai_compat")  # no address saved
    monkeypatch.setattr(local, "second_pass", lambda text, **k: [])
    monkeypatch.setattr(pipeline, "_local", lambda *a, **k: type("R", (), {"text": "local answer"})())
    ans = pipeline.run("Who should I write to?", [Document("n.txt", TEXT, [])], Vault(), mode="claude")
    assert any("nothing was sent" in n for n in ans.notices) and pipeline.CLOUD_WARNING not in ans.notices
