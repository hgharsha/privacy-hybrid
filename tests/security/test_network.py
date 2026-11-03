"""Phase 6: addresses, redirects, the Claude CLI and error messages. Python-level guards are not an operating-system firewall (see THREAT-MODEL.md);
these tests check what this process itself will and will not do."""
import json
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from privhybrid import config, egress, keystore, providers
from privhybrid.vault import Vault

TEXT = "Please summarise the garden notes." + " The weather was mild and the report was short and clear." * 6
PROF = {"provider": "openai_compat", "model": "m", "base_url": "https://api.example.com/v1", "api_key": "sk-test-1234567890"}


def send(profile=PROF, text=TEXT):
    return egress.send("claude", [{"role": "user", "content": text}], Vault(), profile=profile, checker=lambda t: [])


def resolves(monkeypatch, *ips):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET6 if ":" in ip else socket.AF_INET, 1, 6, "", (ip, 443)) for ip in ips])


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.9", "172.16.0.1", "169.254.169.254", "127.0.0.2", "0.0.0.0", "100.64.0.1",
                                "::1", "fc00::1", "fe80::1", "::ffff:10.0.0.5", "::ffff:127.0.0.1"])
def test_cloud_names_that_resolve_to_private_or_reserved_addresses_are_refused(monkeypatch, ip):
    resolves(monkeypatch, ip)
    with pytest.raises(providers.NotSent):
        send()


def test_one_private_answer_among_public_ones_refuses_the_name(monkeypatch):
    resolves(monkeypatch, "93.184.216.34", "10.0.0.5")  # a rebinding-style mixed answer
    with pytest.raises(providers.NotSent):
        send()


@pytest.mark.parametrize("url", ["http://api.example.com/v1", "https://user:pw@api.example.com/v1", "https://api.example.com/v1?key=x",
                                 "https://api.example.com/v1#frag", "ftp://api.example.com/v1", "file:///etc/passwd", "https:///v1", "https://api.example.com:99999/v1"])
def test_odd_cloud_addresses_are_refused(url):
    with pytest.raises(egress.EgressBlocked):
        send({**PROF, "base_url": url})


def test_a_redirect_from_the_cloud_service_is_not_followed(tmp_path, monkeypatch):
    hits = {"other": 0}

    class Other(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_POST(self):
            hits["other"] += 1
            self.send_response(200); self.end_headers()
    other = HTTPServer(("127.0.0.1", 0), Other)
    threading.Thread(target=other.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{other.server_address[1]}/stolen"

    class Redirector(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(307); self.send_header("Location", target); self.end_headers()
    r = HTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=r.serve_forever, daemon=True).start()
    try:
        with pytest.raises(providers.ProviderError):
            send({**PROF, "base_url": f"http://127.0.0.1:{r.server_address[1]}/v1"})
        assert hits["other"] == 0
    finally:
        other.shutdown(); r.shutdown()


def test_error_replies_never_carry_the_key_or_the_text(tmp_path, monkeypatch):
    class Bad(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            out = b"error: bad key sk-test-1234567890 and your prompt " + body
            self.send_response(500); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    h = HTTPServer(("127.0.0.1", 0), Bad)
    threading.Thread(target=h.serve_forever, daemon=True).start()
    log = egress.AuditLog(str(tmp_path / "audit.jsonl"))
    try:
        with pytest.raises(providers.ProviderError) as ei:
            egress.send("claude", [{"role": "user", "content": TEXT}], Vault(), log=log, checker=lambda t: [],
                        profile={**PROF, "base_url": f"http://127.0.0.1:{h.server_address[1]}/v1"})
        shown = str(ei.value) + (tmp_path / "audit.jsonl").read_text()
        assert "sk-test" not in shown and "garden" not in shown
    finally:
        h.shutdown()


# --- the Claude CLI -----------------------------------------------------------------------------------

def test_providers_refuse_to_run_outside_the_gateway(monkeypatch):
    ran = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: ran.append(a) or (_ for _ in ()).throw(AssertionError("spawned")))
    for prof in ({"provider": "claude_cli", "model": ""}, PROF, {"provider": "anthropic", "model": "x", "api_key": "k"}):
        with pytest.raises(providers.NotSent):
            providers.chat(prof, [{"role": "user", "content": "raw text with jane.doe@example.com"}])
    assert ran == []


def test_claude_cli_gets_the_prompt_on_stdin_with_no_tools_and_a_minimal_environment(monkeypatch):
    seen = {}

    class P:
        returncode = 0

        def __init__(self, cmd, **kw):
            seen.update(cmd=cmd, env=kw["env"], cwd=kw["cwd"])

        def communicate(self, inp=None, timeout=None):
            seen["stdin"] = inp
            return json.dumps({"result": "ok"}), "stderr with SECRET-IN-STDERR"
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-pass")
    monkeypatch.setenv("PRIVHYBRID_CLOUD_API_KEY", "sk-should-not-pass")
    monkeypatch.setattr(subprocess, "Popen", P)
    res = egress.send("claude", [{"role": "user", "content": TEXT + " Write to jane.doe@example.com."}], Vault(), profile={"provider": "claude_cli", "model": ""}, checker=lambda t: [])
    assert res.text == "ok"
    assert "jane.doe" not in " ".join(seen["cmd"]) and "jane.doe" not in seen["stdin"]  # not in argv, and masked on stdin
    assert "--strict-mcp-config" in seen["cmd"] and seen["cmd"][seen["cmd"].index("--mcp-config") + 1] == '{"mcpServers":{}}'
    assert "--tools" in seen["cmd"] and seen["cmd"][seen["cmd"].index("--tools") + 1] == ""
    assert set(seen["env"]) <= set(providers.CLAUDE_ENV_KEYS) | set(providers.CLAUDE_FIXED_ENV) | {"CLAUDE_CONFIG_DIR"} and "AWS_SECRET_ACCESS_KEY" not in seen["env"] and "PRIVHYBRID_CLOUD_API_KEY" not in seen["env"]
    assert all(seen["env"].get(k) == v for k, v in providers.CLAUDE_FIXED_ENV.items())  # telemetry and error reporting asked off


def test_claude_cli_error_output_is_not_shown(monkeypatch):
    class P:
        returncode = 1

        def __init__(self, *a, **k): pass

        def communicate(self, inp=None, timeout=None):
            return json.dumps({"is_error": True, "result": "internal: the prompt was " + (inp or "")[:200]}), "trace SECRET-IN-STDERR"
    monkeypatch.setattr(subprocess, "Popen", P)
    with pytest.raises(providers.ProviderError) as ei:
        egress.send("claude", [{"role": "user", "content": TEXT}], Vault(), profile={"provider": "claude_cli", "model": ""}, checker=lambda t: [])
    assert "SECRET" not in str(ei.value) and "garden" not in str(ei.value)


# --- remote Ollama --------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", ["http://8.8.8.8:11434", "http://example.com:11434", "http://192.168.1.5", "http://192.168.1.5:80", "http://192.168.1.5:11434/api",
                                 "http://user:pw@192.168.1.5:11434", "http://[2001:db8::1]:11434", "http://192.168.1.5:11434,http://8.8.8.8:1"])
def test_only_listed_private_addresses_on_high_ports_can_be_a_remote_model(url):
    assert config.valid_ollama_url(url) is False


def test_default_is_this_machine_only_and_a_remote_model_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    for k in ("PRIVHYBRID_OLLAMA_URL", "PRIVHYBRID_EMBED_URL", "PRIVHYBRID_OLLAMA_BACKUPS"):
        monkeypatch.delenv(k, raising=False)
    assert config.lan_endpoints() == set() and config.current()["remote_ollama_warning"] == ""
    config.save({"ollama_url": "http://192.168.1.5:11434"})
    cur = config.current()
    assert cur["remote_ollama"] == ["http://192.168.1.5:11434"] and "not encrypted" in cur["remote_ollama_warning"] and "tunnel" in cur["remote_ollama_warning"]


def _run_claude_cli_env(monkeypatch):
    seen = {}

    class P:
        returncode = 0

        def __init__(self, cmd, **kw):
            seen["env"] = kw["env"]

        def communicate(self, inp=None, timeout=None):
            return json.dumps({"result": "ok"}), ""
    monkeypatch.setattr(subprocess, "Popen", P)
    providers._chat_claude_cli({"provider": "claude_cli", "model": ""}, [{"role": "user", "content": "hi"}], 5)
    return seen["env"]


def test_claude_cli_uses_the_private_config_folder_when_it_exists(monkeypatch, tmp_path):
    monkeypatch.setattr(providers, "CLAUDE_CONFIG_DIR", str(tmp_path))
    assert _run_claude_cli_env(monkeypatch)["CLAUDE_CONFIG_DIR"] == str(tmp_path)


def test_claude_cli_without_the_private_folder_sets_no_config_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(providers, "CLAUDE_CONFIG_DIR", str(tmp_path / "missing"))
    assert "CLAUDE_CONFIG_DIR" not in _run_claude_cli_env(monkeypatch)
