"""Shared fixtures for the security tests. They keep the mandatory local second-pass check ON (marker `strict`) and capture what really
arrives at a mock cloud service and a mock search service over real loopback sockets. Synthetic data only; no real credentials."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from privhybrid import config, egress, keystore, providers, server


def pytest_collection_modifyitems(items):
    for it in items:
        if "tests/security" not in str(it.fspath).replace("\\", "/"):
            continue  # this hook sees every collected test
        it.add_marker(pytest.mark.strict)  # conftest.py in tests/ then leaves REQUIRE_SECOND_PASS at its real default (True)


class Net:
    def __init__(self):
        self.cloud, self.search = [], []


def _serve(handler):
    httpd = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture
def net(tmp_path, monkeypatch):
    n = Net()

    class Cloud(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_POST(self):
            n.cloud.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            out = json.dumps({"choices": [{"message": {"content": "cloud answer"}}]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out))); self.end_headers()
            self.wfile.write(out)

    class Search(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            if self.path.startswith("/search"):
                n.search.append(self.path)  # the status line's /healthz probe is not a search
            out = json.dumps({"results": [{"title": "t", "url": "https://example.org/x", "content": "public fact"}]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out))); self.end_headers()
            self.wfile.write(out)

    cloud, search = _serve(Cloud), _serve(Search)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    store = {}
    monkeypatch.setattr(keystore, "_backend", lambda op, uid, v: store.get(uid) if op == "get" else (store.__setitem__(uid, v) if op == "set" else store.pop(uid, None)))
    config.save({"cloud_provider": "openai_compat", "cloud_url": f"http://127.0.0.1:{cloud.server_address[1]}/v1", "cloud_model": "m", "cloud_api_key": "sk-test-0000000000"})
    monkeypatch.setattr(egress, "SEARX_URL", f"http://127.0.0.1:{search.server_address[1]}")
    real_chat = providers.chat

    def chat(profile, messages, timeout=0):
        if profile["provider"] == "openai_compat":
            return real_chat(profile, messages, timeout)  # a real HTTP request to the mock cloud
        system = " ".join(m["content"] for m in messages if m["role"] == "system")
        if "check text for privacy" in system:
            return providers.Reply("NONE", profile["provider"], "", "x")
        if "lasting facts" in system:
            return providers.Reply("NONE", profile["provider"], "", "x")
        if "ONE short web search query" in system:
            return providers.Reply("current weather", profile["provider"], "", "x")
        return providers.Reply("local answer", profile["provider"], "", "x")
    monkeypatch.setattr(providers, "chat", chat)
    monkeypatch.setattr(providers, "embed", lambda prof, texts, timeout=120: [[1.0, 0.0, 0.5] for _ in texts])
    yield n
    cloud.shutdown(); search.shutdown()


@pytest.fixture
def srv(net, tmp_path):
    httpd = server.serve(port=0, data_dir=str(tmp_path / "users"), audit_path=str(tmp_path / "audit.jsonl"), dictionary_path=str(tmp_path / "d.txt"))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd
    httpd.shutdown()
