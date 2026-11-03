"""An OpenAI-compatible local server (LM Studio, llama.cpp, vLLM) as the local model. Checked against a stand-in server, not a real one."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from privhybrid import config, egress, providers


class Fake(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Fake.seen.append((self.path, self.headers.get("Authorization"), body))
        if self.path == "/v1/chat/completions":
            out = {"choices": [{"message": {"content": "hello from lmstudio"}}], "usage": {"prompt_tokens": 3, "completion_tokens": 4}}
        elif self.path == "/v1/embeddings":
            out = {"data": [{"index": i, "embedding": [float(i), 1.0]} for i in reversed(range(len(body["input"])))]}
        else:
            self.send_response(404); self.end_headers(); return
        data = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def server(monkeypatch, tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "state" / "config.json")
    for k in ("PRIVHYBRID_LOCAL_RUNTIME", "PRIVHYBRID_OLLAMA_URL", "PRIVHYBRID_OLLAMA_BACKUPS", "PRIVHYBRID_EMBED_URL"):
        monkeypatch.delenv(k, raising=False)
    Fake.seen.clear()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_default_runtime_is_ollama_and_bad_values_are_refused(server):
    assert config.profile("answer")["provider"] == "ollama"
    with pytest.raises(ValueError):
        config.save({"local_runtime": "something-else"})


def test_chat_and_embeddings_use_the_openai_endpoints_with_no_key(server):
    config.save({"local_runtime": "local_openai", "ollama_url": server})
    prof = config.profile("answer")
    assert prof["provider"] == "local_openai" and prof["base_url"] == server
    reply = providers.chat(prof, [{"role": "user", "content": "hi"}])
    assert reply.text == "hello from lmstudio" and reply.tier == "local"
    vecs = providers.embed(config.profile("embed"), ["a", "b"])
    assert vecs == [[0.0, 1.0], [1.0, 1.0]]  # reordered by index
    assert [p for p, _, _ in Fake.seen] == ["/v1/chat/completions", "/v1/embeddings"]
    assert all(auth is None for _, auth, _ in Fake.seen)


def test_the_local_route_accepts_it_but_only_on_local_addresses(server):
    config.save({"local_runtime": "local_openai", "ollama_url": server})
    egress._check_profile("local", config.profile("answer"))
    with pytest.raises(egress.EgressBlocked):
        egress._check_profile("local", {"provider": "local_openai", "model": "m", "base_url": "http://8.8.8.8:1234"})
    with pytest.raises(egress.EgressBlocked):
        egress._check_profile("claude", {"provider": "local_openai", "model": "m", "base_url": server})
