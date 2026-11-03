import http.server
import threading
import time

import pytest

from privhybrid import providers


class Slow(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        time.sleep(5)

    def log_message(self, *a):
        pass


def test_stop_ends_a_waiting_model_call_at_once():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    token = providers.Cancel()
    got = []

    def call():
        providers.ACTIVE.cancel = token
        try:
            providers._post(f"http://127.0.0.1:{srv.server_port}/api/chat", {}, {}, 30, "ollama")
        except providers.Cancelled:
            got.append("cancelled")
        except BaseException as exc:
            got.append(repr(exc))

    t = threading.Thread(target=call); t.start()
    time.sleep(0.3); start = time.time(); token.stop(); t.join(3)
    srv.shutdown()
    assert got == ["cancelled"] and time.time() - start < 2


def test_cancelled_is_not_an_ordinary_exception():
    with pytest.raises(providers.Cancelled):
        try:
            raise providers.Cancelled()
        except Exception:
            pytest.fail("swallowed")
