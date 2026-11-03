import base64
import json
import threading
import urllib.error
import urllib.request

import pytest

from privhybrid import egress, providers, server

PAD = " The weather was mild and the report was short and clear." * 12


@pytest.fixture
def srv(monkeypatch, tmp_path):
    def chat(profile, messages, timeout=0):
        system = " ".join(m["content"] for m in messages if m["role"] == "system")
        if profile["provider"] == "claude_cli":
            return providers.Reply("Write to [EMAIL_1].", "claude_cli", "", "x")
        if "lasting facts about the user" in system:
            user = " ".join(m["content"] for m in messages if m["role"] == "user")
            return providers.Reply("I want to buy a house in 2028." if "buy a house" in user else "NONE", profile["provider"], "", "x")
        text = "NONE" if "check text for privacy" in system else "local answer"
        return providers.Reply(text, profile["provider"], "", "x")
    monkeypatch.setattr(providers, "chat", chat)
    monkeypatch.setattr(providers, "embed", lambda prof, texts, timeout=120: [[1.0, float(len(t) % 7), 0.5] for t in texts])
    httpd = server.serve(port=0, data_dir=str(tmp_path / "users"), audit_path=str(tmp_path / "audit.jsonl"), dictionary_path=str(tmp_path / "d.txt"))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd
    httpd.shutdown()


class C:
    def __init__(self, httpd):
        self.base = f"http://127.0.0.1:{httpd.server_address[1]}"
        self.cookie = ""

    def req(self, method, path, body=None, headers=None, host=None):
        h = {"X-Requested-With": "privhybrid", "Content-Type": "application/json"}
        if self.cookie:
            h["Cookie"] = self.cookie
        h.update(headers or {})
        if host:
            h["Host"] = host
        r = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
        try:
            with urllib.request.urlopen(r) as res:
                raw = res.read().decode()
                if res.headers.get("Set-Cookie"):
                    self.cookie = res.headers["Set-Cookie"].split(";")[0]
                return res.status, raw, res.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), e.headers

    def login(self, email="maria@example.com", password="correct horse 1"):
        status = self.req("POST", "/api/register", {"email": email, "password": password})
        if status[0] != 200:
            status = self.req("POST", "/api/login", {"email": email, "password": password})
        return status


def events(raw):
    out = []
    for block in raw.strip().split("\n\n"):
        ev = block.split("\n")[0][len("event: "):]
        out.append((ev, json.loads(block.split("\n")[1][len("data: "):])))
    return out


def test_binds_loopback_only(srv):
    assert srv.server_address[0] == "127.0.0.1"


def test_login_required_and_password_checked(srv):
    c = C(srv)
    assert c.req("GET", "/api/state")[0] == 401
    assert c.login()[0] == 200  # registers
    assert c.req("GET", "/api/state")[0] == 200
    d = C(srv)
    assert d.req("POST", "/api/login", {"email": "maria@example.com", "password": "wrong password"})[0] == 401
    assert d.req("POST", "/api/login", {"email": "nobody@example.com", "password": "whatever123"})[0] == 401
    assert d.login()[0] == 200


def test_lockout_after_repeated_failures(srv):
    c = C(srv)
    c.login()
    d = C(srv)
    codes = [d.req("POST", "/api/login", {"email": "maria@example.com", "password": "bad bad bad"})[0] for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    assert d.login()[0] == 429


def test_wrong_host_and_missing_csrf_header_rejected(srv):
    c = C(srv)
    assert c.req("GET", "/api/state", host="evil.example.com")[0] == 403  # DNS rebinding
    assert c.req("POST", "/api/login", {"email": "a@b.co", "password": "x"}, headers={"X-Requested-With": ""})[0] == 403
    assert c.req("POST", "/api/login", {"email": "a@b.co", "password": "x"}, headers={"Origin": "http://evil.example.com"})[0] == 403


def test_static_security_headers_and_no_path_escape(srv):
    c = C(srv)
    status, body, h = c.req("GET", "/")
    assert status == 200 and "Private Assistant" in body
    assert "default-src 'self'" in h["Content-Security-Policy"] and h["X-Frame-Options"] == "DENY"
    assert c.req("GET", "/static/../src/privhybrid/server.py")[0] in (403, 404)
    assert c.req("GET", "/static/%2e%2e/PLAN.md")[0] in (403, 404)


def test_chat_local_streams_steps_chunks_done(srv):
    c = C(srv); c.login()
    status, raw, _ = c.req("POST", "/api/chat", {"question": "hello there", "mode": "local"})
    evs = events(raw)
    assert status == 200 and [e for e, _ in evs][-1] == "done"
    assert "".join(d for e, d in evs if e == "chunk") == "local answer"


def test_tier1_returns_needs_approval_and_sends_nothing(srv, monkeypatch):
    c = C(srv); c.login()
    seen = []
    orig = providers.chat
    monkeypatch.setattr(providers, "chat", lambda p, m, t=0: seen.append(p["provider"]) or orig(p, m, t))
    status, raw, _ = c.req("POST", "/api/chat", {"question": "My SSN is 123-45-6789." + PAD, "mode": "claude"})
    ev = events(raw)[-1]
    assert ev[0] == "needs_approval" and ev[1]["kinds"] == {"SSN": 1} and "123-45-6789" not in raw
    assert "claude_cli" not in seen


def test_upload_chat_with_file_and_audit_has_no_text(srv, tmp_path):
    c = C(srv); c.login()
    data = base64.b64encode(("Contact jane.doe@example.com." + PAD).encode()).decode()
    assert c.req("POST", "/api/upload", {"name": "note.txt", "data": data})[0] == 200
    _, raw, _ = c.req("POST", "/api/chat", {"question": "Who to contact?", "mode": "claude"})
    assert [e for e, _ in events(raw)][-1] == "done"
    assert "jane.doe@example.com" in "".join(d for e, d in events(raw) if e == "chunk")  # restored for the user
    audit = c.req("GET", "/api/audit")[1]
    assert "jane.doe" not in audit and "Contact" not in audit and '"EMAIL": 1' in audit


def test_bad_upload_is_refused(srv):
    c = C(srv); c.login()
    assert c.req("POST", "/api/upload", {"name": "scan.png", "data": base64.b64encode(b"\x89PNG").decode()})[0] == 422


def test_register_rules(srv):
    c = C(srv)
    assert c.req("POST", "/api/register", {"email": "not-an-email", "password": "longenough1"})[0] == 400
    assert c.req("POST", "/api/register", {"email": "a@example.com", "password": "short"})[0] == 400
    assert c.req("POST", "/api/register", {"email": "a@example.com", "password": "longenough1"})[0] == 200
    assert C(srv).req("POST", "/api/register", {"email": "A@Example.com", "password": "longenough1"})[0] == 400  # same email


def test_each_user_has_a_separate_library(srv, tmp_path):
    a, b = C(srv), C(srv)
    a.login("a@example.com", "password A 111"); b.login("b@example.com", "password B 222")
    data = base64.b64encode(("Maria's savings account is at Northwind Credit Union." + PAD).encode()).decode()
    assert a.req("POST", "/api/upload", {"name": "notes.txt", "data": data})[0] == 200
    assert [d["name"] for d in json.loads(a.req("GET", "/api/state")[1])["docs"]] == ["notes.txt"]
    assert json.loads(b.req("GET", "/api/state")[1])["docs"] == []
    users = tmp_path / "users"
    blob = b"".join(p.read_bytes() for p in users.rglob("*") if p.is_file())
    assert b"Northwind" not in blob and b"a@example.com" not in blob  # sealed on disk, email not in the clear


def test_library_survives_a_new_login_and_server_restart(srv, tmp_path):
    a = C(srv); a.login("a@example.com", "password A 111")
    data = base64.b64encode(("The lease ends in June." + PAD).encode()).decode()
    a.req("POST", "/api/upload", {"name": "lease.txt", "data": data})
    again = C(srv)
    assert again.req("POST", "/api/login", {"email": "a@example.com", "password": "password A 111"})[0] == 200
    assert json.loads(again.req("GET", "/api/state")[1])["docs"][0]["name"] == "lease.txt"


def test_chat_is_saved_learned_and_forgotten_on_delete(srv):
    c = C(srv); c.login()
    _, raw, _ = c.req("POST", "/api/chat", {"question": "I prefer paying bills on the 5th.", "mode": "local"})
    cid = events(raw)[-1][1]["chat_id"]
    chats = json.loads(c.req("GET", "/api/chats")[1])["chats"]
    assert [x["id"] for x in chats] == [cid]
    assert json.loads(c.req("GET", "/api/chats/get?id=" + cid)[1])["msgs"][0]["q"] == "I prefer paying bills on the 5th."
    sess = next(iter(srv.app.sessions.values()))
    for t in sess.bg:
        t.join(10)
    assert any(d["kind"] == "memory" and d["chat"] == cid for d in sess.library)
    assert json.loads(c.req("GET", "/api/state")[1])["docs"] == []  # memories are not listed as files
    c.req("POST", "/api/chats/delete", {"id": cid})
    assert not any(d.get("chat") == cid for d in sess.library)


def test_tier1_exchange_is_not_learned(srv):
    c = C(srv); c.login()
    c.req("POST", "/api/chat", {"question": "My SSN is 123-45-6789.", "mode": "local"})
    sess = next(iter(srv.app.sessions.values()))
    for t in sess.bg:
        t.join(10)
    assert not any(d.get("kind") == "memory" for d in sess.library)


def test_logout_ends_the_session(srv):
    c = C(srv); c.login()
    assert c.req("POST", "/api/logout", {})[0] == 200
    assert c.req("GET", "/api/state")[0] == 401


def test_user_facts_are_remembered_used_and_forgotten(srv, monkeypatch):
    c = C(srv); c.login()
    _, raw, _ = c.req("POST", "/api/chat", {"question": "I want to buy a house in 2028, what should I save?", "mode": "local"})
    cid = events(raw)[-1][1]["chat_id"]
    sess = next(iter(srv.app.sessions.values()))
    for t in sess.bg:
        t.join(10)
    facts = json.loads(c.req("GET", "/api/state")[1])["facts"]
    assert [f["text"] for f in facts] == ["I want to buy a house in 2028."]
    seen = []
    orig = providers.chat
    monkeypatch.setattr(providers, "chat", lambda p, m, t=0: seen.append(" ".join(x["content"] for x in m)) or orig(p, m, t))
    c.req("POST", "/api/chat", {"question": "How am I doing?", "mode": "local"})
    assert any("What I know about you" in x and "buy a house in 2028" in x for x in seen)  # given to the model next time
    c.req("POST", "/api/facts/delete", {"id": facts[0]["id"]})
    assert json.loads(c.req("GET", "/api/state")[1])["facts"] == []
    c.req("POST", "/api/chat", {"question": "I want to buy a house in 2028 again", "mode": "local"})
    for t in sess.bg:
        t.join(10)
    c.req("POST", "/api/chats/delete", {"id": cid})
    assert all(f["chat"] != cid for f in sess.facts)


def test_change_password_signs_out_other_devices_and_delete_account(srv):
    a, other = C(srv), C(srv)
    a.login("a@example.com", "password A 111"); other.login("a@example.com", "password A 111")
    assert a.req("POST", "/api/password", {"old": "wrong wrong 1", "new": "password B 222"})[0] == 400
    assert a.req("POST", "/api/password", {"old": "password A 111", "new": "password B 222"})[0] == 200
    assert a.req("GET", "/api/state")[0] == 200 and other.req("GET", "/api/state")[0] == 401
    fresh = C(srv)
    assert fresh.req("POST", "/api/login", {"email": "a@example.com", "password": "password A 111"})[0] == 401
    assert fresh.req("POST", "/api/login", {"email": "a@example.com", "password": "password B 222"})[0] == 200
    assert a.req("POST", "/api/account/delete", {"password": "nope nope 11"})[0] == 400
    assert a.req("POST", "/api/account/delete", {"password": "password B 222"})[0] == 200
    assert a.req("GET", "/api/state")[0] == 401
    assert C(srv).req("POST", "/api/login", {"email": "a@example.com", "password": "password B 222"})[0] == 401


def test_remember_off_learns_nothing(srv):
    c = C(srv); c.login()
    c.req("POST", "/api/chat", {"question": "I want to buy a house in 2028.", "mode": "local", "remember": False})
    sess = next(iter(srv.app.sessions.values()))
    for t in sess.bg:
        t.join(10)
    assert sess.facts == [] and not any(d.get("kind") == "memory" for d in sess.library)
    assert len(sess.chats) == 1  # the chat itself is still saved


def test_config_endpoint_needs_login_and_refuses_remote_url(srv, monkeypatch, tmp_path):
    from privhybrid import config
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    c = C(srv)
    assert c.req("GET", "/api/config")[0] == 401
    c.login()
    assert c.req("GET", "/api/config")[0] == 200
    assert c.req("POST", "/api/config", {"ollama_url": "http://8.8.8.8:11434"})[0] == 400
    assert c.req("POST", "/api/config", {"answer": "qwen3:30b"})[0] == 200
    assert json.loads(c.req("GET", "/api/config")[1])["config"]["answer"] == "qwen3:30b"


def test_folders_move_and_scoped_chat(srv):
    c = C(srv); c.login()
    up = lambda n, t, f: c.req("POST", "/api/upload", {"name": n, "data": base64.b64encode((t + PAD).encode()).decode(), "folder": f})
    assert up("tax.txt", "Tax code ALPHA.", "Taxes")[0] == 200
    assert up("trip.txt", "Trip code BRAVO.", "")[0] == 200
    docs = {d["name"]: d["folder"] for d in json.loads(c.req("GET", "/api/state")[1])["docs"]}
    assert docs == {"tax.txt": "Taxes", "trip.txt": ""}
    assert c.req("POST", "/api/move", {"name": "trip.txt", "folder": "  Travel  "})[0] == 200
    docs = {d["name"]: d["folder"] for d in json.loads(c.req("GET", "/api/state")[1])["docs"]}
    assert docs["trip.txt"] == "Travel"
    _, raw, _ = c.req("POST", "/api/chat", {"question": "What is the code?", "mode": "local", "folder": "Taxes"})
    done = [d for e, d in events(raw) if e == "done"][-1]
    assert done["sources"] in (["tax.txt"], []) and "trip.txt" not in str(done["sources"])


def _upload(c, name, text, folder=""):
    import base64
    return c.req("POST", "/api/upload", {"name": name, "data": base64.b64encode(text.encode()).decode(), "folder": folder})


def test_bad_base64_is_400_and_negative_length_rejected(srv):
    c = C(srv); c.login()
    assert c.req("POST", "/api/upload", {"name": "a.txt", "data": "!!not base64"})[0] == 400
    assert c.req("POST", "/api/reset", {}, headers={"Content-Length": "-1"})[0] == 400


def test_rename_file_and_folder(srv):
    c = C(srv); c.login()
    _upload(c, "a.txt", "alpha note", "Tax"); _upload(c, "b.txt", "beta note", "Tax")
    assert c.req("POST", "/api/rename", {"name": "a.txt", "new": "b.txt"})[0] == 409
    assert c.req("POST", "/api/rename", {"name": "a.txt", "new": "  "})[0] == 400
    assert c.req("POST", "/api/rename", {"name": "a.txt", "new": "c.txt"})[0] == 200
    assert c.req("POST", "/api/folder/rename", {"old": "", "new": "X"})[0] == 400
    assert c.req("POST", "/api/folder/rename", {"old": "Tax", "new": "Taxes"})[0] == 200
    docs = json.loads(c.req("GET", "/api/state")[1])["docs"]
    assert {(d["name"], d["folder"]) for d in docs} == {("c.txt", "Taxes"), ("b.txt", "Taxes")}
    c.req("POST", "/api/folder/rename", {"old": "Taxes", "new": ""})
    assert {d["folder"] for d in json.loads(c.req("GET", "/api/state")[1])["docs"]} == {""}


def test_only_first_account_is_admin(srv):
    a, b = C(srv), C(srv)
    a.login("one@example.com", "password one 1"); b.login("two@example.com", "password two 2")
    assert json.loads(a.req("GET", "/api/state")[1])["admin"] is True
    assert json.loads(b.req("GET", "/api/state")[1])["admin"] is False
    assert a.req("GET", "/api/audit")[0] == 200
    assert b.req("GET", "/api/audit")[0] == 403
    assert b.req("POST", "/api/config", {"answer": "x"})[0] == 403


def test_rename_refuses_personal_detail(srv):
    c = C(srv); c.login()
    _upload(c, "a.txt", "alpha")
    assert c.req("POST", "/api/rename", {"name": "a.txt", "new": "report_for_123-45-6789.txt"})[0] == 400


def test_demo_link_only_when_enabled(srv):
    c = C(srv)
    assert c.req("GET", "/demo")[0] == 401
    srv.app.demo = True
    import http.client
    h = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
    h.request("GET", "/demo"); r = h.getresponse()
    assert r.status == 302 and "ph_session=" in r.getheader("Set-Cookie")
    c.cookie = r.getheader("Set-Cookie").split(";")[0]
    docs = json.loads(c.req("GET", "/api/state")[1])["docs"]
    assert len(docs) >= 3 and {d["folder"] for d in docs} == {"Demo"}


def test_demo_visit_wipes_earlier_uploads(srv):
    import http.client
    srv.app.demo = True
    def visit():
        h = http.client.HTTPConnection("127.0.0.1", srv.server_address[1]); h.request("GET", "/demo")
        c = C(srv); c.cookie = h.getresponse().getheader("Set-Cookie").split(";")[0]; return c
    c = visit(); _upload(c, "mine.txt", "my own upload")
    assert "mine.txt" in c.req("GET", "/api/state")[1]
    assert "mine.txt" not in visit().req("GET", "/api/state")[1]


def test_activity_summary_admin_only_and_has_no_text(srv):
    a, b = C(srv), C(srv)
    a.login("one@example.com", "password one 1"); b.login("two@example.com", "password two 2")
    _upload(a, "note.txt", "Contact jane.doe@example.com." + PAD)
    a.req("POST", "/api/chat", {"question": "Who to contact?", "mode": "claude"})
    r = json.loads(a.req("GET", "/api/activity")[1])
    assert r["summary"]["routes"]["claude"]["ok"] == 1 and r["summary"]["masked"] == {"EMAIL": 1}
    assert r["recent"] and "jane.doe" not in json.dumps(r) and set(r["health"]) == {"ollama", "search"}
    assert b.req("GET", "/api/activity")[0] == 403


def test_metrics_is_off_unless_enabled_and_has_no_text(srv, monkeypatch, tmp_path):
    assert C(srv).req("GET", "/metrics")[0] != 200  # not enabled: never answers
    monkeypatch.setenv("PRIVHYBRID_METRICS", "1")
    httpd = server.serve(port=0, data_dir=str(tmp_path / "u2"), audit_path=str(tmp_path / "a2.jsonl"), dictionary_path=str(tmp_path / "d2.txt"))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        c = C(httpd)
        c.login()
        _upload(c, "note.txt", "Contact jane.doe@example.com." + PAD)
        c.req("POST", "/api/chat", {"question": "Who to contact?", "mode": "claude"})
        status, body, headers = C(httpd).req("GET", "/metrics")  # no login: it is for a local scraper
        assert status == 200 and headers["Content-Type"].startswith("text/plain")
        assert 'privhybrid_requests_total{route="claude",outcome="ok"} 1' in body and 'privhybrid_masked_total{kind="EMAIL"} 1' in body
        assert "jane.doe" not in body
    finally:
        httpd.shutdown()


def test_non_object_bodies_are_a_clean_400(srv):
    c = C(srv)
    c.login()
    for path in ("/api/login", "/api/upload", "/api/chat", "/api/rename"):
        for bad in ([], "x", 5):
            assert c.req("POST", path, bad)[0] == 400
    assert c.req("POST", "/api/chat", {"question": "hi", "mode": []})[0] == 400


def test_long_question_refused_and_many_questions_stay_local(srv):
    c = C(srv)
    c.login()
    assert c.req("POST", "/api/chat", {"question": "a" * (server.MAX_QUESTION + 1), "mode": "local"})[0] == 400
    raw = c.req("POST", "/api/chat", {"question": "What is 1+1? And 2+2? And 3+3?", "mode": "auto"})[1]
    assert "Several questions" in raw and '"route": "local"' in raw


def test_second_question_while_one_runs_is_refused(srv):
    c = C(srv)
    c.login()
    s = next(iter(srv.app.sessions.values()))
    s.chat_lock.acquire()
    try:
        assert c.req("POST", "/api/chat", {"question": "hello", "mode": "local"})[0] == 409
    finally:
        s.chat_lock.release()
    assert "done" in c.req("POST", "/api/chat", {"question": "hello", "mode": "local"})[1]


def test_upload_never_overwrites_and_rename_edge_cases(srv):
    c = C(srv)
    c.login()
    _upload(c, "statement.txt", "first" + PAD)
    _upload(c, "statement.txt", "second" + PAD)
    names = sorted(d["name"] for d in json.loads(c.req("GET", "/api/state")[1])["docs"])
    assert names == ["statement (2).txt", "statement.txt"]
    assert c.req("POST", "/api/rename", {"name": "statement.txt", "new": "statement.txt"})[0] == 200
    assert c.req("POST", "/api/rename", {"name": "gone.txt", "new": "other.txt"})[0] == 404


def test_corrupt_audit_rows_do_not_break_activity(srv, tmp_path):
    c = C(srv)
    c.login()
    with open(tmp_path / "audit.jsonl", "a") as f:
        f.write('5\n[]\n{"route":"claude","kinds":{"SSN":"x"}}\n{"route":"claude","kinds":[1]}\nnot json\n')
    assert c.req("GET", "/api/activity")[0] == 200


def test_lockout_holds_the_address_that_guessed(srv):
    c = C(srv)
    c.login("owner@example.com", "correct horse 1")
    for _ in range(5):
        C(srv).req("POST", "/api/login", {"email": "owner@example.com", "password": "wrong password"})
    assert C(srv).req("POST", "/api/login", {"email": "owner@example.com", "password": "correct horse 1"})[0] == 429


def test_look_is_saved_per_account_and_validated(srv):
    a = C(srv)
    a.login("owner@example.com", "correct horse 1")
    assert json.loads(a.req("GET", "/api/state")[1])["prefs"] == {}
    assert a.req("POST", "/api/prefs", {"style": "forest", "theme": "dark"})[0] == 200
    assert a.req("POST", "/api/prefs", {"style": "pink"})[0] == 400
    assert a.req("POST", "/api/prefs", {"theme": 5})[0] == 400
    again = C(srv)
    again.login("owner@example.com", "correct horse 1")
    assert json.loads(again.req("GET", "/api/state")[1])["prefs"] == {"style": "forest", "theme": "dark"}
    other = C(srv)
    other.login("second@example.com", "correct horse 2")
    assert json.loads(other.req("GET", "/api/state")[1])["prefs"] == {}


@pytest.fixture
def sched_srv(monkeypatch, tmp_path):
    from privhybrid import keystore
    kc = {}
    monkeypatch.setattr(keystore, "_backend", lambda op, uid, v: kc.__setitem__(uid, v) if op == "set" else (kc.pop(uid, None) if op == "delete" else kc.get(uid)))
    monkeypatch.setenv("PRIVHYBRID_SCHEDULER", "1")
    monkeypatch.setattr(providers, "embed", lambda prof, texts, timeout=120: [[1.0, 0.0, 0.0] for t in texts])
    httpd = server.serve(port=0, data_dir=str(tmp_path / "users"), audit_path=str(tmp_path / "audit.jsonl"), dictionary_path=str(tmp_path / "d.txt"))
    httpd.app.scheduler.stop()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    httpd.kc = kc
    yield httpd
    httpd.shutdown()


def test_scheduler_is_off_unless_the_server_switch_is_on(srv):
    c = C(srv)
    c.login()
    assert json.loads(c.req("GET", "/api/sched")[1])["server"] is False
    assert c.req("POST", "/api/sched/optin", {"enable": True, "password": "correct horse 1"})[0] == 403


def test_scheduled_jobs_flow(sched_srv):
    from privhybrid import schedule
    c = C(sched_srv)
    c.login()
    assert c.req("POST", "/api/sched/optin", {"enable": True, "password": "wrong password"})[0] == 400
    assert c.req("POST", "/api/sched/job", {"action": "add", "question": "rates?", "mode": "web"})[0] == 400  # not opted in
    st = json.loads(c.req("POST", "/api/sched/optin", {"enable": True, "password": "correct horse 1"})[1])
    assert st["optin"] and st["keychain"] and st["jobs"] == [] and len(sched_srv.kc) == 1
    body = {"action": "add", "question": "What are mortgage rates today?", "mode": "web", "schedule": {"freq": "daily", "hour": 7, "minute": 0}}
    st = json.loads(c.req("POST", "/api/sched/job", body)[1])
    assert st["jobs"][0]["mode"] == "web" and st["jobs"][0]["next_run"] > 0
    assert c.req("POST", "/api/sched/job", {**body, "question": "my SSN is 123-45-6789"})[0] == 400
    # a result left while signed out is a chat at the next sign-in
    app = sched_srv.app
    sess = next(iter(app.sessions.values()))
    schedule.deposit(sess.account, sess.S, {"job": st["jobs"][0]["id"], "question": body["question"], "mode": "web", "ts": 1.0,
                                           "status": "ok", "answer": "rates are 6%", "notices": [], "steps": []})
    c.req("POST", "/api/logout")
    c2 = C(sched_srv)
    c2.login()
    rows = json.loads(c2.req("GET", "/api/chats")[1])["chats"]
    assert rows[0]["title"].startswith("Scheduled:")
    chat = json.loads(c2.req("GET", "/api/chats/get?id=" + rows[0]["id"])[1])
    assert chat["msgs"][0]["a"] == "rates are 6%" and chat["scheduled"] is True
    # opting out removes the key and the jobs; deleting the account removes the key too
    st = json.loads(c2.req("POST", "/api/sched/optin", {"enable": False, "password": "correct horse 1"})[1])
    assert st["optin"] is False and sched_srv.kc == {}
    c2.req("POST", "/api/sched/optin", {"enable": True, "password": "correct horse 1"})
    assert len(sched_srv.kc) == 1
    assert c2.req("POST", "/api/account/delete", {"password": "correct horse 1"})[0] == 200
    assert sched_srv.kc == {}


def test_metrics_include_latency_and_scheduled_runs():
    rows = [{"route": "local", "outcome": "ok", "ms": 100}, {"route": "local", "outcome": "ok", "ms": 300},
            {"event": "scheduled_run", "status": "ok"}, {"event": "scheduled_run", "status": "failed: sensitive data"}]
    text = server.activity.prometheus(server.activity.summarize(rows), {"ollama": True})
    assert 'privhybrid_request_ms_sum{route="local"} 400' in text and 'privhybrid_request_ms_count{route="local"} 2' in text
    assert 'privhybrid_scheduled_runs_total{status="ok"} 1' in text and 'privhybrid_scheduled_runs_total{status="failed"} 1' in text
    assert 'route="?"' not in text  # scheduler events are not requests


def test_https_mode_serves_over_tls_with_secure_cookie(tmp_path):
    import ssl
    import http.client
    from privhybrid import tls
    folder = tls.make(tmp_path / "tls", ["127.0.0.1"])
    assert oct((folder / "server.key").stat().st_mode & 0o777) == "0o600"
    httpd = server.serve(port=0, data_dir=str(tmp_path / "u"), audit_path=str(tmp_path / "a.jsonl"), dictionary_path=str(tmp_path / "d.txt"), tls_dir=str(folder))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        ctx = ssl.create_default_context(cafile=str(folder / "ca.crt"))
        port = httpd.server_address[1]
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
        body = json.dumps({"email": "t@example.com", "password": "a long password 1"})
        conn.request("POST", "/api/register", body, {"Content-Type": "application/json", "X-Requested-With": "privhybrid", "Origin": f"https://127.0.0.1:{port}"})
        r = conn.getresponse()
        assert r.status == 200 and "Secure" in r.getheader("Set-Cookie") and r.getheader("Strict-Transport-Security")
        r.read()
        conn.request("GET", "/api/tls", headers={"Cookie": r.getheader("Set-Cookie").split(";")[0]})
        info = json.loads(conn.getresponse().read())
        assert info["enabled"] and info["expires"] and 300 < info["days_left"] <= 397
        plain = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            plain.request("GET", "/")
            plain.getresponse().read()
            ok = False
        except (OSError, http.client.HTTPException):
            ok = True
        assert ok  # plain HTTP is not answered on a TLS port
    finally:
        httpd.shutdown()


def test_audit_log_is_owner_only(tmp_path):
    from privhybrid import egress
    log = egress.AuditLog(str(tmp_path / "logs" / "a.jsonl"))
    log.write(route="local", outcome="ok")
    assert (tmp_path / "logs" / "a.jsonl").stat().st_mode & 0o077 == 0


def test_scheduler_notes_are_not_counted_as_requests():
    text = server.activity.prometheus(server.activity.summarize([{"event": "scheduler", "detail": "keychain unavailable"}]), {})
    assert 'route="?"' not in text


def test_amount_sign_keeps_a_debit_and_a_credit_apart():
    from privhybrid.vault import Vault
    v = Vault()
    r = v.mask("The monthly statement for the household account lists one charge of -$50.00 near the start and a refund of $50.00 near the end of the period.")
    text = r[0] if isinstance(r, tuple) else getattr(r, "text", r)
    assert "[AMOUNT_1]" in text and "[AMOUNT_2]" in text
    back = v.unmask(text)[0]
    assert "-$50.00" in back and back.count("$50.00") == 2


def test_a_bracketed_amount_in_prose_is_not_negative():
    from privhybrid.vault import _norm
    assert _norm("AMOUNT", "$50") == _norm("AMOUNT", "($50") == "50"
    assert _norm("AMOUNT", "($50.00)") == "-50.00" and _norm("AMOUNT", "-$50.00") == "-50.00" and _norm("AMOUNT", "5-10") == "510"


def test_a_client_that_never_finishes_the_tls_handshake_is_not_reported(capsys):
    import socket as sk
    srv = server.Server.__new__(server.Server)
    try:
        raise sk.timeout("handshake timed out")
    except sk.timeout:
        srv.handle_error(None, ("127.0.0.1", 1))
    assert capsys.readouterr().err == ""


def test_empty_folders_persist_rename_and_delete(srv):
    c = C(srv); c.login()
    state = lambda: json.loads(c.req("GET", "/api/state")[1])
    assert c.req("POST", "/api/folder/create", {"name": "  "})[0] == 400
    assert c.req("POST", "/api/folder/create", {"name": "Tax"})[0] == 200
    assert c.req("POST", "/api/folder/create", {"name": "Tax"})[0] == 200  # idempotent
    assert state()["folders"] == ["Tax"] and state()["docs"] == []
    assert c.req("POST", "/api/folder/rename", {"old": "Tax", "new": "Taxes"})[0] == 200
    assert state()["folders"] == ["Taxes"]
    _upload(c, "a.txt", "alpha note", "Taxes")
    assert c.req("POST", "/api/folder/delete", {"name": "Taxes"})[0] == 200
    st = state()
    assert st["folders"] == [] and [(d["name"], d["folder"]) for d in st["docs"]] == [("a.txt", "")]  # the file stays, in Unsorted


def test_failed_index_is_recorded_and_files_are_indexed_again_later(srv, monkeypatch):
    from privhybrid import rag
    real_build = rag.build
    c = C(srv); c.login()
    monkeypatch.setattr(rag, "build", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("model busy")) if k.get("embedder") is None and len(a) == 3 else real_build(*a, **k))
    _upload(c, "a.txt", "alpha note", "")
    import time
    for _ in range(40):
        notes = json.loads(c.req("GET", "/api/state")[1])["docs"][0]["notes"]
        if any("unavailable" in n for n in notes):
            break
        time.sleep(0.1)
    assert any("Search index unavailable" in n for n in notes)


def _locked_pdf_with_text(user_pw):
    import io
    from pypdf import PdfWriter
    from pypdf.generic import NameObject, DictionaryObject, DecodedStreamObject
    w = PdfWriter()
    page = w.add_blank_page(300, 300)
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): w._add_object(font)})})
    stream = DecodedStreamObject()
    stream.set_data(b"BT /F1 12 Tf 20 150 Td (Transcript GPA three point eight) Tj ET")
    page[NameObject("/Contents")] = w._add_object(stream)
    w.encrypt(user_pw, owner_password="owner")
    buf = io.BytesIO(); w.write(buf)
    return buf.getvalue()


def test_journey_locked_pdf_asks_for_password_then_is_saved_and_listed(srv):
    c = C(srv); c.login()
    data = base64.b64encode(_locked_pdf_with_text("s3cret")).decode()
    r = c.req("POST", "/api/upload", {"name": "2022_transcript.pdf", "data": data, "folder": ""})
    assert r[0] == 422 and "Password needed" in r[1]
    assert c.req("POST", "/api/upload", {"name": "2022_transcript.pdf", "data": data, "folder": "", "password": "bad"})[0] == 422
    assert c.req("POST", "/api/upload", {"name": "2022_transcript.pdf", "data": data, "folder": "", "password": "s3cret"})[0] == 200
    assert [d["name"] for d in json.loads(c.req("GET", "/api/state")[1])["docs"]] == ["2022_transcript.pdf"]


def test_journey_upload_while_ollama_is_down_still_saves_the_file(srv, monkeypatch):
    from privhybrid import providers
    monkeypatch.setattr(providers, "embed", lambda *a, **k: (_ for _ in ()).throw(providers.Unreachable("down")))
    c = C(srv); c.login()
    assert _upload(c, "note.txt", "alpha note about taxes", "Tax")[0] == 200
    st = json.loads(c.req("GET", "/api/state")[1])
    assert [(d["name"], d["folder"]) for d in st["docs"]] == [("note.txt", "Tax")] and st["folders"] == ["Tax"]


def test_extreme_privacy_forces_local_and_blocks_web_jobs(srv, monkeypatch):
    c = C(srv); c.login()
    assert c.req("POST", "/api/prefs", {"extreme": True})[0] == 200
    seen = []
    orig = providers.chat
    monkeypatch.setattr(providers, "chat", lambda p, m, t=0: seen.append(p["provider"]) or orig(p, m, t))
    for mode in ("claude", "web", "auto"):
        _, raw, _ = c.req("POST", "/api/chat", {"question": "What is the weather today? Search the web.", "mode": mode})
        ev = events(raw)
        assert ev[-1][0] == "done" and ev[-1][1]["route"] == "local" and not ev[-1][1]["sources"]
    assert seen and set(seen) == {"ollama"}
    _, raw, _ = c.req("GET", "/api/state")
    assert json.loads(raw)["prefs"]["extreme"] is True
    assert c.req("POST", "/api/prefs", {"theme": "dark"})[0] == 200  # other prefs saves keep the lock
    assert json.loads(c.req("GET", "/api/state")[1])["prefs"]["extreme"] is True


def test_transcribe_runs_on_this_mac_and_rejects_junk(srv, monkeypatch):
    from privhybrid import speech

    class Seg:
        text = " how much tax "

    class Model:
        def transcribe(self, path, **kw):
            assert open(path, "rb").read() == b"audio-bytes"
            return [Seg(), Seg()], None
    monkeypatch.setattr(speech, "_load", lambda root: Model())
    c = C(srv)
    assert c.req("POST", "/api/transcribe", {"data": ""})[0] == 401  # signed in only
    c.login()
    status, raw, _ = c.req("POST", "/api/transcribe", {"data": base64.b64encode(b"audio-bytes").decode()})
    assert status == 200 and json.loads(raw)["text"] == "how much tax how much tax"
    assert c.req("POST", "/api/transcribe", {"data": "%%%"})[0] == 400
    assert c.req("POST", "/api/transcribe", {"data": ""})[0] == 503
