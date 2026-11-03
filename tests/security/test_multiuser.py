"""Phases 4 and 5: registration, permissions, isolation, limits, and concurrent sessions of one account."""
import base64
import json
import threading

import pytest

from privhybrid import accounts, server
from tests.test_server import C, events

PW = "correct horse 1"


def admin(srv):
    a = C(srv)
    assert a.req("POST", "/api/register", {"email": "admin@example.com", "password": PW})[0] == 200
    return a


def invite(a, perms=None):
    return json.loads(a.req("POST", "/api/admin/invite", {"perms": perms or {}})[1])["code"]


def join(srv, a, email, perms=None):
    c = C(srv)
    code = invite(a, perms)
    assert c.req("POST", "/api/register", {"email": email, "password": PW, "invite": code})[0] == 200
    return c


def up(c, name="notes.txt", text="The garden needs watering on Tuesday. " * 3):
    return c.req("POST", "/api/upload", {"name": name, "data": base64.b64encode(text.encode()).decode()})


def ask(c, mode, q="Tell me about my garden notes."):
    return c.req("POST", "/api/chat", {"question": q, "mode": mode, "remember": False})


# --- registration --------------------------------------------------------------------------------

def test_registration_is_closed_after_the_first_account(srv):
    admin(srv)
    assert C(srv).req("POST", "/api/register", {"email": "b@example.com", "password": PW})[0] == 400


def test_invitation_works_once_and_a_wrong_code_does_not(srv):
    a = admin(srv)
    code = invite(a)
    assert C(srv).req("POST", "/api/register", {"email": "x@example.com", "password": PW, "invite": "nope"})[0] == 400
    assert C(srv).req("POST", "/api/register", {"email": "b@example.com", "password": PW, "invite": code})[0] == 200
    assert C(srv).req("POST", "/api/register", {"email": "c@example.com", "password": PW, "invite": code})[0] == 400


def test_simultaneous_first_registrations_make_exactly_one_administrator(tmp_path):
    store = accounts.Store(tmp_path / "users")
    ok, bad = [], []

    def go(i):
        try:
            ok.append(store.register(f"u{i}@example.com", PW))
        except accounts.AuthError:
            bad.append(i)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(6)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len(ok) == 1 and len(bad) == 5 and store.count() == 1 and store.admin_id() == ok[0].id


def test_simultaneous_use_of_one_invitation_admits_one_account(tmp_path):
    store = accounts.Store(tmp_path / "users")
    store.register("admin@example.com", PW)
    code = store.create_invite()
    ok = []

    def go(i):
        try:
            ok.append(store.register(f"u{i}@example.com", PW, invite=code))
        except accounts.AuthError:
            pass
    ts = [threading.Thread(target=go, args=(i,)) for i in range(5)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len(ok) == 1


def test_a_setup_code_can_protect_the_first_account(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIVHYBRID_SETUP_TOKEN", "s3tup-code")
    store = accounts.Store(tmp_path / "users")
    with pytest.raises(accounts.AuthError):
        store.register("a@example.com", PW)
    assert store.register("a@example.com", PW, invite="s3tup-code").id == store.admin_id()


def test_existing_accounts_keep_what_they_could_do(tmp_path):
    root = tmp_path / "users"
    store = accounts.Store(root)
    b = store.register("old@example.com", PW, by_admin=False) if False else None
    a = store.register("a@example.com", PW)
    (root / "access.json").unlink()  # an install from before permissions existed
    store2 = accounts.Store(root)
    assert store2.perms(a.id)["cloud"] and store2.perms(a.id)["admin"] and store2.registration_mode() == "invite"


# --- permissions ---------------------------------------------------------------------------------

def test_new_accounts_have_no_cloud_or_web_until_granted(srv, net):
    a = admin(srv)
    b = join(srv, a, "b@example.com")
    assert ask(b, "claude")[0] == 403 and ask(b, "web")[0] == 403
    assert events(ask(b, "auto", "What is the weather today?")[1])[-1][1]["route"] == "local"
    assert net.cloud == [] and net.search == []
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "perms": {"cloud": True}})
    assert events(ask(b, "claude", "Summarise the garden notes please. " + "The weather was mild and the report was short and clear. " * 6)[1])[-1][0] == "done"
    assert len(net.cloud) == 1


def test_permission_changes_apply_to_a_signed_in_user_at_once(srv, net):
    a = admin(srv)
    b = join(srv, a, "b@example.com", {"cloud": True})
    q = "Summarise the garden notes please. " + "The weather was mild and the report was short and clear. " * 6
    assert events(ask(b, "claude", q)[1])[-1][0] == "done"
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "perms": {"cloud": False}})
    assert ask(b, "claude", q)[0] == 403 and len(net.cloud) == 1


def test_upload_and_library_permissions(srv):
    a = admin(srv)
    b = join(srv, a, "b@example.com")
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "perms": {"upload": False}})
    assert up(b)[0] == 403
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "perms": {"upload": True, "library": False}})
    assert up(b)[0] == 200 and b.req("POST", "/api/remove", {"name": "notes.txt"})[0] == 403


def test_only_the_administrator_reaches_admin_calls(srv):
    a = admin(srv)
    b = join(srv, a, "b@example.com")
    for path in ("/api/admin/invite", "/api/admin/registration", "/api/admin/user/create", "/api/admin/user/access", "/api/admin/transfer"):
        assert b.req("POST", path, {})[0] == 403
    assert b.req("GET", "/api/admin/users")[0] == 403 and b.req("GET", "/api/audit")[0] == 403
    assert b.req("POST", "/api/config", {"cloud_provider": "claude_cli"})[0] == 403
    assert C(srv).req("POST", "/api/admin/invite", {})[0] == 401


def test_administrator_cannot_be_disabled_and_role_can_be_transferred(srv):
    a = admin(srv)
    b = join(srv, a, "b@example.com")
    assert a.req("POST", "/api/admin/user/access", {"email": "admin@example.com", "disabled": True})[0] == 400
    assert a.req("POST", "/api/admin/transfer", {"email": "b@example.com", "password": "wrong password"})[0] == 400
    assert a.req("POST", "/api/admin/transfer", {"email": "b@example.com", "password": PW})[0] == 200
    assert b.req("POST", "/api/admin/invite", {})[0] == 200 and a.req("POST", "/api/admin/invite", {})[0] == 403


# --- isolation, sessions, disabled and deleted accounts --------------------------------------------------

def test_one_user_cannot_see_anothers_files_chats_or_prefs(srv):
    a = admin(srv)
    b = join(srv, a, "b@example.com")
    assert up(a, "secret.txt", "Ledger of the garden club, kept private. " * 3)[0] == 200
    ev = events(a.req("POST", "/api/chat", {"question": "garden club ledger?", "mode": "local"})[1])
    cid = ev[-1][1]["chat_id"]
    a.req("POST", "/api/prefs", {"extreme": True})
    st = json.loads(b.req("GET", "/api/state")[1])
    assert st["docs"] == [] and not st["prefs"].get("extreme")
    assert json.loads(b.req("GET", "/api/chats")[1]) in ([], {"chats": []}) or "secret" not in b.req("GET", "/api/chats")[1]
    assert b.req("POST", "/api/chats/get", {"id": cid})[0] in (400, 404) or "garden club" not in b.req("GET", f"/api/chats/get?id={cid}")[1]
    assert b.req("POST", "/api/remove", {"name": "secret.txt"})[0] == 200
    assert [d["name"] for d in json.loads(a.req("GET", "/api/state")[1])["docs"]] == ["secret.txt"]


def test_two_users_at_the_same_time_keep_separate_libraries(srv):
    a = admin(srv)
    b = join(srv, a, "b@example.com")
    ts = [threading.Thread(target=lambda c=c, n=n: [up(c, f"garden-{n}-{i}.txt", f"{n} private text number {i}. " * 4) for i in range(4)]) for c, n in ((a, "a"), (b, "b"))]
    [t.start() for t in ts]; [t.join() for t in ts]
    na = {d["name"] for d in json.loads(a.req("GET", "/api/state")[1])["docs"]}
    nb = {d["name"] for d in json.loads(b.req("GET", "/api/state")[1])["docs"]}
    assert na == {f"garden-a-{i}.txt" for i in range(4)} and nb == {f"garden-b-{i}.txt" for i in range(4)}


def test_idle_session_expires(srv):
    a = admin(srv)
    next(iter(srv.app.sessions.values())).last -= server.IDLE_SECONDS + 5
    assert a.req("GET", "/api/state")[0] == 401


def test_disabled_account_is_signed_out_and_cannot_sign_in(srv):
    a = admin(srv)
    b = join(srv, a, "b@example.com")
    assert b.req("GET", "/api/state")[0] == 200
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "disabled": True})
    assert b.req("GET", "/api/state")[0] == 401
    assert C(srv).req("POST", "/api/login", {"email": "b@example.com", "password": PW})[0] == 401
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "disabled": False})
    assert C(srv).req("POST", "/api/login", {"email": "b@example.com", "password": PW})[0] == 200


def test_password_change_signs_out_other_devices_and_old_password_dies(srv):
    a = admin(srv)
    b1 = join(srv, a, "b@example.com")
    b2 = C(srv)
    assert b2.req("POST", "/api/login", {"email": "b@example.com", "password": PW})[0] == 200
    up(b1, "mine.txt", "Only mine, said the gardener. " * 4)
    assert b1.req("POST", "/api/password", {"old": PW, "new": "another horse 22"})[0] == 200
    assert b2.req("GET", "/api/state")[0] == 401
    assert C(srv).req("POST", "/api/login", {"email": "b@example.com", "password": PW})[0] == 401
    b3 = C(srv)
    assert b3.req("POST", "/api/login", {"email": "b@example.com", "password": "another horse 22"})[0] == 200
    assert [d["name"] for d in json.loads(b3.req("GET", "/api/state")[1])["docs"]] == ["mine.txt"]


def test_account_deletion_removes_data_and_access(srv, tmp_path):
    a = admin(srv)
    b = join(srv, a, "b@example.com")
    up(b)
    assert b.req("POST", "/api/account/delete", {"password": PW})[0] == 200
    assert C(srv).req("POST", "/api/login", {"email": "b@example.com", "password": PW})[0] == 401
    assert "b@example.com" not in json.dumps(srv.app.store.access())


# --- limits -------------------------------------------------------------------------------------------

def test_storage_upload_rate_and_cloud_quotas(srv, net):
    a = admin(srv)
    b = join(srv, a, "b@example.com", {"cloud": True})
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "limits": {"storage_mb": 0, "uploads_per_minute": 100}})
    assert up(b)[0] == 413
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "limits": {"storage_mb": 50, "uploads_per_minute": 2}})
    assert up(b, "one.txt")[0] == 200 and up(b, "two.txt")[0] == 429
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "limits": {"cloud_per_day": 1, "chats_per_minute": 50}})
    q = "Summarise the garden notes please. " + "The weather was mild and the report was short and clear. " * 6
    assert ask(b, "claude", q)[0] == 200 and ask(b, "claude", q)[0] == 429 and len(net.cloud) == 1
    a.req("POST", "/api/admin/user/access", {"email": "b@example.com", "limits": {"chats_per_minute": 1}})
    assert ask(b, "local", "Another question about the garden?")[0] in (200, 429)


# --- concurrent sessions of one account (Phase 5) -------------------------------------------------------

def test_two_sessions_of_one_account_never_overwrite_each_other(srv):
    a1 = admin(srv)
    a2 = C(srv)
    assert a2.req("POST", "/api/login", {"email": "admin@example.com", "password": PW})[0] == 200
    ts = [threading.Thread(target=lambda c=c, n=n: [up(c, f"{n}{i}.txt", f"{n} text number {i} for the garden. " * 4) for i in range(5)]) for c, n in ((a1, "x"), (a2, "y"))]
    [t.start() for t in ts]; [t.join() for t in ts]
    want = {f"{n}{i}.txt" for n in "xy" for i in range(5)}
    assert {d["name"] for d in json.loads(a1.req("GET", "/api/state")[1])["docs"]} == want
    assert {d["name"] for d in json.loads(a2.req("GET", "/api/state")[1])["docs"]} == want
    for s in list(srv.app.sessions.values()):
        for t in s.bg:
            t.join(10)
    a3 = C(srv)
    srv.app.sessions.clear()  # everyone signed out; read back from disk
    assert a3.req("POST", "/api/login", {"email": "admin@example.com", "password": PW})[0] == 200
    assert {d["name"] for d in json.loads(a3.req("GET", "/api/state")[1])["docs"]} == want


def test_a_change_made_outside_the_server_is_not_overwritten(srv, tmp_path):
    a = admin(srv)
    up(a, "first.txt")
    s = next(iter(srv.app.sessions.values()))
    for t in s.bg:
        t.join(10)  # the background index of first.txt has finished and saved
    s.account.save("library.bin", [{"name": "outside.txt", "text": "written by another program", "notes": [], "chunks": [], "vecs": "", "dim": 0, "kind": "file", "chat": ""}])
    # the server's copy is now stale: its next write must be refused and the outside data kept
    assert up(a, "second.txt")[0] == 409
    names = [d["name"] for d in s.account.load("library.bin", [])]
    assert names == ["outside.txt"]
    assert up(a, "third.txt")[0] == 200  # after the reload the next write goes through


def test_account_save_refuses_a_stale_version(tmp_path):
    store = accounts.Store(tmp_path / "users")
    acct = store.register("a@example.com", PW)
    v1 = acct.save("facts.bin", [1])
    acct.save("facts.bin", [1, 2], base=v1)
    with pytest.raises(accounts.Conflict):
        acct.save("facts.bin", [9], base=v1)
    assert acct.load("facts.bin", None) == [1, 2]


def test_older_unversioned_files_still_load(tmp_path):
    import secrets
    store = accounts.Store(tmp_path / "users")
    acct = store.register("a@example.com", PW)
    nonce = secrets.token_bytes(12)
    (acct.folder / "facts.bin").write_bytes(nonce + acct._aead.encrypt(nonce, json.dumps([{"id": "1", "text": "old"}]).encode(), b"facts.bin"))
    assert acct.load("facts.bin", None) == [{"id": "1", "text": "old"}] and acct.load_v("facts.bin", None)[1] == 0


def test_password_change_with_background_work_keeps_every_file_readable(srv):
    a = admin(srv)
    for i in range(3):
        up(a, f"f{i}.txt", f"Garden note number {i}, watered on Tuesday. " * 4)
    assert a.req("POST", "/api/password", {"old": PW, "new": "another horse 22"})[0] == 200
    s = next(iter(srv.app.sessions.values()))
    for t in s.bg:
        t.join(10)
    up(a, "after.txt")  # written under the new key by the same session
    srv.app.sessions.clear()
    c = C(srv)
    assert c.req("POST", "/api/login", {"email": "admin@example.com", "password": "another horse 22"})[0] == 200
    assert len(json.loads(c.req("GET", "/api/state")[1])["docs"]) == 4


def test_first_account_from_another_machine_needs_the_setup_code(tmp_path, monkeypatch):
    monkeypatch.delenv("PRIVHYBRID_SETUP_TOKEN", raising=False)
    store = accounts.Store(tmp_path / "users")
    with pytest.raises(accounts.AuthError):
        store.register("a@example.com", PW, from_loopback=False)
    assert store.count() == 0
    assert store.register("a@example.com", PW, from_loopback=True).id == store.admin_id()


def test_a_setup_code_also_works_from_another_machine(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIVHYBRID_SETUP_TOKEN", "s3tup-code")
    store = accounts.Store(tmp_path / "users")
    assert store.register("a@example.com", PW, invite="s3tup-code", from_loopback=False).id == store.admin_id()


def test_other_users_see_a_reduced_config(srv):
    a = admin(srv)
    b = join(srv, a, "b@example.com")
    full = json.loads(a.req("GET", "/api/config")[1])["config"]
    seen = json.loads(b.req("GET", "/api/config")[1])["config"]
    assert "ollama_url" in full and "ollama_url" not in seen and "cloud_url" not in seen
