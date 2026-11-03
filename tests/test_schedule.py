import json
import time
from types import SimpleNamespace

import pytest

from privhybrid import accounts, egress, keystore, pipeline, schedule, sealed

FOLDERS = ["Taxes"]


@pytest.fixture
def kc(monkeypatch):
    """A dict instead of the real Keychain; `down` makes it unavailable."""
    store = {"down": False}

    def backend(op, uid, value):
        if store["down"]:
            raise RuntimeError("locked")
        if op == "get":
            return store.get(uid)
        if op == "set":
            store[uid] = value
        else:
            store.pop(uid, None)
    monkeypatch.setattr(keystore, "_backend", backend)
    return store


@pytest.fixture
def acct(tmp_path):
    return accounts.Store(tmp_path / "users").register("maria@example.com", "correct horse 1")


def job(**kw):
    base = {"question": "What are mortgage rates today?", "mode": "web", "schedule": {"freq": "daily", "hour": 7, "minute": 0}}
    return {**base, **kw}


def fake_app(acct, sessions=None):
    return SimpleNamespace(store=accounts.Store(acct.folder.parent), sessions=sessions or {}, dictionary={}, log=egress.AuditLog(None))


def ans(text="rates are 6%", route="public_fact"):
    return pipeline.Answer(text, route, ["route: x"], [], [], ["https://example.org"])


# --- sealing -------------------------------------------------------------------------------

def test_sealed_roundtrip_and_tampering():
    priv, pub = sealed.new_keypair()
    mk = sealed.derive(b"s" * 32, b"mac")
    secret = "northwind-plaintext-marker-7f3a"  # long enough that random base64 cannot contain it by chance
    item = sealed.seal(pub, {"answer": secret}, 1, mk)
    assert secret not in json.dumps(item)
    assert sealed.open_item(priv, item, mk) == ({"answer": secret}, True)
    assert sealed.open_item(priv, item, None)[1] is False  # Keychain key unavailable: shown as unverified
    assert sealed.open_item(priv, {**item, "mac": "AAAA"}, mk)[1] is False
    with pytest.raises(sealed.SealError):
        sealed.open_item(priv, {**item, "seq": 2}, mk)  # sequence is bound into the ciphertext
    with pytest.raises(sealed.SealError):
        sealed.open_item(sealed.new_keypair()[0], item, mk)


# --- opt-in and storage --------------------------------------------------------------------

def test_optin_and_optout(acct, kc):
    assert not schedule.enabled(acct)
    S = schedule.enable(acct)
    assert schedule.enabled(acct) and kc[acct.id] and schedule.load_key(acct) == S
    schedule.edit(acct, S, FOLDERS, "add", job(), [])
    raw = b"".join(p.read_bytes() for p in (acct.folder / "sched").iterdir() if p.is_file())
    assert b"mortgage" not in raw  # job text is never plain on disk
    schedule.disable(acct)
    assert not schedule.enabled(acct) and acct.id not in kc and not (acct.folder / "sched").exists()


def test_keychain_down_means_no_key(acct, kc):
    schedule.enable(acct)
    kc["down"] = True
    assert schedule.load_key(acct) is None


def test_job_validation(acct, kc):
    S = schedule.enable(acct)
    bad = [job(question=""), job(question="x" * 8001), job(question="my SSN is 123-45-6789"), job(mode="claude"),
           job(mode="local", folder="Nope"), job(schedule={"freq": "hourly", "hour": 1, "minute": 0}),
           job(schedule={"freq": "daily", "hour": 25, "minute": 0})]
    for b in bad:
        with pytest.raises(schedule.SchedError):
            schedule.edit(acct, S, FOLDERS, "add", b, [])
    for _ in range(schedule.MAX_JOBS):
        schedule.edit(acct, S, FOLDERS, "add", job(), [])
    with pytest.raises(schedule.SchedError):
        schedule.edit(acct, S, FOLDERS, "add", job(), [])


def test_next_run():
    t0 = time.mktime((2026, 11, 2, 12, 0, 0, 0, 0, -1))  # a Monday
    daily = schedule.next_run({"freq": "daily", "hour": 7, "minute": 30, "weekday": 0}, t0)
    assert time.localtime(daily)[2:5] == (3, 7, 30)
    weekly = schedule.next_run({"freq": "weekly", "hour": 7, "minute": 0, "weekday": 2}, t0)
    assert time.localtime(weekly)[2] == 4 and time.localtime(weekly).tm_wday == 2
    assert schedule.next_run({"freq": "daily", "hour": 12, "minute": 0, "weekday": 0}, t0) > t0


# --- running -------------------------------------------------------------------------------

def test_web_job_gets_no_files_and_local_job_only_its_folder():
    seen = []
    runner = lambda q, docs, vault, mode, log: (seen.append((mode, [d.name for d in docs])), ans())[1]
    snap = {"Taxes": [{"name": "w4.txt", "text": "filing status single", "notes": [], "chunks": ["filing status single"], "vecs": "", "dim": 0}]}
    j = {"id": "1", "question": "What is my filing status?", "mode": "web", "folder": ""}
    assert schedule.run_job(j, snap, {}, runner=runner)["status"] == "ok"
    assert seen[-1] == ("web", [])
    schedule.run_job({**j, "mode": "local", "folder": "Taxes"}, snap, {}, runner=runner)
    assert seen[-1] == ("local", ["w4.txt"])


def test_run_refuses_claude_and_sensitive_output():
    j = {"id": "1", "question": "rates?", "mode": "web", "folder": ""}
    assert schedule.run_job(j, {}, {}, runner=lambda *a: ans(route="claude"))["status"] == "failed: route not allowed"
    r = schedule.run_job(j, {}, {}, runner=lambda *a: ans("your SSN is 123-45-6789"))
    assert r["status"] == "failed: sensitive data" and r["answer"] == ""
    r = schedule.run_job(j, {}, {}, runner=lambda *a: (_ for _ in ()).throw(RuntimeError("boom 123-45-6789")))
    assert r["status"] == "failed: RuntimeError" and "123-45-6789" not in json.dumps(r) and "boom" not in json.dumps(r)


def test_scheduler_runs_due_job_and_user_reads_it_after_signin(acct, kc, monkeypatch):
    S = schedule.enable(acct)
    schedule.edit(acct, S, FOLDERS, "add", job(), [])
    jid = schedule.jobs(acct, S)[0]["id"]
    monkeypatch.setattr(pipeline, "run", lambda *a, **k: ans())
    sch = schedule.Scheduler(fake_app(acct), clock=lambda: time.time() + 5)
    assert sch.tick() == 0  # not due yet
    schedule.edit(acct, S, FOLDERS, "run", {"id": jid}, [])
    assert sch.tick() == 1 and sch.tick() == 0  # ran once, next run is tomorrow
    assert (acct.folder / "sched" / "inbox.jsonl").exists()
    assert b"rates are" not in (acct.folder / "sched" / "inbox.jsonl").read_bytes()
    got = schedule.collect(acct, S)
    assert got[0]["answer"] == "rates are 6%" and got[0]["verified"] is True
    chat = schedule.as_chat(got[0])
    assert chat["scheduled"] and chat["msgs"][0]["a"] == "rates are 6%"
    assert schedule.collect(acct, S) == []  # inbox is cleared
    assert schedule.jobs(acct, S)[0]["status"] == "ok"


def test_scheduler_skips_when_paused_busy_or_keychain_down(acct, kc, monkeypatch):
    S = schedule.enable(acct)
    schedule.edit(acct, S, FOLDERS, "add", job(), [])
    jid = schedule.jobs(acct, S)[0]["id"]
    monkeypatch.setattr(pipeline, "run", lambda *a, **k: ans())
    schedule.edit(acct, S, FOLDERS, "run", {"id": jid}, [])
    busy = SimpleNamespace(account=acct, chat_lock=SimpleNamespace(locked=lambda: True), merge_inbox=lambda: None)
    assert schedule.Scheduler(fake_app(acct, {"a": busy})).tick() == 0  # an interactive question wins
    kc["down"] = True
    assert schedule.Scheduler(fake_app(acct)).tick() == 0
    kc["down"] = False
    schedule.edit(acct, S, FOLDERS, "pause", {"id": jid}, [])
    assert schedule.Scheduler(fake_app(acct)).tick() == 0
    schedule.edit(acct, S, FOLDERS, "resume", {"id": jid}, [])
    schedule.edit(acct, S, FOLDERS, "run", {"id": jid}, [])
    assert schedule.Scheduler(fake_app(acct)).tick() == 1


def test_late_run_is_marked_missed_and_not_repeated(acct, kc, monkeypatch):
    S = schedule.enable(acct)
    schedule.edit(acct, S, FOLDERS, "add", job(), [])
    monkeypatch.setattr(pipeline, "run", lambda *a, **k: ans())
    later = time.time() + 3 * 86400  # the Mac was off for three days
    sch = schedule.Scheduler(fake_app(acct), clock=lambda: later)
    assert sch.tick() == 1 and sch.tick() == 0  # one run, not three
    got = schedule.collect(acct, S)
    assert len(got) == 1 and got[0]["missed"] is True
    assert "Missed run" in schedule.as_chat(got[0])["msgs"][0]["notices"][-1]


def test_replayed_inbox_item_is_rejected(acct, kc):
    S = schedule.enable(acct)
    res = {"job": "1", "question": "q", "mode": "web", "ts": time.time(), "status": "ok", "answer": "a", "notices": [], "steps": []}
    schedule.deposit(acct, S, res)
    inbox = acct.folder / "sched" / "inbox.jsonl"
    saved = inbox.read_bytes()
    assert len(schedule.collect(acct, S)) == 1
    inbox.write_bytes(saved)  # restored from a backup
    assert schedule.collect(acct, S) == []


def test_forged_item_without_the_keychain_key_is_unverified(acct, kc):
    S = schedule.enable(acct)
    pub = (acct.folder / "sched" / "pub.key").read_bytes()
    res = {"job": "1", "question": "q", "mode": "web", "ts": time.time(), "status": "ok", "answer": "buy now", "notices": [], "steps": []}
    item = sealed.seal(pub, res, 1, b"\0" * 32)  # an attacker knows the public key but not S
    (acct.folder / "sched" / "inbox.jsonl").write_text(json.dumps(item) + "\n")
    got = schedule.collect(acct, S)
    assert got[0]["verified"] is False and "Unverified" in schedule.as_chat(got[0])["msgs"][0]["notices"][-1]


# --- snapshot and password change ----------------------------------------------------------

def test_snapshot_follows_the_library_and_forgets_deleted_files(acct, kc):
    S = schedule.enable(acct)
    lib = [{"name": "w4.txt", "text": "single", "notes": [], "chunks": ["single"], "folder": "Taxes", "kind": "file", "vecs": "x"},
           {"name": "trip.txt", "text": "Lisbon", "notes": [], "chunks": ["Lisbon"], "folder": "Trips", "kind": "file"}]
    schedule.edit(acct, S, ["Taxes", "Trips"], "add", job(mode="local", folder="Taxes"), lib)
    snap = lambda: schedule._read(acct.folder / "sched" / "snap.s", schedule._file_key(S), {})["folders"]
    assert list(snap()) == ["Taxes"] and [d["name"] for d in snap()["Taxes"]] == ["w4.txt"]  # only the job's folder
    schedule.refresh_snapshot(acct, S, lib[1:])  # w4.txt deleted in the library
    assert snap()["Taxes"] == []


def test_password_change_keeps_results_readable(tmp_path, kc):
    store = accounts.Store(tmp_path / "users")
    a = store.register("maria@example.com", "correct horse 1")
    S = schedule.enable(a)
    res = {"job": "1", "question": "q", "mode": "web", "ts": time.time(), "status": "ok", "answer": "kept", "notices": [], "steps": []}
    schedule.deposit(a, S, res)
    a2 = store.change_password(a, "correct horse 1", "another horse 22")
    assert schedule.collect(a2, S)[0]["answer"] == "kept"
    assert kc[a.id]  # the Keychain key is unchanged


def test_enabling_twice_keeps_jobs_and_unread_results(acct, kc):
    S = schedule.enable(acct)
    schedule.edit(acct, S, FOLDERS, "add", job(), [])
    schedule.deposit(acct, S, {"job": "x", "question": "q", "mode": "web", "ts": 1.0, "status": "ok", "answer": "a", "notices": [], "steps": []})
    assert schedule.enable(acct) == S
    assert len(schedule.jobs(acct, S)) == 1
    assert len(schedule.collect(acct, S)) == 1  # still readable: the key pair was not replaced


def test_one_unreadable_account_does_not_stop_the_others(tmp_path, kc):
    store = accounts.Store(tmp_path / "users")
    a, b = store.register("a@example.com", "correct horse 1"), store.register("b@example.com", "correct horse 1")
    store.set_access(b.id, perms={"scheduled": True})  # a new account has no scheduled-processing permission until the administrator grants it
    Sa, Sb = schedule.enable(a), schedule.enable(b)
    schedule.edit(b, Sb, FOLDERS, "add", job(), [])
    schedule.edit(b, Sb, FOLDERS, "run", {"id": schedule.jobs(b, Sb)[0]["id"]}, [])
    kc[a.id] = __import__("base64").b64encode(b"x" * 32).decode()  # a's Keychain key no longer matches its files
    ran = []
    sch = schedule.Scheduler(fake_app(a), clock=lambda: time.time() + 5)
    sch._run = lambda acct, S, j: ran.append(acct.id)
    assert sch.tick() == 1 and ran == [b.id]


def test_enable_with_a_missing_keychain_key_does_not_wipe_jobs(acct, kc):
    S = schedule.enable(acct)
    schedule.edit(acct, S, FOLDERS, "add", job(), [])
    kc.pop(acct.id)  # the Keychain item is gone but the files remain
    with pytest.raises(schedule.SchedError):
        schedule.enable(acct)
    assert (schedule.slots(acct.folder.parent) and len(schedule.jobs(acct, S)) == 1)


def test_an_unverified_item_does_not_move_the_replay_counter(acct, kc):
    S = schedule.enable(acct)
    d = schedule._dir(acct)
    forged = sealed.seal((d / "pub.key").read_bytes(), {"job": "x", "question": "q", "mode": "web", "ts": 1.0, "status": "ok", "answer": "a",
                                                          "notices": [], "steps": []}, 2 ** 40, b"w" * 32)  # wrong MAC key
    (d / "inbox.jsonl").write_text(json.dumps(forged) + "\n")
    got = schedule.collect(acct, S)
    assert got and got[0]["verified"] is False
    schedule.deposit(acct, S, {"job": "y", "question": "q", "mode": "web", "ts": 2.0, "status": "ok", "answer": "real", "notices": [], "steps": []})
    assert [r["answer"] for r in schedule.collect(acct, S)] == ["real"]  # the genuine result still arrives


def test_a_run_that_crashes_moves_on_instead_of_retrying_every_tick(acct, kc, monkeypatch):
    S = schedule.enable(acct)
    schedule.edit(acct, S, FOLDERS, "add", job(), [])
    schedule.edit(acct, S, FOLDERS, "run", {"id": schedule.jobs(acct, S)[0]["id"]}, [])
    monkeypatch.setattr(schedule, "deposit", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    monkeypatch.setattr(pipeline, "run", lambda *a, **k: ans())
    clock = lambda: time.time() + 5
    sch = schedule.Scheduler(fake_app(acct), clock=clock)
    assert sch.tick() == 0
    j = schedule.jobs(acct, S)[0]
    assert j["status"].startswith("failed") and j["next_run"] > clock()
    assert sch.tick() == 0  # not due again


def test_unverified_items_are_not_shown_twice(acct, kc):
    S = schedule.enable(acct)
    d = schedule._dir(acct)
    item = sealed.seal((d / "pub.key").read_bytes(), {"job": "x", "question": "q", "mode": "web", "ts": 1.0, "status": "ok", "answer": "a", "notices": [], "steps": []}, 5, b"w" * 32)
    (d / "inbox.jsonl").write_text(json.dumps(item) + "\n")
    assert len(schedule.collect(acct, S)) == 1
    (d / "inbox.jsonl").write_text(json.dumps(item) + "\n")  # restored from a backup
    assert schedule.collect(acct, S) == []


def test_jobs_follow_a_folder_rename_and_pause_when_it_is_deleted(tmp_path, monkeypatch):
    from privhybrid import schedule, accounts
    store = accounts.Store(tmp_path)
    acct = store.register("a@example.com", "a long password")
    monkeypatch.setattr(schedule, "enabled", lambda a: True)
    S = b"k" * 32
    lib = [{"name": "t.txt", "text": "x", "notes": [], "chunks": ["x"], "folder": "Tax", "kind": "file"}]
    schedule._dir(acct).mkdir(parents=True, exist_ok=True)
    schedule._write(schedule._dir(acct) / "defs.s", schedule._file_key(S), {"jobs": [
        {"id": "1", "mode": "local", "folder": "Tax", "paused": False, "status": "waiting"},
        {"id": "2", "mode": "web", "folder": "", "paused": False, "status": "waiting"}], "next_seq": 3})
    schedule.folder_changed(acct, S, "Tax", "Taxes", lib)
    j = {x["id"]: x for x in schedule.jobs(acct, S)}
    assert j["1"]["folder"] == "Taxes" and not j["1"]["paused"] and j["2"]["folder"] == ""
    schedule.folder_changed(acct, S, "Taxes", "", lib)
    j = {x["id"]: x for x in schedule.jobs(acct, S)}
    assert j["1"]["paused"] and "deleted" in j["1"]["status"] and not j["2"]["paused"]


def test_real_slot_account_runs_web_job_and_extreme_still_blocks(acct, kc, monkeypatch):
    """The scheduler sees accounts as (id, folder) only; it must still read the Extreme setting, and fail closed when it is stale."""
    from privhybrid import policy
    S = schedule.enable(acct)
    slot = schedule.slots(acct.folder.parent)[0]
    policy.update(acct, style="mac")
    schedule.publish_policy(acct, S)
    assert schedule.scheduler_extreme(slot, S) is False
    policy.update(acct, extreme=True)  # changed without the scheduler's copy being refreshed
    assert schedule.scheduler_extreme(slot, S) is True  # stale copy: unknown means on
    schedule.publish_policy(acct, S)
    assert schedule.scheduler_extreme(slot, S) is True
    policy.update(acct, extreme=False)
    schedule.publish_policy(acct, S)
    assert schedule.scheduler_extreme(slot, S) is False
    (acct.folder / "sched" / "policy.s").unlink()
    assert schedule.scheduler_extreme(slot, S) is True  # missing copy: on
