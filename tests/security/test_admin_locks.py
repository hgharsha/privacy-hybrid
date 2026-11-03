"""V3: administrator permission consistency and cross-process storage locking. Synthetic data only."""
import json
import os
import stat
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from privhybrid import accounts, filelock

PW = "correct horse 1"
SRC = str(Path(__file__).resolve().parents[2] / "src")


@pytest.fixture
def store(tmp_path):
    return accounts.Store(tmp_path / "accts")


def two(store):
    a = store.register("a@example.com", PW)
    b = store.register("b@example.com", PW, by_admin=True)
    return a, b


# --- administrator consistency ---------------------------------------------------------------------

def test_transfer_updates_both_records(store):
    a, b = two(store)
    store.transfer_admin(a, PW, "b@example.com")
    assert store.admin_id() == b.id
    assert store.perms(b.id)["admin"] is True
    assert store.perms(a.id)["admin"] is False
    assert store.record(a.id)["perms"]["admin"] is False  # the stored flag is cleared too, not only ignored


def test_stale_admin_flag_gives_nothing(store):
    a, b = two(store)
    data = store.access()
    data["users"][b.id]["perms"]["admin"] = True  # leftover flag on a non-administrator
    store._write_access(data)
    assert store.perms(b.id)["admin"] is False
    accounts.Store(store.root)  # restart: the leftover flag is cleaned up
    assert store.record(b.id)["perms"]["admin"] is False


def test_former_admin_cannot_transfer_again(store):
    a, b = two(store)
    store.transfer_admin(a, PW, "b@example.com")
    with pytest.raises(accounts.AuthError):
        store.transfer_admin(a, PW, "a@example.com")


def test_transfer_to_disabled_or_unknown_or_self_refused(store):
    a, b = two(store)
    store.set_access(b.id, disabled=True)
    for who in ("b@example.com", "nobody@example.com", "a@example.com"):
        with pytest.raises(accounts.AuthError):
            store.transfer_admin(a, PW, who)
    assert store.admin_id() == a.id


def test_disabled_account_has_no_permissions(store):
    a, b = two(store)
    store.set_access(b.id, perms={"cloud": True})
    store.set_access(b.id, disabled=True)
    assert not any(store.perms(b.id).values())


def test_concurrent_transfers_leave_exactly_one_admin(store):
    a = store.register("a@example.com", PW)
    store.register("b@example.com", PW, by_admin=True)
    store.register("c@example.com", PW, by_admin=True)
    out = []

    def go(to):
        try:
            store.transfer_admin(a, PW, to)
            out.append(to)
        except accounts.AuthError:
            out.append(None)

    ts = [threading.Thread(target=go, args=(t,)) for t in ("b@example.com", "c@example.com")]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(1 for o in out if o) == 1  # the second one finds it is no longer the administrator
    admins = [u for u in store.access()["users"] if store.perms(u)["admin"]]
    assert admins == [store.admin_id()] and len(admins) == 1


def test_missing_admin_file_recovers_to_oldest_account(store):
    a, b = two(store)
    (store.root / "admin").unlink()
    assert store.admin_id() == a.id


# --- locking ---------------------------------------------------------------------------------------

def test_lock_is_reentrant_and_times_out_across_threads(tmp_path):
    p = tmp_path / "x.lock"
    with filelock.locked(p):
        with filelock.locked(p):
            pass
        err = []

        def other():
            try:
                with filelock.locked(p, timeout=0.2):
                    pass
            except filelock.LockTimeout as e:
                err.append(e)
        t = threading.Thread(target=other)
        t.start(); t.join()
        assert err  # a second holder gives up with LockTimeout instead of waiting forever
    with filelock.locked(p, timeout=1):  # and it is free again afterwards
        pass


CHILD = textwrap.dedent("""
    import sys
    sys.path.insert(0, {src!r})
    from privhybrid import accounts
    st = accounts.Store({root!r})
    acct = st.login("a@example.com", {pw!r})
    n = int(sys.argv[1])
    for i in range(n):
        while True:
            obj, ver = acct.load_v("count.bin", {{"n": 0}})
            obj["n"] += 1
            try:
                acct.save("count.bin", obj, base=ver)
                break
            except accounts.Conflict:
                continue
""")


def test_two_processes_do_not_lose_updates(store):
    store.register("a@example.com", PW)
    code = CHILD.format(src=SRC, root=str(store.root), pw=PW)
    ps = [subprocess.Popen([sys.executable, "-c", code, "25"]) for _ in range(2)]
    assert [p.wait(timeout=120) for p in ps] == [0, 0]
    acct = store.login("a@example.com", PW)
    obj, ver = acct.load_v("count.bin", None)
    assert obj == {"n": 50} and ver == 50  # 2 x 25 increments, none lost, no version skipped


def test_stale_version_rejected_across_handles(store):
    a = store.register("a@example.com", PW)
    a.save("f.bin", {"x": 1})
    other = store.login("a@example.com", PW)  # a second "process" with its own key object
    _, v1 = a.load_v("f.bin", None)
    other.save("f.bin", {"x": 2}, base=v1)
    with pytest.raises(accounts.Conflict):
        a.save("f.bin", {"x": 3}, base=v1)
    assert a.load("f.bin", None) == {"x": 2}


def test_password_change_keeps_files_readable_and_private(store):
    a = store.register("a@example.com", PW)
    a.save("notes.bin", {"k": "v"})
    fresh = store.change_password(a, PW, "another long pass 2")
    assert store.login("a@example.com", "another long pass 2").load("notes.bin", None) == {"k": "v"}
    with pytest.raises(accounts.AuthError):
        store.login("a@example.com", PW)
    assert not (store.root / f"{a.id}.bak").exists() and not (store.root / f"{a.id}.rekeying").exists()
    for f in list(fresh.folder.iterdir()) + [store.root / "admin", store.root / "access.json"]:
        assert stat.S_IMODE(f.stat().st_mode) & 0o077 == 0, f.name  # nothing readable by group or others


def test_interrupted_password_change_rolls_back_on_restart(store, monkeypatch):
    a = store.register("a@example.com", PW)
    a.save("notes.bin", {"k": "v"})
    a.save("other.bin", {"k": "w"})
    real = accounts.Account.save
    calls = []

    def dying(self, name, obj, base=None, rekey=False):
        calls.append(name)
        if rekey and len(calls) == 2:
            raise KeyboardInterrupt  # the process is killed half way: no rollback code runs
        return real(self, name, obj, base, rekey)

    monkeypatch.setattr(accounts.Account, "save", dying)
    with pytest.raises(KeyboardInterrupt):
        store.change_password(a, PW, "another long pass 2")
    monkeypatch.undo()
    assert (store.root / f"{a.id}.rekeying").exists()  # the crash left a marker and a backup
    accounts.Store(store.root)  # restart
    back = accounts.Store(store.root).login("a@example.com", PW)  # the old password works again
    assert back.load("notes.bin", None) == {"k": "v"} and back.load("other.bin", None) == {"k": "w"}
    assert not list(store.root.glob("*.rekeying")) and not list(store.root.glob("*.bak"))


def test_failed_password_change_rolls_back(store, monkeypatch):
    a = store.register("a@example.com", PW)
    a.save("notes.bin", {"k": "v"})
    real = accounts.Account.save

    def boom(self, name, obj, base=None, rekey=False):
        if rekey:
            raise OSError("disk full")
        return real(self, name, obj, base, rekey)

    monkeypatch.setattr(accounts.Account, "save", boom)
    with pytest.raises(OSError):
        store.change_password(a, PW, "another long pass 2")
    monkeypatch.undo()
    assert store.login("a@example.com", PW).load("notes.bin", None) == {"k": "v"}


def test_killed_holder_does_not_leave_a_stale_lock(tmp_path):
    p = tmp_path / "k.lock"
    code = f"import sys,time; sys.path.insert(0,{SRC!r})\nfrom privhybrid import filelock\nwith filelock.locked({str(p)!r}):\n print('held',flush=True); time.sleep(60)"
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
    assert proc.stdout.readline().strip() == b"held"
    with pytest.raises(filelock.LockTimeout):
        with filelock.locked(p, timeout=0.3):
            pass
    proc.kill(); proc.wait()
    with filelock.locked(p, timeout=3):  # the operating system freed it when the process died
        pass


def test_succession_is_stable_across_a_password_change(store):
    a, b = two(store)
    c = store.register("c@example.com", PW, by_admin=True)
    store.change_password(b, PW, "another pass 2")  # used to refresh b's file time and make c "older"
    (store.root / "admin").unlink()
    import shutil
    shutil.rmtree(store.root / a.id)
    assert store.admin_id() == b.id and c.id != b.id


def test_old_scrypt_accounts_sign_in_and_are_upgraded(store, monkeypatch):
    import json
    monkeypatch.setattr(accounts, "SCRYPT", {"n": 2 ** 15, "r": 8, "p": 1, "length": 64})
    old = store.register("old@example.com", PW)
    old.save("facts.bin", [{"id": "1", "text": "kept"}])
    meta = store.root / old.id / "meta.json"
    m = json.loads(meta.read_text()); m.pop("kdf"); meta.write_text(json.dumps(m))  # as written before the parameters were stored
    monkeypatch.undo()
    assert store.kdf_outdated(old.id)
    again = store.login("old@example.com", PW)  # still works on the stored (old) cost
    up = store.upgrade_kdf(again, PW)
    assert not store.kdf_outdated(old.id) and json.loads(meta.read_text())["kdf"]["n"] == 2 ** 16
    assert store.login("old@example.com", PW).load("facts.bin", None)[0]["text"] == "kept"
    assert up.load("facts.bin", None)[0]["text"] == "kept"
