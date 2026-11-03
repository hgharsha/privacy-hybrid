"""Scheduled jobs (docs/SCHEDULED-JOBS-DESIGN.md). Jobs run while nobody is signed in; results wait, sealed, until sign-in.

Per user, in <account folder>/sched/ (everything there is encrypted under keys derived from the Keychain key S, never the
password key): defs.s (jobs), snap.s (a copy of the folders local jobs read). inbox.jsonl holds sealed results. The password-key
side is sched.bin (private key + replay counter) in the account folder, re-encrypted with the other files on a password change.
K, the password key, is never written or wrapped. Claude is never used; web jobs get no files at all.
"""
import base64
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import detect as D
from . import keystore, pipeline, policy, providers, rag, sealed
from .accounts import Account
from .vault import NeedsApproval, Vault
from . import egress

MAX_JOBS, MAX_QUESTION, TICK, GRACE = 20, 8000, 30, 900
MODES = ("web", "local")
FOLDER_DIR = "sched"
_LOCK = threading.RLock()  # scheduler thread and request handlers both read-modify-write the same files


class SchedError(ValueError):
    """Bad input; the message is safe to show."""


def _dir(acct: Account) -> Path:
    return acct.folder / FOLDER_DIR


def slots(root: Path) -> List[Any]:
    """Accounts that opted in, as (id, folder) only: the scheduler never has a password key."""
    return [SimpleNamespace(id=p.name, folder=p) for p in sorted(Path(root).iterdir())
            if p.is_dir() and not p.name.endswith(".bak") and (p / FOLDER_DIR / "defs.s").exists()]


def enabled(acct: Any) -> bool:
    return (_dir(acct) / "defs.s").exists()


# --- files under S ---------------------------------------------------------------------------

def _write(path: Path, key: bytes, obj: Any) -> None:
    nonce = secrets.token_bytes(12)
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.write_bytes(nonce + AESGCM(key).encrypt(nonce, json.dumps(obj).encode(), path.name.encode()))
    tmp.chmod(0o600)
    os.replace(tmp, path)


def _read(path: Path, key: bytes, default: Any) -> Any:
    try:
        blob = path.read_bytes()
    except OSError:
        return default
    try:
        return json.loads(AESGCM(key).decrypt(blob[:12], blob[12:], path.name.encode()))
    except (InvalidTag, ValueError):
        raise SchedError("scheduled jobs could not be decrypted")


def _file_key(S: bytes) -> bytes:
    return sealed.derive(S, b"privhybrid-sched-files-v1")


def _mac_key(S: bytes) -> bytes:
    return sealed.derive(S, b"privhybrid-inbox-mac-v1")


# --- opt-in ----------------------------------------------------------------------------------

def enable(acct: Account) -> bytes:
    """Create S in the Keychain, the key pair and an empty job list. Returns S (kept in memory by the caller)."""
    with _LOCK:
        if enabled(acct):  # already on: a repeat request must not replace the key pair or empty the job list
            existing = keystore.get(acct.id)
            if existing:
                return existing
            raise SchedError("The saved key is missing from the Keychain. Turn scheduled jobs off, then on again (this clears the old jobs).")
        S = keystore.get(acct.id) or secrets.token_bytes(32)
        keystore.put(acct.id, S)
        d = _dir(acct)
        d.mkdir(mode=0o700, exist_ok=True)
        state = acct.load("sched.bin", {})
        priv, pub = sealed.new_keypair()
        acct.save("sched.bin", {"priv": base64.b64encode(priv).decode(), "max_seq": state.get("max_seq", 0)})
        (d / "pub.key").write_bytes(pub)
        (d / "pub.key").chmod(0o600)
        _write(d / "defs.s", _file_key(S), {"jobs": [], "next_seq": state.get("max_seq", 0) + 1})
        _write(d / "snap.s", _file_key(S), {})
        publish_policy(acct, S)
        return S


def disable(acct: Account) -> None:
    """Remove the key, the jobs, the snapshots and unread results. The replay counter stays so old items stay rejected."""
    import shutil
    with _LOCK:
        try:
            keystore.delete(acct.id)
        except keystore.KeychainUnavailable:
            pass  # without the key the files below are unreadable anyway; they are removed regardless
        shutil.rmtree(_dir(acct), ignore_errors=True)
        state = acct.load("sched.bin", {})
        if state:
            acct.save("sched.bin", {"max_seq": state.get("max_seq", 0)})


def load_key(acct: Account) -> Optional[bytes]:
    """S for a signed-in session; None if this account has not opted in or the Keychain will not answer."""
    if not enabled(acct):
        return None
    try:
        return keystore.get(acct.id)
    except keystore.KeychainUnavailable:
        return None


# --- jobs ------------------------------------------------------------------------------------

def next_run(sched: Dict[str, int], after: float) -> float:
    """The next time strictly after `after` that matches a daily or weekly time (local clock)."""
    t = datetime.fromtimestamp(after).replace(hour=sched["hour"], minute=sched["minute"], second=0, microsecond=0)
    if sched["freq"] == "weekly":
        t += timedelta(days=(sched["weekday"] - t.weekday()) % 7)
    while t.timestamp() <= after:
        t += timedelta(days=7 if sched["freq"] == "weekly" else 1)
    return t.timestamp()


def clean_job(data: dict, folders: List[str]) -> dict:
    q = str(data.get("question", "")).strip()
    if not q or len(q) > MAX_QUESTION:
        raise SchedError(f"The question must be 1 to {MAX_QUESTION} characters")
    mode = data.get("mode")
    if mode not in MODES:
        raise SchedError("Pick web or local")
    if D.detect(q).tier1:
        raise SchedError("That question contains data that must never be sent (SSN, card, password). Remove it.")
    folder = " ".join(str(data.get("folder") or "").split())[:40]
    if mode == "local" and folder not in folders:
        raise SchedError("Pick a folder that has files in it for a local job")
    s = data.get("schedule") or {}
    try:
        sched = {"freq": s["freq"], "hour": int(s["hour"]), "minute": int(s["minute"]), "weekday": int(s.get("weekday", 0))}
    except (KeyError, TypeError, ValueError):
        raise SchedError("Pick a time")
    if sched["freq"] not in ("daily", "weekly") or not (0 <= sched["hour"] < 24 and 0 <= sched["minute"] < 60 and 0 <= sched["weekday"] < 7):
        raise SchedError("Pick a daily or weekly time")
    return {"question": q, "mode": mode, "folder": folder if mode == "local" else "", "schedule": sched}


def jobs(acct: Account, S: bytes) -> List[dict]:
    return _read(_dir(acct) / "defs.s", _file_key(S), {"jobs": []})["jobs"]


def _defs(acct: Account, S: bytes) -> dict:
    return _read(_dir(acct) / "defs.s", _file_key(S), {"jobs": [], "next_seq": 1})


def edit(acct: Account, S: bytes, folders: List[str], action: str, data: dict, library: List[dict]) -> List[dict]:
    """add | update | delete | pause | resume | run (run = due now). Signed in only. Returns the job list."""
    with _LOCK:
        defs = _defs(acct, S)
        js = defs["jobs"]
        job = next((j for j in js if j["id"] == data.get("id")), None)
        if action == "add":
            if len(js) >= MAX_JOBS:
                raise SchedError(f"At most {MAX_JOBS} scheduled jobs")
            new = clean_job(data, folders)
            js.append({**new, "id": secrets.token_hex(6), "paused": False, "last_run": None, "status": "waiting",
                       "next_run": next_run(new["schedule"], time.time()), "created": time.time()})
        elif job is None:
            raise SchedError("No such job")
        elif action == "update":
            job.update(clean_job({**job, **data}, folders))
            job["next_run"] = next_run(job["schedule"], time.time())
        elif action == "delete":
            js.remove(job)
        elif action in ("pause", "resume"):
            job["paused"] = action == "pause"
            if action == "resume":
                job["next_run"] = next_run(job["schedule"], time.time())
        elif action == "run":
            job["next_run"], job["paused"] = time.time(), False
        else:
            raise SchedError("Unknown action")
        _write(_dir(acct) / "defs.s", _file_key(S), defs)
        refresh_snapshot(acct, S, library)
        return js


def folder_changed(acct: Account, S: bytes, old: str, new: str, library: List[dict]) -> None:
    """A folder was renamed (new = its name) or deleted (new = ""): local jobs follow a rename; on a delete they pause, so they never read a different folder later."""
    if not S or not enabled(acct):
        return
    with _LOCK:
        defs = _defs(acct, S)
        hit = [j for j in defs["jobs"] if j["mode"] == "local" and j["folder"] == old]
        for j in hit:
            if new:
                j["folder"] = new
            else:
                j["paused"], j["status"] = True, "Paused: its folder was deleted. Pick another folder."
        if hit:
            _write(_dir(acct) / "defs.s", _file_key(S), defs)
    refresh_snapshot(acct, S, library)


def refresh_snapshot(acct: Account, S: bytes, library: List[dict]) -> None:
    """Copy only the folders local jobs use into snap.s. Called on every library change, so a deleted file leaves at once."""
    if not S or not enabled(acct):
        return
    with _LOCK:
        want = {j["folder"] for j in _defs(acct, S)["jobs"] if j["mode"] == "local"}
        snap = {"at": time.time(), "folders": {f: [{"name": d["name"], "text": d["text"], "notes": d.get("notes", []), "chunks": d.get("chunks", []),
                                                  "vecs": "", "dim": 0, "kind": "file"}
                                                 for d in library if d.get("kind", "file") == "file" and d.get("folder", "") == f] for f in want}}
        _write(_dir(acct) / "snap.s", _file_key(S), snap)


def _prefs_stamp(acct: Any) -> Optional[list]:
    try:
        st = (acct.folder / "prefs.bin").stat()
    except FileNotFoundError:
        return [0, 0]  # no preferences file: nothing is switched on
    except OSError:
        return None
    return [st.st_mtime_ns, st.st_size]


def publish_policy(acct: Account, S: Optional[bytes]) -> None:
    """Copy the Extreme-privacy setting into a sealed file the scheduler can read (it never holds the password key).
    The stamp of prefs.bin goes with it, so a later change this copy did not see reads as 'unknown', which means on."""
    if not S or not enabled(acct):
        return
    try:
        flag = policy.extreme(acct)
    except Exception:
        flag = True
    with _LOCK:
        _write(_dir(acct) / "policy.s", _file_key(S), {"extreme": bool(flag), "stamp": _prefs_stamp(acct)})


def scheduler_extreme(acct: Any, S: bytes) -> bool:
    """Extreme privacy as the scheduler sees it. Anything missing, unreadable or out of date counts as on."""
    try:
        cur = _read(_dir(acct) / "policy.s", _file_key(S), None)
        if not isinstance(cur, dict) or cur.get("stamp") is None or cur.get("stamp") != _prefs_stamp(acct):
            return True
        return bool(cur.get("extreme", True))
    except Exception:
        return True


def snapshot_age(acct: Account, S: bytes) -> Optional[float]:
    return _read(_dir(acct) / "snap.s", _file_key(S), {}).get("at")


# --- running ---------------------------------------------------------------------------------

def run_job(job: dict, snapshot: Dict[str, List[dict]], dictionary: Dict[str, str], log=None,
            runner: Optional[Callable] = None, is_extreme: Optional[Callable[[], bool]] = None,
            can: Optional[Callable[[str], bool]] = None) -> dict:
    """One run -> a result dict. Never raises; nothing sensitive is returned on failure."""
    base = {"job": job["id"], "question": job["question"], "mode": job["mode"], "ts": time.time()}
    fail = lambda why: {**base, "status": f"failed: {why}", "answer": "", "notices": [], "steps": []}
    try:
        if D.detect(job["question"]).tier1:
            return fail("sensitive data")
        if is_extreme is not None:
            with egress.bound(is_extreme, can):  # the policy and permissions are read again before every send inside this run
                if job["mode"] != "local" and egress.extreme_now():
                    return fail("extreme privacy")
                if job["mode"] == "web" and can is not None and not can("web"):
                    return fail("no web access")
                return run_job(job, snapshot, dictionary, log, runner)
        docs = [] if job["mode"] == "web" else rag.select(job["question"], snapshot.get(job["folder"], []))  # web: no files, ever
        ans = (runner or pipeline.run)(job["question"], docs, Vault(dictionary), job["mode"], log)
        if ans.route == "claude":
            return fail("route not allowed")
        if D.detect(ans.text).tier1:
            return fail("sensitive data")
        return {**base, "status": "ok", "answer": ans.text, "notices": ans.notices, "steps": ans.steps, "sources": ans.sources, "route": ans.route}
    except NeedsApproval:
        return fail("sensitive data")
    except (egress.EgressBlocked, providers.ProviderError) as exc:
        return fail(type(exc).__name__)
    except Exception as exc:  # never echo the text: it could contain input
        return fail(type(exc).__name__)


def deposit(acct: Account, S: bytes, result: dict) -> None:
    """Seal one result to the user's public key and append it to the inbox."""
    with _LOCK:
        d = _dir(acct)
        defs = _defs(acct, S)
        seq = defs["next_seq"]
        defs["next_seq"] = seq + 1
        _write(d / "defs.s", _file_key(S), defs)
        item = sealed.seal((d / "pub.key").read_bytes(), result, seq, _mac_key(S))
        with open(d / "inbox.jsonl", "a") as fh:
            fh.write(json.dumps(item) + "\n")
        (d / "inbox.jsonl").chmod(0o600)


def collect(acct: Account, S: Optional[bytes]) -> List[dict]:
    """Open every waiting result (signed in only, needs the password key). Replays and unreadable items are dropped.
    Each result gets `verified`: False when the MAC is wrong or the Keychain key could not be read."""
    with _LOCK:
        inbox = _dir(acct) / "inbox.jsonl"
        state = acct.load("sched.bin", {})
        if not inbox.exists() or "priv" not in state:
            return []
        priv, seen, out = base64.b64decode(state["priv"]), state.get("max_seq", 0), []
        unv = [tuple(x) for x in state.get("unv", [])]  # (id, seq) of items shown as unverified: they never move max_seq, so remember them
        for line in inbox.read_text().splitlines():
            try:
                item = json.loads(line)
                if int(item["seq"]) <= state.get("max_seq", 0) or (item.get("id"), int(item["seq"])) in unv:
                    continue  # old item put back (for example from a backup)
                obj, ok = sealed.open_item(priv, item, _mac_key(S) if S else None)
            except (ValueError, KeyError, TypeError, sealed.SealError):
                continue
            if ok:  # an item that fails the MAC must not move the replay counter: anyone who can write the inbox can seal one
                seen = max(seen, int(item["seq"]))
            else:
                unv.append((item.get("id"), int(item["seq"])))
            out.append({**obj, "verified": ok, "seq": int(item["seq"])})
        acct.save("sched.bin", {**state, "max_seq": seen, "unv": [list(x) for x in unv[-500:]]})
        inbox.unlink()
        return sorted(out, key=lambda r: r["seq"])


def as_chat(result: dict, missed: bool = False) -> dict:
    title = ("Scheduled: " + result["question"])[:60]
    notes = list(result.get("notices", []))
    if result.get("missed") or missed:
        notes.append("Missed run: the Mac was off or asleep at the scheduled time, so this ran late.")
    if not result.get("verified", True):
        notes.append("Unverified: this result could not be checked against the scheduler key. Treat it with care.")
    answer = result["answer"] if result["status"] == "ok" else f"This scheduled run did not complete ({result['status']})."
    return {"title": title, "ts": result["ts"], "scheduled": True,
            "msgs": [{"q": result["question"], "a": answer, "route": result.get("route") or ("public_fact" if result.get("mode") == "web" else "local"), "steps": result.get("steps", []),
                      "notices": notes, "sources": result.get("sources", []), "scheduled": True}]}


class Scheduler:
    """One thread, one job at a time. Interactive questions win: a user who is asking something is skipped this tick."""

    def __init__(self, app: Any, clock: Callable[[], float] = time.time) -> None:
        self.app, self.clock = app, clock
        self._stop = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(TICK):
            try:
                self.tick()
            except Exception:
                pass  # a bad tick must not kill the scheduler

    def _allowed(self, uid: str, kind: str) -> bool:
        store = self.app.store
        try:
            return bool(store.perms(uid).get(kind)) and not store.record(uid).get("disabled")
        except Exception:
            return False  # permissions unreadable: not allowed

    def tick(self) -> int:
        """Run what is due. Returns how many ran."""
        ran = 0
        for acct in slots(self.app.store.root):
            if not self._allowed(acct.id, "scheduled"):
                continue  # a disabled account, or one without permission for scheduled processing, does not run
            busy = any(s.account.id == acct.id and s.chat_lock.locked() for s in list(self.app.sessions.values()))
            if busy:
                continue
            try:
                S = keystore.get(acct.id)
            except keystore.KeychainUnavailable:
                self.app.log.write(event="scheduler", detail="keychain unavailable, run skipped")
                continue
            if not S:
                continue
            try:
                due = [j for j in jobs(acct, S) if not j["paused"] and j["next_run"] <= self.clock()]
            except SchedError:  # this account's jobs cannot be read (key changed); the others must still run
                self.app.log.write(event="scheduler", detail="jobs unreadable, account skipped")
                continue
            for job in due:
                try:
                    self._run(acct, S, job)
                    ran += 1
                except Exception as exc:  # a full disk or an unreadable file must not starve the accounts after this one
                    self.app.log.write(event="scheduler", detail=f"run failed: {type(exc).__name__}")
                    self._give_up(acct, S, job, type(exc).__name__)
        return ran

    def _give_up(self, acct: Account, S: bytes, job: dict, why: str) -> None:
        """A run that cannot finish moves to its next slot, so it is not retried (and re-sealed) on every tick."""
        try:
            with _LOCK:
                defs = _defs(acct, S)
                for j in defs["jobs"]:
                    if j["id"] == job["id"]:
                        j["last_run"], j["status"] = self.clock(), f"failed: {why}"
                        j["next_run"] = next_run(j["schedule"], self.clock())
                _write(_dir(acct) / "defs.s", _file_key(S), defs)
        except Exception:
            pass  # the disk or the key is the problem: nothing more to do here

    def _run(self, acct: Account, S: bytes, job: dict) -> None:
        late = self.clock() - job["next_run"] > GRACE
        snap = _read(_dir(acct) / "snap.s", _file_key(S), {}).get("folders", {})
        result = run_job(job, snap, self.app.dictionary, self.app.log, is_extreme=lambda: scheduler_extreme(acct, S),
                         can=lambda k: self._allowed(acct.id, k))
        result["missed"] = late
        self.app.log.write(event="scheduled_run", status="ok" if result["status"] == "ok" else "failed", mode=job["mode"])
        with _LOCK:
            deposit(acct, S, result)
            defs = _defs(acct, S)
            for j in defs["jobs"]:
                if j["id"] == job["id"]:
                    j["last_run"], j["status"] = self.clock(), result["status"]
                    j["next_run"] = next_run(j["schedule"], self.clock())
            _write(_dir(acct) / "defs.s", _file_key(S), defs)
        for s in list(self.app.sessions.values()):  # signed in right now: show it without waiting for the next sign-in
            if s.account.id == acct.id:
                s.merge_inbox()
