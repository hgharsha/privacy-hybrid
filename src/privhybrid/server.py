"""Local web UI server (T11). Binds 127.0.0.1 only, email + password accounts, same-origin checks, no request text in logs.

Run: PYTHONPATH=src .venv/bin/python -m privhybrid.server
"""
import base64
import datetime
import binascii
import hmac
import json
import mimetypes
import os
import re
import secrets
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional

from . import detect as D
from urllib.parse import parse_qs, urlparse

from . import accounts, activity, config, egress, ingest, keystore, local, lockdown, pipeline, providers, policy, rag, schedule, speech, tls
from .vault import NeedsApproval, Vault

import ipaddress
import sys
import socket
import ssl

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "static"
STATE = ROOT / "state"
MAX_BODY = 8 * 1024 * 1024
ACCOUNT_FAILS_PER_MINUTE = 20  # across all addresses: caps guessing against one account from many machines
PREAUTH_BODY = 16 * 1024  # sign-in and sign-up carry an email, a password and an invite code
SOCKET_TIMEOUT = 30  # seconds a client may stay silent mid-request before its connection is dropped
MAX_CONNECTIONS = 64  # simultaneous connections; more are closed at once
BG_WORKERS = 4  # indexing and memory work for all accounts together
STYLES = ("mac", "indigo", "ocean", "forest", "graphite", "vision")
THEMES = ("auto", "light", "dark")
MAX_QUESTION = 8000  # one paste must not hold the local model for minutes
MANY_QUESTIONS = 3  # this many question marks in one message: answered locally, never split
IDLE_SECONDS = 8 * 3600
MAX_FACTS_SHOWN = 60
DEMO_EMAIL, DEMO_PASSWORD = "demo@example.com", "demo-pass-2026"  # throwaway; only reachable with PRIVHYBRID_DEMO=1
CSP = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"


class _Bg:
    """A queued background job that can be joined (tests and shutdown use join; is_alive says whether it still runs)."""

    def __init__(self, fut) -> None:
        self.fut = fut

    def join(self, timeout=None) -> None:
        try:
            self.fut.result(timeout)
        except Exception:
            pass

    def is_alive(self) -> bool:
        return not self.fut.done()


class Shared:
    """Everything stored for one signed-in account, held once and used by every session (device) of that account, so a second device never
    works from a stale copy. Each file is saved against the version it was read at: if something else changed it on disk (another process,
    a restore) the write is refused with accounts.Conflict and the copy here is reloaded, never silently overwritten."""

    def __init__(self, account: accounts.Account) -> None:
        self.account = account
        self.lock = threading.Lock()  # guards the collections below
        self.io = threading.RLock()  # every write, and a password change, hold this: no write can use a key that is being replaced
        self.ver: Dict[str, int] = {}
        self.library: List[dict] = self._get("library.bin", [])  # decrypted for this login only
        self.chats: Dict[str, dict] = self._get("chats.bin", {})
        self.folders: List[str] = self._get("folders.bin", [])  # folder names, so an empty folder survives a reload
        self.facts: List[dict] = self._get("facts.bin", [])  # what the user has told the assistant about themselves
        self.sessions = 0

    def _get(self, name: str, default):
        obj, self.ver[name] = self.account.load_v(name, default)
        return obj

    def save(self, name: str, obj) -> None:
        with self.io:
            try:
                self.ver[name] = self.account.save(name, obj, base=self.ver.get(name, 0))
            except accounts.Conflict:
                fresh = self._get(name, type(obj)())
                if isinstance(obj, list):
                    obj[:] = fresh
                else:
                    obj.clear(); obj.update(fresh)
                raise

    def rekey(self, account: accounts.Account) -> None:
        """After a password change: the new key for everyone, and the versions the re-encryption wrote."""
        self.account = account
        for name in list(self.ver):
            self.ver[name] = account.load_v(name, None)[1]


def _shared(name: str):
    return property(lambda self: getattr(self.shared, name), lambda self, v: setattr(self.shared, name, v))


POOL = ThreadPoolExecutor(max_workers=BG_WORKERS, thread_name_prefix="privhybrid-bg")  # bounded: uploads queue behind it, they do not each start a thread


class Session:
    library, chats, folders, facts, lock, account = (_shared(n) for n in ("library", "chats", "folders", "facts", "lock", "account"))

    def __init__(self, dictionary: Dict[str, str], account: accounts.Account, shared: Optional[Shared] = None) -> None:
        self.shared = shared or Shared(account)
        self.vault = Vault(dictionary)  # the placeholder map lives here, in memory only
        self.prefs: dict = {}  # a view only; the stored policy is read from disk when it matters (policy.py)
        try:
            self.prefs = policy.prefs(self.account)
        except policy.PolicyUnavailable:
            self.prefs = {"extreme": True}
        self.bg: List["_Bg"] = []
        self.pool = POOL
        self.can = lambda kind: True  # App replaces this with the account's stored permissions
        self.S = schedule.load_key(account)  # scheduler key from the Keychain; None unless this account opted in
        self.cancel = None  # the providers.Cancel of the question being answered; /api/cancel stops it
        self.pending = {}  # preview id -> [Event, answer]: a cloud send waiting for the user to look at it
        self.chat_lock = threading.Lock()  # one question at a time (the vault is shared); never held with lock
        self.last = time.time()

    def bind(self):
        """Every thread that sends anything for this account asks the stored policy again right before it transmits."""
        return egress.bound(lambda: policy.extreme(self.account), lambda kind: self.can(kind))

    def submit(self, fn) -> None:
        job = _Bg(self.pool.submit(fn))
        self.bg = [x for x in self.bg if x.is_alive()] + [job]

    def extreme(self) -> bool:
        return policy.extreme(self.account)  # read from disk each time: another device may have changed it

    def docs(self) -> List[ingest.Document]:
        return [rag._doc(d) for d in self.library]

    def start_index(self, it: dict, notes: List[str]) -> None:
        """Build the search index for one saved file in the background; the file is already kept either way."""
        def index() -> None:
            try:
                with self.bind():
                    full = rag.build(it["name"], it["text"], notes)
            except Exception:
                full = {"vecs": "", "dim": 0, "notes": notes + ["Search index unavailable; keyword matching only."]}
            with self.lock:
                if any(d is it for d in self.library):
                    it.update(vecs=full["vecs"], dim=full["dim"], notes=full["notes"])
                    try:
                        self.save_library()
                    except accounts.Conflict:
                        pass  # the file changed elsewhere; the index is rebuilt at the next sign-in
        self.submit(index)

    def resume_indexing(self) -> None:
        """After a restart or sign-in: files whose index never finished are indexed again (one at a time)."""
        todo = [d for d in self.library if d.get("kind", "file") == "file" and not d.get("vecs")]
        def run() -> None:
            for d in todo:
                self_notes = [n for n in d.get("notes", []) if not n.startswith("Search index")]
                try:
                    with self.bind():
                        full = rag.build(d["name"], d["text"], self_notes)
                except Exception:
                    continue
                with self.lock:
                    if any(x is d for x in self.library) and full["vecs"]:
                        d.update(vecs=full["vecs"], dim=full["dim"], notes=full["notes"])
                        try:
                            self.save_library()
                        except accounts.Conflict:
                            return
        if todo:
            self.submit(run)

    def save_folders(self) -> None:
        self.shared.save("folders.bin", self.folders)

    def save_library(self) -> None:
        self.shared.save("library.bin", self.library)
        schedule.refresh_snapshot(self.account, self.S, self.library)  # a deleted or moved file leaves local jobs' copy at once

    def merge_inbox(self) -> None:
        """Results scheduled jobs left while nobody was signed in become chats."""
        if not schedule.enabled(self.account):
            return
        with self.lock:
            self.S = self.S or schedule.load_key(self.account)
            schedule.publish_policy(self.account, self.S)  # the scheduler reads Extreme privacy from this sealed copy
            got = schedule.collect(self.account, self.S)
            for r in got:
                self.chats[secrets.token_hex(8)] = schedule.as_chat(r)
            if got:
                self.save_chats()

    def save_facts(self) -> None:
        self.shared.save("facts.bin", self.facts)

    def known(self) -> Optional[ingest.Document]:
        if not self.facts:
            return None
        lines = "\n".join(f"- {f['text']}" for f in self.facts[-MAX_FACTS_SHOWN:])
        return ingest.Document("What I know about you", lines, [])

    def save_chats(self) -> None:
        self.shared.save("chats.bin", self.chats)


class App:
    def __init__(self, data_dir: str, audit_path: str, dictionary_path: str = "") -> None:
        self.store = accounts.Store(Path(data_dir))
        self._swept = 0.0
        self.sessions: Dict[str, Session] = {}
        self.log = egress.AuditLog(audit_path)
        self.audit_path = audit_path
        self.transcriber = None  # tests replace this; None means the real Whisper model
        self.dictionary = D.load_dictionary(dictionary_path) if dictionary_path else {}
        self.fails: List[tuple] = []
        self.demo_items: Optional[List[dict]] = None
        self.metrics = os.environ.get("PRIVHYBRID_METRICS") == "1"  # opt-in: GET /metrics for Prometheus, from this Mac only
        self.demo = os.environ.get("PRIVHYBRID_DEMO") == "1"  # opt-in: /demo signs in a shared throwaway account
        self.sched_on = os.environ.get("PRIVHYBRID_SCHEDULER") == "1" and not self.demo  # opt-in: scheduled jobs (docs/SCHEDULED-JOBS-DESIGN.md)
        self.scheduler = schedule.Scheduler(self)
        self.lock = threading.Lock()
        self.rates: Dict[tuple, List[float]] = {}

    def allow(self, uid: str, kind: str, limit: int, window: float = 60.0) -> bool:
        """Sliding-window limit per account and kind ("chat", "upload", "cloud"). A limit of 0 means none allowed."""
        now = time.time()
        with self.lock:
            hits = [t for t in self.rates.get((uid, kind), []) if now - t < window]
            ok = len(hits) < limit
            if ok:
                hits.append(now)
            self.rates[(uid, kind)] = hits
            return ok

    def perm(self, uid: str, kind: str) -> bool:
        return bool(self.store.perms(uid).get(kind)) and not self.store.record(uid).get("disabled")

    def locked_out(self, *keys: str, limit: int = 5) -> bool:
        """Five failures in a minute for the same email or the same address lock that one out."""
        now = time.time()
        with self.lock:
            self.fails = [f for f in self.fails if now - f[0] < 60]
            return any(sum(1 for f in self.fails if f[1] == k) >= limit for k in keys)

    def fail(self, *keys: str) -> None:
        with self.lock:
            self.fails += [(time.time(), k) for k in keys]

    def upgrade_kdf(self, acct: accounts.Account, password: str) -> accounts.Account:
        """Move an older account to the current scrypt cost at sign-in, but only when no other device is signed in (they would hold the old key)."""
        with self.lock:
            busy = any(v.account.id == acct.id for v in self.sessions.values())
        if busy or not self.store.kdf_outdated(acct.id):
            return acct
        try:
            return self.store.upgrade_kdf(acct, password)
        except (accounts.AuthError, accounts.Conflict, OSError):
            return acct  # signing in still works on the old setting

    def new_session(self, account: accounts.Account) -> str:
        sid = secrets.token_urlsafe(32)
        uid = account.id
        with self.lock:  # looked up and registered in one step: two devices signing in together share one state
            shared = next((v.shared for v in self.sessions.values() if v.account.id == uid), None)
            sess = Session(self.dictionary, account, shared)
            sess.can = lambda kind: self.perm(uid, kind)  # read from the stored record each time: the administrator's change applies at once
            self.sessions[sid] = sess
        sess.resume_indexing()
        sess.merge_inbox()
        return sid

    def drop_session(self, sid: str) -> None:
        with self.lock:
            self.sessions.pop(sid, None)

    def drop_others(self, keep: "Session") -> None:
        """Other devices still hold the old key: they must sign in again."""
        with self.lock:
            for sid in [k for k, v in self.sessions.items() if v.account.id == keep.account.id and v is not keep]:
                del self.sessions[sid]

    def get_session(self, sid: str) -> Optional[Session]:
        with self.lock:
            now = time.time()
            if now - self._swept > 60:  # abandoned tabs too: the key goes with the session
                for k in [k for k, v in self.sessions.items() if now - v.last > IDLE_SECONDS]:
                    del self.sessions[k]
                self._swept = now
            s = self.sessions.get(sid)
            if s and now - s.last > IDLE_SECONDS:
                del self.sessions[sid]
                return None
            if s and self.store.record(s.account.id).get("disabled"):
                del self.sessions[sid]  # a disabled account is signed out at its next request
                return None
            if s:
                s.last = now
        return s

    def ollama_url(self) -> str:
        return str(config.current()["ollama_url"])

    def ollama_up(self) -> str:
        """The first configured Ollama address that answers ("" if none). Remembered for 5 s: a dead address costs 2 s per probe."""
        now = time.time()
        urls = tuple([self.ollama_url()] + config.ollama_backups())
        if getattr(self, "_up", None) and self._up[0] == urls and now - self._up[1] < 5:
            return self._up[2]
        def up(u: str) -> bool:
            try:
                return egress.probe(u + ("/v1/models" if config.local_runtime() == "local_openai" else "/api/tags"))
            except egress.EgressBlocked:
                return False
        url = next((u for u in urls if up(u)), "")
        self._up = (urls, now, url)
        return url

    def installed_models(self) -> List[str]:
        try:
            if config.local_runtime() == "local_openai":
                return sorted(m["id"] for m in egress.local_json(self.ollama_up() + "/v1/models").get("data", []))
            return sorted(m["name"] for m in egress.local_json(self.ollama_up() + "/api/tags").get("models", []))
        except Exception:
            return []

    def health(self) -> Dict[str, bool]:
        return {"ollama": bool(self.ollama_up()),
                "search": egress.probe(egress.SEARX_URL + "/healthz") or egress.probe(egress.SEARX_URL)}

    def audit_tail(self, n: int = 40) -> List[dict]:
        try:
            return activity.load(self.audit_path, n)
        except OSError:
            return []


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "privhybrid"
        timeout = SOCKET_TIMEOUT  # a client that stops sending mid-request loses its connection instead of holding a worker forever

        def setup(self):
            if getattr(self.server, "tls", False):  # handshake here, not in accept(): a stalled client must not block everyone else
                self.request.settimeout(10)
                self.request.do_handshake()
                self.request.settimeout(None)
            super().setup()

        def log_message(self, fmt, *args):  # request lines can carry paths only, but keep the console quiet anyway
            pass

        # --- helpers ---
        def _this_mac(self) -> bool:
            """The caller is a process on this Mac: loopback, or this machine's own address (the server may be bound to the LAN IP only)."""
            peer = self.client_address[0]
            return ipaddress.ip_address(peer).is_loopback or peer == self.connection.getsockname()[0]

        def _headers(self, code, ctype, length=None, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            if length is not None:
                self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            if getattr(self.server, "tls", False):
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            for k, v in (extra or {}).items():
                self.send_header(k, v)

        def _json(self, code, obj, extra=None):
            body = json.dumps(obj).encode()
            self._headers(code, "application/json", len(body), extra)
            self.end_headers()
            self.wfile.write(body)

        def _secure(self) -> str:
            return "; Secure" if getattr(self.server, "tls", False) else ""

        def _hosts(self):
            port = self.server.server_address[1]
            names = {"127.0.0.1", "localhost", self.server.server_address[0]}
            return {f"{n}:{port}" for n in names}

        def _host_ok(self) -> bool:
            return (self.headers.get("Host") or "").lower() in self._hosts()  # blocks DNS rebinding

        def _same_origin(self) -> bool:
            origin = self.headers.get("Origin")
            scheme = "https" if getattr(self.server, "tls", False) else "http"
            if origin and origin not in {f"{scheme}://{h}" for h in self._hosts()}:
                return False
            return self.headers.get("X-Requested-With") == "privhybrid"

        def _session(self) -> Optional[Session]:
            c = SimpleCookie(self.headers.get("Cookie", ""))
            sid = c["ph_session"].value if "ph_session" in c else ""
            return app.get_session(sid)

        def _body(self, limit: int = MAX_BODY) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > limit:
                raise ValueError("body too large")
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("body must be an object")
            return body

        # --- routes ---
        def do_GET(self):
            if not self._host_ok():
                return self._json(403, {"error": "bad host"})
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path.startswith("/static/"):
                return self._static(path[len("/static/"):])
            if path == "/metrics" and app.metrics and self._this_mac():
                body = activity.prometheus(activity.summarize(activity.load(app.audit_path)), app.health()).encode()
                self._headers(200, "text/plain; version=0.0.4", len(body))
                self.end_headers()
                return self.wfile.write(body)
            if path == "/demo" and app.demo:
                return self._demo()
            s = self._session()
            if s is None:
                return self._json(401, {"error": "login required"})
            if path == "/api/state":
                return self._json(200, {"docs": [{"name": d["name"], "notes": d["notes"], "chars": len(d["text"]), "folder": d.get("folder", "")} for d in s.library if d.get("kind", "file") == "file"],
                                        "folders": sorted(set(s.folders) | set(self._folders(s))),
                                        "health": app.health(), "modes": list(pipeline.MODES), "email": s.account.email, "admin": app.store.admin_id() == s.account.id, "perms": app.store.perms(s.account.id),
                                        "facts": [{"id": f["id"], "text": f["text"]} for f in s.facts], "prefs": self._fresh_prefs(s), "demo": app.demo, "cloud_label": config.cloud_label()})
            if path == "/api/config":
                cfg = config.current()
                if app.store.admin_id() != s.account.id:  # others see what the app is called, not where it connects
                    cfg = {k: cfg[k] for k in ("cloud_label", "cloud_provider", "remote_ollama_warning") if k in cfg}
                return self._json(200, {"config": cfg, "installed": app.installed_models()})
            if path == "/api/tls":
                if app.store.admin_id() != s.account.id:
                    return self._json(403, {"error": "only the first account can view this"})
                d = getattr(self.server, "tls_dir", "")
                if not d:
                    return self._json(200, {"enabled": False})
                try:
                    end = tls.expires(d)
                except (OSError, ValueError):
                    return self._json(200, {"enabled": True, "expires": None})
                days = (end - datetime.datetime.now(datetime.timezone.utc)).days
                return self._json(200, {"enabled": True, "expires": end.date().isoformat(), "days_left": days})
            if path == "/api/sched":
                return self._json(200, self._sched_state(s))
            if path == "/api/chats":
                rows = sorted(({"id": k, "title": v["title"], "ts": v["ts"]} for k, v in s.chats.items()), key=lambda r: -r["ts"])
                return self._json(200, {"chats": rows})
            if path == "/api/chats/get":
                cid = (parse_qs(urlparse(self.path).query).get("id") or [""])[0]
                if cid not in s.chats:
                    return self._json(404, {"error": "not found"})
                return self._json(200, {"id": cid, **s.chats[cid]})
            if path == "/api/activity":
                if app.store.admin_id() != s.account.id:
                    return self._json(403, {"error": "only the first account can view activity"})
                rows = activity.load(app.audit_path)
                return self._json(200, {"summary": activity.summarize(rows), "recent": rows[-30:][::-1], "health": app.health()})
            if path == "/api/audit":
                if app.store.admin_id() != s.account.id:
                    return self._json(403, {"error": "only the first account can view the audit log"})
                return self._json(200, {"rows": app.audit_tail()})
            if path == "/api/admin/users":
                if app.store.admin_id() != s.account.id:
                    return self._json(403, {"error": "administrator only"})
                acc = app.store.access()
                return self._json(200, {"registration": acc.get("registration", "invite"), "invites_open": len(acc.get("invites", {})),
                                        "users": [{"id": uid, "admin": uid == app.store.admin_id(), "disabled": bool(r.get("disabled")),
                                                   "perms": app.store.perms(uid), "limits": app.store.limits(uid)} for uid, r in acc["users"].items()]})
            self._json(404, {"error": "not found"})

        def _folders(self, s: Session) -> List[str]:
            return sorted({d.get("folder", "") for d in s.library if d.get("kind", "file") == "file" and d.get("folder")})

        def _sched_state(self, s: Session) -> dict:
            on = schedule.enabled(s.account)
            out = {"server": app.sched_on, "optin": on, "keychain": s.S is not None, "jobs": [], "folders": self._folders(s)}
            if on and s.S:
                out["jobs"] = [{k: j[k] for k in ("id", "question", "mode", "folder", "schedule", "paused", "last_run", "next_run", "status")}
                               for j in schedule.jobs(s.account, s.S)]
                out["snapshot_at"] = schedule.snapshot_age(s.account, s.S)
            return out

        def _sched_post(self, s: Session, path: str, body: dict):
            if not app.sched_on:
                return self._json(403, {"error": "Scheduled jobs are switched off on this server (PRIVHYBRID_SCHEDULER=1 turns them on)."})
            try:
                if path == "/api/sched/optin":
                    key = "pw:" + s.account.id
                    if app.locked_out(key):
                        return self._json(429, {"error": "too many attempts, wait a minute"})
                    try:
                        app.store.login(s.account.email, str(body.get("password", "")))
                    except accounts.AuthError as exc:
                        app.fail(key)
                        return self._json(400, {"error": str(exc)})
                    with s.lock:
                        if body.get("enable") is True:
                            s.S = schedule.enable(s.account)
                            schedule.refresh_snapshot(s.account, s.S, s.library)
                        else:
                            schedule.disable(s.account)
                            s.S = None
                else:
                    if s.S is None:
                        return self._json(400, {"error": "Scheduled jobs are off, or the Keychain is not answering."})
                    if s.extreme() and self._would_use_web(s, body):
                        return self._json(400, {"error": "Extreme privacy is on, so web jobs cannot be added or resumed. Turn it off first, or use a folder job."})
                    with s.lock:
                        schedule.edit(s.account, s.S, self._folders(s), str(body.get("action", "")), body, s.library)
            except schedule.SchedError as exc:
                return self._json(400, {"error": str(exc)})
            except keystore.KeychainUnavailable:
                return self._json(503, {"error": "The system keychain did not answer. Unlock it and try again (a server with no desktop session has none, so scheduled jobs are not available there)."})
            return self._json(200, self._sched_state(s))

        def _fresh_prefs(self, s: Session) -> dict:
            try:
                s.prefs = policy.prefs(s.account)
            except policy.PolicyUnavailable:
                s.prefs = {**s.prefs, "extreme": True}  # unreadable: shown (and enforced) as on
            return s.prefs

        def _admin(self, s: Session, path: str, body: dict):
            """Administrator-only: invitations, accounts, permissions, limits, registration mode, transferring the role."""
            if app.store.admin_id() != s.account.id:
                return self._json(403, {"error": "administrator only"})
            try:
                if path == "/api/admin/invite":
                    return self._json(200, {"code": app.store.create_invite(body.get("perms") if isinstance(body.get("perms"), dict) else None)})
                if path == "/api/admin/registration":
                    app.store.set_registration(str(body.get("mode", "")))
                    return self._json(200, {"registration": app.store.registration_mode()})
                if path == "/api/admin/user/create":
                    acct = app.store.register(str(body.get("email", "")), str(body.get("password", "")), by_admin=True)
                    if isinstance(body.get("perms"), dict):
                        app.store.set_access(acct.id, perms=body["perms"])
                    return self._json(200, {"id": acct.id})
                if path == "/api/admin/user/access":
                    target = app.store.user_id(str(body.get("email", "")))
                    if not (app.store.root / target / "meta.json").exists():
                        return self._json(404, {"error": "no such account"})
                    app.store.set_access(target, perms=body.get("perms") if isinstance(body.get("perms"), dict) else None,
                                         limits=body.get("limits") if isinstance(body.get("limits"), dict) else None,
                                         disabled=bool(body["disabled"]) if "disabled" in body else None)
                    return self._json(200, {"perms": app.store.perms(target), "limits": app.store.limits(target)})
                if path == "/api/admin/lockdown":
                    return self._lockdown(s, body)
                if path == "/api/admin/transfer":
                    key = "pw:" + s.account.id
                    if app.locked_out(key):
                        return self._json(429, {"error": "too many attempts, wait a minute"})
                    try:
                        app.store.transfer_admin(s.account, str(body.get("password", "")), str(body.get("email", "")))
                    except accounts.AuthError:
                        app.fail(key)
                        raise
                    return self._json(200, {"ok": True})
            except (accounts.AuthError, ValueError, TypeError) as exc:
                return self._json(400, {"error": str(exc) if isinstance(exc, accounts.AuthError) else "bad request"})
            return self._json(404, {"error": "not found"})

        def _peer_is_local(self) -> bool:
            """The real connection address (never a header, which a client can set): this computer itself."""
            return self.client_address[0] in ("127.0.0.1", "::1")

        def _lockdown(self, s: Session, body: dict):
            """Optional OS-level network block for the macOS user that runs the app. Only from this computer's own address, only for the administrator,
            only 'status' or 'on' (turning it off stays a terminal step), and only the fixed scripts/lockdown.sh: macOS shows its own password dialog,
            so this server never sees the password. The result is 'requested', never 'verified'."""
            local = self._peer_is_local()
            target = LOCKDOWN_USER
            info = {"local": local, "platform": sys.platform, "app_user": _whoami(), "target_user": target,
                    "running_as_target": _whoami() == target}
            if not local:
                info["message"] = "This can only be done on the computer where the app is installed. Sign in there (http://127.0.0.1) to use it."
                return self._json(200, info)
            action = str(body.get("action", "status"))
            if action == "status":
                info["message"] = ("The app runs as the lockdown user. Turn the lockdown on from this page or with scripts/lockdown.sh." if info["running_as_target"] else
                                   f"The app is not running as '{target}', so a lockdown for that user would not protect this copy. See docs/SECURITY.md.")
                return self._json(200, info)
            if action != "on" or body.get("confirm") is not True:  # 'off' and anything else is a terminal step
                return self._json(400, {"error": "only 'on' with confirmation is available here; to turn it off run scripts/lockdown.sh off in a terminal"})
            if sys.platform != "darwin":
                return self._json(400, {"error": "macOS only; see docs/SECURITY.md for containers and Linux"})
            if not lockdown.script_is_trusted():
                app.log.write(route="lockdown", outcome="refused", reason="script not root-owned")
                return self._json(200, {**info, "ok": False, "message": "Refused: scripts/lockdown.sh and every folder above it must be owned by root and not writable by anyone else, "
                                        "otherwise the app's user could change what runs with administrator rights. Run it yourself in a terminal: sudo scripts/lockdown.sh on " + target})
            ok = lockdown.request_on(target)
            app.log.write(route="lockdown", outcome="requested" if ok else "failed", reason=target)
            if not ok:
                return self._json(200, {**info, "ok": False, "message": "It was not turned on (cancelled, or no password dialog was available). Run: sudo scripts/lockdown.sh on " + target})
            return self._json(200, {**info, "ok": True, "message": f"Requested for '{target}'. This is not verified: test it with 'sudo -u {target} curl -m 5 https://example.com'."})

        def _would_use_web(self, s: Session, body: dict) -> bool:
            action = str(body.get("action", ""))
            if action in ("add", "update"):
                return body.get("mode") == "web"
            if action in ("resume", "run"):
                return any(j["id"] == body.get("id") and j["mode"] == "web" for j in schedule.jobs(s.account, s.S))
            return False

        def _demo(self):
            """One click in: shared demo account, fake sample files loaded once. Only when PRIVHYBRID_DEMO=1."""
            try:
                try:
                    acct = app.store.login(DEMO_EMAIL, DEMO_PASSWORD)
                except accounts.AuthError:
                    acct = app.store.register(DEMO_EMAIL, DEMO_PASSWORD)
                sid = app.new_session(acct)
            except accounts.AuthError as exc:
                return self._json(500, {"error": str(exc)})
            s = app.sessions[sid]
            with app.lock:  # embedded once; a second visitor waits for it instead of seeing an empty library
                if app.demo_items is None:
                    items = []
                    for f in sorted((ROOT / "samples").glob("*.txt")):
                        doc = ingest.extract(f.name, f.read_bytes())
                        items.append({**rag.build(doc.name, doc.text, doc.notes), "folder": "Demo"})
                    app.demo_items = items
            with s.lock:  # every visit starts clean: only the samples, no earlier uploads, chats or memories
                s.library = [dict(i) for i in app.demo_items]
                s.chats, s.facts = {}, []
                s.save_library(); s.save_chats(); s.save_facts()
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"ph_session={sid}; HttpOnly; SameSite=Strict; Path=/{self._secure()}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _static(self, name):
            f = (STATIC / name).resolve()
            if STATIC.resolve() not in f.parents or not f.is_file():
                return self._json(404, {"error": "not found"})
            data = f.read_bytes()
            self._headers(200, mimetypes.guess_type(str(f))[0] or "application/octet-stream", len(data))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            try:
                return self._post()
            except accounts.Conflict:
                return self._json(409, {"error": "This changed in another session or program, so it was not saved. Reload and try again."})

        def _post(self):
            if not self._host_ok() or not self._same_origin():
                return self._json(403, {"error": "forbidden"})
            path = self.path.split("?", 1)[0]
            sign_in = path in ("/api/login", "/api/register")
            if not sign_in and self._session() is None:  # nobody signed in gets nothing read or parsed
                self.close_connection = True
                return self._json(401, {"error": "login required"})
            try:
                body = self._body(PREAUTH_BODY if sign_in else MAX_BODY)
            except ValueError:
                self.close_connection = True
                return self._json(400, {"error": "bad request"})
            if sign_in:
                email, password = str(body.get("email", "")), str(body.get("password", ""))
                addr = self.client_address[0]
                uid_key = app.store.user_id(email)
                keys = (addr, addr + "|" + uid_key, "acct|" + uid_key)  # a stranger's wrong guesses lock out their own address, not the owner
                if app.locked_out(addr, addr + "|" + uid_key) or app.locked_out("acct|" + uid_key, limit=ACCOUNT_FAILS_PER_MINUTE):
                    return self._json(429, {"error": "too many attempts, wait a minute"})
                try:
                    if path == "/api/register":
                        reg = "reg:" + self.client_address[0]
                        if app.locked_out(reg):
                            return self._json(429, {"error": "too many accounts created, wait a minute"})
                        acct = app.store.register(email, password, invite=str(body.get("invite", ""))[:200],
                                                  from_loopback=self.client_address[0] in ("127.0.0.1", "::1"))
                        app.fail(reg)  # at most five new accounts a minute from one address
                    else:
                        acct = app.store.login(email, password)
                        acct = app.upgrade_kdf(acct, password)
                except accounts.AuthError as exc:
                    app.fail(*keys)
                    return self._json(401 if path == "/api/login" else 400, {"error": str(exc)})
                try:
                    sid = app.new_session(acct)
                except accounts.AuthError:
                    return self._json(500, {"error": "Your saved data could not be decrypted"})
                return self._json(200, {"ok": True}, {"Set-Cookie": f"ph_session={sid}; HttpOnly; SameSite=Strict; Path=/{self._secure()}"})
            s = self._session()
            if s is None:
                return self._json(401, {"error": "login required"})
            if path == "/api/logout":
                c = SimpleCookie(self.headers.get("Cookie", ""))
                app.drop_session(c["ph_session"].value)
                return self._json(200, {"ok": True}, {"Set-Cookie": f"ph_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{self._secure()}"})
            uid = s.account.id
            need = PATH_PERM.get(path)
            if need and not app.perm(uid, need):
                return self._json(403, {"error": f"This account does not have permission for that ({need}). Ask the administrator."})
            if path.startswith("/api/admin/"):
                return self._admin(s, path, body)
            if path == "/api/upload":
                lim = app.store.limits(uid)
                if not app.allow(uid, "upload", lim["uploads_per_minute"]):
                    return self._json(429, {"error": "Too many uploads this minute. Wait a moment."})
                try:
                    raw = base64.b64decode(str(body.get("data", "")), validate=True)
                except ValueError:
                    return self._json(400, {"error": "file data is not valid base64"})
                try:
                    doc = ingest.extract(str(body.get("name", "file")), raw, str(body.get("password", ""))[:256])  # used once, never stored or logged
                except ingest.Unreadable as exc:
                    return self._json(422, {"error": str(exc)})
                def _no_index(*_a, **_k):
                    raise ValueError("indexing happens after the file is saved")
                if sum(len(d["text"]) for d in s.library) + len(doc.text) > lim["storage_mb"] * 1024 * 1024:
                    return self._json(413, {"error": f"This account's storage limit ({lim['storage_mb']} MB of text) would be exceeded. Remove some files first."})
                item = rag.build(doc.name, doc.text, doc.notes, embedder=_no_index, financial=doc.financial, summary=doc.summary)  # saved at once; the slow search index is added below
                item["notes"] = list(doc.notes) + ["Search index is being built; keyword matching until it is ready."]
                item["folder"] = _folder(body.get("folder"))
                with s.lock:
                    if item["folder"] and item["folder"] not in s.folders and len(s.folders) >= MAX_FOLDERS:
                        return self._json(400, {"error": f"up to {MAX_FOLDERS} folders"})
                    taken = {d["name"] for d in s.library if d.get("kind", "file") == "file"}
                    base, dot, ext = item["name"].rpartition(".")
                    n = 2
                    while item["name"] in taken:  # a second file with the same name is kept beside the first, never over it
                        item["name"] = f"{base} ({n}).{ext}" if dot else f"{item['name'].split(' (')[0]} ({n})"
                        n += 1
                    s.library.append(item)
                    s.save_library()
                    _remember_folder(s, item["folder"])
                s.start_index(item, list(doc.notes))
                return self._json(200, {"name": item["name"], "notes": item["notes"], "chars": len(item["text"])})
            if path == "/api/move":
                with s.lock:
                    nf = _folder(body.get("folder"))
                    if nf and nf not in s.folders and len(s.folders) >= MAX_FOLDERS:
                        return self._json(400, {"error": f"up to {MAX_FOLDERS} folders"})
                    for d in s.library:
                        if d["name"] == body.get("name") and d.get("kind", "file") == "file":
                            d["folder"] = _folder(body.get("folder"))
                    _remember_folder(s, _folder(body.get("folder")))
                    s.save_library()
                return self._json(200, {"ok": True})
            if path == "/api/folder/create":
                name = _folder(body.get("name"))
                if not name:
                    return self._json(400, {"error": "folder name required"})
                with s.lock:
                    if name not in s.folders:
                        if len(s.folders) >= MAX_FOLDERS:
                            return self._json(400, {"error": f"up to {MAX_FOLDERS} folders"})
                        s.folders.append(name)
                        s.save_folders()
                return self._json(200, {"ok": True})
            if path == "/api/folder/delete":
                name = _folder(body.get("name"))
                if not name:
                    return self._json(400, {"error": "folder name required"})
                with s.lock:
                    for d in s.library:
                        if d.get("kind", "file") == "file" and d.get("folder", "") == name:
                            d["folder"] = ""  # the files stay, in Unsorted
                    s.folders = [f for f in s.folders if f != name]
                    s.save_library()
                    s.save_folders()
                    schedule.folder_changed(s.account, s.S, name, "", s.library)
                return self._json(200, {"ok": True})
            if path == "/api/folder/rename":
                old, new = _folder(body.get("old")), _folder(body.get("new"))
                if not old:
                    return self._json(400, {"error": "folder name required"})
                if new and new != old and (new in s.folders or any(d.get("folder", "") == new for d in s.library)):
                    return self._json(409, {"error": "a folder with that name already exists"})
                with s.lock:
                    s.folders = sorted({new if f == old else f for f in s.folders} - {""})
                    s.save_folders()
                    for d in s.library:
                        if d.get("kind", "file") == "file" and d.get("folder", "") == old:
                            d["folder"] = new  # blank new name moves the files back to Unsorted
                    s.save_library()
                    schedule.folder_changed(s.account, s.S, old, new, s.library)
                return self._json(200, {"ok": True})
            if path == "/api/rename":
                old, new = str(body.get("name", "")), str(body.get("new", "")).strip()[:120]
                if not new:
                    return self._json(400, {"error": "name required"})
                if ingest.safe_name(new)[1]:
                    return self._json(400, {"error": "that name contains personal detail; pick a generic one"})
                with s.lock:
                    if new == old:
                        return self._json(200, {"ok": True})
                    if not any(d["name"] == old and d.get("kind", "file") == "file" for d in s.library):
                        return self._json(404, {"error": "that file no longer exists"})
                    if any(d["name"] == new and d.get("kind", "file") == "file" for d in s.library):
                        return self._json(409, {"error": "a file with that name already exists"})
                    for d in s.library:
                        if d["name"] == old and d.get("kind", "file") == "file":
                            d["name"] = new
                    s.save_library()
                return self._json(200, {"ok": True})
            if path == "/api/remove":
                with s.lock:
                    s.library = [d for d in s.library if d["name"] != body.get("name") or d.get("kind", "file") != "file"]
                    s.save_library()
                return self._json(200, {"ok": True})
            if path == "/api/prefs":
                style, theme = body.get("style", s.prefs.get("style", "mac")), body.get("theme", s.prefs.get("theme", "auto"))
                if style not in STYLES or theme not in THEMES:
                    return self._json(400, {"error": "unknown style or theme"})
                changes = {"style": style, "theme": theme, **({"extreme": bool(body["extreme"])} if "extreme" in body else {}),
                           **({"review_cloud": bool(body["review_cloud"])} if "review_cloud" in body else {})}
                with s.lock, s.shared.io:
                    s.prefs = policy.update(s.account, **changes)  # merged into the stored copy, never written from this session's cache
                    extreme = bool(s.prefs.get("extreme"))
                    schedule.publish_policy(s.account, s.S)
                    if extreme and s.S is not None:  # no web job may keep running while the lock is on
                        for j in schedule.jobs(s.account, s.S):
                            if j["mode"] == "web" and not j["paused"]:
                                schedule.edit(s.account, s.S, self._folders(s), "pause", {"id": j["id"]}, s.library)
                return self._json(200, {"ok": True})
            if path in ("/api/sched/optin", "/api/sched/job"):
                return self._sched_post(s, path, body)
            if path == "/api/reset":
                with s.lock:
                    s.vault = Vault(app.dictionary)  # new placeholders; the library stays
                return self._json(200, {"ok": True})
            if path == "/api/chats/delete":
                with s.lock:
                    cid = str(body.get("id", ""))
                    s.chats.pop(cid, None)
                    s.save_chats()
                    s.library = [d for d in s.library if d.get("chat") != cid]  # deleting a chat also forgets what it taught
                    s.facts = [f for f in s.facts if f.get("chat") != cid]
                    s.save_library(); s.save_facts()
                return self._json(200, {"ok": True})
            if path in ("/api/password", "/api/account/delete"):
                key = "pw:" + s.account.id
                if app.locked_out(key):
                    return self._json(429, {"error": "too many attempts, wait a minute"})
                try:
                    with s.lock, s.shared.io:  # no write by another device or a background task runs while the key is replaced
                        if path == "/api/password":
                            s.shared.rekey(app.store.change_password(s.account, str(body.get("old", "")), str(body.get("new", ""))))
                        else:
                            app.store.delete(s.account, str(body.get("password", "")))
                except accounts.AuthError as exc:
                    app.fail(key)
                    return self._json(400, {"error": str(exc)})
                app.drop_others(s)
                if path == "/api/account/delete":
                    c = SimpleCookie(self.headers.get("Cookie", ""))
                    app.drop_session(c["ph_session"].value)
                    try:
                        keystore.delete(s.account.id)  # the scheduler key goes with the account
                    except keystore.KeychainUnavailable:
                        pass
                    return self._json(200, {"ok": True}, {"Set-Cookie": f"ph_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{self._secure()}"})
                return self._json(200, {"ok": True})
            if path == "/api/config":
                if app.store.admin_id() != s.account.id:
                    return self._json(403, {"error": "only the first account can change settings"})
                try:
                    config.save(body)
                except ValueError as exc:
                    return self._json(400, {"error": str(exc)})
                return self._json(200, {"config": config.current(), "installed": app.installed_models()})
            if path == "/api/facts/delete":
                with s.lock:
                    s.facts = [f for f in s.facts if f["id"] != body.get("id")]
                    s.save_facts()
                return self._json(200, {"ok": True})
            if path == "/api/chat":
                return self._chat(s, body)
            if path == "/api/transcribe":
                try:
                    audio = base64.b64decode(str(body.get("data", "")), validate=True)
                    text = speech.transcribe(audio, STATE / "models", runner=app.transcriber)
                except (ValueError, binascii.Error):
                    return self._json(400, {"error": "That recording could not be read."})
                except speech.SpeechError as exc:
                    return self._json(503, {"error": str(exc)})
                return self._json(200, {"text": text})
            if path == "/api/approve":
                slot = s.pending.get(str(body.get("id", "")))
                if slot is None:
                    return self._json(404, {"error": "nothing is waiting for approval"})
                slot[1] = body.get("ok") is True and (not slot[2] or body.get("confirmed") is True)  # flagged text needs the explicit second confirmation
                slot[0].set()
                return self._json(200, {"ok": True})
            if path == "/api/cancel":
                c = s.cancel
                if c:
                    c.stop()
                return self._json(200, {"ok": True})
            self._json(404, {"error": "not found"})

        def _sse(self, event, data):
            self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()

        def _remember(self, s: Session, cid: str, question: str, ans, remember: bool = True) -> str:
            """Save the exchange in this user's encrypted chat file. Only finished answers are kept."""
            with s.lock:
                if cid not in s.chats:
                    cid = secrets.token_hex(8)
                    s.chats[cid] = {"title": question[:60], "ts": time.time(), "msgs": []}
                chat = s.chats[cid]
                chat["ts"] = time.time()
                chat["msgs"].append({"q": question, "a": ans.text, "route": ans.route, "steps": ans.steps,
                                     "notices": ans.notices, "sources": ans.sources})
                s.save_chats()
            if remember:
                self._learn(s, cid, question, ans.text)
            return cid

        def _learn(self, s: Session, cid: str, question: str, answer: str) -> None:
            """What was discussed becomes this user's knowledge. Runs in the background so the reply is not held up.
            Two kinds: facts the user stated about themselves (always given to the assistant), and the exchange itself
            (indexed for search). Anything holding Tier 1 data (SSN, card, password...) stays in the chat only."""
            text = f"Question: {question}\nAnswer: {answer}"
            if D.detect(text).tier1:
                return

            def work():
                try:
                    with s.bind():
                        facts = local.extract_facts(question, log=app.log)
                except (providers.ProviderError, egress.EgressBlocked):
                    facts = []
                with s.bind():
                    item = rag.build(f"Earlier chat: {question[:40]}", text, [], kind="memory", chat=cid)
                with s.lock:
                    have = {f["text"].casefold() for f in s.facts}
                    for f in facts:
                        if f.casefold() not in have and not D.detect(f).tier1:
                            s.facts.append({"id": secrets.token_hex(6), "text": f, "chat": cid, "ts": time.time()})
                            have.add(f.casefold())
                    s.library.append(item)
                    try:
                        s.save_library(); s.save_facts()
                    except accounts.Conflict:
                        pass  # changed elsewhere: this memory is dropped rather than overwrite newer data

            s.submit(work)

        def _chat(self, s: Session, body: dict):
            question = str(body.get("question", "")).strip()
            mode = body.get("mode", "auto")
            forced = False
            if not question or not isinstance(mode, str) or mode not in pipeline.MODES:
                return self._json(400, {"error": "question and a valid mode are required"})
            if len(question) > MAX_QUESTION:
                return self._json(400, {"error": f"That is too long ({len(question)} characters). Keep it under {MAX_QUESTION}."})
            if s.extreme():
                if mode != "local":
                    mode = "local"  # Extreme privacy: nothing ever leaves this computer, whatever was asked
                    forced = True
            uid = s.account.id
            lim = app.store.limits(uid)
            if not app.perm(uid, "local"):
                return self._json(403, {"error": "This account may not use the model. Ask the administrator."})
            if not app.allow(uid, "chat", lim["chats_per_minute"]):
                return self._json(429, {"error": "Too many questions this minute. Wait a moment."})
            if mode == "claude" and not app.perm(uid, "cloud"):
                return self._json(403, {"error": "Cloud AI is not enabled for this account. Use Local, or ask the administrator."})
            if mode == "web" and not app.perm(uid, "web"):
                return self._json(403, {"error": "Web search is not enabled for this account. Use Local, or ask the administrator."})
            if mode == "auto" and not app.perm(uid, "web"):
                mode = "local"  # an auto question never reaches the web for an account without web access
            if mode == "claude" and not app.allow(uid, "cloud", lim["cloud_per_day"], 86400.0):
                return self._json(429, {"error": "This account's daily cloud limit is used up. Use Local or try tomorrow."})
            if not s.chat_lock.acquire(timeout=3):  # a few seconds: a question that was just stopped is still letting go
                return self._json(409, {"error": "Still answering your last question. Wait for it to finish."})
            try:
                self._headers(200, "text/event-stream", extra={"Connection": "close"})
                self.end_headers()
                if forced:
                    self._sse("notice", "Extreme privacy is on, so this was answered on this Mac only.")
                if mode == "auto" and question.count("?") >= MANY_QUESTIONS:
                    mode = "local"  # one route per message: with several questions the safe one wins
                    self._sse("notice", "Several questions in one message, so it was answered on this Mac. Ask web questions on their own.")
                with s.lock:
                    scope = _folder(body.get("folder"))
                    lib = [d for d in s.library if d.get("kind", "file") != "file" or d.get("folder", "") == scope] if scope else list(s.library)
                    with s.bind():
                        docs = rag.select(question, lib)
                    if s.known():
                        docs.insert(0, s.known())
                s.cancel = providers.ACTIVE.cancel = token = providers.Cancel()

                def progress(t):
                    token.check()
                    self._sse("step", t)
                def approve(info):
                    """Show the user exactly what will leave and wait for a yes. No answer in five minutes counts as no."""
                    pid = secrets.token_hex(8)
                    warnings = D.watch_flags("\n\n".join(info["messages"]))
                    slot = s.pending[pid] = [threading.Event(), False, bool(warnings)]  # third item: needs the extra "send anyway" confirmation
                    try:
                        self._sse("preview", {"id": pid, "text": "\n\n".join(info["messages"]), "kinds": info["kinds"],
                                              "host": info.get("host") or config.cloud_label(), "warnings": warnings})
                        deadline = time.time() + APPROVAL_WAIT
                        while not slot[0].wait(0.5):
                            token.check()  # Stop ends the wait
                            if time.time() > deadline:
                                return False
                        return slot[1]
                    finally:
                        s.pending.pop(pid, None)
                def soft_approve(info):
                    """Review is off: nothing is shown unless the filter is unsure about something; then the preview and a second confirmation are required."""
                    return approve(info) if D.watch_flags("\n\n".join(info["messages"])) else True
                review = bool(self._fresh_prefs(s).get("review_cloud", REVIEW_DEFAULT)) or any(d.financial for d in docs)  # financial material is always shown first, whatever the preference
                with s.bind():
                    ans = pipeline.run(question, docs, s.vault, mode, app.log, progress=progress, approve=approve if review else soft_approve)  # slow: uploads and renames only take s.lock
                cid = self._remember(s, str(body.get("chat_id", "")), question, ans, body.get("remember", True) is not False)  # saved before streaming: a closed tab loses nothing
                for note in ans.notices:
                    self._sse("notice", note)
                for i in range(0, len(ans.text), 48):  # the text is already restored; providers here do not stream
                    self._sse("chunk", ans.text[i:i + 48])
                self._sse("done", {"route": ans.route, "sources": ans.sources, "chat_id": cid})
            except providers.Cancelled:
                pass  # Stop: nothing saved, the lock is released below
            except OSError:
                pass  # the browser went away mid-answer
            except NeedsApproval as exc:
                self._sse("needs_approval", {"reason": str(exc), "kinds": exc.kinds, "options": ["local", "cancel"]})
            except (egress.EgressBlocked, providers.ProviderError) as exc:
                self._sse("error", {"error": type(exc).__name__, "detail": str(exc)[:200]})
            except Exception as exc:  # never echo the exception text: it could contain input
                try:
                    self._sse("error", {"error": type(exc).__name__})
                except OSError:
                    pass
            finally:
                s.cancel = providers.ACTIVE.cancel = None
                s.chat_lock.release()

    return Handler


MAX_FOLDERS = 100
LOCKDOWN_USER = os.environ.get("PRIVHYBRID_LOCKDOWN_USER", "phsvc")


def _whoami() -> str:
    import getpass
    try:
        return getpass.getuser()
    except Exception:
        return ""


REVIEW_DEFAULT = True  # a cloud send is shown to the user first unless they switch that off in Settings
APPROVAL_WAIT = 300.0  # seconds a cloud send waits for the user to look at it
PATH_PERM = {"/api/upload": "upload", "/api/move": "library", "/api/folder/create": "library", "/api/folder/delete": "library", "/api/folder/rename": "library",
             "/api/rename": "library", "/api/remove": "library", "/api/sched/optin": "scheduled", "/api/sched/job": "scheduled"}


def _remember_folder(s: "Session", name: str) -> None:
    """A folder that a file was put in is kept in the folder list too. The caller holds s.lock."""
    if name and name not in s.folders and len(s.folders) < MAX_FOLDERS:
        s.folders.append(name)
        s.save_folders()


def _folder(v) -> str:
    """A folder is a short label on a file; empty means unsorted."""
    return " ".join(str(v or "").split())[:40]


def check_bind(host: str) -> str:
    """Loopback by default. A home-network address is allowed only when asked for; never all interfaces."""
    ip = ipaddress.ip_address(host)
    if ip.is_loopback:
        return host
    if ip.is_unspecified or not ip.is_private or ip.version != 4:
        raise ValueError("Bind address must be 127.0.0.1 or one private IPv4 address, never 0.0.0.0")
    return host


class Server(ThreadingHTTPServer):
    tls = False
    daemon_threads = True

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):  # over the limit: close at once, before a thread is started
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, TimeoutError, socket.timeout)):  # socket.timeout is its own class before Python 3.10
            return  # a client that would not finish the TLS handshake, or hung up: nothing to report
        super().handle_error(request, client_address)


def serve(port: int = DEFAULT_PORT, data_dir: str = "", audit_path: str = "", dictionary_path: str = "",
          host: str = HOST, tls_dir: str = "") -> ThreadingHTTPServer:
    STATE.mkdir(exist_ok=True)
    app = App(data_dir or str(STATE / "users"), audit_path or str(ROOT / "logs" / "audit.jsonl"), dictionary_path or str(STATE / "dictionary.txt"))
    if app.demo and not ipaddress.ip_address(host).is_loopback:
        raise ValueError("PRIVHYBRID_DEMO shares one throwaway account: use it on 127.0.0.1 only")
    tls_dir = tls_dir or os.environ.get("PRIVHYBRID_TLS_DIR", "")
    if not ipaddress.ip_address(host).is_loopback and not tls_dir and os.environ.get("PRIVHYBRID_ALLOW_HTTP") != "1":
        raise ValueError("A network address needs HTTPS (set PRIVHYBRID_TLS_DIR), or PRIVHYBRID_ALLOW_HTTP=1 to accept plain HTTP on this network")
    httpd = Server((check_bind(host), port), make_handler(app))
    httpd.app = app
    if tls_dir:
        ctx = tls.server_context(tls_dir)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
        httpd.tls = True
        httpd.tls_dir = tls_dir
    if app.sched_on:
        app.scheduler.start()
    return httpd


if __name__ == "__main__":
    with egress.loopback_only():  # nothing in this process may connect anywhere but this machine
        httpd = serve(port=int(os.environ.get("PRIVHYBRID_PORT", DEFAULT_PORT)), host=os.environ.get("PRIVHYBRID_BIND", HOST))  # PRIVHYBRID_BIND=<LAN ip> is the phone-on-Wi-Fi exception
        print(f"privhybrid on {'https' if httpd.tls else 'http'}://{httpd.server_address[0]}:{httpd.server_address[1]}  (register on first visit)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
