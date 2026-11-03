"""The only way a prompt leaves the gateway: send(). Policy per destination (threat model T6, T10, T12).

local    Ollama on 127.0.0.1: raw text allowed.
claude   Claude CLI: tier 2-3 as placeholders only; tier 1 or leftover entities stop the request.
freellm  FreeLLMAPI on 127.0.0.1: tier 4 only: generic text with no entity and no placeholder.
Anything else (OpenRouter, Anthropic API, other LAN hosts) is refused in this project. The one LAN exception: the Ollama addresses the admin lists in Settings (private IPs, port 1024+).

Fallback is local only and is never a retry on a cloud route with weaker redaction.
"""
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional
from urllib.parse import urlparse

from . import detect as D
from . import config, filelock, providers
from .vault import NeedsApproval, PH_RE, Vault

ROUTES = ("local", "claude", "freellm")
LOCAL_PROFILE = {"provider": "ollama", "model": "gemma4:26b"}  # default only; the pipeline passes config.profile("answer")
CLAUDE_PROFILE = {"provider": "claude_cli", "model": ""}
FREELLM_PROFILE = {"provider": "freellmapi", "model": "auto"}
_PROVIDER_FOR = {"local": "ollama", "claude": "claude_cli", "freellm": "freellmapi"}
MAX_PROMPT_BYTES = 60 * 1024
REQUIRE_SECOND_PASS = True  # the Claude route needs the local-model check; if it is missing or fails, nothing is sent
SEARX_URL = "http://127.0.0.1:8888"
MAX_QUERY_CHARS = 200


class EgressBlocked(RuntimeError):
    """A hard policy refusal (wrong destination, bad address). Not something the user can approve."""


class PolicyBlocked(EgressBlocked):
    """Extreme privacy is on (or could not be checked): nothing external may be reached."""


_POLICY = threading.local()  # per thread: how to ask "is Extreme privacy on for this account right now?"


@contextlib.contextmanager
def bound(is_extreme: Callable[[], bool], can: Optional[Callable[[str], bool]] = None) -> Iterator[None]:
    """Everything this thread sends inside the block asks `is_extreme()` (and `can("cloud"|"web")`, the account's permissions) again
    immediately before it transmits."""
    prev = (getattr(_POLICY, "fn", None), getattr(_POLICY, "can", None))
    _POLICY.fn, _POLICY.can = is_extreme, can
    try:
        yield
    finally:
        _POLICY.fn, _POLICY.can = prev


def extreme_now() -> bool:
    fn = getattr(_POLICY, "fn", None)
    if fn is None:
        return False  # library use outside the server: no account, no policy
    try:
        return bool(fn())
    except Exception:
        return True  # cannot tell: treat as on


def _require_external(what: str, kind: str = "cloud") -> None:
    if extreme_now():
        raise PolicyBlocked(f"Extreme privacy is on: {what} is not available")
    can = getattr(_POLICY, "can", None)
    if can is not None:
        try:
            ok = bool(can(kind))
        except Exception:
            ok = False  # permissions unreadable: not allowed
        if not ok:
            raise PolicyBlocked(f"This account is not allowed to use {what}")


@dataclass
class Result:
    text: str
    route: str
    degraded: bool = False
    notice: str = ""
    unknown_placeholders: List[str] = field(default_factory=list)


# --- addresses ------------------------------------------------------------------------------

is_loopback_url = providers.is_loopback_url


class Declined(EgressBlocked):
    """The user looked at what was about to be sent and said no. Nothing was sent."""


def _check_profile(route: str, profile: Dict[str, str]) -> None:
    allowed = ("claude_cli", "openai_compat") if route == "claude" else (("ollama", "local_openai") if route == "local" else (_PROVIDER_FOR[route],))
    if profile.get("provider") not in allowed:
        raise EgressBlocked(f"Route {route} only allows provider {' or '.join(allowed)}")
    if profile.get("provider") == "openai_compat":
        validate_cloud_url(profile.get("base_url") or "")
    if route in ("local", "freellm"):
        base = profile.get("base_url") or providers.default_base_url(profile["provider"])
        ok = is_loopback_url if route == "freellm" else providers.is_local_url  # local may also use the Ollama addresses listed in Settings
        for url in [base] + [u for u, _ in providers.fallbacks(profile)]:
            if not ok(url):
                if route == "local" and providers.strict_local() and providers.is_loopback_url(url) is False:
                    raise EgressBlocked(f"Extreme privacy or local-only mode is on, so the model on another computer ({urlparse(url).hostname}) is not used. Run a model on this computer to keep working.")
                raise EgressBlocked(f"{route} must be on this machine (127.0.0.1) or a listed private-network Ollama address, not {urlparse(url).hostname}")


# --- audit log: counts and route only, never text -------------------------------------------

AUDIT_MAX_BYTES = 10 * 1024 * 1024  # rotate the audit log at this size (PH-019: it used to grow without limit)
AUDIT_KEEP = 12  # archives kept; the oldest beyond this are deleted


class AuditLog:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        """Hash of the last line already in the file (read each time, so another process appending does not break the chain)."""
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                fh.seek(max(0, fh.tell() - 65536))
                lines = fh.read().splitlines()
        except OSError:
            return ""
        return hashlib.sha256(lines[-1]).hexdigest() if lines else ""

    def write(self, **fields) -> None:
        if not self.path:
            return
        with self._lock:
            os.makedirs(os.path.dirname(self.path) or ".", mode=0o700, exist_ok=True)
            with filelock.locked(self.path + ".lock"):
                prev = self._last_hash()
                try:
                    if os.path.getsize(self.path) >= AUDIT_MAX_BYTES:
                        os.replace(self.path, f"{self.path}.{time.time_ns()}")  # archive keeps its 0600 mode; the new file's first line names the hash of the archive's last line
                        self._prune()
                except OSError:
                    pass
                fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)  # owner only
                with os.fdopen(fd, "a+", encoding="utf-8") as fh:
                    fh.write(json.dumps({"ts": round(time.time(), 1), **fields, "prev": prev}, sort_keys=True) + "\n")

    def _prune(self) -> None:
        base = os.path.basename(self.path) + "."
        folder = os.path.dirname(self.path) or "."
        old = sorted(n for n in os.listdir(folder) if n.startswith(base) and n[len(base):].isdigit())
        for n in old[:-AUDIT_KEEP]:
            try:
                os.remove(os.path.join(folder, n))
            except OSError:
                pass


def verify_chain(path: str) -> Optional[int]:
    """None if every line names the hash of the line before it; otherwise the number of the first line that does not.
    Lines written before the chain existed are skipped. This shows edits and deletions in the middle, not the loss of the last lines."""
    prev, started = "", False
    with open(path, "rb") as fh:
        for n, raw in enumerate(fh.read().splitlines(), 1):
            try:
                rec = json.loads(raw)
            except ValueError:
                return n
            if "prev" in rec:
                if started and rec["prev"] != prev:
                    return n
                started = True
            prev = hashlib.sha256(raw).hexdigest()
    return None


# --- per-route preparation ------------------------------------------------------------------

UNREADABLE_SCRIPT_LIMIT = 0.10


def _recheck_masked(text: str) -> None:
    """Defense in depth: run the detector again on what is about to leave. Placeholders are not entities."""
    if D.unreadable_script_share(text) >= UNREADABLE_SCRIPT_LIMIT:  # names and addresses in these scripts are not found, so nothing can be masked reliably
        raise NeedsApproval("Much of this text is in a script the privacy check cannot read reliably, so it stays on this computer", {"SCRIPT": 1})
    det = D.detect(PH_RE.sub("PLACEHOLDER", text))
    left = [e for e in det.sensitive if e.text != "PLACEHOLDER"]  # a labelled placeholder ("username: [ID_1]") is fine
    if any(e.tier == 1 for e in left):
        raise NeedsApproval("Tier 1 data found in the outgoing text", {e.kind: 1 for e in left if e.tier == 1})
    if left:
        raise NeedsApproval("Sensitive text survived masking", {e.kind: 1 for e in left})


def _prepare(route: str, messages: List[Dict[str, str]], vault: Vault,
             checker: Optional[Callable[[str], List[str]]] = None) -> (List[Dict[str, str]], Dict[str, int]):
    if route == "local":
        return messages, {}
    out, counts = [], {}
    for m in messages:
        if route == "claude":
            text, c = vault.mask(str(m["content"]))
            _recheck_masked(text)
            known = vault.leaks(text)
            if known:  # a value this account holds is still in the outgoing text, however it is written
                raise NeedsApproval("A known personal value is still in the outgoing text", {"KNOWN": known})
            if checker is None and REQUIRE_SECOND_PASS:
                raise NeedsApproval("The local privacy check is not available, so nothing was sent")
            if checker is not None:
                try:
                    left = checker(text)
                except Exception as exc:  # model down, timeout, bad reply: fail closed
                    raise NeedsApproval(f"The local privacy check failed ({type(exc).__name__}), so nothing was sent")
                if left:
                    raise NeedsApproval("The local privacy check found personal detail the detector missed", {"LLM": len(left)})
            for k, n in c.items():
                counts[k] = counts.get(k, 0) + n
        else:  # freellm: tier 4, generic text only
            text = str(m["content"])
            det = D.detect(text)
            if det.sensitive or det.quasi:
                raise NeedsApproval("FreeLLMAPI only receives generic text with no personal or financial detail",
                                    {e.kind: 1 for e in det.sensitive})
            if PH_RE.search(text):
                raise NeedsApproval("FreeLLMAPI never receives placeholders")
        out.append({**m, "content": text})
    if sum(len(m["content"].encode("utf-8")) for m in out) > MAX_PROMPT_BYTES:
        raise NeedsApproval("Prompt is over the size limit")
    return out, counts


# --- the one exit ---------------------------------------------------------------------------

def _dest(profile: Dict[str, str]) -> Dict[str, str]:
    """The cloud host (never the path or the key) for the audit log, so a third-party send can be attributed."""
    return {"host": urlparse(profile.get("base_url", "")).hostname or ""} if profile.get("provider") == "openai_compat" else {}


def send(route: str, messages: List[Dict[str, str]], vault: Vault, profile: Optional[Dict[str, str]] = None,
         log: Optional[AuditLog] = None, timeout: float = 0,
         checker: Optional[Callable[[str], List[str]]] = None,
         approve: Optional[Callable[[dict], bool]] = None) -> Result:
    """Send messages down one route. `approve` (cloud routes) is shown exactly what will leave and must return True. Raises NeedsApproval (ask the user) or EgressBlocked (never allowed)."""
    if route not in ROUTES:
        raise EgressBlocked(f"Unknown route {route!r}")
    profile = profile or (config.cloud_profile() if route == "claude" else {"local": LOCAL_PROFILE, "freellm": FREELLM_PROFILE}[route])
    log = log or AuditLog()
    started = time.time()
    try:
        _check_profile(route, profile)
        outgoing, counts = _prepare(route, messages, vault, checker)
        if route != "local":
            _require_external("sending to a cloud or third-party service")  # after the slow local check, right before transmission
            if approve is not None and not approve({"messages": [str(m["content"]) for m in outgoing], "kinds": counts, **_dest(profile),
                                                    "provider": profile.get("provider", "")}):
                raise Declined("The user declined to send this")
    except (NeedsApproval, EgressBlocked) as exc:
        log.write(route=route, outcome="declined" if isinstance(exc, Declined) else "blocked", reason=type(exc).__name__, kinds=getattr(exc, "kinds", {}))
        raise
    try:
        try:
            with _cloud_access(profile):
                if route != "local":
                    _require_external("sending to a cloud or third-party service")  # last look, after the address is resolved
                with providers.gated():
                    reply = providers.chat(profile, outgoing, timeout)
        except EgressBlocked as exc:  # a refused or private address: logged once, nothing sent, and the caller falls back
            log.write(route=route, outcome="blocked", reason="EgressBlocked", kinds=counts, ms=int((time.time() - started) * 1000), **_dest(profile))
            err = providers.NotSent(str(exc))
            err.logged = True  # the outer handler must not write a second row
            raise err
    except providers.ProviderError as exc:
        if not getattr(exc, "logged", False):
            log.write(route=route, outcome="error", error=type(exc).__name__, kinds=counts,
                      ms=int((time.time() - started) * 1000), **_dest(profile))
        raise
    text, unknown = (vault.unmask(reply.text) if route == "claude" else (reply.text, []))
    log.write(route=route, outcome="ok", provider=profile.get("provider"), **_dest(profile), **({"host": reply.host} if reply.host else {}), kinds=counts, bytes=sum(len(m["content"]) for m in outgoing),
              unknown=len(unknown), ms=int((time.time() - started) * 1000))
    return Result(text, route, unknown_placeholders=unknown)


def probe(url: str, timeout: float = 2) -> bool:
    """Is a service on this machine (or a listed Ollama address) answering? Used for the UI status line."""
    if not providers.is_local_url(url):
        raise EgressBlocked("Probes are for services on this machine only")
    try:
        providers.open_local(url, timeout).close()
        return True
    except Exception:
        return False


def local_json(url: str, timeout: float = 3) -> dict:
    """GET JSON from a service on this machine or a listed Ollama address; used to list installed Ollama models."""
    if not providers.is_local_url(url):
        raise EgressBlocked("Local lookups are for services on this machine only")
    with providers.open_local(url, timeout) as res:
        return json.load(res)


def check_query(query: str) -> str:
    """Query gate (T4): a web query may carry no personal or financial detail at all."""
    q = " ".join(query.split())
    if not q:
        raise NeedsApproval("Empty search query")
    if len(q) > MAX_QUERY_CHARS:
        raise NeedsApproval("Search query is too long to be generic")
    det = D.detect(q)
    if det.sensitive or det.quasi:
        raise NeedsApproval("Search query contains personal or financial detail", {e.kind: 1 for e in det.sensitive})
    if PH_RE.search(q) or re.search(r"\d{5,}", q):
        raise NeedsApproval("Search query contains placeholders or long numbers")
    return q


def search(query: str, log: Optional[AuditLog] = None, base: str = "", limit: int = 5, timeout: float = 20) -> List[Dict[str, str]]:
    """Public web search through a SearXNG instance on this machine. Results are untrusted text."""
    log = log or AuditLog()
    base = base or SEARX_URL
    if not is_loopback_url(base):
        raise EgressBlocked("Search must go through SearXNG on this machine")
    try:
        q = check_query(query)
    except NeedsApproval as exc:
        log.write(route="search", outcome="blocked", kinds=exc.kinds)
        raise
    try:
        _require_external("web search", "web")  # re-read on every call, so a retry is checked again
    except PolicyBlocked:
        log.write(route="search", outcome="blocked", reason="PolicyBlocked")
        raise
    url = f"{base.rstrip('/')}/search?" + urllib.parse.urlencode({"q": q, "format": "json"})
    try:
        with providers.open_local(url, timeout) as res:
            data = json.load(res)
    except (OSError, ValueError) as exc:
        log.write(route="search", outcome="error", error=type(exc).__name__)
        raise providers.Unavailable(f"Search is unavailable ({type(exc).__name__})")
    rows = [{"title": str(r.get("title", ""))[:200], "url": str(r.get("url", ""))[:300],
             "snippet": str(r.get("content", ""))[:500]} for r in data.get("results", [])[:limit]]
    log.write(route="search", outcome="ok", results=len(rows), qlen=len(q))
    return rows


def send_with_fallback(route: str, messages: List[Dict[str, str]], vault: Vault, log: Optional[AuditLog] = None,
                       **kw) -> Result:
    """Cloud route first; on a provider failure answer locally with the original text. Never retries the cloud.
    NeedsApproval is not swallowed: the user decides whether to go local."""
    try:
        return send(route, messages, vault, log=log, **kw)
    except providers.ProviderError as exc:
        if route == "local":
            raise
        res = send("local", messages, vault, **{**kw, "profile": config.profile("answer"), "log": log})  # the model the user chose; the caller's other options kept
        res.degraded = True
        res.notice = f"{route} was unavailable ({type(exc).__name__}); answered locally instead."
        return res


# --- process-wide guard (T6) ----------------------------------------------------------------

def validate_cloud_url(url: str) -> str:
    """One check for save time and send time: https (http only for a service on this machine), a host, no credentials, query or fragment."""
    u = urlparse(url)
    try:
        u.port
    except ValueError:
        raise EgressBlocked("The cloud address has an invalid port")
    if u.username or u.password or not u.hostname or u.query or u.fragment:
        raise EgressBlocked("The cloud address must be a plain URL such as https://api.example.com/v1")
    if u.scheme not in ("https", "http") or (u.scheme == "http" and not is_loopback_url(url)):
        raise EgressBlocked("The cloud address must start with https:// (http:// only for a service on this machine)")
    return url


@contextlib.contextmanager
def _cloud_access(profile: Dict[str, str]) -> Iterator[None]:
    """Let THIS thread reach the configured cloud service, and only it, for the length of one call. The name is resolved here, every
    address must be public, and the connection is pinned to the address chosen here, so a second lookup cannot send it elsewhere."""
    if profile.get("provider") != "openai_compat" or is_loopback_url(profile.get("base_url", "")):
        yield
        return
    u = urlparse(profile["base_url"])
    port = u.port or 443
    try:
        ips = list(dict.fromkeys(ai[4][0] for ai in socket.getaddrinfo(u.hostname, port, proto=socket.IPPROTO_TCP)))  # resolver order, no repeats
    except OSError:
        raise providers.NotSent("The cloud service address could not be resolved")
    if not ips or not all(ipaddress.ip_address(i).is_global for i in ips):
        raise EgressBlocked("The cloud address resolves to a private or reserved address")
    providers.PIN.target = (ips, port)  # thread-local: it is both where the connection goes and the only thing the guard allows
    try:
        yield
    finally:
        providers.PIN.target = None


_GUARD = {"depth": 0, "connect": None, "connect_ex": None}
_GUARD_LOCK = threading.Lock()


def _allowed(sock, address) -> bool:
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return True
    host = address[0] if isinstance(address, tuple) else address
    target = getattr(providers.PIN, "target", None)  # this thread's vetted cloud addresses and port, for the length of one call
    try:
        return (ipaddress.ip_address(host).is_loopback or bool(target and host in target[0] and address[1] == target[1])
                or (not providers.strict_local() and (host, address[1]) in config.lan_endpoints()))
    except ValueError:
        return host == "localhost"


@contextlib.contextmanager
def loopback_only() -> Iterator[None]:
    """Inside this block any socket connect to a non-loopback address raises. Subprocesses (the Claude CLI) are
    separate processes and are only reachable through send(). Nesting is safe: the original methods are restored when the outermost block ends."""
    with _GUARD_LOCK:
        if _GUARD["depth"] == 0:
            _GUARD["connect"], _GUARD["connect_ex"] = socket.socket.connect, socket.socket.connect_ex
            real, real_ex = _GUARD["connect"], _GUARD["connect_ex"]

            def wrap(fn):
                def guarded(self, address):
                    if not _allowed(self, address):
                        raise EgressBlocked(f"Blocked connection to {address[0] if isinstance(address, tuple) else address}")
                    return fn(self, address)
                return guarded
            socket.socket.connect, socket.socket.connect_ex = wrap(real), wrap(real_ex)
        _GUARD["depth"] += 1
    try:
        yield
    finally:
        with _GUARD_LOCK:
            _GUARD["depth"] -= 1
            if _GUARD["depth"] == 0:
                socket.socket.connect, socket.socket.connect_ex = _GUARD["connect"], _GUARD["connect_ex"]