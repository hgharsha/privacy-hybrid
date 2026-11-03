# Copied from ~/projects/uiorchestor/providers.py on 2026-10-27. Independent copy: not synced.
"""One chat call for every model provider (stdlib only, so the engine host needs no extra packages).

Tiers: local (Ollama), free (free cloud), claude (subscription CLI), paid (billed per token).
Callers get a Reply or one of the typed errors below; keys never appear in errors.
"""
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import time
import contextlib
import subprocess
import threading
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

class Cancelled(BaseException):
    """The user pressed Stop. A BaseException so no fallback or `except Exception` turns it into a retry on another model."""


class Cancel:
    """One per question. `stop()` closes whatever connection or process the question is waiting on."""
    def __init__(self) -> None:
        self.stopped, self._closers, self._lock = False, [], threading.Lock()

    def watch(self, closer) -> None:
        with self._lock:
            self._closers.append(closer)
            gone = self.stopped
        if gone:
            closer()

    def check(self) -> None:
        if self.stopped:
            raise Cancelled()

    def stop(self) -> None:
        with self._lock:
            self.stopped, closers = True, list(self._closers)
        for c in closers:
            try:
                c()
            except Exception:
                pass


ACTIVE = threading.local()  # ACTIVE.cancel is the Cancel of the question this thread is answering, if any

PIN = threading.local()  # egress sets PIN.target = ([ip, ...], port) for the length of one cloud call: the connection goes to that vetted address only


GATE = threading.local()  # egress.send() opens it for the length of one outgoing call; anything that is not the local model refuses to run without it


@contextlib.contextmanager
def gated():
    prev = getattr(GATE, "open", False)
    GATE.open = True
    try:
        yield
    finally:
        GATE.open = prev


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # a redirect is an error, never followed: it could carry the key and the masked text somewhere else


class _PinnedConn(http.client.HTTPSConnection):
    def __init__(self, host, ips, **kw):
        super().__init__(host, **kw)
        self._ips = ips

    def connect(self):  # only the addresses egress vetted, in resolver order; the real name is kept for the certificate check and SNI
        last: Exception = OSError("no address")
        for ip in self._ips:
            try:
                sock = socket.create_connection((ip, self.port), self.timeout)
            except OSError as exc:
                last = exc
                continue
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            return
        raise last


class _PinnedHTTPS(urllib.request.HTTPSHandler):
    def __init__(self, ips):
        super().__init__()
        self._ips = ips

    def https_open(self, req):
        return self.do_open(lambda host, **kw: _PinnedConn(host, self._ips, **kw), req)


def is_loopback_url(url: str) -> bool:
    """The one definition of "on this machine" (egress and the key rule both use it)."""
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    try:
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def strict_local() -> bool:
    """True when nothing may go to another computer, not even a listed Ollama: PRIVHYBRID_LOCAL_ONLY=1, or Extreme privacy is on right now.
    Fails closed: if the policy cannot be read, extreme_now() says on."""
    if os.environ.get("PRIVHYBRID_LOCAL_ONLY", "") in ("1", "true", "yes"):
        return True
    from . import egress  # late import: egress imports this module
    return egress.extreme_now()


def is_local_url(url: str) -> bool:
    """This machine, or an Ollama address the owner listed in Settings (a private-network IP and the exact port)."""
    if is_loopback_url(url):
        return True
    if strict_local():
        return False  # content would leave this computer: only with explicit configuration, and never under Extreme privacy or LOCAL_ONLY
    from urllib.parse import urlparse
    from . import config  # late import: config is a leaf, but keep providers importable on its own
    u = urlparse(url)
    try:
        return (str(ipaddress.ip_address(u.hostname or "")), u.port or (443 if u.scheme == "https" else 80)) in config.lan_endpoints()
    except ValueError:
        return False


def fallbacks(profile: Dict[str, str]) -> List[Tuple[str, str]]:
    """(address, model override) of each backup in a profile's "fallback_urls" ("url" or "url|model")."""
    return [(u, m) for u, _, m in (e.partition("|") for e in (profile.get("fallback_urls") or "").split(",") if e)]


def _reachable(url: str) -> None:
    """A few seconds to open a connection; a machine that is off or asleep must not hold things up for the full model timeout."""
    from urllib.parse import urlparse
    u = urlparse(url)
    try:
        socket.create_connection((u.hostname, u.port or (443 if u.scheme == "https" else 80)), 3).close()
    except OSError as exc:
        raise Unreachable(f"Cannot reach {u.hostname}:{u.port} ({type(exc).__name__})")


def _with_fallbacks(profile: Dict[str, str], call):
    """Run call(profile) on the main Ollama address, then on each backup if the one before could not be reached."""
    tries = [(profile.get("base_url") or default_base_url("ollama"), "")] + fallbacks(profile)
    last = None
    for u, m in tries:
        if not is_local_url(u):
            continue
        try:
            if len(tries) > 1 and not is_loopback_url(u):
                _reachable(u)
            out = call({**profile, "base_url": u, **({"model": m} if m else {})})
            if isinstance(out, Reply) and not is_loopback_url(u):
                from urllib.parse import urlparse
                out.host = f"{urlparse(u).hostname}:{urlparse(u).port}"
            return out
        except Unreachable as exc:  # a slow or failing answer is not retried elsewhere: the first machine may still be working on it
            last = exc
    raise last or Unavailable("No usable local model address")


class _LoopbackRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, newurl) if is_loopback_url(newurl) and newurl.startswith(("http://", "https://")) else None


def open_local(url: str, timeout: float):
    """GET on this machine: http(s) only (no file:// or ftp://), no proxy from the environment, redirects only to another loopback address."""
    if not url.startswith(("http://", "https://")):
        raise ValueError("Only http(s) addresses on this machine are allowed")
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _LoopbackRedirect()).open(url, timeout=timeout)


def _opener() -> urllib.request.OpenerDirector:
    handlers: list = [urllib.request.ProxyHandler({}), _NoRedirect()]  # no proxy from the environment, no redirects
    target = getattr(PIN, "target", None)
    if target:
        handlers.append(_PinnedHTTPS(target[0]))  # target = (addresses, port)
    return urllib.request.build_opener(*handlers)


LLM_TIMEOUT = float(os.environ.get("UIORCH_LLM_TIMEOUT", "1800"))
MAX_LOCAL_REPLY_TOKENS = 8192  # a whole 300-line file is ~4k tokens; a model stuck repeating itself stops here, not at the timeout
MAX_LOCAL_REPLY_TOKENS_ROOMY = 16384  # when the context has room: thinking models spend thousands of tokens before answering
CLAUDE_BIN = os.environ.get("UIORCH_CLAUDE_BIN", "claude")
# The Claude CLI gets only what it needs to find the subscription login; no other environment values.
CLAUDE_ENV_KEYS = ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR")
# Fixed values, not copied from the caller: ask the CLI not to send usage telemetry or error reports (PH-020: a capture showed
# device/account metadata going to Anthropic and a third-party log service). Names are the CLI's documented opt-outs.
CLAUDE_FIXED_ENV = {"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
                    "ENABLE_CLAUDEAI_MCP_SERVERS": "false"}  # the last one: do not attach the account's claude.ai connectors (Gmail, Drive...)
# A private config folder for the app's CLI (PH-020). If it exists, the CLI is started with CLAUDE_CONFIG_DIR pointing at it, so it never
# reads the owner's own ~/.claude (notes, plugins, settings). Create and log in with scripts/claude_login.sh; without the folder the old behaviour applies.
CLAUDE_CONFIG_DIR = os.environ.get("PRIVHYBRID_CLAUDE_CONFIG_DIR") or str(Path(__file__).resolve().parents[2] / "state" / "claude-config")
LIMIT_HINTS = ("usage limit", "rate limit", "limit reached", "limit will reset", "quota")

PROVIDERS = ("ollama", "local_openai", "openrouter", "freellmapi", "claude_cli", "anthropic", "openai_compat")


class ProviderError(RuntimeError):
    pass


class RateLimited(ProviderError):
    pass


class Unavailable(ProviderError):
    pass


class AuthMissing(ProviderError):
    pass


class Unreachable(Unavailable):
    """Nothing was answered at all (refused, no route, unknown model): safe to try the next address. A timeout or a 5xx is not."""


class NotSent(Unavailable):
    """The call was refused before anything left this computer (bad or blocked address): nothing was sent."""


class BadReply(ProviderError):
    pass


class PaidNotApproved(ProviderError):
    def __init__(self, stage: str = "", model: str = "", est_cost: float = 0.0):
        super().__init__(f"Paid model {model or '?'} needs your approval for {stage or 'this step'}")
        self.stage, self.model, self.est_cost = stage, model, est_cost


@dataclass
class Reply:
    text: str
    provider: str
    model: str
    tier: str
    usage: Dict[str, Any] = field(default_factory=dict)
    cost_usd: float = 0.0
    host: str = ""  # set when a machine other than this one answered (host:port, never text), for the activity log


def tier_of(provider: str, model: str) -> str:
    if provider in ("ollama", "local_openai"):
        return "local"
    if provider == "claude_cli":
        return "claude"
    if provider == "anthropic":
        return "paid"
    if provider == "openrouter":
        free = model.endswith(":free") or model == "openrouter/free"
        return "free" if free else "paid"
    if provider == "freellmapi":
        return "free"
    if provider == "openai_compat":
        return "cloud"
    raise ProviderError(f"Unsupported provider: {provider}")


def default_base_url(provider: str) -> str:
    return {
        "ollama": "http://127.0.0.1:11434",
        "openrouter": "https://openrouter.ai/api/v1",
        "freellmapi": "http://127.0.0.1:3001/v1",
    }.get(provider, "")


def _post(url: str, headers: Dict[str, str], body: Dict[str, Any], timeout: float, who: str) -> Dict[str, Any]:
    if not url.startswith(("http://", "https://")):
        raise BadReply(f"{who}: only http(s) addresses are allowed")
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    token = getattr(ACTIVE, "cancel", None)
    try:
        if token and url.startswith("http://"):  # this machine or the LAN: a plain connection that Stop can close
            return _post_stoppable(url, headers, body, timeout, who, token)
        with _opener().open(req, timeout=timeout) as res:
            return json.load(res)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise RateLimited(f"{who} is rate limited (HTTP 429)")
        if exc.code in (401, 403):
            raise AuthMissing(f"{who} refused the key (HTTP {exc.code})")
        if exc.code >= 500:
            raise Unavailable(f"{who} is down (HTTP {exc.code})")
        raise BadReply(f"{who} returned HTTP {exc.code}")
    except urllib.error.URLError as exc:
        raise Unreachable(f"Cannot reach {who} ({exc.reason})")
    except (TimeoutError, OSError) as exc:
        raise Unavailable(f"{who} did not answer in time ({type(exc).__name__})")
    except ValueError:
        raise BadReply(f"{who} sent a reply that is not JSON")


def _post_stoppable(url: str, headers: Dict[str, str], body: Dict[str, Any], timeout: float, who: str, token: Cancel) -> Dict[str, Any]:
    parts = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    token.watch(lambda: (conn.sock and conn.sock.shutdown(socket.SHUT_RDWR), conn.close()))
    try:
        conn.request("POST", parts.path or "/", json.dumps(body).encode(), headers)
        res = conn.getresponse()
        data = res.read()
        if res.status >= 400:
            raise urllib.error.HTTPError(url, res.status, res.reason, res.headers, None)
        return json.loads(data)
    except (OSError, http.client.HTTPException) as exc:
        token.check()  # a closed socket from Stop looks like any other network error
        raise exc if isinstance(exc, OSError) else OSError(type(exc).__name__)
    finally:
        conn.close()


OLLAMA_LOCK = threading.Lock()


def embed(profile: Dict[str, str], texts: List[str], timeout: float = 60) -> List[List[float]]:
    """Vectors from the Ollama embedding model (this machine or a listed backup). The caller (rag.py) checks the profile."""
    return _with_fallbacks(profile, lambda p: _embed_at(p, texts, timeout))


def _embed_at(profile: Dict[str, str], texts: List[str], timeout: float) -> List[List[float]]:
    base = (profile.get("base_url") or default_base_url("ollama")).rstrip("/")
    if profile.get("provider") == "local_openai":  # LM Studio, llama.cpp, vLLM: POST /v1/embeddings. Not tested against a real server.
        payload = _post(f"{base}/v1/embeddings", {"Content-Type": "application/json"},
                        {"model": profile["model"], "input": texts}, timeout, "Local embeddings")
        try:
            rows = sorted(payload["data"], key=lambda r: r.get("index", 0))
            vecs = [r["embedding"] for r in rows]
        except (KeyError, TypeError, AttributeError):
            raise BadReply("Local embeddings: unexpected reply")
        if len(vecs) != len(texts):
            raise BadReply("Local embeddings: unexpected reply")
        return vecs
    payload = _post(f"{base}/api/embed", {"Content-Type": "application/json"},
                    {"model": profile["model"], "input": texts, "keep_alive": "24h"},  # stay loaded: a cold load next to a big resident model can hang
                    timeout, "Ollama embeddings")
    vecs = payload.get("embeddings")
    if not isinstance(vecs, list) or len(vecs) != len(texts):
        raise BadReply("Ollama embeddings: unexpected reply")
    return vecs


_CTX_SEEN: Dict[str, int] = {}


def _loaded(base: str, model: str) -> Dict[str, Any]:
    """The model as Ollama has it loaded right now ({} if not loaded or unknown)."""
    try:
        with open_local(f"{base}/api/ps", 3) as res:
            return next((m for m in json.load(res).get("models", []) if model in (m.get("name"), m.get("model"))), {})
    except (OSError, ValueError, AttributeError):
        return {}


def _ollama_options(base: str, model: str, messages: List[Dict[str, str]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """num_ctx and keep_alive that never disturb a model someone else already loaded: a loaded model keeps its
    context when the prompt fits (a different num_ctx reloads it) and a pinned model (keep_alive -1, e.g. the
    Mac mini's always-loaded models) stays pinned."""
    want = _num_ctx(model, messages)
    loaded = _loaded(base, model)
    options: Dict[str, Any] = {"num_ctx": want}
    extra: Dict[str, Any] = {"keep_alive": "30m"}
    if loaded:
        have = int(loaded.get("context_length") or 0)
        if have >= sum(len(m["content"]) for m in messages) // 3 + 6000:
            options["num_ctx"] = have
        if str(loaded.get("expires_at", ""))[:4] > str(time.gmtime().tm_year + 1):
            extra = {}
    return options, extra


def _num_ctx(model: str, messages: List[Dict[str, str]]) -> int:
    """16k, 24k or 32k, whichever fits the prompt plus room for the reply. It only ever grows per model, since
    Ollama reloads a model (tens of seconds) whenever num_ctx changes."""
    need = sum(len(m["content"]) for m in messages) // 3 + 6000
    size = next((c for c in (16384, 24576) if need <= c), 32768)
    _CTX_SEEN[model] = max(size, _CTX_SEEN.get(model, 0))
    return _CTX_SEEN[model]


def reply_budget(num_ctx: int, messages: List[Dict[str, str]]) -> int:
    """Reply tokens: what the context has left after the prompt, at least 8k and at most 16k."""
    room = num_ctx - sum(len(m["content"]) for m in messages) // 3 - 256
    return max(MAX_LOCAL_REPLY_TOKENS, min(MAX_LOCAL_REPLY_TOKENS_ROOMY, room))


def _ran_out_thinking(payload: Dict[str, Any]) -> bool:
    message = payload.get("message") if isinstance(payload.get("message"), dict) else {}
    return payload.get("done_reason") == "length" and not str(message.get("content") or "").strip() and bool(message.get("thinking"))


def _chat_http(profile: Dict[str, str], messages: List[Dict[str, str]], timeout: float) -> Reply:
    provider, model = profile["provider"], profile["model"]
    base = (profile.get("base_url") or default_base_url(provider)).rstrip("/")
    headers = {"Content-Type": "application/json"}
    if provider == "local_openai":  # an OpenAI-compatible server on this machine or a listed private-network address: no key, tier local. Not tested against a real server.
        url = f"{base}/v1/chat/completions"
        body = {"model": model, "messages": messages, "temperature": 0.2, "stream": False}
    elif provider == "ollama":
        url = f"{base}/api/chat"
        options, extra = _ollama_options(base, model, messages)
        body = {"model": model, "messages": messages, "stream": False, **extra,
                "options": {"temperature": 0.2, **options, "num_predict": reply_budget(options["num_ctx"], messages)}}
    else:
        local_service = provider == "openai_compat" and is_loopback_url(base)  # LM Studio, llama.cpp and the like need no key
        if not profile.get("api_key") and not local_service:
            raise AuthMissing(f"{provider} needs an API key")
        url = f"{base}/chat/completions"
        body = {"model": model, "messages": messages, "temperature": 0.2}
        if profile.get("api_key"):
            headers["Authorization"] = f"Bearer {profile['api_key']}"
        if provider == "openrouter":
            body["provider"] = {"data_collection": "deny"}
    payload = _post(url, headers, body, timeout, provider)
    if provider == "ollama" and _ran_out_thinking(payload):  # thinking used the whole budget: ask once more, answer directly
        payload = _post(url, headers, {**body, "think": False}, timeout, provider)
        if not str((payload.get("message") or {}).get("content") or "").strip():
            raise BadReply(f"{model} ran out of reply tokens before answering")
    try:
        text = payload["message"]["content"] if provider == "ollama" else payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise BadReply(f"{provider} sent a reply without text")
    if not isinstance(text, str) or not text.strip():
        raise BadReply(f"{provider} sent an empty reply")
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    if provider == "ollama":
        usage = {"prompt_tokens": payload.get("prompt_eval_count"), "completion_tokens": payload.get("eval_count")}
    return Reply(text, provider, model, tier_of(provider, model), usage)


def _flatten(messages: List[Dict[str, str]]) -> str:
    return "\n\n".join(f"[{m['role']}]\n{m['content']}" for m in messages)


def _chat_claude_cli(profile: Dict[str, str], messages: List[Dict[str, str]], timeout: float) -> Reply:
    """Claude Code CLI on the subscription: text only (no tools), empty folder, minimal environment."""
    cmd = [CLAUDE_BIN, "-p", "--output-format", "json", "--tools", "", "--no-session-persistence",
           "--setting-sources", "", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}']  # no MCP servers at all (PH-020: a capture showed startup calls to mcp-proxy)
    model = profile.get("model", "")
    if model and model != "default":
        cmd += ["--model", model]
    env = {k: os.environ[k] for k in CLAUDE_ENV_KEYS if k in os.environ}
    env.update(CLAUDE_FIXED_ENV)
    if os.path.isdir(CLAUDE_CONFIG_DIR):
        env["CLAUDE_CONFIG_DIR"] = CLAUDE_CONFIG_DIR
    with tempfile.TemporaryDirectory(prefix="uiorch-claude-") as cwd:
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, cwd=cwd, env=env)
        except FileNotFoundError:
            raise Unavailable("Claude CLI is not installed on this machine")
        token = getattr(ACTIVE, "cancel", None)
        if token:
            token.watch(proc.kill)
        try:
            out, err = proc.communicate(_flatten(messages), timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.communicate()
            raise Unavailable("Claude CLI did not answer in time")
        if token:
            token.check()
        done = subprocess.CompletedProcess(cmd, proc.returncode, out, err)
    try:
        data = json.loads(done.stdout)
    except ValueError:
        raise BadReply("Claude CLI sent output that is not JSON")
    text = str(data.get("result") or "")
    if data.get("is_error"):
        if any(h in text.lower() for h in LIMIT_HINTS):
            raise RateLimited("Claude usage limit reached")
        if "login" in text.lower():
            raise AuthMissing("Claude CLI is not logged in on this machine")
        raise BadReply("Claude CLI reported an error")
    if not text.strip():
        raise BadReply("Claude CLI sent an empty reply")
    # Subscription calls cost nothing per token, whatever the CLI reports.
    return Reply(text, "claude_cli", model or "default", "claude", data.get("usage") or {}, 0.0)


# USD per million tokens (input, output). Unknown models are priced high on purpose so the paid cap errs safe.
ANTHROPIC_PRICES = {"opus": (15.0, 75.0), "sonnet": (3.0, 15.0), "haiku": (1.0, 5.0)}


def _anthropic_cost(model: str, usage: Dict[str, Any]) -> float:
    price = next((v for k, v in ANTHROPIC_PRICES.items() if k in model), (15.0, 75.0))
    return round((int(usage.get("input_tokens") or 0) * price[0] + int(usage.get("output_tokens") or 0) * price[1]) / 1e6, 6)


def _chat_anthropic(profile: Dict[str, str], messages: List[Dict[str, str]], timeout: float) -> Reply:
    """Anthropic API (billed per token): the paid rung when you choose an API key over the subscription."""
    if not profile.get("api_key"):
        raise AuthMissing("anthropic needs an API key")
    model = profile["model"]
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    turns = [{"role": m["role"], "content": m["content"]} for m in messages if m["role"] in ("user", "assistant")]
    body: Dict[str, Any] = {"model": model, "max_tokens": 16000, "messages": turns, "temperature": 0.2}
    if system:
        body["system"] = system
    base = (profile.get("base_url") or "https://api.anthropic.com/v1").rstrip("/")
    headers = {"Content-Type": "application/json", "x-api-key": profile["api_key"], "anthropic-version": "2023-06-01"}
    payload = _post(f"{base}/messages", headers, body, timeout, "anthropic")
    try:
        text = "".join(b.get("text", "") for b in payload["content"] if b.get("type") == "text")
    except (KeyError, TypeError, AttributeError):
        raise BadReply("anthropic sent a reply without text")
    if not text.strip():
        raise BadReply("anthropic sent an empty reply")
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    return Reply(text, "anthropic", model, "paid", usage, _anthropic_cost(model, usage))


def chat(profile: Dict[str, str], messages: List[Dict[str, str]], timeout: float = 0) -> Reply:
    provider = profile.get("provider", "ollama")
    if provider not in PROVIDERS:
        raise ProviderError(f"Unsupported provider: {provider}")
    timeout = timeout or LLM_TIMEOUT
    if provider not in ("ollama", "local_openai") and not getattr(GATE, "open", False):
        # the Claude CLI, the Anthropic API and every OpenAI-compatible service are reached only through egress.send (masking, re-check, local check)
        raise NotSent("Cloud providers can only be reached through the privacy gateway")
    if provider == "claude_cli":
        return _chat_claude_cli(profile, messages, timeout)
    if provider == "anthropic":
        return _chat_anthropic(profile, messages, timeout)
    if provider in ("ollama", "local_openai"):
        def one(p):
            with OLLAMA_LOCK:  # the local runner stalled when the background fact extraction and a new question hit it together; held per attempt
                return _chat_http({**p, "provider": provider}, messages, timeout)
        return _with_fallbacks(profile, one)
    return _chat_http({**profile, "provider": provider}, messages, timeout)
