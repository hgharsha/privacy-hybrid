"""Local model settings. Order: environment variable, then state/config.json, then the default.

Keys: answer, check, summary, query, embed (model names), ollama_url and ollama_backups (this machine, or an IP address on your
private network such as another Mac or a Linux box; egress enforces that and allows only those exact addresses).
Env: PRIVHYBRID_ANSWER_MODEL, PRIVHYBRID_CHECK_MODEL, PRIVHYBRID_SUMMARY_MODEL, PRIVHYBRID_QUERY_MODEL, PRIVHYBRID_EMBED_MODEL,
PRIVHYBRID_OLLAMA_URL, PRIVHYBRID_OLLAMA_BACKUPS (comma separated).
"""
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

DEFAULT_MODEL = "gemma4:26b"  # caught names/addresses that qwen2.5:7b missed in a trial (2026-10-27)
DEFAULT_EMBED = "nomic-embed-text"
DEFAULT_URL = "http://127.0.0.1:11434"
CONFIG_FILE = Path(__file__).resolve().parents[2] / "state" / "config.json"


def _file() -> dict:
    try:
        data = json.loads(CONFIG_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


_PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]
MAX_BACKUPS = 3


def valid_ollama_url(url: str) -> bool:
    """http(s) on this machine, or a literal private-network IP (no names: a name could be re-pointed elsewhere)."""
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.path not in ("", "/") or u.query:
        return False
    if re.search(r"[\s#?;,|@\\]", url) or url.rstrip("/") != f"{u.scheme}://{u.netloc}":  # exactly scheme://host[:port]: no fragment, params, list separators
        return False
    if u.hostname.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(u.hostname)
        port = u.port  # raises ValueError on a bad port
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    # another machine: an explicit high port only, so this cannot be pointed at a router, web or admin service (80, 443, 22 ...)
    return any(ip in n for n in _PRIVATE_NETS) and port is not None and port >= 1024


def _is_loopback(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    try:
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _clean(url: object) -> str:
    return str(url).strip().rstrip("/")


def _entry(raw: str) -> Tuple[str, str]:
    """"http://ip:port" or "http://ip:port model": the model name, if given, replaces the chat models on that machine."""
    parts = raw.split()
    return (_clean(parts[0]), parts[1]) if len(parts) == 2 else (_clean(raw), "")


def _entry_ok(url: str, model: str) -> bool:
    return valid_ollama_url(url) and (not model or bool(_MODEL_RE.match(model)))


def ollama_backup_entries() -> List[Tuple[str, str]]:
    """(address, model override) for each backup, in order."""
    env = os.environ.get("PRIVHYBRID_OLLAMA_BACKUPS")
    raw = env.split(",") if env else (_file().get("ollama_backups") or [])
    primary = ollama_url()
    out: List[Tuple[str, str]] = []
    for url, model in (_entry(x) for x in raw if isinstance(x, str) and x.strip()):
        if url != primary and url not in [u for u, _ in out] and _entry_ok(url, model):
            out.append((url, model))
    return out[:MAX_BACKUPS]


def ollama_backups() -> List[str]:
    return [u for u, _ in ollama_backup_entries()]


def embed_url() -> str:
    """Where library-search embeddings run first ("" = same as the chat address). Lets a quiet machine do them while the main one is busy."""
    u = _clean(os.environ.get("PRIVHYBRID_EMBED_URL") or _file().get("embed_url") or "")
    return u if u and valid_ollama_url(u) else ""


def ollama_url() -> str:
    return _clean(os.environ.get("PRIVHYBRID_OLLAMA_URL") or _file().get("ollama_url") or DEFAULT_URL)


_LAN_CACHE: dict = {}


def lan_endpoints() -> Set[Tuple[str, int]]:
    """(host, port) of the configured non-loopback Ollama addresses: the only places off this machine the process may connect.
    Cached until config.json or the environment changes (this runs on every connection)."""
    env = tuple(os.environ.get(k) for k in ("PRIVHYBRID_OLLAMA_URL", "PRIVHYBRID_OLLAMA_BACKUPS", "PRIVHYBRID_EMBED_URL"))
    try:
        stamp = (CONFIG_FILE.stat().st_mtime_ns,) + env
    except OSError:
        stamp = (None,) + env
    if _LAN_CACHE.get("stamp") != stamp or _LAN_CACHE.get("file") != str(CONFIG_FILE):
        _LAN_CACHE.update(stamp=stamp, file=str(CONFIG_FILE), value=_compute_lan())
    return set(_LAN_CACHE["value"])


def _compute_lan() -> Set[Tuple[str, int]]:
    out: Set[Tuple[str, int]] = set()
    for url in [ollama_url(), embed_url()] + ollama_backups():
        if not url:
            continue
        u = urlparse(url)
        if valid_ollama_url(url) and u.hostname and u.hostname.lower() != "localhost" and not ipaddress.ip_address(u.hostname).is_loopback:
            out.add((str(ipaddress.ip_address(u.hostname)), u.port or (443 if u.scheme == "https" else 80)))
    return out


LOCAL_RUNTIMES = ("ollama", "local_openai")


def local_runtime() -> str:
    """"ollama" (default) or "local_openai": any OpenAI-compatible server on this machine or the private network (LM Studio, llama.cpp, vLLM)."""
    r = os.environ.get("PRIVHYBRID_LOCAL_RUNTIME") or str(_file().get("local_runtime") or "ollama")
    return r if r in LOCAL_RUNTIMES else "ollama"


def profile(key: str) -> Dict[str, str]:
    """Local-model profile for answer, check, summary, query or embed."""
    cfg = _file()
    model = os.environ.get(f"PRIVHYBRID_{key.upper()}_MODEL") or str(cfg.get(key) or (DEFAULT_EMBED if key == "embed" else DEFAULT_MODEL))
    out = {"provider": local_runtime(), "model": model}
    url = os.environ.get("PRIVHYBRID_OLLAMA_URL") or cfg.get("ollama_url")
    if url:
        out["base_url"] = str(url)
    backups = ollama_backup_entries()
    eu = embed_url() if key == "embed" else ""
    if eu:  # embeddings go to their own machine first, then the chat address and the backups
        rest = [u for u in [ollama_url()] + [b for b, _ in backups] if u != eu]
        out["base_url"], out["fallback_urls"] = eu, ",".join(rest)
        return out
    if backups:  # tried in order, only when the one before did not answer; "url|model" swaps the chat model there (embeddings keep theirs)
        out["fallback_urls"] = ",".join(u if (not m or key == "embed") else f"{u}|{m}" for u, m in backups)
    return out


KEYS = ("answer", "check", "summary", "query", "embed")
CLOUD_PROVIDERS = ("claude_cli", "openai_compat")
CLOUD_KEY_ACCOUNT = "cloud-api-key"  # the API key lives in the system keychain, never in config.json


def _key_account(url: str) -> str:
    """One keychain entry per service origin (scheme, host, port): a key saved for one service can never be found for another."""
    from urllib.parse import urlparse
    u = urlparse(url or "")
    return f"{CLOUD_KEY_ACCOUNT}:{u.scheme}://{(u.hostname or '').lower()}:{u.port or (443 if u.scheme == 'https' else 80)}"
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$")


def cloud_provider() -> str:
    p = os.environ.get("PRIVHYBRID_CLOUD_PROVIDER") or str(_file().get("cloud_provider") or "claude_cli")
    return p if p in CLOUD_PROVIDERS else "claude_cli"


def cloud_api_key() -> str:
    key = os.environ.get("PRIVHYBRID_CLOUD_API_KEY")
    if key:
        return key
    from . import keystore  # late import: keystore needs no config
    try:
        return (keystore.get(_key_account(str(_file().get("cloud_url") or ""))) or b"").decode()
    except keystore.KeychainUnavailable:
        return ""


def cloud_profile() -> Dict[str, str]:
    """The profile the Claude (masked) route sends to: the Claude CLI, or an OpenAI-compatible service chosen in Settings."""
    if cloud_provider() == "claude_cli":
        return {"provider": "claude_cli", "model": ""}
    cfg = _file()
    out = {"provider": "openai_compat", "model": str(cfg.get("cloud_model") or ""), "base_url": str(cfg.get("cloud_url") or "")}
    key = cloud_api_key()
    if key:
        out["api_key"] = key
    return out


def cloud_label() -> str:
    return "Claude (masked)" if cloud_provider() == "claude_cli" else "Cloud model (masked)"


def current() -> Dict[str, object]:
    """Effective settings for the UI: value plus whether an environment variable overrides it."""
    cfg = _file()
    out: Dict[str, object] = {}
    for k in KEYS:
        out[k] = profile(k)["model"]
        out[k + "_env"] = bool(os.environ.get(f"PRIVHYBRID_{k.upper()}_MODEL"))
    out["ollama_url"] = os.environ.get("PRIVHYBRID_OLLAMA_URL") or cfg.get("ollama_url") or DEFAULT_URL
    out["ollama_url_env"] = bool(os.environ.get("PRIVHYBRID_OLLAMA_URL"))
    out["embed_url"] = embed_url()
    out["embed_url_env"] = bool(os.environ.get("PRIVHYBRID_EMBED_URL"))
    out["ollama_backups"] = [f"{u} {m}" if m else u for u, m in ollama_backup_entries()]
    out["ollama_backups_env"] = bool(os.environ.get("PRIVHYBRID_OLLAMA_BACKUPS"))
    remote = sorted({u for u in [ollama_url(), embed_url()] + ollama_backups() if u and not _is_loopback(u)})
    out["remote_ollama"] = remote
    out["remote_ollama_warning"] = (
        "Questions and whole documents are sent to another machine on your network (" + ", ".join(remote) + "). "
        + ("This connection is not encrypted, so anyone on that network could read them. " if any(u.startswith("http://") for u in remote) else "")
        + "Only use a computer you control, and prefer an encrypted tunnel (SSH, WireGuard or Tailscale) or https.") if remote else ""
    out["local_runtime"] = local_runtime()
    out["local_runtime_env"] = bool(os.environ.get("PRIVHYBRID_LOCAL_RUNTIME"))
    out["cloud_provider"] = cloud_provider()
    out["cloud_provider_env"] = bool(os.environ.get("PRIVHYBRID_CLOUD_PROVIDER"))
    out["cloud_key_env"] = bool(os.environ.get("PRIVHYBRID_CLOUD_API_KEY"))
    out["cloud_url"] = str(cfg.get("cloud_url") or "")
    out["cloud_model"] = str(cfg.get("cloud_model") or "")
    out["cloud_key_set"] = bool(cloud_api_key())  # the key itself is never sent back
    out["cloud_label"] = cloud_label()
    return out


def _save_cloud(values: dict, cfg: dict):
    """Validate the cloud settings into `cfg`. Returns the keychain step, run only after the file is written, so a failed write never leaves a key paired with the wrong service."""
    from urllib.parse import urlparse
    from . import egress, keystore
    old_account = _key_account(str(cfg.get("cloud_url") or ""))
    if values.get("cloud_provider"):
        if values["cloud_provider"] not in CLOUD_PROVIDERS:
            raise ValueError("Unknown cloud provider")
        cfg["cloud_provider"] = values["cloud_provider"]
    if "cloud_url" in values:  # an explicit empty value clears it
        url = str(values["cloud_url"] or "").strip().rstrip("/")
        if url:
            try:
                egress.validate_cloud_url(url)
            except egress.EgressBlocked as exc:
                raise ValueError(str(exc))
            cfg["cloud_url"] = url
        else:
            cfg.pop("cloud_url", None)
    if "cloud_model" in values:
        m = str(values["cloud_model"] or "").strip()
        if m and not _MODEL_RE.match(m):
            raise ValueError("Bad cloud model name")
        if m:
            cfg["cloud_model"] = m
        else:
            cfg.pop("cloud_model", None)
    if cfg.get("cloud_provider") == "openai_compat" and not (cfg.get("cloud_url") and cfg.get("cloud_model")):
        raise ValueError("An OpenAI-compatible cloud model needs an address and a model name")
    new_account = _key_account(str(cfg.get("cloud_url") or ""))
    moved = old_account != new_account and bool(cfg.get("cloud_url"))  # a different service: its own, empty keychain slot
    if values.get("cloud_api_key_clear"):
        def after():
            for acct in {old_account, new_account}:
                try:
                    keystore.delete(acct)
                except keystore.KeychainUnavailable:
                    pass
        return after
    if values.get("cloud_api_key"):
        key = str(values["cloud_api_key"]).strip()
        if not 8 <= len(key) <= 400 or any(c.isspace() for c in key):
            raise ValueError("That does not look like an API key")

        def after():
            try:
                keystore.put(new_account, key.encode())
            except keystore.KeychainUnavailable:
                raise ValueError("The system keychain did not answer, so the key was not saved. Set PRIVHYBRID_CLOUD_API_KEY instead.")
            if moved:
                try:
                    keystore.delete(old_account)  # tidy up: the old service's key is no longer used
                except keystore.KeychainUnavailable:
                    pass
        return after
    return lambda: None


def save(values: dict) -> None:
    """Validate and write state/config.json. Raises ValueError. Loopback is enforced here and again by egress."""
    from . import egress  # late import: egress imports config
    cfg = _file()
    for k in KEYS:
        if values.get(k):
            m = str(values[k]).strip()
            if not _MODEL_RE.match(m):
                raise ValueError(f"Bad model name for {k}")
            cfg[k] = m
    if values.get("local_runtime"):
        if values["local_runtime"] not in LOCAL_RUNTIMES:
            raise ValueError("Unknown local model server")
        cfg["local_runtime"] = values["local_runtime"]
    if values.get("ollama_url"):
        url = _clean(values["ollama_url"])
        if not valid_ollama_url(url):
            raise ValueError("The Ollama address must be http(s) on this machine, or an IP address on your private network (for example http://192.168.1.20:11434)")
        cfg["ollama_url"] = url
    if "embed_url" in values:
        eu = _clean(values["embed_url"] or "")
        if eu and not valid_ollama_url(eu):
            raise ValueError("The embeddings address must be http(s) on this machine, or an IP address on your private network with a port of 1024 or higher")
        cfg["embed_url"] = eu
    if "ollama_backups" in values:
        raw = values["ollama_backups"]
        items = [x for x in (raw.splitlines() if isinstance(raw, str) else raw or []) if str(x).strip()]
        entries = [_entry(str(x)) for x in items]
        if len(entries) > MAX_BACKUPS or not all(_entry_ok(u, m) for u, m in entries):
            raise ValueError(f"Backup Ollama addresses: up to {MAX_BACKUPS}, each http(s) on this machine or a private-network IP address, optionally followed by a model name")
        cfg["ollama_backups"] = [f"{u} {m}" if m else u for u, m in entries]
    after = _save_cloud(values, cfg)
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    os.replace(tmp, CONFIG_FILE)
    after()
