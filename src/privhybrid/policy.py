"""The one account-level privacy policy (Extreme privacy). The source of truth is the account's encrypted prefs.bin on disk.

Nothing caches it: every check reads the file again, so a change made in one session or device applies to every other session,
background thread and scheduled job at once. If the file cannot be read or decrypted the answer is "unknown", and callers treat
unknown as Extreme privacy on (cloud and web stay blocked).
"""
import threading
from typing import Any

from cryptography.exceptions import InvalidTag

_LOCK = threading.Lock()  # read-modify-write of prefs.bin is one step, across every session of every account


class PolicyUnavailable(RuntimeError):
    """The stored policy could not be read. Treated as 'Extreme privacy on'."""


class PrefsRolledBack(PolicyUnavailable):
    """prefs.bin is older than one this install has already seen (a file restored from a backup). Treated as 'Extreme privacy on'."""


def _seen_path(acct: Any):
    return acct.folder.parent / f".{acct.folder.name}.prefs_seen"  # outside the account folder, so restoring that folder does not restore it


def _seen(acct: Any) -> int:
    try:
        return int(_seen_path(acct).read_text().strip() or 0)
    except (OSError, ValueError):
        return 0


def _mark_seen(acct: Any, ver: int, force: bool = False) -> None:
    if not force and ver <= _seen(acct):
        return
    try:
        p = _seen_path(acct)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(str(ver))
        tmp.chmod(0o600)
        tmp.replace(p)
    except OSError:
        pass  # the check is then weaker, never stricter than before


def _read(acct: Any, allow_rollback: bool = False) -> dict:
    path = acct.folder / "prefs.bin"
    try:
        blob = path.read_bytes()
    except FileNotFoundError:
        if not acct.folder.is_dir():
            raise PolicyUnavailable("account folder missing")
        return {}  # no preferences saved yet: nothing is switched on
    except OSError:
        raise PolicyUnavailable("prefs unreadable")
    try:
        prefs, ver = acct.load_v("prefs.bin", None)
    except Exception:
        raise PolicyUnavailable("prefs undecryptable")
    if not isinstance(prefs, dict):
        raise PolicyUnavailable("prefs malformed")
    if ver < _seen(acct):
        if not allow_rollback:
            raise PrefsRolledBack("prefs older than the last one seen")
        return {**prefs, "extreme": True}  # an explicit change starts from the safe side
    _mark_seen(acct, ver)
    return prefs


def prefs(acct: Any) -> dict:
    return _read(acct)


def extreme(acct: Any) -> bool:
    """True when Extreme privacy is on, or when that cannot be determined."""
    try:
        return bool(_read(acct).get("extreme"))
    except PolicyUnavailable:
        return True


def update(acct: Any, **changes: Any) -> dict:
    """Merge changes into the stored preferences (fresh read, then write), so a session with an old copy cannot undo a newer change."""
    with _LOCK:
        cur = _read(acct, allow_rollback=True)
        new = {**cur, **{k: v for k, v in changes.items() if k != "extreme"}}
        if "extreme" in changes:
            new.pop("extreme", None)
            if changes["extreme"]:
                new["extreme"] = True
        ver = acct.save("prefs.bin", new)
        _mark_seen(acct, ver, force=True)  # an explicit save is the new baseline
        return new
