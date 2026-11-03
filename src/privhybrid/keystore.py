"""The scheduler key S lives in the macOS Keychain, never in a file (docs/SCHEDULED-JOBS-DESIGN.md).

A read can hang on an "allow access" dialog (a different program than the one that stored it), so every call has a time limit
and any failure becomes KeychainUnavailable: the scheduler skips that run, it never crashes and never falls back to a file.
"""
import base64
import threading
from typing import Callable, Optional

SERVICE = "privhybrid-sched"
TIMEOUT = 10.0


class KeychainUnavailable(RuntimeError):
    pass


def _keyring():
    import keyring
    return keyring


_backend: Optional[Callable] = None  # tests replace this with a dict-backed fake: (op, uid, value) -> value


def _call(op: str, uid: str, value: Optional[str] = None) -> Optional[str]:
    box: dict = {}

    def work() -> None:
        try:
            if _backend:
                box["r"] = _backend(op, uid, value)
                return
            kr = _keyring()
            if op == "get":
                box["r"] = kr.get_password(SERVICE, uid)
            elif op == "set":
                kr.set_password(SERVICE, uid, value or "")
            elif op == "delete":
                try:
                    kr.delete_password(SERVICE, uid)
                except kr.errors.PasswordDeleteError:
                    pass  # already gone
        except Exception as exc:  # keyring has many backend-specific errors
            box["e"] = exc

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(TIMEOUT)
    if t.is_alive() or "e" in box:
        raise KeychainUnavailable("Keychain unavailable")
    return box.get("r")


def get(uid: str) -> Optional[bytes]:
    v = _call("get", uid)
    return base64.b64decode(v) if v else None


def put(uid: str, secret: bytes) -> None:
    _call("set", uid, base64.b64encode(secret).decode())


def delete(uid: str) -> None:
    _call("delete", uid)
