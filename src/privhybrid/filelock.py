"""Cross-process lock: an advisory flock on a small lock file, so two processes (or two threads) cannot interleave a read-modify-write.

Re-entrant for one thread (a nested `with` on the same path only counts up). A lock that cannot be taken within `timeout` seconds raises
LockTimeout instead of waiting forever. The operating system releases a flock when its process ends, so a killed process never leaves a stale lock.
Lock order, to avoid deadlocks: the store lock (`.store.lock`) first, then one account lock (`.<id>.lock`); never the other way round.
Supported: macOS and Linux (fcntl). On Windows there is no flock: the lock then only covers threads of one process (documented in docs/SECURITY.md).
"""
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None

DEFAULT_TIMEOUT = 15.0
_local = threading.local()
_thread_locks: dict = {}
_guard = threading.Lock()


class LockTimeout(RuntimeError):
    pass


def _thread_lock(key: str) -> threading.Lock:
    with _guard:
        return _thread_locks.setdefault(key, threading.Lock())


@contextmanager
def locked(path, timeout: float = DEFAULT_TIMEOUT):
    path = Path(path)
    key = str(path)
    held = getattr(_local, "held", None)
    if held is None:
        held = _local.held = {}
    if key in held:  # this thread already holds it
        held[key] += 1
        try:
            yield
        finally:
            held[key] -= 1
        return
    tl = _thread_lock(key)
    if not tl.acquire(timeout=timeout):
        raise LockTimeout(f"could not take {path.name} within {timeout:g}s")
    fd = None
    try:
        if fcntl is not None:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            end = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= end:
                        raise LockTimeout(f"could not take {path.name} within {timeout:g}s")
                    time.sleep(0.02)
        held[key] = 1
        try:
            yield
        finally:
            held.pop(key, None)
    finally:
        if fd is not None:
            os.close(fd)  # closing the descriptor releases the flock
        tl.release()
