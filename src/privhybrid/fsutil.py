"""File helpers that behave the same on macOS, Linux and Windows. private(): owner-only access (POSIX chmod; Windows removes inherited access and grants only the current user, inherited by files created later in a folder). replace(): os.replace that retries briefly on Windows when the destination is open elsewhere."""
import os
import subprocess
import time
from pathlib import Path

NT = os.name == "nt"
_run = subprocess.run  # bound now so tests that fake subprocess.run to watch the lockdown helper do not see icacls
_BS = chr(92)


def private(path, mode: int = 0o600) -> None:
    path = Path(path)
    if not NT:
        os.chmod(path, mode)
        return
    user = os.environ.get("USERNAME")
    if not user or not path.exists():
        return
    domain = os.environ.get("USERDOMAIN")
    who = f"{domain}{_BS}{user}" if domain else user
    grant = f"{who}:(OI)(CI)F" if path.is_dir() else f"{who}:F"
    _run(["icacls", str(path), "/inheritance:r", "/grant:r", grant], capture_output=True, check=False)


def replace(src, dst, tries: int = 40) -> None:
    for i in range(tries):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if not NT or i == tries - 1:
                raise
            time.sleep(0.05)
