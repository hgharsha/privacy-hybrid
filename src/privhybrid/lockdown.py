"""The optional OS lockdown request. The only thing here that starts a process, and it starts only /usr/bin/osascript with a fixed script path:
macOS shows its own administrator-password dialog, so this program never sees the password. It opens no network connection."""
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "lockdown.sh"


def script_is_trusted(script: Path = SCRIPT) -> bool:
    """True only if the script is a regular file and it and EVERY parent directory up to / is owned by root, is not a symlink and is writable
    by nobody but root. Otherwise a process running as the app user could swap the script before it is run with administrator rights.
    Git file modes say nothing about this: a normal checkout is owned by the user who cloned it, so it fails here on purpose."""
    try:
        p = Path(os.path.abspath(script))
        for node in [p, *p.parents]:
            st = os.lstat(node)
            if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        return stat.S_ISREG(os.lstat(p).st_mode)
    except OSError:
        return False


def request_on(target: str) -> bool:
    """Ask macOS to run `lockdown.sh on <target>` with administrator rights. True only if it ran and exited 0 (still not proof the rule works)."""
    if sys.platform != "darwin" or not SCRIPT.exists():
        return False
    if not script_is_trusted(SCRIPT):  # checked immediately before the privileged run; a root-only path cannot be changed in between by the app user
        return False
    if not re.fullmatch(r"[A-Za-z0-9_./ -]+", str(SCRIPT)) or not re.fullmatch(r"[A-Za-z0-9_.-]+", target):
        return False
    cmd = f'do shell script "/bin/sh \'{SCRIPT}\' on {target}" with administrator privileges'
    try:
        return subprocess.run(["/usr/bin/osascript", "-e", cmd], capture_output=True, text=True, timeout=120).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
