"""Windows only: fsutil.private() leaves a folder readable by the current user and nobody else (checked with icacls, synthetic data only)."""
import os
import subprocess

import pytest

from privhybrid import fsutil

pytestmark = pytest.mark.skipif(os.name != "nt", reason="icacls exists only on Windows")


def acl_lines(path):
    out = subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True).stdout
    return [line.replace(str(path), "").strip() for line in out.splitlines() if line.strip() and "Successfully processed" not in line]


def check_owner_only(path, inherited_ok=False):
    lines = acl_lines(path)
    text = "\n".join(lines).lower()
    for broad in ("everyone", "users", "authenticated users"):
        assert broad not in text.replace(os.environ["USERNAME"].lower(), ""), (broad, lines)
    assert os.environ["USERNAME"].lower() in text, lines
    if not inherited_ok:
        assert not any("(i)" in line.lower() for line in lines), lines  # nothing inherited from the parent


def test_private_folder_and_file_are_owner_only(tmp_path):
    d = tmp_path / "acct"
    d.mkdir()
    fsutil.private(d, 0o700)
    check_owner_only(d)
    f = d / "meta.json"
    f.write_text("{}")  # created later: must inherit owner-only access from the folder
    fsutil.private(f, 0o600)
    check_owner_only(f)
    g = d / "later.bin"
    g.write_bytes(b"x")
    check_owner_only(g, inherited_ok=True)  # inherited, but from our owner-only folder
