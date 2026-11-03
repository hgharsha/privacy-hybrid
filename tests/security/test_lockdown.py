"""V3: the optional OS lockdown helper. The real osascript / pfctl are never run: subprocess is replaced. Synthetic data only."""
import subprocess
import sys

import pytest

from privhybrid import lockdown, server
from tests.security.test_multiuser import admin, join


class Fake:
    calls = []

    def __init__(self, rc=0):
        self.rc = rc

    def __call__(self, args, **kw):
        Fake.calls.append(args)
        return subprocess.CompletedProcess(args, self.rc, "", "")


@pytest.fixture
def fake(monkeypatch):
    Fake.calls = []
    f = Fake()
    monkeypatch.setattr(lockdown.subprocess, "run", f)
    monkeypatch.setattr(lockdown.sys, "platform", "darwin")
    monkeypatch.setattr(server.sys, "platform", "darwin")
    return f


def test_status_for_the_administrator_on_this_computer(srv, net, fake):
    a = admin(srv)
    st, body, _ = a.req("POST", "/api/admin/lockdown", {"action": "status"})
    assert st == 200 and '"local": true' in body.lower() and Fake.calls == []


def test_only_the_administrator(srv, net, fake):
    a = admin(srv)
    b = join(srv, a, "two@example.com")
    assert b.req("POST", "/api/admin/lockdown", {"action": "on", "confirm": True})[0] == 403
    assert Fake.calls == []


def test_a_request_from_another_device_is_refused_with_an_explanation(srv, net, fake, monkeypatch):
    a = admin(srv)
    # simulate a LAN peer by patching the handler class method that reads the connection address
    import http.server
    orig = http.server.BaseHTTPRequestHandler
    for cls in orig.__subclasses__():
        if hasattr(cls, "_peer_is_local"):
            monkeypatch.setattr(cls, "_peer_is_local", lambda self: False)
    st, body, _ = a.req("POST", "/api/admin/lockdown", {"action": "on", "confirm": True})
    assert st == 200 and "computer where the app is installed" in body and Fake.calls == []


def test_off_and_unconfirmed_are_refused(srv, net, fake):
    a = admin(srv)
    assert a.req("POST", "/api/admin/lockdown", {"action": "off", "confirm": True})[0] == 400
    assert a.req("POST", "/api/admin/lockdown", {"action": "on"})[0] == 400
    assert Fake.calls == []


def test_on_runs_only_the_fixed_script_with_the_macos_prompt(srv, net, fake, monkeypatch):
    monkeypatch.setattr(lockdown, "script_is_trusted", lambda *_: True)  # the real checkout is user-owned and correctly refused (see PH-008 tests)
    a = admin(srv)
    st, body, _ = a.req("POST", "/api/admin/lockdown", {"action": "on", "confirm": True, "user": "root; rm -rf /"})
    assert st == 200 and "not verified" in body
    (args,) = Fake.calls
    assert args[0] == "/usr/bin/osascript" and "with administrator privileges" in args[2]
    assert "scripts/lockdown.sh" in args[2] and args[2].count(" on phsvc") == 1 and "rm -rf" not in args[2]  # the user name from the request is ignored


def test_failure_is_reported_not_hidden(srv, net, monkeypatch):
    monkeypatch.setattr(lockdown.subprocess, "run", Fake(1))
    monkeypatch.setattr(lockdown.sys, "platform", "darwin")
    monkeypatch.setattr(server.sys, "platform", "darwin")
    a = admin(srv)
    st, body, _ = a.req("POST", "/api/admin/lockdown", {"action": "on", "confirm": True})
    assert st == 200 and '"ok": false' in body.lower() and "sudo scripts/lockdown.sh on" in body


def test_script_defaults_to_a_plan_and_refuses_without_root():
    if sys.platform != "darwin":  # pf exists only on macOS: elsewhere the script must refuse, and change nothing
        for args in ([], ["on"], ["plan"]):
            r = subprocess.run(["sh", "scripts/lockdown.sh", *args], capture_output=True, text=True)
            assert r.returncode == 2 and "macOS" in r.stderr
        return
    r = subprocess.run(["sh", "scripts/lockdown.sh"], capture_output=True, text=True)
    assert r.returncode == 0 and "Nothing was changed" in r.stdout
    r = subprocess.run(["sh", "scripts/lockdown.sh", "on"], capture_output=True, text=True)
    assert r.returncode != 0
    r = subprocess.run(["sh", "scripts/lockdown.sh", "plan", "a b"], capture_output=True, text=True)
    assert r.returncode == 2


# PH-008: the script is run with administrator rights, so it must not be changeable by the app user.
def _fake_lstat(monkeypatch, owner=0, writable=(), links=()):
    real = lockdown.os.lstat

    def fake(path, *a, **k):
        st = real(path, *a, **k)
        mode = st.st_mode & ~0o022  # the machine's real modes must not leak into the control case (CI runners have group-writable temp parents)
        if str(path) in writable:
            mode |= 0o020
        if str(path) in links:
            mode = (mode & ~0o170000) | 0o120000
        return lockdown.os.stat_result((mode, st.st_ino, st.st_dev, st.st_nlink, owner, st.st_gid, st.st_size, 0, 0, 0))
    monkeypatch.setattr(lockdown.os, "lstat", fake)


def test_refuses_non_root_script(tmp_path):
    """A file in the user's own checkout (owned by the user, parents writable by the user) is never trusted."""
    if hasattr(lockdown.os, "geteuid") and lockdown.os.geteuid() == 0:
        pytest.skip("running as root")
    s = tmp_path / "lockdown.sh"
    s.write_text("#!/bin/sh\n")
    assert lockdown.script_is_trusted(s) is False
    assert lockdown.script_is_trusted(lockdown.SCRIPT) is False  # the real checkout is owned by whoever cloned it


def test_refuses_script_when_any_parent_is_group_or_world_writable(tmp_path, monkeypatch):
    s = tmp_path / "lockdown.sh"
    s.write_text("#!/bin/sh\n")
    _fake_lstat(monkeypatch, owner=0)
    assert lockdown.script_is_trusted(s) is True  # all root-owned, none writable by others: the control case
    _fake_lstat(monkeypatch, owner=0, writable={str(tmp_path)})
    assert lockdown.script_is_trusted(s) is False  # a writable parent lets the app user swap the file
    _fake_lstat(monkeypatch, owner=0, writable={str(s)})
    assert lockdown.script_is_trusted(s) is False


def test_refuses_a_symlinked_script_or_parent(tmp_path, monkeypatch):
    s = tmp_path / "lockdown.sh"
    s.write_text("#!/bin/sh\n")
    _fake_lstat(monkeypatch, owner=0, links={str(s)})
    assert lockdown.script_is_trusted(s) is False
    _fake_lstat(monkeypatch, owner=0, links={str(tmp_path)})
    assert lockdown.script_is_trusted(s) is False


def test_refuses_when_a_missing_or_non_root_parent_is_in_the_chain(tmp_path, monkeypatch):
    assert lockdown.script_is_trusted(tmp_path / "nope.sh") is False
    s = tmp_path / "lockdown.sh"
    s.write_text("#!/bin/sh\n")
    _fake_lstat(monkeypatch, owner=501)
    assert lockdown.script_is_trusted(s) is False


def test_request_on_never_starts_osascript_for_an_untrusted_script(fake, monkeypatch):
    monkeypatch.setattr(lockdown, "script_is_trusted", lambda *_: False)
    assert lockdown.request_on("phsvc") is False and Fake.calls == []


def test_request_on_runs_osascript_only_after_the_check_passes(fake, monkeypatch):
    monkeypatch.setattr(lockdown, "script_is_trusted", lambda *_: True)
    assert lockdown.request_on("phsvc") is True and len(Fake.calls) == 1


def test_server_explains_that_an_untrusted_script_was_not_run(srv, net, fake):
    a = admin(srv)
    st, body, _ = a.req("POST", "/api/admin/lockdown", {"action": "on", "confirm": True})
    assert st == 200 and '"ok": false' in body.lower() and "owned by root" in body and Fake.calls == []
