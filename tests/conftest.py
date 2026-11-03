import pytest

from privhybrid import egress


@pytest.fixture(autouse=True)
def _second_pass_off_by_default(monkeypatch, request):
    """Older tests predate the local-model check; tests marked `strict` keep the real default (required)."""
    if "strict" not in request.keywords:
        monkeypatch.setattr(egress, "REQUIRE_SECOND_PASS", False)


@pytest.fixture(autouse=True)
def _open_registration_for_older_tests(monkeypatch, request):
    """Reason: the older tests register several accounts freely, which predates invitation-only registration. The tests under tests/security
    do not get this: they run with the real default (invitation only)."""
    if "tests/security" not in str(request.fspath).replace("\\", "/"):
        monkeypatch.setenv("PRIVHYBRID_REGISTRATION", "open")


@pytest.fixture(autouse=True)
def _short_approval_wait(monkeypatch):
    """A cloud send waits for the user to approve a preview; a test that forgets to answer should fail fast, not sit for minutes."""
    from privhybrid import server
    monkeypatch.setattr(server, "APPROVAL_WAIT", 2.0)
    monkeypatch.setattr(server, "REVIEW_DEFAULT", False)  # older tests drive the cloud route directly; the preview tests turn it on


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path, monkeypatch):
    """Tests never read the real state/config.json (it can name a model on another computer, which strict local-only mode refuses)."""
    from privhybrid import config
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
