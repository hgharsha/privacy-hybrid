"""Commits must carry a GitHub noreply identity, never one guessed from the machine's name (it would be public in the history)."""
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_identity.sh"
GOOD = "16566517+someone@users.noreply.github.com"
BAD = "someone@Some-MacBook-Pro.local"


def _commit(repo, email, name="x", committer=None, msg="c"):
    env = {**os.environ, "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": committer or email}
    (repo / "f").write_text(email + str(len(list(repo.iterdir()))))
    subprocess.run(["git", "add", "f"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", msg], cwd=repo, check=True, env=env)


def _check(repo):
    return subprocess.run(["sh", str(SCRIPT), "HEAD"], cwd=repo, capture_output=True, text=True)


def _repo(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    return tmp_path


def test_noreply_identities_pass(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, GOOD)
    _commit(repo, GOOD, committer="noreply@github.com")
    assert _check(repo).returncode == 0


def test_a_machine_name_identity_fails_and_is_not_printed(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, GOOD)
    _commit(repo, BAD)
    r = _check(repo)
    assert r.returncode == 1 and "Some-MacBook-Pro" not in r.stdout + r.stderr


def test_a_bad_committer_alone_fails(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, GOOD, committer=BAD)
    assert _check(repo).returncode == 1


def test_a_session_link_in_the_message_fails(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, GOOD, msg="Fix\n\nClaude-Session: https://claude.ai/code/session_x")
    assert _check(repo).returncode == 1
