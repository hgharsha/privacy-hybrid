"""Phase 1: Extreme privacy is one account-wide setting, read again before every send. Checked against requests that really arrive
at a mock cloud service and a mock search service, with two sessions of the same account signed in at once."""
import json

import pytest

from privhybrid import egress, local, pipeline, policy
from privhybrid.vault import Vault
from tests.test_server import C, events

Q = "What is the weather today? Search the web."
PAD = " The weather was mild and the report was short and clear." * 6


def ask(c, mode, q=Q):
    return events(c.req("POST", "/api/chat", {"question": q, "mode": mode, "remember": False})[1])


def two_sessions(srv):
    a, b = C(srv), C(srv)
    assert a.login()[0] == 200 and b.login()[0] == 200
    return a, b


def test_baseline_cloud_and_search_really_reach_the_mocks_when_extreme_is_off(srv, net):
    a, b = two_sessions(srv)
    assert ask(b, "claude", "Summarise the lease please." + PAD)[-1][0] == "done"
    assert ask(b, "web")[-1][0] == "done"
    assert len(net.cloud) == 1 and len(net.search) == 1  # the paths are live, so the zero counts below mean something


def test_a_stale_second_session_cannot_reach_cloud_or_web_after_extreme_is_enabled_elsewhere(srv, net):
    a, b = two_sessions(srv)
    b.req("GET", "/api/state")  # b has loaded the old (off) preference
    assert a.req("POST", "/api/prefs", {"extreme": True})[0] == 200
    for mode in ("claude", "web", "auto"):
        ev = ask(b, mode, "Summarise the lease please." + PAD if mode == "claude" else Q)
        assert ev[-1][0] == "done" and ev[-1][1]["route"] == "local"
    assert net.cloud == [] and net.search == []


def test_theme_change_from_a_stale_session_cannot_switch_extreme_off(srv, net):
    a, b = two_sessions(srv)
    a.req("POST", "/api/prefs", {"extreme": True})
    assert b.req("POST", "/api/prefs", {"theme": "dark"})[0] == 200
    assert json.loads(a.req("GET", "/api/state")[1])["prefs"]["extreme"] is True
    assert ask(b, "claude", "Summarise the lease please." + PAD)[-1][1]["route"] == "local"
    assert net.cloud == []


def test_turning_it_off_restores_normal_modes_for_every_session(srv, net):
    a, b = two_sessions(srv)
    a.req("POST", "/api/prefs", {"extreme": True})
    a.req("POST", "/api/prefs", {"extreme": False})
    assert ask(b, "claude", "Summarise the lease please." + PAD)[-1][0] == "done" and len(net.cloud) == 1


def test_unreadable_policy_blocks_cloud_and_search(srv, net, tmp_path):
    a, b = two_sessions(srv)
    a.req("POST", "/api/prefs", {"theme": "dark"})
    for f in (tmp_path / "users").glob("*/prefs.bin"):
        f.write_bytes(b"corrupt" * 10)
    for mode, q in (("claude", "Summarise the lease please." + PAD), ("web", Q)):
        assert ask(b, mode, q)[-1][1].get("route") != "claude"
    assert net.cloud == [] and net.search == []


def test_a_switch_during_the_local_check_stops_the_request_before_it_leaves(srv, net, monkeypatch):
    a, b = two_sessions(srv)
    real = local.second_pass

    def slow_check(text, **kw):
        a.req("POST", "/api/prefs", {"extreme": True})  # the other device flips the switch mid-request
        return real(text, **kw)
    monkeypatch.setattr(local, "second_pass", slow_check)
    ev = ask(b, "claude", "Summarise the lease please." + PAD)
    assert ev[-1][1]["route"] == "local" and net.cloud == []


def test_search_retry_asks_again(net):
    state = {"extreme": False, "n": 0}
    real = egress.search

    def flaky(query, **kw):
        state["n"] += 1
        if state["n"] == 1:
            state["extreme"] = True  # switched on between the first try and the retry
            return []
        return real(query, **kw)
    with egress.bound(lambda: state["extreme"]):
        with pytest.raises(egress.PolicyBlocked):
            flaky("current weather") or flaky("current weather")
    assert net.search == []


def test_scheduled_web_job_is_refused_when_extreme_is_on(net):
    from privhybrid import schedule
    job = {"id": "j", "question": "current weather", "mode": "web", "folder": ""}
    res = schedule.run_job(job, {}, {}, is_extreme=lambda: True)
    assert res["status"].startswith("failed") and net.search == []
    res = schedule.run_job(job, {}, {}, is_extreme=lambda: False)
    assert res["status"] == "ok" and len(net.search) == 1


def test_the_policy_helper_fails_closed(tmp_path):
    class A:
        folder = tmp_path / "missing"
    assert policy.extreme(A()) is True  # no folder: unknown means on


def test_restoring_an_older_prefs_file_does_not_switch_extreme_off(tmp_path):
    from privhybrid import accounts
    store = accounts.Store(tmp_path / "users")
    acct = store.register("a@example.com", "correct horse 1")
    policy.update(acct, style="mac")  # version 1: extreme off
    old = (acct.folder / "prefs.bin").read_bytes()
    policy.update(acct, extreme=True)  # version 2: extreme on
    assert policy.extreme(acct) is True
    (acct.folder / "prefs.bin").write_bytes(old)  # a file restored from a backup
    assert policy.extreme(acct) is True  # older than what was seen: treated as on
    policy.update(acct, extreme=False)  # an explicit change is the new baseline
    assert policy.extreme(acct) is False
