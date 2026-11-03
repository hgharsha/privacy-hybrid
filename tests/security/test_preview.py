"""The user sees exactly what will be sent to the cloud and says yes or no first. Checked against a mock cloud service."""
import json
import urllib.request

import pytest

from privhybrid import server
from tests.test_server import C

PAD = " The weather was mild and the report was short and clear." * 6
Q = "Summarise the lease with landlord Margaret Ellsworth please." + PAD


@pytest.fixture(autouse=True)
def review_on(monkeypatch):
    monkeypatch.setattr(server, "REVIEW_DEFAULT", True)


def chat(c, answer, mode="claude", q=Q):
    """Run a chat, answer the preview as `answer` (True, False, or None = never answer). Returns (events, preview data)."""
    h = {"X-Requested-With": "privhybrid", "Content-Type": "application/json", "Cookie": c.cookie}
    r = urllib.request.Request(c.base + "/api/chat", data=json.dumps({"question": q, "mode": mode, "remember": False}).encode(), headers=h, method="POST")
    evs, preview, ev = [], None, ""
    with urllib.request.urlopen(r) as res:
        for raw in res:
            line = raw.decode().rstrip("\n")
            if line.startswith("event: "):
                ev = line[7:]
            elif line.startswith("data: "):
                data = json.loads(line[6:])
                evs.append((ev, data))
                if ev == "preview":
                    preview = data
                    if answer is not None:
                        code, _, _ = c.req("POST", "/api/approve", {"id": data["id"], "ok": answer})
                        assert code == 200
    return evs, preview


def signed_in(srv):
    c = C(srv)
    assert c.login()[0] == 200
    return c


def test_preview_shows_the_masked_text_and_nothing_is_sent_before_yes(srv, net):
    c = signed_in(srv)
    evs, pv = chat(c, True)
    assert pv and "Margaret Ellsworth" not in pv["text"] and "[PERSON_1]" in pv["text"]
    assert evs[-1][0] == "done" and evs[-1][1]["route"] == "claude"
    assert len(net.cloud) == 1 and "Margaret Ellsworth" not in json.dumps(net.cloud)
    assert pv["text"] in json.dumps(net.cloud).replace("\\n", "\n") or "[PERSON_1]" in json.dumps(net.cloud)


def test_no_means_nothing_is_sent_and_it_is_answered_locally(srv, net):
    c = signed_in(srv)
    evs, pv = chat(c, False)
    assert pv and net.cloud == []
    assert evs[-1][0] == "done" and evs[-1][1]["route"] == "local"
    assert any("chose not to send" in str(d) for e, d in evs if e == "notice")


def test_no_answer_counts_as_no(srv, net, monkeypatch):
    monkeypatch.setattr(server, "APPROVAL_WAIT", 1.0)
    c = signed_in(srv)
    evs, pv = chat(c, None)
    assert pv and net.cloud == []
    assert evs[-1][1]["route"] == "local"


def test_the_review_can_be_switched_off_in_settings(srv, net):
    c = signed_in(srv)
    assert c.req("POST", "/api/prefs", {"review_cloud": False})[0] == 200
    evs, pv = chat(c, None)
    assert pv is None and len(net.cloud) == 1


def test_approving_an_unknown_id_is_refused(srv, net):
    c = signed_in(srv)
    assert c.req("POST", "/api/approve", {"id": "nope", "ok": True})[0] == 404


def test_extreme_privacy_still_wins_over_an_approved_preview(srv, net):
    c = signed_in(srv)
    assert c.req("POST", "/api/prefs", {"extreme": True})[0] == 200
    evs, pv = chat(c, True)
    assert pv is None and net.cloud == [] and evs[-1][1]["route"] == "local"


# --- V3: financial documents, cancellation, several sessions, exact content ---------------------------------------

FIN = "Date,Description,Amount\n" + "\n".join(f"2026-10-{1 + i % 27:02d},ACMEXSHOP,-{20 + i}.5{i % 10}" for i in range(12)) + "\n"


def up_fin(c):
    import base64
    return c.req("POST", "/api/upload", {"name": "fin.csv", "data": base64.b64encode(FIN.encode()).decode()})


def test_financial_summary_is_shown_even_when_the_review_is_off(srv, net):
    c = signed_in(srv)
    assert c.req("POST", "/api/prefs", {"review_cloud": False})[0] == 200
    assert up_fin(c)[0] == 200
    evs, pv = chat(c, True, q="Where does my money go?")
    assert pv is not None and "Financial summary" in pv["text"]  # the exact outgoing text, not a description of it
    assert len(net.cloud) == 1 and "ACMEXSHOP" not in json.dumps(net.cloud)


def test_financial_rejection_sends_nothing(srv, net):
    c = signed_in(srv)
    c.req("POST", "/api/prefs", {"review_cloud": False})
    up_fin(c)
    evs, pv = chat(c, False, q="Where does my money go?")
    assert pv and net.cloud == [] and evs[-1][1]["route"] == "local"


def test_financial_timeout_sends_nothing(srv, net, monkeypatch):
    monkeypatch.setattr(server, "APPROVAL_WAIT", 1.0)
    c = signed_in(srv)
    c.req("POST", "/api/prefs", {"review_cloud": False})
    up_fin(c)
    evs, pv = chat(c, None, q="Where does my money go?")
    assert pv and net.cloud == []


def test_financial_without_any_way_to_approve_never_sends(net):
    """A scheduled job has no approve callback: financial material stays here."""
    from privhybrid import pipeline
    from privhybrid.ingest import Document
    d = Document("fin.csv", FIN, [], "table", "Financial summary: total spending 300", "fin.csv")
    ans = pipeline.run("Where does my money go?", [d], mode="claude", approve=None)
    assert ans.route == "local" and net.cloud == [] and any("nothing was sent" in n for n in ans.notices)


def test_stop_during_the_wait_cancels(srv, net):
    import threading
    import time
    c = signed_in(srv)
    h = {"X-Requested-With": "privhybrid", "Content-Type": "application/json", "Cookie": c.cookie}
    r = urllib.request.Request(c.base + "/api/chat", data=json.dumps({"question": Q, "mode": "claude", "remember": False}).encode(), headers=h, method="POST")
    out = []

    def run():
        with urllib.request.urlopen(r) as res:
            out.append(res.read().decode())
    t = threading.Thread(target=run)
    t.start()
    time.sleep(1.5)
    assert c.req("POST", "/api/cancel", {})[0] == 200
    t.join(10)
    assert not t.is_alive() and net.cloud == []


def test_two_sessions_have_separate_approvals(srv, net):
    from tests.security.test_multiuser import admin, join
    a = admin(srv)
    b = join(srv, a, "two@example.com", {"cloud": True})
    assert a.req("POST", "/api/prefs", {"review_cloud": True})[0] == 200
    _, pa = chat(a, True)
    _, pb = chat(b, False)
    assert pa["id"] != pb["id"]
    assert len(net.cloud) == 1  # a's yes sent a's text only; b's no sent nothing
    assert b.req("POST", "/api/approve", {"id": pa["id"], "ok": True})[0] == 404  # one session cannot answer another's question


FLAGGED = "Please check my note: the number is four one five five five five one two three four, thanks." + PAD


def test_unsure_text_forces_the_preview_even_with_review_off(srv, net):
    c = signed_in(srv)
    assert c.req("POST", "/api/prefs", {"review_cloud": False})[0] == 200
    evs, pv = chat(c, False, q=FLAGGED)
    assert pv and pv["warnings"] and net.cloud == []  # shown despite Review off, and "no" sends nothing
    assert evs[-1][1]["route"] == "local"


def test_flagged_text_needs_the_second_confirmation(srv, net):
    c = signed_in(srv)
    h = {"X-Requested-With": "privhybrid", "Content-Type": "application/json", "Cookie": c.cookie}
    for confirmed, expect_sent in ((False, 0), (True, 1)):
        net.cloud.clear()
        r = urllib.request.Request(c.base + "/api/chat", data=json.dumps({"question": FLAGGED, "mode": "claude", "remember": False}).encode(), headers=h, method="POST")
        ev = ""
        with urllib.request.urlopen(r) as res:
            for raw in res:
                line = raw.decode().rstrip("\n")
                if line.startswith("event: "):
                    ev = line[7:]
                elif line.startswith("data: ") and ev == "preview":
                    pid = json.loads(line[6:])["id"]
                    assert c.req("POST", "/api/approve", {"id": pid, "ok": True, **({"confirmed": True} if confirmed else {})})[0] == 200
        assert len(net.cloud) == expect_sent  # a plain "yes" on flagged text is not enough


def test_ordinary_text_with_review_off_is_not_interrupted(srv, net):
    c = signed_in(srv)
    assert c.req("POST", "/api/prefs", {"review_cloud": False})[0] == 200
    evs, pv = chat(c, None)
    assert pv is None and len(net.cloud) == 1


def test_warning_box_does_not_rely_on_inline_styles():
    """The page's CSP is style-src 'self': inline style attributes are dropped by the browser, so the warning must be styled in style.css."""
    import re
    from pathlib import Path
    static = Path(server.__file__).resolve().parents[2] / "static"
    html, css = (static / "index.html").read_text(), (static / "style.css").read_text()
    for el in re.findall(r"<[^>]*(?:pvWarn|pvConfirm|pvconfirm)[^>]*>", html):
        assert "style=" not in el, el
    assert ".pvwarn" in css and "button:disabled" in css
