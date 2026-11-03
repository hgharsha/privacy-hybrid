"""Live end-to-end through the running server (fake data). Needs: server on :8765 (register/login livetest@example.com),
Ollama with gemma4:26b, SearXNG on :8888, Claude CLI logged in."""
import base64, json, sys, time, urllib.request
sys.path.insert(0, "tests")
import corpus as C

BASE = "http://127.0.0.1:8765"
cookie = ""
def call(path, body):
    global cookie
    h = {"X-Requested-With": "privhybrid", "Content-Type": "application/json"}
    if cookie: h["Cookie"] = cookie
    with urllib.request.urlopen(urllib.request.Request(BASE + path, json.dumps(body).encode(), h), timeout=600) as r:
        if r.headers.get("Set-Cookie"): cookie = r.headers["Set-Cookie"].split(";")[0]
        return r.read().decode()
def events(raw):
    return [(b.split("\n")[0][7:], json.loads(b.split("\n")[1][6:])) for b in raw.strip().split("\n\n")]
def chat(q, mode):
    t = time.time(); evs = events(call("/api/chat", {"question": q, "mode": mode}))
    text = "".join(d for e, d in evs if e == "chunk")
    print(f"\n[{mode}] {q}\n  events: {[e for e, _ in evs if e != 'chunk']} ({time.time()-t:.0f}s)")
    for e, d in evs:
        if e in ("step", "notice", "needs_approval", "error"): print("  ", e, d)
    print("  answer:", text[:300].replace("\n", " "))
    return evs

try:
    call("/api/register", {"email": "livetest@example.com", "password": "livetest-pass-1"})
except Exception:
    call("/api/login", {"email": "livetest@example.com", "password": "livetest-pass-1"})
doc = (C.STATEMENT + C.PAD * 3).encode()
call("/api/upload", {"name": "maria_statement.txt", "data": base64.b64encode(doc).decode()})
chat("How much did I spend at the bistro, and what is the payroll deposit?", "local")
chat("Compare my savings transfer to current 5-year CD rates.", "auto")
chat("Summarise this statement in two sentences.", "claude")
chat("My SSN is 123-45-6789, can you remember it?", "claude")
