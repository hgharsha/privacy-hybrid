#!/usr/bin/env python3
"""Build a static security dashboard from docs/security/REMEDIATION_TRACKER.md.

Usage: python scripts/build_dashboard.py [out_dir]   (default: _site)
No dependencies, no JavaScript, no external requests. The tracker stays the source of truth.
"""
import html
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACKER = ROOT / "docs/security/REMEDIATION_TRACKER.md"
REPO = "hgharsha/privacy-hybrid"

STATUS_COLORS = {"Closed": "#2da44e", "Mostly fixed": "#bf8700", "Open": "#cf222e", "Accepted": "#6e7781"}
PRIO_COLORS = {"P1": "#cf222e", "P2": "#bf8700", "P3": "#0969da"}
SEV_COLORS = {"Medium": "#bc4c00", "Low": "#0969da", "Info": "#6e7781", "Not rated": "#8250df"}


def rows(text):
    out, header = [], None
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells[0] == "ID":
            header = cells
        elif header and re.fullmatch(r"PH-\d+", cells[0]):
            out.append(dict(zip(header, cells)))
    return out


def status_group(s):
    s = s.lower()
    for key, name in (("closed", "Closed"), ("mostly", "Mostly fixed"), ("open", "Open"), ("accepted", "Accepted")):
        if s.startswith(key):
            return name
    return "Open"


def strip_md(s):
    return html.escape(re.sub(r"[`*]", "", s))


CONTROLS = [  # (control, what it does, tracker findings that must be Closed for the tick)
    ("Sensitive text is masked or blocked before it leaves", "ID numbers, passports and non-US addresses", ["PH-001", "PH-002"]),
    ("Extreme privacy cannot be undone by accident", "older backups and the scheduler respect it", ["PH-006", "PH-007"]),
    ("Sign-in is hardened", "setup code, slow password hashing, throttling per account", ["PH-004", "PH-010", "PH-011"]),
    ("Network traffic is protected", "TLS required on the LAN, bodies capped before sign-in", ["PH-005", "PH-009"]),
    ("Accounts are kept apart", "other users get a reduced config view, stable admin succession", ["PH-013", "PH-018"]),
    ("Nothing readable is kept in memory caches", "no document text cached", ["PH-012"]),
    ("Tamper-evident audit log", "hash chain, private folder, rotation", ["PH-019"]),
    ("Cloud helper sends only the prompt", "telemetry off, no connectors, checked by capture", ["PH-020"]),
    ("Locked-down install", "root-run script refused unless owned by root", ["PH-008"]),
    ("Supply chain pinned and checked", "hashed lock file, pinned Actions, CI scans", ["PH-014"]),
    ("Public repo is protected", "pull request and green checks required, admins included", ["PH-015"]),
]


def donut(counts, total):
    r, c, off, parts = 70, 2 * 3.14159265 * 70, 0.0, []
    for name, n in counts:
        if not n:
            continue
        length = c * n / total
        parts.append(
            f'<circle r="{r}" cx="90" cy="90" fill="none" stroke="{STATUS_COLORS[name]}" stroke-width="28" '
            f'stroke-dasharray="{length:.2f} {c - length:.2f}" stroke-dashoffset="{-off:.2f}" transform="rotate(-90 90 90)"/>'
        )
        off += length
    return (f'<svg viewBox="0 0 180 180" width="180" height="180" role="img" aria-label="Findings by status">'
            f'{"".join(parts)}<text x="90" y="88" text-anchor="middle" font-size="34" font-weight="700" fill="currentColor">{total}</text>'
            f'<text x="90" y="110" text-anchor="middle" font-size="12" fill="#6e7781">findings</text></svg>')


def bars(counter, colors):
    top = max(counter.values()) if counter else 1
    out = []
    for k, n in counter.items():
        w = 100 * n / top
        out.append(f'<div class="bar"><span>{html.escape(k)}</span><div class="track"><div class="fill" '
                   f'style="width:{w:.0f}%;background:{colors.get(k, "#6e7781")}"></div></div><b>{n}</b></div>')
    return "".join(out)


def build():
    text = TRACKER.read_text()
    data = rows(text)
    total = len(data)
    groups = Counter(status_group(r["Status"]) for r in data)
    order = ["Closed", "Mostly fixed", "Open", "Accepted"]
    sev = Counter(r["Severity"] for r in data)
    prio = Counter(r["Priority"].split(" ")[0] for r in data)
    legend = "".join(
        f'<li><i style="background:{STATUS_COLORS[k]}"></i>{k} <b>{groups[k]}</b></li>' for k in order)

    cards = []
    for r in sorted(data, key=lambda r: (order.index(status_group(r["Status"])), r["ID"])):
        g = status_group(r["Status"])
        tests = [t.split("::")[-1] for t in re.findall(r"`([^`]+)`", r["Regression test"])]
        links = ""
        if tests:
            more = f" (+{len(tests) - 1} more)" if len(tests) > 1 else ""
            links = f"test: <code>{html.escape(tests[0])}</code>{more}"
        cards.append(
            f'<div class="card" style="border-left-color:{STATUS_COLORS[g]}">'
            f'<div class="top"><b>{r["ID"]}</b><span class="pill" style="background:{STATUS_COLORS[g]}">{g}</span></div>'
            f'<div class="title">{strip_md(r["Title"])}</div>'
            f'<div class="meta"><span style="color:{SEV_COLORS.get(r["Severity"], "#6e7781")}">{strip_md(r["Severity"])}</span>'
            f' · {strip_md(r["Priority"])} · effort {strip_md(r["Effort"])}</div>'
            f'<div class="note">{strip_md(r["Status"])}</div>'
            f'<div class="meta">{links}</div></div>')

    state = ""
    by_id = {r["ID"]: status_group(r["Status"]) for r in data}
    controls = []
    for name, what, ids in CONTROLS:
        ok = all(by_id.get(i) == "Closed" for i in ids)
        mark, color = ("✔", "#2da44e") if ok else ("◐", "#bf8700")
        controls.append(
            f'<li><span class="ck" style="background:{color}">{mark}</span><div><b>{html.escape(name)}</b>'
            f'<div class="meta">{html.escape(what)} ({", ".join(ids)})</div></div></li>')
    limits = [f'<li><b>{r["ID"]}</b> {strip_md(r["Title"])}: accepted limit</li>'
              for r in data if status_group(r["Status"]) == "Accepted"]
    unverified = re.findall(r"^\| ([^|]+?) \| ([^|]+?) \|$", text.split("## Validation items")[-1].split("## Change log")[0], re.M)
    limits += [f"<li>Not yet verified: {strip_md(i)}</li>" for i, _ in unverified if i not in ("Item", "---")
               and not i.startswith("-")]

    def scrub(t):  # old commit ids and CI run numbers no longer resolve
        t = re.sub(r"\s*\((?:tests|security-scan)[^)]*\)", "", t)
        t = re.sub(r"`?\b(?=[0-9a-f]*\d)[0-9a-f]{7}\b`?", "", t)
        return re.sub(r"\s+([:;,.])", r"\1", re.sub(r"\s{2,}", " ", t))

    log = re.findall(r"^\| (\d{4}-\d{2}-\d{2}) \| (.*) \|$", text, re.M)
    timeline = "".join(
        f'<li><time>{d}</time><span>{strip_md(scrub(t))[:260]}</span></li>' for d, t in reversed(log))
    open_items = [r for r in data if status_group(r["Status"]) == "Open"]
    alert = ""
    if open_items:
        alert = ('<div class="alert"><b>Still open:</b> ' + ", ".join(
            f'{r["ID"]} ({strip_md(r["Title"])})' for r in open_items) + "</div>")
    badge = lambda wf: (f'<a href="https://github.com/{REPO}/actions/workflows/{wf}">'
                        f'<img alt="{wf}" src="https://github.com/{REPO}/actions/workflows/{wf}/badge.svg?branch=main"></a>')

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>privacy-hybrid security dashboard</title>
<style>
:root{{color-scheme:light dark;--bg:#fff;--fg:#1f2328;--card:#f6f8fa;--line:#d0d7de}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--fg:#e6edf3;--card:#161b22;--line:#30363d}}}}
body{{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}}
main{{max-width:1040px;margin:0 auto;padding:24px 16px 48px}}
h1{{margin:0 0 4px}}h2{{margin:32px 0 12px;font-size:18px}}
.sub{{color:#6e7781;font-size:13px}}
.panel{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}}
.box{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}}
.box h3{{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:#6e7781}}
.donut{{display:flex;gap:16px;align-items:center}}
ul.legend{{list-style:none;margin:0;padding:0}}.legend li{{margin:4px 0}}
.legend i{{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:8px}}
.bar{{display:grid;grid-template-columns:80px 1fr 24px;gap:8px;align-items:center;margin:6px 0;font-size:13px}}
.track{{background:var(--line);border-radius:6px;height:12px;overflow:hidden}}.fill{{height:100%}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}}
.card{{background:var(--card);border:1px solid var(--line);border-left:6px solid;border-radius:8px;padding:12px}}
.top{{display:flex;justify-content:space-between;align-items:center}}
.pill{{color:#fff;font-size:11px;border-radius:99px;padding:2px 8px}}
.title{{margin:6px 0 2px;font-weight:600}}.meta{{font-size:12px;color:#6e7781;margin-top:4px}}
.note{{font-size:12px;margin-top:4px}}
.alert{{background:#ffebe9;color:#82071e;border:1px solid #ff8182;border-radius:8px;padding:10px 14px;margin:16px 0}}
@media(prefers-color-scheme:dark){{.alert{{background:#3d1115;color:#ffa198}}}}
ol.tl{{list-style:none;margin:0;padding:0;border-left:3px solid var(--line)}}
.tl li{{margin:0 0 12px;padding-left:14px;position:relative;font-size:13px}}
.tl li:before{{content:"";position:absolute;left:-8px;top:6px;width:11px;height:11px;border-radius:50%;background:#2da44e}}
.tl time{{font-weight:600;margin-right:8px}}
ul.ctl{{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:8px}}
.ctl li{{display:flex;gap:10px;align-items:flex-start;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px}}
.ck{{color:#fff;border-radius:50%;width:22px;height:22px;flex:none;text-align:center;line-height:22px;font-size:13px}}
ul.lim{{margin:0;padding-left:20px;font-size:13px}}
a{{color:#0969da}}
</style></head><body><main>
<h1>privacy-hybrid security dashboard</h1>
<div class="sub">Generated from <a href="https://github.com/{REPO}/blob/main/docs/security/REMEDIATION_TRACKER.md">REMEDIATION_TRACKER.md</a>.
Self-assessment by the owner, not an independent audit. {state}</div>
{alert}
<div class="panel" style="margin-top:16px">
<div class="box"><h3>Findings by status</h3><div class="donut">{donut([(k, groups[k]) for k in order], total)}<ul class="legend">{legend}</ul></div></div>
<div class="box"><h3>By severity</h3>{bars(sev, SEV_COLORS)}</div>
<div class="box"><h3>By priority</h3>{bars(prio, PRIO_COLORS)}</div>
<div class="box"><h3>CI (main)</h3>{badge("test.yml")}<br><br>{badge("security-scan.yml")}
<div class="meta">Checks: tests 3.11/3.13, static, lock, CodeQL, gitleaks, dependencies.</div></div>
</div>
<h2>What protects you</h2><ul class="ctl">{"".join(controls)}</ul>
<h2>Known limits</h2><ul class="lim">{"".join(limits)}</ul>
<h2>Findings</h2><div class="grid">{"".join(cards)}</div>
<h2>Timeline</h2><ol class="tl">{timeline}</ol>
<p class="sub">Deeper detail: <a href="https://github.com/{REPO}/tree/main/docs/security">docs/security</a>.</p>
</main></body></html>"""


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "_site")
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(build())
    print(f"wrote {out / 'index.html'}")
