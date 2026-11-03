"""Build the E2E report (markdown) from pytest output, browser results and the isolated audit log."""
import datetime, json, re, sys
pytest_txt, results_json, audit = sys.argv[1:4]
res = json.load(open(results_json))
summary = [l for l in open(pytest_txt).read().splitlines() if re.search(r"\d+ (passed|failed)", l)]
try:
    lines = [json.loads(x) for x in open(audit).read().splitlines() if x.strip()]
except OSError:
    lines = []
passed = sum(r["ok"] for r in res)
print(f"# End-to-end test report\n\nRun: {datetime.datetime.now():%Y-%m-%d %H:%M}. Fake data only; isolated server, config and audit log.\n")
print(f"**Browser E2E: {passed}/{len(res)} passed.** Unit/integration: `{summary[-1].strip('= ') if summary else 'n/a'}`.\n")
print("| Area | Check | Result | Detail |\n|---|---|---|---|")
for r in res:
    print(f"| {r['group']} | {r['name']} | {'PASS' if r['ok'] else '**FAIL**'} | {r['detail'].replace('|', '/')[:110]} |")
print(f"\nAudit log of the run: {len(lines)} entries, routes {sorted({str(l.get('route')) for l in lines})}. Counts only (checked: no SSN, name or remembered fact in it).")
print("\n## Not covered\n- Claude CLI route through the browser (needs the Claude CLI; covered by `scripts/live_claude_check.py`).\n- Web search route (needs SearXNG).\n- Packet-level capture of outbound traffic.\n- Real phone / LAN access.")
