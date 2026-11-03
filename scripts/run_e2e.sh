#!/bin/sh
# Full automated test run: unit tests + isolated server + browser end-to-end. Writes E2E-REPORT.md.
# Needs: .venv, Ollama running (gemma4:26b, nomic-embed-text), Chrome, playwright-core (set PW=<path to index.mjs>).
# Uses a temp data dir, temp config and temp audit log: your real accounts, state/config.json and logs are untouched.
set -u
cd "$(dirname "$0")/.."
PW="${PW:-playwright-core}"; export PW
T=$(mktemp -d); export CFG="$T/config.json" RESULTS="$T/results.json" BASE=http://127.0.0.1:8799
echo '{}' > "$CFG"
.venv/bin/python -m pytest -q -p no:cacheprovider 2>&1 | tee "$T/pytest.txt" | tail -3
PYTHONPATH=src .venv/bin/python - "$T" <<'PY' &
import sys, pathlib
from privhybrid import config, server
t = pathlib.Path(sys.argv[1]); config.CONFIG_FILE = pathlib.Path(str(t / "config.json"))
server.serve(port=8799, data_dir=str(t / "users"), audit_path=str(t / "audit.jsonl")).serve_forever()
PY
SRV=$!
echo "warming up the local model..."; curl -s -m 600 localhost:11434/api/generate -d '{"model":"gemma4:26b","prompt":"hi","stream":false,"options":{"num_predict":1}}' >/dev/null
for i in 1 2 3 4 5 6 7 8 9 10; do curl -s -o /dev/null $BASE/ && break; sleep 1; done
node scripts/e2e_suite.mjs; RC=$?
kill $SRV 2>/dev/null
.venv/bin/python scripts/make_report.py "$T/pytest.txt" "$RESULTS" "$T/audit.jsonl" > E2E-REPORT.md
echo "report: E2E-REPORT.md (exit $RC)"; exit $RC
