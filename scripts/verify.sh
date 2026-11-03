#!/bin/sh
# One-command verification of the threat-model controls (fake data only). Run from the project root.
set -e
cd "$(dirname "$0")/.."
.venv/bin/python -c "import pytest, xdist" 2>/dev/null || .venv/bin/pip install --quiet -r requirements-dev.txt  # test tools are not part of the runtime install
echo "== 1. All tests (detector, vault, egress, corpus, pipeline, server, intake) =="
.venv/bin/python -m pytest -q -n auto
echo "== 2. No planted value in logs/ =="
PYTHONPATH=tests .venv/bin/python - <<'PY'
import glob, re, corpus as C
data = "".join(open(f).read() for f in glob.glob("logs/*"))
needles = [re.sub(r"^(DOB: |username: |check #)", "", v) for v in C.TIER2_VALUES + C.TIER3_VALUES + list(C.DICTIONARY)] + ["123-45-6789", "Delgado"]
leaks = [n for n in needles if n in data]
assert not leaks, f"LEAK in logs: {leaks}"
print("clean:", len(data.splitlines()), "log lines scanned")
PY
echo "== 3. Server is not reachable from the LAN =="
if lsof -iTCP:8765 -sTCP:LISTEN -P 2>/dev/null | grep -q '\*:8765'; then echo "FAIL: listening on all interfaces"; exit 1; fi
echo "ok (not bound to all interfaces)"
echo "== 4. Placeholder map is not on disk =="
if grep -rIl "PERSON_1\]" state 2>/dev/null | grep -q .; then echo "FAIL: placeholders found in state/"; exit 1; fi
echo "ok"
