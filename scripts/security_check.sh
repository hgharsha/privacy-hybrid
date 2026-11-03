#!/bin/sh
# Security checks in one command. Runs the security tests, then static analysis and a dependency audit if those tools are installed.
#   scripts/security_check.sh            tests only, plus bandit / pip-audit when present
#   pip install bandit pip-audit         (in a throwaway venv is fine; they are not project dependencies)
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
status=0
echo "== security tests =="
$PY -m pytest tests/security -v -q || status=1
echo "== full test suite =="
$PY -m pytest -q -n auto || status=1
if $PY -c "import bandit" 2>/dev/null || command -v bandit >/dev/null 2>&1; then
  echo "== bandit (medium and above) =="
  (command -v bandit >/dev/null 2>&1 && bandit -q -r src -ll) || $PY -m bandit -q -r src -ll || status=1
else
  echo "== bandit not installed: skipped =="
fi
if $PY -c "import pip_audit" 2>/dev/null || command -v pip-audit >/dev/null 2>&1; then
  echo "== dependency audit (sends package names and versions to the PyPI advisory service) =="
  (command -v pip-audit >/dev/null 2>&1 && pip-audit -r requirements.txt --progress-spinner off) || $PY -m pip_audit -r requirements.txt --progress-spinner off || status=1
else
  echo "== pip-audit not installed: skipped =="
fi
exit $status
