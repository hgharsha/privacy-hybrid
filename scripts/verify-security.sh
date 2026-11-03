#!/bin/sh
# Run before pushing: secret scan of the full git history, dependency advisories, bandit, and the security tests.
#   brew install gitleaks        (once; or download from https://github.com/gitleaks/gitleaks/releases)
#   .venv/bin/pip install bandit pip-audit
# Nothing is uploaded except package names and versions sent to the PyPI advisory service by pip-audit.
set -u
cd "$(dirname "$0")/.."
status=0
echo "== gitleaks (full history, values redacted) =="
if command -v gitleaks >/dev/null 2>&1; then gitleaks detect --source . --redact --exit-code 1 || status=1
else echo "gitleaks not installed: FAILED (install it, then re-run)"; status=1; fi
echo "== security tests, dependency audit, bandit =="
sh scripts/security_check.sh || status=1
[ "$status" = 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED OR WERE SKIPPED"
exit $status
