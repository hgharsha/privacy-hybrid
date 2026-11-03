# Plan: independent security re-review (saved 2026-11-02, not started)

Source: an external prompt asking for a fresh review, a corrected SAR and a final PASS/FAIL decision. My assessment: about half repeats existing work; the rest is worth doing in a trimmed form. Nothing here is approved or done yet.

## Ground rules
- Local branch only (e.g. `sar-rereview`). No push, no force-push, no GitHub settings changes.
- Synthetic data only. Do not claim a test passed unless it was run. Keep verified / inferred / unverified separate.
- Run the adversarial pass in a fresh subagent so it is not anchored on earlier conclusions. Note in the report that it is still the same model family, so not truly independent.

## Step 1: docs consistency (small, ~1 hour) — recommended
Known errors to fix:
- `docs/security/REMEDIATION_TRACKER.md` header says "Thirteen findings are Closed" but lists 14 IDs.
- Tracker says assessed commit `40638c6`; the fixes landed later (public `4dbb63e`, private `5a5bf13` at last check).
- Check the other four SAR docs and `docs/SECURITY.md` for the same drift (SHA, counts, stale CI run IDs, status differences).
Deliverable: one assessed SHA, a separate line for later docs-only commits, counts that match the table.

## Step 2: fresh evidence run (medium) — recommended
- Record exact commit, Python versions, commands, pass/fail and test counts.
- `.venv/bin/python -m pytest -q -n auto` on 3.11 and 3.13.
- Confirm which scanners CI really runs (gitleaks, codeql, dependencies, static, lock). Check whether bandit and pip-audit are configured. If not, run once locally and label "run locally, not in CI", or list as not run.
- Read the actual scan results; do not report clean from a green tick alone.
- Re-read public branch protection via API (read-only).

## Step 3: adversarial pass and new tests (largest) — optional
- PH-008: trace `scripts/lockdown.sh` install path, writability of parent dirs, symlink/path swaps, whether ownership is checked right before the privileged run. Decide OPEN / PARTIAL / FIXED; if still credible, recommend disabling the feature.
- PH-020: trace what the Claude CLI receives (stdin, cwd, CLAUDE.md, plugins, MCP, env). Write a runbook for the owner: throwaway macOS user, intercepting proxy, synthetic data only. Cannot be run by the assistant.
- PH-003: test Latin, non-Latin, mixed, transliterated, short snippets, threshold edges. State plainly it is a refusal guard, not multilingual PII detection.
- PH-019: tests for edit, middle delete, reorder, bad append, truncation, full rewrite. Expect truncation and full rewrite to go undetected (no external anchor). Document as tamper evidence only.
- Re-check every Closed finding against code and tests; reopen any that are unsupported.

## Step 4: decision and remediation plan — recommended
- Final outcome (PASS / CONDITIONAL PASS / FAIL / INSUFFICIENT EVIDENCE) with reasons; suitability for local use, real financial data, cloud features, privileged macOS features.
- P0–P3 table: finding, file, attack scenario, fix, regression test, acceptance criteria, safe to do now?
- External audit scope recommendation.
- Expected result: CONDITIONAL PASS again, unless the PH-008 trace finds something worse.

## Owner-only items (assistant cannot do)
- PH-020 network capture.
- Keychain ACL test on a second user.
- `pf` lockdown test: `sudo -u <user> curl -m 5 https://example.com` should time out.
- Any truly independent audit.

## Review commands when done
- `git log --oneline main..sar-rereview`
- `git diff main..sar-rereview --stat`
- `.venv/bin/python -m pytest -q -n auto`
