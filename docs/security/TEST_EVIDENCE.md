# Test evidence

Assessment date: 2026-11-01. Baseline assessed commit (before any fixes; later state is in SECURITY_ASSESSMENT.md section 0 and the tracker): `40638c60c9286b65a231c3ac19ca3b5a5c6a2428` (public `main`, committed 2026-11-01 18:28 -0600). Private development commit used for the first runs: `229a6b9aec2ed62b633c5e9ed103dc1f28d52cd8` (private repository, not viewable by outside reviewers).

Rule applied throughout: a result is stated as passing only if I ran it in this session and saw the output. Anything else is listed under "Not run".

## 1. Environment

| Item | Value |
|---|---|
| Host | macOS 27.2 (build 26B123), Darwin 27.2.0, arm64 |
| Python used for all runs | 3.12.14, `.venv/bin/python` |
| System `python3` | 3.9.6 (not used) |
| Test runner | pytest 9.2.0 with pytest-xdist 3.8.0 (`-n auto`), as pinned in `requirements.txt` |
| Network | Tests use loopback mock servers; no external service was contacted by any check I ran |
| Installed distributions in the venv | 78 (`pip list --format=freeze`) |

Python 3.11 and 3.13 are in the CI matrix but were **not** available locally; their results come from CI only (section 4).

## 2. Local runs (executed in this session)

| # | Command (working directory = repo root unless stated) | Tree | Result |
|---|---|---|---|
| 1 | `.venv/bin/python -m pytest -q -n auto -rs --junitxml=<scratch>/junit.xml` | private `229a6b9`, clean worktree | **594 passed**, 0 failed, 0 errors, 0 skipped, 19.7 s (JUnit `time=19.468`) |
| 2 | `.venv/bin/python -m pytest tests/security -q -n auto -rs -p no:cacheprovider` | private `229a6b9` | **288 passed**, 0 failed, 0 skipped, 14.30 s |
| 3 | `git archive public/main \| tar -x -C <scratch>/pub`, then in that directory `…/.venv/bin/python -m pytest -q -n auto -p no:cacheprovider --junitxml=…` | exported public `main` `40638c6` | **594 passed**, 20.28 s |
| 4 | `.venv/bin/python -m compileall -q src scripts` | private `229a6b9` | exit 0 |

Notes
- Run 3 is the one that corresponds to the assessed commit. `git diff --stat 229a6b9 public/main` shows only `LICENSE`, `PLAN.md`, `PROGRESS.md` and `docs/THREAT-MODEL.md` differ, so runs 1 and 2 apply equally to source, tests, scripts, static files and workflows.
- The JUnit file for run 1 reports `tests=594 failures=0 errors=0 skipped=0`; 288 of those cases are under `tests/security`.
- Each run printed no skip list because nothing was skipped.

## 3. Targeted probes (executed; synthetic data only)

Each probe is a short Python script run with `.venv/bin/python -I` from the repo root against the source tree, writing only to a temporary directory under the session scratch area. No network is involved. The scripts are reproduced in appendix A so a reviewer can re-run them.

| Probe | Question | Observed | Finding |
|---|---|---|---|
| 1 | Does `policy.extreme()` work for the object type the scheduler holds? | Real `Account`, no `prefs.bin` → `False`; real `Account` with `prefs.bin`, Extreme off → `False`; scheduler-style `SimpleNamespace(id, folder)` with `prefs.bin` present → **`True`** | PH-007 |
| 2 | Does the detector mask UK/US addresses, passport lines, spelled SSN, CJK text? | `221B Baker Street, London NW1 6XE`: only `London` (PLACE, Tier 4), not masked. `1600 Pennsylvania Avenue NW, Washington, DC 20500`: masked. Passport line, spelled SSN, CJK sentence: no entities, not masked. Employer + DOB + name: masked | PH-002, PH-003 |
| 3 | Which passport phrasings are caught? | Caught: `passport number: C01X00T47`. Missed: `passport no. X1234567`, `my passport is X1234567`. Also caught: driver licence and EIN/tax ID phrasings tested | PH-001 |
| 4 | Can an older ciphertext undo Extreme privacy? Who becomes admin after deletion? Is plaintext cached? | After enabling Extreme: `True`; after writing the older `prefs.bin` bytes back: **`False`**, no error. Admin deleted → administrator became the *third-created* account `c`, not `b` (b changed password later). `rag._financial.cache_info().currsize == 1` after one call | PH-006, PH-013, PH-012 |

Mask results for the first survey (appendix A5) hit the 20 % "too much of the text is sensitive" guard because the strings were very short; the padded variants in probes 2 and 3 are the meaningful ones.

## 4. CI evidence (GitHub Actions, public repository)

Queried with `gh run list` / `gh run view` on 2026-11-01. I read the conclusions and job names. I did **not** open the job logs, so I did not independently confirm per-job test counts or bandit/gitleaks output; "success" means the job exit status.

| Workflow run | Commit | Result | Jobs (all `success`) |
|---|---|---|---|
| [tests 41367338310](a CI run) | `40638c6` | success | `test (3.11)`, `test (3.13)`, `static` (compileall + `bandit -ll`) |
| [security-scan 41367338205](a CI run) | `40638c6` | success | `gitleaks`, `codeql (python)`, `codeql (javascript-typescript)`, `dependencies` (`pip-audit -r requirements.txt`) |
| [tests 41365706428](a CI run) | `c6df2fa` (TLS key-identifier fix for Python 3.13) | success | same |
| [security-scan 41365706528](a CI run) | `c6df2fa` | success | same |

Repository state queried via the GitHub API: open code-scanning alerts 0; secret scanning disabled; one historical Dependabot alert (pytest, GHSA-6w46-j5rx-g56g, medium) in state `fixed`.

Workflow definitions: [`.github/workflows/test.yml`](https://github.com/hgharsha/privacy-hybrid/blob/main/.github/workflows/test.yml), [`security-scan.yml`](https://github.com/hgharsha/privacy-hybrid/blob/main/.github/workflows/security-scan.yml). The `tests` workflow runs `pytest tests/security` and then the whole suite on Python 3.11 and 3.13.

## 5. What the tests do and do not exercise

What they do:
- `tests/security` (288 cases) run with the production defaults: the local second-pass check required, review-before-send on, invitation-only registration (`tests/security/conftest.py` marks every such test `strict`). They capture what arrives at mock cloud and search servers over real loopback sockets.
- Covered areas by file name: admin locks, Extreme privacy, financial classification and summaries, HTTP limits, known-value leak check, local-only mode, lockdown script, multi-user isolation, network guard, PII policy, preview/approval, second pass, summary masking.

What limits their weight:
- Outside `tests/security`, `tests/conftest.py` switches the second pass off, the preview off and registration to open for older tests, so those 306 cases do not run the production defaults.
- The local second-pass "model" is a stub in tests. No test measures how often a real small model fails to catch a leak.
- The cloud endpoint in tests is an OpenAI-compatible mock on loopback; the Claude CLI subprocess path is covered by unit tests with fakes, not by a real CLI.
- The scheduler tests use a full `Account` object, not the object the real scheduler loop builds (see PH-007).
- At the baseline commit no test restored an older encrypted file (PH-006), exercised the lockdown script's trust path (PH-008), or covered non-US addresses and several passport phrasings (PH-001, PH-002). All but PH-008 were added in later rounds; PH-008 tests were added on 2026-11-02 (section 10). No test runs against a genuinely root-owned install.

## 6. Not run (so no claim is made)

| Item | Reason |
|---|---|
| `bandit`, `pip-audit`, `gitleaks`, `semgrep` locally | Not installed; installing tools was outside the rules of this task. CI reports success for bandit (`-ll`), pip-audit and gitleaks, unverified by me |
| Python 3.11 / 3.13 locally | Interpreters not available |
| Real Claude CLI, `scripts/live_claude_check.py`, `scripts/live_e2e.py` | Would send data to a third party and needs the owner's login |
| Real Ollama model quality, second-pass efficacy | No model run |
| macOS Keychain behaviour and access-control prompts | Tests use a dictionary backend |
| TLS to a real phone/browser, certificate trust flows | Not exercised |
| `scripts/lockdown.sh on` and `pf` behaviour | Needs root and an administrator dialog; also altering network filters is out of scope |
| Browser end-to-end scripts (`scripts/*.mjs`), accessibility, UI behaviour | Not run |
| Load, soak, fuzzing, memory-pressure tests | Not run (PH-009 is therefore inferred) |
| `scripts/mac_shell.swift` and the macOS app wrapper | Not reviewed in this assessment |
| `static/app.js` | Only searched for `innerHTML`, `insertAdjacent`, `eval`, `document.write` (no matches). Not read line by line |
| Transitive dependency vulnerability scan | Not run |
| Pen-test of a live instance | None performed |

## 7. Re-run after fixes (2026-11-01, executed in this session)

Tree: private commit `fdfa60323700c331adc910bcdb59af6e185e8ac1`, clean worktree after commit.

| # | Command | Result |
|---|---|---|
| 5 | `.venv/bin/python -m pytest -q -n auto` | **613 passed**, 0 failed, 18.76 s |
| 6 | `.venv/bin/python -m pytest -q -n auto tests/security` | **306 passed**, 0 failed, 13.88 s |
| 7 | `.venv/bin/python -m compileall -q src scripts` | exit 0 |
| 8 | Probes A1 to A4 from appendix A, extracted unchanged and run with `-I` | see below |

Probe results on the fixed tree:
- A1: `False`, `False`, `True` (unchanged; the scheduler now uses `schedule.scheduler_extreme`, covered by `tests/test_schedule.py::test_real_slot_account_runs_web_job_and_extreme_still_blocks`).
- A2: `221B Baker Street` ADDRESS and `NW1 6XE` ZIP masked; passport line raises `NeedsApproval`; spelled SSN and CJK sentence still undetected (PH-003).
- A3: `passport no. X1234567` and `my passport is X1234567` now GOVID Tier 1; `Reisepass Nr. C01X00T47` still only `PERSON`.
- A4: after restoring the older `prefs.bin`, `policy.extreme()` is `True` (was `False`); admin succession still goes to `c` (PH-013 open); plaintext cache still 1 entry (PH-012 open).

New regression tests: `test_pii_policy.py` (`test_id_phrasings_block_the_request`, `test_non_us_addresses_are_masked`, `test_passport_and_address_rules_leave_ordinary_text_alone`), `test_multiuser.py` (two first-account tests), `test_extreme_privacy.py` (`test_restoring_an_older_prefs_file_does_not_switch_extreme_off`), `test_schedule.py` (the scheduler test above).

CI on public `c5bd7d4`: [tests 41370411813](a CI run) and [security-scan 41370411807](a CI run) both concluded success (conclusion read via `gh run list`; job logs not read). A local run of the exported public tree also gave 613 passed. Not re-run locally: Python 3.11 and 3.13, bandit, pip-audit, gitleaks, and everything in section 6.

## Appendix A: probe scripts

Run each as `.venv/bin/python -I <file> <tmpdir>` from the repo root. They use only synthetic values.

<a id="a1"></a>
### A1. Probe 1: policy object types

```python
import sys, tempfile, pathlib
sys.path.insert(0, "src")
from types import SimpleNamespace
from privhybrid import accounts, policy
d = pathlib.Path(tempfile.mkdtemp(dir=sys.argv[1]))
st = accounts.Store(d / "users")
a = st.register("probe@example.com", "correct horse battery")
print("no prefs.bin:", policy.extreme(a))
policy.update(a, style="mac", theme="dark")                      # Extreme not set
print("real Account, prefs.bin present:", policy.extreme(a))
ns = SimpleNamespace(id=a.id, folder=a.folder)                   # what schedule.slots() returns
print("scheduler-style object:", policy.extreme(ns))
```

Observed: `False`, `False`, `True`.

<a id="a2"></a>
### A2. Probe 2: addresses, passport line, spelled SSN, CJK

```python
import sys; sys.path.insert(0, "src")
from privhybrid import detect as D
from privhybrid.vault import Vault, NeedsApproval
PAD = " The weather was mild and the report was short and clear." * 8
cases = {
 "uk_street": "Please mail it to 221B Baker Street, London NW1 6XE." + PAD,
 "us_street": "I live at 1600 Pennsylvania Avenue NW, Washington, DC 20500." + PAD,
 "passport":  "My passport no. X1234567 expires soon." + PAD,
 "ssn_words": "social security number: zero seven eight, zero five, one one two zero" + PAD,
 "cjk":       "昨天我见到了王小明，他住在北京市朝阳区。" + PAD,
 "emp_dob":   "Jane works at Acme Corp and was born March 3, 1985." + PAD}
for k, t in cases.items():
    d = D.detect(t)
    print(k, [(e.kind, e.tier, e.text) for e in d.entities], d.quasi)
    try: print("  masked:", Vault().mask(t)[0][:100])
    except NeedsApproval as e: print("  NeedsApproval:", e)
```

<a id="a3"></a>
### A3. Probe 3: passport and other ID phrasings

```python
import sys; sys.path.insert(0, "src")
from privhybrid import detect as D
for t in ["passport number: C01X00T47", "passport no. X1234567", "Passport # 123456789", "passport: 123456789",
          "my passport is X1234567", "Reisepass Nr. C01X00T47", "driver license D1234567",
          "driver's license number: D123-4567-8901", "EIN 12-3456789", "tax ID 12-3456789"]:
    d = D.detect(t + " " + "The weather was mild. " * 8)
    print(f"{t:40} -> {[(e.kind, e.tier) for e in d.entities]}")
```

Observed: the 1st, 3rd, 4th, 7th to 10th lines report a Tier 1 entity (the 3rd and 4th as `SSN`, because nine digits); `passport no. X1234567` and `my passport is X1234567` report `[]`; `Reisepass Nr.` reports only a `PERSON`.

<a id="a4"></a>
### A4. Probe 4: rollback, administrator succession, plaintext cache

```python
import sys, tempfile, pathlib, time
sys.path.insert(0, "src")
from privhybrid import accounts, policy, rag
base = pathlib.Path(tempfile.mkdtemp(dir=sys.argv[1]))
st = accounts.Store(base / "users")
a = st.register("admin@example.com", "correct horse battery")
policy.update(a, theme="dark");           old = (a.folder / "prefs.bin").read_bytes()
policy.update(a, extreme=True);           print("extreme on:", policy.extreme(a))
(a.folder / "prefs.bin").write_bytes(old); print("after restoring older file:", policy.extreme(a))
st.set_registration("open")
b = st.register("b@example.com", "correct horse battery"); time.sleep(0.05)
c = st.register("c@example.com", "correct horse battery"); time.sleep(0.05)
st.change_password(b, "correct horse battery", "another long password")
st.delete(a, "correct horse battery")
print("admin is b:", st.admin_id() == b.id, " admin is c:", st.admin_id() == c.id)
txt = "Date,Description,Amount\n" + "\n".join(f"2026-10-{1+i%27:02d},SHOP{i},-{20+i}.50" for i in range(12)) + "\n"
rag._financial("fin.csv", txt); print("cache entries:", rag._financial.cache_info().currsize)
```

Observed: `True`, `False`, `admin is b: False admin is c: True`, `cache entries: 1`.

<a id="a5"></a>
### A5. Initial detector survey

A 17-line survey of short strings (SSN, card, IBAN, phone, e-mail, names in several scripts, address, medical, account number, passport, date of birth) was run first. Tier 1 stops fired for dashed SSN, unlabelled SSN, test card number, IBAN, medical diagnosis and a labelled bank account; e-mail, phone, English names and date of birth were found as Tier 2. The misses it revealed (spelled SSN, CJK name, passport phrasing, UK street) were re-run in padded form as probes 2 and 3 because the unpadded masks tripped the 20 % rule.

## 8. Third round (public `b963e14`)

| Check | Result | Basis |
|---|---|---|
| Full suite, local | 622 passed | Run by me: `.venv/bin/python -m pytest -q -n auto` |
| CI | tests [41374810179] and security-scan [41374810181] succeeded; the dependency-graph job also succeeded | Run status read from GitHub; logs not read line by line |
| New regression tests | `test_signed_out_post_is_refused_before_the_body_is_read`, `test_sign_in_bodies_are_capped_small`, `test_many_addresses_guessing_one_account_hit_an_account_wide_delay`, `test_other_users_see_a_reduced_config`, `test_succession_is_stable_across_a_password_change`, `test_log_dir_is_private`, `test_no_document_text_is_cached_in_the_process` | Passed locally and in CI |
| Not exercised | Browser Settings dialog for a non-administrator; 20 real peers against one account (the counter is tested directly); behaviour of existing installs whose `logs/` already exists with a looser mode | |

[41374810179]: a CI run
[41374810181]: a CI run

## 9. Fourth round (public `aec65d4`)

| Check | Result | Basis |
|---|---|---|
| Full suite, local | 634 passed | Run by me |
| CI | tests [41376563928] and security-scan [41376564070] succeeded | Run status read from GitHub; logs not read line by line |
| New regression tests | PH-003 (`test_spelled_ssn_and_foreign_id_labels_block_the_request`, `test_ordinary_number_words_and_labels_are_left_alone`, `test_mostly_non_latin_text_is_not_sent_to_the_cloud`, `test_a_few_foreign_words_in_english_text_are_fine`), PH-011 (`test_old_scrypt_accounts_sign_in_and_are_upgraded`), PH-017 (`test_every_cited_threat_exists`), PH-019 (`test_audit_log_chain_shows_an_edited_line`) | Passed |
| Repository settings (PH-015) | Read back through the GitHub API after changing: secret scanning, push protection and Dependabot security updates enabled; required checks `test (3.11)`, `test (3.13)`, `static`, `lock` | Verified by reading the settings, not by triggering a blocked push |
| Not exercised | A real second-pass model on foreign-language text; the KDF upgrade interrupted by a crash; the new scrypt cost under many simultaneous sign-ins | |

[41376563928]: a CI run
[41376564070]: a CI run

## 10. Re-review 2026-11-02 (private tree `a64589b` plus an uncommitted change; nothing pushed)

| Check | Result | Basis |
|---|---|---|
| Repository state | Public HEAD `77a6166117d7d7f7c19b1afcccae6835cc3354fd`, private HEAD `a64589b`; latest application-code commit public `aec65d472e3c746a177568ce0f97bcd0ea7b3b5a` / private `fc02867`. Every commit after those is documentation-only. The PH-008 change below is in the private working tree only | `git log`, `git diff --stat` |
| Test-reference audit | Every `test_*` name cited in the five documents was checked against `def` lines under `tests/`. One was missing: `test_refuses_non_root_script` (cited for PH-008 but never written). It now exists | Scripted grep, run by me |
| Full suite, local | **641 passed** (634 before + 7 new), `pytest -q -n auto`, Python in `.venv`, macOS | Run by me; one earlier run of the lockdown file showed one failure caused by the change itself (the old test assumed the user-owned checkout would be accepted) and was corrected, see below |
| `tests/security/test_lockdown.py` | 14 passed (7 existing, 7 new) | Run by me |
| New PH-008 tests | The real checkout and a temp file are refused (real `lstat`, current user is not root); simulated root-owned chain accepted (control); writable parent, writable file, symlinked file, symlinked parent, non-root owner, missing file all refused; `osascript` is never started for an untrusted script and is started once for a trusted one; the server returns "Refused" and starts nothing | The root-owned case is simulated by patching `os.lstat`. No genuine root-owned install, no `osascript`, no `pfctl` was run |
| Existing test changed | `test_on_runs_only_the_fixed_script_with_the_macos_prompt` now patches `script_is_trusted` to true, because the real checkout is (correctly) refused | Changed deliberately; the fixed-path and ignored-user-name assertions are unchanged |
| bandit / pip-audit | **Not run.** bandit is not installed in the local environment; pip-audit was not run; CI results for these were not read | Stated, not assumed |
| CI on the changed code | Public `9a8233e`: `static`, `lock`, security-scan passed; **`test (3.11)` and `test (3.13)` failed** on `test_refuses_script_when_any_parent_is_group_or_world_writable`: the control case read the CI runner's real (group-writable) temp-folder modes. This was a defect in the test, not in `script_is_trusted`; the test now clears the real group/other write bits before applying the simulated ones. Re-run result is recorded in the next row once CI reads it | Read from GitHub run logs |
| PH-020 | No network capture made; no real CLI run | Procedure in FINDINGS.md |


## 11. PH-008 real-install test (owner-run, 2026-11-02, macOS)

| Check | Result | Basis |
|---|---|---|
| Root-owned copy at `/usr/local/ph008` (root:wheel, go-w) | `script_is_trusted` returned **True** | Owner ran it at 11:15 CST |
| User-owned checkout (`~/projects/privacy-hybrid`) | **False** (refused, as intended) | Owner ran it at 11:16 CST |
| Same copy with `scripts/` made group/world-writable | **False** | Owner ran it at 11:16 CST, then restored the mode |
| Not tested | The full `osascript` administrator-prompt path and `lockdown.sh` itself were not run; only the trust check was exercised on a real filesystem | Stated, not assumed |

## 12. PH-020 network capture (owner-run, 2026-11-02, macOS, Claude CLI 2.1.316, mitmproxy)

| Check | Result | Basis |
|---|---|---|
| Canaries planted | User memory line in `~/.claude/CLAUDE.md` (backed up and restored), a file named `CANARY-FILENAME-8b05.txt` in `~`; prompt marker on stdin | Settings-file canary skipped so a running session was not affected |
| App configuration, first run | `CANARY-USERMEM-7f3a`: 0, `CANARY-FILENAME-8b05`: 0, prompt marker: 1 (in the message request only) | Owner ran it; I read the saved text |
| Hosts, first run | `api.anthropic.com`, `mcp-proxy.anthropic.com`, `http-intake.logs.us5.datadoghq.com` (third-party log service), MCP registry paths | Telemetry bodies carried device/account IDs and platform data, not prompt text |
| Fix | `CLAUDE_FIXED_ENV` (public `0a59120`) | Test in `test_network.py` |
| Re-capture with opt-outs | Canaries 0, prompt marker 1, `datadoghq`: 0, `event_logging`: 0 | Owner ran it |
| Hostnames in the second output | `calendar`, `drive`, `gmail` MCP hosts, `claude.com`, `gstatic.com`, `iana.org` also matched | **Not verified** whether these were requests or text inside response bodies; the file was deleted before I could check |
| Positive control | **Not saved** (the control capture file was missing) | The capture does show prompt text in plain form, so it can read bodies, but the CLI reading `CLAUDE.md` without `--setting-sources ""` was not shown |
| Raw recordings | Deleted by the owner; they held account identifiers | Not kept |

## 13. bandit and pip-audit (run by me, 2026-11-02, local)

| Check | Result | Basis |
|---|---|---|
| `bandit -r src` | 0 High, 0 Medium, 12 Low. Low items: subprocess imports and calls (B404, B603: fixed argument lists, no shell), `try/except/pass` (B110, B112), empty-string password defaults in `ingest.py` (B107, not credentials), and `xml.etree` (B405) | One item read in source: `ingest.py` refuses any XML containing `<!DOCTYPE` or `<!ENTITY` before parsing, so entity expansion is not possible; the others were not individually reviewed |
| `pip-audit -r requirements.lock --no-deps --disable-pip` | No known vulnerabilities found | Advisory database as of the run; tool warned that hashes were not verified in this mode |
| Not covered | Transitive packages not in the lock; vulnerabilities not yet published | Stated, not assumed |

## 14. PH-020 final captures (owner-run, 2026-11-02, macOS, Claude CLI 2.1.316, mitmproxy, `scripts/ph020_capture.sh`)

| Check | Result | Basis |
|---|---|---|
| Method | Two runs per capture: the app's exact setup, and a control without `--setting-sources ""`; canaries planted in the private config folder's `CLAUDE.md` and as a file name in `$HOME`; raw recordings deleted, only counts and hostnames kept | Script prints and saves a summary |
| Capture 2 (private config folder, telemetry opt-outs) | App run: canaries 0, prompt marker 1, `datadoghq` 0, `event_logging` 0. Control: user-memory canary **1** (valid). Hosts requested: `api.anthropic.com` (GET and POST), `mcp-proxy.anthropic.com` (5 POST) | The `mcp-proxy` calls are the account's claude.ai connectors; whether any carried the prompt was not checked |
| Fix | No MCP servers, `ENABLE_CLAUDEAI_MCP_SERVERS=false` (public `3c24d3c`) | Test in `test_network.py` |
| Capture 3 (final) | App run: canaries 0, prompt marker 1, `datadoghq` 0, `event_logging` 0, `mcp-proxy` 0. Control: user-memory canary 1 (valid). Hosts requested in each run: **one POST to `api.anthropic.com`** | Owner ran it at 14:54 |
| Earlier, superseded | The 11:29 capture on the owner's real config folder found telemetry to a third-party log service | Section 12 |
| Not tested | Settings-file canary (skipped to avoid touching live settings); behaviour if the private config folder is missing (the code then uses the old setup, covered by a unit test only) | Stated, not assumed |

## 15. Maybe-sensitive warning tier (run by me, 2026-11-02, local)

| Check | Result | Basis |
|---|---|---|
| Full suite | **650 passed** (646 + 4 new), `pytest -q -n auto` | Run by me |
| Detector | `watch_flags` flags spelled-out digit runs of six or more, unmasked numbers of nine or more digits, and nine sensitive words/phrases; clean prose and masked text are not flagged | `test_watch_flags_marks_what_the_filter_cannot_mask` |
| Server | Flagged text shows the preview even with Review off; "no" sends nothing; a plain "yes" without the second confirmation sends nothing; ordinary text with Review off is not interrupted | three tests in `tests/security/test_preview.py`, against the mock cloud service |
| Browser dialog | `node --check static/app.js` passed; **the dialog itself was not clicked through in a browser** | Stated, not assumed |
| Not covered | Scheduled jobs (no one to ask); false negatives of the heuristic | Documented in SECURITY.md and FINDINGS.md |
