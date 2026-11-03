# Security assessment: Privacy Hybrid

| | |
|---|---|
| Repository | [`hgharsha/privacy-hybrid`](https://github.com/hgharsha/privacy-hybrid) (public, production) |
| Baseline assessed commit (before fixes) | `40638c60c9286b65a231c3ac19ca3b5a5c6a2428`, `main`, 2026-11-01 18:28 -0600 |
| Also run against | private development commit `229a6b9aec2ed62b633c5e9ed103dc1f28d52cd8` (same `src/`, `tests/`, `scripts/`, `static/`, `.github/`; four non-code files differ) |
| Assessment date | 2026-11-01 |
| Latest code state | public `aec65d472e3c746a177568ce0f97bcd0ea7b3b5a`, private `fc02867`. Latest public HEAD `77a6166117d7d7f7c19b1afcccae6835cc3354fd` (private HEAD `a64589b`). Every commit after the code state (public `d51ea35`, `4dbb63e`, `77a6166`; private `a99b9ec`, `5a5bf13`, `c16f0a2`, `a64589b`) is **documentation-only**. A later local, uncommitted, unpushed change adds a PH-008 check (`lockdown.py`, `server.py`, tests); it is not part of any commit above. See the final decision at the end of section 0. |
| Assessor | The project's AI coding assistant (Claude), working at the repository owner's request |
| Companion documents | [THREAT_MODEL.md](THREAT_MODEL.md), [FINDINGS.md](FINDINGS.md), [TEST_EVIDENCE.md](TEST_EVIDENCE.md), [REMEDIATION_TRACKER.md](REMEDIATION_TRACKER.md) |

**This is not a certification and not an independent third-party audit.** It was produced by the same AI assistant that helped build the project, for the owner, in a single working session. It has the blind spots of that arrangement. Independent reviewers should treat it as a map of where to look and what was actually executed, and should re-run the checks in [TEST_EVIDENCE.md](TEST_EVIDENCE.md).

The baseline assessment (sections 1 to 9 below) changed no application source. A re-assessment after the first round of fixes is in **section 0**; sections 1 to 9 describe the baseline commit `40638c6` and are kept unchanged for comparison.

## 0. Re-assessment after fixes (2026-11-01)

| | |
|---|---|
| Re-assessed commit | private development commit `fdfa60323700c331adc910bcdb59af6e185e8ac1` (fixes on top of `229a6b9`). Now on public `main` as `c5bd7d4`; CI (test 3.11 and 3.13, static, gitleaks, CodeQL, dependencies) succeeded: [tests](a CI run), [security-scan](a CI run). |
| What changed | Five findings fixed with regression tests: PH-001, PH-002, PH-004, PH-006, PH-007 |
| Evidence | [TEST_EVIDENCE.md](TEST_EVIDENCE.md) section 7 |

Verified by execution on `fdfa603` (Python 3.12.14, macOS arm64):
- Full suite 613 passed, 0 failed, 0 skipped; security suite 306 passed (baseline 594 and 288; the 19 added tests are the regression tests).
- The original probes A1 to A4 were re-run unchanged. Passport phrasings (`passport no. X1234567`, `my passport is X1234567`) now stop the request; `221B Baker Street` and the UK postcode are masked; restoring an older `prefs.bin` leaves Extreme privacy on; a scheduler-style account reads the Extreme setting through the new sealed copy (unit-level, not a full scheduler tick).
- Probe A1 still prints `True` for `policy.extreme()` on a scheduler-style object. That is expected: the scheduler no longer calls it; it calls `schedule.scheduler_extreme()`.

Second round (public `fa6bb6a`, CI green: tests 41371210194, security-scan 41371210217): PH-005 Closed (network binds need HTTPS unless `PRIVHYBRID_ALLOW_HTTP=1`); PH-014 mostly fixed (hash-locked `requirements.lock`, pinned spaCy model, SHA-pinned Actions, CI drift check). PH-008 deliberately left open. The pip-audit run on the lock succeeded in CI but its output was not read.
Third round (public `b963e14`): PH-009 (sign-in bodies capped at 16 KiB, other signed-out POSTs refused before the body is read), PH-010 (account-wide limit of 20 failed sign-ins a minute; a LAN host can use it to block one account's sign-in for up to a minute), PH-012 (cache removed), PH-013 (creation time kept across password changes), PH-018 (reduced config for non-admins), PH-019 (log directory 0700 only), PH-014 remainder (test tools moved out of the runtime requirements). New and changed tests: 622 pass locally and in CI. PH-010 and PH-018 were tested at component or API level only, not in a browser.

Fourth round (public `aec65d4`): PH-003 (number-word SSNs, ID labels in five languages, cloud send refused for mostly non-Latin text), PH-011 (per-account scrypt parameters, 64 MiB, upgrade at sign-in), PH-015 (secret scanning, push protection, Dependabot security updates, correct required check names), PH-017 (threat model synced, doc-consistency test), PH-019 (audit-log hash chain). 634 tests pass locally and in CI.
Status after the fourth round (public `aec65d4`, CI green: tests 41376563928, security-scan 41376564070): 14 findings Closed (PH-001, 002, 004, 005, 006, 007, 009, 010, 011, 012, 013, 014, 017, 018), 3 mostly fixed (PH-003, 015, 019), 1 Accepted, 2 not closed: PH-008 (Medium, left open on purpose) and PH-020 (needs the owner). The verdict stays CONDITIONAL PASS: the second-pass model quality, Keychain ACLs, the `pf` lockdown and the Claude CLI traffic are still unverified, and this is still a self-check by the assistant that wrote the fixes.

Residuals and new caveats from the fixes themselves:
- PH-004: protects only when the request arrives from a non-loopback address. A reverse proxy on the same Mac would look like loopback; the docs say not to proxy the app.
- PH-006: the high-water mark lives next to, not inside, the account folder. Restoring the whole data folder together with the marker file still rolls the setting back. Not a monotonic hardware counter.
- PH-007: the scheduler's copy is stamped against `prefs.bin`; if Extreme is changed while the Keychain is unavailable, scheduled web jobs stay blocked until the next sign-in. Fails closed.
- PH-002: the new address and postcode rules are regex heuristics checked against a handful of phrasings, not a multi-country corpus. The recommended corpus test (REMEDIATION_TRACKER) is not written.
- The fixes were written and tested by the same assistant that wrote the assessment.

**Conclusion after re-assessment: still CONDITIONAL PASS.** No Critical or High finding was present before or after. The detection gaps (PH-001/002), rollback (PH-006), scheduler defect (PH-007), plain HTTP (PH-005) and dependency pinning (PH-014) are closed in code with green CI. What keeps it from PASS: PH-008 (open), PH-020 and the other unverified claims, and the fact that this is a self-check by the assistant that wrote the fixes.

### Final decision (2026-11-02, second look; tests re-run locally, CI and scanners not re-run)

Evidence: code re-read for PH-008 and PH-020; the full suite was run locally on the working tree (641 passed, see [TEST_EVIDENCE.md](TEST_EVIDENCE.md) section 10). bandit and pip-audit were not run. The review is still not independent: it was done by the same assistant that made the fixes.

**Outcome: CONDITIONAL PASS** (not PASS, because two findings are accepted limits and other validations are not done; not FAIL, because no Critical or High finding exists and the core controls behaved as designed; not INSUFFICIENT EVIDENCE overall, only for the four specific claims in section 5).

Finding counts, identical in all five documents: **18 Closed** (PH-001, 002, 004, 005, 006, 007, 008, 009, 010, 011, 012, 013, 014, 015, 017, 018, 019, 020), **0 mostly fixed**, **2 Accepted** (PH-003, PH-016), **0 Open**. Updated 2026-11-02 after the PH-008 real-install test and the PH-020 capture.

- **Safe for local use:** one owner or a trusted household, loopback or HTTPS LAN, review-before-send on, local model. Acceptable for real financial or personal data on that basis, with the caveat that detection is regex plus an unmeasured second-pass model: a strong filter, not a guarantee.
- **Cloud features (restrict):** keep to masked text with the Tier 1 block and review-before-send on. Non-Latin names and addresses are refused, not masked (PH-003). Treat the **Claude CLI path as unvalidated**: the code requests no tools, no session persistence, no setting sources, an empty working directory and a five-variable environment, but what the CLI actually puts on the wire has not been captured (PH-020). Prefer the Anthropic API path, whose request is built by this code, until PH-020 is captured.
- **Privileged macOS lockdown (PH-008):** keep unused. The script and its parents were owned by the app user and nothing checked that before running it as root. A local check now refuses that (tested with simulated ownership, not merged, not tested on a real root-owned install), which in practice disables the in-app button; use the terminal step with `sudo` yourself.
- **Must be validated before broader deployment (other users or machines):** a measured miss rate for the second-pass model; Keychain ACL test; `pf` test; reading the pip-audit and bandit output; an external audit.
- **Needs an external audit:** the PII detection and masking pipeline, the egress guard and Claude CLI path, key handling (scrypt, AES-GCM, Keychain), and the installer and lockdown scripts.

| Priority | Finding | Component | Attack scenario | Fix | Regression test and acceptance | Safe now? |
|---|---|---|---|---|---|---|
| P1 | PH-008 | `scripts/lockdown.sh`, `lockdown.py` | A process running as the app user replaces the script before it is run as root | Check written locally (owner root, no symlink, not group/world-writable, script and all parents, immediately before the run). Still to do: merge it, and an install layout under a root-owned path | `test_refuses_non_root_script` (exists, passes) and six more; acceptance: a user-writable script is never executed as root, shown once on a real root-owned install | Yes: the check; the install layout needs your decision |
| P1 | PH-020 | `providers.py` Claude CLI path (`_chat_claude_cli`) | Unknown whether the CLI adds user-level memory, plugins, environment or telemetry beyond the preview (not established either way) | Owner-run capture on a disposable macOS user and account with synthetic canaries (procedure in FINDINGS.md PH-020); if extra content is found, change the invocation or use the API path | A recorded capture; acceptance: every outbound byte maps to the preview | Needs the owner |
| P2 | PH-003 | `detect.py`, `egress._recheck_masked` | Name or address in a non-Latin script, below the 10% share threshold, is sent in clear | Per-script NER, or refuse any non-Latin letters near a Tier 2 cue | Corpus test with short snippets and threshold edges | Larger change, plan it |
| P2 | PH-019 | `egress.AuditLog` | An attacker with file access truncates the log or rewrites the whole chain; this is not detected | Periodic checkpoint of the last hash kept elsewhere; run `verify_chain` at start-up; rotation | Truncation and rewrite tests; acceptance: both are detected against a checkpoint | Yes, small |
| P2 | PH-015 | GitHub settings | Compromised owner token pushes straight to `main` (admin bypass) | Require review or signed commits, or accept the risk for a single-owner project | Settings read-back | Settings change needs your approval |
| P3 | PH-014 residual | `requirements.lock`, Dependabot | Dependabot bumps conflict with the hash lock | Regenerate the lock in the same PR | CI `lock` job | Yes |
| P3 | Validation | pip-audit, second-pass model, Keychain ACL, `pf` | CI ran pip-audit but the output was not read; the others were never measured | Read the pip-audit output; run the labelled corpus and the manual tests | Results recorded in TEST_EVIDENCE.md | Partly owner-run |
| P3 | PH-002, 006, 007 | `detect.py`, `policy.py`, `schedule.py` | Residuals listed above | Address corpus, whole-folder restore marker, Keychain-down case | One test each | Yes, each small |

## 1. Executive summary

Privacy Hybrid answers questions about a household's documents with a local model and, only when the user chooses, sends masked text to a cloud model or a generic query to a local web-search proxy. The design is unusually conservative for a project of this size: one outbound code path, fail-closed checks, per-account encryption at rest, a preview the user must approve before any cloud send, and a test suite that runs the security tests with production defaults.

What I did: read the Python source (about 5,150 lines in `src/privhybrid`), the installer and lockdown scripts, the CI workflows and the project's security documents; ran the full test suite on the assessed tree (594 passed, 0 failed, 0 skipped) and the 288 security tests separately; wrote and ran four small probes against the code with synthetic data; and queried GitHub for CI and repository settings.

What I found: **no Critical or High finding.** Twenty findings are recorded: seven Medium, nine Low, three Informational and one that needs validation. The Medium ones fall into four themes:

1. **Detector gaps in the control that decides what is masked** (PH-001 passport phrasings, PH-002 non-US addresses). Verified by execution.
2. **Integrity of the stored privacy policy** (PH-006). An older encrypted file restored from backup, or written by a process without the password, silently turns Extreme privacy off. Verified by execution.
3. **Deployment defaults** (PH-004 no setup token, PH-005 plain HTTP on a LAN bind, PH-008 a root-run script in a writable path).
4. **Supply chain** (PH-014).

Separately, PH-007 (Low) is a functional defect worth the owner's attention: the background scheduler cannot read the Extreme-privacy setting, so scheduled **web** jobs probably cannot run for any account that has saved a preference. It fails closed, so it is not a leak, but it contradicts the documented scheduled-web behaviour (and what was discussed with the owner earlier in this project).

## 2. Overall security posture

**Good for its stated use**: a single owner or small trusted household, reached over loopback or an HTTPS LAN link, with the Claude route reviewed by the user each time. The central design choices are sound and, where I could test them, they held.

**Not yet adequate** for any of these without the fixes listed in section 7: a LAN install on an untrusted network, reliance on Extreme privacy as an integrity-protected switch, or reliance on the PII detector as the sole barrier for non-US data. The detector is probabilistic by nature; the project says so, and I confirmed it.

## 3. Review coverage

| Area | Examined | Method | Outcome |
|---|---|---|---|
| Financial classification and ingestion | `ingest.py`, `finance.py`, `rag.py`, `pipeline.py` | Read; security test results; no new probes beyond cache check | Classification at intake before chunking; summaries without rows; scheduled jobs cannot send financial material. Heuristic, so a financial document with unusual layout may fall back to the generic path. PH-012 |
| PII detection and sanitisation | `detect.py`, `vault.py`, `egress.py` `_prepare`, `local.py` | Read; probes 2, 3, A5 | Strong on US formats, checksums, labelled Tier 1 values. Gaps found: PH-001, PH-002, PH-003 |
| Local storage, encryption, keys | `accounts.py`, `keystore.py`, `sealed.py`, `policy.py` | Read; probe 4 | AES-GCM with filename AAD, scrypt, atomic writes, locks, rekey rollback. No rollback detection (PH-006), modest KDF cost (PH-011), plaintext cache (PH-012) |
| Cloud egress and approval | `egress.py`, `providers.py`, `server.py` chat/approve, `pipeline.py` | Read; `tests/security/test_preview.py` read; tests run | Preview, decline, timeout, stop and cross-session isolation behaved as designed in tests. Claude CLI content beyond stdin unconfirmed (PH-020) |
| Extreme Privacy and OS isolation | `policy.py`, `egress.py`, `lockdown.py`, `scripts/lockdown.sh` | Read; probes 1, 4; lockdown script not executed (PH-008 trust check unit-tested with simulated ownership) | Re-read on every send; unknown means on. PH-006, PH-007, PH-008, PH-016 |
| Multi-user isolation and authorisation | `accounts.py`, `server.py` | Read; tests run | Per-account keys and state; permissions re-read per request; admin cannot read others' files. PH-013, PH-018 |
| Administrator permissions and transfers | `accounts.transfer_admin`, `server._admin` | Read; tests run | Transfer re-authenticates and is atomic under the store lock. PH-013 |
| Cross-process locking, concurrency | `filelock.py`, `accounts.save`, `server.Shared` | Read; tests run | Advisory `flock` with timeouts, fixed lock order, versioned writes. Windows has thread-level locking only (documented) |
| Scheduled tasks and background processing | `schedule.py`, `sealed.py`, `keystore.py` | Read; probe 1 | Sealed results, MAC, replay counter, no cloud mode. PH-007 |
| API authentication and authorisation | `server.py` | Read | Cookie sessions, CSRF header and Origin check, Host check, per-path permissions. PH-009, PH-010, PH-018 |
| Logging, telemetry, error handling | `egress.AuditLog`, `activity.py`, `server.py` | Read; file modes checked | No telemetry code found. Audit log has counts only. PH-019 |
| Dependency and supply chain | `requirements.txt`, installer, workflows, `pip list` | Read; counts; GitHub API | PH-014, PH-015 |
| CI workflows and test coverage | `.github/workflows/*`, `tests/` | Read; CI conclusions queried; tests run | CI runs tests on 3.11/3.13, CodeQL, gitleaks, pip-audit, bandit. Logs not read. See TEST_EVIDENCE section 5 for what tests do not cover |
| Installation, deployment, configuration | `scripts/install.py`, `config.py`, `tls.py`, docs | Read | Sensible defaults (loopback, 0600 files, generated TLS CA with discarded key). PH-004, PH-005 |

Not reviewed in depth: `scripts/mac_shell.swift`, the app wrapper, `static/app.js` beyond a pattern search, browser end-to-end scripts, the speech model path.

## 4. Verified behaviours

"Verified" means I ran the check and saw the result on this commit. These are observed behaviours of this code, not guarantees.

1. The complete suite (594 tests) and the security suite (288) pass on the assessed tree with Python 3.12.14 and no skips ([TEST_EVIDENCE.md](TEST_EVIDENCE.md) section 2).
2. With the default configuration, a cloud send does not occur until the user approves a preview; "no", a timeout and Stop each send nothing; one session cannot answer another's approval (`tests/security/test_preview.py`, run).
3. Financial material is previewed even when review-before-send is off, and a job with no way to ask never sends it (same file, run).
4. With Extreme privacy on, an approved preview still sends nothing (same file, run).
5. The detector stops dashed and bare SSNs, a test card number, an IBAN, a labelled bank account and a medical diagnosis as Tier 1, and masks US-format addresses, English names, e-mail, phone and date of birth (probes 2 and A5).
6. A scheduler-style account object makes `policy.extreme()` return `True` once `prefs.bin` exists (probe 1). This is a verified defect (PH-007), not a guarantee.
7. The source contains no `pickle`, `yaml.load`, `eval`, `exec`, `shell=True`, `os.system`, `verify=False` or certificate-bypass code, and only two process-spawning call sites (the Claude CLI and `osascript`) (pattern search of `src/` and `scripts/*.py`).
8. `static/app.js` contains no `innerHTML`, `insertAdjacent*`, `eval` or `document.write` (pattern search).

## 5. Unverified claims

| Claim (source) | Why I could not verify it |
|---|---|
| The local second-pass model catches what the detector misses (`docs/SECURITY.md`, T1, T22) | Tests stub the model. No real model was run. The docs themselves say a small checker misses more |
| The Claude CLI "gets the masked prompt on stdin, no tools, an empty working directory and a minimal environment" and nothing else is sent | The invocation flags are in the code, but what the CLI adds to its own request is outside the repository (PH-020) |
| The scheduler key is protected by the macOS Keychain from other applications | Tests use a dictionary backend; Keychain access control not exercised |
| The `pf` lockdown confines the dedicated user to loopback | Script not executed; the project itself marks it untested on the owner's Mac |
| Certificates generated by `tls.py` are accepted by iOS/Safari/Python 3.13 | CI covers Python 3.13 per its conclusion (logs not read); device trust not exercised |
| Account folders and files are unreadable by other OS users | Modes observed on the owner's tree (`state/users` is `drwx------`, key and audit files `0600`); not checked on a fresh install |
| `pip-audit`, `bandit`, `gitleaks`, CodeQL are clean | Only the CI job conclusions were read; none ran locally |
| Failure-mode timing of login does not reveal which e-mails exist | Same-cost code path read; no timing measurement |
| Protection against prompt injection from documents and web pages | No adversarial corpus was run |

## 6. Remaining architectural risks

1. **Probabilistic PII detection.** Regex, NER and a model; no proof of absence. The user preview and the Tier 1 stop are the real backstops, and the preview depends on a human reading it.
2. **In-process network guard.** It patches `socket.connect` only (PH-016); a compromised dependency can bypass it. Combined with unpinned transitive dependencies (PH-014), a supply-chain compromise has direct access to decrypted data in memory.
3. **One process holds every signed-in user's decrypted data.** A logic bug in the shared `Shared`/`Session` layer would be a cross-user exposure. Tests cover the known paths.
4. **Password is the only root of trust for stored data and policy.** No recovery, no rollback detection (PH-006), moderate KDF cost (PH-011).
5. **Scheduled-job design trades password protection for convenience.** Key S in the Keychain lets background jobs read a copy of opted-in folders without the password. Documented as T14/T16; same-user malware is out of scope.
6. **Administrator power over destinations.** The administrator chooses the cloud URL and LAN Ollama addresses, which receive raw or masked content. Constrained (public HTTPS pinned; private IP, port ≥ 1024) but still a confidentiality lever for whoever holds the role (PH-004, PH-013).
7. **Optional plain HTTP on the LAN** (PH-005) and plain HTTP to a remote Ollama (documented).
8. **Third-party black box:** the Claude CLI (PH-020).

## 7. Recommended remediation priorities

P1 (before relying on the control or before a new LAN install): PH-001, PH-002, PH-004, PH-006, PH-007, PH-014, and the PH-020 validation.
P2: PH-005, PH-008, PH-003, PH-015, PH-017.
P3: PH-009 to PH-013, PH-018, PH-019.
Details, test names and effort are in [REMEDIATION_TRACKER.md](REMEDIATION_TRACKER.md).

## 8. Limitations of this assessment

- Single session, one assessor, an AI model with no memory of design intent beyond the repository; no second reviewer.
- Source reading was thorough for `accounts`, `server`, `egress`, `policy`, `schedule`, `pipeline`, `ingest`, `providers` (selected parts), `config`, `tls`, `lockdown`; partial for `detect.py` (rules at the lines cited and the probes), `finance.py` (classification and summary functions), `rag.py`, `local.py`; not read: `speech.py`, `scripts/mac_shell.swift`, the end-to-end JavaScript scripts.
- No live system was attacked. No network scan, no load test, no fuzzing, no authenticated dynamic scan.
- The probes are small and use synthetic values; they demonstrate the specific cases listed and do not estimate miss rates.
- Findings marked Inferred were not executed.
- Severity is my judgement; CVSS vectors are provided for some findings without numeric scores.
- The assessment covers the repository state at one commit. It says nothing about the owner's running installation, its configuration, its data, or the machine it runs on.

## 9. Conclusion

**CONDITIONAL PASS.**

Reasoning:
- The assessment found no Critical or High vulnerability, and the core controls that I could exercise (approval gate, Extreme-privacy override, financial handling, per-account isolation, input limits) behaved as designed on 594 passing tests, 288 of them security tests run with production defaults. That rules out FAIL.
- It is not an unconditional PASS because three verified weaknesses touch the controls the product is named for (PH-001/PH-002 in what gets masked, PH-006 in whether Extreme privacy can be trusted), two deployment defaults make a new LAN install risky (PH-004, PH-005), and a scheduler defect (PH-007) shows that a documented feature has no end-to-end test for its real object types.
- It is not INSUFFICIENT EVIDENCE overall because the code was readable, the tests runnable and many claims were checked by execution. It **is** insufficient for four specific claims (section 5): second-pass efficacy, what the Claude CLI actually transmits, Keychain access control and the `pf` lockdown.

The condition: the assessment applies to a single owner or trusted household using loopback or an HTTPS LAN link with review-before-send left on, **and** the P1 items are tracked to closure. A re-assessment after those fixes, preferably by someone other than the project's own assistant, is recommended before the project is described as suitable for anyone beyond that setting.
