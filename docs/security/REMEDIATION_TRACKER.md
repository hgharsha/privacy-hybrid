# Remediation tracker

Latest code state: public `aec65d4` (full `aec65d472e3c746a177568ce0f97bcd0ea7b3b5a`; private `fc02867`). Latest public HEAD `77a6166117d7d7f7c19b1afcccae6835cc3354fd` and later private commits are documentation only. Created 2026-11-01 from [FINDINGS.md](FINDINGS.md). Commit ids and CI run numbers in these documents refer to the repository history before 2026-11-02, which was replaced by a clean history; they are kept as text and no longer resolve to commits. Baseline assessed commit `40638c6`. **Eighteen findings are Closed with green CI on the public repo (PH-001, 002, 004, 005, 006, 007, 008, 009, 010, 011, 012, 013, 014, 015, 017, 018, 019, 020) — see the table — and PH-003 and PH-016 are Accepted (documented limits, see their rows).** "Fix commit" is the public commit; the private repo holds the same changes. Update this table when a fix lands, with the fixing commit and the regression test that now passes. A finding is "Closed" only when the fix is merged **and** its regression test exists and passes in CI.

Effort: S under half a day, M one to two days, L more than two days (rough estimates, not commitments).

## Priorities

| Priority | Meaning |
|---|---|
| P1 | Fix before relying on the affected control, or before a new LAN install |
| P2 | Fix in the next release |
| P3 | Hardening or hygiene |

## Tracker

| ID | Title | Severity | Priority | Effort | Status | Fix commit | Regression test | Notes |
|---|---|---|---|---|---|---|---|---|
| PH-001 | Passport numbers missed | Medium | P1 | S | Closed | `c5bd7d4` | `test_id_phrasings_block_the_request` | Widen the separator grammar in `detect.py:99` |
| PH-002 | Non-US addresses not masked | Medium | P1 | M | Closed | `c5bd7d4` | `test_non_us_addresses_are_masked` | Alphanumeric house numbers, postcodes |
| PH-004 | No default setup token | Medium | P1 | S | Closed | `c5bd7d4` | `test_first_account_from_another_machine_needs_the_setup_code` | Installer generates and stores token, or loopback-only until first account |
| PH-006 | Older file restores undo Extreme privacy | Medium | P1 | M | Closed | `c5bd7d4` | `test_restoring_an_older_prefs_file_does_not_switch_extreme_off` | Monotonic counter outside the folder |
| PH-007 | Scheduler cannot read Extreme setting | Low | P1 | M | Closed | `c5bd7d4` | `test_real_slot_account_runs_web_job_and_extreme_still_blocks` | Contradicts documented scheduled-web behaviour; fail-closed today |
| PH-014 | Unpinned transitive deps, model, Actions | Medium | P1 | M | Closed (residual: Dependabot vs lock) | `fa6bb6a`, `b963e14` | CI job `lock`; Actions SHA check | Add hashes, pin model wheel |
| PH-005 | Plain HTTP on LAN allowed | Medium | P2 | S | Closed | `fa6bb6a` | `test_lan_bind_requires_tls_or_flag` | Documented residual today |
| PH-008 | Root-run script in writable path | Medium | P1 | S | Closed | private `a92d56e` | `tests/security/test_lockdown.py::test_refuses_non_root_script` (exists since 2026-11-02; earlier versions of this table cited it before it existed) and six more in the same file | Verified on a real root-owned install 2026-11-02 (see TEST_EVIDENCE.md §11) |
| PH-003 | Spelled SSN, non-Latin names | Low | P2 | M | Accepted (the detector cannot mask spelled-out numbers or non-Latin names; mitigations: the script guard refuses, a "maybe sensitive" warning forces the preview and a second confirmation even with Review off, and the owner sees the text before it leaves; deliberate sharing by the user is out of scope) | `aec65d4`, warning tier in the commit after public `e134ee1` | `test_spelled_ssn_and_foreign_id_labels_block_the_request`, `test_mostly_non_latin_text_is_not_sent_to_the_cloud`, `test_unsure_text_forces_the_preview_even_with_review_off`, `test_flagged_text_needs_the_second_confirmation`, `test_watch_flags_marks_what_the_filter_cannot_mask` | Documented limit |
| PH-015 | Repo governance gaps | Low | P2 | S | Closed (nothing reaches public `main` except through a pull request with the four checks green and the owner's merge click, admins included; accepted residual: no signed commits and no independent reviewer, because the owner is the only maintainer) | n/a (settings) | n/a (setting read back from the GitHub API) | Required check names, secret scanning, push protection |
| PH-017 | Public threat model stale | Low | P2 | S | Closed | `aec65d4` | `tests/test_docs.py::test_every_cited_threat_exists` | Sync from private tree; fix T11 |
| PH-012 | Plaintext kept in `lru_cache` | Low | P3 | S | Closed | `b963e14` | `test_no_document_text_is_cached_in_the_process` |  |
| PH-013 | Admin succession by mtime | Low | P3 | S | Closed | `b963e14` | `test_succession_is_stable_across_a_password_change` |  |
| PH-009 | Body read before auth | Low | P3 | S | Closed | `b963e14` | `test_signed_out_post_is_refused_before_the_body_is_read`, `test_sign_in_bodies_are_capped_small` |  |
| PH-010 | Per-address throttling only | Low | P3 | S | Closed | `b963e14` | `test_many_addresses_guessing_one_account_hit_an_account_wide_delay` |  |
| PH-011 | scrypt cost modest | Low | P3 | M | Closed | `aec65d4` | `test_old_scrypt_accounts_sign_in_and_are_upgraded` | Needs per-account parameters |
| PH-018 | `/api/config` visible to all users | Info | P3 | S | Closed | `b963e14` | `test_other_users_see_a_reduced_config` |  |
| PH-019 | Log dir permissions, no tamper evidence | Info | P3 | S | Closed (log rotates at 10 MB, keeps 12 archives; hash chain continues across a rotation) | `b963e14`, `aec65d4`; rotation in the commit after public `3e0f0ab` | `test_log_dir_is_private`, `test_audit_log_chain_shows_an_edited_line`, `test_audit_log_rotates_and_keeps_the_chain` | Documented limit: the chain shows edits and deletions in the middle, not loss of the last lines |
| PH-016 | In-process egress guard scope | Info | n/a | n/a | Accepted | | n/a | Keep documented; OS firewall for strong isolation |
| PH-020 | Claude CLI traffic beyond stdin | Not rated | P1 (validation) | M | Closed (owner-run capture 2026-11-02, three runs; last: the app's setup made one request, to `api.anthropic.com`; no canary, no telemetry, no connector traffic; control valid) | public `0a59120`, `5f43d57`, `3c24d3c` | `tests/security/test_network.py` (opt-outs, no MCP, private config folder) | Owner-run: `scripts/ph020_capture.sh`; see TEST_EVIDENCE.md §14 |

## Validation items that are not findings yet

| Item | What would close it |
|---|---|
| Real local second-pass model efficacy | A labelled corpus of leaks run against the model the owner uses (14B or larger recommended by the docs); record the miss rate |
| Keychain item access control for the scheduler key | On a second local user and as another app, try to read the item; record prompts and results |
| TLS trust on devices, certificate renewal | Manual test on each device class |
| `pf` lockdown correctness | `sudo -u <user> curl -m 5 https://example.com` must time out (the script itself documents this test) |
| Transitive dependency vulnerabilities | Run `pip-audit` against a fully resolved environment; record the version of the advisory database |

## Change log

| Date | Change |
|---|---|
| 2026-11-01 | Tracker created from the assessment. All items open. |
| 2026-11-01 | PH-001, 002, 004, 006, 007 fixed in the working tree with regression tests (613 tests pass locally). Not committed; become Closed when merged and green in CI. |
| 2026-11-01 | Fixes pushed to public as `c5bd7d4`; CI green (tests 41370411813, security-scan 41370411807). PH-001, 002, 004, 006, 007 set to Closed. |
| 2026-11-01 | PH-005 and PH-014 fixed in private; pushed to public for CI. PH-008 left open on purpose. |
| 2026-11-01 | Public `fa6bb6a` CI green (tests 41371210194, security-scan 41371210217). PH-005 Closed; PH-014 partly fixed. |
| 2026-11-01 | Public `b963e14` (tests 41374810179, security-scan 41374810181): PH-009, 010, 012, 013, 018 Closed; PH-019 partly fixed; PH-014 Closed with residual; `pytest` moved to `requirements-dev.txt`. Fix-commit column filled in. |
| 2026-11-01 | Public `aec65d4` (tests 41376563928, security-scan 41376564070): PH-011, 017 Closed; PH-003, 019 mostly fixed. PH-015 settings changed on the public repo (secret scanning, push protection, Dependabot security updates, real required check names). |
| 2026-11-02 | Re-review. PH-008: confirmed the script and all its parents are owned by the app user; added an owner/mode/symlink check on the script and every parent immediately before `osascript` (local, uncommitted) and 7 tests; the previously cited `test_refuses_non_root_script` had not existed. PH-020: code mitigations documented, capture procedure written, nothing run. Counts unchanged: 14 Closed, 3 mostly fixed, 1 Accepted, PH-008 and PH-020 Open. Local run: 641 passed. |
| 2026-11-02 | PH-008 Closed. Owner-run test on a real root-owned copy at `/usr/local/ph008`: trusted copy returns True; the user-owned checkout returns False; making the scripts directory group/world-writable returns False. Counts: 15 Closed, 3 mostly fixed, 1 Accepted, 1 Open (PH-020). |
| 2026-11-02 | PH-020 capture run by the owner (mitmproxy, own user, real login, canaries planted in `CLAUDE.md` and a filename). Result: no canary in any request; prompt text only in the message request. Finding: the CLI also sent usage telemetry and error metadata to Anthropic and a third-party log service. Fix: `CLAUDE_FIXED_ENV` opt-outs (public `0a59120`); re-capture showed no log-service and no event-logging requests. Gaps: no saved positive control; other hostnames in the output may come from response bodies and were not checked. PH-020 set to Mostly fixed. Counts: 15 Closed, 4 mostly fixed, 1 Accepted, 0 Open. |
| 2026-11-02 | PH-019 Closed: the audit log now rotates at 10 MB and keeps 12 archives; the first line of the new file carries the hash of the archive's last line; test `test_audit_log_rotates_and_keeps_the_chain`. Counts: 16 Closed, 3 mostly fixed (PH-003, 015, 020), 1 Accepted, 0 Open. |
| 2026-11-02 | PH-020 Closed. The app's CLI now runs with a private config folder (when present), telemetry and error reporting off, and no MCP servers or account connectors. Owner-run capture with a valid control (the user-memory canary shows up when settings are allowed): the app's setup made exactly one request, to `api.anthropic.com`; no canary string, no telemetry, no connector traffic. Counts: 17 Closed, 2 mostly fixed (PH-003, 015), 1 Accepted, 0 Open. |
| 2026-11-02 | PH-015 Closed. `enforce_admins` turned on for public `main` (required: pull request, 4 status checks; 0 approvals because a sole owner cannot approve their own pull request). The owner can no longer push straight to `main`; every change needs a pull request, green checks and the owner's merge click. Accepted residual: no signed commits, no independent reviewer. Counts: 18 Closed, 1 mostly fixed (PH-003), 1 Accepted, 0 Open. |
| 2026-11-02 | PH-003 moved to Accepted by the owner's decision, with a new mitigation: a "maybe sensitive" warning (digits spelled out, long unmasked numbers, words like passport or account number) forces the preview and a second "send anyway" confirmation even when Review is off. Not covered: scheduled jobs (nobody to ask) and deliberate sharing by the user. Counts: 18 Closed, 0 mostly fixed, 2 Accepted (PH-003, 016), 0 Open. |
