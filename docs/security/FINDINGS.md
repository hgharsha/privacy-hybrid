# Findings

Assessment date: 2026-11-01 (statuses updated through 2026-11-02; the finding text below is the original assessment, the **Status** line of each finding is current). Baseline assessed commit (before any fixes; later state is in SECURITY_ASSESSMENT.md section 0 and the tracker): `40638c60c9286b65a231c3ac19ca3b5a5c6a2428` (public `main`). See [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) for scope, method and limits. This is a self-assessment by the project's AI coding assistant at the owner's request. It is **not** an independent third-party audit and not a certification.

File and line references are to the assessed commit. `src/`, `scripts/`, `static/`, `tests/` and `.github/` are byte-identical between public `main` (`40638c6`) and the private development commit `229a6b9` where the local checks were run (`git diff --stat` shows only `LICENSE`, `PLAN.md`, `PROGRESS.md`, `docs/THREAT-MODEL.md` differ).

## How to read this document

**Evidence class**
- **Verified**: I executed a local check in this session and observed the result (commands in [TEST_EVIDENCE.md](TEST_EVIDENCE.md), appendix A).
- **Inferred**: concluded from reading the code; not executed.
- **Needs validation**: a source-grounded hypothesis whose deciding fact is outside the repository or needs a live system. No severity is assigned.

**Severity.** No finding here reaches High or Critical. Severity is qualitative unless a CVSS v4.0 vector is given. Where a vector is given, I did **not** compute a numeric score with the official FIRST calculator, so no number is stated; reviewers should compute it. CVSS is unsuitable for the privacy-control coverage gaps (PH-001 to PH-003), which are weaknesses in a defence-in-depth layer rather than a conventional vulnerability, so those use the qualitative scale:

- **Medium**: a real control is weakened or bypassable under stated preconditions, with bounded blast radius.
- **Low**: limited impact, strong preconditions, or a defect that fails closed.
- **Informational**: observation or accepted, documented residual risk.

**Status** in the summary table is the current state; each finding's own section says what changed and where. At the assessed commit every finding was Open.

## Summary

| ID | Title | Severity | Evidence | Status |
|---|---|---|---|---|
| [PH-001](#ph-001) | Passport numbers missed with common phrasings | Medium | Verified | Closed |
| [PH-002](#ph-002) | Non-US street addresses not masked | Medium | Verified | Closed |
| [PH-003](#ph-003) | Spelled-out SSN and non-Latin names undetected | Low | Verified | Accepted |
| [PH-004](#ph-004) | First visitor becomes administrator; no setup token by default | Medium | Inferred | Closed |
| [PH-005](#ph-005) | Plain HTTP allowed on a LAN bind | Medium | Inferred | Closed |
| [PH-006](#ph-006) | Extreme privacy can be silently undone by restoring an older file | Medium | Verified | Closed |
| [PH-007](#ph-007) | Scheduler cannot read the Extreme-privacy setting | Low | Verified (component) | Closed |
| [PH-008](#ph-008) | Root-run lockdown script lives in a user-writable path | Medium | Inferred | Closed |
| [PH-009](#ph-009) | Request body read before authentication | Low | Inferred | Closed |
| [PH-010](#ph-010) | Login throttling is per address, not per account | Low | Inferred | Closed |
| [PH-011](#ph-011) | scrypt cost parameter is modest | Low | Inferred | Closed |
| [PH-012](#ph-012) | Document plaintext kept in a process-wide cache after sign-out | Low | Verified | Closed |
| [PH-013](#ph-013) | Administrator succession uses file modification time | Low | Verified | Closed |
| [PH-014](#ph-014) | Transitive dependencies, spaCy model and Actions not pinned | Medium | Verified (counts) / Inferred (impact) | Closed |
| [PH-015](#ph-015) | Repository governance gaps | Low | Verified | Closed |
| [PH-016](#ph-016) | Egress guard is in-process and covers `connect` only | Informational | Inferred | Accepted (documented) |
| [PH-017](#ph-017) | Public threat model out of date | Low | Verified | Closed |
| [PH-018](#ph-018) | `/api/config` readable by every signed-in user | Informational | Inferred | Closed |
| [PH-019](#ph-019) | Log directory permissions and no tamper evidence | Informational | Verified (perms) | Closed |
| [PH-020](#ph-020) | What the Claude CLI sends beyond stdin (capture run; telemetry and connector traffic found and switched off) | Not rated | Verified | Closed |

Counts: Critical 0, High 0, Medium 7, Low 9, Informational 3, Needs validation 1.

---

<a id="ph-001"></a>
## PH-001: Passport numbers missed with common phrasings

- **Severity:** Medium (qualitative; CVSS unsuitable). **Evidence:** Verified.
- **Component:** deterministic PII detector, Tier 1 government-ID rule.
- **Location:** [`src/privhybrid/detect.py:99`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/detect.py); policy entry in `src/privhybrid/pii_policy.json` ("Passport", Tier 1, `masking: block`).
- **Description:** The rule is `\b(?:passport|…)\b\s*(?:no|number|#)?[:\s)]*([A-Z0-9][A-Z0-9\-]{5,14})\b`. After the keyword it accepts an optional `no`/`number`/`#` and then only `:`, whitespace or `)`. A period after `no`, or a filler word such as `is`, breaks the match. Policy says passports are Tier 1 and must stop the request; these phrasings are not detected at all.
- **Attack scenario:** A user pastes "my passport is X1234567" (or "passport no. X1234567") into a question or file sent through the Claude route. The Tier 1 stop (`vault.py` `mask`) never fires and no placeholder is created.
- **Preconditions:** Cloud permission, Claude/cloud route selected, passport written in one of the missed phrasings. Remaining defences are the local second-pass model (not exercised here) and the default-on preview the user must approve.
- **Reproduction (safe, local, synthetic data):** [Appendix A, probe 3](TEST_EVIDENCE.md#a3). Observed: `passport number: C01X00T47` is blocked as `GOVID` Tier 1; `passport no. X1234567` and `my passport is X1234567` produce **no entities**. The policy's own sample ("passport number X1234567") passes, which is why existing tests do not notice.
- **Impact:** Confidentiality of a government identifier on the cloud route; the strongest-tier control has a hole.
- **Recommended remediation:** Allow an optional period after `no`, filler words (`is`, `was`, `:`, `-`) and ordinal forms between keyword and value; add a symmetric context window (as `_ctx` does elsewhere); add country-specific passport formats. Keep the "block, don't mask" behaviour.
- **Regression test required:** Parametrised test over at least 20 phrasings per Tier 1 ID kind (`passport no.`, `passport is`, `passport #`, line-break between label and value, other languages' labels) asserting a Tier 1 entity; add to `tests/security/test_pii_policy.py`.
- **Status:** Closed 2026-11-01. Fixed in public commit `c5bd7d4`; CI green (tests 41370411813, security-scan 41370411807). passport phrasings now caught (`detect.py` GOVID rule); tests `test_id_phrasings_block_the_request`.

<a id="ph-002"></a>
## PH-002: Non-US street addresses not masked

- **Severity:** Medium (qualitative). **Evidence:** Verified.
- **Component:** detector, address rule; masking policy for "place" entities.
- **Location:** [`detect.py:113`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/detect.py); [`vault.py:83-84`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/vault.py) (a lone PLACE is not masked).
- **Description:** The ADDRESS rule needs `\d{1,6}\s+` followed by capitalised words and a US street suffix. "221B Baker Street, London NW1 6XE" fails (house number `221B`, no space after digits). The only entity found is `London` (PLACE, Tier 4), which `Vault.mask` deliberately leaves in clear unless another quasi-identifier is present.
- **Attack scenario:** A home address in a UK/EU style is included in a document sent via the Claude route. It reaches the outgoing text unmasked.
- **Preconditions:** As PH-001. In the probe the US-format address `1600 Pennsylvania Avenue NW, Washington, DC 20500` **was** masked.
- **Reproduction:** [Appendix A, probe 2](TEST_EVIDENCE.md#a2).
- **Impact:** Home-address disclosure to a cloud provider, mitigated by the second pass and the preview.
- **Recommended remediation:** Accept alphanumeric house numbers and trailing-number formats, UK/CA/EU postcodes, and a street-suffix word preceded or followed by a number; treat "street word + PLACE" as ADDRESS.
- **Regression test required:** Address corpus per country in `tests/corpus.py`, asserting masking in `Vault.mask`.
- **Status:** Closed 2026-11-01. Fixed in public commit `c5bd7d4`; CI green (tests 41370411813, security-scan 41370411807). alphanumeric house numbers, more street types, street-first forms, UK and Canadian postcodes; tests `test_non_us_addresses_are_masked`.

<a id="ph-003"></a>
## PH-003: Spelled-out SSN and non-Latin-script names undetected

- **Severity:** Low (documented limitation). **Evidence:** Verified.
- **Component:** detector (regex + Presidio `en_core_web_lg`).
- **Location:** detector as a whole; limitation acknowledged in [`docs/SECURITY.md`](https://github.com/hgharsha/privacy-hybrid/blob/main/docs/SECURITY.md) ("non-English text can be missed").
- **Description:** "social security number: zero seven eight, zero five, one one two zero" and a Chinese name/address sentence produced no entities and were not masked. A Russian name with Cyrillic script was detected (PERSON), a Chinese one was not.
- **Impact:** Same channel as PH-001, requires unusual input.
- **Recommended remediation:** Normalise number words before the digit rules; for text with a large non-Latin share, either block the cloud route or require an explicit confirm; keep the documentation.
- **Regression test required:** Cases for number words and for CJK/Arabic/Devanagari text asserting block-or-mask.
- **Status:** Accepted 2026-11-02 (owner's decision). The detector cannot mask spelled-out numbers or non-Latin names. Mitigations: the script guard refuses mostly non-Latin text; a "maybe sensitive" warning (digits spelled out as words, long unmasked numbers, words such as passport or account number) forces the preview and a second "send anyway" confirmation even when Review is off (`test_unsure_text_forces_the_preview_even_with_review_off`, `test_flagged_text_needs_the_second_confirmation`). Limits: scheduled jobs have nobody to ask; the warning is heuristic and will miss things; a person who deliberately sends their own data is outside what a tool can prevent. Earlier state: Mostly fixed 2026-11-01 (CI green on public `aec65d4` (tests 41376563928, security-scan 41376564070)). Number-word SSNs after "social security"/"SSN" are Tier 1; ID labels in German, French, Spanish, Italian, Dutch (Reisepass, passeport, pasaporte, passaporto, paspoort, Führerschein, DNI, NIE, NIF, BSN and others, with Nr./n°/número) are Tier 1; a cloud send is stopped when 10% or more of the letters are in CJK, Arabic, Hebrew, Indic, Thai or Hangul script (the text stays local). Tests in `test_pii_policy.py`. Residual: names and addresses in those scripts are still not *masked* (the whole send is refused instead); other languages' number words and ID labels are not covered; heuristics checked on a handful of examples. Kept Open for those.

<a id="ph-004"></a>
## PH-004: First visitor becomes administrator; no setup token by default

- **Severity:** Medium. **Evidence:** Inferred (code and installer read; not exercised against a fresh LAN install).
- **CVSS 4.0 vector (score not computed):** `CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` (AT:P: only before the owner registers).
- **Component:** account registration; installer.
- **Location:** [`accounts.py:321-325`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/accounts.py); [`scripts/install.py:31-39`](https://github.com/hgharsha/privacy-hybrid/blob/main/scripts/install.py) and `:304-307` (`--bind`).
- **Description:** The first registration becomes administrator. `PRIVHYBRID_SETUP_TOKEN` is the only guard and it is optional; the installer neither generates nor requires one, even with `--bind <LAN IP>`. The docs recommend setting it (`docs/SECURITY.md`, Deployment recommendations 2).
- **Attack scenario:** The service is started on a LAN address before the owner has registered; another device on the network registers first and becomes administrator. As administrator it can create users, grant cloud/web permissions, change the Ollama and cloud addresses in Settings (documents then flow to an address it chose, within the private-IP rules in `config.valid_ollama_url`) and read the audit log. It cannot read other accounts' files.
- **Preconditions:** Fresh install (no account yet), non-loopback bind, no token, attacker on the same network.
- **Reproduction:** Not executed against a live LAN service. The decision path is `tests/security/test_multiuser.py:85` (token case) and the absence of a default.
- **Impact:** Takeover of the administrator role on a new LAN-exposed install.
- **Recommended remediation:** Installer generates a random token, stores it in the macOS Keychain, prints it once; or refuses non-loopback registration while zero accounts exist.
- **Regression test required:** With no accounts and no token, a registration from a non-loopback peer must be refused; with a LAN bind and no accounts the server must not start or must log a hard warning.
- **Status:** Closed 2026-11-01. Fixed in public commit `c5bd7d4`; CI green (tests 41370411813, security-scan 41370411807). first account from a non-loopback address needs `PRIVHYBRID_SETUP_TOKEN` (`accounts.register(from_loopback=)`); tests in `test_multiuser.py`.

<a id="ph-005"></a>
## PH-005: Plain HTTP allowed on a LAN bind

- **Severity:** Medium (documented residual risk). **Evidence:** Inferred.
- **CVSS 4.0 vector (score not computed):** `CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`.
- **Component:** HTTP server, bind policy.
- **Location:** [`server.py:1062-1069`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/server.py) (`check_bind`); [`server.py:1106-1111`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/server.py) (TLS optional); `README.md:87`.
- **Description:** A private IPv4 bind is accepted without TLS. Passwords, session cookies (no `Secure` flag without TLS, `server.py:381`), documents and answers then cross the LAN in clear.
- **Attack scenario:** A device on the same Wi-Fi sniffs the login POST or session cookie and replays it.
- **Preconditions:** LAN bind without `--tls`; attacker on the L2 segment.
- **Impact:** Credential and data disclosure, session hijack on the LAN.
- **Recommended remediation:** Refuse non-loopback binds without TLS unless an explicit `--insecure-http` flag is given; show a persistent banner when it is on.
- **Regression test required:** `serve(host=<private ip>)` without TLS raises unless the flag is set.
- **Status:** Closed 2026-11-01 (CI green on public `fa6bb6a` (tests 41371210194 incl. new `lock` job, security-scan 41371210217)): `serve()` and `install.py` refuse a non-loopback bind without TLS unless `PRIVHYBRID_ALLOW_HTTP=1`; tests `test_lan_bind_requires_tls_or_flag`, `test_network_bind_without_tls_is_refused`. Existing installs started without TLS and without the flag will stop at next restart.

<a id="ph-006"></a>
## PH-006: Extreme privacy can be silently undone by restoring an older file

- **Severity:** Medium. **Evidence:** Verified.
- **Component:** encrypted per-account storage; privacy policy.
- **Location:** [`accounts.py:61-70`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/accounts.py) and `:72-93`; [`policy.py:19-47`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/policy.py).
- **Description:** Each file is AES-GCM sealed with the filename as associated data and carries a version counter, but the counter is only compared with the version already read in this process (`base`). A previously valid ciphertext of the same file name decrypts and is accepted. `policy.extreme()` reads `prefs.bin` fresh each time, so an older `prefs.bin` with Extreme privacy off takes effect immediately and without any signal.
- **Attack scenario (a) benign:** a Time Machine or manual restore of the account folder to an earlier date turns Extreme privacy off. **(b) hostile:** a process with write access to the user's data directory (but without the password) copies an old `prefs.bin` back.
- **Preconditions:** Write access to `state/users/<id>/` and a saved older copy.
- **Reproduction:** [Appendix A, probe 4](TEST_EVIDENCE.md#a4). Observed: after enabling Extreme, `extreme()` → `True`; after writing back the older bytes, `extreme()` → `False` with no error.
- **Impact:** The headline control can be disabled without the password. Cloud sends remain gated by masking, the second pass and the preview, which limits the consequence.
- **Recommended remediation:** Keep a monotonic "highest version seen" per file outside the folder (macOS Keychain or a separate root of trust) and treat a lower version as tampering; at minimum treat a version decrease inside a running process as "Extreme on" and warn. Document the backup-restore behaviour.
- **Regression test required:** Restoring an older `prefs.bin` must either raise or leave `extreme()` at its latest value.
- **Status:** Closed 2026-11-01. Fixed in public commit `c5bd7d4`; CI green (tests 41370411813, security-scan 41370411807). `policy.py` keeps the highest `prefs.bin` version seen outside the account folder; an older file reads as Extreme on; test `test_restoring_an_older_prefs_file_does_not_switch_extreme_off`. Residual: restoring the whole data folder together with the marker file.

<a id="ph-007"></a>
## PH-007: Scheduler cannot read the Extreme-privacy setting

- **Severity:** Low (fails closed; availability and test-coverage defect). **Evidence:** Verified at component level; end-to-end scheduler tick with a web job was not executed.
- **Component:** scheduled jobs; policy.
- **Location:** [`schedule.py:42-45`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/schedule.py) (`slots` returns `SimpleNamespace(id, folder)`), [`schedule.py:394-398`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/schedule.py) (`is_extreme=lambda: policy.extreme(acct)`), [`policy.py:19-47`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/policy.py).
- **Description:** The scheduler runs without the password key, so its account object has no `load()`. `prefs.bin` is sealed under the password key, so the scheduler could not decrypt it anyway. Once `prefs.bin` exists, `policy._read` fails and `extreme()` returns `True` ("unknown means on").
- **Effect:** For any account that has ever saved a preference, scheduled **web** jobs fail with "extreme privacy"; scheduled local jobs run under `strict_local()` so a listed LAN Ollama is refused. No data leaks (fail closed), but the documented behaviour ("web jobs run unless Extreme privacy is on") cannot work, and no test covers the real scheduler account type.
- **Reproduction:** [Appendix A, probe 1](TEST_EVIDENCE.md#a1). Observed: real `Account` with `prefs.bin` → `False`; scheduler-style object → `True`.
- **Recommended remediation:** Mirror a minimal `extreme` flag into the scheduler's key-S-sealed state when the user changes it, and read that in `run_job`; keep fail-closed.
- **Regression test required:** A scheduler tick with an account from `schedule.slots()`, `prefs.bin` present, Extreme off, must run a web job; with Extreme on it must not.
- **Status:** Closed 2026-11-01. Fixed in public commit `c5bd7d4`; CI green (tests 41370411813, security-scan 41370411807). scheduler reads a sealed `policy.s` copy (stamped against `prefs.bin`, stale or missing means on); test `test_real_slot_account_runs_web_job_and_extreme_still_blocks`.

<a id="ph-008"></a>
## PH-008: Root-run lockdown script lives in a user-writable path

- **Severity:** Medium. **Evidence:** Inferred (not executed: would need an administrator password dialog).
- **CVSS 4.0 vector (score not computed):** `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`.
- **Component:** optional OS network lockdown.
- **Location:** [`lockdown.py:11-19`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/lockdown.py); [`server.py:574-598`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/server.py); `scripts/lockdown.sh` (mode `-rwxr-xr-x`, owned by the app user).
- **Description:** The app asks `osascript` to run `/bin/sh '<repo>/scripts/lockdown.sh' on <user>` "with administrator privileges". The script is in the repository tree, owned and writable by the account that runs the app; there is no ownership, mode or hash check before it is executed as root.
- **Attack scenario:** Code already running as the app user (including the dedicated lockdown user, which the feature is meant to confine) replaces `lockdown.sh`; the next time an administrator presses "Lock down" and enters their password, the replacement runs as root.
- **Preconditions:** Code execution as the app user plus an administrator approving the dialog.
- **Impact:** Local privilege escalation through a trusted workflow; defeats the point of the dedicated-user model.
- **Recommended remediation:** Install the script once to a root-owned, non-writable location with `sudo` (for example `/usr/local/libexec/privhybrid-lockdown`) and have the app call only that path after checking `st_uid == 0` and no group/other write; or remove the in-app button and keep the terminal step.
- **Regression test required:** `lockdown.request_on` refuses when the script is not root-owned or is group/world-writable (mock `os.stat`).
- **Re-review 2026-11-02 (verified by reading the code and `ls -l`):** `scripts/lockdown.sh` is `-rwxr-xr-x` owned by the app user, in a checkout whose every folder up to the home directory is owned by that user. Git records only the executable bit, so the checkout says nothing about who may change the file. The original description is correct: the script path was passed to `osascript ... with administrator privileges` with no ownership or mode check.
- **Change (local working tree only; not committed, not pushed):** `lockdown.script_is_trusted()` now requires the script and **every parent directory up to `/`** to be owned by root, not symlinks, and not group- or world-writable. `lockdown.request_on()` calls it immediately before starting `osascript`, and the server returns a "Refused" message (and audit entry) without starting anything when it fails. Because a root-only path cannot be changed by the app user between the check and the run, there is no race window. The check cannot be satisfied by an ordinary checkout, so the in-app "Lock down" button is effectively disabled until the script is installed to a root-owned location (for example `/usr/local/libexec/`, which also needs `SCRIPT` to point there; that install layout is **not** built). The terminal step `sudo scripts/lockdown.sh on` is unchanged and is run by the administrator, not by the app.
- **Tests (run 2026-11-02, all pass):** `tests/security/test_lockdown.py`: `test_refuses_non_root_script` (real files: a temp file and the real checkout are refused), `test_refuses_script_when_any_parent_is_group_or_world_writable`, `test_refuses_a_symlinked_script_or_parent`, `test_refuses_when_a_missing_or_non_root_parent_is_in_the_chain`, `test_request_on_never_starts_osascript_for_an_untrusted_script`, `test_request_on_runs_osascript_only_after_the_check_passes`, `test_server_explains_that_an_untrusted_script_was_not_run`. The root-owned case is simulated by replacing `os.lstat`; no test runs against a genuinely root-owned install, and `osascript`/`pfctl` are never run.
- **Status:** Closed 2026-11-02. Owner-run test on a real root-owned copy passed (trusted True, user-owned checkout False, group/world-writable directory False). Earlier note: the property "a user-writable or non-root-owned script is never run as root" is demonstrated only at the unit level with simulated ownership, and the change is not yet merged. It stays Open until it is merged with green CI and checked once against a real root-owned install (owner-run, needs sudo).

<a id="ph-009"></a>
## PH-009: Request body read before authentication

- **Severity:** Low. **Evidence:** Inferred (no load test).
- **CVSS 4.0 vector (score not computed):** `CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`.
- **Location:** [`server.py:404-411`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/server.py) and `:651-658` (`_body()` runs before the session check); limits at `:39-41`.
- **Description:** Any client that passes the Host and Origin checks can make the server read and `json.loads` up to 8 MiB per request before it learns the caller has no session. With 64 allowed connections and a 30 s read timeout this is roughly half a GiB of buffering plus parsing.
- **Impact:** Local/LAN memory and CPU pressure. Not remote: the port is not meant to be internet-facing.
- **Recommended remediation:** Cap unauthenticated bodies (login and register need a few KiB), or check the session before reading the body for every other path.
- **Regression test required:** `tests/security/test_http_limits.py`: an unauthenticated POST with a 1 MiB body is refused before it is read.
- **Status:** Closed 2026-11-01 (CI green on public `b963e14` (tests 41374810179, security-scan 41374810181)). Sign-in bodies capped at 16 KiB; any other POST without a session gets 401 before the body is read. Tests `test_signed_out_post_is_refused_before_the_body_is_read`, `test_sign_in_bodies_are_capped_small`.

<a id="ph-010"></a>
## PH-010: Login throttling is per address, not per account

- **Severity:** Low. **Evidence:** Inferred.
- **Location:** [`server.py:251-260`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/server.py) and `:659-664`.
- **Description:** Five failures per minute are counted per source address and per (address, account). There is no account-wide counter, so several LAN hosts can each try five passwords a minute against one account; scrypt time is then the only brake. Conversely, behind a reverse proxy every client shares one address, so one stranger's failures lock everyone out.
- **Recommended remediation:** Add an account-wide slow-down (exponential, never a permanent lock); document the proxy case or add trusted-proxy handling.
- **Regression test required:** Failures from three distinct peers against one account trigger the account-level delay.
- **Status:** Closed 2026-11-01 (CI green on public `b963e14` (tests 41374810179, security-scan 41374810181)). Added an account-wide limit of 20 failed sign-ins a minute across all addresses. Trade-off: someone on the LAN who sends 20 bad guesses can block that account's sign-in for up to a minute (the existing per-address rule still stops them first from one machine). Proxy case not changed. Test `test_many_addresses_guessing_one_account_hit_an_account_wide_delay` (component level: it exercises the counter, not 20 real peers).

<a id="ph-011"></a>
## PH-011: scrypt cost parameter is modest

- **Severity:** Low. **Evidence:** Inferred.
- **Location:** [`accounts.py:28`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/accounts.py): `n=2**15, r=8, p=1`.
- **Description:** This protects data at rest if someone obtains the account folder (backup, disk image). The value is below the `N=2**17` that, as I recall, OWASP's Password Storage Cheat Sheet lists as a first-choice scrypt configuration; reviewers should confirm against the current text. Parameters are not stored per account, so raising them requires a migration.
- **Recommended remediation:** Store `n,r,p` in `meta.json`, raise the default, re-derive at next sign-in.
- **Regression test required:** Old-parameter accounts still sign in and are upgraded.
- **Status:** Closed 2026-11-01 (CI green on public `aec65d4` (tests 41376563928, security-scan 41376564070)). New and re-keyed accounts use scrypt N=2^16, r=8, p=2 (64 MiB; one of OWASP's equivalent settings, which I recall rather than re-read) and store the parameters in `meta.json`; older accounts sign in on their stored parameters and are re-encrypted at the next sign-in when no other device of that account is signed in. Test `test_old_scrypt_accounts_sign_in_and_are_upgraded`. Not tested: upgrade interrupted by a crash (it reuses the password-change path, which has its own rollback test); a stricter N=2^17 was not chosen because 64 concurrent sign-ins would then need about 8 GiB.

<a id="ph-012"></a>
## PH-012: Document plaintext kept in a process-wide cache after sign-out

- **Severity:** Low. **Evidence:** Verified.
- **Location:** [`rag.py:106-109`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/rag.py) (`@functools.lru_cache(maxsize=32)` on `_financial(name, text)`).
- **Description:** The cache key is the full document text, so up to 32 decrypted documents stay in module memory after the session ends, account deletion or password change. The design says keys and data live only for the session.
- **Reproduction:** [Appendix A, probe 4](TEST_EVIDENCE.md#a4): `rag._financial.cache_info().currsize == 1` after one call.
- **Impact:** Larger memory-disclosure window (crash dump, swap). There is no cross-account leak: the cache is keyed by content.
- **Recommended remediation:** Remove the cache (intake already stores the classification), or key by a salted hash and clear it on session end.
- **Regression test required:** After `drop_session`, the cache is empty.
- **Status:** Closed 2026-11-01 (CI green on public `b963e14` (tests 41374810179, security-scan 41374810181)). The cache was removed; test `test_no_document_text_is_cached_in_the_process`.

<a id="ph-013"></a>
## PH-013: Administrator succession uses file modification time

- **Severity:** Low. **Evidence:** Verified.
- **Location:** [`accounts.py:276-297`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/accounts.py) (oldest by `meta.json` mtime); `:383-386` (a password change rewrites `meta.json`).
- **Description:** When the `admin` file is missing or points to a deleted account, "the oldest remaining account" becomes administrator, measured by `meta.json` mtime. A password change refreshes that mtime, so the user who changed their password most recently is *less* likely, and an arbitrary user *more* likely, to be chosen.
- **Reproduction:** [Appendix A, probe 4](TEST_EVIDENCE.md#a4). Accounts created in order admin, b, c; b changes password; admin deletes their account → administrator becomes **c**, not b.
- **Impact:** An unexpected user silently gains administrator rights (cloud and web grants, Settings); cannot read others' data.
- **Recommended remediation:** Record a creation timestamp in `access.json`, or require an explicit transfer and otherwise leave the role unassigned; write an audit event on any automatic change.
- **Regression test required:** Succession is stable across password changes.
- **Status:** Closed 2026-11-01 (CI green on public `b963e14` (tests 41374810179, security-scan 41374810181)). Accounts now carry a creation time in `meta.json`, kept across password changes; accounts made before this change still fall back to file time until their next password change. Test `test_succession_is_stable_across_a_password_change`.

<a id="ph-014"></a>
## PH-014: Transitive dependencies, spaCy model and GitHub Actions are not pinned

- **Severity:** Medium (supply chain). **Evidence:** counts Verified; impact Inferred.
- **Location:** `requirements.txt` (9 direct pins); `scripts/install.py:187` and `.github/workflows/test.yml:21` (`python -m spacy download en_core_web_lg`); workflows `uses: actions/checkout@v7`, `actions/setup-python@v7`, `github/codeql-action/*@v4` (tags, not commit SHAs).
- **Description:** The development venv has 78 installed distributions against 9 pinned direct dependencies, so about 69 transitive packages float with no hashes or lock file. The NER model is fetched without a version pin or checksum. `pytest` and `pytest-xdist` are in the runtime `requirements.txt`; `numpy` is imported by `rag.py` but not declared. Positive controls: Dependabot version updates are active, CI runs `pip-audit -r requirements.txt`, CodeQL and gitleaks (the gitleaks download is version- and checksum-pinned).
- **Attack scenario:** A compromised transitive package or model artefact executes inside the process that decrypts user documents; the in-process egress guard (PH-016) does not stop UDP, DNS or subprocesses.
- **Recommended remediation:** Generate a hash-locked file (`pip-compile --generate-hashes` or `uv pip compile`) and install with `--require-hashes`; pin the model wheel URL and SHA-256; pin Actions to full commit SHAs; split `requirements-dev.txt`; declare `numpy`.
- **Regression test required:** CI job that fails when the lock file differs from a fresh compile or when an Action is not SHA-pinned.
- **Status:** Closed 2026-11-01 (CI green on public `b963e14` (tests 41374810179, security-scan 41374810181); earlier round `fa6bb6a`): hash-locked `requirements.lock` installed with `--require-hashes`; spaCy model pinned by URL and SHA-256; every Action pinned to a commit SHA; CI job `lock` fails on lock drift or an unpinned Action; `pytest` and `pytest-xdist` moved to `requirements-dev.txt` (the lock is runtime only; `verify.sh` installs them on demand). Residual: Dependabot raises PRs against `requirements.txt` only, so the lock must be regenerated by hand (the `lock` job will say so); the pip-audit job passed but its output was not read; dev tools are pinned but not hash-locked.

<a id="ph-015"></a>
## PH-015: Repository governance gaps

- **Severity:** Low. **Evidence:** Verified with `gh api` on 2026-11-01.
- **Observed on public `main`:**
  - Required status-check context is `test`, but the workflow jobs report as `test (3.11)`, `test (3.13)` and `static`; the effect of this mismatch on merging was **not** tested.
  - `enforce_admins: false`, required approving reviews: 0, signed commits not required; the last 15 commits are unsigned (`git log --format=%G?` → `N`).
  - Secret scanning, push protection and Dependabot *security* updates are reported `disabled` for the public repo (gitleaks in CI partly compensates).
- **Recommended remediation:** Set required contexts to the real job names, enable secret scanning and push protection (no cost on public repos), consider signed commits.
- **Regression test required:** n/a (configuration); record the settings in the tracker.
- **Status:** Closed 2026-11-02. `enforce_admins` is now on for public `main` (read back from the GitHub API): a pull request, the four status checks and the owner's merge click are required, with no bypass for the owner. Accepted residual: commits are not signed and there is no independent reviewer (required approvals stay at 0 because a sole owner cannot approve their own pull request). Earlier state: Mostly fixed 2026-11-01 (settings changed by me through the GitHub API; verified by reading them back): secret scanning, push protection and Dependabot security updates enabled; required status checks changed from the non-existent `test` to the real job names `test (3.11)`, `test (3.13)`, `static`, `lock`. Not done: signed commits, required reviews, `enforce_admins` (so the owner can still push directly; deliberate for a one-person project). Risk: push protection can block a push that contains something that looks like a secret.

<a id="ph-016"></a>
## PH-016: Egress guard is in-process and covers `connect` only

- **Severity:** Informational. **Evidence:** Inferred from code; the project documents it.
- **Location:** [`egress.py:356-390`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/egress.py); `docs/SECURITY.md` ("The connection guard is Python-level").
- **Description:** `loopback_only()` replaces `socket.socket.connect/connect_ex` for IPv4/IPv6. It does not cover UDP `sendto`, name resolution (`getaddrinfo` is used to resolve the cloud host, `egress.py:340`), native extensions that open sockets directly, or subprocesses. The Claude CLI is a separate process that reaches Anthropic by design.
- **Impact:** The guard is a good tripwire for application bugs, not a barrier against malicious or compromised dependencies. The OS-level `pf` lockdown is the stronger control and is optional.
- **Recommended remediation:** Keep describing it as defence in depth; pair with PH-014 and the optional OS firewall.
- **Status:** Accepted, documented.

<a id="ph-017"></a>
## PH-017: Public threat model out of date

- **Severity:** Low. **Evidence:** Verified (`git diff 229a6b9 public/main -- docs/THREAT-MODEL.md`).
- **Description:** On public `main`, `docs/THREAT-MODEL.md` has no rows T20 to T27 (stale privacy setting, financial chunks, checker injection, stranger registration, multi-device writes, upload DoS, direct provider calls, LAN model), although `docs/SECURITY.md` and the tests refer to those threats. Row T11 still says "bind 127.0.0.1 only; PIN or token", which the code no longer does (private IPv4 bind is allowed, accounts replace the PIN). A reviewer reading only the public threat model sees fewer controls than exist and one that is wrong.
- **Recommended remediation:** Sync the private tree's threat model to public; correct T11.
- **Regression test required:** CI check that every `T<n>` cited in `docs/SECURITY.md` exists in the threat model.
- **Status:** Closed 2026-11-01 (CI green on public `aec65d4` (tests 41376563928, security-scan 41376564070)). Public `docs/THREAT-MODEL.md` now has T20 to T27 and a corrected T11; test `tests/test_docs.py::test_every_cited_threat_exists`.

<a id="ph-018"></a>
## PH-018: `/api/config` readable by every signed-in user

- **Severity:** Informational. **Evidence:** Inferred.
- **Location:** [`server.py:437-438`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/server.py), `config.current()` (`config.py:202-232`).
- **Description:** Any invited user receives the LAN Ollama addresses, the cloud URL and model name. The API key is never returned (`cloud_key_set` only). Writing is admin-only.
- **Recommended remediation:** Return a reduced object to non-administrators.
- **Status:** Closed 2026-11-01 (CI green on public `b963e14` (tests 41374810179, security-scan 41374810181)). Non-administrators get only the cloud label, provider and the remote-model warning. Test `test_other_users_see_a_reduced_config`. The settings dialog was not exercised in a browser for a non-admin; the page code tolerates missing fields by reading, but I did not run it.

<a id="ph-019"></a>
## PH-019: Log directory permissions and no tamper evidence

- **Severity:** Informational. **Evidence:** permissions Verified; remainder Inferred.
- **Location:** [`egress.py` `AuditLog.write`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/egress.py): file opened `0600` but the directory is created with default mode.
- **Observed:** `logs/` is `drwxr-xr-x`; `logs/audit.jsonl` is `-rw-------`; `logs/server.out` and `~/Library/Logs/privhybrid.log` are `-rw-r--r--`. `server.out` begins with a Python traceback and a client address; I did not review the rest of either file. The audit log holds counts, routes, hosts and timings, no text (the code and a canary test say so). It is append-only JSONL without rotation or hash chaining, so edits are undetectable.
- **Recommended remediation:** Create `logs/` as `0700`, rotate, and optionally chain hashes.
- **Status:** Closed 2026-11-02: the audit log now rotates at 10 MB and keeps 12 archives, and the hash chain continues across a rotation (`test_audit_log_rotates_and_keeps_the_chain`). Earlier state: Mostly fixed 2026-11-01 (CI green on public `aec65d4` (tests 41376563928, security-scan 41376564070)). `logs/` is created `0700`; each audit line now carries the SHA-256 of the line before it, and `egress.verify_chain(path)` finds the first edited or deleted line in the middle of the file (it cannot detect lost final lines or a rewrite of the whole file). Tests `test_log_dir_is_private`, `test_audit_log_chain_shows_an_edited_line`. Not done: rotation, the mode of an existing `logs/`, `server.out` and `~/Library/Logs/privhybrid.log`, and nothing calls `verify_chain` automatically yet.

<a id="ph-020"></a>
## PH-020: What the Claude CLI sends beyond stdin (capture run; telemetry and connector traffic found and switched off)

- **Severity:** Not rated (needs validation).
- **Location:** `_chat_claude_cli` in [`providers.py`](https://github.com/hgharsha/privacy-hybrid/blob/main/src/privhybrid/providers.py) (public `aec65d4`).
- **Re-review 2026-11-02 (code reading only):** the call is reachable only through the privacy gateway (`chat()` raises `NotSent` unless the gate is open). These code-level mitigations are **verified present in the source**:
  - the masked prompt is the only data written to stdin;
  - `--tools ""` (no tools), `--no-session-persistence` (nothing saved), `--setting-sources ""` (no settings files requested);
  - `cwd` is a fresh empty temporary directory, deleted afterwards;
  - the environment is built from an allow-list: `PATH`, `HOME`, `USER`, `LOGNAME`, `TMPDIR` (proxy variables and other secrets are not passed);
  - JSON output only; cost is reported as 0 for the subscription.
- **What these do not establish (unverified):** they are *requests to the CLI*. Nothing in the repository shows what the CLI then puts on the wire. In particular it is **not established** whether user-level memory or instructions under `~/.claude` (reachable because `HOME` is passed), plugins, MCP servers, environment details or telemetry are included in the request or sent to other hosts, and equally not established that they are not. This document makes no claim that `CLAUDE.md`, plugins or project files are transmitted. The project's `scripts/live_claude_check.py` was not run. No network capture has been made.
- **Hypothesis to test:** the bytes sent to the provider contain only the prompt text (plus the CLI's fixed system prompt), and the only hosts contacted are the provider's own.
- **Validation procedure (owner-run, macOS; the assistant cannot run it because it needs a login and sends data to a third party). Use synthetic data only and a disposable account:**
  1. **Disposable setup.** Create a standard (non-admin) macOS user `phcapture`. Sign in as that user. Install the Claude CLI for it and log in with a disposable or throwaway Claude account, never your real subscription. Install `mitmproxy` (`brew install mitmproxy`), run `mitmdump` once so it creates `~/.mitmproxy/mitmproxy-ca-cert.pem`, and do not trust that certificate system-wide; use it only through `NODE_EXTRA_CA_CERTS` below.
  2. **Canaries (all synthetic).** `echo 'CANARY-USERMEM-7f3a' > ~/.claude/CLAUDE.md`. Create `~/.claude/settings.json` containing `{"env":{"X":"CANARY-SETTINGS-2e41"}}`. Put a file named `CANARY-FILENAME-8b05.txt` in `~` and in `$TMPDIR`. Export `CANARY_ENV=CANARY-ENVVAR-5b2e` in the shell. The prompt text is `PH020-PROMPT-MARKER 4111-not-a-real-number`.
  3. **Capture.** Terminal A: `mitmdump -w ~/ph020.flows`. Terminal B, replicating exactly what the app runs (same flags, empty temp directory, allow-listed environment) and adding only the proxy variables:
     ```
     d=$(mktemp -d); cd "$d"
     printf 'PH020-PROMPT-MARKER 4111-not-a-real-number' | env -i PATH="$PATH" HOME="$HOME" USER="$USER" LOGNAME="$LOGNAME" TMPDIR="$TMPDIR" \
       HTTPS_PROXY=http://127.0.0.1:8080 NODE_EXTRA_CA_CERTS="$HOME/.mitmproxy/mitmproxy-ca-cert.pem" \
       claude -p --output-format json --tools "" --no-session-persistence --setting-sources ""
     ```
     Optionally record host-level traffic at the same time: `sudo tcpdump -i any -w ~/ph020.pcap` (shows destinations and sizes only, not content).
  4. **Positive control.** Repeat step 3 once **without** `--setting-sources ""` so you can see whether the canary detection works at all. If the canaries never appear even in the control, the capture method is not seeing content (for example the CLI pins its certificate): the result is **inconclusive**, not a pass.
  5. **Analyse.** `mitmdump -nr ~/ph020.flows --flow-detail 4 > ~/ph020.txt`, then `grep -c` each of `CANARY-USERMEM-7f3a`, `CANARY-SETTINGS-2e41`, `CANARY-FILENAME-8b05`, `CANARY-ENVVAR-5b2e`; list contacted hosts with `mitmdump -nr ~/ph020.flows --flow-detail 0`. Record the CLI version (`claude --version`), macOS version, date and the full command.
  6. **Pass criteria.** In the capture of the exact app configuration: no canary string appears; the prompt marker appears exactly as the preview shows it; every host is a provider host the owner expects. Anything else is a finding. Record the result in `TEST_EVIDENCE.md`.
  7. **Clean up.** Log out and delete `phcapture` (and its home folder), revoke the disposable account's session, delete `ph020.*`, and remove `~/.mitmproxy`.
- **Status:** Closed 2026-11-02. Owner-run capture (`scripts/ph020_capture.sh`, evidence in TEST_EVIDENCE.md section 14). The first captures found usage telemetry (to Anthropic and a third-party log service) and startup calls to the account's connectors (`mcp-proxy.anthropic.com`). Fixes: telemetry and error-reporting opt-outs, no MCP servers or connectors, and a private config folder for the app's CLI (`CLAUDE_CONFIG_DIR`, created by `scripts/claude_login.sh`). Last capture: one request in total, to `api.anthropic.com`; no canary string; control valid. Limit: the settings-file canary was not tested, and the private config folder is used only if it exists.
