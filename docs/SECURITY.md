# Security and deployment guide

Date: 2026-11-01. Read with [THREAT-MODEL.md](THREAT-MODEL.md) and [../PII-STANDARD.md](../PII-STANDARD.md). This describes what the code does and what it does not. It is not a guarantee: no test suite proves the absence of a leak.

## What leaves the computer, by mode

| Mode | Raw documents and questions | Masked text | Web | Notes |
|---|---|---|---|---|
| **Local only** (Local, or Auto with no web wording) | stay on this computer, sent to the local model only | n/a | none | The model may run on a listed private-network machine (see "Trusted LAN model"). |
| **Trusted LAN model** | go to the Ollama machine(s) you listed in Settings, over plain HTTP unless you tunnel | n/a | none | Unencrypted on the LAN. Use a computer you control; prefer SSH, WireGuard or Tailscale. Settings shows a warning while any remote address is set. |
| **Web facts** (Local + web) | stay local | n/a | a short generic query written by the local model and checked for personal detail; results come back as untrusted text | Never your files. A query with personal or financial detail is stopped. |
| **Sanitized cloud** (Claude, or a cloud model you configured) | never | masked placeholders only, after the Tier 1 stop, re-check and the local model check. A financial document is replaced by a local summary: counts, rounded totals, category shares and month totals, with no merchants, descriptions, dates or row amounts. | none | The provider sees the masked text and has its own retention terms. A cloud failure falls back to the local model, never to a weaker cloud route. |
| **Extreme privacy** (per-account switch) | stay local | nothing | none | No cloud, no web search, no scheduled web jobs. Read from the account's stored setting immediately before every send, on every device, background task and retry. If the setting cannot be read, cloud and web stay blocked. The local model (including a listed LAN machine) still works. |

A request already handed to a provider when Extreme privacy is switched on elsewhere completes; the next one is blocked. The Claude CLI is a separate process and cannot be recalled once started.

## Controls in this release

- **Account-wide policy.** `policy.py` reads the stored setting each time; `egress.send`, `egress.search`, scheduled jobs and retries all ask again before transmitting.
- **Financial documents.** Recognised at intake (`finance.py`), before chunking, from the filename, column names, statement wording and dated amounts; length and row count are not factors. A document that looks financial but cannot be parsed stays on this computer. Direction of unsigned amounts in a text statement is inferred (balance change, then wording) and may be wrong; totals are rounded to three figures.
- **PII policy.** `src/privhybrid/pii_policy.json` is checked against the detector and `PII-STANDARD.md` by tests.
- **Registration.** The first account is the administrator (optionally protected by `PRIVHYBRID_SETUP_TOKEN`). Afterwards an account needs an invitation code, an administrator-created account, or `PRIVHYBRID_REGISTRATION=open` / the open setting. Existing installs: every existing account keeps all it could do, recorded in `access.json`; registration becomes invitation-only.
- **Permissions and limits** (local model, cloud, web, upload, library, scheduled, admin): new accounts get local, upload and library only. Per account: questions per minute, uploads per minute, cloud requests per day, storage. Counters are in memory and reset on restart.
- **Admin API** (no UI yet): `POST /api/admin/invite`, `/user/create`, `/user/access` (permissions, limits, disable), `/registration`, `/transfer`; `GET /api/admin/users`.
- **Storage.** One shared copy of each account's data for all its devices; every file is saved against the version it was read at, and a changed file is refused (HTTP 409), never overwritten. A password change holds all writes while it re-encrypts.
- **Network.** Cloud names must resolve to public addresses only (IPv4 and IPv6, mapped addresses included) and the connection is pinned to the vetted address; redirects are refused; providers other than the local model refuse to run unless called through `egress.send`. The Claude CLI gets the masked prompt on stdin, no tools, an empty working directory and a minimal environment; its error output is never shown.
- **HTTP.** 30 s silence limit per connection, 64 simultaneous connections, 8 MB bodies, a bounded background pool of 4, archive members read with a hard size cap, entity definitions in spreadsheet XML refused.

## Limits you should know about

- The connection guard is Python-level. It is not an operating-system firewall; other processes on the computer are not constrained by it. Use the system firewall.
- The local checker is a model and can be wrong. The deterministic detector is the primary control; the checker only adds a layer. A small checker (under 14B) misses more.
- The detector is pattern and NER based: names and employers outside its patterns, free text in unusual formats and non-English text can be missed. A cloud send is refused when 10% or more of the letters are in scripts the detector cannot read (CJK, Arabic, Hebrew, Indic, Thai, Hangul), so such text stays on this computer.
- Anyone who can read the computer's disk while you are signed in, or your password, can read your data. There is no password recovery.
- The administrator can change cloud settings and permissions but cannot read other accounts' files.
- LAN traffic is plain HTTP unless HTTPS (`--tls`) is on. Never expose the port to the internet.

## Deployment recommendations

1. Install with `--tls` and `--bind <LAN IP>`; trust the certificate on each device; turn on the system firewall.
2. Set `PRIVHYBRID_SETUP_TOKEN` before the first visit if the link is reachable by others.
3. Keep registration on invitation; grant cloud only to people you trust (it spends your subscription or API budget); lower `cloud_per_day` for others.
4. Use a checker model of 14B or larger.
5. If the model runs on another machine, tunnel to it.
6. Run `scripts/security_check.sh` after changes. Update dependencies; `pip-audit` reports known issues.


## Review before sending to the cloud

If the filter is unsure about something it cannot mask (digits spelled out as words, a long number left in the text, words such as passport or account number), the preview appears even when Review is off and needs a second tick, "I checked it and still want to send it". This is a safety net for accidents, not a lock: it is heuristic, scheduled jobs cannot ask, and nothing here can stop a person who deliberately sends their own data.

By default every cloud send is shown to you first: a dialog lists the exact masked text and the destination, and nothing is sent until you press Send. Don't send, closing the dialog, Stop, or no answer within five minutes all mean no, and the question is answered on this computer. The setting is under Settings (Review before sending to the cloud) and is stored per account. Extreme privacy and the permission checks still run after you approve. Scheduled jobs have nobody to ask and are not previewed; they only run for accounts that opted in.

## Known-values check

Before a cloud send, every value this account is known to hold (ones masked earlier in the session and the dictionary of your own terms) is searched for in the outgoing text, ignoring case, spacing, punctuation, zero-width characters and full-width forms. A hit stops the send. It does not catch look-alike letters from other alphabets, and values shorter than four characters are skipped.

## Advanced: network lockdown outside the app (optional, done by whoever runs it)

The app's own checks stop it sending data out, but they run inside Python. A bug or a dependency that opens its own connection would not be stopped by the operating system. For the strongest protection, add a rule outside the app. This needs no change to the app's code: it is a setup step on the computer, and it is up to the person running it whether to do it.

- **macOS:** run the service as a dedicated user and add a `pf` rule for that user. Allow only this computer, the Ollama and SearXNG addresses you listed, and the cloud endpoints you use.
- **Container:** run the service with a network policy that allows the same list.
- **Extreme privacy:** the in-app switch cannot change an operating-system rule. For a hard guarantee, run a second copy of the service with no internet access at all and use that one for Extreme privacy.

Without this step, the in-app guard is the only barrier. It is a strong one for the app's own code paths, but it is not an operating-system guarantee.

## V3 changes (2026-11-01)

**Financial material is recognised from its content.** `finance.concept_signals` flags unstructured notes (401(k), IRA, Roth, HSA, brokerage, tax return or transcript, mortgage, loans, account balances, net worth, asset allocation, RMDs, foreign accounts and similar) on the extracted text, so a generic filename does not hide it. One strong term is enough, even in a one-line note. Common words such as "salary" or "balance" count only with an amount or with other such words, so a recipe with prices is not flagged. A flagged document with no readable transaction table has no summary and stays on this computer. A document that mixes financial and ordinary text is treated as financial as a whole (safer, but it also keeps the ordinary part local). Some ordinary uses of words like "stock" or "bonds" will be flagged; that is the cost of failing closed. A file that cannot be read at all (for example a scan without a text layer) is refused at upload: it is neither stored nor sent.

**What a financial summary may contain.** Rounded totals (income, spending, net), the reporting period, category totals and shares, and a closing balance, only for categories and months with at least three transactions. Merchants, descriptions, individual amounts and dates, and account numbers are never included. The summary still goes through the normal masking and the Tier 1 stop; tests check that the aggregates survive and that rows do not.

**Approval policy.** The Review preference applies to ordinary cloud requests. A request that involves a financial document is always shown first and needs a yes, whatever the preference says. Without a way to ask (scheduled jobs) a financial document is never sent. Tier 1 data is never sent, approved or not. Extreme privacy overrides everything. No answer within five minutes, Stop, or closing the dialog all count as no. The dialog shows the exact outgoing text and the destination.

**Local Ollama and remote Ollama.** A model on this computer (127.0.0.1) always works. A model on another computer must be listed in Settings by the administrator, sends questions and whole documents across your network (plain HTTP unless tunnelled), and is refused while Extreme privacy is on, or always when `PRIVHYBRID_LOCAL_ONLY=1` is set. If the policy cannot be read, the app treats it as on.

**Application controls versus operating-system isolation.** Extreme privacy and the connection guard are checks inside the app. They do not stop other programs on the computer, and they are not a firewall. For operating-system enforcement use `scripts/lockdown.sh` (macOS, one user, `pf`): `plan` shows what it would do and changes nothing, `on` and `off` need `sudo`, the rule is not saved and disappears on reboot, and it refuses to restrict the account you are using. The administrator can request `on` from Settings on the computer where the app is installed; macOS shows its own password dialog and the app never sees the password; the result is "requested", not verified. Turning it off is a terminal step. If you run the app as your own user, the helper protects nothing; it is meant for a separate user that runs the app. Containers and Linux are described above and are not automated.

**Strict local-only deployment (supported).** For the strongest local-only setup, run the app as a dedicated, non-administrator macOS user (default `phsvc`) and load the operating-system rule with `scripts/lockdown.sh on phsvc`. That user can then reach only this computer (127.0.0.1 and ::1): the local model, and nothing else. The cloud, web search and any other network destination are blocked by the operating system itself, so even a bug or a dependency that opens its own connection cannot send data out. Combine it with Extreme privacy in Settings so the app also answers everything locally. Setup: create the user, install and run the app under it, check with `scripts/lockdown.sh plan phsvc`, then `sudo scripts/lockdown.sh on phsvc`; `status` shows the rule and `off` removes it. Limits: the rule is not saved and disappears on reboot; it restricts only that user; the script refuses system accounts, the account running `sudo` and the user logged in at the console; and cloud and web modes do not work for that user while it is on. This is optional and is not the default setup.

**Storage locking.** Account saves, registrations, administrator changes, permission records and password changes take a file lock (`flock`), so two processes cannot interleave a write; a stale version is refused. Lock order is the store lock, then one account lock. A lock that cannot be taken in 15 seconds fails with an error instead of waiting forever. A killed process releases its lock automatically. A password change keeps a backup and a marker; if the process dies half way, the next start rolls the account back to the consistent earlier state (the old password works). Limits: macOS and Linux only; network file systems may not honour `flock`; prefs and scheduled-job files still use in-process locks.

**Administrator.** Only the id in the `admin` file has administrator rights; a stored flag on any other account is ignored and cleaned up at start. A transfer updates both records in one step under the lock, so there is never more than one administrator. A disabled account has no permissions. If the `admin` file is lost, the oldest account becomes administrator.

**Recovery.** Lost `admin` file: restart; the oldest account takes over. Interrupted password change: restart; the account is rolled back and the old password works. Stale lock files in the data folder are harmless and can be deleted when the app is stopped.

- Passwords are stretched with scrypt (N=2^16, r=8, p=2, stored per account; older accounts are upgraded at their next sign-in). The audit log chains each line to the hash of the one before it (`egress.verify_chain`), which shows edits in the middle of the file, not a rewrite of all of it.
