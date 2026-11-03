# Threat model (phase 1)

Date: 2026-10-27. Scope: M1 Max only. Data classes: see ../PII-STANDARD.md.

## Assets
- Raw tier 1-3 values (statements, IDs, names, amounts).
- The placeholder map (placeholder -> real value).
- Prompts and answers in raw form.

## Trust boundaries
| Zone | Trusted with raw data? |
|---|---|
| Browser UI on 127.0.0.1 | yes |
| Gateway process (this project) | yes |
| Ollama on this Mac (127.0.0.1:11434) | yes |
| Claude CLI / Anthropic | redacted tier 2-3 only; never tier 1 |
| FreeLLMAPI (localhost gateway, then third-party free providers) | generic text only (tier 4) |
| Web search (SearXNG, others) | generic query only |
| Disk: logs, state, caches | no raw values |

## Threats and controls
| # | Threat | Control | Test (phase) |
|---|---|---|---|
| T1 | Entity missed by detector, sent raw | layered detection, local LLM second pass, fail closed | corpus, 100% planted entities (2) |
| T2 | Re-identification from quasi-identifiers | combination rule in standard | corpus (2) |
| T3 | Raw data in logs | log placeholder form only, counts, route | log scan for canaries (3) |
| T4 | Raw data in web query | separate query gate, local rewrite to generic text | 20-question set (4) |
| T5 | Cloud echoes or invents placeholders | unmasker flags unknowns, never guesses | unit tests (2) |
| T6 | Non-gated egress (a library calls out) | one egress function, host allow-list, test asserts no other sockets | egress test (5) |
| T7 | Prompt injection in web results or files makes the model leak data | web text treated as untrusted; no tool can read the map; output re-checked by gate before display of any outbound call | injection set (5) |
| T8 | Placeholder map stolen from disk or memory dump | memory only; if saved, encrypted with key in Keychain | review (6) |
| T9 | Streaming splits a placeholder, partial leak or bad unmask | buffer until closing bracket | stream tests (6) |
| T10 | Fallback retries with weaker redaction | fallback is local-only; no retry path to cloud | unit test (6) |
| T11 | UI exposed on LAN | binds 127.0.0.1 by default; a private LAN address needs HTTPS (or `PRIVHYBRID_ALLOW_HTTP=1`); per-user accounts, setup code for the first account from another machine, Host/Origin checks, no CORS | check `lsof` (3); tests/test_bind.py; tests/security/test_multiuser.py |
| T12 | Cloud provider retains or trains on data | Claude subscription terms reviewed; FreeLLM gets tier 4 only | manual review (5) |
| T13 | Uploaded file hides PII (PDF image, metadata, filename) | extract text locally, strip metadata, scan filenames | corpus (2) |
| T14 | Scheduled jobs: malware as the same user reads the Keychain key and forges or reads job data | opt-in per account and by env switch (off by default); results sealed to the account key, so only the password opens them; MAC marks forged items "Unverified"; replay counter | tests/test_schedule.py; accepted residual risk |
| T15 | Scheduled job sends private data out | web jobs get no files; local jobs read one folder copy; Claude is never used; a tier 1 hit in question or answer fails the run | tests/test_schedule.py |
| T16 | Keychain item or login keychain file copied (disk, Time Machine) | needs FileVault and a strong Mac password; turning jobs off deletes the key, jobs, folder copy and unopened results | design note, honest limits |
| T17 | Old result file put back from a backup | per-result sequence number, replays rejected at sign-in | tests/test_schedule.py |
| T19 | Ollama on another machine (Settings: address and backups): questions and file text cross the network unencrypted; a wrong address sends them to the wrong host | admin-only setting; only literal private-network IPs (10/8, 172.16/12, 192.168/16, fc00::/7) or this machine, no names, no credentials, no paths; the connection guard allows exactly those host:port pairs and nothing else; the free-model gateway stays loopback-only; exactly scheme://IP:port with port 1024 or higher (no fragment, params, list separators); failover only when a machine cannot be reached within 3 s, never on a timeout, error or missing model, never to cloud; the answering machine (host:port, no text) is written to the activity log | tests/test_config.py; residual: plain HTTP only with `PRIVHYBRID_ALLOW_HTTP=1` and an unauthenticated Ollama on the other machine (T11) |
| T20 | Privacy setting stale in a second device or background task, so a cloud or web request leaves after Extreme privacy was switched on | one stored setting read from disk before every send; unreadable counts as on; a preferences write merges into the stored copy | tests/security/test_extreme_privacy.py (real requests at mock services) |
| T21 | Small statement or RAG chunk of a bank file reaches a cloud as rows | classified at intake before chunking; cloud gets a local aggregate summary only; unparseable financial documents stay local | tests/security/test_financial.py (final request body) |
| T22 | Document text talks the local checker into approving a leak, or the checker fails | checker input fenced and treated as data; anything but NONE or a short list blocks; Tier 1 and masking are deterministic and independent of the checker | tests/security/test_second_pass.py |
| T23 | Stranger registers on a shared link; one user spends the owner's cloud budget or reads another's data | invitation-only registration; per-user permissions (cloud off by default) and quotas; per-account encryption | tests/security/test_multiuser.py |
| T24 | Two devices of one account overwrite each other, or a worker writes with an old key | one shared state per account; versioned writes refuse stale copies; password change holds writes | tests/security/test_multiuser.py |
| T25 | Slow client or oversized/hostile upload ties up the server | socket timeouts, connection cap, body cap, bounded pool, capped archive reads, entity-free XML | tests/security/test_http_limits.py |
| T26 | A code path calls the Claude CLI or a cloud API directly | providers refuse to run outside `egress.send` | tests/security/test_network.py |
| T27 | Local network model reachable by others, traffic readable | warning in Settings; explicit admin setting; residual: plain HTTP only with `PRIVHYBRID_ALLOW_HTTP=1` | tests/security/test_network.py; accepted residual risk |
| T18 | Third-party cloud model chosen in Settings (not Claude): provider keeps or trains on the masked text, key stolen, address pointed at an internal service | same masking, Tier 1 stop and local re-check as the Claude route; one https address the admin entered, resolved to public addresses only, reachable only during a request; key in the system keychain, never in config or logs; per-answer notice and Settings warning; marked untested with real providers | tests/test_cloud.py (local stand-in only); provider terms review (T12) per provider |

## Out of scope (accepted)
- A compromised Mac or malicious local process.
- Anthropic or free providers misusing correctly redacted text.
- Legal compliance certification.

## Phase 1 exit criteria
- [x] Skeleton, copied gate and provider code in place.
- [x] Threat list written.
- [x] Copied outbound tests pass in this project (33 passed). Removed 2026-10-31: the copy was never used; egress.py is the only exit.
- [~] Tier assignments: conditionally approved 2026-10-27, owner review pending. Threat list: confirmed to proceed.

## Exception: phone on home Wi-Fi (2026-10-27, owner request)
`PRIVHYBRID_BIND=<private LAN IP>` binds the UI to one private address (never 0.0.0.0, never a public IP). Still required: PIN, lockout, Host/Origin/CSRF checks. Residual risk (T11): plain HTTP, so anyone on the same Wi-Fi can read the traffic, unless local HTTPS is on (`scripts/install.py --tls`: private CA, key discarded, Secure cookie, HSTS). Use on a trusted home network, run it only while needed, stop it afterwards. Default stays 127.0.0.1. Replacement planned: Tailscale (PLAN.md section 10).


Scheduled jobs (opt-in, 2026-10-31): see SCHEDULED-JOBS-DESIGN.md for the key design and its limits.
