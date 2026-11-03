# Verification: threat model T1-T13

Run everything: `./scripts/verify.sh` (tests, log scan, LAN-bind check, map-not-on-disk check). All data is fake.
Live checks (need Ollama gemma4:26b, SearXNG, Claude CLI): start the server, then `scripts/live_e2e.py` (account `livetest@example.com`).

| # | Control | Status | Proof |
|---|---|---|---|
| T1 | Regex+checksums, Presidio large model, user dictionary, local-LLM second pass, fail closed | Done | `tests/test_detect.py`, `tests/test_corpus.py` (all planted Tier 1-3 values), `test_local_ingest_search.py::test_claude_route_requires_the_local_check` |
| T2 | Combination rule (zip+date, place+employer, dob+place) | Done (basic) | `test_detect.py::test_quasi_identifier_flag` |
| T3 | Audit log: route, outcome, counts only; server request logging off | Done | `test_egress.py::test_audit_log_has_no_raw_values`, `verify.sh` step 2 |
| T4 | Query gate + local rewrite + SearXNG on 127.0.0.1 | Done | `test_local_ingest_search.py` (query gate, search), live "auto" flow in `live_e2e.py` |
| T5 | Unmasker flags unknown placeholders, never guesses | Done | `test_vault.py::test_unknown_placeholder_is_flagged_not_guessed` |
| T6 | One exit (`egress.send/search/probe`), loopback-only addresses, socket guard, static call-site test | Done, with one limit | `test_egress.py` (wrong destination, guard, call sites). Limit: the Claude CLI is a separate process; only reachable via `send()` |
| T7 | Web text fenced as untrusted, map never in a prompt, unknown placeholders flagged | Done | `test_corpus.py::test_injection_text_cannot_extract_map`, `test_pipeline.py::test_untrusted_web_text_is_fenced` |
| T8 | Map in memory only: no pickle/copy/repr | Done | `test_vault.py::test_map_cannot_be_saved_or_printed`, `verify.sh` step 4 |
| T9 | Buffer until `]` | Done for the unmasker; providers here do not stream | `test_vault.py::test_stream_split_anywhere_is_safe`. The UI streams the already-restored answer |
| T10 | Fallback is local only, one cloud try | Done | `test_egress.py::test_fallback_is_local_only...`, `test_pipeline.py::test_cloud_failure_degrades_to_local_only` |
| T11 | 127.0.0.1 bind, email + password accounts, encrypted per-user storage, lockout, Host/Origin/CSRF checks, CSP | Done | `tests/test_server.py`, `verify.sh` step 3 |
| T12 | Claude: masked only; FreeLLM: generic only; others refused | Policy enforced. Provider terms review is manual and still open | `test_egress.py::test_freellm_only_generic_text`, `test_wrong_destination_refused` |
| T13 | Local text extraction (txt/csv/json/pdf/docx), metadata never read, filename scan, images refused | Done | `test_local_ingest_search.py` intake tests |

## Live results (2026-10-27, fake statement)
- local: answered on the Mac only.
- auto: routed to local + web facts; only a generic query left (SearXNG), gemma combined results with the file.
- claude: dense file summarized locally, masked, re-checked, local privacy check passed, Claude answered, values restored.
- SSN in the question: stopped before any send, approval dialog offers "run locally".
- 9 audit/server log lines scanned: no planted value.

## Known gaps and choices
- Dates become `[DATE_n]` (reversible) instead of relative/month-only. Stricter than the standard, less useful for date math.
- Presidio over-masks unusual words (fails safe).
- No packet-level capture of the Claude CLI's own traffic (needs root); we prove what is handed to it.
- Scanned PDFs and images are refused (no OCR).
- The `check_host` helper copied from uiorchestor still allows LAN hosts but nothing calls it.
- Merchants are only caught via the dictionary file or NER.
- Second pass costs about 5-30 s on the local model per Claude request.

## Phone on home Wi-Fi (exception)
`PRIVHYBRID_ALLOW_HTTP=1 PRIVHYBRID_BIND=<Mac LAN IP> PYTHONPATH=src .venv/bin/python -m privhybrid.server`, then open `http://<that IP>:8765` on the phone (same Wi-Fi). Stop with `pkill -f privhybrid.server`. Back to Mac-only: omit the variable.

## Run it
```
scripts/start_searxng.sh                     # once; Docker, bound to 127.0.0.1:8888
PYTHONPATH=src .venv/bin/python -m privhybrid.server   # then open http://127.0.0.1:8765 ; register on first visit
```
Your own terms (names, employer, accounts, merchants) go in `state/dictionary.txt`, one `KIND: value` per line (KIND is PERSON, ORG, ACCOUNT, MERCHANT, ...).
