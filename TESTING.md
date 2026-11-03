# Try it: test cases (fake data only)

Open the UI, register with an email and password (first visit), then sign in. Mode choices: Auto, Local only, Local + web facts, Claude (masked). After each answer, open "What happened" and the badge to see the route.

| # | Mode | Type this | Expect |
|---|---|---|---|
| 1 | Auto | `What is 15% of 240?` | Badge "Local only". Nothing leaves the Mac. |
| 2 | Auto | `What are current 5-year CD rates?` | Badge "Local + web facts"; steps show a generic query and search results; "Sources" lists links. |
| 3 | Auto | `My neighbour Dana Whitfield lives at 10 Example Street, phone (415) 555-0171. Draft a short thank-you note.` | Local only (private detail present, so it stays on the Mac). |
| 4 | Claude (masked) | `Draft a polite email to Jane Doe (jane.doe@example.com) about the $4,250.00 invoice due 10/15/2026.` | Badge "Claude (masked)"; reply shows the real name, email and amount restored. Steps: masked and re-checked, local privacy check passed. |
| 5 | Claude (masked) | `My SSN is 123-45-6789, remember it.` | Dialog "Stopped before sending", SSN x1. Nothing sent. "Run locally" answers on the Mac. |
| 6 | Claude (masked) | `Charge card 4111 1111 1111 1111.` | Stopped, CARD x1. |
| 7 | Claude (masked) | `Here is my password: hunter2hunter2` | Stopped, SECRET x1. |
| 8 | Claude (masked) | `routing number 021000021 and account number 123456789012` | Stopped (ROUTING, BANKACCT). |
| 9 | Local + web facts | `Is a 4.5% savings rate good right now?` | Web steps run; answer cites sources. |

## With a file
Add `samples/maria_statement.txt` (fake; on the Mac, or save its text as a .txt on your phone).
| # | Mode | Type this | Expect |
|---|---|---|---|
| 10 | Local only | `How much did I spend at the bistro, and what is the payroll deposit?` | $87.43 and $12,480.55, local only. |
| 11 | Auto | `Compare my savings transfer to current 5-year CD rates.` | "Local + web facts"; your file stays on the Mac. |
| 12 | Claude (masked) | `Summarise this statement in two sentences.` | Steps: "summarized ... locally", masked, privacy check passed, Claude answered. Takes about a minute. |
| 13 | any | Add a photo or `.png` | Error: only text, CSV, JSON, PDF with text, DOCX. |
| 14 | any | Name a file `report_for_123-45-6789.txt` and add it | Listed as `document.txt` (personal detail in the name was dropped). |

## Controls
- **Audit log** button: only routes, outcomes and counts such as `"EMAIL": 1`. No text. Check after test 4.
- **New session** clears files, chat and the placeholder memory.
- **Remove** next to a file drops it from the session.
- Five wrong passwords lock that email, or that address, for a minute.
- "Cancel" in the stop dialog sends nothing anywhere.

## Things that are expected
- Claude mode is slow (about 1 min): local summary, local check, then Claude.
- Odd words may get masked (the detector errs on the safe side).
- Dates show as the original date in the answer; they were placeholders only while the text was out.

## Accounts, library and memory (new)
- A. Register `a@example.com`, upload `samples/maria_statement.txt`, sign out, sign in again: the file is still listed.
- B. Register a second user: they see no files and no chats from the first.
- C. Ask "I prefer paying bills on the 5th." Open a New chat and ask "When do I like to pay bills?": the answer should use what you said earlier.
- D. Delete that chat, ask again: it no longer knows.
- E. Say "My SSN is 123-45-6789" in a chat: it stays in the chat but is not learned.
- F. Say "I want to buy a house in 2028 and my sister Priya is moving in." Wait ~20 s: "What I remember" lists the facts. In a New chat ask "What are my plans?": it answers from them. Click Forget on one and ask again.
- G. Untick "Remember", say "I own a boat", wait: nothing new under "What I remember".
- H. Account > Change password; sign out and in with the new one. Account > Delete account: sign-in with that email no longer works.
- I. Send two questions quickly: the second shows "queued…" then runs. Enter sends, Shift+Enter adds a line.

## Automated testing
- **Unit/integration (no Ollama needed, fake data):** `.venv/bin/python -m pytest -q` (189 tests: detectors, vault, egress, corpus, pipeline, server, accounts).
- **One command, includes leak checks on logs/state and LAN-bind check:** `sh scripts/verify.sh`.
- **Live check with the real local model and Claude CLI:** `PYTHONPATH=src .venv/bin/python scripts/live_e2e.py` and `scripts/live_claude_check.py`.
- **Everything in one go (unit tests + isolated server + 26 browser checks + report):** `PW=<path to playwright-core/index.mjs> sh scripts/run_e2e.sh` writes `E2E-REPORT.md`. Needs Ollama, Chrome. Uses a temp data dir, config and audit log.
- **Old manual browser walk-through:** start the server, then `PW=<path to playwright-core/index.mjs> node scripts/browser_e2e.mjs`.
- **CI:** `.github/workflows/test.yml` runs pytest on every push and PR.
- **Add a case:** put the fake value in `tests/corpus.py`; `test_corpus.py` then checks it is masked on the wire, restored in the reply, and absent from the audit log.
