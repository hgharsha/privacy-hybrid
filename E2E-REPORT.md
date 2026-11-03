# End-to-end test report

Run: 2026-11-01 06:26. Fake data only; isolated server, config and audit log.

**Browser E2E: 30/30 passed.** Unit/integration: `301 passed, 1 warning in 48.81s`.

| Area | Check | Result | Detail |
|---|---|---|---|
| Accounts | login screen shows when signed out | PASS |  |
| Accounts | register new account | PASS |  |
| Library | upload a file and list it | PASS | document.txtMoveRenameRemove |
| Library | move a file into a new folder and scope questions to it | PASS | folder Banking created, listed and selectable |
| Settings | local model panel lists installed models | PASS | 7 installed models listed |
| Settings | default values shown | PASS |  |
| Settings | outside Ollama address is refused | PASS |  |
| Settings | bad model name is refused | PASS |  |
| Settings | valid change saves to the config file | PASS |  |
| Settings | change survives a reload | PASS |  |
| Settings | switch back to default model for the chat tests | PASS |  |
| Chat | two questions sent back to back are queued and both answered | PASS | Local only / Local only |
| Chat | chat is saved in the sidebar | PASS |  |
| Memory | facts the user stated are remembered | PASS | I want to buy a house in 2028. / Priya is my sister. / Priya is moving in with me. |
| Memory | new chat starts empty | PASS |  |
| Memory | new chat recalls remembered facts | PASS | You plan to buy a house in 2028, and your sister Priya will be moving in with you.✓Youon this computer✓Local m |
| Privacy | Tier 1 data (SSN) stops and asks before sending | PASS |  |
| Privacy | audit log has counts only, no planted value | PASS | 10 audit lines |
| Session | reload keeps login and chats | PASS |  |
| Session | reopen a saved chat | PASS |  |
| Accounts | sign out returns to login | PASS |  |
| Accounts | wrong password is rejected | PASS |  |
| Accounts | sign in again; library and facts intact | PASS |  |
| Accounts | change password | PASS |  |
| Accounts | delete account removes everything | PASS |  |
| UI | theme button cycles Auto → Light → Dark and persists | PASS |  |
| UI | light and dark both render readable text (contrast > 4.5) | PASS |  |
| UI | no horizontal overflow at 320px (small phone) | PASS |  |
| UI | no horizontal overflow at phone width | PASS |  |
| UI | no JavaScript errors during the run | PASS |  |

Audit log of the run: 6 entries, routes ['local']. Counts only (checked: no SSN, name or remembered fact in it).

## Not covered
- Claude CLI route through the browser (needs the Claude CLI; covered by `scripts/live_claude_check.py`).
- Web search route (needs SearXNG).
- Packet-level capture of outbound traffic.
- Real phone / LAN access.
