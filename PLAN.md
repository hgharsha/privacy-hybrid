# Privacy-first hybrid local + cloud assistant: plan only

Date: 2026-10-27. Status: plan, no code written. Decisions from the user: personal data + web research; new project that reuses uiorchestor pieces; cloud allowed = Claude (subscription CLI) + FreeLLMAPI + web search; fail closed and ask.

## 1. Review of the pasted prompt
- Good: inspects the system first, names the right failure modes.
- Weak points:
  - Asks for everything at once (analysis, design, code, UI integration). It invites a half-built result. Split into phases with a test gate between each.
  - Assumes cloud LLMs must see redacted text. For web research that is usually unnecessary (see section 3).
  - "Local model or Presidio" is left open. Use both: regex/Presidio for structured data, local LLM only as a second-pass checker.
  - Streaming + unmasking is hard (a placeholder can be split across chunks). The prompt does not say how.
  - No pass/fail leak test defined up front.

## 2. What already exists (read-only look)
- Machine: M1 Max, 64 GB. Ollama has qwen3-coder-next, gemma4:26b, qwen3:30b, qwen2.5-coder:32b, qwen2.5:7b, llama3.1:8b, nomic-embed.
- `uiorchestor/routing.py`: ladder per stage (local -> FreeLLMAPI -> Claude CLI), caps, cooldowns, `cloud_enabled: false` until a leak test passes.
- `uiorchestor/outbound.py`: fails-closed gate. Blocks secret files/dirs, caps prompt size, masks secrets, allow-lists hosts.
- `providers.py`: Ollama, FreeLLMAPI, Claude CLI adapters.
- FinanceOS (server) already redacts/blocks cloud by design.

## 3. Why the earlier UI Orchestrator attempt likely fell short (hypotheses to verify)
- Built for source code: the gate blocks files and masks secrets one way. There is no reversible map, so nothing can be unmasked afterwards.
- No detector for names, amounts, accounts, addresses, dates of birth. Secret patterns are not PII patterns.
- The router decides by stage (plan/write/review), not by data sensitivity or by whether the task needs the web.
- Cloud stayed off, so the hybrid path was never exercised end to end.
- Mixed tasks (private file + web fact) have no defined split.

## 4. Core design idea
Do not send the user's data to the cloud at all when only a public fact is needed.

```
question + private files
   |
   v
[Local classifier]  local-only | needs-public-fact | needs-strong-model
   |
   +-- local-only -------------------------------> local model answers
   +-- needs-public-fact:
   |     local model writes a GENERIC query ("current 5-year CD rates"), no personal entities
   |     query gate checks it -> web search -> public results
   |     local model combines results with the private data           (cloud LLM never sees private data)
   +-- needs-strong-model:
         redact (reversible placeholders) -> gate -> Claude/FreeLLM -> unmask locally -> verify
```

Components:
1. **Privacy gate**: regex + Presidio (names, emails, phones, SSN, account numbers, amounts, addresses, dates), plus local-LLM second pass on the redacted output ("does anything personal remain?"). Stable placeholders per session: `[PERSON_1]`, `[AMOUNT_3]`. Map kept in memory, encrypted file only if resume is needed, never logged.
2. **Router**: rules first (file origin, tags, keywords, detected entity count), local model only for ties.
3. **Query gate**: separate, stricter check for web search text (queries leak too).
4. **Providers**: reuse uiorchestor `providers.py` (Ollama, FreeLLMAPI, Claude CLI). Optionally LiteLLM later; not needed now.
5. **Unmasker**: replace placeholders in the final text; if the cloud invented or dropped a placeholder, flag it rather than guess. For streaming, buffer until a placeholder closes (`]`), then flush.
6. **Orchestration**: small explicit state machine (classify, redact, gate, call, unmask, verify, answer). Not LangGraph at first; fewer moving parts and easier to audit.
7. **Fallback**: cloud error or gate block -> local answer with a visible notice; never retry with weaker redaction.
8. **Logging**: log only placeholder-form text, entity counts, route, provider, latency. Raw prompts never written to disk.

## 5. Web search options you can use (pick one primary)
| Option | Cost | Privacy | Note |
|---|---|---|---|
| SearXNG self-hosted (Docker on server or mini) | free | best: queries go out under your IP, no account | meta-search, quality varies; recommended default |
| Claude CLI built-in web search | subscription | query goes to Anthropic | easy; only after the query gate |
| Brave Search API | free tier, limits change, verify | account tied to key | clean JSON, good for agents |
| Tavily / Exa | free tier, verify | account tied to key | built for LLM agents, returns extracted text |
| Perplexity Sonar API | paid per call | sends query to Perplexity | strongest answers; add only if SearXNG is not enough |

Recommendation: SearXNG first, Claude CLI search as the fallback. Verify current free-tier limits before relying on any of them.

## 6. Phases (each ends with a test gate; nothing proceeds on a fail)
0. **Decide** the open questions in section 8.
1. **Project skeleton + threat model** (what must never leave: list of entity types). No cloud.
2. **Privacy gate alone**: redact/unmask round trip on a test corpus of fake statements. Gate: 100% of planted entities masked, 100% restored.
3. **Local-only pipeline** with router and logging. Gate: log scan finds zero raw entities.
4. **Public-fact path**: query writer + query gate + SearXNG. Gate: 20 mixed questions, no personal entity in any outbound query.
5. **Cloud path** with Claude CLI, then FreeLLMAPI (strictest mode). Gate: leak test using a canary string; capture outbound traffic (proxy/tcpdump) and confirm it is absent.
6. **Streaming + tool calls + fallback**. Gate: kill the network mid-run, answer degrades to local.
7. **Interface**: web UI (decided), started in phase 3 and extended each phase. Also expose an OpenAI-compatible endpoint if cheap.

## 7. Verification that data never left
- Canary tokens in test data (fake SSN, unique name), grep outbound captures and logs for them.
- All cloud calls go through one function; a test asserts no other network egress from the process (allow-list hosts, as `outbound.py` already does).
- `mitmproxy` or `lsof -i`/`tcpdump` during the phase 5 run.
- Fake data only for tests; no real statements until phase 5 passes.

## 8. Decisions (2026-10-27)
- Independent project: copy `outbound.py` and `providers.py` from uiorchestor, do not import them. Changes there are not auto-synced; note the copy date in the file header.
- FreeLLMAPI receives fully generic text only (no amounts, names or ids, even as placeholders).
- Runs on the M1 Max only for now. No mini/server deploy, no Docker changes on them.
- A web UI is needed: small vanilla HTML/JS page (same no-build style as uiorchestor) served locally on 127.0.0.1, with chat, a route/redaction badge per message, a "what was sent" viewer (placeholder form), and an approve/deny dialog for fail-closed asks. This replaces phase 7's "decide later": the UI starts in phase 3 against the local-only pipeline and grows with each phase.

PII definitions live in PII-STANDARD.md (name, phone, DOB, SSN, bank accounts, transactions, and more, in four tiers). Review it; edit the user dictionary list when we start phase 1.

## 9. Out of scope for now
Any implementation, Docker changes, or installing Presidio/SearXNG.

## 10. Later (owner requests, 2026-10-27)
- **Private only:** the GitHub repo stays private. Never make it public; never publish the UI to the internet (no Funnel, no port forwarding).
- **Phone-optimized UI:** the current page is responsive but not tuned for phone. To do: larger touch targets, bottom-anchored composer, collapsible file/mode drawer, file upload from the phone camera roll/Files app, offline-safe PIN entry, add-to-home-screen icon.
- **Safer phone access:** today's phone access is the plain-HTTP home Wi-Fi exception below. Replace it with Tailscale (tailnet-only HTTPS via `tailscale serve`, loopback bind kept) when approved. Needs: install Tailscale on this Mac and the phone, allow the tailnet hostname in the Host check, set cookies `Secure`.
- Remaining gaps: see VERIFY.md (provider-terms review, Claude CLI packet capture, relative dates, OCR, over-masking).
