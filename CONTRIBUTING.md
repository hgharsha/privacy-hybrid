# Contributing

Pull requests are welcome, especially from people running setups the author cannot test.

## Untested areas (good first contributions)
- **Local model servers other than Ollama** (LM Studio, llama.cpp, vLLM): chat and embeddings go to `/v1/chat/completions` and `/v1/embeddings`. This was written against a stand-in server in `tests/test_local_openai.py` and has never run against a real one. If you try it, please report what worked or open a pull request with the fix.
- Windows install, the cloud route with a real API key, other Linux distributions.

## Rules that must not loosen
- Anything leaving the machine goes through `egress.py` and is checked there. Do not add another way out.
- No secrets, personal data or real documents in code, tests, samples or docs. Test data is fake.
- The local model must stay on this computer or a private-network address listed in Settings.

## How to send a change
1. Fork, create a branch, make the change.
2. Run `python -m pytest -q` (all tests must pass).
3. Open a pull request that says what you tested and on which machine and server.

Using your own AI agent (Claude Code, Codex) on your fork is fine; follow `AGENTS.md`.
