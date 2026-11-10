# Setting up privacy-hybrid (for AI coding agents: Claude Code, Codex and similar)

Goal: install the assistant on this computer, check that it works, and report. Do the steps in order and stop to ask the person only where marked **ASK**.

1. **Check the basics.** Python 3.11 or newer (`python3 --version`), a Mac or Ubuntu (Windows 11 was run once: use `.venv\Scripts\python.exe`; files are not owner-only there and `verify.sh` is Unix-only), and Ollama (`ollama --version`; if missing, tell the person to install it from https://ollama.com, do not try to install it yourself). The local model is served by Ollama (tested). LM Studio, llama.cpp, vLLM and other OpenAI-compatible servers have experimental support that has never been run against a real server: choose "OpenAI-compatible" under Settings > Local model server (or set `PRIVHYBRID_LOCAL_RUNTIME=local_openai`) and point the address at the server (`http://127.0.0.1:1234`, no `/v1`; it adds `/v1` itself). It needs a chat model and an embeddings model loaded in that server. Tell the person it is untested and offer Ollama instead; if it fails, report the exact error rather than editing the code. Fixes are welcome as a pull request (see CONTRIBUTING.md). Run from the repository root.
2. **Models.** Run `ollama list`. If `gemma4:26b` or `nomic-embed-text` is missing, **ASK** before pulling (the first is about 17 GB), then `ollama pull <name>`. A smaller chat model works too: set it later in Settings.
3. **Preview, then install.** `python3 scripts/install.py --dry-run`, read the output, then `python3 scripts/install.py`. It needs no sudo. Do not add `--bind`, `--tls` or `--scheduler` unless the person wants phone or LAN access (**ASK**; see the README section "Let other people and devices on your network use it").
4. **Verify.** Run `./scripts/verify.sh` (tests and privacy checks, fake data only). Then check `curl -s http://127.0.0.1:8765/` returns the page. Report any failing step with its output.
5. **Hand over.** Tell the person to open the "Private Assistant" app (or http://127.0.0.1:8765/), register an account (the first account is the admin), and try `TESTING.md`.

Rules:
- Never put secrets, passwords or API keys in files, commits or chat. Do not read `state/`, `logs/` or any account data.
- Do not open firewall ports, change router settings, use sudo, or make any repository public.
- Do not send anything to a cloud model: the cloud route is off until the person adds a key in Settings.
- Speech to text downloads a small Whisper model (about 460 MB) the first time the microphone is used. Mention it, do not trigger it.
- Uninstall is `python3 scripts/install.py --uninstall` (data in `state/` stays).
