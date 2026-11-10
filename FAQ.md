# FAQ and known limits

Based on the code. Nothing here needs real data; all examples are fake.

## Asking questions

**Can I ask a second question while the first is running?**
Yes. Type the next question and send it. It shows "queued…" and runs as soon as the first one finishes, one at a time. Stop cancels everything queued. The server itself only handles one question per signed-in session: a second request that arrives while one runs (from another device, or a direct call) is refused at once with "Still answering your last question. Wait for it to finish." (HTTP 409). Uploads, the library and other chats keep working.

**How long can one question run?**
Up to 30 minutes, then the model call gives up. Change it with `UIORCH_LLM_TIMEOUT` (seconds).

**What if I close the tab or lose Wi-Fi mid-answer?**
Treat the answer as lost. Progress steps are written to the browser as they happen; if that connection is gone, the request stops and nothing is saved. Ask again. The "busy" lock is released when the request stops.

**Is there a length limit?**
8000 characters per question. Uploads and request bodies are capped at 8 MB.

**Why was my web question answered on the Mac?**
A message with 3 or more question marks is always answered locally, never split across routes. Ask web questions one at a time.

**What do the modes mean?**
- auto: the app picks a route.
- local: answered by Ollama on this Mac. Nothing leaves.
- web: only a generic, rewritten query goes out (never your data).
- claude: masked text goes to Claude. Anything that must never leave (SSN, card, password, account or routing number) stops the request and asks you.

## Phone and network

**Can the phone work without the Mac?**
No. The Mac does all the work (masking, files, models). Away from home, reach the Mac over Tailscale.

**What does "Can't reach your Mac" mean?**
The page lost contact with the server. It retries every 8 seconds and hides itself when the Mac answers. It only appears on a page that was already open: a browser cannot load the app fresh while the Mac is unreachable, so you see the browser's own error page instead (an offline page would need a service worker, which is not built).

**Is the LAN link safe?**
Not by default: it is plain HTTP, so passwords and documents cross the network unencrypted. Turn on local HTTPS: `python3 scripts/install.py --tls --bind <your Mac's LAN IP>` (add your other options). It makes a private certificate in `state/tls/` (the key that signed it is thrown away) and the link becomes `https://<ip>:8765/`. Then trust `state/tls/ca.crt` once on each device: on the Mac, double-click it and set Always Trust; on an iPhone, AirDrop it, install the profile, then turn it on under Settings > General > About > Certificate Trust Settings. Plain HTTP stops being served, the session cookie becomes Secure, and the certificate lasts 13 months (Settings shows the expiry date to the first account) (run the installer again with `--tls --renew-tls --bind <new IP>` to renew, or if the Mac's IP changes). Tailscale is the alternative when you are away from home.

## Sharing with family

**Who can use it?**
New accounts need an invitation code from the administrator (the first account); the administrator also decides whether each account may use the cloud, the web, uploads or scheduled jobs. Share the link only with people you trust. Each account's library, search index and chats are encrypted with that person's own password; other accounts cannot read them. Only the first account can open Settings and Activity.

**Does it use my family's data for anything?**
No. Everything stays on this Mac except what the route allows (generic web queries, or masked text to Claude when someone picks that mode). Nothing is shared between accounts.

**How do I add a family member's phone?**
Give them `https://<your Mac's IP>:8765/`, and put `state/tls/ca.crt` on their phone once (AirDrop on iPhone; Settings > Security > Install a certificate on Android), then they register. Steps are in the README under "Let other people and devices on your network use it".

**I get a certificate warning.**
The device does not trust `state/tls/ca.crt` yet (on iPhone, also switch it on under Settings > General > About > Certificate Trust Settings), or the link still says `http://` or an old IP. If the Mac's IP changed, run `python3 scripts/install.py --tls --renew-tls --bind <new IP>` and re-trust the new `ca.crt` on each device.

**The link stopped working after a restart. How do I keep the address the same?**
The address comes from your router, which can hand out a different one after a restart, and the HTTPS certificate is tied to that address. Give the computer a fixed address so it never changes. This is untested here, and the menus differ by router, so treat the steps as a guide:
- Best: in your router's admin page (often `192.168.1.1` or `192.168.0.1`), find "DHCP reservation", "address reservation" or "static lease", pick this computer from the list and save. Nothing changes on the computer.
- On the computer instead: set the network connection's IP to "Manual" using its current address, router and subnet mask. Pick an address outside the router's automatic range, or it may clash with another device.
- Skip it entirely: Tailscale gives each device a stable address that works at home and away.
If the address does change anyway, delete `state/tls/`, run the installer again with `--bind <new IP>` and trust the new `ca.crt`.

## Accounts

**How do I turn on voice input on this computer?**
The speech model is not installed with the app, and the app never downloads anything itself. Once, run `.venv/bin/python scripts/fetch_voice_model.py`. It downloads about 460 MB (the `small` model; set `PRIVHYBRID_WHISPER=base` first for about 145 MB, rougher results) into `state/models/`. After that, audio is transcribed on this computer and never stored or sent. Until then, the microphone shows "The speech model is not on this computer yet".

**I forgot my password.**
There is no recovery (no mail server, and data is encrypted with a key from the password). Delete the account and start over.

**Who can see Settings and Activity?**
Only the first account on the Mac.

**How long do I stay signed in?**
Sessions expire after 8 hours idle. Repeated wrong passwords are rate limited (wait a minute).

## Library and folders

**Does an empty folder stay?**
Yes. Folder names are saved (encrypted, per account) the moment you create them, so an empty folder survives a reload and a restart. Rename or Delete it from its row; deleting a folder keeps its files in Unsorted.

**Why does "search only this folder" not list my empty folder?**
It lists folders that contain files; an empty one would find nothing.

## Privacy

**Can masking miss something?**
Yes. Detection is layered (patterns, a local model pass, a final local check) and fails closed, but it is not perfect. Use a strong `check` model; a small one missed a name and address in testing. Settings shows a red warning when the chosen checker looks under 14B (judged from the model name). Do not rely on it alone for data you cannot afford to expose.

**What does Extreme privacy do?**
It is a checkbox in Settings. When on, every question is answered by the local model only, whatever mode you pick: no web search and no cloud. New web jobs cannot be added and running ones stop. The header shows "Extreme privacy on". It is a per-account setting, and turning it off restores your normal modes.

**Is a bank statement or spreadsheet ever sent to Claude?**
Only a summary made on your computer: transaction count, rounded totals, category shares and month totals. Merchants, descriptions, dates, account numbers and individual amounts are not in it. Bank CSV/XLSX/PDF/text files are recognised when you add them, however small. If a file looks financial but cannot be read as a table, it stays on your computer and the cloud route stops. The summary is approximate (and the direction of unsigned amounts in a text statement is a best guess).

**I turned on Extreme privacy on my laptop. Does my phone stop sending to the cloud?**
Yes, immediately. The setting is stored once for the account and read again before every cloud, web or scheduled request, so a phone or a background task that was already signed in cannot send. A question already handed to a provider before you switched it on finishes.

**What is stored on disk?**
Library, search index and chats are AES-GCM encrypted per user, readable only while signed in. The audit log holds counts, routes and timings, never text.

**What is out of scope?**
A compromised Mac or a malicious local process, and a provider misusing correctly masked text. See `docs/THREAT-MODEL.md`.

## Scheduled jobs

**What are they?**
Saved questions that run daily or weekly on the Mac, even while you are signed out. Each result is waiting as a chat marked "Scheduled:" at your next sign-in.

**How do I turn them on?**
The server needs `PRIVHYBRID_SCHEDULER=1` (off by default; not available in demo mode). Then each account opts in under **Schedule** with its password. Jobs are web-only (public facts, no files) or local (one folder of your files). They never use Claude.

**What does turning it on change for my security?**
A key is stored in this Mac's Keychain so jobs can run while you are signed out. Your scheduled questions and a copy of the folders your local jobs read are protected by that key, not your password, so anyone who can use your Mac login can read them. Results are sealed so only your password opens them. Turn on FileVault and use a strong Mac password. Turning it off deletes the key, jobs, copies and unopened results. See `docs/SCHEDULED-JOBS-DESIGN.md`.

**When does a job not run?**
- You are asking a question at that moment (it retries on the next 30-second check).
- The Keychain will not answer (for example the Mac has not been unlocked since boot): the run is skipped and noted in the activity log.
- The Mac was off: the job runs once when it is back, marked "Missed run", not once per missed day.
- It asks about, or would answer with, an SSN, card or password: the run fails and says so, nothing is sent.

**Why does a local job show an old file?**
Local jobs read a copy of the folder, refreshed whenever you change your library and shown with its time. Deleting a file removes it from the copy at once.

**Does it work on Linux and Windows?**
The app does (Ubuntu tested). Scheduled jobs need the system keychain (macOS Keychain, Windows Credential Locker, or a desktop's Secret Service on Linux). A headless Linux server has none, so turning them on is refused there. Windows 11 was tested once (the app, install and tests); scheduled jobs on Windows are not tested.

**What if the Python or the venv is rebuilt?**
A rebuilt venv on the same Python still reads the key. A Python upgrade that changes the interpreter may make macOS ask for permission, which blocks unattended runs until you turn scheduled jobs off and on again.

## Install as an app

`python3 scripts/install.py` sets up the environment, starts the assistant at login and adds an app icon that opens it in its own window (Mac: launchd and `~/Applications/Private Assistant.app`; Linux: a `systemd --user` service and a menu entry; Windows 11: a Startup-folder entry and a Start menu shortcut, tested once). No admin rights. `--dry-run` shows what it would do, `--uninstall` removes it (your data in `state/` stays), `--scheduler` turns on scheduled jobs, `--metrics` serves `/metrics` for monitoring, `--tls` serves HTTPS with a local certificate. It needs Ollama installed first (https://ollama.com), and Python 3.11 to 3.13 (on a newer Python it uses `uv` to fetch 3.12 if `uv` is installed).

**I can't find the app in Finder or Launchpad.** The installer puts it in your personal Applications folder, `~/Applications/Private Assistant.app`, which the Applications entry in Finder's sidebar does not show. Spotlight (Cmd+Space) finds it by the name "Private Assistant" (not "privacy hybrid"). To list it under Applications and Launchpad too, run `ln -s ~/Applications/"Private Assistant.app" /Applications/` (remove that link with `rm "/Applications/Private Assistant.app"` if you uninstall), or drag the app to the Dock.

## Monitoring

**Can I see how it is doing over time?**
Yes, with Prometheus, Grafana and Loki on the same Mac. Install the assistant with `--metrics`, then run `TARGET=<ip>:8765 ./observability/setup.sh` (TARGET only if you used `--bind`). Grafana is at http://127.0.0.1:3000 (change the default `admin` / `admin` password on first sign-in). Five dashboards, all under Dashboards → Private Assistant:
- **overview**: services up, answers and stops by route, answer time, masked values, firing alerts.
- **privacy**: share of answers that stayed on this Mac, answers sent to Claude, stopped requests, web searches, masked values by kind.
- **performance**: uptime history, answer time, requests per minute, errors, time spent answering.
- **scheduled jobs**: runs, failures, success rate.
- **this Mac**: CPU, memory, disk, load and network (from `node_exporter`).

**Can I search the logs?**
Yes. Loki keeps the activity log (route, outcome, timings, counts of masked kinds; never text) for 30 days, and Alloy feeds it from `logs/audit.jsonl`. In Grafana open Explore or Drilldown > Logs and pick the Loki source. Both listen on this Mac only and usage reporting is off. The error output in `logs/server.out` is deliberately not sent.

**Will it warn me?**
Yes. Five alerts (assistant down, Ollama down, search down for 5 minutes, a scheduled job failed in the last hour, 3 or more errors in 15 minutes) show up in Prometheus under Alerts and as a macOS notification, once per alert. The notifier is `observability/notify.py`, started at login by `setup.sh`. Edit `observability/prometheus.rules.yml` to change them, then run `setup.sh` again.

**What does it record?**
Counts, routes and timings from the activity log. Never question or answer text. `/metrics` answers only processes on this Mac (loopback or the Mac's own address); another device on the Wi-Fi gets a refusal. See `observability/`.

## Network safety

**Should I turn on the macOS firewall?**
It is optional and does not affect the assistant or Ollama on this Mac (it only filters incoming connections, and signed apps such as Ollama are allowed automatically). It stops other programs from accepting connections by accident. Allow Python if macOS asks.

**Can it use Ollama on another machine, with a backup?**
Yes. Settings > Ollama address takes this Mac or an IP address on your own network (for example `http://192.168.1.20:11434`), and "Backup Ollama addresses" takes up to 3 more, tried in order when the one before does not answer. Only literal private-network IPs are accepted (no names, no outside addresses), and the app can connect to exactly those host:port pairs and nothing else. Use the same model names on each machine (`ollama pull`); a machine missing the model is skipped. The traffic is plain HTTP on your network, and that Ollama has no login, so use it on a trusted network. Over SSH or Tailscale it is encrypted.

**Is Ollama exposed?**
If `OLLAMA_HOST` is `0.0.0.0` (a common setting so other machines can use it), anyone on your Wi-Fi can use your models without a login. The assistant itself only talks to Ollama on this Mac. If nothing else needs it, set `OLLAMA_HOST=127.0.0.1:11434` and restart Ollama; if a server needs it, restrict port 11434 to that machine's address.

**How do I make sure Ollama sends nothing out of my network?** (untested on other setups)
Ollama runs models on your computer, so your prompts stay here. It can still connect out to download models, check for updates, or use cloud models (names ending in `-cloud`; avoid `ollama signin`). To block that:
1. Install LuLu (free firewall from objective-see.org: `brew install --cask lulu`) and approve its system extension in System Settings.
2. Add rules for `/Applications/Ollama.app/Contents/Resources/ollama`: **Allow** your home network range (for example `192.168.1.0/24`, so your phone or another machine can still reach it) and **Block** any other address. Set the "Ollama" menu-bar app to **Block** too, since it checks for updates.
3. To pull a model or update, switch the Block rule to Allow, do it, then switch it back. LuLu has no scheduler, so this is manual; a monthly calendar reminder helps.
4. Run `observability/setup.sh`. It installs a small watchdog that checks every minute and shows a notification (and writes `~/Library/Logs/privhybrid-egress.log`) if Ollama or llama.cpp ever connects outside your network. It logs only the process name and remote address.
5. Test: turn Wi-Fi off and ask a question. It should still answer.

**Are the monitoring pages exposed?**
Grafana, Prometheus and node_exporter listen on this Mac only. `/metrics` answers only programs on this Mac.

## Other cloud models (ChatGPT, Grok, OpenRouter, OpenCode, ...)

**Can I use something other than Claude for the "masked" mode?**
Yes, in Settings > "Cloud model": choose "Other: any OpenAI-compatible service" and enter its address (https), a model name and an API key. The same privacy steps run first: Tier 1 data (SSN, card, password, account or routing number) stops the request, names, amounts and dates become placeholders, and the local model re-checks the masked text. Then the provider gets only that masked text and your values are restored on this computer.

**Is it tested?**
Only against a local stand-in service in the automated tests (masking, key handling, address rules). It is **not tested with real providers** yet. If something does not work with yours, the answer falls back to the local model and says so.

**What should I know first?**
- The provider sees the masked text and has its own retention and training terms. Read them before you use it.
- Use an API key with a spend limit. Usage is billed by the provider, unlike the Claude CLI on a subscription.
- The key is stored in this computer's keychain (or `PRIVHYBRID_CLOUD_API_KEY`), never in a file, and is never shown again.
- Only the one address you entered can be reached, only while a request runs, and only if it resolves to a public address. The address must be `https://` (a service on this computer may use `http://`).
- It applies to everyone who uses this app; only the first account can change it. Each answer from it carries a notice saying so.

## Look and feel

**How do I change colours?**
Account menu: pick a style (Mac, Indigo, Ocean, Forest, Graphite, Vision) and Auto/Light/Dark. It is saved per account and applies on every device you sign in on.

**The header wraps on a mid-size window.**
Known; around 1100 px wide it takes two rows.

## Demo mode

**What is `/demo`?**
With `PRIVHYBRID_DEMO=1` (loopback only), opening `/demo` signs in to a shared throwaway account reset to the fake samples on every visit. Visiting it resets state, so do not link it from anything automatic. Never enable it on a server with real data.

## Troubleshooting

- Nothing answers: is Ollama running (`ollama list`)? Settings lists installed models.
- 429 "too many attempts": wait a minute.
- Colour style will not save: restart the server after updating (new styles are validated server-side).
- Tests: `.venv/bin/python -m pytest -q`. Full check: `./scripts/verify.sh`.

## Not built yet

- Offline or phone-only mode.
- Scheduled jobs that use Claude or another cloud model.
- Cloud providers other than OpenAI-compatible ones (for example Anthropic's own API).
- Real-provider testing of the OpenAI-compatible route.
- Scheduled jobs on Windows, and Windows versions other than the one tested (Windows 11).
- Automatic certificate renewal (re-run the installer with `--tls` after deleting `state/tls/`).
