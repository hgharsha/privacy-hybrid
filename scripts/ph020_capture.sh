#!/bin/bash
# PH-020 capture: what does the Claude CLI send? Run it yourself, on your own Mac, logged in to Claude.
#   bash scripts/ph020_capture.sh
# Uses the app's PRIVATE Claude config folder (state/claude-config, create it first: bash scripts/claude_login.sh), so your own
# ~/.claude is never read or changed. It plants fake secrets (canaries), runs the CLI twice through mitmproxy (the app's exact setup, then a control
# without --setting-sources ""), prints counts and hostnames, and removes everything it made. It only edits
# CLAUDE.md inside the private folder (restored, also on Ctrl-C) and creates one empty file in $HOME.
# Sends one synthetic prompt per run to Anthropic using your normal login. Needs: claude, mitmproxy (brew install mitmproxy).
# Do not use other Claude sessions while it runs (about 1 minute).
set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

PORT=8081
CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
PRIV="${PRIVHYBRID_CLAUDE_CONFIG_DIR:-$(cd "$(dirname "$0")/.." && pwd)/state/claude-config}"
CM="$PRIV/CLAUDE.md"
CANARY_FILE="$HOME/CANARY-FILENAME-8b05.txt"
SUMMARY="$HOME/ph020-summary.txt"
WORK=$(mktemp -d)
HAD_CM=0
MP=""

command -v claude >/dev/null || { echo "claude not found on PATH"; exit 1; }
command -v mitmdump >/dev/null || { echo "mitmdump not found (brew install mitmproxy)"; exit 1; }
[ -d "$PRIV" ] || { echo "No private config folder at $PRIV - run: bash scripts/claude_login.sh"; exit 1; }
if [ ! -f "$CERT" ]; then
  echo "Creating the mitmproxy certificate once..."
  mitmdump -q --listen-port "$PORT" & MP=$!; sleep 5; kill "$MP" 2>/dev/null; wait "$MP" 2>/dev/null; MP=""
  [ -f "$CERT" ] || { echo "No certificate at $CERT"; exit 1; }
fi

if [ -f "$CM" ]; then HAD_CM=1; cp -p "$CM" "$WORK/CLAUDE.md.bak"; fi

cleanup() {
  [ -n "$MP" ] && kill "$MP" 2>/dev/null
  if [ "$HAD_CM" = 1 ]; then cp -p "$WORK/CLAUDE.md.bak" "$CM"; else rm -f "$CM"; fi
  rm -f "$CANARY_FILE"
  rm -rf "$WORK"
  if [ -f "$CM" ] && grep -q CANARY "$CM"; then echo "WARNING: canary still in $CM - remove it by hand"; else echo "Restored $CM; temporary files removed."; fi
}
trap cleanup EXIT INT TERM

echo 'CANARY-USERMEM-7f3a' >> "$CM"
touch "$CANARY_FILE"

run() {  # run <name> [extra claude flags]
  local name=$1; shift
  mitmdump -q -w "$WORK/$name.flows" --listen-port "$PORT" & MP=$!
  for _ in $(seq 1 20); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 1; done
  local d; d=$(mktemp -d)
  ( cd "$d" && printf 'PH020-PROMPT-MARKER 4111-not-a-real-number' | env -i PATH="$PATH" HOME="$HOME" CLAUDE_CONFIG_DIR="$PRIV" USER="$USER" LOGNAME="${LOGNAME:-$USER}" TMPDIR="$d" \
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 ENABLE_CLAUDEAI_MCP_SERVERS=false \
      HTTPS_PROXY="http://127.0.0.1:$PORT" NODE_EXTRA_CA_CERTS="$CERT" \
      claude -p --output-format json --tools "" --no-session-persistence --strict-mcp-config --mcp-config '{"mcpServers":{}}' "$@" > "$WORK/$name.reply" 2>&1 )
  sleep 1; kill "$MP" 2>/dev/null; wait "$MP" 2>/dev/null; MP=""
  rm -rf "$d"
  if ! grep -q '"is_error":false' "$WORK/$name.reply"; then
    echo "[$name] The CLI did not answer normally (not logged in?). Reply was:"; head -c 400 "$WORK/$name.reply"; echo; return 1
  fi
  mitmdump -nr "$WORK/$name.flows" --flow-detail 4 2>/dev/null | grep -vi 'authorization\|x-api-key\|cookie' > "$WORK/$name.txt"
}

count() { grep -c -- "$2" "$WORK/$1.txt"; }
hosts() { grep -oE '^[0-9.:]+: (GET|POST|PUT|HEAD|OPTIONS|CONNECT|DELETE) https?://[^/ ?]+' "$WORK/$1.txt" | sed -E 's#^[0-9.:]+: ([A-Z]+) https?://#\1 #' | sort | uniq -c; }

echo "== Run 1 of 2: the app's exact setup"
run app --setting-sources "" || exit 1
echo "== Run 2 of 2: control (settings files allowed; the user-memory canary SHOULD show up)"
run control || exit 1

{
  echo "PH-020 capture summary $(date '+%Y-%m-%d %H:%M') CLI $(claude --version 2>/dev/null | head -1) macOS $(sw_vers -productVersion)"
  for n in app control; do
    echo; echo "--- $n"
    for c in CANARY-USERMEM-7f3a CANARY-FILENAME-8b05 PH020-PROMPT-MARKER datadoghq event_logging mcp-proxy; do echo "$c: $(count $n $c)"; done
    echo "Hosts actually requested (method, host):"; hosts $n
  done
  echo
  A_CAN=$(( $(count app CANARY-USERMEM-7f3a) + $(count app CANARY-FILENAME-8b05) ))
  [ "$A_CAN" = 0 ] && [ "$(count app PH020-PROMPT-MARKER)" -ge 1 ] && echo "APP RUN: PASS (no canary in any request; prompt text present)" || echo "APP RUN: CHECK (canary found, or prompt text missing)"
  [ "$(count app datadoghq)" = 0 ] && [ "$(count app event_logging)" = 0 ] && echo "TELEMETRY: PASS (none seen)" || echo "TELEMETRY: CHECK (traffic still seen)"
  [ "$(count app mcp-proxy)" = 0 ] && echo "MCP CONNECTORS: PASS (no connector traffic)" || echo "MCP CONNECTORS: CHECK (connector traffic still seen)"
  [ "$(count control CANARY-USERMEM-7f3a)" -ge 1 ] && echo "CONTROL: VALID (the canary shows up when the CLI is allowed to read settings, so the capture can see it)" || echo "CONTROL: INCONCLUSIVE (the canary never showed up even in the control)"
} | tee "$SUMMARY"
echo
echo "Saved $SUMMARY (counts and hostnames only, no tokens). Send me its contents."
