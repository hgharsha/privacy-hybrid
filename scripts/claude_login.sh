#!/bin/bash
# One-time: create the app's private Claude config folder and sign in there (same Claude account, separate login and settings).
#   bash scripts/claude_login.sh
# The app then starts the Claude CLI with CLAUDE_CONFIG_DIR pointing at this folder, so it never reads your own ~/.claude.
D="${PRIVHYBRID_CLAUDE_CONFIG_DIR:-$(cd "$(dirname "$0")/.." && pwd)/state/claude-config}"
mkdir -p "$D" && chmod 700 "$D" || exit 1
echo "Private config folder: $D"
echo "Claude will open: sign in if asked (type /login), wait for the prompt, then type /exit."
CLAUDE_CONFIG_DIR="$D" claude
echo "Check: CLAUDE_CONFIG_DIR=\"$D\" claude -p 'say hi'   (should answer, not 'Not logged in')"
