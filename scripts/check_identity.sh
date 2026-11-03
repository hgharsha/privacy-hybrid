#!/bin/sh
# Fail if any commit in the given range has an author or committer email that is not a GitHub noreply address,
# or a message that carries a Claude session link or Claude-Session trailer.
# Usage: sh scripts/check_identity.sh <git log arguments, e.g. BASE..HEAD>
# Prints only short commit ids, never the offending address (CI logs are public).
[ $# -gt 0 ] || { echo "usage: check_identity.sh <rev-range>"; exit 2; }
bad=$(git log --format='%h %ae %ce' "$@" | awk '{ for (i = 2; i <= 3; i++) if ($i !~ /@users\.noreply\.github\.com$/ && $i != "noreply@github.com") { print $1; break } }')
if [ -n "$bad" ]; then
  echo "These commits have an author or committer email that is not a GitHub noreply address:"
  echo "$bad"
  echo "Fix: git config user.email <id>+<login>@users.noreply.github.com, then re-author them (git commit --amend --reset-author)."
  exit 1
fi
msgs=$(git log --format='%h' -i -E --grep='claude\.ai/code|Claude-Session' "$@")
if [ -n "$msgs" ]; then
  echo "These commits have a session link or Claude-Session trailer in the message (not allowed):"
  echo "$msgs"
  exit 1
fi
