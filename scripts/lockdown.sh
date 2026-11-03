#!/bin/sh
# Optional operating-system network lockdown for ONE macOS user (default: phsvc) that runs this app. You run it; nothing runs by itself.
#   scripts/lockdown.sh plan  [user]   show exactly what would be done (default; changes nothing)
#   sudo scripts/lockdown.sh on  [user]   load a pf rule: that user may only talk to this computer (127.0.0.1 / ::1)
#   sudo scripts/lockdown.sh off [user]   remove that rule again
#   sudo scripts/lockdown.sh status [user] show the rule that is loaded
# Only that user is affected, never you. The rule lives in the macOS anchor com.apple/privacy-hybrid, is not saved, and is gone after a reboot.
# This is network filtering for one user, not a firewall for the whole machine, and it does not by itself make anything "secure".
set -eu
ACTION="${1:-plan}"
TARGET="${2:-phsvc}"
ANCHOR="com.apple/privacy-hybrid"
TOKEN_FILE="/var/db/privacy-hybrid-pf.token"
RULES="pass out quick on lo0 all user $TARGET
block drop out quick all user $TARGET"

case "$TARGET" in *[!A-Za-z0-9_.-]*|"") echo "Invalid user name." >&2; exit 2;; esac
[ "$(uname)" = "Darwin" ] || { echo "This script is for macOS (pf). On Linux use a container network policy; see docs/SECURITY.md." >&2; exit 2; }

plan() {
  echo "User that will be restricted: $TARGET"
  echo "Rules (anchor $ANCHOR):"; echo "$RULES" | sed 's/^/    /'
  echo "Commands for 'on':  pfctl -a $ANCHOR -f <rules file>;  pfctl -E (the token is kept in $TOKEN_FILE)"
  echo "Commands for 'off': pfctl -a $ANCHOR -F all;  pfctl -X <saved token>"
  echo "Nothing was changed."
}

[ "$ACTION" = "plan" ] && { plan; exit 0; }
[ "$(id -u)" = "0" ] || { echo "Run with sudo (or from the app's administrator prompt)." >&2; exit 1; }

case "$ACTION" in
  on)
    id "$TARGET" >/dev/null 2>&1 || { echo "No such user: $TARGET" >&2; exit 1; }
    uid="$(id -u "$TARGET")"
    [ "$uid" -ge 500 ] || { echo "Refusing: $TARGET is a system account." >&2; exit 1; }
    [ "$TARGET" != "${SUDO_USER:-}" ] || { echo "Refusing: that is the account you are using; you would lose your own network." >&2; exit 1; }
    console="$(stat -f%Su /dev/console 2>/dev/null || true)"
    [ "$TARGET" != "$console" ] || { echo "Refusing: $TARGET is the user logged in at this Mac." >&2; exit 1; }
    tmp="$(mktemp)"; echo "$RULES" > "$tmp"
    pfctl -a "$ANCHOR" -nf "$tmp"            # syntax check first
    pfctl -a "$ANCHOR" -f "$tmp"             # loads into the anchor only; the main ruleset is not touched
    rm -f "$tmp"
    out="$(pfctl -E 2>&1 || true)"
    tok="$(echo "$out" | sed -n 's/.*Token : *//p' | head -1)"
    [ -n "$tok" ] && { umask 077; echo "$tok" > "$TOKEN_FILE"; }
    echo "Lockdown requested for $TARGET. Test it: sudo -u $TARGET curl -m 5 https://example.com (should time out)."
    ;;
  off)
    pfctl -a "$ANCHOR" -F all 2>&1 | grep -v ALTQ || true
    if [ -s "$TOKEN_FILE" ]; then pfctl -X "$(cat "$TOKEN_FILE")" 2>&1 | grep -v ALTQ || true; rm -f "$TOKEN_FILE"; fi
    echo "Lockdown removed for $TARGET."
    ;;
  status)
    pfctl -a "$ANCHOR" -sr 2>&1 | grep -v ALTQ || true
    ;;
  *) echo "Usage: lockdown.sh plan|on|off|status [user]" >&2; exit 2;;
esac
