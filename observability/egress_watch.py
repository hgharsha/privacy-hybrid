#!/usr/bin/env python3
"""Every 60s, checks that the local model (Ollama, llama.cpp) make no connection to an address outside your own network.
Shows a macOS notification and appends to ~/Library/Logs/privhybrid-egress.log. Records process name and remote IP only, never any text. Stdlib only."""
import ipaddress
import os
import re
import subprocess
import time

WATCH = re.compile(r"(?i)^(ollama|llama)")  # this app guards its own sockets in-process (egress.loopback_only)
LOG = os.path.expanduser("~/Library/Logs/privhybrid-egress.log")
CONN = re.compile(r"->\[?([0-9a-fA-F:.]+?)\]?:(\d+) \(ESTABLISHED\)")


def outside(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return not (a.is_loopback or a.is_private or a.is_link_local)


def find_outside(lsof_text: str) -> set:
    """lsof -i -nP output -> {(process, remote ip)} for every established connection that leaves the local network."""
    found = set()
    for line in lsof_text.splitlines()[1:]:
        cols = line.split()
        m = CONN.search(line)
        if cols and m and WATCH.match(cols[0]) and outside(m.group(1)):
            found.add((cols[0], m.group(1)))
    return found


def notify(text: str) -> None:
    subprocess.run(["osascript", "-e", f'display notification "{text}" with title "Private Assistant: data left this network?"'], check=False)


def scan() -> set:
    out = subprocess.run(["lsof", "-i", "-nP"], capture_output=True, text=True, timeout=20).stdout
    return find_outside(out)


if __name__ == "__main__":
    seen: set = set()
    while True:
        try:
            now = scan()
            for proc, ip in sorted(now - seen):
                with open(LOG, "a") as f:
                    f.write(f"{time.strftime('%F %T')} OUTBOUND {proc} -> {ip}\n")
                notify(f"{proc} connected to {ip}")
            seen = now
        except (OSError, subprocess.SubprocessError):
            pass
        time.sleep(60)
