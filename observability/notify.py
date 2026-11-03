#!/usr/bin/env python3
"""Shows a macOS notification when a Prometheus alert starts firing. Polls every 60s; stdlib only. Alert names and summaries only, never any text from questions."""
import json
import subprocess
import time
import urllib.request

PROM = "http://127.0.0.1:9090/api/v1/alerts"


def firing(fetch=lambda: urllib.request.urlopen(PROM, timeout=5).read()) -> dict:
    data = json.loads(fetch())["data"]["alerts"]
    return {a["labels"]["alertname"]: a.get("annotations", {}).get("summary", "") for a in data if a["state"] == "firing"}


def new_alerts(now: dict, seen: set) -> list:
    return [(n, s) for n, s in sorted(now.items()) if n not in seen]


def notify(title: str, text: str) -> None:
    esc = lambda x: x.replace("\\", "\\\\").replace('"', "'")
    subprocess.run(["osascript", "-e", f'display notification "{esc(text)}" with title "Private Assistant: {esc(title)}"'], check=False)


if __name__ == "__main__":
    seen: set = set()
    while True:
        try:
            now = firing()
            for name, text in new_alerts(now, seen):
                notify(name, text)
            seen = set(now)
        except (OSError, ValueError, KeyError):
            pass  # Prometheus not up yet: try again next minute
        time.sleep(60)
