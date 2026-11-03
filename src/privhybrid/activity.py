"""Observability from the audit log alone: counts, routes and timings. No text is ever read or stored here."""
import json
from pathlib import Path
from typing import Dict, List

MAX_ROWS = 5000  # newest rows only; the log is append-only and can grow


def load(path: str, n: int = MAX_ROWS) -> List[dict]:
    try:
        with open(path, "rb") as f:  # read the tail only: the log is append-only and can grow for years
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - n * 400))
            lines = f.read().decode("utf-8", "replace").splitlines()[-n:]
            if size > n * 400:
                lines = lines[1:]  # the first line is probably cut in half
    except OSError:
        return []
    rows = []
    for x in lines:
        try:
            r = json.loads(x)
            if isinstance(r, dict):  # a hand-edited or half-written line must not break the panel
                rows.append(r)
        except ValueError:
            pass
    return rows


def summarize(rows: List[dict]) -> dict:
    """Per route: requests by outcome, average ms, and how many values were masked by kind."""
    routes: Dict[str, dict] = {}
    masked: Dict[str, int] = {}
    scheduled: Dict[str, int] = {"ok": 0, "failed": 0}  # always present so dashboards show 0, not "no data"
    for r in rows:
        if r.get("event"):  # scheduler notes are not requests
            if r.get("event") == "scheduled_run":
                k = "ok" if r.get("status") == "ok" else "failed"
                scheduled[k] = scheduled.get(k, 0) + 1
            continue
        s = routes.setdefault(str(r.get("route", "?")), {"ok": 0, "blocked": 0, "error": 0, "ms_total": 0, "timed": 0})
        out = r.get("outcome") if r.get("outcome") in ("ok", "blocked", "error") else "error"
        s[out] += 1
        if isinstance(r.get("ms"), (int, float)):
            s["ms_total"] += r["ms"]
            s["timed"] += 1
        if r.get("route") == "claude":
            kinds = r.get("kinds")
            for k, v in (kinds.items() if isinstance(kinds, dict) else ()):
                if isinstance(v, int):
                    masked[str(k)] = masked.get(str(k), 0) + v
    for s in routes.values():
        s["avg_ms"] = round(s["ms_total"] / s["timed"]) if s["timed"] else None
    return {"routes": routes, "masked": masked, "scheduled": scheduled, "total": len(rows)}


def prometheus(summary: dict, health: Dict[str, bool]) -> str:
    out = ["# TYPE privhybrid_requests_total counter"]
    for route, s in sorted(summary["routes"].items()):
        for outcome in ("ok", "blocked", "error"):
            out.append(f'privhybrid_requests_total{{route="{_esc(route)}",outcome="{outcome}"}} {s[outcome]}')
    out.append("# TYPE privhybrid_request_ms_sum counter")
    for route, s in sorted(summary["routes"].items()):
        out.append(f'privhybrid_request_ms_sum{{route="{_esc(route)}"}} {s["ms_total"]}')
        out.append(f'privhybrid_request_ms_count{{route="{_esc(route)}"}} {s["timed"]}')
    out.append("# TYPE privhybrid_scheduled_runs_total counter")
    for status, n in sorted(summary.get("scheduled", {}).items()):
        out.append(f'privhybrid_scheduled_runs_total{{status="{_esc(status)}"}} {n}')
    out.append("# TYPE privhybrid_masked_total counter")
    for kind, n in sorted(summary["masked"].items()):
        out.append(f'privhybrid_masked_total{{kind="{_esc(kind)}"}} {n}')
    out.append("# TYPE privhybrid_up gauge")
    for name, up in sorted(health.items()):
        out.append(f'privhybrid_up{{service="{_esc(name)}"}} {int(bool(up))}')
    return "\n".join(out) + "\n"


def _esc(v: str) -> str:
    return "".join(c for c in str(v) if c.isalnum() or c in "_-.")
