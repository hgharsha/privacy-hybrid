"""Live check (fake data): send the masked corpus statement through the real Claude CLI and assert that no planted
value is in the text handed to the CLI. Run: PYTHONPATH=src:tests .venv/bin/python scripts/live_claude_check.py"""
import subprocess

import corpus as C
from privhybrid import egress, providers
from privhybrid.vault import Vault

rec = []
real = subprocess.run
providers.subprocess.run = lambda cmd, **kw: (rec.append(kw.get("input", "")), real(cmd, **kw))[1]
prompt = "Summarise this bank statement in two sentences. Keep any [KIND_n] tokens as written.\n\n" + C.STATEMENT + C.PAD * 4
res = egress.send("claude", [{"role": "user", "content": prompt}], Vault(C.DICTIONARY), log=egress.AuditLog("logs/audit.jsonl"), timeout=240)
sent = "\n".join(rec)
needles = [n.replace("check #", "") for n in (v.split(": ", 1)[-1] if v.startswith(("DOB", "username")) else v
                                              for v in C.TIER2_VALUES + C.TIER3_VALUES + list(C.DICTIONARY))]
leaks = [n for n in needles if n in sent]
assert len(rec) == 1 and not leaks, f"calls={len(rec)} leaks={leaks}"
print("OK: 1 CLI call, no planted value in its input.\nReply:", res.text)
