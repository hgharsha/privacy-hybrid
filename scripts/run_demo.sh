#!/bin/sh
# Throwaway demo on this Mac only (127.0.0.1:8791), fake data in a temp folder. Open http://127.0.0.1:8791/demo
cd "$(dirname "$0")/.." || exit 1
pkill -f 'privhybrid.*demo-run' 2>/dev/null
D=$(mktemp -d)
PRIVHYBRID_DEMO=1 PYTHONPATH=src exec .venv/bin/python -c "
import sys
from privhybrid import server
h = server.serve(port=${PORT:-8791}, data_dir='$D', audit_path='$D/audit.jsonl')  # demo-run
print('demo on http://127.0.0.1:${PORT:-8791}/demo', flush=True)
h.serve_forever()"
