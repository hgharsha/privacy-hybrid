#!/bin/sh
# Mac: installs Prometheus and Grafana with Homebrew, points them at this assistant, and starts both as background services.
# Usage: TARGET=192.168.1.20:8765 [SCHEME=https] ./setup.sh   (default target 127.0.0.1:8765)
# Also starts a notifier (notify.py) that shows a macOS notification when an alert fires.
# Needs the assistant installed with --metrics (python3 scripts/install.py --metrics ...). Grafana: http://127.0.0.1:3000 (first login admin / admin, it asks you to change it).
set -e
cd "$(dirname "$0")"
command -v brew >/dev/null || { echo "Homebrew is required: https://brew.sh"; exit 1; }
brew list prometheus >/dev/null 2>&1 || brew install prometheus
brew list grafana >/dev/null 2>&1 || brew install grafana
brew list node_exporter >/dev/null 2>&1 || brew install node_exporter
brew list loki >/dev/null 2>&1 || brew install loki
brew list grafana-alloy >/dev/null 2>&1 || brew install grafana-alloy
P=$(brew --prefix)
sed "s#127.0.0.1:8765#${TARGET:-127.0.0.1:8765}#" prometheus.yml > "$P/etc/prometheus.yml"  # TARGET=<ip>:<port> when the assistant is bound to your LAN address
if [ "$SCHEME" = "https" ]; then  # the assistant serves HTTPS (install.py --tls): trust its local CA when scraping
  CA="$(cd .. && pwd)/state/tls/ca.crt" python3 - <<'PY'
import os
import subprocess
p = subprocess.run(["brew", "--prefix"], capture_output=True, text=True).stdout.strip() + "/etc/prometheus.yml"
s = open(p).read().replace("    metrics_path: /metrics\n", "    metrics_path: /metrics\n    scheme: https\n    tls_config:\n      ca_file: " + os.environ["CA"] + "\n", 1)
open(p, "w").write(s)
PY
fi
cp prometheus.rules.yml "$P/etc/prometheus.rules.yml"
mkdir -p "$P/var/lib/grafana/dashboards" "$P/etc/grafana/provisioning/datasources" "$P/etc/grafana/provisioning/dashboards"
cp grafana/*.json "$P/var/lib/grafana/dashboards/"
cp grafana/datasource.yml "$P/etc/grafana/provisioning/datasources/privhybrid.yml"
sed "s#/opt/homebrew#$P#" grafana/dashboards.yml > "$P/etc/grafana/provisioning/dashboards/privhybrid.yml"
grep -q "^provisioning = $P/etc/grafana/provisioning" "$P/etc/grafana/grafana.ini" || \
  sed -i '' "s#^;provisioning = conf/provisioning#provisioning = $P/etc/grafana/provisioning#" "$P/etc/grafana/grafana.ini"
# logs: Loki stores the audit log (no text in it); Alloy reads the file and pushes to Loki. Both listen on this Mac only, usage reporting off.
mkdir -p "$P/etc/grafana-alloy" "$P/var/lib/grafana-alloy/data"
sed "s#__VAR__#$P/var#g" loki.yml > "$P/etc/loki-local-config.yaml"
sed "s#__AUDIT__#$(cd .. && pwd)/logs/audit.jsonl#" alloy.alloy > "$P/etc/grafana-alloy/config.alloy"
brew services restart loki
A="$HOME/Library/LaunchAgents/local.privhybrid.alloy.plist"
cat > "$A" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.privhybrid.alloy</string>
<key>ProgramArguments</key><array><string>$P/opt/grafana-alloy/bin/alloy</string><string>run</string><string>--disable-reporting</string><string>--server.http.listen-addr=127.0.0.1:12345</string><string>--storage.path=$P/var/lib/grafana-alloy/data</string><string>$P/etc/grafana-alloy</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
PL
launchctl bootout "gui/$(id -u)/local.privhybrid.alloy" 2>/dev/null || true
sleep 2
launchctl bootstrap "gui/$(id -u)" "$A"
brew services start node_exporter
brew services restart prometheus
brew services restart grafana
# macOS notification when an alert fires (LaunchAgent, starts at login)
L="$HOME/Library/LaunchAgents/local.privhybrid.notify.plist"
cat > "$L" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.privhybrid.notify</string>
<key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>$(pwd)/notify.py</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
PL
launchctl bootout "gui/$(id -u)/local.privhybrid.notify" 2>/dev/null || true
sleep 2
launchctl bootstrap "gui/$(id -u)" "$L"
# watchdog: notifies if Ollama / llama.cpp ever connect outside your own network (LaunchAgent, starts at login)
W="$HOME/Library/LaunchAgents/local.privhybrid.egresswatch.plist"
cat > "$W" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.privhybrid.egresswatch</string>
<key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>$(pwd)/egress_watch.py</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
PL
launchctl bootout "gui/$(id -u)/local.privhybrid.egresswatch" 2>/dev/null || true
sleep 2
launchctl bootstrap "gui/$(id -u)" "$W"
echo "Prometheus http://127.0.0.1:9090   Grafana http://127.0.0.1:3000 (dashboards: Private Assistant, 5 of them)"
