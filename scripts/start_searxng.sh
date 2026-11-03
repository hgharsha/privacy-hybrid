#!/bin/sh
# Private metasearch on this Mac only: 127.0.0.1:8888 -> SearXNG. Needs Docker. Queries leave from your IP via SearXNG.
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)/state/searxng"
mkdir -p "$DIR"
if [ ! -f "$DIR/settings.yml" ]; then
  KEY=$(python3 -c 'import secrets;print(secrets.token_hex(24))')
  cat > "$DIR/settings.yml" <<YML
use_default_settings: true
server:
  secret_key: "$KEY"
  limiter: false
  public_instance: false
search:
  formats: [html, json]
YML
  chmod 600 "$DIR/settings.yml"
fi
docker rm -f privhybrid-searxng >/dev/null 2>&1 || true
docker run -d --name privhybrid-searxng --restart unless-stopped -p 127.0.0.1:8888:8080 \
  -v "$DIR/settings.yml:/etc/searxng/settings.yml:ro" searxng/searxng:latest
echo "SearXNG on http://127.0.0.1:8888"
