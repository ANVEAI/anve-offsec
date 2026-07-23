#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

source .env

echo "==> OpenClaw gateway: waiting for health..."
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:18789/healthz" >/dev/null 2>&1; then
    echo "    healthy"
    break
  fi
  sleep 2
done

echo "==> OpenClaw gateway: applying sandbox/offline defaults..."
# Sandbox is disabled because the browser sidecar already runs in a
# locked-down container and Chromium's sandbox cannot start there.
docker compose exec openclaw openclaw config set agents.defaults.sandbox.mode off

echo "==> OpenClaw gateway: ready"
echo ""
echo "    Control UI: http://127.0.0.1:18789"
echo "    Default model is read from config/openclaw/openclaw.json"
