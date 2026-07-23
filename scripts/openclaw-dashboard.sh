#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .env

URL="http://127.0.0.1:18789"
echo "OpenClaw Control UI: ${URL}"
echo "Gateway token: ${OPENCLAW_GATEWAY_TOKEN}"
open "${URL}" 2>/dev/null || true
