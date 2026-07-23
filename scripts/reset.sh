#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose down --remove-orphans
docker compose build --no-cache
echo "Reset complete. Start a fresh shell with: ./scripts/shell.sh"
