#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

TASK="${*:-}"
if [ -z "$TASK" ]; then
  echo "Usage: $0 <browser task description>"
  echo "Example: $0 'navigate to https://example.com and report the page title'"
  exit 1
fi

# Run the OpenClaw agent turn inside the openclaw sidecar container.
# The gateway listens on localhost inside that container, so no extra
# gateway URL / device-pairing setup is required from the kali-ai host.
# The model used is configured in config/openclaw/openclaw.json.
docker compose exec openclaw \
  openclaw agent --agent main --message "$TASK" --thinking medium
