#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

AGENT="${1:-}"
shift || true
TASK="${*:-}"

if [ -z "$AGENT" ] || [ -z "$TASK" ]; then
  echo "Usage: launch-agent.sh <agent-name> <task description>"
  echo ""
  echo "Available agents:"
  ls -1 config/agents/*.prompt 2>/dev/null | sed 's|config/agents/||;s|\.prompt$||' | sed 's/^/  - /'
  exit 1
fi

PROMPT_FILE="config/agents/${AGENT}.prompt"
if [ ! -f "$PROMPT_FILE" ]; then
  echo "Unknown agent: $AGENT (no $PROMPT_FILE)"
  exit 1
fi

PROMPT=$(cat "$PROMPT_FILE")

# HERMES_EPHEMERAL_SYSTEM_PROMPT injects the agent persona for this session only.
# We run in quiet mode so output is suitable for piping/logging.
docker compose exec -e HERMES_EPHEMERAL_SYSTEM_PROMPT="$PROMPT" kali \
  hermes chat -Q --max-turns 20 -q "$TASK"
