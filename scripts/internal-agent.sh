#!/usr/bin/env bash
# Runs a specialized Hermes agent inside the container (no docker compose exec).
# Supports nested agent paths (mitre/recon, owasp/injection, research/osint).
# Injects past lessons from /work/memory/lessons.jsonl for self-learning.
set -euo pipefail

AGENT="${1:-}"
shift || true
TASK="${*:-}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)_$RANDOM}"

if [ -z "$AGENT" ] || [ -z "$TASK" ]; then
  echo "Usage: internal-agent.sh <agent-path> <task description>"
  echo ""
  echo "Available agents:"
  find /agents -name "*.prompt" 2>/dev/null | sed 's|/agents/||;s|\.prompt$||' | sort | sed 's/^/  - /'
  exit 1
fi

PROMPT_FILE="/agents/${AGENT}.prompt"
if [ ! -f "$PROMPT_FILE" ]; then
  echo "Unknown agent: $AGENT (no $PROMPT_FILE)"
  exit 1
fi

mkdir -p "/work/dashboard-logs" "/work/memory/lessons"
LOG_FILE="/work/dashboard-logs/${RUN_ID}.log"
STATE_FILE="/work/dashboard-logs/${RUN_ID}.json"
DONE_FILE="/work/dashboard-logs/${RUN_ID}.done"
TIMEOUT_FLAG="/work/dashboard-logs/${RUN_ID}.timeout"
# Clear stale flags — the Continue feature reuses the same RUN_ID
rm -f "$DONE_FILE" "$TIMEOUT_FLAG"

BASE_PROMPT=$(cat "$PROMPT_FILE")

# Per-agent model tiering (PentAGI-style provider profiles)
MODEL="k3"
MODELS_FILE="/agents/models.json"
if [ -f "$MODELS_FILE" ]; then
  MODEL=$(python3 -c "import json,sys; d=json.load(open('$MODELS_FILE')); print(d.get('$AGENT', d.get('default','k3')))" 2>/dev/null || echo "k3")
fi

# Self-evolution: inject scenario-aware strategy guidance from evolution engine
STRATEGY_GUIDANCE=""
if command -v python3 >/dev/null 2>&1 && [ -f /tools/evolution_engine.py ]; then
  STRATEGY_GUIDANCE=$(python3 /tools/evolution_engine.py guidance "$TASK" "$AGENT" 2>/dev/null || true)
fi

# Self-learning: inject relevant past lessons into the prompt via RAG (Qdrant)
PAST_LESSONS=""
if command -v python3 >/dev/null 2>&1 && [ -f /tools/rag_client.py ]; then
  PAST_LESSONS=$(python3 /tools/rag_client.py search-lessons "$TASK" "$AGENT" 3 2>/dev/null | python3 -c "
import json, sys
lessons = json.load(sys.stdin)
for lesson in lessons:
    outcome = lesson.get('outcome', '')
    tools = ', '.join(lesson.get('tools_used', [])[:5])
    print(f\"- Previous {lesson.get('agent','agent')} run '{lesson.get('task','')[:60]}' ({lesson.get('status','?')}): {outcome[:120]}\")
    if tools:
        print(f\"  Tools used: {tools}\")
    print(f\"  Evidence: {', '.join(lesson.get('evidence_paths', [])[:3])}\")
    print()
" 2>/dev/null || true)
fi

# Fallback to file-based lessons if RAG is unavailable or returns nothing
if [ -z "$PAST_LESSONS" ]; then
  LESSONS_FILE="/work/memory/lessons.jsonl"
  if [ -f "$LESSONS_FILE" ] && [ -s "$LESSONS_FILE" ]; then
    PAST_LESSONS=$(python3 - "$AGENT" "$TASK" <<'PYEOF' 2>/dev/null || true
import json, sys, re
from pathlib import Path

agent = sys.argv[1] if len(sys.argv) > 1 else ""
task = sys.argv[2] if len(sys.argv) > 2 else ""
lessons_path = Path("/work/memory/lessons.jsonl")

if not lessons_path.exists():
    sys.exit(0)

task_words = set(re.findall(r"\w+", task.lower()))
matches = []

for line in lessons_path.read_text().splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        lesson = json.loads(line)
    except Exception:
        continue
    same_agent = lesson.get("agent", "") == agent
    lesson_words = set(re.findall(r"\w+", lesson.get("task", "").lower()))
    overlap = len(task_words & lesson_words)
    status_score = 1 if lesson.get("status") == "done" else 0
    score = (3 if same_agent else 0) + overlap + status_score
    if score > 0:
        matches.append((score, lesson))

matches.sort(key=lambda x: x[0], reverse=True)
for score, lesson in matches[:3]:
    outcome = lesson.get("outcome", "")
    tools = ", ".join(lesson.get("tools_used", [])[:5])
    print(f"- Previous {lesson.get('agent','agent')} run '{lesson.get('task','')[:60]}' ({lesson.get('status','?')}): {outcome[:120]}")
    if tools:
        print(f"  Tools used: {tools}")
    print(f"  Evidence: {', '.join(lesson.get('evidence_paths', [])[:3])}")
    print()
PYEOF
)
  fi
fi

# Professional attack plan: generate a structured plan from the planning engine
ATTACK_PLAN=""
TARGET=""
PLAN_FILE="/work/dashboard-logs/${RUN_ID}.plan.md"
PLAN_JSON_FILE="/work/dashboard-logs/${RUN_ID}.plan.json"
if command -v python3 >/dev/null 2>&1 && [ -f /tools/planning_engine.py ]; then
  TARGET=$(python3 - "$TASK" <<'PYEOF' 2>/dev/null || true
import re, sys
from urllib.parse import urlparse
task = sys.argv[1]
m = re.search(r"https?://[^\s/'\"]+", task)
if m:
    host = urlparse(m.group(0)).netloc.split(":")[0]
    if host:
        print(host)
        sys.exit(0)
m = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b", task)
print(m.group(1) if m else "")
PYEOF
)
  if [ -n "$TARGET" ]; then
    ATTACK_PLAN=$(python3 /tools/planning_engine.py markdown "$TARGET" "$TASK" 2>/dev/null || true)
    if [ -n "$ATTACK_PLAN" ]; then
      printf '%s\n' "$ATTACK_PLAN" > "$PLAN_FILE" 2>/dev/null || true
    fi
    python3 /tools/planning_engine.py generate "$TARGET" "$TASK" > "$PLAN_JSON_FILE" 2>/dev/null || true
  fi
fi

# Build final prompt with strategy guidance + past lessons + attack plan
PROMPT="$BASE_PROMPT"
if [ -n "$ATTACK_PLAN" ]; then
  PROMPT="${PROMPT}

## ATTACK PLAN (pre-generated by the planning engine)
${ATTACK_PLAN}

Follow this plan's phases in order. Use the recommended tools, techniques, and decision points. Adapt when the situation demands it, but document every deviation and why you made it.

The engagement runner hands you ONE phase at a time. When you finish the phase you were given, output exactly: PHASE_COMPLETE: <phase name>. If you are truly blocked after real effort, output exactly: PHASE_BLOCKED: <phase name> — <reason>. These markers drive the runner; never emit them prematurely."
fi
if [ -n "$STRATEGY_GUIDANCE" ]; then
  PROMPT="${PROMPT}

${STRATEGY_GUIDANCE}"
fi
if [ -n "$PAST_LESSONS" ]; then
  PROMPT="${PROMPT}

## PAST LESSONS (self-learning memory)
The following lessons were learned from previous runs. Use them to improve your approach:
${PAST_LESSONS}

Apply these lessons where relevant; do not repeat past mistakes."
fi
if [ -n "$TARGET" ]; then
  PROMPT="${PROMPT}

## FINDINGS CONTRACT (mandatory)
Record EVERY finding as one JSON object per line in /work/loot/${TARGET}/findings.jsonl — append incrementally as you discover them, never wait until the end:
{\"id\":\"F-001\",\"title\":\"...\",\"type\":\"sqli|xss|ssrf|lfi|rce|info disclosure|auth-bypass|idor|csrf|jwt|xxe|ssti|file upload|misconfiguration|other\",\"severity\":\"critical|high|medium|low|info\",\"detail\":\"what it is and how you verified it\",\"evidence\":[\"/work/loot/${TARGET}/path-to-raw-output\"]}
Rules: severity reflects real exploitability, detail must say how it was verified, evidence must point to saved raw output. This file drives automated chain analysis and the final business report after your run — if it is empty or malformed, your work produces no deliverable. Large engine/tool outputs go to files under /work/loot/${TARGET}/ and are referenced by path, not pasted into chat."
fi

# Write initial run state
cat > "$STATE_FILE" <<EOF
{
  "run_id": "${RUN_ID}",
  "agent": "${AGENT}",
  "model": "${MODEL}",
  "task": "${TASK}",
  "status": "running",
  "started_at": "$(date -Iseconds)",
  "log_file": "${LOG_FILE}",
  "plan_file": $(if [ -n "$ATTACK_PLAN" ]; then echo "\"${PLAN_FILE}\""; else echo "null"; fi),
  "lessons_injected": $(if [ -n "$PAST_LESSONS" ]; then echo 3; else echo 0; fi)
}
EOF

echo "==> Agent: ${AGENT}" | tee -a "$LOG_FILE"
echo "==> Model: ${MODEL}" | tee -a "$LOG_FILE"
echo "==> Task: ${TASK}" | tee -a "$LOG_FILE"
echo "==> Run ID: ${RUN_ID}" | tee -a "$LOG_FILE"
echo "==> Started: $(date -Iseconds)" | tee -a "$LOG_FILE"
echo "==> Lessons injected: $(if [ -n "$PAST_LESSONS" ]; then echo 3; else echo 0; fi)" | tee -a "$LOG_FILE"
echo "==> Attack plan: $(if [ -n "$ATTACK_PLAN" ]; then echo "generated (see ${PLAN_FILE})"; else echo "not generated"; fi)" | tee -a "$LOG_FILE"

# Check and optionally install required tools for this agent
TOOLS_STATUS=$(python3 /tools/tool_installer.py "${AGENT}" --json 2>/dev/null || echo '{}')
MISSING_COUNT=$(echo "$TOOLS_STATUS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('missing',[])))" 2>/dev/null || echo "0")
if [ "$MISSING_COUNT" -gt 0 ]; then
  echo "==> Installing missing tools..." | tee -a "$LOG_FILE"
  python3 /tools/tool_installer.py "${AGENT}" --install 2>&1 | tee -a "$LOG_FILE"
fi
echo "==> Tools ready: $(echo "$TOOLS_STATUS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('tools',[])))" 2>/dev/null || echo "0") available, ${MISSING_COUNT} missing" | tee -a "$LOG_FILE"

# Two-tier agent budget check
BUDGET=$(python3 /tools/agent_budgets.py get "${AGENT}" 2>/dev/null || echo '{"tier":"general","max_tool_calls":100}')
TIER=$(echo "$BUDGET" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tier','general'))" 2>/dev/null || echo "general")
MAX_CALLS=$(echo "$BUDGET" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('max_tool_calls',100))" 2>/dev/null || echo "100")
echo "==> Agent tier: ${TIER} (max ${MAX_CALLS} tool calls)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Run the engagement runner: phase-chunked, long-running, self-healing.
# The runner executes the attack plan phase by phase, resuming the same Hermes
# session across turns, retrying failed phases with adapted approaches, and
# injecting operator instructions between turns. The assembled prompt is passed
# by file (it can be large); output is appended to the run log.
PROMPT_PATH="/work/dashboard-logs/${RUN_ID}.prompt"
printf '%s\n' "$PROMPT" > "$PROMPT_PATH"
set +e
python3 /tools/engagement_runner.py "$RUN_ID" "$AGENT" "$TASK" "$TARGET" "$PLAN_JSON_FILE" "$PROMPT_PATH" "$MODEL" "$MAX_CALLS" >> "$LOG_FILE" 2>&1 &
HERMES_PID=$!

# Background stream monitor: share findings and check for instructions
# NOTE: a killed Hermes becomes a zombie and kill -0 still succeeds on it, so the
# loop must also stop on the done-file; the EXIT trap guarantees cleanup.
STREAM_MONITOR_PID=""

cleanup() {
  touch "$DONE_FILE" 2>/dev/null || true
  if [ -n "${STREAM_MONITOR_PID:-}" ]; then
    kill "$STREAM_MONITOR_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if command -v python3 >/dev/null 2>&1 && [ -f /tools/stream_manager.py ]; then
  (
    while kill -0 "$HERMES_PID" 2>/dev/null && [ ! -f "$DONE_FILE" ]; do
      # Check for new log content and share findings
      if [ -f "$LOG_FILE" ]; then
        # Share new findings from log lines
        NEW_FINDINGS=$(tail -n 50 "$LOG_FILE" 2>/dev/null | grep -E "(FOUND|VULNERABILITY|CRITICAL|HIGH|MEDIUM|LOW|Discovered|Detected|Identified|Found)" | head -n 5 || true)
        if [ -n "$NEW_FINDINGS" ]; then
          echo "$NEW_FINDINGS" | while IFS= read -r line; do
            python3 /tools/stream_manager.py share-finding "$RUN_ID" "discovery" "Log Finding" "$line" "info" 2>/dev/null || true
          done
        fi
      fi

      # NOTE: pending operator instructions are consumed by the engagement
      # runner between turns — do NOT mark them read here or the runner
      # would never see them.

      sleep 2
    done
  ) &
  STREAM_MONITOR_PID=$!
fi

# Wait for the engagement runner. It manages its own per-turn timeouts, phase
# retries, and the optional wall-clock cap (AGENT_ENGAGEMENT_MAX_HOURS), so no
# external watchdog is needed — exit code 124 means the wall clock was hit and
# the engagement is resumable via Continue.
wait "$HERMES_PID" 2>/dev/null
EXIT_CODE=$?

if [ "$EXIT_CODE" -eq 124 ]; then
  echo "==> WALL CLOCK: engagement paused (state saved) — resume with Continue" | tee -a "$LOG_FILE"
  STATUS="timeout"
fi

# The runner has been reaped by wait above, so the monitor's kill -0 now fails
# and it exits on its own; the EXIT trap touches the done-file as a backstop.
STATUS="${STATUS:-done}"
if [ "$EXIT_CODE" -ne 0 ] && [ "$STATUS" != "timeout" ]; then
  STATUS="failed"
fi

# Save wall-clock-pause state for resuming
if [ "$STATUS" = "timeout" ]; then
  echo "==> Engagement paused (wall clock). Use 'Continue' to resume at the current phase." | tee -a "$LOG_FILE"
  # Save detailed state for high-quality continuation
  python3 /tools/stream_manager.py save-state "$RUN_ID" "{\"status\":\"timeout\",\"task\":\"${TASK}\",\"agent\":\"${AGENT}\",\"log_file\":\"${LOG_FILE}\",\"resumable\":true}" 2>/dev/null || true
fi

# Extract lessons from the run for the self-learning memory
LESSON_OUTCOME=""
TOOLS_USED=""
EVIDENCE_PATHS=""
if [ -f "$LOG_FILE" ]; then
  # Try to extract the final response/summary
  LESSON_OUTCOME=$(tail -n 20 "$LOG_FILE" | grep -v "^==>" | head -n 5 | tr '\n' ' ' | cut -c1-300 || echo "")
  # Extract tool names mentioned in the log (common offensive-security tools)
  TOOLS_USED=$(grep -oP '\b(nmap|sqlmap|gobuster|ffuf|nikto|hydra|metasploit|msfconsole|searchsploit|curl|wget|python3|bash|powershell|evil-winrm|netexec|impacket|bloodhound|responder|john|hashcat|sslyze|sslscan|testssl|whatweb|wappalyzer|subfinder|amass|theHarvester|dnsrecon|dnsenum|masscan|rustscan|nc|netcat|socat|ssh|scp|rsync|ftp|tftp|telnet|rdp|vnc|mitmproxy|burp|zap|postman|httpie|jq|awk|sed|grep|find|cat|tar|zip|unzip|7z|openssl|gpg|base64|xxd|hexdump|strings|file|binwalk|dd|mount|umount|fdisk|gdisk|parted|mkfs|fsck|blkid|lsblk|df|du|free|top|htop|ps|kill|killall|pkill|pgrep|watch|screen|tmux|crontab|at|systemctl|service|journalctl|dmesg|lsmod|modprobe|sysctl|lscpu|lsusb|lspci|lshw|dmidecode|hdparm|smartctl|tcpdump|wireshark|tshark|ngrep|ettercap|bettercap|arpspoof|dnsspoof|ip|ifconfig|iwconfig|iw|ethtool|route|netstat|ss|lsof|fuser|pmap|vmstat|iostat|mpstat|sar|pidstat|glances|atop|nmon|lsb_release|hostnamectl|timedatectl|localectl|loginctl|nmtui|nmcli)\b' "$LOG_FILE" | sort -u | tr '\n' ',' | sed 's/,$//' || echo "")
  # Extract evidence paths mentioned
  EVIDENCE_PATHS=$(grep -oP '/work/loot/[^\s"'"'"']+' "$LOG_FILE" | sort -u | head -n 10 | tr '\n' ',' | sed 's/,$//' || echo "")
fi

# Phase 1 fix: prefer the structured findings contract for evidence paths.
# Grepping the log captured malformed fragments (e.g. "{headers.txt",
# "findings.jsonl)") that polluted strategy.json / lessons memory. When the
# findings.jsonl contract exists, derive clean, validated evidence from it.
if [ -n "$TARGET" ] && [ -s "/work/loot/${TARGET}/findings.jsonl" ]; then
  _CLEAN_EVIDENCE=$(python3 - "/work/loot/${TARGET}/findings.jsonl" <<'PYEOF' 2>/dev/null || true
import json, sys
seen, paths = set(), []
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    try:
        f = json.loads(line)
    except Exception:
        continue
    for ev in (f.get("evidence") or []):
        ev = str(ev).strip()
        if ev.startswith("/work/loot/") and ev not in seen and not any(c in ev for c in "{}()"):
            seen.add(ev); paths.append(ev)
print(",".join(paths[:15]))
PYEOF
)
  if [ -n "$_CLEAN_EVIDENCE" ]; then
    EVIDENCE_PATHS="$_CLEAN_EVIDENCE"
  fi
fi

# Append lesson to self-learning memory (file + Qdrant RAG)
if [ -n "$LESSON_OUTCOME" ] || [ "$STATUS" = "failed" ]; then
  python3 <<PYEOF 2>/dev/null || true
import json
from datetime import datetime, timezone

lesson = {
    "run_id": "${RUN_ID}",
    "agent": "${AGENT}",
    "model": "${MODEL}",
    "task": "${TASK}",
    "status": "${STATUS}",
    "exit_code": ${EXIT_CODE},
    "outcome": """${LESSON_OUTCOME}""".strip(),
    "tools_used": [t for t in """${TOOLS_USED}""".split(",") if t],
    "evidence_paths": [p for p in """${EVIDENCE_PATHS}""".split(",") if p],
    "timestamp": datetime.now(timezone.utc).isoformat()
}

# Write to file-based memory
with open("/work/memory/lessons.jsonl", "a") as f:
    f.write(json.dumps(lesson) + "\n")

# Upsert to Qdrant RAG
try:
    import subprocess, sys
    subprocess.run([sys.executable, "/tools/rag_client.py", "upsert-lesson", json.dumps(lesson)],
                   capture_output=True, timeout=30)
except Exception:
    pass

# Run post-run evolution (update strategy memory + prompts)
try:
    import subprocess, sys
    subprocess.run([sys.executable, "/tools/evolution_engine.py", "post-run", json.dumps(lesson)],
                   capture_output=True, timeout=30)
except Exception:
    pass

# Update patterns
patterns_path = "/work/memory/patterns.json"
try:
    with open(patterns_path) as f:
        patterns = json.load(f)
except Exception:
    patterns = {}

agent = "${AGENT}"
if agent not in patterns:
    patterns[agent] = {"runs": 0, "success": 0, "failed": 0, "tools": {}}

patterns[agent]["runs"] = patterns[agent].get("runs", 0) + 1
if "${STATUS}" == "done":
    patterns[agent]["success"] = patterns[agent].get("success", 0) + 1
else:
    patterns[agent]["failed"] = patterns[agent].get("failed", 0) + 1

for tool in lesson["tools_used"]:
    patterns[agent]["tools"][tool] = patterns[agent]["tools"].get(tool, 0) + 1

with open(patterns_path, "w") as f:
    json.dump(patterns, f, indent=2)
PYEOF
fi

# Post-run: automated chain analysis + business report from structured findings.
# Runs even on timeout — partial findings still produce a deliverable.
CHAINS_FILE=""
AUTO_REPORT=""
FINDINGS_FILE="/work/loot/${TARGET}/findings.jsonl"
if [ -n "$TARGET" ] && [ -s "$FINDINGS_FILE" ]; then
  echo "==> Post-run: findings contract found, running chain analysis + report..." | tee -a "$LOG_FILE"
  FINDINGS_CONSOLIDATED="/work/loot/${TARGET}/findings.consolidated.json"
  AUTO_REPORT_JSON="/work/loot/${TARGET}/auto-report.json"
  python3 - "$FINDINGS_FILE" "$FINDINGS_CONSOLIDATED" <<'PYEOF' 2>/dev/null || true
import json, sys
findings = []
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    try:
        findings.append(json.loads(line))
    except Exception:
        continue
json.dump({"findings": findings}, open(sys.argv[2], "w"), indent=2)
print(len(findings))
PYEOF
  if [ -s "$FINDINGS_CONSOLIDATED" ]; then
    WANT_CHAINS="/work/loot/${TARGET}/chains.json"
    if python3 /tools/chain_engine.py identify "$FINDINGS_CONSOLIDATED" > /tmp/${RUN_ID}_chains_raw.json 2>/dev/null; then
      if python3 - "/tmp/${RUN_ID}_chains_raw.json" "$WANT_CHAINS" <<'PYEOF' 2>/dev/null
import json, sys
chains = json.load(open(sys.argv[1]))
json.dump({"chains": chains if isinstance(chains, list) else []}, open(sys.argv[2], "w"), indent=2)
PYEOF
      then
        CHAINS_FILE="$WANT_CHAINS"
      fi
    fi
    THREAT_JSON="{}"
    if [ -s "$PLAN_JSON_FILE" ]; then
      THREAT_JSON=$(python3 -c "import json; print(json.dumps(json.load(open('$PLAN_JSON_FILE')).get('threat_model', {})))" 2>/dev/null || echo '{}')
    fi
    CHAINS_ARG='{"chains":[]}'
    if [ -n "$CHAINS_FILE" ]; then
      CHAINS_ARG="$CHAINS_FILE"
    fi
    if python3 /tools/reporting_engine.py generate "$TARGET" "$FINDINGS_CONSOLIDATED" "$CHAINS_ARG" "$THREAT_JSON" > "$AUTO_REPORT_JSON" 2>/dev/null; then
      AUTO_REPORT=$(python3 -c "import json; print(json.load(open('$AUTO_REPORT_JSON')).get('report_file', ''))" 2>/dev/null || echo "")
      echo "==> Post-run: chains -> ${CHAINS_FILE}" | tee -a "$LOG_FILE"
      echo "==> Post-run: business report -> ${AUTO_REPORT:-failed}" | tee -a "$LOG_FILE"
    else
      echo "==> Post-run: report generation failed (see ${AUTO_REPORT_JSON})" | tee -a "$LOG_FILE"
    fi
  fi
fi

# Finalize run state
cat > "$STATE_FILE" <<EOF
{
  "run_id": "${RUN_ID}",
  "agent": "${AGENT}",
  "model": "${MODEL}",
  "task": "${TASK}",
  "status": "${STATUS}",
  "exit_code": ${EXIT_CODE},
  "started_at": "$(grep -oP '"started_at": "\K[^"]+' "$STATE_FILE" || date -Iseconds)",
  "finished_at": "$(date -Iseconds)",
  "log_file": "${LOG_FILE}",
  "plan_file": $(if [ -n "$ATTACK_PLAN" ]; then echo "\"${PLAN_FILE}\""; else echo "null"; fi),
  "chains_file": $(if [ -n "$CHAINS_FILE" ]; then echo "\"${CHAINS_FILE}\""; else echo "null"; fi),
  "report_file": $(if [ -n "$AUTO_REPORT" ]; then echo "\"${AUTO_REPORT}\""; else echo "null"; fi),
  "lessons_injected": $(if [ -n "$PAST_LESSONS" ]; then echo 3; else echo 0; fi),
  "lesson_written": $(if [ -n "$LESSON_OUTCOME" ] || [ "$STATUS" = "failed" ] || [ "$STATUS" = "timeout" ]; then echo "true"; else echo "false"; fi),
  "can_continue": $(if [ "$STATUS" = "done" ] || [ "$STATUS" = "failed" ] || [ "$STATUS" = "timeout" ]; then echo "true"; else echo "false"; fi)
}
EOF

echo "" | tee -a "$LOG_FILE"
echo "==> Finished: $(date -Iseconds)" | tee -a "$LOG_FILE"
echo "==> Status: ${STATUS} (exit ${EXIT_CODE})" | tee -a "$LOG_FILE"
echo "==> Lesson written: $(if [ -n "$LESSON_OUTCOME" ] || [ "$STATUS" = "failed" ]; then echo "yes"; else echo "no"; fi)" | tee -a "$LOG_FILE"

exit "$EXIT_CODE"
