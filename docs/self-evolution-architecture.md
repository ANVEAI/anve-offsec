# kali-ai Self-Evolution Architecture

## Overview

kali-ai is designed to be a continuously learning and evolving offensive-security platform. It doesn't just execute tasks — it learns from every action, identifies what works in each scenario, updates its own strategies, and suggests next steps based on accumulated experience.

## Core Components

### 1. Strategy Memory (`/work/memory/strategy.json`)

Structured knowledge about what works in each scenario:

```json
{
  "scenarios": {
    "web-app:sql-injection": {
      "target_type": "web-app",
      "vuln_class": "sql-injection",
      "tools": ["sqlmap", "burp", "manual-payloads"],
      "techniques": ["error-based", "time-based", "union-based"],
      "success_rate": 0.85,
      "avg_time_minutes": 12,
      "common_failures": ["waf-blocked", "parameter-not-injectable"],
      "confidence": 0.9,
      "last_updated": "2026-07-21T10:00:00Z",
      "run_count": 15,
      "evidence": ["/work/loot/target1/", "/work/loot/target2/"]
    }
  },
  "target_profiles": {
    "dvwa": {
      "os": "linux",
      "services": ["http", "mysql"],
      "technologies": ["php", "apache"],
      "vuln_classes": ["sqli", "xss", "csrf", "lfi", "command-injection"],
      "best_agents": ["bug-bounty", "owasp/injection"],
      "success_rate": 0.92
    }
  },
  "tool_effectiveness": {
    "sqlmap": {"success": 12, "failed": 3, "avg_time": 8},
    "nmap": {"success": 45, "failed": 2, "avg_time": 3},
    "zap": {"success": 8, "failed": 1, "avg_time": 15}
  },
  "next_step_suggestions": {
    "recon:web-found": ["web-agent", "owasp/injection", "owasp/misconfig"],
    "web:vuln-found": ["exploit-agent", "owasp/injection"],
    "ad:smb-found": ["ad-agent", "mitre/credential-access"]
  }
}
```

### 2. Evolution Engine (`/tools/evolution_engine.py`)

The brain that learns from runs and updates the system:

**Post-Run Loop** (after every agent run):
1. Extract scenario (target type, vuln class, service)
2. Extract strategy used (tools, techniques, order)
3. Extract outcome (success, time, failures)
4. Update strategy memory with new data point
5. Recalculate confidence scores
6. Update agent prompt if the strategy is significantly better/worse

**Periodic Deep Review** (every N runs or on demand):
1. Analyze all lessons and identify patterns
2. Cluster similar scenarios and identify best strategies
3. Update agent prompts with new strategy guidance
4. Prune low-confidence or outdated strategies
5. Suggest new agent types or modifications
6. Generate evolution report

**Proactive Suggestion Loop** (before a new run):
1. Analyze the task/target to identify the scenario
2. Look up similar past scenarios in strategy memory
3. Retrieve the best strategy (tools, techniques, order)
4. Inject scenario-specific guidance into the agent prompt
5. Suggest next steps after the current run completes

### 3. Self-Evolving Agent Prompts

Agent prompts now have three layers:

1. **Base Layer** (static): Defines the agent's role, scope, and rules (from `.prompt` files)
2. **Strategy Layer** (dynamic): Scenario-specific guidance from strategy memory (injected via `HERMES_EPHEMERAL_SYSTEM_PROMPT`)
3. **Feedback Layer** (dynamic): Recent lessons and what worked/didn't in similar scenarios (injected via RAG)

Example injected strategy guidance:

```
## STRATEGY GUIDANCE (from self-evolution memory)
Scenario: web-app:sql-injection (similar to 15 past runs)
- Best tools: sqlmap (85% success), burp (78% success), manual payloads (72% success)
- Recommended order: recon → parameter mapping → sqlmap --batch → manual verification
- Common pitfalls: WAF blocks (use --tamper=space2comment), false positives (verify with time-based)
- Expected time: ~12 minutes
- Next steps if successful: exploit-agent, report-agent
- Next steps if failed: research/exploit-db, reflect-agent
```

### 4. Continuous Evolution Loops

**Loop 1: Post-Run (immediate)**
- Trigger: every agent run completes
- Action: extract lesson, update strategy memory, update prompt if needed
- Output: updated strategy.json, possibly updated .prompt file

**Loop 2: Periodic Deep Review (every 10 runs or daily)**
- Trigger: run count threshold or time threshold
- Action: analyze all lessons, identify patterns, update all prompts
- Output: evolution report, updated prompts, pruned strategies

**Loop 3: Proactive Suggestion (before a new run)**
- Trigger: new agent run launched
- Action: identify scenario, retrieve best strategy, inject guidance
- Output: scenario-aware prompt with strategy guidance

**Loop 4: Cross-Agent Learning (after a successful run)**
- Trigger: high-success run completes
- Action: share the successful strategy with related agents
- Output: updated prompts for related agents, shared strategy

## Data Flow

```
Agent Run
  → Log + Evidence
    → Lesson Extraction (internal-agent.sh)
      → lessons.jsonl + Qdrant (RAG)
        → Evolution Engine (post-run loop)
          → strategy.json (updated)
            → Agent Prompt (strategy layer)
              → Next Agent Run (better informed)
                → ...
```

## Evolution Metrics

Track these to measure self-improvement over time:

- **Success rate**: % of runs that complete successfully (target: trending upward)
- **Time to result**: average time per scenario (target: trending downward)
- **Tool effectiveness**: success rate per tool per scenario (target: identify best tools)
- **Strategy confidence**: how much we trust each strategy (target: high-confidence strategies win)
- **Scenario coverage**: % of known scenarios with a proven strategy (target: expanding)
- **Prompt evolution**: number of prompt updates from learning (target: continuous)

## Safety and Guardrails

- **Human approval for destructive actions**: never auto-approve destructive actions
- **Confidence thresholds**: only use strategies with confidence > 0.7 for auto-execution
- **Rollback**: keep previous prompt versions for rollback if a new strategy fails
- **Rate limiting**: don't auto-run more than N consecutive runs without human review
- **Scope enforcement**: never exceed the authorized target scope, even if a strategy suggests it
