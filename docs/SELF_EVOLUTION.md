# 🧬 Self-Evolution & Vector RAG Specification (`tools/evolution_engine.py`)

This document details **anve-offsec**'s self-learning engine, vector memory indexing in Qdrant, strategy memory structure, and dynamic prompt injection algorithms.

---

## 🔁 The Evolution Feedback Loop

```
+-------------------------------------------------------------------------------+
|                           Post-Run Learning Pipeline                          |
|                                                                               |
|  [Completed Run] ──► [Extract Scenario] ──► [Score Strategy] ──► [Qdrant RAG] |
|                                                                       │       |
|                                                                       ▼       |
|  [Next Run] ◄── [Inject Strategy Guidance] ◄── [Query Vector DB] ◄────┘       |
+-------------------------------------------------------------------------------+
```

---

## 📊 Strategy Memory Structure (`/work/memory/strategy.json`)

The evolution engine tracks historical performance across target scenarios:

```json
{
  "scenarios": {
    "web-app:sql-injection": {
      "target_type": "web-app",
      "vuln_class": "sql-injection",
      "best_tools": ["sqlmap", "manual-payloads"],
      "success_rate": 0.85,
      "avg_time_minutes": 12,
      "common_failures": ["waf-blocked", "parameter-not-injectable"],
      "confidence": 0.9,
      "run_count": 15
    },
    "api:idor": {
      "target_type": "api",
      "vuln_class": "idor",
      "best_tools": ["idor_scanner.py", "openclaw"],
      "success_rate": 0.78,
      "avg_time_minutes": 9,
      "confidence": 0.82,
      "run_count": 8
    }
  }
}
```

---

## 🎯 Confidence Thresholding Heuristics

1. **Eligible Strategy Injection (`CONFIDENCE_THRESHOLD = 0.7`)**:
   When a new run starts, `evolution_engine.py` queries Qdrant for similar scenarios. If the strategy confidence score is $> 0.7$, it injects empirical guidance into Hermes' prompt.
2. **Static Prompt Auto-Evolution (`AUTO_PROMPT_UPDATE_THRESHOLD = 0.85`)**:
   When a strategy achieves $> 85\%$ success across at least 10 runs, the engine automatically updates the static prompt file (`/config/agents/*.prompt`) to make the strategy baseline behavior for all future deployments.

---

## 💉 Dynamic Strategy Injection Example

Before launching a phase, the following strategy block is appended to `HERMES_EPHEMERAL_SYSTEM_PROMPT`:

```text
## STRATEGY GUIDANCE (from self-evolution memory)
Scenario: web-app:sql-injection (similar to 15 past runs)
- Best tools: sqlmap (85% success), manual payloads (72% success)
- Recommended order: recon -> parameter mapping -> sqlmap --batch --tamper=space2comment
- Common pitfalls: WAF blocks (use space2comment), false positives (verify with time-based)
- Expected time: ~12 minutes
```
