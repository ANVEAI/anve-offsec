#!/usr/bin/env python3
"""
Model router for kali-ai (Phase 6 — cost/latency-aware routing).

Routes each task-class to the right model tier so the premium reasoning
model is not burned on high-volume grunt work, and relieves the Kimi
quota ceiling by pushing parsing/summarize/dedup work to a cheaper model
(or a local fallback when available).

Usage: python3 /tools/model_router.py <command> [args]

Commands:
  route <task_class>                       Map a task class -> model + tier.
  for-agent <agent_name>                   Resolve the model for an agent.
  plan-budget <total_usd> <n_phases>       Suggest a per-phase cost split.
  estimate <model> <in_tokens> <out_tokens>  Rough cost estimate (approx).
"""

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# OPERATOR-EDITABLE TABLES — adjust model ids / prices to match your account.
# ---------------------------------------------------------------------------

# Model ids per tier. Edit these to point at your provisioned models.
MODELS = {
    "PLAN": "k3",               # deep reasoning: planning, exploitation, chaining
    "WORK": "k3",               # balanced: recon, web, api, scanning, enumeration
    "CHEAP": "kimi-for-coding",  # high-volume parsing / summarize / dedup / format
}

# Local model used as a CHEAP fallback when present (no API cost).
LOCAL_MODEL = "ollama/qwen2.5-coder"

# Approximate USD per 1M tokens {input, output}. EDIT-ME: these are rough
# placeholder rates for budgeting only — confirm against your billing.
PRICES: Dict[str, Dict[str, float]] = {
    "k3":              {"input": 0.60, "output": 2.50},   # Kimi K3 max (approx)
    "kimi-for-coding": {"input": 0.15, "output": 0.60},   # cheaper coding tier (approx)
    "ollama/qwen2.5-coder": {"input": 0.0, "output": 0.0},  # local, no API cost
}

# Task-class -> tier mapping.
TASK_TIERS: Dict[str, str] = {
    # PLAN tier (deep reasoning)
    "planning": "PLAN", "reflection": "PLAN", "exploitation": "PLAN",
    "chaining": "PLAN", "privesc": "PLAN",
    # WORK tier (balanced)
    "recon": "WORK", "web": "WORK", "api": "WORK",
    "scanning": "WORK", "enumeration": "WORK",
    # CHEAP tier (high-volume parsing/formatting)
    "parse": "CHEAP", "summarize": "CHEAP", "dedup": "CHEAP",
    "report-format": "CHEAP", "classify": "CHEAP", "triage": "CHEAP",
}

# Keywords used to fall back an agent name -> tier when unmapped in config.
CHEAP_AGENT_KEYWORDS = ["report", "curator", "parse", "summar", "dedup", "format", "triage", "classif"]
PLAN_AGENT_KEYWORDS = ["plan", "reflect", "exploit", "chain", "privesc", "advis", "barrier"]

MODELS_CONFIG = Path("/config/agents/models.json")


def _local_available() -> Optional[str]:
    """Return the local fallback model id if a local runtime looks present."""
    if os.environ.get("KALI_LOCAL_MODEL"):
        return os.environ["KALI_LOCAL_MODEL"]
    if shutil.which("ollama"):
        return LOCAL_MODEL
    return None


def route(task_class: str) -> dict:
    """Map a task class to a model id, tier, and (for CHEAP) a local fallback."""
    tc = (task_class or "").strip().lower()
    tier = TASK_TIERS.get(tc)
    if tier is None:
        # Unknown class: bias toward WORK (balanced) unless it smells cheap.
        if any(k in tc for k in ["parse", "summar", "dedup", "format", "triage", "classif"]):
            tier = "CHEAP"
        elif any(k in tc for k in ["plan", "reflect", "exploit", "chain", "privesc"]):
            tier = "PLAN"
        else:
            tier = "WORK"
        reason = f"'{task_class}' not in TASK_TIERS; inferred {tier} by keyword"
    else:
        reason = f"'{task_class}' mapped to {tier} tier"

    model = MODELS[tier]
    local_fallback = _local_available() if tier == "CHEAP" else None
    return {
        "task_class": task_class,
        "tier": tier,
        "model": model,
        "local_fallback": local_fallback,
        "reason": reason,
    }


def for_agent(agent_name: str) -> dict:
    """Resolve the configured model for an agent from /config/agents/models.json.

    Falls back to route() heuristics by agent-name keywords when the agent
    is absent from the config.
    """
    name = (agent_name or "").strip()
    config: Dict[str, str] = {}
    config_error = None
    try:
        if MODELS_CONFIG.exists():
            config = json.loads(MODELS_CONFIG.read_text(encoding="utf-8"))
        else:
            config_error = "models.json not found"
    except Exception as e:
        config_error = f"models.json unreadable: {e}"

    # Exact match, then case-insensitive match against config keys.
    if name in config:
        return {"agent": name, "model": config[name], "source": "config"}
    for key, val in config.items():
        if key.lower() == name.lower():
            return {"agent": name, "model": val, "source": "config"}

    # Heuristic fallback by agent-name keywords.
    low = name.lower()
    if any(k in low for k in CHEAP_AGENT_KEYWORDS):
        tier = "CHEAP"
    elif any(k in low for k in PLAN_AGENT_KEYWORDS):
        tier = "PLAN"
    else:
        tier = "WORK"
    model = config.get("default", MODELS[tier])
    out = {
        "agent": name,
        "model": model,
        "source": "heuristic",
        "tier": tier,
        "local_fallback": _local_available() if tier == "CHEAP" else None,
    }
    if config_error:
        out["note"] = config_error
    return out


def plan_budget(total_usd: float, n_phases: int) -> dict:
    """Suggest a per-phase cost split; planning-heavy early phases get more.

    Weights taper: earliest phases (planning/recon) receive a larger share
    than later formatting/reporting phases.
    """
    if n_phases <= 0:
        return {"error": "n_phases must be >= 1"}
    if total_usd < 0:
        return {"error": "total_usd must be >= 0"}
    # Descending weights: phase 1 gets the most, tapering linearly but never <1.
    weights = [max(1.0, n_phases - i * 0.5) for i in range(n_phases)]
    wsum = sum(weights)
    per_phase = [round(total_usd * (w / wsum), 4) for w in weights]
    # Correct rounding drift onto the first phase.
    drift = round(total_usd - sum(per_phase), 4)
    if per_phase:
        per_phase[0] = round(per_phase[0] + drift, 4)
    return {
        "total_usd": total_usd,
        "n_phases": n_phases,
        "per_phase": per_phase,
        "note": "Early phases (planning/recon) weighted higher than late "
                "phases (reporting/formatting). Edit weights in plan_budget().",
    }


def estimate(model: str, input_tokens: int, output_tokens: int) -> dict:
    """Rough USD cost estimate from the PRICES table (approximate)."""
    price = PRICES.get(model)
    if price is None:
        return {"model": model, "error": "unknown model — not in PRICES table",
                "known_models": list(PRICES.keys())}
    usd = (input_tokens / 1_000_000.0) * price["input"] + \
          (output_tokens / 1_000_000.0) * price["output"]
    return {
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "usd": round(usd, 6),
        "note": "approximate — prices in PRICES are operator-editable placeholders",
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]
    try:
        if cmd == "route":
            if not args:
                print(json.dumps({"error": "usage: route <task_class>"}))
                sys.exit(1)
            print(json.dumps(route(args[0]), indent=2))
        elif cmd == "for-agent":
            if not args:
                print(json.dumps({"error": "usage: for-agent <agent_name>"}))
                sys.exit(1)
            print(json.dumps(for_agent(args[0]), indent=2))
        elif cmd == "plan-budget":
            if len(args) < 2:
                print(json.dumps({"error": "usage: plan-budget <total_usd> <n_phases>"}))
                sys.exit(1)
            print(json.dumps(plan_budget(float(args[0]), int(args[1])), indent=2))
        elif cmd == "estimate":
            if len(args) < 3:
                print(json.dumps({"error": "usage: estimate <model> <in_tokens> <out_tokens>"}))
                sys.exit(1)
            print(json.dumps(estimate(args[0], int(args[1]), int(args[2])), indent=2))
        else:
            print(json.dumps({"error": f"unknown command: {cmd}"}))
            print(__doc__)
            sys.exit(1)
    except ValueError as e:
        print(json.dumps({"error": f"invalid numeric argument: {e}"}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
