#!/usr/bin/env python3
"""
Two-tier agent budget manager for kali-ai.

Enforces tool call budgets per agent type:
- General agents (100 tool calls): Assistant, Primary Agent, Pentester, Coder, Installer
- Limited agents (20 tool calls): Searcher, Enricher, Memorist, Generator, Reporter, Adviser, Reflector, Planner

Inspired by PentAGI's two-tier agent budgets.

Usage: python3 /tools/agent_budgets.py <command> [args]
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

BUDGETS_FILE = Path("/config/agent-budgets.json")

DEFAULT_BUDGETS = {
    "general": {
        "max_tool_calls": 100,
        "agents": [
            "recon", "web", "ad", "exploit", "report", "bug-bounty",
            "mitre/recon", "mitre/resource-development", "mitre/initial-access",
            "mitre/execution", "mitre/persistence", "mitre/privilege-escalation",
            "mitre/defense-evasion", "mitre/credential-access", "mitre/discovery",
            "mitre/lateral-movement", "mitre/collection", "mitre/c2",
            "mitre/exfiltration", "mitre/impact", "mitre/post-exploit",
            "owasp/access-control", "owasp/crypto", "owasp/injection",
            "owasp/insecure-design", "owasp/misconfig", "owasp/components",
            "owasp/auth", "owasp/integrity", "owasp/logging", "owasp/ssrf",
            "research/web-search", "research/exploit-db", "research/cve-lookup",
            "research/osint", "auth-wall/login", "auth-wall/session",
            "auth-wall/post-auth", "user-scenario/builder", "user-scenario/executor"
        ]
    },
    "limited": {
        "max_tool_calls": 20,
        "agents": [
            "reflect", "curator", "rag"
        ]
    }
}


def _load_budgets() -> Dict[str, Any]:
    if not BUDGETS_FILE.exists():
        return DEFAULT_BUDGETS
    try:
        return json.loads(BUDGETS_FILE.read_text())
    except Exception:
        return DEFAULT_BUDGETS


def get_budget(agent: str) -> Dict[str, Any]:
    """Get the budget for an agent."""
    budgets = _load_budgets()
    for tier_name, tier in budgets.items():
        if agent in tier.get("agents", []):
            return {
                "tier": tier_name,
                "max_tool_calls": tier.get("max_tool_calls", 100),
                "agent": agent,
            }
    return {
        "tier": "general",
        "max_tool_calls": 100,
        "agent": agent,
    }


def check_budget(agent: str, tool_calls_used: int) -> Dict[str, Any]:
    """Check if an agent has exceeded its budget."""
    budget = get_budget(agent)
    max_calls = budget["max_tool_calls"]
    remaining = max_calls - tool_calls_used
    return {
        "agent": agent,
        "tier": budget["tier"],
        "max_tool_calls": max_calls,
        "tool_calls_used": tool_calls_used,
        "remaining": remaining,
        "exceeded": remaining < 0,
        "warning": remaining <= 5 and remaining >= 0,
    }


def list_budgets() -> Dict[str, Any]:
    """List all agent budgets."""
    return _load_budgets()


def set_budget(tier: str, agent: str, max_tool_calls: int) -> Dict[str, Any]:
    """Set a custom budget for an agent."""
    budgets = _load_budgets()
    if tier not in budgets:
        budgets[tier] = {"max_tool_calls": max_tool_calls, "agents": []}
    if agent not in budgets[tier]["agents"]:
        budgets[tier]["agents"].append(agent)
    budgets[tier]["max_tool_calls"] = max_tool_calls
    BUDGETS_FILE.write_text(json.dumps(budgets, indent=2))
    return {"tier": tier, "agent": agent, "max_tool_calls": max_tool_calls}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "get":
        if not args:
            print("Usage: agent_budgets.py get <agent>")
            sys.exit(1)
        print(json.dumps(get_budget(args[0]), indent=2))
    elif cmd == "check":
        if len(args) < 2:
            print("Usage: agent_budgets.py check <agent> <tool_calls_used>")
            sys.exit(1)
        print(json.dumps(check_budget(args[0], int(args[1])), indent=2))
    elif cmd == "list":
        print(json.dumps(list_budgets(), indent=2))
    elif cmd == "set":
        if len(args) < 3:
            print("Usage: agent_budgets.py set <tier> <agent> <max_tool_calls>")
            sys.exit(1)
        print(json.dumps(set_budget(args[0], args[1], int(args[2])), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
