#!/usr/bin/env python3
"""
Pattern manager for kali-ai.

Agentic workflow patterns inspired by CAI's patterns.
Supports Swarm (decentralized), Hierarchical (top-down), Chain-of-Thought (sequential),
Auction-Based (competitive), and Recursive (self-refining) patterns.

Usage: python3 /tools/pattern_manager.py <command> [args]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PATTERNS_FILE = Path("/config/patterns.json")

DEFAULT_PATTERNS = {
    "patterns": [
        {
            "id": "bug-bounty-hierarchical",
            "name": "Bug Bounty Hierarchical",
            "type": "hierarchical",
            "description": "Top-level planner assigns tasks to specialized sub-agents",
            "agents": ["bug-bounty", "recon", "web", "owasp/injection", "exploit", "report"],
            "flow": [
                {"step": 1, "agent": "bug-bounty", "action": "plan", "output": "strategy"},
                {"step": 2, "agent": "recon", "action": "execute", "input": "strategy", "output": "recon_evidence"},
                {"step": 3, "agent": "web", "action": "execute", "input": "recon_evidence", "output": "web_evidence"},
                {"step": 4, "agent": "owasp/injection", "action": "execute", "input": "web_evidence", "output": "vuln_evidence"},
                {"step": 5, "agent": "exploit", "action": "execute", "input": "vuln_evidence", "output": "exploit_evidence"},
                {"step": 6, "agent": "report", "action": "execute", "input": "exploit_evidence", "output": "report"},
            ],
        },
        {
            "id": "ctf-swarm",
            "name": "CTF Swarm",
            "type": "swarm",
            "description": "Decentralized agents self-assign tasks and share results dynamically",
            "agents": ["recon", "web", "exploit", "research/exploit-db", "research/cve-lookup"],
            "flow": [
                {"step": "dynamic", "agent": "any", "action": "self-assign", "condition": "available"},
            ],
        },
        {
            "id": "pentest-chain",
            "name": "Penetration Test Chain",
            "type": "chain-of-thought",
            "description": "Sequential pipeline where each agent refines the previous agent's output",
            "agents": ["recon", "web", "owasp/injection", "exploit", "mitre/post-exploit", "report"],
            "flow": [
                {"step": 1, "agent": "recon", "action": "execute", "output": "recon_evidence"},
                {"step": 2, "agent": "web", "action": "execute", "input": "recon_evidence", "output": "web_evidence"},
                {"step": 3, "agent": "owasp/injection", "action": "execute", "input": "web_evidence", "output": "vuln_evidence"},
                {"step": 4, "agent": "exploit", "action": "execute", "input": "vuln_evidence", "output": "exploit_evidence"},
                {"step": 5, "agent": "mitre/post-exploit", "action": "execute", "input": "exploit_evidence", "output": "post_exploit_evidence"},
                {"step": 6, "agent": "report", "action": "execute", "input": "post_exploit_evidence", "output": "report"},
            ],
        },
        {
            "id": "parallel-scan-auction",
            "name": "Parallel Scan Auction",
            "type": "auction-based",
            "description": "Agents bid on tasks based on capability and cost; best-fit agent wins",
            "agents": ["recon", "web", "owasp/misconfig", "owasp/injection", "owasp/access-control"],
            "flow": [
                {"step": "auction", "agent": "any", "action": "bid", "criteria": ["capability", "cost", "speed"]},
            ],
        },
        {
            "id": "code-review-recursive",
            "name": "Code Review Recursive",
            "type": "recursive",
            "description": "Single agent continuously refines its own output by executing and updating instructions",
            "agents": ["report"],
            "flow": [
                {"step": "recursive", "agent": "report", "action": "refine", "max_iterations": 5},
            ],
        },
    ]
}


def _load_patterns() -> Dict[str, Any]:
    if not PATTERNS_FILE.exists():
        return DEFAULT_PATTERNS
    try:
        return json.loads(PATTERNS_FILE.read_text())
    except Exception:
        return DEFAULT_PATTERNS


def _save_patterns(patterns: Dict[str, Any]) -> None:
    PATTERNS_FILE.write_text(json.dumps(patterns, indent=2))


def get_pattern(pattern_id: str) -> Optional[Dict[str, Any]]:
    """Get a pattern by ID."""
    patterns = _load_patterns()
    for p in patterns.get("patterns", []):
        if p.get("id") == pattern_id:
            return p
    return None


def get_pattern_for_task(task_type: str) -> Optional[Dict[str, Any]]:
    """Get the best pattern for a task type."""
    patterns = _load_patterns()
    mapping = {
        "bug-bounty": "bug-bounty-hierarchical",
        "ctf": "ctf-swarm",
        "pentest": "pentest-chain",
        "parallel-scan": "parallel-scan-auction",
        "code-review": "code-review-recursive",
    }
    pattern_id = mapping.get(task_type)
    if pattern_id:
        return get_pattern(pattern_id)
    return None


def create_pattern(pattern_id: str, name: str, pattern_type: str, agents: List[str], flow: List[Dict[str, Any]], description: str = "") -> Dict[str, Any]:
    """Create a new pattern."""
    patterns = _load_patterns()
    new_pattern = {
        "id": pattern_id,
        "name": name,
        "type": pattern_type,
        "description": description,
        "agents": agents,
        "flow": flow,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    patterns.setdefault("patterns", []).append(new_pattern)
    _save_patterns(patterns)
    return new_pattern


def remove_pattern(pattern_id: str) -> Dict[str, Any]:
    """Remove a pattern."""
    patterns = _load_patterns()
    original_count = len(patterns.get("patterns", []))
    patterns["patterns"] = [p for p in patterns.get("patterns", []) if p.get("id") != pattern_id]
    if len(patterns["patterns"]) < original_count:
        _save_patterns(patterns)
        return {"removed": True, "pattern_id": pattern_id}
    return {"removed": False, "pattern_id": pattern_id, "reason": "not found"}


def list_patterns() -> List[Dict[str, Any]]:
    """List all patterns."""
    return _load_patterns().get("patterns", [])


def execute_pattern(pattern_id: str, task: str, target: str) -> Dict[str, Any]:
    """Execute a pattern (returns the flow for the runner to execute)."""
    pattern = get_pattern(pattern_id)
    if not pattern:
        return {"error": f"pattern not found: {pattern_id}"}

    return {
        "pattern_id": pattern_id,
        "name": pattern.get("name"),
        "type": pattern.get("type"),
        "task": task,
        "target": target,
        "flow": pattern.get("flow", []),
        "agents": pattern.get("agents", []),
        "status": "ready",
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "get":
        if not args:
            print("Usage: pattern_manager.py get <pattern_id>")
            sys.exit(1)
        result = get_pattern(args[0])
        print(json.dumps(result or {"error": "not found"}, indent=2))
    elif cmd == "for-task":
        if not args:
            print("Usage: pattern_manager.py for-task <task_type>")
            sys.exit(1)
        result = get_pattern_for_task(args[0])
        print(json.dumps(result or {"error": "not found"}, indent=2))
    elif cmd == "create":
        if len(args) < 5:
            print("Usage: pattern_manager.py create <id> <name> <type> <agents-json> <flow-json> [description]")
            sys.exit(1)
        description = args[5] if len(args) > 5 else ""
        print(json.dumps(create_pattern(args[0], args[1], args[2], json.loads(args[3]), json.loads(args[4]), description), indent=2))
    elif cmd == "remove":
        if not args:
            print("Usage: pattern_manager.py remove <pattern_id>")
            sys.exit(1)
        print(json.dumps(remove_pattern(args[0]), indent=2))
    elif cmd == "list":
        print(json.dumps(list_patterns(), indent=2))
    elif cmd == "execute":
        if len(args) < 3:
            print("Usage: pattern_manager.py execute <pattern_id> <task> <target>")
            sys.exit(1)
        print(json.dumps(execute_pattern(args[0], args[1], args[2]), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
