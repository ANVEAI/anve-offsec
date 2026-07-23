#!/usr/bin/env python3
"""
Handoff manager for kali-ai.

Agent delegation for specialized tasks. Inspired by CAI's handoffs.
Allows an agent to delegate tasks to another agent when specialized expertise is needed.

Usage: python3 /tools/handoff_manager.py <command> [args]
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

HANDOFFS_FILE = Path("/config/handoffs.json")

DEFAULT_HANDOFFS = {
    "handoffs": [
        {
            "id": "recon-to-web",
            "from_agent": "recon",
            "to_agent": "web",
            "condition": "web_service_found",
            "description": "Hand off to web agent when HTTP/HTTPS services are discovered",
        },
        {
            "id": "recon-to-ad",
            "from_agent": "recon",
            "to_agent": "ad",
            "condition": "smb_or_ldap_found",
            "description": "Hand off to AD agent when SMB/LDAP services are discovered",
        },
        {
            "id": "web-to-exploit",
            "from_agent": "web",
            "to_agent": "exploit",
            "condition": "vulnerability_confirmed",
            "description": "Hand off to exploit agent when a vulnerability is confirmed",
        },
        {
            "id": "exploit-to-post-exploit",
            "from_agent": "exploit",
            "to_agent": "mitre/post-exploit",
            "condition": "initial_access_gained",
            "description": "Hand off to post-exploit agent when initial access is gained",
        },
        {
            "id": "post-exploit-to-report",
            "from_agent": "mitre/post-exploit",
            "to_agent": "report",
            "condition": "objectives_completed",
            "description": "Hand off to report agent when objectives are completed",
        },
        {
            "id": "any-to-reflect",
            "from_agent": "*",
            "to_agent": "reflect",
            "condition": "failure_detected",
            "description": "Hand off to reflect agent when a failure is detected",
        },
        {
            "id": "any-to-adviser",
            "from_agent": "*",
            "to_agent": "adviser",
            "condition": "loop_detected",
            "description": "Hand off to adviser agent when a loop is detected",
        },
        {
            "id": "any-to-barrier",
            "from_agent": "*",
            "to_agent": "barrier",
            "condition": "human_input_needed",
            "description": "Hand off to barrier agent when human input is needed",
        },
    ]
}


def _load_handoffs() -> Dict[str, Any]:
    if not HANDOFFS_FILE.exists():
        return DEFAULT_HANDOFFS
    try:
        return json.loads(HANDOFFS_FILE.read_text())
    except Exception:
        return DEFAULT_HANDOFFS


def _save_handoffs(handoffs: Dict[str, Any]) -> None:
    HANDOFFS_FILE.write_text(json.dumps(handoffs, indent=2))


def get_handoffs_for_agent(agent: str) -> List[Dict[str, Any]]:
    """Get all handoffs available for an agent."""
    handoffs = _load_handoffs()
    return [h for h in handoffs.get("handoffs", []) if h.get("from_agent") == agent or h.get("from_agent") == "*"]


def check_handoff_condition(agent: str, evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Check if a handoff condition is met based on evidence."""
    handoffs = get_handoffs_for_agent(agent)
    for handoff in handoffs:
        condition = handoff.get("condition", "")
        if condition == "web_service_found" and evidence.get("web_service"):
            return handoff
        if condition == "smb_or_ldap_found" and (evidence.get("smb") or evidence.get("ldap")):
            return handoff
        if condition == "vulnerability_confirmed" and evidence.get("vulnerability"):
            return handoff
        if condition == "initial_access_gained" and evidence.get("access"):
            return handoff
        if condition == "objectives_completed" and evidence.get("completed"):
            return handoff
        if condition == "failure_detected" and evidence.get("failure"):
            return handoff
        if condition == "loop_detected" and evidence.get("loop"):
            return handoff
        if condition == "human_input_needed" and evidence.get("human_input"):
            return handoff
    return None


def create_handoff(from_agent: str, to_agent: str, condition: str, description: str = "") -> Dict[str, Any]:
    """Create a new handoff."""
    handoffs = _load_handoffs()
    new_handoff = {
        "id": f"{from_agent}-to-{to_agent}-{uuid.uuid4().hex[:8]}",
        "from_agent": from_agent,
        "to_agent": to_agent,
        "condition": condition,
        "description": description,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    handoffs.setdefault("handoffs", []).append(new_handoff)
    _save_handoffs(handoffs)
    return new_handoff


def remove_handoff(handoff_id: str) -> Dict[str, Any]:
    """Remove a handoff."""
    handoffs = _load_handoffs()
    original_count = len(handoffs.get("handoffs", []))
    handoffs["handoffs"] = [h for h in handoffs.get("handoffs", []) if h.get("id") != handoff_id]
    if len(handoffs["handoffs"]) < original_count:
        _save_handoffs(handoffs)
        return {"removed": True, "handoff_id": handoff_id}
    return {"removed": False, "handoff_id": handoff_id, "reason": "not found"}


def list_handoffs() -> List[Dict[str, Any]]:
    """List all handoffs."""
    return _load_handoffs().get("handoffs", [])


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "get":
        if not args:
            print("Usage: handoff_manager.py get <agent>")
            sys.exit(1)
        print(json.dumps(get_handoffs_for_agent(args[0]), indent=2))
    elif cmd == "check":
        if not args:
            print("Usage: handoff_manager.py check <agent> <evidence-json>")
            sys.exit(1)
        evidence = json.loads(args[1]) if len(args) > 1 else {}
        result = check_handoff_condition(args[0], evidence)
        print(json.dumps(result or {"handoff": None}, indent=2))
    elif cmd == "create":
        if len(args) < 3:
            print("Usage: handoff_manager.py create <from_agent> <to_agent> <condition> [description]")
            sys.exit(1)
        description = args[3] if len(args) > 3 else ""
        print(json.dumps(create_handoff(args[0], args[1], args[2], description), indent=2))
    elif cmd == "remove":
        if not args:
            print("Usage: handoff_manager.py remove <handoff_id>")
            sys.exit(1)
        print(json.dumps(remove_handoff(args[0]), indent=2))
    elif cmd == "list":
        print(json.dumps(list_handoffs(), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
