#!/usr/bin/env python3
"""
Stream manager for kali-ai.

Real-time findings sharing and mid-run instruction injection.
Agent streams discoveries to a findings file; users inject instructions to a queue file.

Usage: python3 /tools/stream_manager.py <command> [args]
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

RUNS_DIR = Path("/work/dashboard-logs")


def _run_dir(run_id: str) -> Path:
    return RUNS_DIR / f"{run_id}_stream"


def _ensure_dir(run_id: str) -> Path:
    d = _run_dir(run_id)
    d.mkdir(exist_ok=True)
    return d


def _findings_file(run_id: str) -> Path:
    return _run_dir(run_id) / "findings.jsonl"


def _instructions_file(run_id: str) -> Path:
    return _run_dir(run_id) / "instructions.jsonl"


def _state_file(run_id: str) -> Path:
    return _run_dir(run_id) / "state.json"


def share_finding(run_id: str, finding_type: str, title: str, detail: str, severity: str = "info", evidence: Optional[List[str]] = None) -> Dict[str, Any]:
    """Share a finding from the agent to the dashboard in real-time."""
    _ensure_dir(run_id)
    finding = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": finding_type,  # discovery, vulnerability, evidence, note, error, progress
        "title": title,
        "detail": detail,
        "severity": severity,  # critical, high, medium, low, info
        "evidence": evidence or [],
    }
    with _findings_file(run_id).open("a") as f:
        f.write(json.dumps(finding) + "\n")
    return finding


def get_findings(run_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Get all findings for a run."""
    f = _findings_file(run_id)
    if not f.exists():
        return []
    findings = []
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            continue
    return findings[-limit:]


def inject_instruction(run_id: str, instruction: str, priority: str = "normal") -> Dict[str, Any]:
    """Inject an instruction for the agent to see on its next turn."""
    _ensure_dir(run_id)
    instr = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "instruction": instruction,
        "priority": priority,  # low, normal, high, urgent
        "status": "pending",
    }
    with _instructions_file(run_id).open("a") as f:
        f.write(json.dumps(instr) + "\n")
    return instr


def get_pending_instructions(run_id: str) -> List[Dict[str, Any]]:
    """Get pending instructions for a run."""
    f = _instructions_file(run_id)
    if not f.exists():
        return []
    instructions = []
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            instr = json.loads(line)
            if instr.get("status") == "pending":
                instructions.append(instr)
        except Exception:
            continue
    return instructions


def mark_instruction_read(run_id: str, instruction_id: str) -> Dict[str, Any]:
    """Mark an instruction as read by the agent."""
    f = _instructions_file(run_id)
    if not f.exists():
        return {"error": "no instructions file"}
    instructions = []
    marked = False
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            instr = json.loads(line)
            if instr.get("id") == instruction_id:
                instr["status"] = "read"
                instr["read_at"] = datetime.now(timezone.utc).isoformat()
                marked = True
            instructions.append(instr)
        except Exception:
            continue
    if marked:
        f.write_text("\n".join(json.dumps(i) for i in instructions) + "\n")
    return {"marked": marked, "instruction_id": instruction_id}


def get_run_state(run_id: str) -> Dict[str, Any]:
    """Get the saved state for a run."""
    f = _state_file(run_id)
    if not f.exists():
        return {"run_id": run_id, "state": "not_found"}
    try:
        return json.loads(f.read_text())
    except Exception:
        return {"run_id": run_id, "state": "error"}


def save_run_state(run_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
    """Save the current state for a run (for resuming)."""
    _ensure_dir(run_id)
    state["run_id"] = run_id
    state["saved_at"] = datetime.now(timezone.utc).isoformat()
    _state_file(run_id).write_text(json.dumps(state, indent=2))
    return state


def get_continuation_context(run_id: str) -> Dict[str, Any]:
    """Get full context for a high-quality continuation."""
    findings = get_findings(run_id, 50)
    state = get_run_state(run_id)
    state_file = RUNS_DIR / f"{run_id}.json"
    run_state = {}
    if state_file.exists():
        try:
            run_state = json.loads(state_file.read_text())
        except Exception:
            pass

    # Build continuation context
    completed = [f for f in findings if f.get("type") == "progress" and f.get("status") == "completed"]
    discoveries = [f for f in findings if f.get("type") == "discovery"]
    vulnerabilities = [f for f in findings if f.get("type") == "vulnerability"]
    errors = [f for f in findings if f.get("type") == "error"]

    return {
        "run_id": run_id,
        "agent": run_state.get("agent"),
        "task": run_state.get("task"),
        "status": run_state.get("status"),
        "completed_steps": [f.get("title") for f in completed],
        "discoveries": [{"title": f.get("title"), "detail": f.get("detail"), "severity": f.get("severity")} for f in discoveries],
        "vulnerabilities": [{"title": f.get("title"), "detail": f.get("detail"), "severity": f.get("severity")} for f in vulnerabilities],
        "errors": [{"title": f.get("title"), "detail": f.get("detail")} for f in errors],
        "state": state,
        "findings_count": len(findings),
        "pending_instructions": get_pending_instructions(run_id),
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "share-finding":
        if len(args) < 4:
            print("Usage: stream_manager.py share-finding <run_id> <type> <title> <detail> [severity] [evidence]")
            sys.exit(1)
        severity = args[4] if len(args) > 4 else "info"
        evidence = args[5].split(",") if len(args) > 5 else None
        print(json.dumps(share_finding(args[0], args[1], args[2], args[3], severity, evidence), indent=2))
    elif cmd == "get-findings":
        if not args:
            print("Usage: stream_manager.py get-findings <run_id> [limit]")
            sys.exit(1)
        limit = int(args[1]) if len(args) > 1 else 100
        print(json.dumps(get_findings(args[0], limit), indent=2))
    elif cmd == "inject":
        if len(args) < 2:
            print("Usage: stream_manager.py inject <run_id> <instruction> [priority]")
            sys.exit(1)
        priority = args[2] if len(args) > 2 else "normal"
        print(json.dumps(inject_instruction(args[0], args[1], priority), indent=2))
    elif cmd == "pending":
        if not args:
            print("Usage: stream_manager.py pending <run_id>")
            sys.exit(1)
        print(json.dumps(get_pending_instructions(args[0]), indent=2))
    elif cmd == "mark-read":
        if len(args) < 2:
            print("Usage: stream_manager.py mark-read <run_id> <instruction_id>")
            sys.exit(1)
        print(json.dumps(mark_instruction_read(args[0], args[1]), indent=2))
    elif cmd == "state":
        if not args:
            print("Usage: stream_manager.py state <run_id>")
            sys.exit(1)
        print(json.dumps(get_run_state(args[0]), indent=2))
    elif cmd == "save-state":
        if len(args) < 2:
            print("Usage: stream_manager.py save-state <run_id> <state-json>")
            sys.exit(1)
        print(json.dumps(save_run_state(args[0], json.loads(args[1])), indent=2))
    elif cmd == "continuation-context":
        if not args:
            print("Usage: stream_manager.py continuation-context <run_id>")
            sys.exit(1)
        print(json.dumps(get_continuation_context(args[0]), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
