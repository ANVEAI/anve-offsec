#!/usr/bin/env python3
"""
Langfuse/OTEL tracing manager for kali-ai.

LLM and system observability with OpenTelemetry and Langfuse.
Inspired by PentAGI's split observability (Langfuse for LLM, Grafana for system).

Usage: python3 /tools/tracing_manager.py <command> [args]
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

TRACING_FILE = Path("/config/tracing.json")
TRACES_DIR = Path("/work/traces")

DEFAULT_TRACING = {
    "enabled": True,
    "langfuse": {
        "enabled": False,
        "url": "http://localhost:3000",
        "public_key": "",
        "secret_key": "",
        "description": "Langfuse for LLM tracing (traces, token usage)",
    },
    "otel": {
        "enabled": False,
        "endpoint": "http://localhost:4318",
        "description": "OpenTelemetry for system metrics",
    },
    "local": {
        "enabled": True,
        "description": "Local file-based tracing to /work/traces/",
    },
}


def _ensure_dirs() -> None:
    TRACES_DIR.mkdir(parents=True, exist_ok=True)


def _load_tracing_config() -> Dict[str, Any]:
    if not TRACING_FILE.exists():
        return DEFAULT_TRACING
    try:
        return json.loads(TRACING_FILE.read_text())
    except Exception:
        return DEFAULT_TRACING


def _save_tracing_config(config: Dict[str, Any]) -> None:
    TRACING_FILE.write_text(json.dumps(config, indent=2))


def start_trace(run_id: str, agent: str, task: str, model: str) -> Dict[str, Any]:
    """Start a new trace for a run."""
    _ensure_dirs()
    trace_id = str(uuid.uuid4())
    trace = {
        "trace_id": trace_id,
        "run_id": run_id,
        "agent": agent,
        "task": task,
        "model": model,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "spans": [],
    }

    trace_file = TRACES_DIR / f"{trace_id}.json"
    trace_file.write_text(json.dumps(trace, indent=2))

    return trace


def add_span(trace_id: str, name: str, input_data: Any, output_data: Any, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Add a span to a trace."""
    trace_file = TRACES_DIR / f"{trace_id}.json"
    if not trace_file.exists():
        return {"error": f"trace not found: {trace_id}"}

    trace = json.loads(trace_file.read_text())
    span = {
        "span_id": str(uuid.uuid4()),
        "name": name,
        "input": input_data,
        "output": output_data,
        "metadata": metadata or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    trace.setdefault("spans", []).append(span)
    trace_file.write_text(json.dumps(trace, indent=2))

    return span


def end_trace(trace_id: str, status: str = "done", output: Optional[Any] = None) -> Dict[str, Any]:
    """End a trace."""
    trace_file = TRACES_DIR / f"{trace_id}.json"
    if not trace_file.exists():
        return {"error": f"trace not found: {trace_id}"}

    trace = json.loads(trace_file.read_text())
    trace["status"] = status
    trace["ended_at"] = datetime.now(timezone.utc).isoformat()
    if output:
        trace["output"] = output
    trace_file.write_text(json.dumps(trace, indent=2))

    return trace


def get_trace(trace_id: str) -> Dict[str, Any]:
    """Get a trace by ID."""
    trace_file = TRACES_DIR / f"{trace_id}.json"
    if not trace_file.exists():
        return {"error": f"trace not found: {trace_id}"}
    return json.loads(trace_file.read_text())


def list_traces(limit: int = 50) -> List[Dict[str, Any]]:
    """List all traces."""
    _ensure_dirs()
    traces = []
    for path in sorted(TRACES_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            traces.append(json.loads(path.read_text()))
        except Exception:
            continue
        if len(traces) >= limit:
            break
    return traces


def get_run_trace(run_id: str) -> Optional[Dict[str, Any]]:
    """Get the trace for a run."""
    for trace in list_traces(1000):
        if trace.get("run_id") == run_id:
            return trace
    return None


def enable_langfuse(url: str, public_key: str, secret_key: str) -> Dict[str, Any]:
    """Enable Langfuse tracing."""
    config = _load_tracing_config()
    config["langfuse"]["enabled"] = True
    config["langfuse"]["url"] = url
    config["langfuse"]["public_key"] = public_key
    config["langfuse"]["secret_key"] = secret_key
    _save_tracing_config(config)
    return {"langfuse": True, "url": url}


def enable_otel(endpoint: str) -> Dict[str, Any]:
    """Enable OpenTelemetry tracing."""
    config = _load_tracing_config()
    config["otel"]["enabled"] = True
    config["otel"]["endpoint"] = endpoint
    _save_tracing_config(config)
    return {"otel": True, "endpoint": endpoint}


def disable_tracing() -> Dict[str, Any]:
    """Disable all tracing."""
    config = _load_tracing_config()
    config["enabled"] = False
    config["langfuse"]["enabled"] = False
    config["otel"]["enabled"] = False
    _save_tracing_config(config)
    return {"enabled": False}


def get_tracing_config() -> Dict[str, Any]:
    """Get tracing configuration."""
    return _load_tracing_config()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "start":
        if len(args) < 4:
            print("Usage: tracing_manager.py start <run_id> <agent> <task> <model>")
            sys.exit(1)
        print(json.dumps(start_trace(args[0], args[1], args[2], args[3]), indent=2))
    elif cmd == "span":
        if len(args) < 4:
            print("Usage: tracing_manager.py span <trace_id> <name> <input> <output> [metadata]")
            sys.exit(1)
        metadata = json.loads(args[4]) if len(args) > 4 else None
        print(json.dumps(add_span(args[0], args[1], args[2], args[3], metadata), indent=2))
    elif cmd == "end":
        if not args:
            print("Usage: tracing_manager.py end <trace_id> [status] [output]")
            sys.exit(1)
        status = args[1] if len(args) > 1 else "done"
        output = args[2] if len(args) > 2 else None
        print(json.dumps(end_trace(args[0], status, output), indent=2))
    elif cmd == "get":
        if not args:
            print("Usage: tracing_manager.py get <trace_id>")
            sys.exit(1)
        print(json.dumps(get_trace(args[0]), indent=2))
    elif cmd == "list":
        limit = int(args[0]) if args else 50
        print(json.dumps(list_traces(limit), indent=2))
    elif cmd == "for-run":
        if not args:
            print("Usage: tracing_manager.py for-run <run_id>")
            sys.exit(1)
        result = get_run_trace(args[0])
        print(json.dumps(result or {"error": "not found"}, indent=2))
    elif cmd == "enable-langfuse":
        if len(args) < 3:
            print("Usage: tracing_manager.py enable-langfuse <url> <public_key> <secret_key>")
            sys.exit(1)
        print(json.dumps(enable_langfuse(args[0], args[1], args[2]), indent=2))
    elif cmd == "enable-otel":
        if not args:
            print("Usage: tracing_manager.py enable-otel <endpoint>")
            sys.exit(1)
        print(json.dumps(enable_otel(args[0]), indent=2))
    elif cmd == "disable":
        print(json.dumps(disable_tracing(), indent=2))
    elif cmd == "config":
        print(json.dumps(get_tracing_config(), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
