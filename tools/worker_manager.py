#!/usr/bin/env python3
"""
Docker-in-Docker ephemeral worker manager for kali-ai.

Spawns isolated, ephemeral worker containers per flow for strict isolation.
Inspired by PentAGI's per-flow worker architecture.

Usage: python3 /tools/worker_manager.py <command> [args]
"""

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKER_IMAGE = "kali-ai:latest"
WORKER_PREFIX = "kali-worker-"
OOB_PORT_START = 28000
OOB_PORT_END = 30000
DOCKER_SOCKET = "/var/run/docker.sock"


def _run(cmd: List[str], capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=capture, text=True)


def _docker_available() -> bool:
    return Path(DOCKER_SOCKET).exists()


def _allocate_oob_port() -> int:
    """Allocate an available OOB port from the range."""
    # Simple approach: pick a random port in range and check if it's free
    import socket
    for port in range(OOB_PORT_START, OOB_PORT_END + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("", port))
                return port
        except OSError:
            continue
    raise RuntimeError("No available OOB ports in range")


def create_worker(
    flow_id: str,
    agent: str,
    task: str,
    oob_port: Optional[int] = None,
    env: Optional[Dict[str, str]] = None,
    volumes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create an ephemeral worker container for a flow."""
    if not _docker_available():
        return {"error": "Docker socket not available", "worker_id": None}

    if oob_port is None:
        oob_port = _allocate_oob_port()

    worker_name = f"{WORKER_PREFIX}{flow_id}"
    worker_env = {
        "FLOW_ID": flow_id,
        "AGENT": agent,
        "TASK": task,
        "OOB_PORT": str(oob_port),
        "KIMI_API_KEY": os.getenv("KIMI_API_KEY", ""),
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
        "MOONSHOT_API_KEY": os.getenv("MOONSHOT_API_KEY", ""),
    }
    if env:
        worker_env.update(env)

    worker_volumes = [
        "./work:/work",
        "./tools:/tools:ro",
        "./config:/config:ro",
        "./scripts:/scripts:ro",
    ]
    if volumes:
        worker_volumes.extend(volumes)

    cmd = [
        "docker", "run", "-d",
        "--name", worker_name,
        "--hostname", worker_name,
        "--network", "kali-ai_default",
        "--cap-add", "NET_ADMIN",
        "--cap-add", "NET_RAW",
        "--rm",
        "-e", f"FLOW_ID={flow_id}",
        "-e", f"AGENT={agent}",
        "-e", f"TASK={task}",
        "-e", f"OOB_PORT={oob_port}",
        "-e", f"KIMI_API_KEY={worker_env['KIMI_API_KEY']}",
        "-e", f"OPENAI_API_KEY={worker_env['OPENAI_API_KEY']}",
        "-e", f"MOONSHOT_API_KEY={worker_env['MOONSHOT_API_KEY']}",
        "-p", f"{oob_port}:{oob_port}",
    ]
    for vol in worker_volumes:
        cmd.extend(["-v", vol])
    cmd.append(WORKER_IMAGE)
    cmd.extend(["/scripts/internal-agent.sh", agent, task])

    result = _run(cmd)
    if result.returncode != 0:
        return {"error": result.stderr, "worker_id": None}

    return {
        "worker_id": worker_name,
        "flow_id": flow_id,
        "agent": agent,
        "task": task,
        "oob_port": oob_port,
        "status": "running",
    }


def list_workers() -> List[Dict[str, Any]]:
    """List all ephemeral worker containers."""
    if not _docker_available():
        return []

    result = _run(["docker", "ps", "-a", "--filter", f"name={WORKER_PREFIX}", "--format", "{{json .}}"])
    workers = []
    for line in result.stdout.splitlines():
        if line.strip():
            try:
                w = json.loads(line)
                workers.append({
                    "worker_id": w.get("Names", ""),
                    "status": w.get("Status", ""),
                    "image": w.get("Image", ""),
                    "created": w.get("CreatedAt", ""),
                })
            except Exception:
                continue
    return workers


def stop_worker(worker_id: str) -> Dict[str, Any]:
    """Stop an ephemeral worker container."""
    if not _docker_available():
        return {"error": "Docker socket not available"}

    result = _run(["docker", "stop", worker_id])
    if result.returncode != 0:
        return {"error": result.stderr, "worker_id": worker_id, "status": "error"}
    return {"worker_id": worker_id, "status": "stopped"}


def remove_worker(worker_id: str) -> Dict[str, Any]:
    """Remove an ephemeral worker container."""
    if not _docker_available():
        return {"error": "Docker socket not available"}

    result = _run(["docker", "rm", "-f", worker_id])
    if result.returncode != 0:
        return {"error": result.stderr, "worker_id": worker_id, "status": "error"}
    return {"worker_id": worker_id, "status": "removed"}


def cleanup_workers() -> Dict[str, Any]:
    """Remove all stopped ephemeral worker containers."""
    if not _docker_available():
        return {"error": "Docker socket not available"}

    result = _run(["docker", "ps", "-a", "--filter", f"name={WORKER_PREFIX}", "--filter", "status=exited", "--format", "{{.Names}}"])
    removed = 0
    for name in result.stdout.splitlines():
        name = name.strip()
        if name:
            _run(["docker", "rm", "-f", name])
            removed += 1
    return {"removed": removed}


def worker_logs(worker_id: str, tail: int = 100) -> str:
    """Get logs from an ephemeral worker container."""
    if not _docker_available():
        return "Docker socket not available"

    result = _run(["docker", "logs", "--tail", str(tail), worker_id])
    return result.stdout


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "create":
        if len(args) < 3:
            print("Usage: worker_manager.py create <flow_id> <agent> <task> [oob_port]")
            sys.exit(1)
        oob_port = int(args[3]) if len(args) > 3 else None
        print(json.dumps(create_worker(args[0], args[1], args[2], oob_port), indent=2))
    elif cmd == "list":
        print(json.dumps(list_workers(), indent=2))
    elif cmd == "stop":
        if not args:
            print("Usage: worker_manager.py stop <worker_id>")
            sys.exit(1)
        print(json.dumps(stop_worker(args[0]), indent=2))
    elif cmd == "remove":
        if not args:
            print("Usage: worker_manager.py remove <worker_id>")
            sys.exit(1)
        print(json.dumps(remove_worker(args[0]), indent=2))
    elif cmd == "cleanup":
        print(json.dumps(cleanup_workers(), indent=2))
    elif cmd == "logs":
        if not args:
            print("Usage: worker_manager.py logs <worker_id> [tail]")
            sys.exit(1)
        tail = int(args[1]) if len(args) > 1 else 100
        print(worker_logs(args[0], tail))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
