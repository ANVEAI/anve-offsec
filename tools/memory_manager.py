#!/usr/bin/env python3
"""
Memory manager for kali-ai.

Supports episodic, semantic, and all memory modes for agent context management.
Inspired by CAI's memory modes.

Usage: python3 /tools/memory_manager.py <command> [args]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

MEMORY_FILE = Path("/config/memory-modes.json")
MEMORY_DIR = Path("/work/memory")

DEFAULT_MEMORY = {
    "mode": "all",  # episodic, semantic, all
    "episodic": {
        "enabled": True,
        "description": "Past actions and experiences (run history, lessons, patterns)",
        "sources": ["lessons.jsonl", "patterns.json", "strategy.json"],
    },
    "semantic": {
        "enabled": True,
        "description": "Knowledge and facts (writeups, CVEs, techniques, tool docs)",
        "sources": ["knowledge corpus", "RAG collections"],
    },
    "online": {
        "enabled": True,
        "interval": 5,
        "description": "Online memory updates every N turns",
    },
    "offline": {
        "enabled": True,
        "description": "Offline memory from file-based storage",
    },
}


def _load_memory_config() -> Dict[str, Any]:
    if not MEMORY_FILE.exists():
        return DEFAULT_MEMORY
    try:
        return json.loads(MEMORY_FILE.read_text())
    except Exception:
        return DEFAULT_MEMORY


def _save_memory_config(config: Dict[str, Any]) -> None:
    MEMORY_FILE.write_text(json.dumps(config, indent=2))


def get_memory_mode() -> Dict[str, Any]:
    """Get current memory mode configuration."""
    return _load_memory_config()


def set_memory_mode(mode: str) -> Dict[str, Any]:
    """Set memory mode: episodic, semantic, all."""
    config = _load_memory_config()
    if mode not in ["episodic", "semantic", "all"]:
        return {"error": f"invalid mode: {mode}. Must be episodic, semantic, or all"}
    config["mode"] = mode
    _save_memory_config(config)
    return {"mode": mode}


def enable_episodic() -> Dict[str, Any]:
    """Enable episodic memory."""
    config = _load_memory_config()
    config["episodic"]["enabled"] = True
    _save_memory_config(config)
    return {"episodic": True}


def disable_episodic() -> Dict[str, Any]:
    """Disable episodic memory."""
    config = _load_memory_config()
    config["episodic"]["enabled"] = False
    _save_memory_config(config)
    return {"episodic": False}


def enable_semantic() -> Dict[str, Any]:
    """Enable semantic memory."""
    config = _load_memory_config()
    config["semantic"]["enabled"] = True
    _save_memory_config(config)
    return {"semantic": True}


def disable_semantic() -> Dict[str, Any]:
    """Disable semantic memory."""
    config = _load_memory_config()
    config["semantic"]["enabled"] = False
    _save_memory_config(config)
    return {"semantic": False}


def enable_online() -> Dict[str, Any]:
    """Enable online memory updates."""
    config = _load_memory_config()
    config["online"]["enabled"] = True
    _save_memory_config(config)
    return {"online": True}


def disable_online() -> Dict[str, Any]:
    """Disable online memory updates."""
    config = _load_memory_config()
    config["online"]["enabled"] = False
    _save_memory_config(config)
    return {"online": False}


def enable_offline() -> Dict[str, Any]:
    """Enable offline memory."""
    config = _load_memory_config()
    config["offline"]["enabled"] = True
    _save_memory_config(config)
    return {"offline": True}


def disable_offline() -> Dict[str, Any]:
    """Disable offline memory."""
    config = _load_memory_config()
    config["offline"]["enabled"] = False
    _save_memory_config(config)
    return {"offline": False}


def set_online_interval(interval: int) -> Dict[str, Any]:
    """Set online memory update interval (turns)."""
    config = _load_memory_config()
    config["online"]["interval"] = interval
    _save_memory_config(config)
    return {"online_interval": interval}


def get_episodic_memory(limit: int = 50) -> List[Dict[str, Any]]:
    """Get episodic memory (past actions and experiences)."""
    lessons_file = MEMORY_DIR / "lessons.jsonl"
    if not lessons_file.exists():
        return []
    lessons = []
    try:
        content = lessons_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return lessons
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            lessons.append(json.loads(line))
        except Exception:
            continue
    return lessons[-limit:]


def get_semantic_memory(query: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Get semantic memory (knowledge and facts)."""
    # This would query the RAG system for knowledge
    # For now, return a placeholder
    return [{"query": query, "note": "Semantic memory queries the RAG knowledge base", "limit": limit}]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "get":
        print(json.dumps(get_memory_mode(), indent=2))
    elif cmd == "set":
        if not args:
            print("Usage: memory_manager.py set <mode>")
            sys.exit(1)
        print(json.dumps(set_memory_mode(args[0]), indent=2))
    elif cmd == "enable-episodic":
        print(json.dumps(enable_episodic(), indent=2))
    elif cmd == "disable-episodic":
        print(json.dumps(disable_episodic(), indent=2))
    elif cmd == "enable-semantic":
        print(json.dumps(enable_semantic(), indent=2))
    elif cmd == "disable-semantic":
        print(json.dumps(disable_semantic(), indent=2))
    elif cmd == "enable-online":
        print(json.dumps(enable_online(), indent=2))
    elif cmd == "disable-online":
        print(json.dumps(disable_online(), indent=2))
    elif cmd == "enable-offline":
        print(json.dumps(enable_offline(), indent=2))
    elif cmd == "disable-offline":
        print(json.dumps(disable_offline(), indent=2))
    elif cmd == "set-interval":
        if not args:
            print("Usage: memory_manager.py set-interval <turns>")
            sys.exit(1)
        print(json.dumps(set_online_interval(int(args[0])), indent=2))
    elif cmd == "episodic":
        limit = int(args[0]) if args else 50
        print(json.dumps(get_episodic_memory(limit), indent=2))
    elif cmd == "semantic":
        if not args:
            print("Usage: memory_manager.py semantic <query> [limit]")
            sys.exit(1)
        limit = int(args[1]) if len(args) > 1 else 10
        print(json.dumps(get_semantic_memory(args[0], limit), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
