#!/usr/bin/env python3
"""
Custom toolchain manager for kali-ai.

Configurable tool prioritization per engagement. Prioritize preferred tools over noisy or ineffective scripts.
Inspired by Pentest Copilot's custom toolchains.

Usage: python3 /tools/toolchain_manager.py <command> [args]
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

TOOLCHAINS_DIR = Path("/config/toolchains")
DEFAULT_TOOLCHAIN = {
    "name": "default",
    "description": "Default toolchain with balanced tool selection",
    "categories": {
        "recon": {"priority": ["nmap", "masscan", "rustscan", "subfinder", "amass", "dnsrecon", "theHarvester"], "avoid": []},
        "web": {"priority": ["zap", "gobuster", "ffuf", "nikto", "nuclei", "whatweb", "sqlmap", "xsstrike"], "avoid": ["dirb"]},
        "exploit": {"priority": ["metasploit", "searchsploit", "impacket", "evil-winrm", "sqlmap", "commix"], "avoid": []},
        "ad": {"priority": ["netexec", "bloodhound.py", "impacket", "responder", "evil-winrm", "kerbrute"], "avoid": []},
        "crypto": {"priority": ["hashcat", "john", "sslyze", "sslscan", "testssl"], "avoid": []},
    },
}


def _ensure_dir() -> None:
    TOOLCHAINS_DIR.mkdir(parents=True, exist_ok=True)


def _load_toolchain(name: str) -> Dict[str, Any]:
    path = TOOLCHAINS_DIR / f"{name}.json"
    if not path.exists():
        return DEFAULT_TOOLCHAIN
    try:
        return json.loads(path.read_text())
    except Exception:
        return DEFAULT_TOOLCHAIN


def _save_toolchain(toolchain: Dict[str, Any]) -> None:
    path = TOOLCHAINS_DIR / f"{toolchain['name']}.json"
    path.write_text(json.dumps(toolchain, indent=2))


def create_toolchain(name: str, description: str = "", categories: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Create a new toolchain."""
    _ensure_dir()
    toolchain = {
        "name": name,
        "description": description or f"Custom toolchain: {name}",
        "categories": categories or DEFAULT_TOOLCHAIN["categories"],
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }
    _save_toolchain(toolchain)
    return toolchain


def get_toolchain(name: str) -> Dict[str, Any]:
    """Get a toolchain by name."""
    return _load_toolchain(name)


def list_toolchains() -> List[Dict[str, Any]]:
    """List all toolchains."""
    _ensure_dir()
    toolchains = []
    for path in TOOLCHAINS_DIR.glob("*.json"):
        try:
            toolchains.append(json.loads(path.read_text()))
        except Exception:
            continue
    return toolchains


def update_toolchain(name: str, categories: Dict[str, Any]) -> Dict[str, Any]:
    """Update a toolchain's categories."""
    toolchain = _load_toolchain(name)
    toolchain["categories"] = categories
    _save_toolchain(toolchain)
    return toolchain


def add_tool_to_category(toolchain_name: str, category: str, tool: str, position: str = "priority") -> Dict[str, Any]:
    """Add a tool to a toolchain category."""
    toolchain = _load_toolchain(toolchain_name)
    if category not in toolchain["categories"]:
        toolchain["categories"][category] = {"priority": [], "avoid": []}
    if tool not in toolchain["categories"][category][position]:
        toolchain["categories"][category][position].append(tool)
    _save_toolchain(toolchain)
    return toolchain


def remove_tool_from_category(toolchain_name: str, category: str, tool: str) -> Dict[str, Any]:
    """Remove a tool from a toolchain category."""
    toolchain = _load_toolchain(toolchain_name)
    if category in toolchain["categories"]:
        for position in ["priority", "avoid"]:
            if tool in toolchain["categories"][category].get(position, []):
                toolchain["categories"][category][position].remove(tool)
    _save_toolchain(toolchain)
    return toolchain


def get_tools_for_category(toolchain_name: str, category: str) -> Dict[str, List[str]]:
    """Get tools for a category from a toolchain."""
    toolchain = _load_toolchain(toolchain_name)
    return toolchain["categories"].get(category, {"priority": [], "avoid": []})


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "create":
        if not args:
            print("Usage: toolchain_manager.py create <name> [description] [categories-json]")
            sys.exit(1)
        description = args[1] if len(args) > 1 else ""
        categories = json.loads(args[2]) if len(args) > 2 else None
        print(json.dumps(create_toolchain(args[0], description, categories), indent=2))
    elif cmd == "get":
        if not args:
            print("Usage: toolchain_manager.py get <name>")
            sys.exit(1)
        print(json.dumps(get_toolchain(args[0]), indent=2))
    elif cmd == "list":
        print(json.dumps(list_toolchains(), indent=2))
    elif cmd == "update":
        if len(args) < 2:
            print("Usage: toolchain_manager.py update <name> <categories-json>")
            sys.exit(1)
        print(json.dumps(update_toolchain(args[0], json.loads(args[1])), indent=2))
    elif cmd == "add-tool":
        if len(args) < 3:
            print("Usage: toolchain_manager.py add-tool <toolchain> <category> <tool> [position]")
            sys.exit(1)
        position = args[3] if len(args) > 3 else "priority"
        print(json.dumps(add_tool_to_category(args[0], args[1], args[2], position), indent=2))
    elif cmd == "remove-tool":
        if len(args) < 3:
            print("Usage: toolchain_manager.py remove-tool <toolchain> <category> <tool>")
            sys.exit(1)
        print(json.dumps(remove_tool_from_category(args[0], args[1], args[2]), indent=2))
    elif cmd == "tools":
        if len(args) < 2:
            print("Usage: toolchain_manager.py tools <toolchain> <category>")
            sys.exit(1)
        print(json.dumps(get_tools_for_category(args[0], args[1]), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
