#!/usr/bin/env python3
"""
MCP (Model Context Protocol) manager for kali-ai.

Supports SSE (Server-Sent Events) and STDIO (Standard Input/Output) transports
for integrating external tools and services with AI agents.
Inspired by CAI's MCP support.

Usage: python3 /tools/mcp_manager.py <command> [args]
"""

import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

MCP_FILE = Path("/config/mcp-servers.json")
MCP_TOOLS_DIR = Path("/work/mcp-tools")

DEFAULT_MCP_SERVERS = {
    "servers": [],
    "transports": {
        "sse": {"enabled": True, "description": "Server-Sent Events for web-based servers"},
        "stdio": {"enabled": True, "description": "Standard Input/Output for local processes"},
    },
}


def _ensure_dirs() -> None:
    MCP_TOOLS_DIR.mkdir(parents=True, exist_ok=True)


def _load_mcp_config() -> Dict[str, Any]:
    if not MCP_FILE.exists():
        return DEFAULT_MCP_SERVERS
    try:
        return json.loads(MCP_FILE.read_text())
    except Exception:
        return DEFAULT_MCP_SERVERS


def _save_mcp_config(config: Dict[str, Any]) -> None:
    MCP_FILE.write_text(json.dumps(config, indent=2))


def load_sse_server(url: str, name: Optional[str] = None) -> Dict[str, Any]:
    """Load an MCP server via SSE transport."""
    config = _load_mcp_config()
    server_id = name or f"sse-{uuid.uuid4().hex[:8]}"
    server = {
        "id": server_id,
        "name": name or server_id,
        "transport": "sse",
        "url": url,
        "status": "connected",
        "connected_at": datetime.now(timezone.utc).isoformat(),
    }
    config.setdefault("servers", []).append(server)
    _save_mcp_config(config)
    return server


def load_stdio_server(command: str, name: Optional[str] = None, args: Optional[List[str]] = None) -> Dict[str, Any]:
    """Load an MCP server via STDIO transport."""
    config = _load_mcp_config()
    server_id = name or f"stdio-{uuid.uuid4().hex[:8]}"
    server = {
        "id": server_id,
        "name": name or server_id,
        "transport": "stdio",
        "command": command,
        "args": args or [],
        "status": "connected",
        "connected_at": datetime.now(timezone.utc).isoformat(),
    }
    config.setdefault("servers", []).append(server)
    _save_mcp_config(config)
    return server


def list_servers() -> List[Dict[str, Any]]:
    """List all MCP servers."""
    return _load_mcp_config().get("servers", [])


def remove_server(server_id: str) -> Dict[str, Any]:
    """Remove an MCP server."""
    config = _load_mcp_config()
    original_count = len(config.get("servers", []))
    config["servers"] = [s for s in config.get("servers", []) if s.get("id") != server_id]
    if len(config["servers"]) < original_count:
        _save_mcp_config(config)
        return {"removed": True, "server_id": server_id}
    return {"removed": False, "server_id": server_id, "reason": "not found"}


def get_server_tools(server_id: str) -> Dict[str, Any]:
    """Get tools from an MCP server (placeholder - would query the actual MCP server)."""
    servers = list_servers()
    server = next((s for s in servers if s.get("id") == server_id), None)
    if not server:
        return {"error": f"server not found: {server_id}"}

    # Placeholder for actual MCP tool discovery
    # In a real implementation, this would query the MCP server for available tools
    tools_file = MCP_TOOLS_DIR / f"{server_id}_tools.json"
    if tools_file.exists():
        try:
            return json.loads(tools_file.read_text())
        except Exception:
            pass

    return {
        "server_id": server_id,
        "transport": server.get("transport"),
        "tools": [
            {"name": "send_http_request", "description": "Send an HTTP request"},
            {"name": "create_repeater_tab", "description": "Create a repeater tab"},
            {"name": "send_to_intruder", "description": "Send request to intruder"},
            {"name": "get_proxy_history", "description": "Get proxy HTTP history"},
        ],
        "note": "Placeholder tools - actual MCP server integration needed",
    }


def add_server_tools(server_id: str, agent: str) -> Dict[str, Any]:
    """Add MCP server tools to an agent."""
    tools = get_server_tools(server_id)
    if "error" in tools:
        return tools

    # In a real implementation, this would register the tools with the agent
    return {
        "server_id": server_id,
        "agent": agent,
        "tools_added": len(tools.get("tools", [])),
        "tools": tools.get("tools", []),
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "load-sse":
        if not args:
            print("Usage: mcp_manager.py load-sse <url> [name]")
            sys.exit(1)
        name = args[1] if len(args) > 1 else None
        print(json.dumps(load_sse_server(args[0], name), indent=2))
    elif cmd == "load-stdio":
        if not args:
            print("Usage: mcp_manager.py load-stdio <command> [name] [args...]")
            sys.exit(1)
        name = args[1] if len(args) > 1 else None
        cmd_args = args[2:] if len(args) > 2 else []
        print(json.dumps(load_stdio_server(args[0], name, cmd_args), indent=2))
    elif cmd == "list":
        print(json.dumps(list_servers(), indent=2))
    elif cmd == "remove":
        if not args:
            print("Usage: mcp_manager.py remove <server_id>")
            sys.exit(1)
        print(json.dumps(remove_server(args[0]), indent=2))
    elif cmd == "tools":
        if not args:
            print("Usage: mcp_manager.py tools <server_id>")
            sys.exit(1)
        print(json.dumps(get_server_tools(args[0]), indent=2))
    elif cmd == "add-tools":
        if len(args) < 2:
            print("Usage: mcp_manager.py add-tools <server_id> <agent>")
            sys.exit(1)
        print(json.dumps(add_server_tools(args[0], args[1]), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
