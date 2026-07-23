#!/usr/bin/env python3
"""
Tool installation registry for kali-ai agents.

Checks which tools are needed for an agent and installs missing ones.
Usage: python3 /tools/tool_installer.py <agent-path> [--install] [--json]
"""

import json
import subprocess
import sys
from pathlib import Path

TOOLS_FILE = Path("/config/tools.json")


def _run(cmd: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)


def _tool_available(check_cmd: str) -> bool:
    result = _run(check_cmd)
    return result.returncode == 0


def _install_apt(pkg: str) -> bool:
    result = _run(f"sudo apt-get install -y --no-install-recommends {pkg}")
    return result.returncode == 0


def _install_pip(pkg: str) -> bool:
    result = _run(f"pip3 install --break-system-packages --user {pkg}")
    return result.returncode == 0


def _install_gem(pkg: str) -> bool:
    result = _run(f"sudo gem install {pkg}")
    return result.returncode == 0


def _install_npm(pkg: str) -> bool:
    result = _run(f"npm install -g {pkg}")
    return result.returncode == 0


def _install_git(url: str, dest: str) -> bool:
    result = _run(f"sudo git clone {url} {dest}")
    return result.returncode == 0


def check_agent_tools(agent: str, install: bool = False) -> dict:
    if not TOOLS_FILE.exists():
        return {"error": f"tools registry not found: {TOOLS_FILE}"}

    with TOOLS_FILE.open() as f:
        registry = json.load(f)

    agent_tools = registry.get("agent_tools", {}).get(agent, [])
    if not agent_tools:
        return {"agent": agent, "tools": [], "missing": [], "installed": [], "note": "no tools mapped"}

    categories = registry.get("categories", {})
    all_tools = {}
    for cat in categories.values():
        all_tools.update(cat.get("tools", {}))

    results = {"agent": agent, "tools": [], "missing": [], "installed": [], "skipped": []}

    for tool_name in agent_tools:
        tool_info = all_tools.get(tool_name)
        if not tool_info:
            results["skipped"].append({"tool": tool_name, "reason": "not in registry"})
            continue

        check_cmd = tool_info.get("check", f"which {tool_name}")
        available = _tool_available(check_cmd)

        tool_result = {"tool": tool_name, "available": available}
        if not available and install:
            installed = False
            method = None
            if "apt" in tool_info:
                installed = _install_apt(tool_info["apt"])
                method = "apt"
            elif "pip" in tool_info:
                installed = _install_pip(tool_info["pip"])
                method = "pip"
            elif "gem" in tool_info:
                installed = _install_gem(tool_info["gem"])
                method = "gem"
            elif "npm" in tool_info:
                installed = _install_npm(tool_info["npm"])
                method = "npm"
            elif "git" in tool_info:
                dest = tool_info.get("dest", f"/opt/{tool_name}")
                installed = _install_git(tool_info["git"], dest)
                method = "git"

            tool_result["installed"] = installed
            tool_result["method"] = method
            if installed:
                results["installed"].append(tool_name)
            else:
                results["missing"].append(tool_name)
        elif not available:
            results["missing"].append(tool_name)
        else:
            results["tools"].append(tool_name)

        results.setdefault("details", []).append(tool_result)

    return results


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    agent = sys.argv[1]
    install = "--install" in sys.argv
    as_json = "--json" in sys.argv

    result = check_agent_tools(agent, install=install)

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Agent: {result['agent']}")
        print(f"  Available: {len(result['tools'])}")
        print(f"  Missing: {len(result['missing'])}")
        if result["missing"]:
            print(f"  Missing tools: {', '.join(result['missing'])}")
        if result["installed"]:
            print(f"  Installed: {', '.join(result['installed'])}")
        if result.get("note"):
            print(f"  Note: {result['note']}")


if __name__ == "__main__":
    main()
