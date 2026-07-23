#!/usr/bin/env python3
"""
Chain engine for kali-ai.

Identifies and documents vulnerability chains with entry point, pivot points, final impact, and business risk.
Uses strategy memory to include what worked in similar scenarios.

Usage: python3 /tools/chain_engine.py <command> [args]
"""

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

WORK_DIR = Path(os.environ.get("KALI_WORK_DIR") or ("/work" if Path("/work").exists() else "work"))
MEMORY_DIR = WORK_DIR / "memory"
STRATEGY_FILE = MEMORY_DIR / "strategy.json"

COMMON_CHAINS = {
    "info-disclosure-auth-bypass": {
        "name": "Info Disclosure → Auth Bypass → Data Access",
        "description": "Exposed API keys, credentials, or sensitive info leads to authentication bypass and data access",
        "entry_points": ["exposed api keys", "credentials in source code", "sensitive info in responses", "debug endpoints"],
        "pivot_points": ["login as admin", "access internal api", "bypass authentication"],
        "final_impact": "full database access, user data exposure, admin panel access",
        "business_risk": "critical — full data breach, regulatory violation, reputational damage",
        "severity": "critical",
    },
    "xss-session-hijack": {
        "name": "XSS → Session Hijack → Account Takeover",
        "description": "Cross-site scripting steals session cookie, leading to account takeover and privilege escalation",
        "entry_points": ["reflected xss", "stored xss", "dom xss"],
        "pivot_points": ["steal session cookie", "login as victim", "change email/password"],
        "final_impact": "account takeover, privilege escalation, data access",
        "business_risk": "high — user account compromise, data theft, reputational damage",
        "severity": "high",
    },
    "ssrf-cloud-metadata": {
        "name": "SSRF → Internal Scan → Cloud Metadata → RCE",
        "description": "Server-side request forgery accesses internal services and cloud metadata, leading to remote code execution",
        "entry_points": ["ssrf vulnerability", "url parameter", "webhook", "file import"],
        "pivot_points": ["access internal services", "find aws metadata", "get iam credentials"],
        "final_impact": "cloud infrastructure access, rce, data exfiltration",
        "business_risk": "critical — full cloud compromise, data breach, financial loss",
        "severity": "critical",
    },
    "lfi-log-poisoning": {
        "name": "LFI → Log Poisoning → RCE",
        "description": "Local file inclusion reads log files, injects code into logs, and includes them for remote code execution",
        "entry_points": ["lfi vulnerability", "path traversal", "file inclusion"],
        "pivot_points": ["read log files", "inject php code into logs", "include logs"],
        "final_impact": "remote code execution, server compromise, full control",
        "business_risk": "critical — full server compromise, data breach, ransomware",
        "severity": "critical",
    },
    "file-upload-web-shell": {
        "name": "File Upload → Web Shell → Persistence",
        "description": "Unrestricted file upload leads to web shell execution and persistent access",
        "entry_points": ["file upload vulnerability", "extension bypass", "content-type bypass"],
        "pivot_points": ["upload malicious file", "access via browser", "execute commands"],
        "final_impact": "web shell, persistent access, server compromise",
        "business_risk": "critical — full server compromise, data breach, ransomware",
        "severity": "critical",
    },
    "csrf-password-change": {
        "name": "CSRF → Password Change → Account Lockout",
        "description": "Cross-site request forgery forces password change, locking out the legitimate user",
        "entry_points": ["csrf vulnerability", "password change form", "state-changing action"],
        "pivot_points": ["force password change", "lock out legitimate user", "maintain access"],
        "final_impact": "account lockout, unauthorized access, data access",
        "business_risk": "high — user account compromise, data theft, reputational damage",
        "severity": "high",
    },
    "sqli-rce": {
        "name": "SQL Injection → RCE → Full Database Access",
        "description": "SQL injection leads to remote code execution and full database access",
        "entry_points": ["sql injection", "login form", "search parameter", "api endpoint"],
        "pivot_points": ["extract database", "read files", "write files", "execute commands"],
        "final_impact": "full database access, rce, server compromise",
        "business_risk": "critical — full data breach, server compromise, ransomware",
        "severity": "critical",
    },
    "idor-privilege-escalation": {
        "name": "IDOR → Privilege Escalation → Admin Access",
        "description": "Insecure direct object reference leads to privilege escalation and admin access",
        "entry_points": ["idor vulnerability", "user id parameter", "object reference"],
        "pivot_points": ["access other users' data", "escalate privileges", "access admin functions"],
        "final_impact": "admin access, privilege escalation, data access",
        "business_risk": "high — unauthorized access, data theft, reputational damage",
        "severity": "high",
    },
    "jwt-forgery": {
        "name": "JWT Algorithm Confusion → Token Forgery → Auth Bypass",
        "description": "JWT algorithm confusion leads to token forgery and authentication bypass",
        "entry_points": ["jwt vulnerability", "algorithm confusion", "weak secret"],
        "pivot_points": ["forge token", "bypass authentication", "access protected resources"],
        "final_impact": "authentication bypass, admin access, data access",
        "business_risk": "high — unauthorized access, data theft, reputational damage",
        "severity": "high",
    },
    "xxe-ssrf": {
        "name": "XXE → SSRF → Internal Network Access",
        "description": "XML external entity leads to server-side request forgery and internal network access",
        "entry_points": ["xxe vulnerability", "xml input", "file upload"],
        "pivot_points": ["read files", "access internal services", "scan internal network"],
        "final_impact": "internal network access, data exfiltration, rce",
        "business_risk": "critical — internal network compromise, data breach, lateral movement",
        "severity": "critical",
    },
}


def _load_strategy() -> Dict[str, Any]:
    if not STRATEGY_FILE.exists():
        return {"scenarios": {}, "tool_effectiveness": {}}
    try:
        return json.loads(STRATEGY_FILE.read_text())
    except Exception:
        return {"scenarios": {}, "tool_effectiveness": {}}


def _load_findings(arg: str) -> List[Dict[str, Any]]:
    """Load findings from a JSON string, a JSON file path, or an object with a 'findings' key."""
    if os.path.isfile(arg):
        arg = Path(arg).read_text()
    data = json.loads(arg)
    if isinstance(data, dict):
        data = data.get("findings", [])
    if not isinstance(data, list):
        raise ValueError("findings must be a JSON list or an object with a 'findings' list")
    return data


def identify_chains(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify potential vulnerability chains from findings."""
    strategy = _load_strategy()
    chains = []

    # Check for common chains
    for chain_id, chain in COMMON_CHAINS.items():
        # Check if we have findings that match the entry points
        matching_findings = []
        for finding in findings:
            finding_type = finding.get("type", "").lower()
            finding_title = finding.get("title", "").lower()
            finding_detail = finding.get("detail", "").lower()

            for entry_point in chain["entry_points"]:
                if entry_point in finding_type or entry_point in finding_title or entry_point in finding_detail:
                    matching_findings.append(finding)
                    break

        if matching_findings:
            chain_instance = {
                "chain_id": f"chain_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}",
                "name": chain["name"],
                "description": chain["description"],
                "entry_points": chain["entry_points"],
                "pivot_points": chain["pivot_points"],
                "final_impact": chain["final_impact"],
                "business_risk": chain["business_risk"],
                "severity": chain["severity"],
                "matching_findings": matching_findings,
                "confidence": min(len(matching_findings) / len(chain["entry_points"]), 1.0),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            chains.append(chain_instance)

    # Sort by confidence and severity
    chains.sort(key=lambda x: (x["severity"] == "critical", x["confidence"]), reverse=True)
    return chains


def chain_to_markdown(chain: Dict[str, Any]) -> str:
    """Convert a chain to markdown."""
    lines = [
        f"## {chain['name']}",
        f"**Severity**: {chain['severity'].upper()}",
        f"**Confidence**: {chain['confidence']:.1%}",
        f"**Business Risk**: {chain['business_risk']}",
        "",
        f"**Description**: {chain['description']}",
        "",
        "**Entry Points**:",
    ]
    for ep in chain["entry_points"]:
        lines.append(f"- {ep}")
    lines.extend([
        "",
        "**Pivot Points**:",
    ])
    for pp in chain["pivot_points"]:
        lines.append(f"- {pp}")
    lines.extend([
        "",
        "**Final Impact**:",
        f"- {chain['final_impact']}",
        "",
        "**Matching Findings**:",
    ])
    for finding in chain["matching_findings"]:
        lines.append(f"- [{finding.get('severity', 'info')}] {finding.get('title', '')}: {finding.get('detail', '')}")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "identify":
        if not args:
            print("Usage: chain_engine.py identify <findings-json>")
            sys.exit(1)
        findings = _load_findings(args[0])
        print(json.dumps(identify_chains(findings), indent=2))
    elif cmd == "markdown":
        if not args:
            print("Usage: chain_engine.py markdown <findings-json>")
            sys.exit(1)
        findings = _load_findings(args[0])
        chains = identify_chains(findings)
        for chain in chains:
            print(chain_to_markdown(chain))
            print()
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
