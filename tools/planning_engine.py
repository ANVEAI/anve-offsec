#!/usr/bin/env python3
"""
Planning engine for kali-ai.

Generates structured attack plans with phases, tools, techniques, and contingencies.
Uses strategy memory to include what worked in similar scenarios.

Usage: python3 /tools/planning_engine.py <command> [args]
"""

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

WORK_DIR = Path(os.environ.get("KALI_WORK_DIR") or ("/work" if Path("/work").exists() else "work"))
MEMORY_DIR = WORK_DIR / "memory"
STRATEGY_FILE = MEMORY_DIR / "strategy.json"


def _load_strategy() -> Dict[str, Any]:
    if not STRATEGY_FILE.exists():
        return {"scenarios": {}, "target_profiles": {}, "tool_effectiveness": {}, "next_step_suggestions": {}}
    try:
        return json.loads(STRATEGY_FILE.read_text())
    except Exception:
        return {"scenarios": {}, "target_profiles": {}, "tool_effectiveness": {}, "next_step_suggestions": {}}


def _target_type_from_task(task: str, target: str = "") -> str:
    """Infer target type from task description and target itself."""
    task = task.lower()
    # Explicit task keywords win
    if any(x in task for x in ["web", "http", "url", "site", "app", "api", "login", "form"]):
        return "web"
    if any(x in task for x in ["ad", "active directory", "domain", "ldap", "kerberos", "smb"]):
        return "ad"
    if any(x in task for x in ["network", "host", "ip", "scan", "smb", "ssh", "rdp"]):
        return "network"
    if any(x in task for x in ["cloud", "aws", "azure", "gcp", "s3", "lambda"]):
        return "cloud"
    if any(x in task for x in ["mobile", "android", "ios", "apk", "ipa"]):
        return "mobile"
    # Fall back to the target's shape: bare IPs and CIDR ranges are network targets
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?", target.strip()):
        return "network"
    return "web"


def _high_value_assets(target_type: str) -> List[str]:
    """Get high-value assets for a target type."""
    assets = {
        "web": ["database", "auth system", "payment processor", "admin panel", "file storage", "user data"],
        "network": ["domain controller", "file server", "database server", "backup server", "mail server"],
        "ad": ["domain controller", "krbtgt", "admin accounts", "service accounts", "gpos", "certificate services"],
        "cloud": ["iam credentials", "s3 buckets", "lambda functions", "rds databases", "ec2 instances", "secrets manager"],
        "mobile": ["local storage", "keychain", "api endpoints", "backend database", "push notification service"],
    }
    return assets.get(target_type, assets["web"])


def _trust_boundaries(target_type: str) -> List[str]:
    """Get trust boundaries for a target type."""
    boundaries = {
        "web": ["public internet", "cdn/waf", "web server", "application server", "database server", "internal network"],
        "network": ["public internet", "perimeter firewall", "dmz", "internal network", "restricted zone", "management network"],
        "ad": ["public internet", "vpn gateway", "domain workstation", "domain member server", "domain controller", "forest root"],
        "cloud": ["public internet", "cloud front door", "vpc", "private subnet", "data subnet", "management plane"],
        "mobile": ["public internet", "app store", "mobile device", "local sandbox", "backend api", "cloud backend"],
    }
    return boundaries.get(target_type, boundaries["web"])


def _attack_phases(target_type: str, strategy: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate attack phases for a target type."""
    scenarios = strategy.get("scenarios", {})

    base_phases = [
        {
            "phase": 1,
            "name": "Reconnaissance",
            "description": "Gather information about the target without direct engagement",
            "tools": ["subfinder", "amass", "dnsrecon", "whois", "crt.sh", "whatweb", "wappalyzer", "shodan", "censys"],
            "techniques": ["passive dns", "certificate transparency", "osint", "technology fingerprinting", "subdomain enumeration"],
            "expected_outcomes": ["target scope", "subdomains", "technologies", "potential entry points", "ip ranges"],
            "decision_points": ["if cloudflare found, look for origin ip", "if waf found, plan bypass techniques", "if cdn found, check for misconfigurations"],
            "contingencies": ["if subfinder fails, use amass", "if crt.sh fails, use censys", "if dnsrecon fails, use dig"],
            "estimated_time_minutes": 15,
        },
        {
            "phase": 2,
            "name": "Scanning & Enumeration",
            "description": "Active scanning and service enumeration to identify attack surfaces",
            "tools": ["nmap", "masscan", "rustscan", "gobuster", "ffuf", "dirsearch", "nikto", "nuclei", "zap", "burpsuite"],
            "techniques": ["port scanning", "service detection", "web path discovery", "parameter discovery", "vulnerability scanning"],
            "expected_outcomes": ["open ports", "services", "web paths", "parameters", "vulnerabilities", "technologies"],
            "decision_points": ["if nmap blocked, use python connect scan", "if gobuster finds nothing, use ffuf with different wordlist", "if zap fails, use manual scanning"],
            "contingencies": ["if nmap fails, use masscan", "if masscan fails, use python connect scan", "if zap fails, use burpsuite"],
            "estimated_time_minutes": 30,
        },
        {
            "phase": 3,
            "name": "Vulnerability Analysis",
            "description": "Analyze discovered vulnerabilities and prioritize exploitation",
            "tools": ["sqlmap", "xsstrike", "dalfox", "commix", "ssrfmap", "gopherus", "tplmap", "searchsploit", "cve-search"],
            "techniques": ["sql injection", "xss", "command injection", "ssrf", "lfi", "xxe", "ssti", "csrf", "idor", "file upload"],
            "expected_outcomes": ["confirmed vulnerabilities", "exploitability", "impact assessment", "priority ranking"],
            "decision_points": ["if sqlmap blocked, use manual time-based blind", "if xsstrike finds nothing, use dalfox", "if public exploit unavailable, write custom exploit"],
            "contingencies": ["if sqlmap fails, use manual time-based blind", "if xsstrike fails, use dalfox", "if all scanners fail, use manual analysis"],
            "estimated_time_minutes": 45,
        },
        {
            "phase": 4,
            "name": "Exploitation",
            "description": "Attempt controlled exploitation of confirmed vulnerabilities",
            "tools": ["metasploit", "custom python", "curl", "burpsuite", "zap", "exploit-db", "searchsploit"],
            "techniques": ["public exploits", "custom exploits", "payload delivery", "proof of concept", "impact demonstration"],
            "expected_outcomes": ["initial access", "proof of concept", "impact evidence", "exploit documentation"],
            "decision_points": ["if public exploit fails, write custom exploit", "if rce achieved, establish persistence", " if access gained, escalate privileges"],
            "contingencies": ["if metasploit fails, use custom python", "if exploit fails, try different payload", "if payload fails, try different technique"],
            "estimated_time_minutes": 60,
        },
        {
            "phase": 5,
            "name": "Post-Exploitation",
            "description": "Maintain access, escalate privileges, and move laterally",
            "tools": ["mimikatz", "pypykatz", "secretsdump.py", "bloodhound.py", "netexec", "evil-winrm", "impacket", "crackmapexec"],
            "techniques": ["privilege escalation", "credential dumping", "lateral movement", "persistence", "defense evasion"],
            "expected_outcomes": ["elevated privileges", "credentials", "lateral movement", "persistence", "network access"],
            "decision_points": ["if privesc fails, try different technique", "if lateral movement blocked, try different protocol", "if persistence fails, try different mechanism"],
            "contingencies": ["if mimikatz fails, use pypykatz", "if secretsdump fails, use lsassy", "if evil-winrm fails, use psexec.py"],
            "estimated_time_minutes": 45,
        },
        {
            "phase": 6,
            "name": "Collection & Exfiltration",
            "description": "Collect sensitive data and exfiltrate it securely",
            "tools": ["curl", "scp", "rsync", "tar", "zip", "7z", "gpg", "openssl", "base64", "xxd"],
            "techniques": ["data collection", "data archiving", "data encryption", "data exfiltration", "evidence preservation"],
            "expected_outcomes": ["collected data", "archived evidence", "encrypted exfil", "documented impact"],
            "decision_points": ["if exfil blocked, use different channel", "if data too large, use compression", "if encryption needed, use gpg"],
            "contingencies": ["if curl fails, use wget", "if scp fails, use rsync", "if tar fails, use zip"],
            "estimated_time_minutes": 30,
        },
        {
            "phase": 7,
            "name": "Reporting",
            "description": "Generate professional report with findings, chains, and recommendations",
            "tools": ["python3", "markdown", "reporting engine"],
            "techniques": ["finding aggregation", "chain documentation", "business impact analysis", "remediation planning", "executive summary"],
            "expected_outcomes": ["professional report", "findings summary", "attack chains", "remediation roadmap", "executive summary"],
            "decision_points": ["if findings unclear, re-verify", "if chains incomplete, document gaps", "if remediation unclear, provide alternatives"],
            "contingencies": ["if reporting engine fails, use manual markdown", "if evidence missing, re-collect", "if analysis incomplete, add caveats"],
            "estimated_time_minutes": 30,
        },
    ]

    # Customize phases based on target type
    if target_type == "ad":
        # Insert AD-specific phases after recon
        ad_phases = [
            {
                "phase": 2.5,
                "name": "AD Enumeration",
                "description": "Enumerate Active Directory users, groups, computers, and trusts",
                "tools": ["netexec", "enum4linux", "ldapsearch", "ldapdomaindump", "bloodhound.py", "rpcclient", "smbmap"],
                "techniques": ["smb enumeration", "ldap enumeration", "kerberos enumeration", "ad trust mapping", "gpo analysis"],
                "expected_outcomes": ["domain users", "domain groups", "domain computers", "trusts", "gpos", "spns"],
                "decision_points": ["if smb signing required, use kerberos", "if ldap blocked, use smb", "if bloodhound fails, use manual enumeration"],
                "contingencies": ["if netexec fails, use enum4linux", "if ldapsearch fails, use rpcclient", "if bloodhound.py fails, use sharphound"],
                "estimated_time_minutes": 20,
            }
        ]
        base_phases = base_phases[:2] + ad_phases + base_phases[2:]

    return base_phases


def generate_plan(target: str, task: str, constraints: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a structured attack plan for a target."""
    strategy = _load_strategy()
    target_type = _target_type_from_task(task, target)
    constraints = constraints or {}

    plan_id = f"plan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    # Build threat model
    threat_model = {
        "target_type": target_type,
        "high_value_assets": _high_value_assets(target_type),
        "trust_boundaries": _trust_boundaries(target_type),
        "attacker_goals": constraints.get("goals", ["data access", "initial access", "persistence", "impact demonstration"]),
        "risk_rating": constraints.get("risk_rating", "high"),
    }

    # Build attack plan
    attack_plan = {
        "plan_id": plan_id,
        "target": target,
        "target_type": target_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "threat_model": threat_model,
        "phases": _attack_phases(target_type, strategy),
        "constraints": constraints,
        "estimated_total_time_minutes": sum(p.get("estimated_time_minutes", 30) for p in _attack_phases(target_type, strategy)),
        "strategy_guidance": strategy.get("scenarios", {}).get(f"{target_type}:general", {}),
    }

    return attack_plan


def plan_to_markdown(plan: Dict[str, Any]) -> str:
    """Convert an attack plan to markdown."""
    lines = [
        f"# Attack Plan: {plan['target']}",
        f"**Target Type**: {plan['target_type']}",
        f"**Created**: {plan['created_at']}",
        f"**Estimated Total Time**: {plan['estimated_total_time_minutes']} minutes",
        "",
        "## Threat Model",
        f"- **High-Value Assets**: {', '.join(plan['threat_model']['high_value_assets'])}",
        f"- **Trust Boundaries**: {', '.join(plan['threat_model']['trust_boundaries'])}",
        f"- **Attacker Goals**: {', '.join(plan['threat_model']['attacker_goals'])}",
        f"- **Risk Rating**: {plan['threat_model']['risk_rating']}",
        "",
        "## Attack Phases",
    ]

    for phase in plan["phases"]:
        lines.extend([
            "",
            f"### Phase {phase['phase']}: {phase['name']}",
            f"**Description**: {phase['description']}",
            f"**Estimated Time**: {phase['estimated_time_minutes']} minutes",
            "",
            "**Tools**:",
        ])
        for tool in phase["tools"]:
            lines.append(f"- {tool}")
        lines.extend([
            "",
            "**Techniques**:",
        ])
        for tech in phase["techniques"]:
            lines.append(f"- {tech}")
        lines.extend([
            "",
            "**Expected Outcomes**:",
        ])
        for outcome in phase["expected_outcomes"]:
            lines.append(f"- {outcome}")
        lines.extend([
            "",
            "**Decision Points**:",
        ])
        for dp in phase["decision_points"]:
            lines.append(f"- {dp}")
        lines.extend([
            "",
            "**Contingencies**:",
        ])
        for cont in phase["contingencies"]:
            lines.append(f"- {cont}")

    if plan.get("strategy_guidance"):
        lines.extend([
            "",
            "## Strategy Guidance",
            f"Based on {plan['strategy_guidance'].get('run_count', 0)} past runs (confidence: {plan['strategy_guidance'].get('confidence', 0):.2f})",
            f"- Success rate: {plan['strategy_guidance'].get('success_rate', 0):.1%}",
            f"- Best tools: {', '.join(plan['strategy_guidance'].get('tools', []))}",
        ])

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "generate":
        if len(args) < 2:
            print("Usage: planning_engine.py generate <target> <task> [constraints-json]")
            sys.exit(1)
        constraints = json.loads(args[2]) if len(args) > 2 else None
        plan = generate_plan(args[0], args[1], constraints)
        print(json.dumps(plan, indent=2))
    elif cmd == "markdown":
        if len(args) < 2:
            print("Usage: planning_engine.py markdown <target> <task> [constraints-json]")
            sys.exit(1)
        constraints = json.loads(args[2]) if len(args) > 2 else None
        plan = generate_plan(args[0], args[1], constraints)
        print(plan_to_markdown(plan))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
