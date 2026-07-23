#!/usr/bin/env python3
"""
Dynamic checklist generator for kali-ai.

Auto-generates and updates structured exploit methodology based on discovered intelligence.
Inspired by Pentest Copilot's dynamic checklists.

Usage: python3 /tools/checklist_generator.py <command> [args]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

CHECKLISTS_DIR = Path("/work/checklists")


def _ensure_dir() -> None:
    CHECKLISTS_DIR.mkdir(parents=True, exist_ok=True)


def _load_checklist(checklist_id: str) -> Dict[str, Any]:
    path = CHECKLISTS_DIR / f"{checklist_id}.json"
    if not path.exists():
        return {"id": checklist_id, "items": [], "created_at": datetime.now(timezone.utc).isoformat()}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {"id": checklist_id, "items": [], "created_at": datetime.now(timezone.utc).isoformat()}


def _save_checklist(checklist: Dict[str, Any]) -> None:
    path = CHECKLISTS_DIR / f"{checklist['id']}.json"
    checklist["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(checklist, indent=2))


def create_checklist(target: str, target_type: str = "web") -> Dict[str, Any]:
    """Create a new checklist for a target."""
    _ensure_dir()
    checklist_id = f"{target.replace('.', '_').replace('://', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    # Base checklist items based on target type
    base_items = {
        "web": [
            {"id": "recon", "name": "Reconnaissance", "status": "pending", "priority": "high", "tools": ["nmap", "whatweb", "subfinder", "amass"], "notes": "Identify target scope, technologies, and attack surface"},
            {"id": "spider", "name": "ZAP Spider", "status": "pending", "priority": "high", "tools": ["zap"], "notes": "Traditional + AJAX spider to discover all endpoints"},
            {"id": "baseline", "name": "Passive Scan", "status": "pending", "priority": "high", "tools": ["zap"], "notes": "Baseline security header and misconfiguration check"},
            {"id": "paths", "name": "Path Discovery", "status": "pending", "priority": "medium", "tools": ["gobuster", "ffuf", "dirsearch"], "notes": "Discover hidden paths and files"},
            {"id": "params", "name": "Parameter Discovery", "status": "pending", "priority": "medium", "tools": ["arjun", "paramspider"], "notes": "Discover hidden parameters and input vectors"},
            {"id": "sqli", "name": "SQL Injection", "status": "pending", "priority": "high", "tools": ["sqlmap", "manual-payloads"], "notes": "Test for SQLi on all parameters"},
            {"id": "xss", "name": "XSS", "status": "pending", "priority": "high", "tools": ["xsstrike", "dalfox", "manual-payloads"], "notes": "Test for reflected, stored, and DOM XSS"},
            {"id": "csrf", "name": "CSRF", "status": "pending", "priority": "medium", "tools": ["zap", "manual-payloads"], "notes": "Test for CSRF on state-changing actions"},
            {"id": "ssrf", "name": "SSRF", "status": "pending", "priority": "medium", "tools": ["ssrfmap", "gopherus", "interactsh"], "notes": "Test for server-side request forgery"},
            {"id": "lfi", "name": "LFI/RFI", "status": "pending", "priority": "medium", "tools": ["manual-payloads", "ffuf"], "notes": "Test for local and remote file inclusion"},
            {"id": "upload", "name": "File Upload", "status": "pending", "priority": "medium", "tools": ["manual-payloads"], "notes": "Test for unrestricted file upload and RCE"},
            {"id": "auth", "name": "Authentication", "status": "pending", "priority": "high", "tools": ["hydra", "burp", "jwt_tool"], "notes": "Test login, session management, and access control"},
            {"id": "idor", "name": "IDOR", "status": "pending", "priority": "high", "tools": ["manual-payloads", "burp"], "notes": "Test for insecure direct object references"},
            {"id": "misconfig", "name": "Misconfiguration", "status": "pending", "priority": "medium", "tools": ["nikto", "nuclei", "sslyze"], "notes": "Check for security misconfigurations"},
            {"id": "components", "name": "Outdated Components", "status": "pending", "priority": "medium", "tools": ["searchsploit", "cve-search", "retire.js"], "notes": "Check for vulnerable and outdated components"},
            {"id": "exploit", "name": "Exploitation", "status": "pending", "priority": "high", "tools": ["metasploit", "custom-payloads"], "notes": "Attempt safe PoC for confirmed vulnerabilities"},
            {"id": "report", "name": "Reporting", "status": "pending", "priority": "high", "tools": ["python3", "markdown"], "notes": "Generate final report with evidence and remediation"},
        ],
        "network": [
            {"id": "host-discovery", "name": "Host Discovery", "status": "pending", "priority": "high", "tools": ["nmap", "masscan", "fping"], "notes": "Discover live hosts in scope"},
            {"id": "port-scan", "name": "Port Scan", "status": "pending", "priority": "high", "tools": ["nmap", "masscan", "rustscan"], "notes": "Full TCP/UDP port scan"},
            {"id": "service-enum", "name": "Service Enumeration", "status": "pending", "priority": "high", "tools": ["nmap", "banner-grab", "version-detect"], "notes": "Identify services and versions"},
            {"id": "smb", "name": "SMB Enumeration", "status": "pending", "priority": "high", "tools": ["smbmap", "enum4linux", "netexec"], "notes": "Enumerate SMB shares, users, and policies"},
            {"id": "ldap", "name": "LDAP Enumeration", "status": "pending", "priority": "high", "tools": ["ldapsearch", "ldapdomaindump", "bloodhound.py"], "notes": "Enumerate AD users, groups, and trusts"},
            {"id": "kerberos", "name": "Kerberos Attacks", "status": "pending", "priority": "medium", "tools": ["kerbrute", "rubeus", "kekeo"], "notes": "Test for AS-REP roasting, kerberoasting, and delegation"},
            {"id": "creds", "name": "Credential Attacks", "status": "pending", "priority": "high", "tools": ["responder", "ntlmrelayx.py", "mimikatz"], "notes": "Poison LLMNR/NBT-NS, relay, and dump credentials"},
            {"id": "lateral", "name": "Lateral Movement", "status": "pending", "priority": "high", "tools": ["evil-winrm", "psexec.py", "wmiexec.py"], "notes": "Move to other systems with harvested credentials"},
            {"id": "privesc", "name": "Privilege Escalation", "status": "pending", "priority": "high", "tools": ["linpeas", "winpeas", "exploit-suggester"], "notes": "Escalate to root/SYSTEM"},
            {"id": "persistence", "name": "Persistence", "status": "pending", "priority": "medium", "tools": ["cron", "systemd", "schtasks"], "notes": "Establish persistence mechanisms"},
            {"id": "exfil", "name": "Exfiltration", "status": "pending", "priority": "medium", "tools": ["curl", "scp", "rsync"], "notes": "Exfiltrate collected data"},
            {"id": "report", "name": "Reporting", "status": "pending", "priority": "high", "tools": ["python3", "markdown"], "notes": "Generate final report with evidence and remediation"},
        ],
        "ad": [
            {"id": "recon", "name": "AD Recon", "status": "pending", "priority": "high", "tools": ["netexec", "enum4linux", "ldapsearch"], "notes": "Enumerate domain, users, groups, and computers"},
            {"id": "smb", "name": "SMB Attacks", "status": "pending", "priority": "high", "tools": ["smbmap", "netexec", "impacket"], "notes": "Test SMB shares, null sessions, and signing"},
            {"id": "kerberos", "name": "Kerberos Attacks", "status": "pending", "priority": "high", "tools": ["kerbrute", "rubeus", "kekeo"], "notes": "AS-REP roast, kerberoast, and delegation attacks"},
            {"id": "creds", "name": "Credential Harvesting", "status": "pending", "priority": "high", "tools": ["responder", "ntlmrelayx.py", "mimikatz", "secretsdump.py"], "notes": "Poison, relay, and dump credentials"},
            {"id": "bloodhound", "name": "BloodHound", "status": "pending", "priority": "high", "tools": ["bloodhound.py", "sharphound"], "notes": "Map AD attack paths"},
            {"id": "delegation", "name": "Delegation Attacks", "status": "pending", "priority": "medium", "tools": ["rubeus", "impacket"], "notes": "Test unconstrained, constrained, and resource-based delegation"},
            {"id": "adcs", "name": "AD CS Attacks", "status": "pending", "priority": "medium", "tools": ["certipy", "certify"], "notes": "Test certificate services vulnerabilities"},
            {"id": "lateral", "name": "Lateral Movement", "status": "pending", "priority": "high", "tools": ["evil-winrm", "psexec.py", "wmiexec.py", "smbexec.py"], "notes": "Move to domain controllers and high-value targets"},
            {"id": "dcsync", "name": "DCSync", "status": "pending", "priority": "high", "tools": ["secretsdump.py", "mimikatz"], "notes": "Dump domain credentials from DC"},
            {"id": "persistence", "name": "Persistence", "status": "pending", "priority": "medium", "tools": ["golden-ticket", "dcsync", "skeleton-key"], "notes": "Establish domain persistence"},
            {"id": "report", "name": "Reporting", "status": "pending", "priority": "high", "tools": ["python3", "markdown"], "notes": "Generate final report with evidence and remediation"},
        ],
    }

    items = base_items.get(target_type, base_items["web"])
    checklist = {
        "id": checklist_id,
        "target": target,
        "target_type": target_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "items": items,
    }
    _save_checklist(checklist)
    return checklist


def update_checklist_item(checklist_id: str, item_id: str, status: str, notes: Optional[str] = None, evidence: Optional[List[str]] = None) -> Dict[str, Any]:
    """Update a checklist item status."""
    checklist = _load_checklist(checklist_id)
    for item in checklist.get("items", []):
        if item.get("id") == item_id:
            item["status"] = status
            if notes:
                item["notes"] = notes
            if evidence:
                item.setdefault("evidence", []).extend(evidence)
            break
    _save_checklist(checklist)
    return checklist


def add_checklist_item(checklist_id: str, item: Dict[str, Any]) -> Dict[str, Any]:
    """Add a new item to a checklist."""
    checklist = _load_checklist(checklist_id)
    item.setdefault("status", "pending")
    item.setdefault("priority", "medium")
    checklist.setdefault("items", []).append(item)
    _save_checklist(checklist)
    return checklist


def get_checklist(checklist_id: str) -> Dict[str, Any]:
    """Get a checklist by ID."""
    return _load_checklist(checklist_id)


def list_checklists() -> List[Dict[str, Any]]:
    """List all checklists."""
    _ensure_dir()
    checklists = []
    for path in CHECKLISTS_DIR.glob("*.json"):
        try:
            checklists.append(json.loads(path.read_text()))
        except Exception:
            continue
    return sorted(checklists, key=lambda x: x.get("created_at", ""), reverse=True)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "create":
        if not args:
            print("Usage: checklist_generator.py create <target> [target_type]")
            sys.exit(1)
        target_type = args[1] if len(args) > 1 else "web"
        print(json.dumps(create_checklist(args[0], target_type), indent=2))
    elif cmd == "update":
        if len(args) < 3:
            print("Usage: checklist_generator.py update <checklist_id> <item_id> <status> [notes] [evidence]")
            sys.exit(1)
        notes = args[3] if len(args) > 3 else None
        evidence = args[4].split(",") if len(args) > 4 else None
        print(json.dumps(update_checklist_item(args[0], args[1], args[2], notes, evidence), indent=2))
    elif cmd == "add":
        if len(args) < 2:
            print("Usage: checklist_generator.py add <checklist_id> <item-json>")
            sys.exit(1)
        print(json.dumps(add_checklist_item(args[0], json.loads(args[1])), indent=2))
    elif cmd == "get":
        if not args:
            print("Usage: checklist_generator.py get <checklist_id>")
            sys.exit(1)
        print(json.dumps(get_checklist(args[0]), indent=2))
    elif cmd == "list":
        print(json.dumps(list_checklists(), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
