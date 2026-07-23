#!/usr/bin/env python3
"""
Authorization checker for kali-ai targets.

Validates whether a target is authorized for testing based on config/authorized-targets.json.
Supports lab mode, CTF platforms, bug bounty platforms, and manual override.

Usage: python3 /tools/auth_checker.py <target> [--override] [--json]
"""

import fnmatch
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

AUTH_FILE = Path("/config/authorized-targets.json")
OVERRIDE_LOG = Path("/work/memory/override-log.jsonl")


def _load_config() -> Dict[str, Any]:
    if not AUTH_FILE.exists():
        return {"targets": [], "override": {"enabled": False}}
    try:
        return json.loads(AUTH_FILE.read_text())
    except Exception:
        return {"targets": [], "override": {"enabled": False}}


def _match_domain(target: str, pattern: str) -> bool:
    """Match a target against a pattern (supports wildcards like *.example.com)."""
    target = target.lower().strip()
    pattern = pattern.lower().strip()

    # Exact match
    if target == pattern:
        return True

    # Wildcard match
    if fnmatch.fnmatch(target, pattern):
        return True

    # IP range match (simplified)
    if "/" in pattern:
        # TODO: implement proper CIDR matching
        pass

    # Subdomain match (e.g., example.com matches sub.example.com)
    if target.endswith("." + pattern):
        return True

    return False


def _extract_domain(target: str) -> str:
    """Extract domain from a target (URL, IP, or domain)."""
    target = target.lower().strip()

    # Remove protocol
    if "://" in target:
        target = target.split("://", 1)[1]

    # Remove path
    target = target.split("/", 1)[0]

    # Remove port
    target = target.split(":", 1)[0]

    return target


def _log_override(target: str, confirmed: bool, confirmation_text: str = "") -> None:
    """Log an override event."""
    OVERRIDE_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "confirmed": confirmed,
        "confirmation_text": confirmation_text,
    }
    with OVERRIDE_LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def check_authorization(target: str, override_confirmed: bool = False, confirmation_text: str = "") -> Dict[str, Any]:
    """
    Check if a target is authorized for testing.

    Returns a dict with:
    - authorized: bool
    - auth_type: str (lab/ctf/bug-bounty/self/client/override/none)
    - reason: str
    - requires_override: bool
    - override_text: str (if override is required)
    """
    config = _load_config()
    domain = _extract_domain(target)

    # Check lab mode targets
    if config.get("lab_mode", False):
        lab_types = {"lab", "self"}
        for t in config.get("targets", []):
            if t.get("type") in lab_types and _match_domain(domain, t.get("domain", "")):
                return {
                    "authorized": True,
                    "auth_type": t.get("type"),
                    "reason": f"Lab/self target: {t.get('notes', '')}",
                    "requires_override": False,
                }

    # Check CTF platforms
    if config.get("allow_ctf", False):
        for t in config.get("targets", []):
            if t.get("type") == "ctf" and _match_domain(domain, t.get("domain", "")):
                return {
                    "authorized": True,
                    "auth_type": "ctf",
                    "reason": f"CTF platform: {t.get('notes', '')}",
                    "requires_override": False,
                }

    # Check bug bounty platforms
    if config.get("allow_bug_bounty", False):
        for t in config.get("targets", []):
            if t.get("type") == "bug-bounty" and _match_domain(domain, t.get("domain", "")):
                return {
                    "authorized": True,
                    "auth_type": "bug-bounty",
                    "reason": f"Bug bounty target: {t.get('notes', '')}",
                    "requires_override": False,
                }

        # Check if target is a bug bounty platform itself
        for platform in config.get("bug_bounty_platforms", []):
            if _match_domain(domain, platform.get("domain", "")):
                return {
                    "authorized": True,
                    "auth_type": "bug-bounty",
                    "reason": f"Bug bounty platform: {platform.get('name')}",
                    "requires_override": False,
                }

    # Check client-authorized targets
    for t in config.get("targets", []):
        if t.get("type") == "client" and _match_domain(domain, t.get("domain", "")):
            return {
                "authorized": True,
                "auth_type": "client",
                "reason": f"Client-authorized: {t.get('notes', '')}",
                "requires_override": False,
            }

    # Check self-authorized targets
    for t in config.get("targets", []):
        if t.get("type") == "self" and _match_domain(domain, t.get("domain", "")):
            return {
                "authorized": True,
                "auth_type": "self",
                "reason": f"Self-authorized: {t.get('notes', '')}",
                "requires_override": False,
            }

    # Not authorized - check override
    override_config = config.get("override", {})
    if override_config.get("enabled", False):
        if override_confirmed:
            _log_override(target, True, confirmation_text)
            return {
                "authorized": True,
                "auth_type": "override",
                "reason": f"Manual override confirmed: {confirmation_text[:100]}",
                "requires_override": False,
            }
        else:
            override_text = override_config.get("confirmation_text", "I confirm I am authorized to test {target}").replace("{target}", target)
            return {
                "authorized": False,
                "auth_type": "none",
                "reason": "Target not in authorized list. Override requires confirmation.",
                "requires_override": True,
                "override_text": override_text,
            }

    return {
        "authorized": False,
        "auth_type": "none",
        "reason": "Target not in authorized list and override is disabled.",
        "requires_override": False,
    }


def add_target(domain: str, auth_type: str, notes: str = "") -> Dict[str, Any]:
    """Add a target to the authorized list."""
    config = _load_config()
    domain = _extract_domain(domain)

    # Check if already exists
    for t in config.get("targets", []):
        if _match_domain(domain, t.get("domain", "")):
            t["type"] = auth_type
            t["notes"] = notes
            t["updated_at"] = datetime.now(timezone.utc).isoformat()
            AUTH_FILE.write_text(json.dumps(config, indent=2))
            return {"added": False, "updated": True, "target": t}

    new_target = {
        "domain": domain,
        "type": auth_type,
        "notes": notes,
        "added_at": datetime.now(timezone.utc).isoformat(),
    }
    config.setdefault("targets", []).append(new_target)
    AUTH_FILE.write_text(json.dumps(config, indent=2))
    return {"added": True, "updated": False, "target": new_target}


def remove_target(domain: str) -> Dict[str, Any]:
    """Remove a target from the authorized list."""
    config = _load_config()
    domain = _extract_domain(domain)

    original_count = len(config.get("targets", []))
    config["targets"] = [t for t in config.get("targets", []) if not _match_domain(domain, t.get("domain", ""))]

    if len(config["targets"]) < original_count:
        AUTH_FILE.write_text(json.dumps(config, indent=2))
        return {"removed": True, "domain": domain}
    return {"removed": False, "domain": domain, "reason": "not found"}


def list_targets() -> Dict[str, Any]:
    """List all authorized targets."""
    config = _load_config()
    return {
        "lab_mode": config.get("lab_mode", False),
        "allow_ctf": config.get("allow_ctf", False),
        "allow_bug_bounty": config.get("allow_bug_bounty", False),
        "targets": config.get("targets", []),
        "bug_bounty_platforms": config.get("bug_bounty_platforms", []),
        "override": config.get("override", {}),
    }


def import_bug_bounty_scope(platform: str, scope_data: list) -> Dict[str, Any]:
    """Import bug bounty scope from a platform (HackerOne, Bugcrowd, etc.)."""
    config = _load_config()
    added = 0
    skipped = 0

    for item in scope_data:
        domain = item.get("domain") or item.get("target") or item.get("asset")
        if not domain:
            skipped += 1
            continue

        # Check if already authorized
        already = False
        for t in config.get("targets", []):
            if _match_domain(_extract_domain(domain), t.get("domain", "")):
                already = True
                skipped += 1
                break

        if not already:
            config.setdefault("targets", []).append({
                "domain": _extract_domain(domain),
                "type": "bug-bounty",
                "notes": f"Imported from {platform}: {item.get('name', '')}",
                "added_at": datetime.now(timezone.utc).isoformat(),
            })
            added += 1

    AUTH_FILE.write_text(json.dumps(config, indent=2))
    return {"added": added, "skipped": skipped, "platform": platform}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "check":
        if not args:
            print("Usage: auth_checker.py check <target> [--override] [--confirm-text 'text']")
            sys.exit(1)
        target = args[0]
        override = "--override" in args
        confirm_text = ""
        if "--confirm-text" in args:
            idx = args.index("--confirm-text")
            if idx + 1 < len(args):
                confirm_text = args[idx + 1]
        result = check_authorization(target, override, confirm_text)
        print(json.dumps(result, indent=2))
    elif cmd == "add":
        if len(args) < 2:
            print("Usage: auth_checker.py add <domain> <type> [notes]")
            sys.exit(1)
        notes = args[2] if len(args) > 2 else ""
        print(json.dumps(add_target(args[0], args[1], notes), indent=2))
    elif cmd == "remove":
        if not args:
            print("Usage: auth_checker.py remove <domain>")
            sys.exit(1)
        print(json.dumps(remove_target(args[0]), indent=2))
    elif cmd == "list":
        print(json.dumps(list_targets(), indent=2))
    elif cmd == "import":
        if len(args) < 2:
            print("Usage: auth_checker.py import <platform> <json-file>")
            sys.exit(1)
        platform = args[0]
        scope_file = Path(args[1])
        if not scope_file.exists():
            print(json.dumps({"error": f"file not found: {scope_file}"}))
            sys.exit(1)
        scope_data = json.loads(scope_file.read_text())
        print(json.dumps(import_bug_bounty_scope(platform, scope_data), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
