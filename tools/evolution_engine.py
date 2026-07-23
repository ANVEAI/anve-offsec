#!/usr/bin/env python3
"""
Self-Evolution Engine for kali-ai.

Analyzes agent runs, identifies what works in each scenario, updates strategy memory,
and evolves agent prompts for continuous improvement.

Usage: python3 /tools/evolution_engine.py <command> [args]
"""

import json
import re
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MEMORY_DIR = Path("/work/memory")
STRATEGY_FILE = MEMORY_DIR / "strategy.json"
LESSONS_FILE = MEMORY_DIR / "lessons.jsonl"
PATTERNS_FILE = MEMORY_DIR / "patterns.json"
EVOLUTION_LOG = MEMORY_DIR / "evolution.log"
AGENTS_DIR = Path("/agents")
CONFIDENCE_THRESHOLD = 0.7
AUTO_PROMPT_UPDATE_THRESHOLD = 0.85


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default if default is not None else {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return default if default is not None else {}


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _log(message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    with EVOLUTION_LOG.open("a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(message)


def _read_lessons(limit: int = 1000) -> List[Dict[str, Any]]:
    if not LESSONS_FILE.exists():
        return []
    lessons = []
    try:
        content = LESSONS_FILE.read_text(encoding="utf-8", errors="replace")
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


def _extract_scenario(lesson: Dict[str, Any]) -> str:
    """Extract a scenario key from a lesson (target_type:vuln_class or target_type:service)."""
    task = lesson.get("task", "").lower()
    agent = lesson.get("agent", "").lower()

    # Web app scenarios
    if any(x in task for x in ["sql", "sqli", "injection"]):
        return "web-app:sql-injection"
    if any(x in task for x in ["xss", "cross-site scripting"]):
        return "web-app:xss"
    if any(x in task for x in ["csrf", "xsrf"]):
        return "web-app:csrf"
    if any(x in task for x in ["lfi", "rfi", "file inclusion"]):
        return "web-app:lfi"
    if any(x in task for x in ["upload", "file upload"]):
        return "web-app:file-upload"
    if any(x in task for x in ["command injection", "rce", "remote code"]):
        return "web-app:command-injection"
    if any(x in task for x in ["ssrf", "server-side request"]):
        return "web-app:ssrf"
    if any(x in task for x in ["xxe", "xml external"]):
        return "web-app:xxe"
    if any(x in task for x in ["ssti", "template injection"]):
        return "web-app:ssti"
    if any(x in task for x in ["jwt", "json web token"]):
        return "web-app:jwt"
    if any(x in task for x in ["idor", "insecure direct object"]):
        return "web-app:idor"
    if any(x in task for x in ["access control", "authorization", "privilege"]):
        return "web-app:access-control"
    if any(x in task for x in ["misconfig", "security header", "cors", "csp", "hsts", "x-frame"]):
        return "web-app:misconfig"
    if any(x in task for x in ["auth", "login", "password", "session", "cookie", "mfa"]):
        return "web-app:auth"
    if any(x in task for x in ["crypto", "tls", "ssl", "certificate", "encryption"]):
        return "web-app:crypto"
    if any(x in task for x in ["component", "outdated", "cve", "vulnerable"]):
        return "web-app:components"
    if any(x in task for x in ["logging", "monitoring", "audit"]):
        return "web-app:logging"

    # Network scenarios
    if any(x in task for x in ["smb", "samba", "netbios", "445", "139"]):
        return "network:smb"
    if any(x in task for x in ["ldap", "active directory", "kerberos", "88", "389"]):
        return "network:ad"
    if any(x in task for x in ["rdp", "3389"]):
        return "network:rdp"
    if any(x in task for x in ["ssh", "22"]):
        return "network:ssh"
    if any(x in task for x in ["ftp", "21"]):
        return "network:ftp"
    if any(x in task for x in ["snmp", "161"]):
        return "network:snmp"
    if any(x in task for x in ["dns", "53"]):
        return "network:dns"

    # Agent-based fallback
    if "mitre/" in agent:
        return f"mitre:{agent.split('/')[-1]}"
    if "owasp/" in agent:
        return f"owasp:{agent.split('/')[-1]}"
    if "research/" in agent:
        return f"research:{agent.split('/')[-1]}"

    # Default
    if "web" in task or "http" in task or "url" in task:
        return "web-app:general"
    if "scan" in task or "port" in task or "host" in task:
        return "network:general"
    return f"general:{agent or 'unknown'}"


def _extract_tools(lesson: Dict[str, Any]) -> List[str]:
    """Extract tools used from a lesson."""
    tools = lesson.get("tools_used", [])
    if isinstance(tools, str):
        tools = [t.strip() for t in tools.split(",") if t.strip()]
    return list(dict.fromkeys(tools))  # dedupe preserving order


def _update_scenario_stats(scenario: Dict[str, Any], lesson: Dict[str, Any], success: bool) -> None:
    """Update scenario statistics with a new data point."""
    scenario["run_count"] = scenario.get("run_count", 0) + 1
    if success:
        scenario["success_count"] = scenario.get("success_count", 0) + 1
    else:
        scenario["failed_count"] = scenario.get("failed_count", 0) + 1

    # Update tools effectiveness
    tools = _extract_tools(lesson)
    if "tool_effectiveness" not in scenario:
        scenario["tool_effectiveness"] = {}
    for tool in tools:
        if tool not in scenario["tool_effectiveness"]:
            scenario["tool_effectiveness"][tool] = {"success": 0, "failed": 0}
        if success:
            scenario["tool_effectiveness"][tool]["success"] += 1
        else:
            scenario["tool_effectiveness"][tool]["failed"] += 1

    # Update success rate
    total = scenario["run_count"]
    if total > 0:
        scenario["success_rate"] = round(scenario["success_count"] / total, 3)

    # Update confidence (based on run count and success rate)
    confidence = min(0.5 + (total / 20) + (scenario["success_rate"] / 2), 1.0)
    scenario["confidence"] = round(confidence, 3)

    # Update last_updated
    scenario["last_updated"] = datetime.now(timezone.utc).isoformat()

    # Add evidence path
    evidence = lesson.get("evidence_paths", [])
    if isinstance(evidence, str):
        evidence = [e.strip() for e in evidence.split(",") if e.strip()]
    if "evidence" not in scenario:
        scenario["evidence"] = []
    for e in evidence[:3]:
        if e not in scenario["evidence"]:
            scenario["evidence"].append(e)


def _update_target_profile(profile: Dict[str, Any], lesson: Dict[str, Any], success: bool) -> None:
    """Update target profile with new information."""
    task = lesson.get("task", "").lower()
    agent = lesson.get("agent", "").lower()

    # Extract technologies
    if "technologies" not in profile:
        profile["technologies"] = []
    for tech in ["php", "apache", "nginx", "iis", "mysql", "postgres", "mongodb", "redis", "node", "python", "java", "dotnet", "wordpress", "joomla", "drupal", "laravel", "django", "flask", "express", "spring", "rails"]:
        if tech in task and tech not in profile["technologies"]:
            profile["technologies"].append(tech)

    # Extract vuln classes
    if "vuln_classes" not in profile:
        profile["vuln_classes"] = []
    vuln_classes = {
        "sql-injection": ["sql", "sqli"],
        "xss": ["xss", "cross-site scripting"],
        "csrf": ["csrf", "xsrf"],
        "lfi": ["lfi", "file inclusion"],
        "file-upload": ["upload", "file upload"],
        "command-injection": ["command injection", "rce"],
        "ssrf": ["ssrf", "server-side request"],
        "xxe": ["xxe", "xml external"],
        "ssti": ["ssti", "template injection"],
        "jwt": ["jwt", "json web token"],
        "idor": ["idor", "insecure direct object"],
        "access-control": ["access control", "authorization", "privilege"],
        "misconfig": ["misconfig", "security header", "cors", "csp", "hsts", "x-frame"],
        "auth": ["auth", "login", "password", "session", "cookie", "mfa"],
        "crypto": ["crypto", "tls", "ssl", "certificate", "encryption"],
        "components": ["component", "outdated", "cve", "vulnerable"],
        "logging": ["logging", "monitoring", "audit"],
        "smb": ["smb", "samba", "netbios"],
        "ad": ["ldap", "active directory", "kerberos"],
        "rdp": ["rdp", "3389"],
        "ssh": ["ssh", "22"],
        "ftp": ["ftp", "21"],
        "snmp": ["snmp", "161"],
        "dns": ["dns", "53"],
    }
    for vuln, keywords in vuln_classes.items():
        if any(k in task for k in keywords) and vuln not in profile["vuln_classes"]:
            profile["vuln_classes"].append(vuln)

    # Update best agents
    if "best_agents" not in profile:
        profile["best_agents"] = {}
    if agent not in profile["best_agents"]:
        profile["best_agents"][agent] = {"success": 0, "failed": 0}
    if success:
        profile["best_agents"][agent]["success"] += 1
    else:
        profile["best_agents"][agent]["failed"] += 1

    # Update success rate
    if "run_count" not in profile:
        profile["run_count"] = 0
        profile["success_count"] = 0
    profile["run_count"] += 1
    if success:
        profile["success_count"] += 1
    if profile["run_count"] > 0:
        profile["success_rate"] = round(profile["success_count"] / profile["run_count"], 3)


def _update_next_steps(next_steps: Dict[str, List[str]], scenario: str, agent: str, success: bool) -> None:
    """Update next-step suggestions based on what worked."""
    if not success:
        return

    # Map scenarios to suggested next agents
    suggestions = {
        "web-app:sql-injection": ["owasp/injection", "exploit", "report"],
        "web-app:xss": ["owasp/injection", "exploit", "report"],
        "web-app:csrf": ["owasp/injection", "exploit", "report"],
        "web-app:lfi": ["owasp/injection", "exploit", "report"],
        "web-app:file-upload": ["owasp/injection", "exploit", "report"],
        "web-app:command-injection": ["owasp/injection", "exploit", "report"],
        "web-app:ssrf": ["owasp/ssrf", "exploit", "report"],
        "web-app:xxe": ["owasp/injection", "exploit", "report"],
        "web-app:ssti": ["owasp/injection", "exploit", "report"],
        "web-app:jwt": ["owasp/auth", "exploit", "report"],
        "web-app:idor": ["owasp/access-control", "exploit", "report"],
        "web-app:access-control": ["owasp/access-control", "exploit", "report"],
        "web-app:misconfig": ["owasp/misconfig", "owasp/access-control", "report"],
        "web-app:auth": ["owasp/auth", "exploit", "report"],
        "web-app:crypto": ["owasp/crypto", "report"],
        "web-app:components": ["owasp/components", "research/cve-lookup", "report"],
        "web-app:logging": ["owasp/logging", "report"],
        "network:smb": ["ad", "mitre/credential-access", "mitre/lateral-movement"],
        "network:ad": ["ad", "mitre/credential-access", "mitre/lateral-movement"],
        "network:rdp": ["ad", "mitre/lateral-movement", "mitre/credential-access"],
        "network:ssh": ["mitre/initial-access", "mitre/execution", "mitre/persistence"],
        "network:ftp": ["mitre/initial-access", "mitre/execution", "mitre/persistence"],
        "network:snmp": ["mitre/discovery", "mitre/credential-access", "report"],
        "network:dns": ["mitre/discovery", "research/osint", "report"],
        "web-app:general": ["web", "owasp/misconfig", "owasp/injection"],
        "network:general": ["recon", "mitre/discovery", "report"],
    }

    if scenario not in next_steps:
        next_steps[scenario] = []
    for agent_suggestion in suggestions.get(scenario, []):
        if agent_suggestion not in next_steps[scenario]:
            next_steps[scenario].append(agent_suggestion)


def _generate_strategy_guidance(scenario: str, scenario_data: Dict[str, Any]) -> str:
    """Generate strategy guidance text for a scenario."""
    if not scenario_data or scenario_data.get("confidence", 0) < CONFIDENCE_THRESHOLD:
        return ""

    tools = scenario_data.get("tool_effectiveness", {})
    sorted_tools = sorted(tools.items(), key=lambda x: x[1].get("success", 0), reverse=True)
    best_tools = [t for t, _ in sorted_tools[:5]]

    lines = [
        f"## STRATEGY GUIDANCE (from self-evolution memory)",
        f"Scenario: {scenario} (based on {scenario_data.get('run_count', 0)} past runs, confidence: {scenario_data.get('confidence', 0):.2f})",
        f"- Success rate: {scenario_data.get('success_rate', 0):.1%}",
        f"- Best tools: {', '.join(best_tools) if best_tools else 'unknown'}",
    ]

    if scenario_data.get("common_failures"):
        lines.append(f"- Common pitfalls: {', '.join(scenario_data['common_failures'][:3])}")

    lines.append("- Adapt your approach based on this guidance; do not repeat past mistakes.")
    return "\n".join(lines)


def _should_update_prompt(scenario_data: Dict[str, Any]) -> bool:
    """Check if the prompt should be updated based on strategy confidence."""
    return scenario_data.get("confidence", 0) >= AUTO_PROMPT_UPDATE_THRESHOLD and scenario_data.get("run_count", 0) >= 5


def _update_agent_prompt(agent: str, scenario: str, guidance: str) -> bool:
    """Update an agent prompt with strategy guidance if confidence is high enough."""
    prompt_file = AGENTS_DIR / f"{agent}.prompt"
    if not prompt_file.exists():
        return False

    content = prompt_file.read_text()
    marker = "## STRATEGY GUIDANCE (from self-evolution memory)"

    if marker in content:
        # Update existing guidance
        parts = content.split(marker)
        new_content = parts[0].rstrip() + "\n\n" + guidance
    else:
        # Append new guidance
        new_content = content.rstrip() + "\n\n" + guidance

    # Backup before updating
    backup_file = prompt_file.with_suffix(".prompt.bak")
    backup_file.write_text(content)

    prompt_file.write_text(new_content)
    _log(f"Updated prompt for {agent} with {scenario} guidance")
    return True


def evolve_post_run(lesson: Dict[str, Any]) -> Dict[str, Any]:
    """Run the post-run evolution loop after a single agent run."""
    strategy = _load_json(STRATEGY_FILE, {"scenarios": {}, "target_profiles": {}, "tool_effectiveness": {}, "next_step_suggestions": {}})

    agent = lesson.get("agent", "")
    task = lesson.get("task", "")
    success = lesson.get("status") == "done"
    scenario = _extract_scenario(lesson)
    target = _extract_target(task)

    # Update scenario stats
    if scenario not in strategy["scenarios"]:
        strategy["scenarios"][scenario] = {
            "target_type": scenario.split(":")[0],
            "vuln_class": scenario.split(":")[-1],
            "tools": [],
            "techniques": [],
            "success_rate": 0,
            "run_count": 0,
            "success_count": 0,
            "failed_count": 0,
            "confidence": 0,
            "evidence": [],
        }
    _update_scenario_stats(strategy["scenarios"][scenario], lesson, success)

    # Update target profile
    if target and target != "unknown":
        if target not in strategy["target_profiles"]:
            strategy["target_profiles"][target] = {"run_count": 0, "success_count": 0, "success_rate": 0, "technologies": [], "vuln_classes": [], "best_agents": {}}
        _update_target_profile(strategy["target_profiles"][target], lesson, success)

    # Update next steps
    _update_next_steps(strategy["next_step_suggestions"], scenario, agent, success)

    # Update global tool effectiveness
    tools = _extract_tools(lesson)
    for tool in tools:
        if tool not in strategy["tool_effectiveness"]:
            strategy["tool_effectiveness"][tool] = {"success": 0, "failed": 0, "avg_time": 0}
        if success:
            strategy["tool_effectiveness"][tool]["success"] += 1
        else:
            strategy["tool_effectiveness"][tool]["failed"] += 1

    # Check if prompt should be updated
    scenario_data = strategy["scenarios"][scenario]
    guidance = _generate_strategy_guidance(scenario, scenario_data)
    prompt_updated = False
    if guidance and _should_update_prompt(scenario_data):
        prompt_updated = _update_agent_prompt(agent, scenario, guidance)

    _save_json(STRATEGY_FILE, strategy)

    result = {
        "scenario": scenario,
        "target": target,
        "success": success,
        "strategy_updated": True,
        "prompt_updated": prompt_updated,
        "confidence": scenario_data.get("confidence", 0),
        "success_rate": scenario_data.get("success_rate", 0),
    }
    _log(f"Post-run evolution: {result}")
    return result


def evolve_deep_review() -> Dict[str, Any]:
    """Run the periodic deep review evolution loop."""
    lessons = _read_lessons(2000)
    strategy = _load_json(STRATEGY_FILE, {"scenarios": {}, "target_profiles": {}, "tool_effectiveness": {}, "next_step_suggestions": {}})

    # Rebuild strategy from all lessons
    for lesson in lessons:
        agent = lesson.get("agent", "")
        success = lesson.get("status") == "done"
        scenario = _extract_scenario(lesson)
        target = _extract_target(lesson.get("task", ""))

        if scenario not in strategy["scenarios"]:
            strategy["scenarios"][scenario] = {
                "target_type": scenario.split(":")[0],
                "vuln_class": scenario.split(":")[-1],
                "tools": [],
                "techniques": [],
                "success_rate": 0,
                "run_count": 0,
                "success_count": 0,
                "failed_count": 0,
                "confidence": 0,
                "evidence": [],
            }
        _update_scenario_stats(strategy["scenarios"][scenario], lesson, success)

        if target and target != "unknown":
            if target not in strategy["target_profiles"]:
                strategy["target_profiles"][target] = {"run_count": 0, "success_count": 0, "success_rate": 0, "technologies": [], "vuln_classes": [], "best_agents": {}}
            _update_target_profile(strategy["target_profiles"][target], lesson, success)

        _update_next_steps(strategy["next_step_suggestions"], scenario, agent, success)

    # Update prompts for high-confidence scenarios
    prompts_updated = 0
    for scenario, data in strategy["scenarios"].items():
        if _should_update_prompt(data):
            agent = _agent_for_scenario(scenario)
            if agent:
                guidance = _generate_strategy_guidance(scenario, data)
                if _update_agent_prompt(agent, scenario, guidance):
                    prompts_updated += 1

    _save_json(STRATEGY_FILE, strategy)

    result = {
        "total_lessons": len(lessons),
        "scenarios": len(strategy["scenarios"]),
        "targets": len(strategy["target_profiles"]),
        "prompts_updated": prompts_updated,
        "high_confidence_scenarios": len([s for s in strategy["scenarios"].values() if s.get("confidence", 0) >= CONFIDENCE_THRESHOLD]),
    }
    _log(f"Deep review evolution: {result}")
    return result


def _extract_target(task: str) -> str:
    """Extract target from task description."""
    # Look for URLs, IPs, domains
    url_match = re.search(r"https?://([^\s/]+)", task)
    if url_match:
        return url_match.group(1).lower()
    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", task)
    if ip_match:
        return ip_match.group(1)
    domain_match = re.search(r"\b([a-z0-9-]+\.[a-z]{2,})\b", task.lower())
    if domain_match:
        return domain_match.group(1)
    return "unknown"


def _agent_for_scenario(scenario: str) -> Optional[str]:
    """Map scenario to agent path."""
    mapping = {
        "web-app:sql-injection": "owasp/injection",
        "web-app:xss": "owasp/injection",
        "web-app:csrf": "owasp/injection",
        "web-app:lfi": "owasp/injection",
        "web-app:file-upload": "owasp/injection",
        "web-app:command-injection": "owasp/injection",
        "web-app:ssrf": "owasp/ssrf",
        "web-app:xxe": "owasp/injection",
        "web-app:ssti": "owasp/injection",
        "web-app:jwt": "owasp/auth",
        "web-app:idor": "owasp/access-control",
        "web-app:access-control": "owasp/access-control",
        "web-app:misconfig": "owasp/misconfig",
        "web-app:auth": "owasp/auth",
        "web-app:crypto": "owasp/crypto",
        "web-app:components": "owasp/components",
        "web-app:logging": "owasp/logging",
        "network:smb": "ad",
        "network:ad": "ad",
        "network:rdp": "ad",
        "network:ssh": "mitre/initial-access",
        "network:ftp": "mitre/initial-access",
        "network:snmp": "mitre/discovery",
        "network:dns": "mitre/discovery",
        "web-app:general": "web",
        "network:general": "recon",
    }
    return mapping.get(scenario)


def get_strategy_guidance(task: str, agent: str = "") -> str:
    """Get strategy guidance for a task/agent before launching a run."""
    strategy = _load_json(STRATEGY_FILE, {"scenarios": {}, "next_step_suggestions": {}})

    # Create a fake lesson to extract scenario
    fake_lesson = {"task": task, "agent": agent, "status": "unknown"}
    scenario = _extract_scenario(fake_lesson)

    scenario_data = strategy["scenarios"].get(scenario, {})
    guidance = _generate_strategy_guidance(scenario, scenario_data)

    # Add next-step suggestions
    next_steps = strategy["next_step_suggestions"].get(scenario, [])
    if next_steps:
        guidance += f"\n- Suggested next steps after this run: {', '.join(next_steps)}"

    return guidance


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "post-run":
        if not args:
            print("Usage: evolution_engine.py post-run <lesson-json>")
            sys.exit(1)
        lesson = json.loads(args[0])
        print(json.dumps(evolve_post_run(lesson), indent=2))
    elif cmd == "deep-review":
        print(json.dumps(evolve_deep_review(), indent=2))
    elif cmd == "guidance":
        if not args:
            print("Usage: evolution_engine.py guidance <task> [agent]")
            sys.exit(1)
        agent = args[1] if len(args) > 1 else ""
        print(get_strategy_guidance(args[0], agent))
    elif cmd == "strategy":
        print(json.dumps(_load_json(STRATEGY_FILE), indent=2))
    elif cmd == "scenario":
        if not args:
            print("Usage: evolution_engine.py scenario <task> [agent]")
            sys.exit(1)
        agent = args[1] if len(args) > 1 else ""
        print(_extract_scenario({"task": args[0], "agent": agent, "status": "unknown"}))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
