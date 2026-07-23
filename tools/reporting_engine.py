#!/usr/bin/env python3
"""
Reporting engine for kali-ai.

Generates business-grade reports with executive summary, threat model, findings, attack chains, risk assessment, and recommendations.
Includes CVSS 4.0 scoring, business impact ratings, and prioritized remediation.

Usage: python3 /tools/reporting_engine.py <command> [args]
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
REPORTS_DIR = WORK_DIR / "reports"

CVSS_4_0_SEVERITY = {
    "critical": {"score": "9.0-10.0", "description": "Direct or indirect exploitation leads to full compromise of the affected system, with high impact on confidentiality, integrity, and availability."},
    "high": {"score": "7.0-8.9", "description": "Exploitation leads to significant impact on confidentiality, integrity, or availability of the affected system."},
    "medium": {"score": "4.0-6.9", "description": "Exploitation leads to limited impact on confidentiality, integrity, or availability of the affected system."},
    "low": {"score": "0.1-3.9", "description": "Exploitation leads to minimal impact on confidentiality, integrity, or availability of the affected system."},
    "info": {"score": "0.0", "description": "No direct impact on confidentiality, integrity, or availability of the affected system."},
}


def _ensure_dir() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _cvss_score(severity: str) -> str:
    """Get CVSS 4.0 score range for a severity."""
    return CVSS_4_0_SEVERITY.get(severity, CVSS_4_0_SEVERITY["info"])["score"]


def _business_impact(severity: str, impact: str) -> str:
    """Get business impact rating for a severity and impact."""
    impacts = {
        "critical": "Critical — Full compromise of the affected system, with severe financial, reputational, regulatory, and operational impact.",
        "high": "High — Significant compromise of the affected system, with substantial financial, reputational, and operational impact.",
        "medium": "Medium — Limited compromise of the affected system, with moderate financial, reputational, and operational impact.",
        "low": "Low — Minimal compromise of the affected system, with minor financial, reputational, and operational impact.",
        "info": "Informational — No direct compromise, but potential for future exploitation if not addressed.",
    }
    return impacts.get(severity, impacts["info"])


def generate_report(
    target: str,
    findings: List[Dict[str, Any]],
    chains: List[Dict[str, Any]],
    threat_model: Dict[str, Any],
    methodology: Optional[str] = None,
    evidence_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Generate a business-grade report."""
    _ensure_dir()

    report_id = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    safe_target = re.sub(r"[^A-Za-z0-9_-]+", "_", target).strip("_") or "target"
    report_file = REPORTS_DIR / f"{safe_target}_bug_bounty_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"

    # Calculate overall risk rating
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    if severity_counts["critical"] > 0:
        overall_risk = "critical"
    elif severity_counts["high"] > 0:
        overall_risk = "high"
    elif severity_counts["medium"] > 0:
        overall_risk = "medium"
    elif severity_counts["low"] > 0:
        overall_risk = "low"
    else:
        overall_risk = "info"

    # Build report
    report_lines = [
        f"# Bug Bounty Report: {target}",
        f"**Report ID**: {report_id}",
        f"**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Target**: {target}",
        f"**Overall Risk Rating**: {overall_risk.upper()}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"This report documents the findings of a security assessment conducted against **{target}**. The assessment identified **{len(findings)} vulnerabilities** across **{len(chains)} attack chains**, with an overall risk rating of **{overall_risk.upper()}**.",
        "",
        f"**Key Findings**:",
        f"- **Critical**: {severity_counts['critical']} vulnerabilities",
        f"- **High**: {severity_counts['high']} vulnerabilities",
        f"- **Medium**: {severity_counts['medium']} vulnerabilities",
        f"- **Low**: {severity_counts['low']} vulnerabilities",
        f"- **Informational**: {severity_counts['info']} findings",
        "",
        "**Immediate Actions Required**:",
    ]

    # Add critical and high findings as immediate actions
    immediate_actions = [f for f in findings if f.get("severity", "").lower() in ["critical", "high"]]
    if immediate_actions:
        for i, action in enumerate(immediate_actions[:5], 1):
            report_lines.append(f"{i}. **{action.get('title', 'Unknown')}** — {action.get('remediation', 'No remediation provided')}")
    else:
        report_lines.append("No critical or high severity vulnerabilities identified.")

    report_lines.extend([
        "",
        "---",
        "",
        "## Scope and Methodology",
        "",
        f"**Target**: {target}",
        f"**Assessment Type**: Bug Bounty / Web Application Security Assessment",
        f"**Methodology**: {methodology or 'OWASP Testing Guide, PTES, and custom automated + manual testing'}",
        f"**Evidence Paths**: {', '.join(evidence_paths or ['/work/loot/'])}",
        "",
        "**Testing Phases**:",
        "1. **Reconnaissance**: Passive and active information gathering",
        "2. **Scanning & Enumeration**: Port scanning, service detection, web path discovery",
        "3. **Vulnerability Analysis**: SQLi, XSS, CSRF, SSRF, LFI, IDOR, auth bypass, and more",
        "4. **Exploitation**: Controlled proof-of-concept exploitation with custom exploits when needed",
        "5. **Post-Exploitation**: Privilege escalation, lateral movement, persistence (where authorized)",
        "6. **Reporting**: Business-grade findings with evidence, impact, and remediation",
        "",
        "---",
        "",
        "## Threat Model",
        "",
        f"**Target Type**: {threat_model.get('target_type', 'web')}",
        f"**High-Value Assets**: {', '.join(threat_model.get('high_value_assets', []))}",
        f"**Trust Boundaries**: {', '.join(threat_model.get('trust_boundaries', []))}",
        f"**Attacker Goals**: {', '.join(threat_model.get('attacker_goals', []))}",
        "",
        "**Attack Paths**:",
    ])

    for chain in chains:
        report_lines.append(f"- **{chain.get('name', 'Unknown')}** ({chain.get('severity', 'unknown')})")

    report_lines.extend([
        "",
        "---",
        "",
        "## Findings",
        "",
    ])

    # Add findings
    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "info").lower()
        report_lines.extend([
            f"### {i}. {finding.get('title', 'Unknown Vulnerability')}",
            f"**Severity**: {severity.upper()} (CVSS 4.0: {_cvss_score(severity)})",
            f"**Business Impact**: {_business_impact(severity, finding.get('impact', ''))}",
            "",
            f"**Description**: {finding.get('description', 'No description provided.')}",
            "",
            "**Evidence**:",
        ])

        for evidence in finding.get("evidence", []):
            report_lines.append(f"- `{evidence}`")

        report_lines.extend([
            "",
            f"**Impact**: {finding.get('impact', 'No impact assessment provided.')}",
            "",
            f"**Business Risk**: {finding.get('business_risk', 'No business risk assessment provided.')}",
            "",
            f"**Remediation**: {finding.get('remediation', 'No remediation provided.')}",
            "",
            f"**References**: {', '.join(finding.get('references', ['No references provided.']))}",
            "",
            "---",
            "",
        ])

    # Add attack chains
    if chains:
        report_lines.extend([
            "## Attack Chains",
            "",
        ])

        for chain in chains:
            report_lines.extend([
                f"### {chain.get('name', 'Unknown Chain')}",
                f"**Severity**: {chain.get('severity', 'unknown').upper()}",
                f"**Confidence**: {chain.get('confidence', 0):.1%}",
                "",
                f"**Description**: {chain.get('description', 'No description provided.')}",
                "",
                "**Entry Points**:",
            ])

            for ep in chain.get("entry_points", []):
                report_lines.append(f"- {ep}")

            report_lines.extend([
                "",
                "**Pivot Points**:",
            ])

            for pp in chain.get("pivot_points", []):
                report_lines.append(f"- {pp}")

            report_lines.extend([
                "",
                f"**Final Impact**: {chain.get('final_impact', 'No impact assessment provided.')}",
                "",
                f"**Business Risk**: {chain.get('business_risk', 'No business risk assessment provided.')}",
                "",
                "---",
                "",
            ])

    # Add risk assessment
    report_lines.extend([
        "## Risk Assessment",
        "",
        f"**Overall Risk Rating**: {overall_risk.upper()}",
        "",
        f"The overall risk rating of **{overall_risk.upper()}** is based on the presence of **{severity_counts['critical']} critical**, **{severity_counts['high']} high**, **{severity_counts['medium']} medium**, and **{severity_counts['low']} low** severity vulnerabilities, as well as **{len(chains)} identified attack chains** that could lead to full compromise of the target.",
        "",
        "**Justification**:",
    ])

    if overall_risk == "critical":
        report_lines.append("- **Critical**: Immediate exploitation could lead to full system compromise, data breach, and severe business impact.")
    elif overall_risk == "high":
        report_lines.append("- **High**: Exploitation could lead to significant system compromise and substantial business impact.")
    elif overall_risk == "medium":
        report_lines.append("- **Medium**: Exploitation could lead to limited system compromise and moderate business impact.")
    elif overall_risk == "low":
        report_lines.append("- **Low**: Exploitation could lead to minimal system compromise and minor business impact.")
    else:
        report_lines.append("- **Informational**: No immediate risk, but potential for future exploitation if not addressed.")

    report_lines.extend([
        "",
        "---",
        "",
        "## Recommendations",
        "",
        "### Quick Wins (Implement within 1 week)",
        "",
    ])

    # Add quick wins
    quick_wins = [f for f in findings if f.get("severity", "").lower() in ["critical", "high"]]
    if quick_wins:
        for i, win in enumerate(quick_wins[:5], 1):
            report_lines.append(f"{i}. **{win.get('title', 'Unknown')}** — {win.get('remediation', 'No remediation provided')}")
    else:
        report_lines.append("No critical or high severity vulnerabilities identified.")

    report_lines.extend([
        "",
        "### Long-Term Fixes (Implement within 1-3 months)",
        "",
        "1. **Implement a Web Application Firewall (WAF)** to protect against common web attacks.",
        "2. **Conduct regular security assessments** (quarterly) to identify and address new vulnerabilities.",
        "3. **Implement security headers** (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) to protect against client-side attacks.",
        "4. **Enforce strong authentication** (MFA) for all user accounts, especially admin accounts.",
        "5. **Implement rate limiting and account lockout** to protect against brute force attacks.",
        "6. **Conduct security training** for developers on secure coding practices.",
        "7. **Implement a vulnerability management program** to track and remediate vulnerabilities.",
        "8. **Conduct penetration testing** (annually) to identify and address complex vulnerabilities.",
        "",
        "---",
        "",
        "## Appendices",
        "",
        "### Appendix A: Raw Evidence",
        "",
    ])

    # Add evidence paths
    if evidence_paths:
        for path in evidence_paths:
            report_lines.append(f"- `{path}`")
    else:
        report_lines.append("- No raw evidence paths provided.")

    report_lines.extend([
        "",
        "### Appendix B: Tool Outputs",
        "",
        "- Tool outputs are available in the evidence directories listed in Appendix A.",
        "",
        "### Appendix C: Methodology Details",
        "",
        f"{methodology or 'OWASP Testing Guide, PTES, and custom automated + manual testing'}",
        "",
        "---",
        "",
        f"*Report generated by kali-ai on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*",
    ])

    # Write report
    report_content = "\n".join(report_lines)
    report_file.write_text(report_content)

    # Build JSON summary
    summary = {
        "report_id": report_id,
        "target": target,
        "date": datetime.now(timezone.utc).isoformat(),
        "overall_risk": overall_risk,
        "severity_counts": severity_counts,
        "findings_count": len(findings),
        "chains_count": len(chains),
        "report_file": str(report_file),
        "report_content": report_content,
    }

    return summary


def _load_arg(arg: str, list_key: Optional[str] = None) -> Any:
    """Load a JSON argument from a string or file path; unwrap a dict's list_key when given."""
    if os.path.isfile(arg):
        arg = Path(arg).read_text()
    data = json.loads(arg)
    if list_key and isinstance(data, dict):
        data = data.get(list_key, [])
    return data


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "generate":
        if len(args) < 4:
            print("Usage: reporting_engine.py generate <target> <findings-json> <chains-json> <threat-model-json> [methodology] [evidence-paths]")
            sys.exit(1)
        methodology = args[4] if len(args) > 4 else None
        evidence_paths = args[5].split(",") if len(args) > 5 else None
        print(json.dumps(generate_report(
            args[0],
            _load_arg(args[1], "findings"),
            _load_arg(args[2], "chains"),
            _load_arg(args[3]),
            methodology,
            evidence_paths,
        ), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
