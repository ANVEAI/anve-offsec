#!/usr/bin/env python3
"""
Bounty report generator for kali-ai (Phase 8 — payout-grade submissions).

Converts /work/loot/<target>/findings.jsonl (+ optional chains.json) into
HackerOne/Bugcrowd-ready markdown submissions, one file per finding, with
CVSS 4.0 vectors, CWE mappings, reproduction steps, impact, and remediation.
Also de-duplicates repeated findings and emits an executive one-pager.

Usage: python3 /tools/bounty_report.py <command> [args]

Commands:
  submissions <target>   Emit platform-ready markdown per finding.
  dedupe <target>        Collapse duplicate findings (same type+endpoint).
  summary <target>       Executive one-pager (SUMMARY.md).
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

WORK_DIR = Path(os.environ.get("KALI_WORK_DIR") or ("/work" if Path("/work").exists() else "work"))
LOOT_DIR = WORK_DIR / "loot"
REPORTS_DIR = WORK_DIR / "reports"

# ---------------------------------------------------------------------------
# OPERATOR-EDITABLE MAPPING TABLES — tune to your program's taxonomy.
# ---------------------------------------------------------------------------

# Normalize noisy finding "type" strings to a canonical key.
TYPE_ALIASES: Dict[str, str] = {
    "sql injection": "sqli", "sqli": "sqli",
    "cross-site scripting": "xss", "xss": "xss", "stored xss": "xss", "reflected xss": "xss",
    "idor": "idor", "bola": "idor", "insecure direct object reference": "idor",
    "ssrf": "ssrf", "server-side request forgery": "ssrf",
    "rce": "rce", "remote code execution": "rce", "command injection": "rce",
    "os command injection": "rce", "code injection": "rce",
    "lfi": "lfi", "local file inclusion": "lfi", "path traversal": "lfi",
    "directory traversal": "lfi", "file inclusion": "lfi", "rfi": "lfi",
    "jwt": "jwt", "json web token": "jwt",
    "xxe": "xxe", "xml external entity": "xxe",
    "mass-assignment": "mass-assignment", "mass assignment": "mass-assignment",
    "auth-bypass": "auth-bypass", "authentication bypass": "auth-bypass",
    "broken authentication": "auth-bypass", "weak credentials": "auth-bypass",
    "csrf": "csrf", "cross-site request forgery": "csrf",
    "ssti": "ssti", "template injection": "ssti",
    "open redirect": "open-redirect", "open-redirect": "open-redirect",
    "deserialization": "deserialization", "insecure deserialization": "deserialization",
    "info disclosure": "info-disclosure", "information disclosure": "info-disclosure",
    "info-disclosure": "info-disclosure",
    "misconfiguration": "misconfiguration", "misconfig": "misconfiguration",
}

TYPE_TO_CWE: Dict[str, str] = {
    "sqli": "CWE-89", "xss": "CWE-79", "idor": "CWE-639", "ssrf": "CWE-918",
    "rce": "CWE-78", "lfi": "CWE-98", "jwt": "CWE-347", "xxe": "CWE-611",
    "mass-assignment": "CWE-915", "auth-bypass": "CWE-287", "csrf": "CWE-352",
    "ssti": "CWE-1336", "open-redirect": "CWE-601", "deserialization": "CWE-502",
    "info-disclosure": "CWE-200", "misconfiguration": "CWE-16", "other": "CWE-1035",
}

CWE_NAMES: Dict[str, str] = {
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (XSS)",
    "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command",
    "CWE-98": "Improper Control of Filename for Include/Require Statement (LFI/RFI)",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-287": "Improper Authentication",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-16": "Configuration",
    "CWE-1035": "Improper Neutralization of Input (Generic Weakness)",
}

# Reasonable CVSS 4.0 base vectors per type (edit to match exact context).
TYPE_TO_CVSS_VECTOR: Dict[str, str] = {
    "sqli": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "xss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "idor": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "ssrf": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "rce": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "lfi": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "jwt": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "xxe": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N",
    "mass-assignment": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
    "auth-bypass": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "csrf": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "ssti": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "open-redirect": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "deserialization": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "info-disclosure": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "misconfiguration": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "other": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
}

# Representative CVSS 4.0 base score per severity band (operator-editable).
SEVERITY_TO_SCORE: Dict[str, float] = {
    "critical": 9.3, "high": 8.1, "medium": 6.1, "low": 3.7, "info": 0.0,
}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

TYPE_TO_IMPACT: Dict[str, str] = {
    "sqli": "An attacker can read, modify, or destroy arbitrary database records, "
            "extract credentials and PII, and in many configurations pivot to file "
            "read/write or remote code execution on the database host.",
    "xss": "An attacker can execute arbitrary JavaScript in victims' browsers to "
           "steal session tokens, perform actions as the victim, deface content, "
           "or deliver further client-side attacks.",
    "idor": "An attacker can access or modify other users' records by manipulating "
            "object identifiers, breaking tenant isolation and exposing PII.",
    "ssrf": "An attacker can coerce the server into making requests to internal "
            "services and cloud metadata endpoints, exposing secrets and enabling "
            "internal network pivoting.",
    "rce": "An attacker can execute arbitrary commands on the server, leading to "
           "full system compromise, data theft, lateral movement, and persistence.",
    "lfi": "An attacker can read arbitrary files (source, config, credentials) and, "
           "where remote inclusion or log poisoning is possible, achieve code execution.",
    "jwt": "An attacker can forge or tamper with authentication tokens to impersonate "
           "any user, including administrators, bypassing access control entirely.",
    "xxe": "An attacker can read local files, perform SSRF, and cause denial of "
           "service by abusing XML external entity processing.",
    "mass-assignment": "An attacker can set unintended object attributes (e.g. role, "
                       "is_admin, price) by injecting extra parameters, escalating "
                       "privilege or manipulating business logic.",
    "auth-bypass": "An attacker can gain authenticated access without valid "
                   "credentials, exposing all functionality and data behind the login.",
    "csrf": "An attacker can force an authenticated victim's browser to perform "
            "state-changing actions without their consent.",
    "ssti": "An attacker can inject template syntax that executes on the server, "
            "typically leading to remote code execution.",
    "open-redirect": "An attacker can craft trusted-looking links that redirect "
                     "victims to malicious sites, aiding phishing and token theft.",
    "deserialization": "An attacker can supply crafted serialized objects to execute "
                       "arbitrary code or manipulate application state.",
    "info-disclosure": "An attacker can obtain sensitive information (versions, "
                       "internal paths, credentials, PII) that aids further attacks.",
    "misconfiguration": "A security misconfiguration weakens the system's defenses "
                        "and can be chained with other issues to increase impact.",
    "other": "This issue weakens the security posture of the application and may be "
             "chained with other findings to increase impact.",
}

TYPE_TO_REMEDIATION: Dict[str, str] = {
    "sqli": "Use parameterized queries / prepared statements for all database access. "
            "Never concatenate untrusted input into SQL. Apply least-privilege DB accounts.",
    "xss": "Contextually output-encode all untrusted data, adopt a strict Content "
           "Security Policy, and set HttpOnly/SameSite on session cookies.",
    "idor": "Enforce server-side authorization on every object access; validate that "
            "the authenticated user owns or may access the requested resource.",
    "ssrf": "Validate and allowlist outbound destinations, block internal/link-local "
            "ranges and metadata endpoints, and disable unused URL schemes.",
    "rce": "Never pass untrusted input to shells or interpreters; use safe APIs with "
           "argument arrays, strict input validation, and least-privilege execution.",
    "lfi": "Avoid user-controlled include/file paths; use allowlists of permitted "
           "resources, canonicalize paths, and disable remote inclusion (allow_url_include=Off).",
    "jwt": "Enforce a fixed signing algorithm server-side, reject 'none', verify "
           "signatures with a strong secret/key, and validate all standard claims.",
    "xxe": "Disable external entity and DTD processing in all XML parsers; prefer "
           "safe parser configurations and less complex data formats.",
    "mass-assignment": "Bind only explicitly allowlisted fields; never mass-assign "
                       "request bodies directly to models. Protect sensitive attributes.",
    "auth-bypass": "Enforce authentication on every protected route, remove default/"
                   "weak credentials, and require strong, unique passwords with MFA.",
    "csrf": "Require anti-CSRF tokens on state-changing requests and enforce "
            "SameSite cookies and origin/referer checks.",
    "ssti": "Never render user input as a template; use logic-less templates or "
            "sandboxed evaluation with strict input validation.",
    "open-redirect": "Avoid user-controlled redirect targets; use allowlists or "
                     "relative-only redirects and validate destinations server-side.",
    "deserialization": "Do not deserialize untrusted data; use safe formats (JSON) "
                       "with schema validation and integrity checks.",
    "info-disclosure": "Remove or restrict access to sensitive files and verbose "
                       "errors; suppress version banners and internal path leakage.",
    "misconfiguration": "Harden configuration to secure defaults, disable unnecessary "
                        "features/listings, and keep components patched and up to date.",
    "other": "Review the affected component, apply input validation and least "
             "privilege, and align configuration with security best practices.",
}


# --- Helpers ---
def _norm_type(raw: str) -> str:
    """Normalize a finding type string to a canonical key."""
    t = (raw or "").strip().lower()
    if t in TYPE_ALIASES:
        return TYPE_ALIASES[t]
    for alias, canon in TYPE_ALIASES.items():
        if alias in t:
            return canon
    return re.sub(r"[^a-z0-9]+", "-", t).strip("-") or "other"


def _norm_sev(raw: str) -> str:
    s = (raw or "").strip().lower()
    return s if s in SEVERITY_ORDER else "info"


def _endpoint(finding: Dict[str, Any]) -> str:
    """Best-effort endpoint/path extraction from title or detail."""
    blob = f"{finding.get('title', '')} {finding.get('detail', '')}"
    m = re.search(r"(https?://[^\s'\"]+|/[\w\-./]+\.\w+|/[\w\-./]{2,})", blob)
    if m:
        return m.group(1).rstrip(".,);")
    return (finding.get("title", "") or "").strip()[:60]


def _read_findings(target: str) -> List[Dict[str, Any]]:
    fp = LOOT_DIR / target / "findings.jsonl"
    findings = []
    if not fp.exists():
        return findings
    for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            continue
    return findings


def _read_chains(target: str) -> List[Dict[str, Any]]:
    fp = LOOT_DIR / target / "chains.json"
    if not fp.exists():
        return []
    try:
        data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if isinstance(data, dict):
        return data.get("chains", []) or []
    if isinstance(data, list):
        return data
    return []


def _steps(finding: Dict[str, Any]) -> List[str]:
    """Build numbered reproduction steps from detail + evidence."""
    detail = (finding.get("detail", "") or "").strip()
    steps: List[str] = []
    # Split detail into sentence-ish steps.
    parts = re.split(r"(?<=[.;])\s+(?=[A-Z0-9])", detail)
    for p in parts:
        p = p.strip()
        if len(p) > 3:
            steps.append(p)
    if not steps and detail:
        steps.append(detail)
    ep = _endpoint(finding)
    if ep:
        steps.insert(0, f"Navigate to the affected endpoint: `{ep}`.")
    evidence = finding.get("evidence", []) or []
    if evidence:
        steps.append("Observe the captured evidence confirming the issue "
                     f"(see {', '.join('`%s`' % e for e in evidence)}).")
    return steps


def _cvss(type_key: str, severity: str) -> Dict[str, Any]:
    return {
        "vector": TYPE_TO_CVSS_VECTOR.get(type_key, TYPE_TO_CVSS_VECTOR["other"]),
        "score": SEVERITY_TO_SCORE.get(severity, 0.0),
    }


def _render_markdown(target: str, finding: Dict[str, Any]) -> str:
    fid = finding.get("id", "F-000")
    title = finding.get("title", "Untitled Finding")
    sev = _norm_sev(finding.get("severity", "info"))
    tkey = _norm_type(finding.get("type", "other"))
    cwe = TYPE_TO_CWE.get(tkey, "CWE-1035")
    cwe_name = CWE_NAMES.get(cwe, "")
    cvss = _cvss(tkey, sev)
    evidence = finding.get("evidence", []) or []

    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- **Finding ID:** {fid}")
    lines.append(f"- **Target:** {target}")
    lines.append(f"- **Vulnerability Type:** `{tkey}`")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("## Severity")
    lines.append(f"**{sev.capitalize()}** — CVSS 4.0 base score **{cvss['score']}**")
    lines.append("")
    lines.append(f"`{cvss['vector']}`")
    lines.append("")
    lines.append("## Weakness")
    lines.append(f"**{cwe}** — {cwe_name}")
    lines.append("")
    lines.append("## Summary")
    lines.append(finding.get("detail", "") or title)
    lines.append("")
    lines.append("## Steps To Reproduce")
    for i, step in enumerate(_steps(finding), 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append("## Proof of Concept")
    if evidence:
        lines.append("The following captured artifacts demonstrate the issue:")
        lines.append("")
        for e in evidence:
            lines.append(f"- `{e}`")
    else:
        lines.append("_See Steps To Reproduce; capture request/response as evidence._")
    lines.append("")
    lines.append("## Impact")
    lines.append(TYPE_TO_IMPACT.get(tkey, TYPE_TO_IMPACT["other"]))
    lines.append("")
    lines.append("## Remediation")
    lines.append(TYPE_TO_REMEDIATION.get(tkey, TYPE_TO_REMEDIATION["other"]))
    lines.append("")
    lines.append("## Supporting Evidence")
    if evidence:
        for e in evidence:
            lines.append(f"- `{e}`")
    else:
        lines.append("- _None attached._")
    lines.append("")
    return "\n".join(lines)


def submissions(target: str) -> dict:
    """Emit a platform-ready markdown file per finding."""
    findings = _read_findings(target)
    if not findings:
        return {"error": "no findings",
                "hint": f"expected /work/loot/{target}/findings.jsonl"}
    out_dir = REPORTS_DIR / target
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return {"error": f"cannot create report dir: {e}"}
    files = []
    for finding in findings:
        fid = str(finding.get("id", "") or f"F-{len(files)+1:03d}")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", fid)
        path = out_dir / f"{safe}.md"
        try:
            path.write_text(_render_markdown(target, finding), encoding="utf-8")
            files.append(str(path))
        except Exception:
            continue
    return {"target": target, "count": len(files), "files": files}


def dedupe(target: str) -> dict:
    """Collapse duplicate findings (same type+endpoint), keep highest severity."""
    findings = _read_findings(target)
    if not findings:
        return {"error": "no findings",
                "hint": f"expected /work/loot/{target}/findings.jsonl"}
    groups: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        key = f"{_norm_type(f.get('type', 'other'))}|{_endpoint(f).lower()}"
        if key not in groups:
            groups[key] = dict(f)
            groups[key]["evidence"] = list(f.get("evidence", []) or [])
            groups[key]["duplicate_ids"] = [f.get("id")]
        else:
            g = groups[key]
            g["duplicate_ids"].append(f.get("id"))
            # merge evidence (dedup)
            merged = list(dict.fromkeys((g.get("evidence") or []) + (f.get("evidence", []) or [])))
            g["evidence"] = merged
            # keep highest severity
            if SEVERITY_ORDER.get(_norm_sev(f.get("severity", "info")), 0) > \
               SEVERITY_ORDER.get(_norm_sev(g.get("severity", "info")), 0):
                g["severity"] = f.get("severity")
                g["title"] = f.get("title", g.get("title"))
                g["detail"] = f.get("detail", g.get("detail"))
    deduped = list(groups.values())
    out_fp = LOOT_DIR / target / "findings.deduped.jsonl"
    try:
        out_fp.parent.mkdir(parents=True, exist_ok=True)
        with out_fp.open("w", encoding="utf-8") as fh:
            for d in deduped:
                fh.write(json.dumps(d, ensure_ascii=False) + "\n")
    except Exception as e:
        return {"error": f"cannot write deduped file: {e}"}
    return {
        "target": target,
        "original": len(findings),
        "deduped": len(deduped),
        "removed": len(findings) - len(deduped),
        "output": str(out_fp),
    }


def summary(target: str) -> dict:
    """Write an executive one-pager SUMMARY.md."""
    findings = _read_findings(target)
    if not findings:
        return {"error": "no findings",
                "hint": f"expected /work/loot/{target}/findings.jsonl"}
    chains = _read_chains(target)
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[_norm_sev(f.get("severity", "info"))] += 1

    criticals = sorted(
        [f for f in findings if _norm_sev(f.get("severity", "info")) in ("critical", "high")],
        key=lambda f: SEVERITY_ORDER.get(_norm_sev(f.get("severity", "info")), 0),
        reverse=True,
    )[:3]

    lines: List[str] = []
    lines.append(f"# Security Assessment Summary — {target}")
    lines.append("")
    lines.append(f"_Generated: {datetime.now(timezone.utc).isoformat()}_")
    lines.append("")
    lines.append(f"**Total findings:** {len(findings)}")
    lines.append("")
    lines.append("## Findings by Severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {sev.capitalize()} | {counts.get(sev, 0)} |")
    lines.append("")
    lines.append("## Attack Chain Highlights")
    lines.append("")
    if chains:
        for c in chains[:5]:
            name = c.get("name", "Unnamed chain")
            csev = _norm_sev(c.get("severity", "info"))
            impact = c.get("final_impact", c.get("business_risk", ""))
            lines.append(f"- **{name}** ({csev}) — {impact}")
    else:
        lines.append("- _No attack chains recorded._")
    lines.append("")
    lines.append("## Top Critical Findings")
    lines.append("")
    if criticals:
        for f in criticals:
            fid = f.get("id", "")
            lines.append(f"1. **[{fid}] {f.get('title', '')}** "
                         f"({_norm_sev(f.get('severity', 'info'))})")
    else:
        lines.append("- _No critical or high findings._")
    lines.append("")

    out_dir = REPORTS_DIR / target
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_fp = out_dir / "SUMMARY.md"
        out_fp.write_text("\n".join(lines), encoding="utf-8")
    except Exception as e:
        return {"error": f"cannot write summary: {e}"}
    return {
        "target": target,
        "total": len(findings),
        "by_severity": counts,
        "chains": len(chains),
        "top_criticals": [f.get("id") for f in criticals],
        "output": str(out_fp),
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]
    try:
        if cmd in ("submissions", "dedupe", "summary"):
            if not args:
                print(json.dumps({"error": f"usage: {cmd} <target>"}))
                sys.exit(1)
            fn = {"submissions": submissions, "dedupe": dedupe, "summary": summary}[cmd]
            print(json.dumps(fn(args[0]), indent=2))
        else:
            print(json.dumps({"error": f"unknown command: {cmd}"}))
            print(__doc__)
            sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
