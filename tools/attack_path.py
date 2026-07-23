#!/usr/bin/env python3
"""Precise attack-path chainer along a kill-chain graph.

Replaces the old substring-matching chain engine (which produced false positives
like "XXE -> SSRF" whenever the literal text "file upload" appeared in unrelated
evidence). This engine matches ONLY on the structured `type` field, requires each
hop to be a DISTINCT finding (different id AND different evidence path), and
requires a minimum number of independent findings before a chain is emitted.

Usage: python3 /tools/attack_path.py <command> [args]

Commands:
  chain <findings_consolidated_json>   Build attack chains from findings.
  score <findings_json>                Overall risk score 0-100.

Finding schema: {id, title, type, severity, detail, evidence:[]}
STDLIB ONLY. No substring matching on free text.
"""

import json
import sys
from pathlib import Path

# Severity ordering / numeric weight for scoring.
SEVERITY_WEIGHT = {
    "info": 1,
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

# Kill-chain phase per finding type (recon -> foothold -> privesc -> lateral -> impact).
KILL_CHAIN_PHASE = {
    "info disclosure": "recon",
    "misconfiguration": "recon",
    "ssrf": "foothold",
    "lfi": "foothold",
    "xxe": "foothold",
    "sqli": "foothold",
    "xss": "foothold",
    "auth-bypass": "privesc",
    "jwt": "privesc",
    "idor": "lateral",
    "bola": "lateral",
    "mass-assignment": "privesc",
    "rce": "impact",
}

# CHAIN_TEMPLATES: the canonical named kill-chain transitions, matched on the
# structured `type` field ONLY (never on free-text). Each hop is a tuple of the
# allowed types for that step. TWO_HOP / THREE_HOP below are the concrete
# realizations the engine walks.
CHAIN_TEMPLATES = {
    "SSRF to cloud-metadata RCE": (("ssrf",), ("info disclosure",), ("rce",)),
    "Auth bypass to mass data exposure": (("idor", "bola"), ("info disclosure",)),
    "LFI to log-poisoning RCE": (("lfi",), ("rce",)),
    "Broken auth to horizontal escalation": (("jwt", "auth-bypass"), ("idor", "bola")),
    "Stored XSS session theft": (("xss",), ("auth-bypass",)),
}

# Two-hop templates: list of (from_types, to_types, name).
TWO_HOP = [
    (("ssrf",), ("info disclosure",), "SSRF to cloud-metadata info disclosure"),
    (("idor", "bola"), ("info disclosure",), "Auth bypass to mass data exposure"),
    (("lfi",), ("rce",), "LFI to log-poisoning RCE"),
    (("jwt", "auth-bypass"), ("idor", "bola"), "Broken auth to horizontal escalation"),
    (("xss",), ("auth-bypass",), "Stored XSS session theft"),
    (("mass-assignment",), ("auth-bypass",), "Mass-assignment privilege escalation"),
    (("sqli",), ("info disclosure",), "SQLi to sensitive data extraction"),
]

# Three-hop templates: list of (t1, t2, t3, name).
THREE_HOP = [
    (("ssrf",), ("info disclosure",), ("rce",), "SSRF to cloud-metadata RCE"),
    (("lfi",), ("info disclosure",), ("rce",), "LFI disclosure to log-poisoning RCE"),
    (("jwt", "auth-bypass"), ("idor", "bola"), ("info disclosure",),
     "Broken auth to horizontal escalation to data exposure"),
]

DEFAULT_MIN_DISTINCT = 2


def emit(obj):
    print(json.dumps(obj, indent=2))


def load_json(path):
    return json.loads(Path(path).read_text())


def norm_type(value):
    return (value or "").strip().lower()


def evidence_paths(finding):
    """Return a set of normalized evidence identifiers for a finding.

    Evidence may be a list of strings or dicts; we extract a stable path/token so
    two hops can be verified as backed by DISTINCT evidence.
    """
    paths = set()
    ev = finding.get("evidence") or []
    if isinstance(ev, str):
        ev = [ev]
    for item in ev:
        if isinstance(item, dict):
            token = item.get("path") or item.get("url") or item.get("endpoint") or json.dumps(item, sort_keys=True)
        else:
            token = str(item)
        token = token.strip()
        if token:
            paths.add(token)
    return paths


def index_by_type(findings):
    """Map normalized type -> list of findings."""
    idx = {}
    for finding in findings:
        idx.setdefault(norm_type(finding.get("type")), []).append(finding)
    return idx


def max_sev_weight(findings):
    return max((SEVERITY_WEIGHT.get((f.get("severity") or "").lower(), 1) for f in findings), default=1)


def sev_label_from_weight(weight):
    for label in ("critical", "high", "medium", "low", "info"):
        if SEVERITY_WEIGHT.get(label) == weight:
            return label
    return "info"


def _distinct(findings):
    """True if all findings have distinct ids AND no shared evidence path across hops."""
    ids = [f.get("id") for f in findings]
    if len(set(ids)) != len(ids):
        return False
    # No single evidence path may be reused across two different hops.
    seen = set()
    for finding in findings:
        paths = evidence_paths(finding)
        if paths & seen:
            return False
        seen |= paths
    return True


def _pick_hop(idx, type_options, used_ids):
    """Return the first finding of an allowed type whose id is unused."""
    for t in type_options:
        for finding in idx.get(t, []):
            if finding.get("id") not in used_ids:
                return finding
    return None


def build_chains(findings, min_distinct=DEFAULT_MIN_DISTINCT):
    idx = index_by_type(findings)
    chains = []
    seen_signatures = set()

    def add_chain(hop_findings, name):
        if len(hop_findings) < min_distinct:
            return
        if not _distinct(hop_findings):
            return
        ids = [f.get("id") for f in hop_findings]
        signature = (name, tuple(sorted(ids)))
        if signature in seen_signatures:
            return
        seen_signatures.add(signature)
        weight = max_sev_weight(hop_findings)
        independent = len(set(ids))
        score = independent * weight
        chains.append(
            {
                "name": name,
                "steps": ids,
                "severity": sev_label_from_weight(weight),
                "score": score,
                "rationale": (
                    f"{independent} distinct findings across kill-chain phases "
                    f"["
                    + " -> ".join(
                        f"{norm_type(f.get('type'))}:{KILL_CHAIN_PHASE.get(norm_type(f.get('type')), '?')}"
                        for f in hop_findings
                    )
                    + f"]; matched on structured type field; max severity weight {weight}."
                ),
            }
        )

    # Three-hop chains first (more specific, higher value).
    for t1, t2, t3, name in THREE_HOP:
        used = set()
        f1 = _pick_hop(idx, t1, used)
        if not f1:
            continue
        used.add(f1.get("id"))
        f2 = _pick_hop(idx, t2, used)
        if not f2:
            continue
        used.add(f2.get("id"))
        f3 = _pick_hop(idx, t3, used)
        if not f3:
            continue
        add_chain([f1, f2, f3], name)

    # Two-hop chains.
    for t1, t2, name in TWO_HOP:
        used = set()
        f1 = _pick_hop(idx, t1, used)
        if not f1:
            continue
        used.add(f1.get("id"))
        f2 = _pick_hop(idx, t2, used)
        if not f2:
            continue
        add_chain([f1, f2], name)

    chains.sort(key=lambda c: c["score"], reverse=True)
    return chains


def cmd_chain(path, min_distinct):
    data = load_json(path)
    findings = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        emit({"status": "error", "detail": "expected {'findings':[...]} or a list"})
        return
    chains = build_chains(findings, min_distinct=min_distinct)
    emit(
        {
            "status": "ok",
            "total_findings": len(findings),
            "min_distinct_findings": min_distinct,
            "chain_count": len(chains),
            "chains": chains,
        }
    )


def compute_risk(findings, chains):
    """Overall risk 0-100 from severities + chain presence."""
    if not findings:
        return 0
    weights = [SEVERITY_WEIGHT.get((f.get("severity") or "").lower(), 1) for f in findings]
    # Base: normalized max + average contribution (max dominates).
    max_w = max(weights)
    avg_w = sum(weights) / len(weights)
    base = (max_w / 5.0) * 70 + (avg_w / 5.0) * 15  # up to 85
    # Chains add up to 15 based on best chain score, capped.
    chain_bonus = 0
    if chains:
        best = max(c["score"] for c in chains)
        chain_bonus = min(15, best)  # score already small integers
    return int(round(min(100, base + chain_bonus)))


def cmd_score(path, min_distinct):
    data = load_json(path)
    findings = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        emit({"status": "error", "detail": "expected {'findings':[...]} or a list"})
        return
    chains = build_chains(findings, min_distinct=min_distinct)
    risk = compute_risk(findings, chains)
    counts = {}
    for finding in findings:
        sev = (finding.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    emit(
        {
            "status": "ok",
            "risk_score": risk,
            "total_findings": len(findings),
            "severity_breakdown": counts,
            "chain_count": len(chains),
            "top_chain": chains[0]["name"] if chains else None,
        }
    )


def usage():
    emit({"status": "error", "detail": "usage: attack_path.py <chain|score> <findings.json> [min_distinct]"})


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        usage()
        return
    cmd, path = args[0], args[1]
    min_distinct = DEFAULT_MIN_DISTINCT
    if len(args) >= 3:
        try:
            min_distinct = max(1, int(args[2]))
        except ValueError:
            min_distinct = DEFAULT_MIN_DISTINCT
    try:
        if cmd == "chain":
            cmd_chain(path, min_distinct)
        elif cmd == "score":
            cmd_score(path, min_distinct)
        else:
            usage()
    except FileNotFoundError:
        emit({"status": "error", "detail": f"file not found: {path}"})
    except ValueError as exc:
        emit({"status": "error", "detail": f"invalid JSON: {exc}"})
    except Exception as exc:  # never leak a stack trace
        emit({"status": "error", "detail": f"{type(exc).__name__}: {exc}"})


if __name__ == "__main__":
    main()
