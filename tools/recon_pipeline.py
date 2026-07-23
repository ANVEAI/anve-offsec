#!/usr/bin/env python3
"""
ProjectDiscovery-style recon orchestrator for kali-ai.

Chains available recon tools (subfinder, dnsx, naabu/nmap, httpx, katana, nuclei)
against an AUTHORIZED target, aggregates results, mines crawled JavaScript for
leaked secrets, and records vulnerabilities to the findings contract.

STDLIB ONLY. Every external tool is gated by shutil.which() and skipped (not
crashed) when missing. All raw output is written under /work/loot/<target>/recon/
and referenced by path.

Usage: python3 /tools/recon_pipeline.py <command> [args]

Commands:
  run <target> [--web|--network]   Run the recon chain and aggregate results.
  write-summary <target>           Build RECON_SUMMARY.md from raw recon files.
"""

import fnmatch
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

CONFIG_FILE = Path("/config/authorized-targets.json")
LOOT_ROOT = Path("/work/loot")
FETCH_SLEEP = 0.3  # polite delay between direct HTTP fetches

# ---------------------------------------------------------------------------
# Authorization rail
# ---------------------------------------------------------------------------


def _extract_host(target: str) -> str:
    """Reduce a URL/IP/domain to its bare host (no scheme, path or port)."""
    t = target.lower().strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    # keep bracketed IPv6 intact, otherwise strip :port
    if not t.startswith("[") and t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t


def _safe_name(target: str) -> str:
    """Filesystem-safe token derived from a target."""
    host = _extract_host(target)
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", host).strip("_") or "target"


def _load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {"targets": [], "lab_mode": False}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {"targets": [], "lab_mode": False}


def _match_domain(host: str, pattern: str) -> bool:
    host = host.lower().strip()
    pattern = pattern.lower().strip()
    if not pattern:
        return False
    if host == pattern:
        return True
    if fnmatch.fnmatch(host, pattern):  # supports *.example.com
        return True
    if host.endswith("." + pattern):
        return True
    return False


def authorized(target: str) -> bool:
    """Return True if `target` is in scope per /config/authorized-targets.json."""
    config = _load_config()
    host = _extract_host(target)

    # localhost / loopback always allowed in lab mode
    if config.get("lab_mode", False):
        if host in ("localhost", "127.0.0.1", "::1"):
            return True
        try:
            if ipaddress.ip_address(host).is_loopback:
                return True
        except ValueError:
            pass

    for t in config.get("targets", []):
        if _match_domain(host, t.get("domain", "")):
            return True
    return False


def ensure_authorized(target: str) -> None:
    """Exit(2) with a structured error if the target is not authorized."""
    if not authorized(target):
        print(json.dumps({"error": "target not authorized", "target": target}))
        sys.exit(2)


# ---------------------------------------------------------------------------
# Findings contract
# ---------------------------------------------------------------------------


def append_finding(target: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    """Append one finding (JSON per line) to /work/loot/<target>/findings.jsonl."""
    out = dict(finding)
    out.setdefault("id", "F-" + uuid.uuid4().hex[:10])
    out.setdefault("title", "Untitled finding")
    out.setdefault("type", "other")
    out.setdefault("severity", "info")
    out.setdefault("detail", "")
    out.setdefault("evidence", [])
    findings_file = LOOT_ROOT / _safe_name(target) / "findings.jsonl"
    findings_file.parent.mkdir(parents=True, exist_ok=True)
    with findings_file.open("a") as f:
        f.write(json.dumps(out) + "\n")
    return out


# ---------------------------------------------------------------------------
# Paths & subprocess helpers
# ---------------------------------------------------------------------------


def _recon_dir(target: str) -> Path:
    d = LOOT_ROOT / _safe_name(target) / "recon"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _run_stage(tool: str, argv: List[str], output_file: Path,
               timeout: int = 300, stdin_data: Optional[str] = None) -> Dict[str, Any]:
    """Run one external CLI stage; write stdout to output_file; never crash."""
    stage = {"tool": tool, "status": "ok", "output_file": str(output_file), "count": 0}
    if shutil.which(tool) is None:
        stage["status"] = "skipped: not installed"
        return stage
    try:
        proc = subprocess.run(
            argv,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output_file.write_text(proc.stdout or "")
        lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
        stage["count"] = len(lines)
        if proc.returncode != 0 and not lines:
            stage["status"] = f"error: exit {proc.returncode}"
            err_snip = (proc.stderr or "").strip()[:300]
            if err_snip:
                stage["stderr"] = err_snip
    except subprocess.TimeoutExpired:
        stage["status"] = f"error: timeout after {timeout}s"
    except Exception as exc:  # noqa: BLE001 - structured, no stack traces
        stage["status"] = f"error: {exc}"
    return stage


def _read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    try:
        return [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]
    except Exception:
        return []


def _is_network_target(target: str) -> bool:
    """True when the target is an IP address or CIDR block."""
    host = _extract_host(target)
    try:
        ipaddress.ip_network(host, strict=False)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# nuclei parsing -> findings
# ---------------------------------------------------------------------------

_NUCLEI_SEV = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def _parse_nuclei(target: str, nuclei_file: Path) -> int:
    """Parse nuclei JSONL output into findings. Returns count appended."""
    count = 0
    for line in _read_lines(nuclei_file):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        info = rec.get("info", {}) or {}
        sev = _NUCLEI_SEV.get(str(info.get("severity", "info")).lower(), "info")
        name = info.get("name") or rec.get("template-id") or "nuclei detection"
        matched = rec.get("matched-at") or rec.get("host") or rec.get("url") or ""
        append_finding(target, {
            "title": f"nuclei: {name}",
            "type": "misconfiguration",
            "severity": sev,
            "detail": f"nuclei template '{rec.get('template-id', '?')}' matched at {matched}.",
            "evidence": [str(nuclei_file)],
        })
        count += 1
    return count


# ---------------------------------------------------------------------------
# JavaScript secret mining
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("bearer_token", re.compile(r"[Bb]earer\s+[A-Za-z0-9\-\._~\+\/]{20,}")),
    ("generic_api_key", re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
]


def _mine_js_secrets(target: str, js_urls: List[str], recon: Path) -> Dict[str, Any]:
    """Fetch each .js URL (rate-limited) and regex for plausible secrets."""
    secrets_file = recon / "js-secrets.txt"
    matches: List[str] = []
    fetched = 0
    for url in js_urls:
        if not url.lower().split("?", 1)[0].endswith(".js"):
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "kali-ai-recon/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 scoped/authorized
                body = resp.read(2_000_000).decode("utf-8", "replace")
            fetched += 1
        except Exception:
            time.sleep(FETCH_SLEEP)
            continue
        found_here = False
        for label, pat in _SECRET_PATTERNS:
            for m in pat.findall(body):
                snippet = m if isinstance(m, str) else str(m)
                matches.append(f"{url}\t{label}\t{snippet[:120]}")
                found_here = True
        if found_here:
            append_finding(target, {
                "title": f"Possible secret leaked in JS: {url}",
                "type": "info disclosure",
                "severity": "medium",
                "detail": "Regex-matched a plausible credential/token in a crawled "
                          "JavaScript file. Manual verification required.",
                "evidence": [str(secrets_file)],
            })
        time.sleep(FETCH_SLEEP)
    if matches:
        secrets_file.write_text("\n".join(matches) + "\n")
    return {"js_fetched": fetched, "secret_hits": len(matches),
            "secrets_file": str(secrets_file) if matches else None}


# ---------------------------------------------------------------------------
# Recon chain
# ---------------------------------------------------------------------------


def run(target: str, mode: str = "auto") -> Dict[str, Any]:
    """Run the recon chain and return an aggregated summary dict."""
    ensure_authorized(target)
    recon = _recon_dir(target)
    host = _extract_host(target)
    stages: List[Dict[str, Any]] = []
    hosts: List[str] = []
    urls: List[str] = []
    services: List[str] = []

    network = mode == "network" or (mode == "auto" and _is_network_target(target))

    if network:
        # IP / CIDR -> nmap service + default scripts
        out = recon / "nmap.txt"
        argv = ["nmap", "-sV", "-sC", "--top-ports", "1000", "-T3", "-oN", str(out), host]
        st = _run_stage("nmap", argv, out, timeout=600)
        stages.append(st)
        for ln in _read_lines(out):
            m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)", ln)
            if m:
                services.append(f"{m.group(1)}/{m.group(2)} {m.group(3)}{m.group(4)}".strip())
        hosts.append(host)
    else:
        # Domain -> subfinder -> dnsx -> naabu/nmap -> httpx -> katana -> nuclei
        subs_file = recon / "subfinder.txt"
        st = _run_stage("subfinder", ["subfinder", "-silent", "-d", host], subs_file, timeout=300)
        stages.append(st)
        subs = _read_lines(subs_file) or [host]
        hosts.extend(subs)

        dnsx_file = recon / "dnsx.txt"
        st = _run_stage("dnsx", ["dnsx", "-silent", "-a", "-resp-only"], dnsx_file,
                        timeout=300, stdin_data="\n".join(subs))
        stages.append(st)

        naabu_file = recon / "naabu.txt"
        if shutil.which("naabu"):
            st = _run_stage("naabu", ["naabu", "-silent", "-top-ports", "1000"], naabu_file,
                            timeout=600, stdin_data="\n".join(subs))
        else:
            # fallback: nmap connect scan of the base host
            st = _run_stage("nmap", ["nmap", "-sV", "--top-ports", "1000", "-T3", host],
                            naabu_file, timeout=600)
        stages.append(st)
        services.extend(_read_lines(naabu_file)[:200])

        httpx_file = recon / "httpx.txt"
        st = _run_stage("httpx", ["httpx", "-silent", "-json"], httpx_file,
                        timeout=300, stdin_data="\n".join(subs))
        stages.append(st)
        for ln in _read_lines(httpx_file):
            try:
                rec = json.loads(ln)
                u = rec.get("url")
                if u:
                    urls.append(u)
            except Exception:
                if ln.startswith("http"):
                    urls.append(ln)

        katana_file = recon / "katana.txt"
        seed = urls or [f"http://{host}", f"https://{host}"]
        st = _run_stage("katana", ["katana", "-silent", "-jc", "-d", "2"], katana_file,
                        timeout=600, stdin_data="\n".join(seed))
        stages.append(st)
        urls.extend([u for u in _read_lines(katana_file) if u.startswith("http")])

        # nuclei with safe, rate-limited templates only
        nuclei_file = recon / "nuclei.jsonl"
        nuclei_targets = list(dict.fromkeys(urls or seed))
        st = _run_stage(
            "nuclei",
            ["nuclei", "-jsonl", "-severity", "low,medium,high,critical",
             "-etags", "dos,intrusive", "-rate-limit", "20", "-silent"],
            nuclei_file, timeout=900, stdin_data="\n".join(nuclei_targets),
        )
        stages.append(st)
        if st["status"] == "ok":
            _parse_nuclei(target, nuclei_file)

        # Mine crawled JS for secrets
        js_urls = list(dict.fromkeys(u for u in urls if u.lower().split("?", 1)[0].endswith(".js")))
        if js_urls:
            stages.append({"tool": "js-secret-miner",
                           **_mine_js_secrets(target, js_urls, recon)})

    urls = list(dict.fromkeys(urls))
    hosts = list(dict.fromkeys(hosts))
    services = list(dict.fromkeys(services))

    summary = {
        "target": target,
        "mode": "network" if network else "web",
        "stages": stages,
        "hosts": hosts,
        "urls": urls,
        "services": services,
        "recon_dir": str(recon),
    }
    (recon / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def write_summary(target: str) -> Dict[str, Any]:
    """Build RECON_SUMMARY.md from the raw recon files on disk."""
    recon = LOOT_ROOT / _safe_name(target) / "recon"
    if not recon.exists():
        return {"error": "no recon data found", "target": target,
                "expected_dir": str(recon)}
    md = [f"# Recon Summary — {target}",
          f"_Generated {datetime.now(timezone.utc).isoformat()}_", ""]

    summary_json = recon / "summary.json"
    if summary_json.exists():
        try:
            data = json.loads(summary_json.read_text())
            md.append(f"- Mode: **{data.get('mode', '?')}**")
            md.append(f"- Hosts discovered: **{len(data.get('hosts', []))}**")
            md.append(f"- URLs discovered: **{len(data.get('urls', []))}**")
            md.append(f"- Services: **{len(data.get('services', []))}**")
            md.append("")
            md.append("## Stages")
            for st in data.get("stages", []):
                md.append(f"- `{st.get('tool')}` — {st.get('status')} "
                          f"(count={st.get('count', 0)})")
            md.append("")
        except Exception:
            pass

    for raw in sorted(recon.glob("*.txt")):
        lines = _read_lines(raw)
        md.append(f"## {raw.name} ({len(lines)} lines)")
        for ln in lines[:40]:
            md.append(f"    {ln}")
        if len(lines) > 40:
            md.append(f"    ... ({len(lines) - 40} more, see {raw})")
        md.append("")

    out = recon / "RECON_SUMMARY.md"
    out.write_text("\n".join(md) + "\n")
    return {"target": target, "summary_file": str(out)}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "run":
        if not args:
            print(json.dumps({"error": "usage: run <target> [--web|--network]"}))
            sys.exit(1)
        target = args[0]
        mode = "auto"
        if "--web" in args:
            mode = "web"
        elif "--network" in args:
            mode = "network"
        print(json.dumps(run(target, mode), indent=2))
    elif cmd == "write-summary":
        if not args:
            print(json.dumps({"error": "usage: write-summary <target>"}))
            sys.exit(1)
        print(json.dumps(write_summary(args[0]), indent=2))
    else:
        print(json.dumps({"error": f"unknown command: {cmd}"}))
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
