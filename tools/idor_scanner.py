#!/usr/bin/env python3
"""
Multi-account BOLA/IDOR differ for kali-ai.

Replays captured requests belonging to account A, then replays the SAME requests
swapped onto a second low-privilege account B, and flags Insecure Direct Object
Reference / Broken Object Level Authorization when B can read A's objects. Also
tries numeric object-id increment/decrement.

READ-ONLY by default (GET/HEAD only); state-changing methods are skipped unless
--include-writes is passed. STDLIB ONLY, polite rate limiting between requests.

Usage: python3 /tools/idor_scanner.py <command> [args]

Commands:
  diff <target> <requests_file> <sessionA_file> <sessionB_file> [--threshold 0.85]
       [--include-writes] [--rate 0.3]
       requests_file: JSONL of {"method","url","headers":{},"body":null}
       sessionA/B_file: JSON {"headers":{"Cookie":"...","Authorization":"..."}}
  probe <target> <url> <sessionA_file> <sessionB_file> [--rate 0.3]
       Quick single-URL cross-account check.
"""

import difflib
import fnmatch
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

CONFIG_FILE = Path("/config/authorized-targets.json")
LOOT_ROOT = Path("/work/loot")
DEFAULT_THRESHOLD = 0.85
DEFAULT_RATE = 0.3
READ_METHODS = {"GET", "HEAD"}
PII_FIELDS = ("email", "ssn", "token", "password", "phone", "api_key",
              "credit_card", "address", "dob")

# ---------------------------------------------------------------------------
# Authorization rail (shared convention)
# ---------------------------------------------------------------------------


def _extract_host(target: str) -> str:
    t = target.lower().strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    if not t.startswith("[") and t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t


def _safe_name(target: str) -> str:
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
    host, pattern = host.lower().strip(), pattern.lower().strip()
    if not pattern:
        return False
    if host == pattern or fnmatch.fnmatch(host, pattern):
        return True
    return host.endswith("." + pattern)


def authorized(target: str) -> bool:
    """Return True if `target` is authorized in /config/authorized-targets.json."""
    config = _load_config()
    host = _extract_host(target)
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
    out.setdefault("type", "idor")
    out.setdefault("severity", "high")
    out.setdefault("detail", "")
    out.setdefault("evidence", [])
    findings_file = LOOT_ROOT / _safe_name(target) / "findings.jsonl"
    findings_file.parent.mkdir(parents=True, exist_ok=True)
    with findings_file.open("a") as f:
        f.write(json.dumps(out) + "\n")
    return out


def _idor_dir(target: str) -> Path:
    d = LOOT_ROOT / _safe_name(target) / "idor"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# HTTP replay
# ---------------------------------------------------------------------------


def _do_request(method: str, url: str, headers: Dict[str, str],
                body: Optional[str], timeout: int = 15) -> Dict[str, Any]:
    """Perform an HTTP request; return {status, body, error}. Never raises."""
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method.upper())
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    req.add_header("User-Agent", "kali-ai-idor/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 authorized
            raw = resp.read(1_000_000).decode("utf-8", "replace")
            return {"status": resp.status, "body": raw, "error": None}
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(1_000_000).decode("utf-8", "replace")
        except Exception:
            raw = ""
        return {"status": exc.code, "body": raw, "error": None}
    except Exception as exc:  # noqa: BLE001
        return {"status": None, "body": "", "error": str(exc)}


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a or "", b or "").ratio()


def _extract_identifiers(text: str) -> List[str]:
    """Pull candidate object identifiers (uuids, longer numeric ids) from a body."""
    ids = set(re.findall(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                         r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", text or ""))
    ids.update(re.findall(r"\b\d{3,}\b", text or ""))
    return list(ids)[:50]


def _looks_like_pii(text: str) -> bool:
    low = (text or "").lower()
    return any(field in low for field in PII_FIELDS)


def _swap_numeric_id(url: str, delta: int) -> Optional[str]:
    """Return url with the last numeric path/query id shifted by delta, else None."""
    parts = urlsplit(url)
    # try path segment ids first
    segs = parts.path.split("/")
    for i in range(len(segs) - 1, -1, -1):
        if segs[i].isdigit():
            new_val = int(segs[i]) + delta
            if new_val < 0:
                return None
            segs[i] = str(new_val)
            return urlunsplit((parts.scheme, parts.netloc, "/".join(segs),
                               parts.query, parts.fragment))
    # then query numeric params
    m = re.search(r"([?&][\w]+=)(\d+)", parts.query and "?" + parts.query or "")
    if m:
        new_val = int(m.group(2)) + delta
        if new_val < 0:
            return None
        new_query = ("?" + parts.query).replace(m.group(0), m.group(1) + str(new_val), 1)[1:]
        return urlunsplit((parts.scheme, parts.netloc, parts.path,
                           new_query, parts.fragment))
    return None


# ---------------------------------------------------------------------------
# Core differ
# ---------------------------------------------------------------------------


def _evaluate(target: str, idx: int, method: str, url: str,
              base: Dict[str, Any], swap: Dict[str, Any],
              threshold: float, idir: Path, kind: str = "swap") -> Optional[Dict[str, Any]]:
    """Compare a baseline (A) response against a cross-account (B) response."""
    evidence_file = idir / f"{idx}.json"
    ratio = _similarity(base.get("body", ""), swap.get("body", ""))
    base_ids = set(_extract_identifiers(base.get("body", "")))
    swap_ids = set(_extract_identifiers(swap.get("body", "")))
    shared_ids = sorted(base_ids & swap_ids)

    record = {
        "index": idx, "kind": kind, "method": method, "url": url,
        "baseline_status": base.get("status"), "swapped_status": swap.get("status"),
        "similarity": round(ratio, 4), "shared_identifiers": shared_ids[:20],
        "baseline_error": base.get("error"), "swapped_error": swap.get("error"),
    }
    evidence_file.write_text(json.dumps(record, indent=2))

    swap_status = swap.get("status")
    is_2xx = isinstance(swap_status, int) and 200 <= swap_status < 300
    similar = ratio >= threshold or bool(shared_ids)

    if is_2xx and similar:
        pii = _looks_like_pii(swap.get("body", ""))
        severity = "critical" if pii else "high"
        ftype = "bola" if kind == "swap" else "idor"
        append_finding(target, {
            "title": f"{ftype.upper()} on {method} {url}",
            "type": ftype,
            "severity": severity,
            "detail": (f"Account B ({kind}) received HTTP {swap_status} with body "
                       f"similarity {ratio:.2f} to account A's baseline "
                       f"(shared ids: {shared_ids[:5]}). "
                       f"{'PII-like fields present. ' if pii else ''}"
                       "Cross-account object access without authorization."),
            "evidence": [str(evidence_file)],
        })
        record["finding"] = ftype
    return record


def diff(target: str, requests_file: str, session_a_file: str, session_b_file: str,
         threshold: float = DEFAULT_THRESHOLD, include_writes: bool = False,
         rate: float = DEFAULT_RATE) -> Dict[str, Any]:
    """Differ across a JSONL of captured requests for two distinct accounts."""
    ensure_authorized(target)
    idir = _idor_dir(target)

    try:
        session_a = json.loads(Path(session_a_file).read_text())
        session_b = json.loads(Path(session_b_file).read_text())
    except Exception as exc:
        return {"error": f"could not load session files: {exc}"}
    headers_a = session_a.get("headers", {})
    headers_b = session_b.get("headers", {})

    try:
        raw_lines = [ln for ln in Path(requests_file).read_text().splitlines() if ln.strip()]
    except Exception as exc:
        return {"error": f"could not load requests file: {exc}"}

    results: List[Dict[str, Any]] = []
    tested = skipped = 0
    for i, line in enumerate(raw_lines):
        try:
            reqspec = json.loads(line)
        except Exception:
            skipped += 1
            continue
        method = (reqspec.get("method") or "GET").upper()
        url = reqspec.get("url")
        if not url or _extract_host(url) not in ("",) and not authorized(url):
            # only test in-scope URLs
            if url and not authorized(url):
                skipped += 1
                continue
        if method not in READ_METHODS and not include_writes:
            skipped += 1
            continue
        body = reqspec.get("body")

        # (1) baseline as A
        base = _do_request(method, url, headers_a, body)
        time.sleep(rate)
        # (2) same request swapped to B
        swap = _do_request(method, url, headers_b, body)
        time.sleep(rate)
        results.append(_evaluate(target, i, method, url, base, swap,
                                 threshold, idir, kind="swap"))
        tested += 1

        # (3) object-id increment/decrement as B (read-only)
        if method in READ_METHODS:
            for delta in (1, -1):
                alt = _swap_numeric_id(url, delta)
                if not alt or not authorized(alt):
                    continue
                alt_resp = _do_request("GET", alt, headers_b, None)
                time.sleep(rate)
                results.append(_evaluate(target, f"{i}_id{delta:+d}", "GET", alt,
                                         base, alt_resp, threshold, idir, kind="id-shift"))

    findings = [r for r in results if r and r.get("finding")]
    return {
        "target": target, "tested": tested, "skipped": skipped,
        "threshold": threshold, "include_writes": include_writes,
        "comparisons": len(results), "findings": len(findings),
        "idor_dir": str(idir),
    }


def probe(target: str, url: str, session_a_file: str, session_b_file: str,
          rate: float = DEFAULT_RATE) -> Dict[str, Any]:
    """Quick single-URL cross-account check (GET only)."""
    ensure_authorized(target)
    if not authorized(url):
        print(json.dumps({"error": "target not authorized", "target": url}))
        sys.exit(2)
    idir = _idor_dir(target)
    try:
        headers_a = json.loads(Path(session_a_file).read_text()).get("headers", {})
        headers_b = json.loads(Path(session_b_file).read_text()).get("headers", {})
    except Exception as exc:
        return {"error": f"could not load session files: {exc}"}

    base = _do_request("GET", url, headers_a, None)
    time.sleep(rate)
    swap = _do_request("GET", url, headers_b, None)
    record = _evaluate(target, "probe", "GET", url, base, swap,
                       DEFAULT_THRESHOLD, idir, kind="swap")
    return {"target": target, "url": url, "result": record}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _flag_value(args: List[str], name: str, cast, default):
    if name in args:
        idx = args.index(name)
        if idx + 1 < len(args):
            try:
                return cast(args[idx + 1])
            except Exception:
                return default
    return default


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "diff":
        if len(args) < 4:
            print(json.dumps({"error": "usage: diff <target> <requests_file> "
                                       "<sessionA_file> <sessionB_file> "
                                       "[--threshold X] [--include-writes] [--rate X]"}))
            sys.exit(1)
        threshold = _flag_value(args, "--threshold", float, DEFAULT_THRESHOLD)
        rate = _flag_value(args, "--rate", float, DEFAULT_RATE)
        include_writes = "--include-writes" in args
        print(json.dumps(diff(args[0], args[1], args[2], args[3],
                              threshold, include_writes, rate), indent=2))
    elif cmd == "probe":
        if len(args) < 4:
            print(json.dumps({"error": "usage: probe <target> <url> "
                                       "<sessionA_file> <sessionB_file> [--rate X]"}))
            sys.exit(1)
        rate = _flag_value(args, "--rate", float, DEFAULT_RATE)
        print(json.dumps(probe(args[0], args[1], args[2], args[3], rate), indent=2))
    else:
        print(json.dumps({"error": f"unknown command: {cmd}"}))
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
