#!/usr/bin/env python3
"""
Knowledge ingestion for kali-ai (Phase 5 — curated offensive-knowledge RAG).

Ingests external offensive-security corpora (nuclei-templates,
PayloadsAllTheThings, CVE feeds, disclosed reports) into the Qdrant
`kali_knowledge` collection so they can be retrieved at plan time.

Reuses /tools/rag_client.py for Qdrant access (import if clean, else a
self-contained urllib fallback against http://qdrant:6333). Documents are
stored with payload {text, source, tags, vuln_class, added_at} keyed by a
content hash id so re-ingestion is idempotent.

Usage: python3 /tools/knowledge_ingest.py <command> [args]

Commands:
  ingest-nuclei <dir>      Walk nuclei-templates .yaml/.yml, upsert each template.
  ingest-payloads <dir>    Walk PayloadsAllTheThings .md, chunk by heading, upsert.
  ingest-cve <json_file>   Ingest a JSON array of {id,summary,cvss,refs}.
  ingest-reports <dir>     Walk disclosed-report .md, chunk by heading, upsert.
  search <query> [limit]   Full-text search kali_knowledge.
  stats                    Point count + breakdown by vuln_class.
"""

import json
import os
import re
import sys
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

QDRANT_HOST = "http://qdrant:6333"
COLLECTION = "kali_knowledge"
KNOWLEDGE_ROOT = Path("/work/knowledge")
MAX_CHUNK = 8000

# --- Reuse rag_client if importable (do NOT reimplement Qdrant from scratch) ---
_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))
try:
    import rag_client  # type: ignore
    _HAVE_RAG = True
except Exception:
    rag_client = None  # type: ignore
    _HAVE_RAG = False


# vuln_class inference: first matching keyword group wins.
VULN_KEYWORDS: List[tuple] = [
    ("sqli", ["sql injection", "sqli", "union select", "union-based", "blind sql", "boolean-based sql"]),
    ("xss", ["cross-site scripting", "cross site scripting", "xss", "reflected script"]),
    ("idor", ["idor", "insecure direct object", "bola", "broken object level"]),
    ("ssrf", ["ssrf", "server-side request forgery", "server side request forgery"]),
    ("rce", ["remote code execution", "command injection", "os command", "code injection", "rce"]),
    ("lfi", ["local file inclusion", "path traversal", "directory traversal", "file inclusion", "lfi", "rfi"]),
    ("jwt", ["json web token", "jwt", "jwks", "alg none", "algorithm confusion"]),
    ("xxe", ["xml external entity", "xxe"]),
    ("ssti", ["server-side template injection", "template injection", "ssti"]),
    ("csrf", ["cross-site request forgery", "csrf"]),
    ("deserialization", ["insecure deserialization", "deserialization", "ysoserial", "pickle"]),
    ("mass-assignment", ["mass assignment", "over-posting", "autobind"]),
    ("auth-bypass", ["authentication bypass", "auth bypass", "broken authentication", "default credential", "weak credential"]),
    ("open-redirect", ["open redirect", "open-redirect"]),
    ("info-disclosure", ["information disclosure", "info disclosure", "sensitive data exposure", "data leak"]),
]


def infer_vuln_class(*texts: str) -> str:
    """Infer a vuln_class from free text via keyword scan; 'other' if none."""
    blob = " ".join(t for t in texts if t).lower()
    for vuln_class, keywords in VULN_KEYWORDS:
        for kw in keywords:
            if kw in blob:
                return vuln_class
    return "other"


def _slug(name: str) -> str:
    """Normalize a folder/label into a slug for vuln_class fallback."""
    s = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return s or "other"


# --- Qdrant plumbing (delegates to rag_client when available) ---
def _call(method: str, endpoint: str, data: Optional[dict] = None) -> dict:
    """Call Qdrant, preferring rag_client._call; urllib fallback otherwise."""
    if _HAVE_RAG:
        try:
            return rag_client._call(method, endpoint, data)
        except Exception as e:
            return {"error": str(e), "status": "error"}
    url = f"{QDRANT_HOST}/{endpoint}"
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")
    if data is not None:
        req.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        return {"error": str(e), "status": "error"}
    except Exception as e:
        return {"error": str(e), "status": "error"}


def _ensure_collection() -> None:
    """Create the kali_knowledge collection + full-text index on 'text' if absent."""
    info = _call("GET", f"collections/{COLLECTION}")
    if isinstance(info, dict) and info.get("result"):
        return
    if _HAVE_RAG:
        try:
            rag_client.create_collection(COLLECTION, vector_size=1)
            rag_client.create_fulltext_index(COLLECTION, "text")
            return
        except Exception:
            pass
    _call("PUT", f"collections/{COLLECTION}", {
        "vectors": {"size": 1, "distance": "Cosine"},
    })
    _call("PUT", f"collections/{COLLECTION}/index", {
        "field_name": "text", "field_schema": "text",
    })


def _hash_id(*parts: str) -> int:
    """Deterministic uint64 point id from content (idempotent upserts)."""
    h = hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()
    return int(h[:15], 16)  # 60 bits, safely < 2^63


def _point_exists(point_id: int) -> bool:
    res = _call("GET", f"collections/{COLLECTION}/points/{point_id}")
    return isinstance(res, dict) and bool(res.get("result"))


def _upsert_doc(text: str, source: str, vuln_class: str, tags: List[str]) -> str:
    """Upsert one knowledge doc. Returns 'ingested' or 'skipped' (idempotent)."""
    text = (text or "").strip()
    if not text:
        return "skipped"
    pid = _hash_id(source, text)
    if _point_exists(pid):
        return "skipped"
    payload = {
        "points": [{
            "id": pid,
            "vector": [0.0],
            "payload": {
                "text": text[:MAX_CHUNK],
                "source": source,
                "tags": tags or [],
                "vuln_class": vuln_class or "other",
                "added_at": datetime.now(timezone.utc).isoformat(),
            },
        }]
    }
    res = _call("PUT", f"collections/{COLLECTION}/points", payload)
    if isinstance(res, dict) and res.get("error"):
        return "error"
    return "ingested"


def _missing(dir_or_file: str) -> dict:
    return {"error": "source not found",
            "hint": f"clone/place into /work/knowledge/ (given: {dir_or_file})"}


def _result(ingested: int, skipped: int, errors: int = 0) -> dict:
    out = {"ingested": ingested, "skipped": skipped, "collection": COLLECTION}
    if errors:
        out["errors"] = errors
    return out


# --- Parsers ---
def _yaml_line(text: str, key: str) -> str:
    """Grab a simple `key: value` from YAML text (no yaml lib, first match)."""
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.+?)\s*$", text, re.MULTILINE)
    if not m:
        return ""
    val = m.group(1).strip().strip('"').strip("'")
    if val in ("|", ">", "|-", ">-", "|+", ">+"):
        return ""  # folded/literal block — skip value capture
    return val


def _split_headings(md: str) -> List[tuple]:
    """Chunk markdown by ## / ### headings -> list of (heading, body)."""
    lines = md.splitlines()
    chunks: List[tuple] = []
    heading = ""
    buf: List[str] = []
    for ln in lines:
        if re.match(r"^#{2,3}\s+", ln):
            if buf and any(b.strip() for b in buf):
                chunks.append((heading, "\n".join(buf).strip()))
            heading = re.sub(r"^#{2,3}\s+", "", ln).strip()
            buf = []
        else:
            buf.append(ln)
    if buf and any(b.strip() for b in buf):
        chunks.append((heading, "\n".join(buf).strip()))
    if not chunks and md.strip():
        chunks.append(("", md.strip()))
    return chunks


def ingest_nuclei(dir_arg: str) -> dict:
    """Walk a nuclei-templates directory and upsert each template."""
    root = Path(dir_arg)
    if not root.exists():
        return _missing(dir_arg)
    ingested = skipped = errors = 0
    try:
        files = list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
        for fp in files:
            try:
                raw = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                errors += 1
                continue
            tid = _yaml_line(raw, "id")
            name = _yaml_line(raw, "name")
            severity = _yaml_line(raw, "severity")
            description = _yaml_line(raw, "description")
            tags_raw = _yaml_line(raw, "tags")
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
            rel = str(fp.relative_to(root))
            vuln_class = infer_vuln_class(tags_raw, name, rel, description)
            text = (f"[{tid}] {name}\nseverity: {severity}\n"
                    f"tags: {tags_raw}\n{description}").strip()
            status = _upsert_doc(text, f"nuclei:{rel}", vuln_class, tags or [tid])
            ingested += status == "ingested"
            skipped += status == "skipped"
            errors += status == "error"
    except Exception as e:
        return {"error": f"nuclei ingest failed: {e}", "ingested": ingested, "skipped": skipped}
    return _result(ingested, skipped, errors)


def ingest_payloads(dir_arg: str) -> dict:
    """Walk a PayloadsAllTheThings-style directory of .md, chunk by heading."""
    root = Path(dir_arg)
    if not root.exists():
        return _missing(dir_arg)
    ingested = skipped = errors = 0
    try:
        for fp in root.rglob("*.md"):
            try:
                md = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                errors += 1
                continue
            rel = fp.relative_to(root)
            top = rel.parts[0] if len(rel.parts) > 1 else fp.stem
            vc = infer_vuln_class(top)
            if vc == "other":
                vc = _slug(top)
            for heading, body in _split_headings(md):
                text = (f"{heading}\n{body}" if heading else body).strip()
                src = f"payloads:{rel}" + (f"#{heading}" if heading else "")
                status = _upsert_doc(text, src, vc, [top])
                ingested += status == "ingested"
                skipped += status == "skipped"
                errors += status == "error"
    except Exception as e:
        return {"error": f"payloads ingest failed: {e}", "ingested": ingested, "skipped": skipped}
    return _result(ingested, skipped, errors)


def ingest_cve(json_file: str) -> dict:
    """Ingest a JSON array of {id, summary, cvss, refs:[]}."""
    fp = Path(json_file)
    if not fp.exists():
        return _missing(json_file)
    try:
        data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        return {"error": f"invalid JSON: {e}", "ingested": 0, "skipped": 0}
    if not isinstance(data, list):
        return {"error": "expected a JSON array of CVE objects", "ingested": 0, "skipped": 0}
    ingested = skipped = errors = 0
    for item in data:
        try:
            cid = str(item.get("id", "")).strip()
            summary = str(item.get("summary", "")).strip()
            cvss = item.get("cvss", "")
            refs = item.get("refs", []) or []
            vc = infer_vuln_class(summary, cid)
            text = (f"{cid}: {summary}\nCVSS: {cvss}\n"
                    f"refs: {', '.join(str(r) for r in refs)}").strip()
            status = _upsert_doc(text, f"cve:{cid}" if cid else json_file, vc,
                                 [cid] if cid else [])
            ingested += status == "ingested"
            skipped += status == "skipped"
            errors += status == "error"
        except Exception:
            errors += 1
    return _result(ingested, skipped, errors)


def ingest_reports(dir_arg: str) -> dict:
    """Walk a directory of disclosed-report markdown, chunk by heading, tag by keyword."""
    root = Path(dir_arg)
    if not root.exists():
        return _missing(dir_arg)
    ingested = skipped = errors = 0
    try:
        for fp in root.rglob("*.md"):
            try:
                md = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                errors += 1
                continue
            rel = fp.relative_to(root)
            for heading, body in _split_headings(md):
                text = (f"{heading}\n{body}" if heading else body).strip()
                vc = infer_vuln_class(heading, body, str(rel))
                src = f"report:{rel}" + (f"#{heading}" if heading else "")
                status = _upsert_doc(text, src, vc, ["disclosed-report"])
                ingested += status == "ingested"
                skipped += status == "skipped"
                errors += status == "error"
    except Exception as e:
        return {"error": f"reports ingest failed: {e}", "ingested": ingested, "skipped": skipped}
    return _result(ingested, skipped, errors)


def _scroll_all(limit: int = 500) -> List[dict]:
    """Scroll all points; prefer rag_client._scroll when available."""
    if _HAVE_RAG:
        try:
            return rag_client._scroll(COLLECTION, limit=limit)
        except Exception:
            pass
    points: List[dict] = []
    offset = None
    while True:
        payload = {"limit": limit, "with_payload": True, "with_vector": False}
        if offset:
            payload["offset"] = offset
        res = _call("POST", f"collections/{COLLECTION}/points/scroll", payload)
        if not isinstance(res, dict) or res.get("error"):
            break
        batch = res.get("result", {}).get("points", [])
        points.extend(batch)
        offset = res.get("result", {}).get("next_page_offset")
        if not offset:
            break
    return points


def search(query: str, limit: int = 5) -> List[dict]:
    """Full-text search kali_knowledge; returns top [{text,source,vuln_class,score}]."""
    query_words = set(re.findall(r"\w+", query.lower()))
    scored = []
    for point in _scroll_all(limit=1000):
        payload = point.get("payload", {})
        text = payload.get("text", "")
        words = set(re.findall(r"\w+", text.lower()))
        score = len(query_words & words)
        if score > 0:
            scored.append((score, {
                "text": text[:400],
                "source": payload.get("source", ""),
                "vuln_class": payload.get("vuln_class", ""),
                "score": score,
            }))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [d for _, d in scored[:limit]]


def stats() -> dict:
    """Return collection point count + breakdown by vuln_class."""
    info = _call("GET", f"collections/{COLLECTION}")
    count = 0
    if isinstance(info, dict):
        count = info.get("result", {}).get("points_count", 0) or 0
    by_class: Dict[str, int] = {}
    for point in _scroll_all(limit=1000):
        vc = point.get("payload", {}).get("vuln_class", "other")
        by_class[vc] = by_class.get(vc, 0) + 1
    return {"collection": COLLECTION, "points": count, "by_vuln_class": by_class}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]
    try:
        if cmd in ("ingest-nuclei", "ingest-payloads", "ingest-reports"):
            if not args:
                print(json.dumps({"error": f"usage: {cmd} <dir>"}))
                sys.exit(1)
            _ensure_collection()
            fn = {"ingest-nuclei": ingest_nuclei,
                  "ingest-payloads": ingest_payloads,
                  "ingest-reports": ingest_reports}[cmd]
            print(json.dumps(fn(args[0]), indent=2))
        elif cmd == "ingest-cve":
            if not args:
                print(json.dumps({"error": "usage: ingest-cve <json_file>"}))
                sys.exit(1)
            _ensure_collection()
            print(json.dumps(ingest_cve(args[0]), indent=2))
        elif cmd == "search":
            if not args:
                print(json.dumps({"error": "usage: search <query> [limit]"}))
                sys.exit(1)
            limit = int(args[1]) if len(args) > 1 else 5
            print(json.dumps(search(args[0], limit), indent=2))
        elif cmd == "stats":
            print(json.dumps(stats(), indent=2))
        else:
            print(json.dumps({"error": f"unknown command: {cmd}"}))
            print(__doc__)
            sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
