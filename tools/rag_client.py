#!/usr/bin/env python3
"""
RAG (Retrieval-Augmented Generation) client for kali-ai.

Uses Qdrant for semantic memory: lessons, writeups, CVEs, and past experiences.
Usage: python3 /tools/rag_client.py <command> [args]
"""

import json
import sys
import time
import uuid
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional

QDRANT_HOST = "http://qdrant:6333"
LESSONS_COLLECTION = "kali_lessons"
KNOWLEDGE_COLLECTION = "kali_knowledge"
MEMORY_DIR = Path("/work/memory")
LESSONS_FILE = MEMORY_DIR / "lessons.jsonl"


def _call(method: str, endpoint: str, data: Optional[dict] = None) -> dict:
    """Call Qdrant API."""
    url = f"{QDRANT_HOST}/{endpoint}"
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")
    if data:
        req.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        return {"error": str(e), "status": "error"}


def create_collection(name: str, vector_size: int = 1) -> dict:
    """Create a Qdrant collection (vector_size=1 for full-text only)."""
    return _call("PUT", f"collections/{name}", {
        "vectors": {"size": vector_size, "distance": "Cosine"},
        "optimizers_config": {"default_segment_number": 2},
        "replication_factor": 1,
    })


def create_fulltext_index(collection: str, field: str) -> dict:
    """Create a full-text index on a field."""
    return _call("PUT", f"collections/{collection}/index", {
        "field_name": field,
        "field_schema": "text",
    })


def create_keyword_index(collection: str, field: str) -> dict:
    """Create a keyword index on a field."""
    return _call("PUT", f"collections/{collection}/index", {
        "field_name": field,
        "field_schema": "keyword",
    })


def create_integer_index(collection: str, field: str) -> dict:
    """Create an integer index on a field."""
    return _call("PUT", f"collections/{collection}/index", {
        "field_name": field,
        "field_schema": "integer",
    })


def setup_collections() -> dict:
    """Set up Qdrant collections with full-text and keyword indexes."""
    results = {}
    for name in [LESSONS_COLLECTION, KNOWLEDGE_COLLECTION]:
        results[f"create_{name}"] = create_collection(name)

        # Full-text indexes for semantic-ish search
        for field in ["task", "outcome", "content", "title", "description"]:
            create_fulltext_index(name, field)

        # Keyword indexes for exact filtering
        for field in ["agent", "status", "category", "tool", "cve", "target"]:
            create_keyword_index(name, field)

        # Integer indexes for numeric filtering
        for field in ["exit_code", "cvss", "year"]:
            create_integer_index(name, field)

    return results


def _scroll(collection: str, filter: Optional[dict] = None, limit: int = 100) -> List[dict]:
    """Scroll all points in a collection."""
    points = []
    offset = None
    while True:
        payload = {"limit": limit, "with_payload": True, "with_vector": False}
        if offset:
            payload["offset"] = offset
        if filter:
            payload["filter"] = filter
        result = _call("POST", f"collections/{collection}/points/scroll", payload)
        if result.get("error"):
            return points
        batch = result.get("result", {}).get("points", [])
        points.extend(batch)
        offset = result.get("result", {}).get("next_page_offset")
        if not offset:
            break
    return points


def upsert_lesson(lesson: Dict[str, Any]) -> dict:
    """Upsert a lesson into the lessons collection."""
    point_id = str(uuid.uuid4())
    payload = {
        "points": [{
            "id": point_id,
            "vector": [0.0],  # dummy vector for full-text only
            "payload": {
                "run_id": lesson.get("run_id"),
                "agent": lesson.get("agent"),
                "model": lesson.get("model"),
                "task": lesson.get("task"),
                "status": lesson.get("status"),
                "exit_code": lesson.get("exit_code", 0),
                "outcome": lesson.get("outcome", ""),
                "tools_used": lesson.get("tools_used", []),
                "evidence_paths": lesson.get("evidence_paths", []),
                "timestamp": lesson.get("timestamp"),
            }
        }]
    }
    return _call("PUT", f"collections/{LESSONS_COLLECTION}/points", payload)


def upsert_knowledge(item: Dict[str, Any]) -> dict:
    """Upsert a knowledge item (writeup, CVE, technique) into the knowledge collection."""
    point_id = str(uuid.uuid4())
    payload = {
        "points": [{
            "id": point_id,
            "vector": [0.0],
            "payload": {
                "title": item.get("title", ""),
                "content": item.get("content", ""),
                "category": item.get("category", ""),  # writeup, cve, technique, tool
                "target": item.get("target", ""),      # service, product, platform
                "cve": item.get("cve", ""),
                "cvss": item.get("cvss", 0),
                "year": item.get("year", 0),
                "source": item.get("source", ""),
                "url": item.get("url", ""),
                "tags": item.get("tags", []),
            }
        }]
    }
    return _call("PUT", f"collections/{KNOWLEDGE_COLLECTION}/points", payload)


def search_lessons(query: str, agent: Optional[str] = None, limit: int = 5) -> List[dict]:
    """Search lessons by task/outcome content and optional agent filter."""
    filter = None
    if agent:
        filter = {"must": [{"key": "agent", "match": {"value": agent}}]}

    # Use scroll with full-text search via Qdrant's query API
    # For simplicity, use scroll and filter in Python for now
    all_lessons = _scroll(LESSONS_COLLECTION, filter=filter, limit=500)

    # Simple keyword scoring
    query_words = set(query.lower().split())
    scored = []
    for point in all_lessons:
        payload = point.get("payload", {})
        text = f"{payload.get('task', '')} {payload.get('outcome', '')} {' '.join(payload.get('tools_used', []))}"
        text_words = set(text.lower().split())
        score = len(query_words & text_words)
        if score > 0:
            scored.append((score, payload))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in scored[:limit]]


def search_knowledge(query: str, category: Optional[str] = None, target: Optional[str] = None, limit: int = 5) -> List[dict]:
    """Search knowledge items by content and optional category/target filter."""
    must = []
    if category:
        must.append({"key": "category", "match": {"value": category}})
    if target:
        must.append({"key": "target", "match": {"value": target}})

    filter = {"must": must} if must else None
    all_items = _scroll(KNOWLEDGE_COLLECTION, filter=filter, limit=500)

    query_words = set(query.lower().split())
    scored = []
    for point in all_items:
        payload = point.get("payload", {})
        text = f"{payload.get('title', '')} {payload.get('content', '')} {' '.join(payload.get('tags', []))}"
        text_words = set(text.lower().split())
        score = len(query_words & text_words)
        if score > 0:
            scored.append((score, payload))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in scored[:limit]]


def ingest_lessons_from_file() -> dict:
    """Ingest all lessons from /work/memory/lessons.jsonl into Qdrant."""
    if not LESSONS_FILE.exists():
        return {"error": "lessons.jsonl not found", "ingested": 0}

    count = 0
    errors = []
    for line in LESSONS_FILE.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            lesson = json.loads(line)
            result = upsert_lesson(lesson)
            if result.get("error"):
                errors.append(result["error"])
            else:
                count += 1
        except Exception as e:
            errors.append(str(e))

    return {"ingested": count, "errors": errors}


def ingest_corpus(corpus_dir: str = "/work/corpus") -> dict:
    """Ingest writeups/CVEs from a corpus directory into Qdrant."""
    corpus = Path(corpus_dir)
    if not corpus.exists():
        return {"error": f"corpus dir not found: {corpus_dir}", "ingested": 0}

    count = 0
    errors = []
    for file_path in corpus.rglob("*.md"):
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            item = {
                "title": file_path.stem,
                "content": content[:10000],  # limit size
                "category": "writeup",
                "source": str(file_path.relative_to(corpus)),
            }
            result = upsert_knowledge(item)
            if result.get("error"):
                errors.append(result["error"])
            else:
                count += 1
        except Exception as e:
            errors.append(str(e))

    return {"ingested": count, "errors": errors}


def get_stats() -> dict:
    """Get collection stats."""
    lessons_info = _call("GET", f"collections/{LESSONS_COLLECTION}")
    knowledge_info = _call("GET", f"collections/{KNOWLEDGE_COLLECTION}")
    return {
        "lessons": lessons_info.get("result", {}),
        "knowledge": knowledge_info.get("result", {}),
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "setup":
        print(json.dumps(setup_collections(), indent=2))
    elif cmd == "ingest-lessons":
        print(json.dumps(ingest_lessons_from_file(), indent=2))
    elif cmd == "ingest-corpus":
        corpus_dir = args[0] if args else "/work/corpus"
        print(json.dumps(ingest_corpus(corpus_dir), indent=2))
    elif cmd == "search-lessons":
        if not args:
            print("Usage: rag_client.py search-lessons <query> [agent] [limit]")
            sys.exit(1)
        agent = args[1] if len(args) > 1 else None
        limit = int(args[2]) if len(args) > 2 else 5
        print(json.dumps(search_lessons(args[0], agent, limit), indent=2))
    elif cmd == "search-knowledge":
        if not args:
            print("Usage: rag_client.py search-knowledge <query> [category] [target] [limit]")
            sys.exit(1)
        category = args[1] if len(args) > 1 else None
        target = args[2] if len(args) > 2 else None
        limit = int(args[3]) if len(args) > 3 else 5
        print(json.dumps(search_knowledge(args[0], category, target, limit), indent=2))
    elif cmd == "stats":
        print(json.dumps(get_stats(), indent=2))
    elif cmd == "upsert-lesson":
        if not args:
            print("Usage: rag_client.py upsert-lesson <json>")
            sys.exit(1)
        print(json.dumps(upsert_lesson(json.loads(args[0])), indent=2))
    elif cmd == "upsert-knowledge":
        if not args:
            print("Usage: rag_client.py upsert-knowledge <json>")
            sys.exit(1)
        print(json.dumps(upsert_knowledge(json.loads(args[0])), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
