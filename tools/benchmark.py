#!/usr/bin/env python3
"""Benchmark replay + precision/recall scoring so capability is a NUMBER.

Replays known-vulnerable targets (DVWA, Juice Shop, VAmPI, Metasploitable2) whose
ground-truth vuln lists are stored in /config/benchmarks/*.json, then scores the
agent's findings.jsonl against ground truth. Every scored run APPENDS a row to
/work/benchmarks/scorecard.jsonl with a UTC timestamp so capability trends over
time and "self-evolving" becomes measurable.

Usage: python3 /tools/benchmark.py <command> [args]

Commands:
  list                                 List available benchmark configs.
  score <benchmark> <findings.jsonl>   Score findings vs ground truth; append row.
  trend [benchmark]                    Per-benchmark f1/recall/precision over time.
  run <benchmark>                      Print the canonical task + target to execute.

Config schema: {name, target, task, base_url, ground_truth:[{id,type,location,severity,note}]}
Match: a ground-truth item is FOUND if some finding shares its type AND its
`location` substring appears in that finding's detail/evidence/endpoint.
STDLIB ONLY.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

CONFIG_DIR = Path("/config/benchmarks")
BENCH_DIR = Path("/work/benchmarks")
SCORECARD = BENCH_DIR / "scorecard.jsonl"


def emit(obj):
    print(json.dumps(obj, indent=2))


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def norm(value):
    return (value or "").strip().lower()


def config_path(name):
    return CONFIG_DIR / f"{name}.json"


def load_config(name):
    path = config_path(name)
    if not path.exists():
        raise FileNotFoundError(f"no benchmark config: {path}")
    return json.loads(path.read_text())


def load_findings(path):
    """Load findings.jsonl (one JSON object per line) or a JSON array."""
    text = Path(path).read_text()
    findings = []
    stripped = text.strip()
    if stripped.startswith("["):
        data = json.loads(stripped)
        if isinstance(data, dict) and "findings" in data:
            data = data["findings"]
        return data if isinstance(data, list) else []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except ValueError:
            continue
    return findings


def finding_haystack(finding):
    """Concatenate the searchable text of a finding for location matching."""
    parts = [
        str(finding.get("detail", "")),
        str(finding.get("endpoint", "")),
        str(finding.get("url", "")),
        str(finding.get("location", "")),
        str(finding.get("title", "")),
    ]
    ev = finding.get("evidence") or []
    if isinstance(ev, str):
        ev = [ev]
    for item in ev:
        if isinstance(item, dict):
            parts.append(json.dumps(item))
        else:
            parts.append(str(item))
    return " ".join(parts).lower()


def cmd_list():
    if not CONFIG_DIR.exists():
        emit({"status": "ok", "benchmarks": []})
        return
    benches = []
    for path in sorted(CONFIG_DIR.glob("*.json")):
        try:
            cfg = json.loads(path.read_text())
            benches.append(
                {
                    "name": cfg.get("name", path.stem),
                    "target": cfg.get("target"),
                    "base_url": cfg.get("base_url"),
                    "ground_truth_count": len(cfg.get("ground_truth", [])),
                }
            )
        except (ValueError, OSError):
            benches.append({"name": path.stem, "error": "unreadable config"})
    emit({"status": "ok", "count": len(benches), "benchmarks": benches})


def score_findings(cfg, findings):
    ground_truth = cfg.get("ground_truth", [])
    gt_types = {norm(g.get("type")) for g in ground_truth}

    matched = []
    missed = []

    # True positives / false negatives: for each ground-truth vuln, is it found?
    matched_finding_keys = set()
    for gt in ground_truth:
        gt_type = norm(gt.get("type"))
        gt_loc = norm(gt.get("location"))
        found = False
        for i, finding in enumerate(findings):
            if norm(finding.get("type")) != gt_type:
                continue
            hay = finding_haystack(finding)
            if gt_loc and gt_loc in hay:
                found = True
                matched_finding_keys.add(i)
                break
        if found:
            matched.append({"id": gt.get("id"), "type": gt_type, "location": gt.get("location")})
        else:
            missed.append(
                {
                    "id": gt.get("id"),
                    "type": gt_type,
                    "location": gt.get("location"),
                    "severity": gt.get("severity"),
                    "note": gt.get("note"),
                }
            )

    # False positives: findings whose TYPE appears nowhere in ground truth
    # (conservative — location mismatch alone is NOT counted as a false positive).
    false_positives = []
    for i, finding in enumerate(findings):
        ftype = norm(finding.get("type"))
        if ftype and ftype not in gt_types:
            false_positives.append(
                {"type": ftype, "title": finding.get("title"), "endpoint": finding.get("endpoint")}
            )

    tp = len(matched)
    fn = len(missed)
    fp = len(false_positives)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "benchmark": cfg.get("name"),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "matched": matched,
        "missed": missed,
        "false_positives": false_positives,
    }


def append_scorecard(result):
    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    row = {
        "ts": now_iso(),
        "benchmark": result["benchmark"],
        "tp": result["tp"],
        "fn": result["fn"],
        "fp": result["fp"],
        "precision": result["precision"],
        "recall": result["recall"],
        "f1": result["f1"],
    }
    with open(SCORECARD, "a") as fh:
        fh.write(json.dumps(row) + "\n")


def cmd_score(name, findings_path):
    cfg = load_config(name)
    findings = load_findings(findings_path)
    result = score_findings(cfg, findings)
    result["findings_scored"] = len(findings)
    append_scorecard(result)
    result["status"] = "ok"
    result["scorecard"] = str(SCORECARD)
    emit(result)


def cmd_trend(name):
    if not SCORECARD.exists():
        emit({"status": "ok", "detail": "no scorecard yet", "trend": {}})
        return
    rows = []
    for line in SCORECARD.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    by_bench = {}
    for row in rows:
        bench = row.get("benchmark")
        if name and bench != name:
            continue
        by_bench.setdefault(bench, []).append(
            {
                "ts": row.get("ts"),
                "f1": row.get("f1"),
                "recall": row.get("recall"),
                "precision": row.get("precision"),
            }
        )
    for series in by_bench.values():
        series.sort(key=lambda r: r.get("ts") or "")
    emit({"status": "ok", "benchmark_filter": name, "trend": by_bench})


def cmd_run(name):
    cfg = load_config(name)
    emit(
        {
            "status": "ok",
            "benchmark": cfg.get("name"),
            "target": cfg.get("target"),
            "base_url": cfg.get("base_url"),
            "task": cfg.get("task"),
            "ground_truth_count": len(cfg.get("ground_truth", [])),
            "next_step": (
                "Have the engagement_runner execute the task above against the "
                "target, then run: benchmark.py score "
                f"{cfg.get('name')} <produced_findings.jsonl>"
            ),
        }
    )


def usage():
    emit({"status": "error", "detail": "usage: benchmark.py <list|score|trend|run> [args]"})


def main():
    args = sys.argv[1:]
    if not args:
        usage()
        return
    cmd = args[0]
    try:
        if cmd == "list":
            cmd_list()
        elif cmd == "score" and len(args) >= 3:
            cmd_score(args[1], args[2])
        elif cmd == "trend":
            cmd_trend(args[1] if len(args) >= 2 else None)
        elif cmd == "run" and len(args) >= 2:
            cmd_run(args[1])
        else:
            usage()
    except FileNotFoundError as exc:
        emit({"status": "error", "detail": str(exc)})
    except ValueError as exc:
        emit({"status": "error", "detail": f"invalid JSON: {exc}"})
    except Exception as exc:  # never leak a stack trace
        emit({"status": "error", "detail": f"{type(exc).__name__}: {exc}"})


if __name__ == "__main__":
    main()
