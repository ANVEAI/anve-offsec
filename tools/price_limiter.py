#!/usr/bin/env python3
"""
Price limiter for kali-ai.

Cost control for conversations by tracking token usage and enforcing price limits.
Inspired by CAI's price limit feature.

Usage: python3 /tools/price_limiter.py <command> [args]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PRICE_FILE = Path("/config/price-limits.json")
USAGE_FILE = Path("/work/memory/price-usage.jsonl")

DEFAULT_PRICE_LIMITS = {
    "enabled": True,
    "limit_usd": 10.0,  # Default $10 per conversation
    "warning_threshold": 0.8,  # Warn at 80% of limit
    "models": {
        "k3": {
            "input_price_per_1k": 0.001,  # $0.001 per 1K input tokens
            "output_price_per_1k": 0.002,  # $0.002 per 1K output tokens
        },
        "kimi-for-coding": {
            "input_price_per_1k": 0.0005,
            "output_price_per_1k": 0.001,
        },
    },
}


def _load_price_limits() -> Dict[str, Any]:
    if not PRICE_FILE.exists():
        return DEFAULT_PRICE_LIMITS
    try:
        return json.loads(PRICE_FILE.read_text())
    except Exception:
        return DEFAULT_PRICE_LIMITS


def _save_price_limits(limits: Dict[str, Any]) -> None:
    PRICE_FILE.write_text(json.dumps(limits, indent=2))


def _load_usage() -> List[Dict[str, Any]]:
    if not USAGE_FILE.exists():
        return []
    usage = []
    try:
        content = USAGE_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return usage
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            usage.append(json.loads(line))
        except Exception:
            continue
    return usage


def _save_usage(entry: Dict[str, Any]) -> None:
    USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with USAGE_FILE.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def record_usage(model: str, input_tokens: int, output_tokens: int, run_id: Optional[str] = None) -> Dict[str, Any]:
    """Record token usage for a model call."""
    limits = _load_price_limits()
    model_config = limits.get("models", {}).get(model, {})

    input_cost = (input_tokens / 1000) * model_config.get("input_price_per_1k", 0.001)
    output_cost = (output_tokens / 1000) * model_config.get("output_price_per_1k", 0.002)
    total_cost = input_cost + output_cost

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "input_cost": round(input_cost, 6),
        "output_cost": round(output_cost, 6),
        "total_cost": round(total_cost, 6),
        "run_id": run_id,
    }
    _save_usage(entry)

    return entry


def get_total_usage(run_id: Optional[str] = None) -> Dict[str, Any]:
    """Get total usage and cost."""
    usage = _load_usage()
    if run_id:
        usage = [u for u in usage if u.get("run_id") == run_id]

    total_input = sum(u.get("input_tokens", 0) for u in usage)
    total_output = sum(u.get("output_tokens", 0) for u in usage)
    total_cost = sum(u.get("total_cost", 0) for u in usage)

    return {
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_cost_usd": round(total_cost, 6),
        "entries": len(usage),
    }


def check_limit(run_id: Optional[str] = None) -> Dict[str, Any]:
    """Check if price limit has been exceeded."""
    limits = _load_price_limits()
    if not limits.get("enabled", True):
        return {"exceeded": False, "reason": "price limits disabled"}

    usage = get_total_usage(run_id)
    limit = limits.get("limit_usd", 10.0)
    warning_threshold = limits.get("warning_threshold", 0.8)
    warning_at = limit * warning_threshold

    total_cost = usage["total_cost_usd"]
    exceeded = total_cost >= limit
    warning = total_cost >= warning_at and not exceeded

    return {
        "exceeded": exceeded,
        "warning": warning,
        "total_cost_usd": total_cost,
        "limit_usd": limit,
        "remaining_usd": round(limit - total_cost, 6),
        "usage": usage,
    }


def set_limit(limit_usd: float) -> Dict[str, Any]:
    """Set the price limit."""
    limits = _load_price_limits()
    limits["limit_usd"] = limit_usd
    _save_price_limits(limits)
    return {"limit_usd": limit_usd}


def set_model_price(model: str, input_price_per_1k: float, output_price_per_1k: float) -> Dict[str, Any]:
    """Set the price for a model."""
    limits = _load_price_limits()
    limits.setdefault("models", {})[model] = {
        "input_price_per_1k": input_price_per_1k,
        "output_price_per_1k": output_price_per_1k,
    }
    _save_price_limits(limits)
    return {"model": model, "input_price_per_1k": input_price_per_1k, "output_price_per_1k": output_price_per_1k}


def enable_limits() -> Dict[str, Any]:
    """Enable price limits."""
    limits = _load_price_limits()
    limits["enabled"] = True
    _save_price_limits(limits)
    return {"enabled": True}


def disable_limits() -> Dict[str, Any]:
    """Disable price limits."""
    limits = _load_price_limits()
    limits["enabled"] = False
    _save_price_limits(limits)
    return {"enabled": False}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "record":
        if len(args) < 3:
            print("Usage: price_limiter.py record <model> <input_tokens> <output_tokens> [run_id]")
            sys.exit(1)
        run_id = args[3] if len(args) > 3 else None
        print(json.dumps(record_usage(args[0], int(args[1]), int(args[2]), run_id), indent=2))
    elif cmd == "usage":
        run_id = args[0] if args else None
        print(json.dumps(get_total_usage(run_id), indent=2))
    elif cmd == "check":
        run_id = args[0] if args else None
        print(json.dumps(check_limit(run_id), indent=2))
    elif cmd == "set-limit":
        if not args:
            print("Usage: price_limiter.py set-limit <limit_usd>")
            sys.exit(1)
        print(json.dumps(set_limit(float(args[0])), indent=2))
    elif cmd == "set-model-price":
        if len(args) < 3:
            print("Usage: price_limiter.py set-model-price <model> <input_price_per_1k> <output_price_per_1k>")
            sys.exit(1)
        print(json.dumps(set_model_price(args[0], float(args[1]), float(args[2])), indent=2))
    elif cmd == "enable":
        print(json.dumps(enable_limits(), indent=2))
    elif cmd == "disable":
        print(json.dumps(disable_limits(), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
