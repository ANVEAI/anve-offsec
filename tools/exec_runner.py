#!/usr/bin/env python3
"""
Structured command executor for kali-ai (Phase 0: shell executor + full output capture).

Runs a shell command, streams the COMPLETE stdout+stderr to a file under
/work/loot/<target>/raw/, and returns a small JSON descriptor referencing that
file by path. This fixes the 8KB tool-output truncation: agents run tools through
this and read the saved file, so large nmap/nuclei/ffuf output is never lost.

Usage:
  python3 /tools/exec_runner.py run <target> <slug> -- <command ...>
  python3 /tools/exec_runner.py run <target> <slug> --timeout 900 -- nmap -sV 10.0.0.1
  python3 /tools/exec_runner.py list <target>
  python3 /tools/exec_runner.py cat <target> <slug>        # print saved output
"""

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LOOT_DIR = Path("/work/loot")
DEFAULT_TIMEOUT = 1800  # per-command safety timeout (seconds)


def _raw_dir(target: str) -> Path:
    d = LOOT_DIR / target / "raw"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _slugify(slug: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", slug).strip("-")
    return slug or "cmd"


def run(target: str, slug: str, command: list, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run a command, capture ALL output to a file, return a descriptor."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = _raw_dir(target) / f"{ts}_{_slugify(slug)}.log"
    start = time.time()
    exit_code = None
    timed_out = False

    header = (
        f"# cmd: {' '.join(command)}\n"
        f"# target: {target}\n"
        f"# started: {datetime.now(timezone.utc).isoformat()}\n"
        f"# timeout: {timeout}s\n\n"
    )
    try:
        with open(out_file, "w") as fh:
            fh.write(header)
            fh.flush()
            proc = subprocess.Popen(
                command,
                stdout=fh,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                proc.wait(timeout=timeout)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                timed_out = True
                exit_code = 124
                fh.write(f"\n\n# TIMEOUT after {timeout}s — process killed\n")
    except FileNotFoundError:
        return {
            "status": "error",
            "error": f"command not found: {command[0] if command else '?'}",
            "target": target,
            "slug": slug,
        }
    except Exception as e:  # noqa: BLE001 - report, never crash the caller
        return {"status": "error", "error": str(e), "target": target, "slug": slug}

    duration = round(time.time() - start, 2)
    size = out_file.stat().st_size if out_file.exists() else 0
    return {
        "status": "ok",
        "target": target,
        "slug": slug,
        "cmd": command,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_s": duration,
        "output_file": str(out_file),
        "output_bytes": size,
        "truncated": False,  # full output is on disk; nothing dropped
    }


def list_outputs(target: str) -> dict:
    d = LOOT_DIR / target / "raw"
    if not d.exists():
        return {"target": target, "outputs": []}
    outputs = [
        {"file": str(p), "bytes": p.stat().st_size}
        for p in sorted(d.glob("*.log"))
    ]
    return {"target": target, "count": len(outputs), "outputs": outputs}


def cat_output(target: str, slug: str) -> str:
    d = LOOT_DIR / target / "raw"
    if not d.exists():
        return ""
    matches = sorted(d.glob(f"*{_slugify(slug)}*.log"))
    if not matches:
        return ""
    return matches[-1].read_text(errors="replace")


def _split_argv(argv: list):
    """Split CLI args at the '--' sentinel into (opts_before, command_after)."""
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)

    cmd = args[0]
    rest = args[1:]

    if cmd == "run":
        opts, command = _split_argv(rest)
        if len(opts) < 2 or not command:
            print(json.dumps({"error": "usage: run <target> <slug> [--timeout N] -- <command...>"}))
            sys.exit(1)
        target, slug = opts[0], opts[1]
        timeout = DEFAULT_TIMEOUT
        if "--timeout" in opts:
            try:
                timeout = int(opts[opts.index("--timeout") + 1])
            except (ValueError, IndexError):
                pass
        print(json.dumps(run(target, slug, command, timeout), indent=2))
    elif cmd == "list":
        if not rest:
            print(json.dumps({"error": "usage: list <target>"}))
            sys.exit(1)
        print(json.dumps(list_outputs(rest[0]), indent=2))
    elif cmd == "cat":
        if len(rest) < 2:
            print(json.dumps({"error": "usage: cat <target> <slug>"}))
            sys.exit(1)
        sys.stdout.write(cat_output(rest[0], rest[1]))
    else:
        print(json.dumps({"error": f"unknown command: {cmd}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
