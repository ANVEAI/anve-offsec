#!/usr/bin/env python3
"""
kali-ai dashboard — browser control plane for specialized offensive-security agents.

Serves a single-page UI + JSON API to launch agent runs, stream live logs,
browse evidence, and view reports. Inspired by PentAGI's flow/task/action
tracking, adapted to Hermes + OpenClaw.
"""

import json
import os
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

APP_DIR = Path("/dashboard")
WORK_DIR = Path("/work")
LOOT_DIR = WORK_DIR / "loot"
REPORTS_DIR = WORK_DIR / "reports"
RUNS_DIR = WORK_DIR / "dashboard-logs"
AGENTS_DIR = Path("/agents")
SCRIPTS_DIR = Path("/scripts")
OPENCLAW_URL = os.getenv("OPENCLAW_DASHBOARD_URL", "http://127.0.0.1:18789")

app = FastAPI(title="kali-ai control plane")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

# In-memory run registry (also persisted per-run to /work/dashboard-logs/<run_id>.json)
RUNS: Dict[str, Dict[str, Any]] = {}


def _ensure_dirs() -> None:
    for p in (LOOT_DIR, REPORTS_DIR, RUNS_DIR):
        p.mkdir(parents=True, exist_ok=True)


def _load_agents() -> List[Dict[str, str]]:
    agents = []
    if not AGENTS_DIR.exists():
        return agents
    # Support nested agent paths: mitre/recon, owasp/injection, research/osint
    for p in sorted(AGENTS_DIR.rglob("*.prompt")):
        rel = p.relative_to(AGENTS_DIR)
        name = str(rel.with_suffix(""))
        category = rel.parts[0] if len(rel.parts) > 1 else "core"
        agents.append({
            "name": name,
            "file": p.name,
            "category": category,
            "description": (p.read_text().splitlines()[0] if p.read_text().splitlines() else "").strip("# "),
        })
    return agents


def _read_lessons(limit: int = 50) -> List[Dict[str, Any]]:
    lessons_file = WORK_DIR / "memory" / "lessons.jsonl"
    if not lessons_file.exists():
        return []
    lessons = []
    try:
        content = lessons_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        # File may be locked by another process writing to it
        return lessons
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            lessons.append(json.loads(line))
        except Exception:
            continue
    return lessons[-limit:]


def _read_patterns() -> Dict[str, Any]:
    patterns_file = WORK_DIR / "memory" / "patterns.json"
    if not patterns_file.exists():
        return {}
    try:
        return json.loads(patterns_file.read_text())
    except Exception:
        return {}


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2))


def _tail_file(path: Path, max_bytes: int = 4096) -> str:
    if not path.exists() or not path.is_file():
        return ""
    size = path.stat().st_size
    with path.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        data = f.read()
    return data.decode("utf-8", errors="replace")


def _stream_lines(path: Path, last_pos: int = 0):
    """Yield (pos, line) pairs starting from last_pos."""
    if not path.exists():
        return last_pos, []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(last_pos)
        lines = f.readlines()
        new_pos = f.tell()
    return new_pos, lines


def _simple_loop_detector(lines: List[str]) -> List[str]:
    """PentAGI-style loop detection: warn on repeated commands or repeated errors."""
    warnings = []
    cmd_counts: Dict[str, int] = {}
    err_counts: Dict[str, int] = {}
    cmd_re = re.compile(r"(?:\$ |Command:|`)([^\n`$]{4,200})")
    err_re = re.compile(r"(?:Error|Exception|failed|FAILED|Traceback)", re.IGNORECASE)
    for line in lines:
        m = cmd_re.search(line)
        if m:
            cmd = m.group(1).strip()
            cmd_counts[cmd] = cmd_counts.get(cmd, 0) + 1
        if err_re.search(line):
            key = line.strip()[:120]
            err_counts[key] = err_counts.get(key, 0) + 1
    for cmd, count in cmd_counts.items():
        if count >= 3:
            warnings.append(f"possible loop: command repeated {count}x — {cmd[:80]}")
    for err, count in err_counts.items():
        if count >= 3:
            warnings.append(f"possible failure loop: error repeated {count}x — {err[:80]}")
    return warnings


def _model_for_agent(agent: str) -> str:
    models_file = AGENTS_DIR / "models.json"
    if models_file.exists():
        try:
            data = json.loads(models_file.read_text())
            return data.get(agent, data.get("default", "k3"))
        except Exception:
            pass
    return "k3"


class RunRequest(BaseModel):
    task: str


class AuthTargetRequest(BaseModel):
    domain: str
    type: str = "self"
    notes: str = ""


class AuthCheckRequest(BaseModel):
    target: str
    override: bool = False
    confirm_text: str = ""


class AuthImportRequest(BaseModel):
    platform: str
    scope: List[Dict[str, Any]]


@app.on_event("startup")
async def startup() -> None:
    _ensure_dirs()
    # Restore any existing runs
    for state_file in RUNS_DIR.glob("*.json"):
        state = _read_json(state_file)
        if state.get("run_id"):
            RUNS[state["run_id"]] = state


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("simple.html", {
        "request": request,
        "agents": _load_agents(),
        "openclaw_url": OPENCLAW_URL,
    })


@app.get("/classic", response_class=HTMLResponse)
async def classic(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "agents": _load_agents(),
        "openclaw_url": OPENCLAW_URL,
    })


@app.get("/api/agents")
async def list_agents():
    return {"agents": _load_agents()}


@app.get("/api/runs")
async def list_runs():
    # refresh from disk to catch out-of-band writes
    for state_file in RUNS_DIR.glob("*.json"):
        state = _read_json(state_file)
        if state.get("run_id"):
            RUNS[state["run_id"]] = state
    runs = sorted(RUNS.values(), key=lambda r: r.get("started_at", ""), reverse=True)
    return {"runs": runs}


@app.post("/api/agents/{agent_name:path}/run")
async def launch_agent(agent_name: str, req: RunRequest):
    task = req.task.strip()
    if not task:
        raise HTTPException(400, "task is required")
    prompt_file = AGENTS_DIR / f"{agent_name}.prompt"
    if not prompt_file.exists():
        raise HTTPException(404, f"unknown agent: {agent_name}")

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    log_file = RUNS_DIR / f"{run_id}.log"
    state_file = RUNS_DIR / f"{run_id}.json"

    model = _model_for_agent(agent_name)
    state = {
        "run_id": run_id,
        "agent": agent_name,
        "model": model,
        "task": task,
        "status": "queued",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "log_file": str(log_file),
    }
    _write_json(state_file, state)
    RUNS[run_id] = state

    # Launch in background via Popen so the HTTP request returns immediately
    env = os.environ.copy()
    env["RUN_ID"] = run_id
    cmd = [str(SCRIPTS_DIR / "internal-agent.sh"), agent_name, task]
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        state["pid"] = proc.pid
        _write_json(state_file, state)
        RUNS[run_id] = state
    except Exception as e:
        state["status"] = "failed"
        state["error"] = str(e)
        _write_json(state_file, state)
        RUNS[run_id] = state
        raise HTTPException(500, f"failed to launch agent: {e}")

    return {"run_id": run_id, "status": "queued"}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str):
    state_file = RUNS_DIR / f"{run_id}.json"
    if not state_file.exists():
        raise HTTPException(404, "run not found")
    state = _read_json(state_file)
    log_file = Path(state.get("log_file", ""))
    state["tail"] = _tail_file(log_file, 8192)
    return state


@app.get("/api/runs/{run_id}/stream")
async def stream_run(run_id: str, request: Request):
    state_file = RUNS_DIR / f"{run_id}.json"
    if not state_file.exists():
        raise HTTPException(404, "run not found")
    state = _read_json(state_file)
    log_file = Path(state.get("log_file", ""))

    async def event_stream():
        last_pos = 0
        while True:
            if await request.is_disconnected():
                break
            # refresh state to detect completion
            cur_state = _read_json(state_file)
            status = cur_state.get("status", "unknown")
            last_pos, lines = _stream_lines(log_file, last_pos)
            for line in lines:
                yield f"data: {json.dumps({'line': line.rstrip()})}\n\n"
            if status in ("done", "failed"):
                yield f"data: {json.dumps({'status': status, 'exit_code': cur_state.get('exit_code')})}\n\n"
                # keep streaming briefly so client can close gracefully
                for _ in range(2):
                    await asyncio.sleep(0.5)
                    last_pos, lines = _stream_lines(log_file, last_pos)
                    for line in lines:
                        yield f"data: {json.dumps({'line': line.rstrip()})}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/runs/{run_id}/supervise")
async def supervise_run(run_id: str):
    state_file = RUNS_DIR / f"{run_id}.json"
    if not state_file.exists():
        raise HTTPException(404, "run not found")
    state = _read_json(state_file)
    log_file = Path(state.get("log_file", ""))
    lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines() if log_file.exists() else []
    warnings = _simple_loop_detector(lines)
    return {"run_id": run_id, "status": state.get("status"), "warnings": warnings}


@app.get("/api/loot")
async def list_loot(path: str = ""):
    root = LOOT_DIR / path
    if not root.exists() or not root.is_dir():
        raise HTTPException(404, "loot path not found")
    items = []
    for p in sorted(root.iterdir(), key=lambda x: (x.is_file(), x.name)):
        rel = p.relative_to(LOOT_DIR)
        items.append({
            "name": p.name,
            "path": str(rel),
            "is_dir": p.is_dir(),
            "size": p.stat().st_size if p.is_file() else None,
            "modified": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(),
        })
    return {"path": path, "items": items}


@app.get("/api/loot/file")
async def get_loot_file(path: str):
    target = LOOT_DIR / path
    if not target.exists() or not target.is_file():
        raise HTTPException(404, "file not found")
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except UnicodeDecodeError:
        content = f"[binary file: {target.stat().st_size} bytes]"
    return PlainTextResponse(content)


@app.get("/api/reports")
async def list_reports():
    if not REPORTS_DIR.exists():
        return {"reports": []}
    reports = []
    for p in sorted(REPORTS_DIR.glob("*.md"), key=lambda x: x.stat().st_mtime, reverse=True):
        reports.append({
            "name": p.name,
            "path": str(p.relative_to(REPORTS_DIR)),
            "size": p.stat().st_size,
            "modified": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(),
        })
    return {"reports": reports}


@app.get("/api/reports/{name}")
async def get_report(name: str):
    target = REPORTS_DIR / name
    if not target.exists() or not target.is_file():
        raise HTTPException(404, "report not found")
    return PlainTextResponse(target.read_text(encoding="utf-8", errors="replace"))


@app.get("/api/memory/lessons")
async def get_lessons(limit: int = 50):
    return {"lessons": _read_lessons(limit)}


@app.get("/api/memory/patterns")
async def get_patterns():
    return {"patterns": _read_patterns()}


@app.get("/api/memory/stats")
async def get_memory_stats():
    lessons = _read_lessons(1000)
    patterns = _read_patterns()
    return {
        "total_lessons": len(lessons),
        "patterns": patterns,
        "agents_with_lessons": len({l.get("agent") for l in lessons if l.get("agent")}),
        "success_rate": round(len([l for l in lessons if l.get("status") == "done"]) / max(len(lessons), 1) * 100, 1),
    }


@app.get("/api/rag/search")
async def rag_search(q: str, agent: Optional[str] = None, limit: int = 5):
    """Search past lessons via RAG (Qdrant)."""
    if not q.strip():
        raise HTTPException(400, "query is required")
    try:
        result = subprocess.run(
            ["python3", "/tools/rag_client.py", "search-lessons", q, agent or "", str(limit)],
            capture_output=True, text=True, timeout=30
        )
        return {"query": q, "agent": agent, "lessons": json.loads(result.stdout)}
    except Exception as e:
        return {"query": q, "agent": agent, "lessons": [], "error": str(e)}


@app.get("/api/rag/knowledge")
async def rag_knowledge(q: str, category: Optional[str] = None, target: Optional[str] = None, limit: int = 5):
    """Search knowledge base via RAG (Qdrant)."""
    if not q.strip():
        raise HTTPException(400, "query is required")
    try:
        result = subprocess.run(
            ["python3", "/tools/rag_client.py", "search-knowledge", q, category or "", target or "", str(limit)],
            capture_output=True, text=True, timeout=30
        )
        return {"query": q, "category": category, "target": target, "items": json.loads(result.stdout)}
    except Exception as e:
        return {"query": q, "category": category, "target": target, "items": [], "error": str(e)}


@app.post("/api/rag/ingest")
async def rag_ingest():
    """Re-ingest lessons and corpus into Qdrant."""
    try:
        lessons_result = subprocess.run(
            ["python3", "/tools/rag_client.py", "ingest-lessons"],
            capture_output=True, text=True, timeout=60
        )
        corpus_result = subprocess.run(
            ["python3", "/tools/rag_client.py", "ingest-corpus", "/work/corpus"],
            capture_output=True, text=True, timeout=60
        )
        return {
            "lessons": json.loads(lessons_result.stdout),
            "corpus": json.loads(corpus_result.stdout),
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/evolution/strategy")
async def get_strategy():
    """Get the current strategy memory."""
    strategy_file = WORK_DIR / "memory" / "strategy.json"
    if not strategy_file.exists():
        return {"scenarios": {}, "target_profiles": {}, "tool_effectiveness": {}, "next_step_suggestions": {}}
    try:
        return json.loads(strategy_file.read_text())
    except Exception:
        return {"scenarios": {}, "target_profiles": {}, "tool_effectiveness": {}, "next_step_suggestions": {}}


@app.get("/api/evolution/guidance")
async def get_guidance(task: str, agent: Optional[str] = None):
    """Get strategy guidance for a task/agent."""
    try:
        result = subprocess.run(
            ["python3", "/tools/evolution_engine.py", "guidance", task, agent or ""],
            capture_output=True, text=True, timeout=30
        )
        return {"task": task, "agent": agent, "guidance": result.stdout.strip()}
    except Exception as e:
        return {"task": task, "agent": agent, "guidance": "", "error": str(e)}


@app.get("/api/evolution/scenario")
async def get_scenario(task: str, agent: Optional[str] = None):
    """Extract scenario from a task/agent."""
    try:
        result = subprocess.run(
            ["python3", "/tools/evolution_engine.py", "scenario", task, agent or ""],
            capture_output=True, text=True, timeout=30
        )
        return {"task": task, "agent": agent, "scenario": result.stdout.strip()}
    except Exception as e:
        return {"task": task, "agent": agent, "scenario": "unknown", "error": str(e)}


@app.post("/api/evolution/deep-review")
async def run_deep_review():
    """Run a deep review evolution cycle."""
    try:
        result = subprocess.run(
            ["python3", "/tools/evolution_engine.py", "deep-review"],
            capture_output=True, text=True, timeout=120
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/evolution/log")
async def get_evolution_log(limit: int = 100):
    """Get the evolution log."""
    log_file = WORK_DIR / "memory" / "evolution.log"
    if not log_file.exists():
        return {"log": []}
    try:
        lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        return {"log": lines[-limit:]}
    except Exception:
        return {"log": []}


@app.get("/api/auth/targets")
async def list_auth_targets():
    """List all authorized targets."""
    try:
        result = subprocess.run(
            ["python3", "/tools/auth_checker.py", "list"],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/auth/targets")
async def add_auth_target(req: AuthTargetRequest):
    """Add an authorized target."""
    domain = req.domain.strip()
    auth_type = req.type.strip()
    notes = req.notes.strip()
    if not domain:
        raise HTTPException(400, "domain is required")
    try:
        result = subprocess.run(
            ["python3", "/tools/auth_checker.py", "add", domain, auth_type, notes],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


@app.delete("/api/auth/targets/{domain}")
async def remove_auth_target(domain: str):
    """Remove an authorized target."""
    try:
        result = subprocess.run(
            ["python3", "/tools/auth_checker.py", "remove", domain],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/auth/check")
async def check_auth(target: str):
    """Check if a target is authorized."""
    try:
        result = subprocess.run(
            ["python3", "/tools/auth_checker.py", "check", target],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/auth/check")
async def check_auth_with_override(req: AuthCheckRequest):
    """Check if a target is authorized, with optional override confirmation."""
    target = req.target.strip()
    override = req.override
    confirm_text = req.confirm_text.strip()
    if not target:
        raise HTTPException(400, "target is required")
    try:
        cmd = ["python3", "/tools/auth_checker.py", "check", target]
        if override:
            cmd.append("--override")
            if confirm_text:
                cmd.extend(["--confirm-text", confirm_text])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/auth/import")
async def import_bug_bounty_scope(req: AuthImportRequest):
    """Import bug bounty scope from a platform."""
    platform = req.platform.strip()
    scope_data = req.scope
    if not platform:
        raise HTTPException(400, "platform is required")
    try:
        # Write scope to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(scope_data, f)
            temp_path = f.name
        result = subprocess.run(
            ["python3", "/tools/auth_checker.py", "import", platform, temp_path],
            capture_output=True, text=True, timeout=30
        )
        import os
        os.unlink(temp_path)
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


class VpnConnectRequest(BaseModel):
    name: str
    content: str


class VpnSaveRequest(BaseModel):
    name: str
    content: str


class ContinueRequest(BaseModel):
    instructions: str


class FeedbackRequest(BaseModel):
    message: str


@app.get("/api/vpn/status")
async def vpn_status():
    """Get VPN connection status."""
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "vpn"],
            capture_output=True, text=True, timeout=10
        )
        status = "connected" if "Up" in result.stdout else "disconnected"
        return {"status": status, "output": result.stdout}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/api/vpn/connections")
async def vpn_connections():
    """List all VPN connections."""
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "vpn"],
            capture_output=True, text=True, timeout=10
        )
        connections = []
        if "Up" in result.stdout:
            connections.append({
                "name": "default",
                "status": "connected",
                "remote_ip": "10.10.10.1",
            })
        return {"connections": connections}
    except Exception as e:
        return {"connections": [], "error": str(e)}


@app.post("/api/vpn/connect")
async def vpn_connect(req: VpnConnectRequest):
    """Connect to a VPN profile."""
    try:
        # Save the profile and start the vpn service
        vpn_dir = Path("/vpn")
        vpn_dir.mkdir(exist_ok=True)
        profile_path = vpn_dir / "active.ovpn"
        profile_path.write_text(req.content)

        result = subprocess.run(
            ["docker", "compose", "up", "-d", "vpn"],
            capture_output=True, text=True, timeout=30
        )
        return {"status": "connecting", "profile": req.name, "output": result.stdout}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/vpn/disconnect")
async def vpn_disconnect():
    """Disconnect from VPN."""
    try:
        result = subprocess.run(
            ["docker", "compose", "stop", "vpn"],
            capture_output=True, text=True, timeout=30
        )
        return {"status": "disconnected", "output": result.stdout}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/vpn/disconnect/{name}")
async def vpn_disconnect_name(name: str):
    """Disconnect a specific VPN connection."""
    try:
        result = subprocess.run(
            ["docker", "compose", "stop", "vpn"],
            capture_output=True, text=True, timeout=30
        )
        return {"status": "disconnected", "name": name, "output": result.stdout}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/vpn/save")
async def vpn_save(req: VpnSaveRequest):
    """Save a VPN profile."""
    try:
        vpn_dir = Path("/vpn")
        vpn_dir.mkdir(exist_ok=True)
        profile_path = vpn_dir / f"{req.name}.ovpn"
        profile_path.write_text(req.content)
        return {"status": "saved", "name": req.name, "path": str(profile_path)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/api/runs/{run_id}/findings")
async def get_run_findings(run_id: str, limit: int = 100):
    """Get real-time findings for a run."""
    try:
        result = subprocess.run(
            ["python3", "/tools/stream_manager.py", "get-findings", run_id, str(limit)],
            capture_output=True, text=True, timeout=30
        )
        return {"run_id": run_id, "findings": json.loads(result.stdout)}
    except Exception as e:
        return {"run_id": run_id, "findings": [], "error": str(e)}


@app.post("/api/runs/{run_id}/findings")
async def share_run_finding(run_id: str, req: dict):
    """Share a finding from the agent to the dashboard."""
    finding_type = req.get("type", "discovery")
    title = req.get("title", "")
    detail = req.get("detail", "")
    severity = req.get("severity", "info")
    evidence = req.get("evidence", [])
    try:
        result = subprocess.run(
            ["python3", "/tools/stream_manager.py", "share-finding", run_id, finding_type, title, detail, severity, ",".join(evidence)],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/runs/{run_id}/instructions")
async def get_run_instructions(run_id: str):
    """Get pending instructions for a run."""
    try:
        result = subprocess.run(
            ["python3", "/tools/stream_manager.py", "pending", run_id],
            capture_output=True, text=True, timeout=30
        )
        return {"run_id": run_id, "instructions": json.loads(result.stdout)}
    except Exception as e:
        return {"run_id": run_id, "instructions": [], "error": str(e)}


@app.post("/api/runs/{run_id}/instructions")
async def inject_run_instruction(run_id: str, req: dict):
    """Inject an instruction for the agent to see on its next turn."""
    instruction = req.get("instruction", "").strip()
    priority = req.get("priority", "normal")
    if not instruction:
        raise HTTPException(400, "instruction is required")
    try:
        result = subprocess.run(
            ["python3", "/tools/stream_manager.py", "inject", run_id, instruction, priority],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/runs/{run_id}/continuation-context")
async def get_continuation_context(run_id: str):
    """Get full context for a high-quality continuation."""
    try:
        result = subprocess.run(
            ["python3", "/tools/stream_manager.py", "continuation-context", run_id],
            capture_output=True, text=True, timeout=30
        )
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/runs/{run_id}/continue")
async def continue_run(run_id: str, req: ContinueRequest):
    """Continue a run with additional instructions."""
    state_file = RUNS_DIR / f"{run_id}.json"
    if not state_file.exists():
        raise HTTPException(404, "run not found")
    state = _read_json(state_file)

    # Create a new run with the same agent + task + high-quality continuation context
    continue_run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_continue_{uuid.uuid4().hex[:8]}"
    continue_log = RUNS_DIR / f"{continue_run_id}.log"
    continue_state_file = RUNS_DIR / f"{continue_run_id}.json"

    original_task = state.get("task", "")

    # Get full continuation context for high-quality continuation
    context = {}
    try:
        context_result = subprocess.run(
            ["python3", "/tools/stream_manager.py", "continuation-context", run_id],
            capture_output=True, text=True, timeout=30
        )
        context = json.loads(context_result.stdout)
    except Exception:
        pass

    # Build high-quality continuation task with full context
    context_parts = [f"Continue from where you left off. Previous run ID: {run_id}. Original task: {original_task}."]

    if context.get("completed_steps"):
        context_parts.append(f"Completed steps: {', '.join(context['completed_steps'])}.")
    if context.get("discoveries"):
        discoveries_str = '; '.join([f"{d.get('title', '')}: {d.get('detail', '')}" for d in context['discoveries'][:5]])
        context_parts.append(f"Discoveries so far: {discoveries_str}.")
    if context.get("vulnerabilities"):
        vulns_str = '; '.join([f"{v.get('title', '')}: {v.get('detail', '')}" for v in context['vulnerabilities'][:5]])
        context_parts.append(f"Vulnerabilities found: {vulns_str}.")
    if context.get("errors"):
        errors_str = '; '.join([f"{e.get('title', '')}: {e.get('detail', '')}" for e in context['errors'][:3]])
        context_parts.append(f"Errors encountered: {errors_str}.")
    if context.get("pending_instructions"):
        instructions_str = '; '.join([i.get('instruction', '') for i in context['pending_instructions']])
        context_parts.append(f"User instructions: {instructions_str}.")

    context_parts.append(f"Additional instructions: {req.instructions}")
    continue_task = " ".join(context_parts)

    model = _model_for_agent(state.get("agent", ""))
    continue_state = {
        "run_id": continue_run_id,
        "agent": state.get("agent"),
        "model": model,
        "task": continue_task,
        "status": "queued",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "log_file": str(continue_log),
        "parent_run_id": run_id,
        "is_continuation": True,
    }
    _write_json(continue_state_file, continue_state)
    RUNS[continue_run_id] = continue_state

    env = os.environ.copy()
    env["RUN_ID"] = continue_run_id
    env["ENGAGEMENT_RESUME_FROM"] = run_id
    cmd = [str(SCRIPTS_DIR / "internal-agent.sh"), state.get("agent", ""), continue_task]
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        continue_state["pid"] = proc.pid
        _write_json(continue_state_file, continue_state)
        RUNS[continue_run_id] = continue_state
    except Exception as e:
        continue_state["status"] = "failed"
        continue_state["error"] = str(e)
        _write_json(continue_state_file, continue_state)
        RUNS[continue_run_id] = continue_state
        raise HTTPException(500, f"failed to continue run: {e}")

    return {"run_id": continue_run_id, "status": "queued", "parent_run_id": run_id}


@app.post("/api/runs/{run_id}/feedback")
async def feedback_run(run_id: str, req: FeedbackRequest):
    """Send feedback/instructions to a running agent."""
    state_file = RUNS_DIR / f"{run_id}.json"
    if not state_file.exists():
        raise HTTPException(404, "run not found")
    state = _read_json(state_file)

    if state.get("status") != "running":
        return {"error": f"run is not running (status: {state.get('status')})", "run_id": run_id}

    # Write feedback to a file that the running agent can read
    feedback_dir = RUNS_DIR / f"{run_id}_feedback"
    feedback_dir.mkdir(exist_ok=True)
    feedback_file = feedback_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.txt"
    feedback_file.write_text(req.message)

    return {
        "run_id": run_id,
        "status": "feedback_sent",
        "feedback_file": str(feedback_file),
        "message": req.message[:100],
    }


@app.get("/api/runs/{run_id}/feedback")
async def get_run_feedback(run_id: str):
    """Get feedback messages for a run."""
    feedback_dir = RUNS_DIR / f"{run_id}_feedback"
    if not feedback_dir.exists():
        return {"run_id": run_id, "feedback": []}
    feedback = []
    for path in sorted(feedback_dir.glob("*.txt")):
        try:
            feedback.append({
                "file": path.name,
                "content": path.read_text(encoding="utf-8", errors="replace"),
                "timestamp": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            })
        except Exception:
            continue
    return {"run_id": run_id, "feedback": feedback}


@app.post("/api/runs/{run_id}/reflect")
async def reflect_run(run_id: str):
    state_file = RUNS_DIR / f"{run_id}.json"
    if not state_file.exists():
        raise HTTPException(404, "run not found")
    state = _read_json(state_file)
    log_file = Path(state.get("log_file", ""))
    if not log_file.exists():
        raise HTTPException(404, "run log not found")

    # Launch the reflect agent with the run log as context
    task = f"Analyze the failed/suboptimal run below and produce a corrected plan + lessons.\n\nOriginal agent: {state.get('agent')}\nOriginal task: {state.get('task')}\nFinal status: {state.get('status')}\n\nRun log:\n{_tail_file(log_file, 6000)}"
    reflect_run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_reflect_{uuid.uuid4().hex[:8]}"
    reflect_log = RUNS_DIR / f"{reflect_run_id}.log"
    reflect_state_file = RUNS_DIR / f"{reflect_run_id}.json"

    model = _model_for_agent("reflect")
    reflect_state = {
        "run_id": reflect_run_id,
        "agent": "reflect",
        "model": model,
        "task": task,
        "status": "queued",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "log_file": str(reflect_log),
        "parent_run_id": run_id,
    }
    _write_json(reflect_state_file, reflect_state)
    RUNS[reflect_run_id] = reflect_state

    env = os.environ.copy()
    env["RUN_ID"] = reflect_run_id
    cmd = [str(SCRIPTS_DIR / "internal-agent.sh"), "reflect", task]
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        reflect_state["pid"] = proc.pid
        _write_json(reflect_state_file, reflect_state)
        RUNS[reflect_run_id] = reflect_state
    except Exception as e:
        reflect_state["status"] = "failed"
        reflect_state["error"] = str(e)
        _write_json(reflect_state_file, reflect_state)
        RUNS[reflect_run_id] = reflect_state
        raise HTTPException(500, f"failed to launch reflect agent: {e}")

    return {"run_id": reflect_run_id, "status": "queued", "parent_run_id": run_id}


@app.post("/api/curate")
async def curate_memory():
    # Launch the curator agent to review and improve memory
    task = "Review /work/memory/lessons.jsonl and /work/memory/patterns.json. Merge duplicate lessons, promote high-value patterns, and suggest agent prompt improvements. Save curation report under /work/memory/curations/."
    curate_run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_curator_{uuid.uuid4().hex[:8]}"
    curate_log = RUNS_DIR / f"{curate_run_id}.log"
    curate_state_file = RUNS_DIR / f"{curate_run_id}.json"

    model = _model_for_agent("curator")
    curate_state = {
        "run_id": curate_run_id,
        "agent": "curator",
        "model": model,
        "task": task,
        "status": "queued",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "log_file": str(curate_log),
    }
    _write_json(curate_state_file, curate_state)
    RUNS[curate_run_id] = curate_state

    env = os.environ.copy()
    env["RUN_ID"] = curate_run_id
    cmd = [str(SCRIPTS_DIR / "internal-agent.sh"), "curator", task]
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        curate_state["pid"] = proc.pid
        _write_json(curate_state_file, curate_state)
        RUNS[curate_run_id] = curate_state
    except Exception as e:
        curate_state["status"] = "failed"
        curate_state["error"] = str(e)
        _write_json(curate_state_file, curate_state)
        RUNS[curate_run_id] = curate_state
        raise HTTPException(500, f"failed to launch curator agent: {e}")

    return {"run_id": curate_run_id, "status": "queued"}


class WorkflowRequest(BaseModel):
    agents: List[Dict[str, str]]  # [{"agent": "recon", "task": "..."}, ...]


class ChainRequest(BaseModel):
    steps: List[Dict[str, str]]  # [{"agent": "recon", "task": "..."}, ...]
    target: str


def _launch_agent_background(agent_name: str, task: str) -> Dict[str, Any]:
    """Launch an agent in the background and return its run state."""
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    log_file = RUNS_DIR / f"{run_id}.log"
    state_file = RUNS_DIR / f"{run_id}.json"

    model = _model_for_agent(agent_name)
    state = {
        "run_id": run_id,
        "agent": agent_name,
        "model": model,
        "task": task,
        "status": "queued",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "log_file": str(log_file),
    }
    _write_json(state_file, state)
    RUNS[run_id] = state

    env = os.environ.copy()
    env["RUN_ID"] = run_id
    cmd = [str(SCRIPTS_DIR / "internal-agent.sh"), agent_name, task]
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        state["pid"] = proc.pid
        _write_json(state_file, state)
        RUNS[run_id] = state
    except Exception as e:
        state["status"] = "failed"
        state["error"] = str(e)
        _write_json(state_file, state)
        RUNS[run_id] = state

    return state


@app.post("/api/workflow/parallel")
async def run_parallel_workflow(req: WorkflowRequest):
    """Launch multiple agents concurrently (subagent parallelism)."""
    if not req.agents:
        raise HTTPException(400, "agents list is required")

    workflow_id = f"wf_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    runs = []
    for item in req.agents:
        agent = item.get("agent", "").strip()
        task = item.get("task", "").strip()
        if not agent or not task:
            continue
        state = _launch_agent_background(agent, task)
        state["workflow_id"] = workflow_id
        runs.append(state)

    return {"workflow_id": workflow_id, "runs": runs, "mode": "parallel"}


@app.post("/api/workflow/chain")
async def run_chain_workflow(req: ChainRequest):
    """Launch agents sequentially in a chain (e.g. recon → web → exploit → report)."""
    if not req.steps:
        raise HTTPException(400, "steps list is required")
    if not req.target:
        raise HTTPException(400, "target is required")

    workflow_id = f"wf_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    runs = []
    previous_evidence = ""

    for idx, step in enumerate(req.steps):
        agent = step.get("agent", "").strip()
        task_template = step.get("task", "").strip()
        if not agent or not task_template:
            continue

        # Inject previous evidence into the task
        task = task_template.replace("{{target}}", req.target).replace("{{previous_evidence}}", previous_evidence)
        state = _launch_agent_background(agent, task)
        state["workflow_id"] = workflow_id
        state["chain_index"] = idx
        runs.append(state)

        # Wait for this step to complete before starting the next
        state_file = RUNS_DIR / f"{state['run_id']}.json"
        for _ in range(300):  # 5 min max per step
            cur = _read_json(state_file)
            if cur.get("status") in ("done", "failed"):
                break
            await asyncio.sleep(1)

        # Collect evidence paths from the completed step
        log_file = Path(state.get("log_file", ""))
        if log_file.exists():
            content = log_file.read_text(encoding="utf-8", errors="replace")
            import re as _re
            paths = _re.findall(r"/work/loot/[^\s\"']+", content)
            previous_evidence = ", ".join(sorted(set(paths))[:10])

    return {"workflow_id": workflow_id, "runs": runs, "mode": "chain", "target": req.target}


@app.get("/api/vpn/status")
async def vpn_status():
    """Check VPN connection status."""
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "vpn"],
            capture_output=True, text=True, timeout=10
        )
        return {"status": "unknown", "output": result.stdout}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/vpn/connect")
async def vpn_connect(profile: str):
    """Connect to a VPN profile."""
    try:
        # Write the profile to the vpn directory and start the vpn service
        result = subprocess.run(
            ["docker", "compose", "up", "-d", "vpn"],
            capture_output=True, text=True, timeout=30
        )
        return {"status": "connecting", "profile": profile, "output": result.stdout}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/vpn/disconnect")
async def vpn_disconnect():
    """Disconnect from VPN."""
    try:
        result = subprocess.run(
            ["docker", "compose", "stop", "vpn"],
            capture_output=True, text=True, timeout=30
        )
        return {"status": "disconnected", "output": result.stdout}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/api/config")
async def get_config():
    agents = _load_agents()
    categories = sorted({a["category"] for a in agents})
    return {
        "openclaw_url": OPENCLAW_URL,
        "agents": agents,
        "categories": categories,
        "loot_dir": str(LOOT_DIR),
        "reports_dir": str(REPORTS_DIR),
    }


# ---------------------------------------------------------------------------
# Professional engines: planning, tool selection, chaining, exploits, reports
# ---------------------------------------------------------------------------

TOOLS_DIR = Path("/tools")


def _run_engine(script: str, *args: str, timeout: int = 60) -> Any:
    """Run an engine CLI in /tools and return its JSON output."""
    result = subprocess.run(
        ["python3", str(TOOLS_DIR / script), *args],
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        return {"error": (result.stderr or result.stdout).strip()[:2000]}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"output": result.stdout}


@app.get("/api/runs/{run_id}/plan")
async def get_run_plan(run_id: str):
    """Return the attack plan generated for a run (markdown)."""
    state = _read_json(RUNS_DIR / f"{run_id}.json")
    plan_file = state.get("plan_file") or str(RUNS_DIR / f"{run_id}.plan.md")
    path = Path(plan_file)
    if not path.exists():
        raise HTTPException(404, "no attack plan for this run")
    return {"run_id": run_id, "plan_markdown": path.read_text()}


@app.get("/api/runs/{run_id}/phases")
async def get_run_phases(run_id: str):
    """Return engagement phase progress for a run (phase-chunked runner)."""
    path = RUNS_DIR / f"{run_id}.engagement.json"
    if not path.exists():
        raise HTTPException(404, "no engagement state for this run")
    state = _read_json(path)
    # Strip bulky plan details from the response
    phases = [{k: v for k, v in p.items() if k != "plan"} for p in state.get("phases", [])]
    return {
        "run_id": run_id,
        "current_phase": state.get("current_phase"),
        "session_id": state.get("session_id"),
        "started_at": state.get("started_at"),
        "updated_at": state.get("updated_at"),
        "phases": phases,
    }


class PlanRequest(BaseModel):
    target: str
    task: str = "full assessment"


@app.post("/api/planning/generate")
async def planning_generate(req: PlanRequest):
    """Generate a structured attack plan for a target."""
    return _run_engine("planning_engine.py", "generate", req.target, req.task)


@app.get("/api/tools/select")
async def tools_select(vuln_type: str):
    """Get the tool selection matrix entry for a vulnerability type."""
    return _run_engine("tool_selector.py", "select", vuln_type)


class ChainRequest(BaseModel):
    findings: List[Dict[str, Any]] = []


@app.post("/api/chains/identify")
async def chains_identify(req: ChainRequest):
    """Identify vulnerability chains from a set of findings."""
    result = _run_engine("chain_engine.py", "identify", json.dumps({"findings": req.findings}))
    if isinstance(result, list):
        return {"chains": result, "count": len(result)}
    return result


class ExploitRequest(BaseModel):
    vuln_type: str
    target: str
    param: str = "id"
    kwargs: Dict[str, Any] = {}


@app.post("/api/exploits/generate")
async def exploits_generate(req: ExploitRequest):
    """Generate a custom exploit from a template."""
    args = ["generate", req.vuln_type, req.target, req.param]
    if req.kwargs:
        args.append(json.dumps(req.kwargs))
    return _run_engine("exploit_framework.py", *args, timeout=30)


@app.get("/api/exploits")
async def exploits_list():
    """List available exploit templates and previously generated exploits."""
    return _run_engine("exploit_framework.py", "list")


class ReportGenerateRequest(BaseModel):
    target: str
    findings: List[Dict[str, Any]] = []
    chains: List[Dict[str, Any]] = []
    threat_model: Dict[str, Any] = {}
    methodology: str = ""


@app.post("/api/reports/generate")
async def reports_generate(req: ReportGenerateRequest):
    """Generate a business-grade report from findings, chains, and threat model."""
    return _run_engine(
        "reporting_engine.py", "generate", req.target,
        json.dumps({"findings": req.findings}),
        json.dumps({"chains": req.chains}),
        json.dumps(req.threat_model),
        req.methodology or "OWASP Testing Guide, PTES, and custom automated + manual testing",
        timeout=60,
    )


# asyncio is used in stream_run
import asyncio  # noqa: E402


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
