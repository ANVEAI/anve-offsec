#!/usr/bin/env python3
"""
Engagement runner for kali-ai — phase-chunked, long-running, self-healing supervisor.

Executes an attack plan phase by phase. Each phase gets up to N Hermes turns;
later turns resume the same Hermes session (--resume) so the agent keeps full
conversation context. Failed turns are retried with an adapted approach
(same -> similar -> different), a mini-lesson is written after every failure,
and pending user instructions are injected between turns.

There is no engagement-level timeout: only a per-turn safety timeout
(AGENT_TURN_TIMEOUT_SECONDS, default 1800) and an optional wall-clock cap
(AGENT_ENGAGEMENT_MAX_HOURS, default 6, 0 = unlimited). State is written after
every turn, so a relaunch with the same run ID resumes at the current phase.

Usage: python3 /tools/engagement_runner.py <run_id> <agent> <task> <target> <plan.json> <prompt_file> <model> <max_turns>
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

WORK_DIR = Path(os.environ.get("KALI_WORK_DIR") or ("/work" if Path("/work").exists() else "work"))
RUNS_DIR = WORK_DIR / "dashboard-logs"
MEMORY_FILE = WORK_DIR / "memory" / "lessons.jsonl"
TOOLS_DIR = Path("/tools") if Path("/tools").exists() else Path(__file__).parent

TURN_TIMEOUT = int(os.environ.get("AGENT_TURN_TIMEOUT_SECONDS", "1800"))
MAX_WALL_HOURS = float(os.environ.get("AGENT_ENGAGEMENT_MAX_HOURS", "6"))
MAX_PHASE_ATTEMPTS = int(os.environ.get("AGENT_MAX_PHASE_ATTEMPTS", "3"))

SESSION_RE = re.compile(r"session_id:\s*([A-Za-z0-9_-]+)")
COMPLETE_RE = re.compile(r"PHASE_COMPLETE:\s*(.+)")
BLOCKED_RE = re.compile(r"PHASE_BLOCKED:\s*(.+)")
API_ERROR_RE = re.compile(r"API call failed|Connection error|Broken pipe|upstream timeout|usage limit|token refresh failed|refresh token", re.IGNORECASE)
MAX_API_RETRIES = int(os.environ.get("AGENT_MAX_API_RETRIES", "5"))


def log(msg: str) -> None:
    print(f"==> [engagement] {msg}", flush=True)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Engagement:
    def __init__(self, run_id: str, agent: str, task: str, target: str,
                 plan: Dict[str, Any], model: str, max_turns: int, prompt_file: str):
        self.run_id = run_id
        self.agent = agent
        self.task = task
        self.target = target
        self.plan = plan
        self.model = model
        self.max_turns = max_turns
        self.prompt_file = prompt_file
        self.state_file = RUNS_DIR / f"{run_id}.engagement.json"
        self.findings_file = WORK_DIR / "loot" / target / "findings.jsonl" if target else None
        self.session_id: Optional[str] = None
        self.phases: List[Dict[str, Any]] = []
        self.started_at = utcnow()
        self._load_or_init_state()

    def _load_or_init_state(self) -> None:
        if self.state_file.exists():
            try:
                state = json.loads(self.state_file.read_text())
                self.phases = state.get("phases", [])
                self.session_id = state.get("session_id")
                self.started_at = state.get("started_at", self.started_at)
                log(f"resumed engagement state: {self._progress()} phases done")
                return
            except Exception:
                pass
        # Adopt a parent engagement's state when launched via Continue
        resume_from = os.environ.get("ENGAGEMENT_RESUME_FROM", "")
        if resume_from:
            parent_file = RUNS_DIR / f"{resume_from}.engagement.json"
            if parent_file.exists():
                try:
                    state = json.loads(parent_file.read_text())
                    self.phases = state.get("phases", [])
                    self.session_id = state.get("session_id")
                    log(f"adopted parent engagement {resume_from}: {self._progress()} phases done, "
                        f"session {'kept' if self.session_id else 'fresh'}")
                    self._save_state()
                    return
                except Exception:
                    pass
        for i, p in enumerate(self.plan.get("phases", []), 1):
            self.phases.append({
                "number": i,
                "name": p.get("name", f"Phase {i}"),
                "status": "pending",
                "attempts": 0,
                "approaches_tried": [],
                "last_error": "",
                "plan": p,
            })
        self._save_state()

    def _save_state(self) -> None:
        state = {
            "run_id": self.run_id,
            "agent": self.agent,
            "task": self.task,
            "target": self.target,
            "phases": self.phases,
            "current_phase": next((p["number"] for p in self.phases if p["status"] in ("pending", "in_progress")), None),
            "session_id": self.session_id,
            "started_at": self.started_at,
            "updated_at": utcnow(),
            "max_phase_attempts": MAX_PHASE_ATTEMPTS,
            "turn_timeout_seconds": TURN_TIMEOUT,
            "max_wall_hours": MAX_WALL_HOURS,
        }
        self.state_file.write_text(json.dumps(state, indent=2))

    def _progress(self) -> str:
        done = sum(1 for p in self.phases if p["status"] == "done")
        return f"{done}/{len(self.phases)}"

    def _findings_count(self) -> int:
        if not self.findings_file or not self.findings_file.exists():
            return 0
        try:
            return sum(1 for line in self.findings_file.read_text().splitlines() if line.strip())
        except Exception:
            return 0

    def _wall_clock_exceeded(self) -> bool:
        if MAX_WALL_HOURS <= 0:
            return False
        started = datetime.fromisoformat(self.started_at.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - started).total_seconds() > MAX_WALL_HOURS * 3600

    def _pending_instructions(self) -> List[str]:
        try:
            result = subprocess.run(
                [sys.executable, str(TOOLS_DIR / "stream_manager.py"), "pending", self.run_id],
                capture_output=True, text=True, timeout=15)
            instructions = json.loads(result.stdout or "[]")
        except Exception:
            return []
        texts = []
        for item in instructions:
            texts.append(item.get("instruction", ""))
            iid = item.get("id", "")
            if iid:
                subprocess.run([sys.executable, str(TOOLS_DIR / "stream_manager.py"), "mark-read", self.run_id, iid],
                               capture_output=True, timeout=10)
        return [t for t in texts if t]

    def _write_mini_lesson(self, phase: Dict[str, Any], approach: str, error: str) -> None:
        lesson = {
            "run_id": self.run_id,
            "agent": self.agent,
            "model": self.model,
            "task": f"[phase:{phase['name']}] {self.task}"[:200],
            "status": "failed",
            "exit_code": 1,
            "outcome": f"Phase '{phase['name']}' attempt {phase['attempts']} ({approach}) failed: {error[:200]}",
            "tools_used": [],
            "evidence_paths": [],
            "timestamp": utcnow(),
        }
        try:
            MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            with MEMORY_FILE.open("a") as f:
                f.write(json.dumps(lesson) + "\n")
        except Exception:
            pass
        try:
            subprocess.run([sys.executable, str(TOOLS_DIR / "rag_client.py"), "upsert-lesson", json.dumps(lesson)],
                           capture_output=True, timeout=30)
        except Exception:
            pass

    def _build_query(self, phase: Dict[str, Any], approach: str, error: str,
                     instructions: List[str]) -> str:
        plan = phase.get("plan", {})
        parts = [
            f"[ENGAGEMENT {self.run_id}] Phase {phase['number']}/{len(self.phases)}: {phase['name']}",
            f"Overall task: {self.task}",
            f"Objective: {plan.get('description', phase['name'])}",
        ]
        if plan.get("tools"):
            parts.append(f"Tools to prefer: {', '.join(plan['tools'])}")
        if plan.get("techniques"):
            parts.append(f"Techniques: {', '.join(plan['techniques'])}")
        if plan.get("decision_points"):
            parts.append(f"Decision points: {'; '.join(plan['decision_points'])}")
        if plan.get("expected_outcomes"):
            parts.append(f"Expected outcomes: {', '.join(plan['expected_outcomes'])}")
        if approach == "similar":
            parts.append(
                f"ADAPTATION: your previous attempt at this phase stalled or failed ({error[:200]}). "
                "Keep the same objective but change tactics: use fallback tools, adjust parameters, "
                "reduce scope, or take a different path to the same goal. For vulnerability-specific "
                "fallbacks, consult: python3 /tools/tool_selector.py select <vuln_type> (see the if_blocked field).")
        elif approach == "different":
            parts.append(
                f"ADAPTATION: two attempts at this phase failed (latest: {error[:200]}). "
                "Use a fundamentally different approach: manual techniques, custom Python exploits via "
                "python3 /tools/exploit_framework.py generate <vuln_type> <target> <param>, or alternative tooling. "
                "If the objective is truly unachievable in this environment, explain why and output PHASE_BLOCKED.")
        if instructions:
            parts.append("NEW INSTRUCTIONS FROM THE OPERATOR (take priority where relevant):")
            parts.extend(f"- {t}" for t in instructions)
        parts.append(
            f"Work on THIS phase only. When it is complete, output exactly: PHASE_COMPLETE: {phase['name']}. "
            f"If you are truly blocked, output exactly: PHASE_BLOCKED: {phase['name']} — <reason>. "
            "Do not start later phases; the supervisor will hand them to you next.")
        return "\n".join(parts)

    def _run_turn(self, query: str) -> Dict[str, Any]:
        env = os.environ.copy()
        try:
            env["HERMES_EPHEMERAL_SYSTEM_PROMPT"] = Path(self.prompt_file).read_text()
        except Exception:
            pass
        cmd = ["hermes", "chat", "-Q", "--max-turns", str(self.max_turns), "-m", self.model]
        if self.session_id:
            cmd += ["--resume", self.session_id]
        cmd += ["-q", query]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, env=env, start_new_session=True)
        except FileNotFoundError:
            return {"outcome": "fatal", "error": "hermes not found on PATH", "output": ""}
        output_lines: List[str] = []
        timed_out = False
        try:
            out, _ = proc.communicate(timeout=TURN_TIMEOUT)
            output_lines = (out or "").splitlines()
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass
            try:
                out, _ = proc.communicate(timeout=10)
                output_lines = (out or "").splitlines()
            except Exception:
                pass
        output = "\n".join(output_lines)
        # Stream the agent's output through to the run log
        if output:
            print(output, flush=True)
        m = SESSION_RE.search(output)
        if m:
            self.session_id = m.group(1)
        cm = COMPLETE_RE.search(output)
        bm = BLOCKED_RE.search(output)
        if API_ERROR_RE.search(output) and not cm and not bm:
            return {"outcome": "api_error", "error": "model API error during turn", "output": output}
        if timed_out:
            return {"outcome": "failed", "error": f"turn timed out after {TURN_TIMEOUT}s", "output": output}
        if bm:
            return {"outcome": "blocked", "error": bm.group(1)[:300], "output": output}
        if cm:
            return {"outcome": "done", "error": "", "output": output}
        return {"outcome": "unknown", "error": "no completion marker", "output": output}

    def run(self) -> int:
        log(f"engagement start: {len(self.phases)} phases, turn timeout {TURN_TIMEOUT}s, "
            f"max {MAX_PHASE_ATTEMPTS} attempts/phase, wall clock {MAX_WALL_HOURS}h")
        for phase in self.phases:
            if phase["status"] == "done":
                continue
            if self._wall_clock_exceeded():
                log(f"wall clock limit reached — state saved, resume with Continue")
                self._save_state()
                return 124
            phase["status"] = "in_progress"
            self._save_state()
            approaches = ["same", "similar", "different"][:MAX_PHASE_ATTEMPTS]
            last_error = ""
            api_retries = 0
            for approach in approaches:
                if self._wall_clock_exceeded():
                    break
                phase["attempts"] += 1
                phase["approaches_tried"].append(approach)
                instructions = self._pending_instructions()
                log(f"phase {phase['number']}/{len(self.phases)} '{phase['name']}' "
                    f"attempt {phase['attempts']} (approach: {approach})"
                    + (f" with {len(instructions)} operator instruction(s)" if instructions else ""))
                findings_before = self._findings_count()
                query = self._build_query(phase, approach, last_error, instructions)
                result = self._run_turn(query)
                findings_after = self._findings_count()
                self._save_state()
                if result["outcome"] == "fatal":
                    log(f"fatal error: {result['error']} — aborting engagement")
                    phase["status"] = "blocked"
                    phase["last_error"] = result["error"]
                    self._save_state()
                    return 2
                if result["outcome"] == "api_error":
                    # Infra failure, not an approach failure: don't burn the attempt,
                    # back off, and retry the same approach.
                    api_retries += 1
                    phase["attempts"] -= 1
                    phase["approaches_tried"].pop()
                    if api_retries > MAX_API_RETRIES:
                        last_error = f"model API unavailable after {MAX_API_RETRIES} retries"
                        log(f"phase '{phase['name']}': {last_error}")
                        break
                    log(f"model API error during turn — backing off 30s and retrying "
                        f"same approach ({api_retries}/{MAX_API_RETRIES})")
                    self._save_state()
                    time.sleep(30)
                    continue
                if result["outcome"] == "done":
                    phase["status"] = "done"
                    phase["last_error"] = ""
                    log(f"phase '{phase['name']}' COMPLETE (findings: {findings_before} -> {findings_after})")
                    break
                if result["outcome"] == "blocked":
                    phase["status"] = "blocked"
                    phase["last_error"] = result["error"]
                    log(f"phase '{phase['name']}' BLOCKED: {result['error'][:200]}")
                    break
                # unknown/failed — count findings growth as implicit progress
                if findings_after > findings_before and result["outcome"] == "unknown":
                    phase["status"] = "done"
                    log(f"phase '{phase['name']}' done via findings growth "
                        f"({findings_before} -> {findings_after}), no marker")
                    break
                last_error = result["error"]
                phase["last_error"] = last_error
                log(f"phase '{phase['name']}' attempt {phase['attempts']} failed: {last_error[:200]} "
                    f"— lesson written, adapting approach")
                self._write_mini_lesson(phase, approach, last_error)
                self._save_state()
            else:
                pass
            if self._wall_clock_exceeded():
                phase["status"] = "pending"
                log("wall clock limit reached mid-phase — state saved, resume with Continue")
                self._save_state()
                return 124
            if phase["status"] == "in_progress":
                phase["status"] = "blocked"
                phase["last_error"] = last_error or "attempts exhausted"
                log(f"phase '{phase['name']}' exhausted {MAX_PHASE_ATTEMPTS} attempts — blocked, moving on")
            self._save_state()
        done = sum(1 for p in self.phases if p["status"] == "done")
        blocked = sum(1 for p in self.phases if p["status"] == "blocked")
        log(f"engagement finished: {done} phases done, {blocked} blocked")
        self._save_state()
        return 0 if done > 0 else 1


def main() -> None:
    if len(sys.argv) < 9:
        print(__doc__)
        sys.exit(1)
    run_id, agent, task, target, plan_file, prompt_file, model, max_turns = sys.argv[1:9]
    plan: Dict[str, Any] = {}
    try:
        plan = json.loads(Path(plan_file).read_text())
    except Exception as e:
        log(f"no usable plan ({e}) — running single-turn fallback")
    if not plan.get("phases"):
        # Fallback: one phase covering the whole task (preserves old behavior)
        plan = {"phases": [{"name": "Full task", "description": task, "tools": [], "techniques": [],
                            "decision_points": [], "expected_outcomes": []}]}
    eng = Engagement(run_id, agent, task, target, plan, model, int(max_turns), prompt_file)
    sys.exit(eng.run())


if __name__ == "__main__":
    main()
