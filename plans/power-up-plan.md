# kali-ai Power-Up Plan

Based on deep testing on 2026-07-22 (engine unit tests, API error-path tests, live
bug-bounty + recon + continuation runs against DVWA).

## What the tests proved works

- All 5 engines: planning (7-phase, threat model), tool selection (14 vuln types),
  chaining (10 templates), exploit generation (7 templates, all compile), reporting
  (CVSS 4.0, business-grade).
- Plan injection into every agent run; plan viewable in dashboard.
- Live run: agent authenticated to DVWA, seeded ZAP with authed traffic, tested
  SQLi/XSS/CSRF/LFI/brute-force, self-debugged tool errors, applied past lessons
  (nmap-blocked memory).
- Continue flow: resumed a timed-out run, reused prior loot, curated chain engine
  false positives, produced a 14-finding / 5-chain CRITICAL business report.
- Instruction injection round-trip: dashboard -> pending -> stream monitor -> run
  log -> marked read.

## Bugs fixed during this test pass

1. planning_engine classified IP/CIDR targets as "web" — now "network" via target shape.
2. exploit_framework `.format()` crashed on 4 templates (literal braces in code) —
   replaced with token replacement.
3. exploit_framework file-upload template had literal newline/tab in strings —
   generated code didn't compile.
4. tool_selector silently fell back to sql-injection for unknown vuln types — now
   returns an error listing available types.
5. reporting_engine crashed on targets containing "/" (raw filename) — sanitized.
6. internal-agent.sh: bare-hostname targets (`http://dvwa`) got no plan — URL host
   extraction added (fixed in previous pass).
7. internal-agent.sh: zombie-Hermes made the stream monitor loop forever; 300s
   timeout truncated all engagements — watchdog pattern + 900s default (fixed in
   previous pass).

## Gaps found (priority order)

### P0 — Agents execute in the wrong container
Runs launched from the dashboard execute `internal-agent.sh` **in the dashboard
container**, which has no NET_RAW/SYS_ADMIN — this is why nmap/masscan are
"blocked" (a lesson the memory keeps re-learning). The kali container has the caps.
Fix: dashboard should launch runs via `docker exec kali ...` (socket is already
mounted into kali; mount it into dashboard or add a tiny runner service in kali).
Impact: unlocks raw-socket scanning, bettercap/responder, packet tooling.

### P1 — Findings are unstructured
The stream monitor scrapes log lines with grep. continuation-context returned
empty discoveries. The agent *manually* wrote `/work/loot/dvwa/findings.json` —
that should be the contract, not an accident.
Fix:
- Standardize `/work/loot/<target>/findings.jsonl` — every agent prompt must
  append structured findings (id, title, type, severity, detail, evidence[]).
- Dashboard findings tab + continuation-context read that file, not log greps.
- Post-run hook: auto-run chain_engine + reporting_engine on findings.jsonl so
  every engagement ends with chains + a business report, even on timeout.

### P2 — Mid-run instructions don't reach the agent's reasoning
Instructions are logged to the run log but `hermes chat -q` is one-shot — the
agent never sees them until a Continue.
Fix options:
- (a) Chunked execution: run the agent in phase-sized turns (from the attack
  plan), injecting pending instructions between turns. Aligns with the plan
  phases and the 100-tool-call budget.
- (b) Hermes interactive mode with a stdin pipe from stream_manager.
Recommend (a) — it also fixes engagement truncation (P3).

### P3 — Engagements truncate before chaining/reporting
15 min / 100 tool calls isn't enough for a full bounty run.
Fix: phase-chunked runner (P2a) — each plan phase is one hermes invocation with
its own budget; state passes via findings.jsonl + plan file. Timeout becomes
per-phase, and Continue resumes at phase granularity.

### P4 — Chain engine precision
Substring matching produced a false positive (XXE->SSRF via "file upload" text).
Fix: require distinct evidence tags per entry point, weight by number of
independent matching findings, and add a `min_distinct_findings` threshold per
chain. The agent already curates manually; the engine should not need curation.

### P5 — Tool installer gaps
dalfox, ssrfmap, gopherus never install. Either fix their install recipes or mark
them optional so every run doesn't start with "3 missing".

### P6 — Output capture truncation
Agent-reported: chain stdout truncated at 8KB through the tool-output pipe. Large
JSON outputs should be written to files and referenced by path (teach prompts:
"engine output > file, then read the file").

## Proposed build order

1. **P0 container fix** — biggest capability unlock for effort.
2. **P1 findings contract + post-run auto chain/report** — makes every run end
   with a deliverable; feeds self-learning with structured data.
3. **P5 installer** — trivial, removes per-run noise.
4. **P2a+P3 phase-chunked runner** — the real "autonomous pentest" architecture:
   plan phases as execution units, steering between phases, per-phase budgets,
   phase-level resume.
5. **P4 chain precision** — quality of reporting.
6. **Benchmark harness** — replay known HTB/THM boxes, score findings vs. ground
   truth, track improvement over time (this is what makes "self-evolving"
   measurable rather than vibes).
7. **Knowledge pipeline** — scheduled ingestion of writeups into Qdrant +
   FTS5/BM25 hybrid search endpoint for agents (the RAG half of the original
   vision, currently only lessons are indexed).

## Verification approach for each step

- P0: `nmap -sS` succeeds inside an agent run; lesson "nmap blocked" stops
  recurring.
- P1: timeout a run on purpose; chains + report still produced from
  findings.jsonl.
- P2a/P3: full DVWA bounty completes end-to-end with report in one run, no
  Continue needed; inject instruction between phases and observe behavior change.
- P4: replay DVWA findings; zero false-positive chains without manual curation.
- Benchmark: 3 known boxes scored; report includes matched/missed vulns.
