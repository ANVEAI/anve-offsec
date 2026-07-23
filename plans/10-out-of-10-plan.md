# kali-ai — Road to 10/10 (8-Phase Build)

Status doc for the capability build kicked off 2026-07-23. Complements
`plans/power-up-plan.md` (which defined P0–P6). This maps my 8-phase plan to
concrete code, marks what shipped vs. what needs an in-container validation run,
and lists the operator steps that require your hands (privileged / must run in
the Docker env).

**Definition of 10/10 (measurable, not vibes):** on the benchmark suite, the
platform autonomously finds ≥90% of ground-truth vulns, emits platform-ready
reports with working PoCs, takes **zero** out-of-scope actions, and its F1 trends
**up** run-over-run. Phase 7 is what makes this a number.

**Safety posture:** the command-content filter (`guardrails.py`) stays removed
per operator decision. The two rails that remain are *offensive advantages*, not
nannies, and every new module enforces the first:
- **Scope/authorization** — every target-touching module calls `authorized()`
  against `/config/authorized-targets.json` and `sys.exit(2)` before any request
  to an unlisted host. Out-of-scope = program ban + legal exposure.
- **Rate/politeness** — throttled requests so you don't get IP-banned mid-engagement.

---

## Phase status

| Phase | What | State | Artifact(s) |
|---|---|---|---|
| 0 | Execution substrate | code shipped; **1 privileged compose change needs you** | `tools/exec_runner.py`, compose diff below |
| 1 | Structured findings contract | contract already existed; **memory-pollution fix shipped** | `scripts/internal-agent.sh` edit |
| 2 | Phase-chunked runner + supervision | already built; enhancement notes | `tools/engagement_runner.py` (existing) |
| 3 | Coverage depth (IDOR/BOLA, API, recon) | shipped | `tools/recon_pipeline.py`, `tools/idor_scanner.py`, `tools/api_tester.py` |
| 4 | Exploitation → proven PoC + precise chains | shipped | `tools/oob_client.py`, `tools/attack_path.py` |
| 5 | Curated offensive-knowledge RAG | shipped | `tools/knowledge_ingest.py` |
| 6 | Cost/latency model routing | shipped | `tools/model_router.py` |
| 7 | Benchmark harness (the scoreboard) | shipped | `tools/benchmark.py`, `config/benchmarks/*.json` |
| 8 | Payout-grade reports + cleanup | shipped | `tools/bounty_report.py`; stray files quarantined; `.gitignore` hardened |

Everything is stdlib-only, matches existing conventions (absolute container
paths, JSON-CLI under `/tools`, graceful degradation when a CLI tool is missing),
and is `py_compile`-clean. It is **syntax-verified on the host but not
run-verified** — host lacks `/work`, Qdrant, the Kali toolchain, and the target
containers. Validate with one engagement in the Docker env (see checklist).

---

## Phase 0 — Execution substrate

- **`tools/exec_runner.py`** (shipped) — runs any command, streams the COMPLETE
  stdout+stderr to `/work/loot/<target>/raw/<ts>_<slug>.log`, returns a JSON
  descriptor referencing the file. Fixes the 8KB tool-output truncation (P6):
  agents run tools through this and read the file, so large nmap/nuclei/ffuf
  output is never dropped. `run <target> <slug> [--timeout N] -- <cmd...>`.

- **Privileged compose change — YOU must apply** (the auto-mode classifier
  blocked me from editing this, correctly, since it grants a container
  root-on-host). In `docker-compose.yml`, service `dashboard` (where runs
  execute; it is `FROM kali-ai` so it already has the toolchain + Hermes):

  ```yaml
      cap_add:
        - NET_ADMIN
        - NET_RAW
        - SYS_ADMIN            # add: mount ns / some packet tooling
      volumes:
        # ... existing mounts ...
        - ./config/benchmarks:/config/benchmarks:ro          # add (Phase 7)
        - /var/run/docker.sock:/var/run/docker.sock          # add: DinD workers
  ```

  This unlocks `nmap -sS`/masscan (NET_RAW already present), packet tooling, and
  ephemeral DinD worker spawning. OOB reverse-shell / interactsh callbacks land
  on the **kali** container (it publishes 28000–30000); agents on the shared
  compose network reach it as host `kali-ai` (see `oob_client.py`). Do NOT also
  publish 28000–30000 on the dashboard service — host-port conflict.

  Alternative (more isolation, more plumbing): keep the dashboard slim and have
  `dashboard/app.py` launch runs via `docker exec kali-ai /scripts/internal-agent.sh`.
  That needs kali to also mount `./scripts:/scripts:ro` and `./config/agents:/agents:ro`,
  plus a docker CLI in the image. The in-place approach above is simpler and
  equally powerful because the image is shared.

## Phase 1 — Findings contract + stop memory pollution

The `findings.jsonl` contract + post-run auto chain/report already existed in
`internal-agent.sh`. The bug was the **lesson extractor still grepped the log**
for evidence paths, capturing malformed fragments (`{headers.txt`,
`findings.jsonl)`, `/work/loot/127.0.0.1.`) that corrupted `strategy.json` and
`lessons.jsonl` — i.e. the self-evolution loop was training on garbage.

- **Fix shipped** (`internal-agent.sh`): when `findings.jsonl` exists, evidence
  paths are derived from its validated `evidence[]` arrays (absolute
  `/work/loot/…`, no brace/paren fragments) instead of the log grep. Grep remains
  only as a fallback when no findings file was produced.
- **Recommended next:** also switch the live stream-monitor's finding-sharing
  (currently `grep -E "FOUND|VULNERABILITY|…"`) to tail `findings.jsonl`.

## Phase 2 — Phase-chunked runner + supervision

`engagement_runner.py` already does phase-by-phase execution, per-phase attempts
(same → similar → different), same-session resume, and operator-instruction
injection between turns. Reflector/adviser prompts exist in `config/agents/`.
Enhancement backlog (not blocking): make reflector/adviser *distinct model calls*
invoked by the runner on failure/loop-detection rather than prompt text, and wire
`agent_budgets` tool-call caps into the per-phase loop.

## Phase 3 — Coverage depth (biggest bounty-yield jump)

- **`recon_pipeline.py`** — ProjectDiscovery-style chain (subfinder → dnsx →
  naabu/nmap → httpx → katana → nuclei, each `which`-gated), parses nuclei JSONL
  into findings, mines crawled `.js` for leaked secrets. `run <target> [--web|--network]`.
- **`idor_scanner.py`** — multi-account BOLA/IDOR differ (replay account A's
  requests with account B's session; `difflib` similarity + numeric id±1 shift;
  read-only by default; PII in body → critical). The highest-ROI bounty class and
  absent from generic scanners. `diff` / `probe`.
- **`api_tester.py`** — OpenAPI/Swagger/GraphQL ingestion → BOLA, mass-assignment,
  missing-auth, JWT alg:none (rebuilds unsigned token only — no signature forgery).
  `ingest` / `test` / `graphql`.

## Phase 4 — Exploitation → proven PoC + precise chains

- **`oob_client.py`** — OOB interaction catcher for BLIND vulns (blind SSRF/XXE/
  RCE): uses `interactsh-client` if present, else a built-in HTTP catcher on the
  OOB port range. `register` returns a callback URL; `poll <token>` returns hits.
  This is how the agent *proves* "the target reached my server."
- **`attack_path.py`** — precise kill-chain chainer that **replaces** the old
  substring matcher's false positives (the XXE→SSRF-via-"file upload"-text bug):
  matches on the structured `type` field only, requires each hop to be a distinct
  finding with distinct evidence, and enforces `min_distinct_findings`. `chain` / `score`.

## Phase 5 — Curated offensive-knowledge RAG (the differentiator)

- **`knowledge_ingest.py`** — ingests external corpora into Qdrant
  `kali_knowledge`: `ingest-nuclei <dir>`, `ingest-payloads <dir>`
  (PayloadsAllTheThings), `ingest-cve <json>`, `ingest-reports <dir>` (disclosed
  H1 reports). Hash-keyed/idempotent. `search <query>` retrieves at plan time:
  "target runs X → here's how this bug class was found on similar stacks."
  Populate sources under `/work/knowledge/` (git-clone nuclei-templates,
  PayloadsAllTheThings, etc.).

## Phase 6 — Model routing (also relieves the Kimi quota ceiling)

- **`model_router.py`** — routes task-classes to model tiers so the premium
  reasoning model isn't burned on parsing: PLAN (planning/reflection/exploit) →
  k3; WORK (recon/web/api) → k3; CHEAP (parse/summarize/dedup/report-format) →
  kimi-for-coding, with an optional local Ollama fallback. `route` / `for-agent` /
  `plan-budget` / `estimate`. The last DVWA run died on a Kimi 403 usage-limit;
  routing grunt work to the cheap tier cuts that.

## Phase 7 — Benchmark harness (earns the "10")

- **`benchmark.py`** + **`config/benchmarks/{dvwa,juice-shop,vampi,metasploitable2}.json`**
  — replay known-vulnerable targets with ground-truth vuln lists; `score` computes
  precision/recall/F1 and appends a row to `/work/benchmarks/scorecard.jsonl`;
  `trend` shows F1 over time. Now "self-evolving" is a curve, and any strategy
  change is A/B-testable instead of trusting `confidence: 1.0`.
- To use Juice Shop / VAmPI, add them as compose services (like DVWA):
  `bkimblad/vampi` or `owasp/vampi` on a port, `bkimlad/juice-shop`/`bkimlad`
  … (use the official `bkimlad/vampi` and `bkimlad/juice-shop` or the OWASP
  images) and add them to `authorized-targets.json` as `lab`.

## Phase 8 — Payout-grade reports + housekeeping

- **`bounty_report.py`** — converts `findings.jsonl` (+ chains) into HackerOne/
  Bugcrowd-ready markdown per finding: CVSS 4.0 vector, CWE, repro steps, impact,
  remediation, evidence. `submissions <target>` / `dedupe <target>` (fixes
  "same bug counted 5×") / `summary <target>`.
- **Cleanup done:** stray `as` (644KB AP-news text) and `dashboard/!` moved to
  `_quarantine/`; `.gitignore` extended with `config/openclaw/` (was leaking
  `browser-extension-relay.secret` + Chromium `Cookies`/`Login Data`),
  `_quarantine/`, `__pycache__/`, `*.pyc`.

---

## Operator validation checklist (run in the Docker env)

1. Apply the Phase 0 compose diff; `docker compose up -d --build`.
2. `docker compose exec dashboard python3 -m py_compile /tools/*.py` — all clean.
3. Phase 0: an engagement runs `nmap -sS` successfully; the "nmap blocked" lesson
   stops recurring; large output lands in `/work/loot/<t>/raw/` un-truncated.
4. Phase 1: force-timeout a run — chains + report still produced; new
   `strategy.json` evidence paths are clean (no `{`/`)` fragments).
5. Phase 3: `idor_scanner.py diff` on two DVWA/Juice-Shop accounts flags a BOLA.
6. Phase 7: `benchmark.py score dvwa /work/loot/dvwa/findings.jsonl` → F1;
   run twice, confirm `trend` shows the curve.
7. Phase 5: clone nuclei-templates into `/work/knowledge/`, `ingest-nuclei`,
   then `search "ssrf metadata"` returns hits.
8. Phase 8: `bounty_report.py submissions dvwa` → per-finding H1 markdown.

## Known follow-ups (post-10 polish)
- Wire reflector/adviser as model calls in the runner loop (Phase 2).
- Switch stream-monitor finding-sharing to `findings.jsonl` (Phase 1 tail).
- Consolidate `.env` keys (MOONSHOT/KIMI/OPENAI overlap) to one provider source.
- Add Juice Shop + VAmPI compose services for the full benchmark suite.
