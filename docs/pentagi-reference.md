# PentAGI — Architecture Reference

Reference notes on [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) (MIT license, Go 1.24 backend + React/TS frontend), researched 2026-07-20. Use as design input for kali-ai's orchestrator, tool layer, memory, and sandboxing. PentAGI is the closest mature open-source analogue to this project — study it before reinventing mechanisms it already solved.

## 1. What it is

- Fully autonomous multi-agent pentest platform, self-hosted, web-UI driven.
- Explicitly **not** a CALDERA-style BAS tool with predefined campaigns — agents author their own approach.
- MIT licensed (plus EULA with acceptable-use terms).

## 2. Agent architecture

- Built on a **fork of langchaingo** (`github.com/vxcontrol/langchaingo`), custom Go orchestration — not LangGraph.
- Data model: `Flow → Task → SubTask → Action → Artifact / Memory`. SubTask carries an `agent_type`.
- **Two-tier agent taxonomy**:
  - General agents (100 tool-call cap): Assistant, Primary Agent, Pentester, Coder, Installer
  - Limited agents (20 tool-call cap): Searcher, Enricher, Memorist, Generator, Reporter, Adviser, Reflector, Planner
- Specialist roles worth copying:
  - **Adviser** — mentor invoked on loop detection (same tool ≥5 times, or ≥10 total calls); injects `<mentor_analysis>` alongside `<original_result>`.
  - **Planner** — generates 3–7 step plans in a `<task_assignment>` structure.
  - **Reflector** — recovery agent after 3 failed tool-call generations; steers toward "barrier tools".
  - **Memorist** — dedicated memory-write agent. **Enricher** — context builder. **Reporter** — vuln report generator.
- **Barrier tools**: `done` and `ask` — explicit model-discoverable halt / ask-a-human actions.
- Runaway protection (always on): `MAX_GENERAL_AGENT_TOOL_CALLS=100`, `MAX_LIMITED_AGENT_TOOL_CALLS=20`. Beta supervision: execution monitor + task planning (~2× quality with <32B models at 2–3× token cost).
- **Context management**: "chain summarization" over a ChainAST — section summarization, QA-pair summarization, per-agent byte budgets (assistants 75KB vs 50KB last-section).

## 3. LLM integration

- 10+ providers incl. OpenAI, Anthropic, Gemini, Bedrock, **Ollama**, DeepSeek, Kimi (Moonshot), **Qwen**, OpenRouter, plus any OpenAI-compatible endpoint via `*_SERVER_URL` overrides.
- **Provider profiles** = YAML files (`custom.provider.yml`, `ollama.provider.yml`) controlling **per-agent-type model selection**, reasoning effort, runtime params, pricing metadata. This is the tiering mechanism: strong model for Adviser/Planner, cheap model for workers.
- Separate `EMBEDDING_*` env config for the embedding model.
- Reference deployment: vLLM + Qwen3.5-27B-FP8 on 4× RTX 5090, 12+ concurrent flows (`examples/guides/vllm-qwen35-27b-fp8.md`).

## 4. Tool / action layer

- `pentagi` container mounts `/var/run/docker.sock` and **spawns per-flow ephemeral worker containers** (`pentagi-terminal-N`) from `vxcontrol/kali-linux`.
- Agents run shell commands inside workers over a PTY (`creack/pty`); all commands + outputs persisted to PostgreSQL.
- **Browser**: dedicated isolated `scraper` container (headless browser, HTTPS :9443, basic auth, `shm_size: 2g`, max 10 concurrent sessions).
- **OOB callbacks**: each worker dynamically allocates 2 host ports from range **28000–30000** — needed for reverse shells / OOB exfil detection.
- Per-flow files: host `{dataDir}/flow-{id}-data/{uploads,resources,container}` mirrored into container at `/work/uploads`, `/work/resources`, injected into prompts as `<task_files>`.
- Search: Tavily, Perplexity, DuckDuckGo, Google CSE, Sploitus (exploit search), Searxng. Global `PROXY_URL` for egress control.

## 5. Memory / knowledge

- **pgvector** (Postgres) as the vector store; agents query similar past tasks/experiences before and during phases.
- Taxonomy: Long-term (vector store + knowledge base), Working (current context/goals), Episodic (past actions + success patterns).
- Optional **Graphiti + Neo4j** knowledge graph (`docker-compose-graphiti.yml`) — auto-captures agent responses and tool executions as semantic relationships.

## 6. Deployment / networking

- Main compose: `pentagi`, `pgvector`, `pgexporter` (:9187), `scraper`. UI on **:8443** HTTPS (default bind 127.0.0.1). Login `admin@pentagi.com`/`admin`.
- Three networks: `pentagi-network`, `observability-network`, `langfuse-network`.
- Auxiliary stacks: Langfuse (LLM tracing), observability (Grafana/VictoriaMetrics/Jaeger/Loki/OTEL), Graphiti.
- **Distributed two-node mode** (`examples/guides/worker_node.md`): worker node runs host Docker (:2376, mutual TLS) + privileged `docker:dind` (:3376); main node spawns workers remotely over TLS. Recommended for production isolation.

## 7. Security model

- Throwaway per-flow containers; per-flow filesystem isolation; nothing crosses flows.
- Biggest attack surface: docker.sock = root-equivalent on host → they recommend TLS-remote Docker or the two-node dind setup.
- Human-in-the-loop: `ASK_USER`, barrier tools, interactive Assistant mode (stop/patch/redirect live flows).
- Egress control via proxy; Bearer-token API auth; no public sign-up.

## 8. Observability

- **Langfuse** for LLM semantics (traces, token usage), **OTEL → VictoriaMetrics/Jaeger/Loki/Grafana** for system metrics. Keep these two planes separate.
- Every command + output stored in Postgres; live terminal visible in flow UI.

## 9. Known limitations

- Supervision betas cost 2–3× tokens/time. Small models (<32B) unreliable without supervision.
- No JSON report export (web/clipboard/MD/PDF only). MCP not exposed in UI.
- Deleting a flow leaves `flow-{id}-data/` on disk.

## 10. Decisions to borrow for kali-ai

1. Flow→Task→SubTask→Action relational model with `agent_type` — queryable, reportable.
2. Two-tier agent budgets + Reflector on repeated failures — cheap always-on runaway protection.
3. Mentor (Adviser) triggered by **pattern detection**, not per-step — quality boost without constant cost.
4. Per-agent-role model tiering via YAML profiles — maps directly to our Qwen/Kimi benchmark plan: same harness, swap model per role.
5. ChainAST-style structured summarization with byte budgets instead of naive truncation.
6. docker.sock-spawned ephemeral per-flow workers + dedicated OOB port range (28000–30000).
7. Barrier tools (`done`/`ask`) as first-class actions.
8. pgvector episodic memory queried before each phase; Graphiti/Neo4j as optional later upgrade.
9. Split observability: Langfuse for LLM, Grafana stack for system.
10. For production: TLS-authenticated dind worker node instead of local docker.sock.
