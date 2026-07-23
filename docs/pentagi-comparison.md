# anve-offsec vs PentAGI — Architecture Comparison

Date: 2026-07-20. PentAGI details from `docs/pentagi-reference.md`.

| Layer | anve-offsec | PentAGI | Assessment |
|---|---|---|---|
| Base | Kali Docker (dev) → Kali VM w/ hypervisor snapshots (prod) | Kali Docker workers spawned via docker.sock; TLS dind worker node for prod | Equivalent in dev. anve-offsec's VM plan gives stronger containment than PentAGI's dind; PentAGI's multi-node scaling is more mature. |
| Brain | Hermes agent (planning/reasoning) | Primary Agent + Planner + Adviser + Reflector (fork of langchaingo, Go) | PentAGI splits supervision into dedicated roles (Reflector on failure, Adviser on loop detection). anve-offsec currently puts all of this in Hermes — borrow the split. |
| Action layer | OpenClaw (browser-level actions) | PTY shell execution in per-flow worker containers + isolated scraper container for browser | PentAGI's shell-over-PTY inside ephemeral workers is the core executor; OpenClaw covers browser but anve-offsec needs an equivalent structured **shell executor** — that's the biggest functional gap. |
| LLM | Kimi K3 core (evaluating vs Qwen+WRN) | 10+ providers incl. Kimi, Qwen, Ollama; per-agent-type tiering via YAML provider profiles | PentAGI already supports both candidate models and per-role tiering — anve-offsec can run the same Kimi-vs-Qwen benchmark with less plumbing. |
| Multi-agents | Specialized sub-agents: recon, vuln analysis, exploitation, reporting | Two-tier: general agents (100 tool calls) + limited specialists (20): Searcher, Enricher, Memorist, Reporter, etc. | Same philosophy. PentAGI adds tool-call budgets + supervision agents — adopt both. |
| Knowledge | RAG: vector DB + FTS5/BM25 hybrid, continuous THM/HTB writeup ingestion, tagged by category/difficulty | pgvector episodic memory (agent experience) + optional Graphiti/Neo4j knowledge graph | **anve-offsec is ahead here**: PentAGI's memory is agent-experience replay, not a curated offensive-knowledge corpus. Our writeup/CVE corpus + hybrid lexical search is a real differentiator. Candidate combo: our RAG + their episodic memory. |
| OOB / networking | Not yet defined | Per-worker dynamic port allocation 28000–30000 for OOB callbacks; PROXY_URL egress control | Borrow directly — needed for reverse shells and OOB exfil detection. |
| Human-in-loop | Undecided | Barrier tools (`done`/`ask`), interactive Assistant mode, stop/patch/redirect live flows | Adopt barrier tools at minimum. |
| Observability | Not yet defined | Langfuse (LLM traces) + OTEL/Grafana (system) + full Postgres command log | Adopt Langfuse-style LLM tracing — critical for the planned Kimi-vs-Qwen benchmark (need per-action traces to score dead-ends). |
| Release posture | Gated exploit layer, rest possibly public | MIT, fully public | Independent of architecture. |

## Gaps in anve-offsec relative to PentAGI (to close)

1. **Structured shell executor** — PTY-in-ephemeral-container with full command/output logging. OpenClaw alone doesn't cover this.
2. **Supervision roles** — Reflector (after N failed tool gens) + Adviser (on loop detection) + hard tool-call budgets.
3. **Per-role model tiering** — provider-profile YAML so planner/adviser can run a different model than workers; doubles as the benchmark harness mechanism.
4. **OOB port range + egress proxy** for worker containers.
5. **LLM tracing** from day one (needed for eval).
6. **Data model** — Flow→Task→SubTask→Action persistence so runs are queryable/reportable.

## Where anve-offsec is (or will be) stronger

- Curated offensive-knowledge RAG (writeups, CVEs, tagged by difficulty) vs. PentAGI's experience-only memory.
- Kimi K3-class reasoning model vs. their documented sub-32B struggles.
- VM-level production containment with snapshots.
