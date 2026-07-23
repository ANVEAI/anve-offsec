# kali-ai — System Architecture (reference spec)

## Layers

- **Base**: Kali Linux Docker image (`kalilinux/kali-rolling`, custom `kali-ai` image
  built from this repo's Dockerfile; native arm64). Production migration target:
  hardened Kali VM with hypervisor snapshots + network isolation.
- **Agent layer**: Hermes Agent (reasoning/planning brain) + OpenClaw Agent
  (browser-level autonomous actions) working together.
- **LLM layer**: Kimi K3 as the core reasoning model (candidate for parallel/replacement
  reasoning vs. Qwen+WhiteRabbitNeo — to be settled by benchmarking).
- **Multi-specialized agents**: task-specific sub-agents — recon, vuln analysis,
  exploitation, privesc, reporting, etc. — orchestrated by Hermes rather than one
  generalist agent. (Cf. PentAGI's two-tier taxonomy in `docs/pentagi-reference.md`:
  general agents with high tool budgets + limited specialist agents with small budgets,
  plus Reflector/Adviser supervision roles.)
- **Knowledge system**: RAG-based, vector DB for continuous ingestion of
  THM/HTB writeups, CVE data, offsec methodology — retrieval over retraining.
  Hybrid search planned: vector (semantic) + FTS5/BM25 (exact terms: CVEs, tool names).

## Environment (current)

- Docker build: `./scripts/build.sh`; shell: `./scripts/shell.sh`; reset: `./scripts/reset.sh`
- Persistent workspace: `./work` → `/work` in container
- Container caps: NET_ADMIN, NET_RAW

## References

- `docs/pentagi-reference.md` — PentAGI architecture notes (closest open-source analogue)
