[⬅️ Back to README](../README.md) | [Architecture](ARCHITECTURE.md) | **Hermes Brain Spec** | [Self-Evolution](SELF_EVOLUTION.md) | [Guardrails](GUARDRAILS_SECURITY.md) | [Case Studies](CASE_STUDIES.md) | [Contributing](CONTRIBUTING.md)

---

# 🧠 The Hermes AI Reasoning Brain Specification

This document details the internal workings of the **Hermes AI Reasoning Brain**, multi-turn session persistence, persona prompt hierarchy, and phase execution loops in **anve-offsec**.

---

## ⚡ Core Concept

Hermes is not a stateless API wrapper that sends single-shot prompts. It is a **stateful, terminal-capable LLM agent CLI** running natively inside the Kali Linux environment.

```
+-------------------------------------------------------------------------------+
|                             Engagement Lifecycle                              |
|                                                                               |
|  Phase 1: Recon   ──►   Phase 2: Vuln Scan   ──►   Phase 3: Exploit           |
|  (Hermes Session)       (Resume Session_ID)        (Resume Session_ID)        |
|          │                       │                          │                 |
|          ▼                       ▼                          ▼                 |
|  [Full Terminal Log]    [Retains Recon Memory]    [Retains Headers/Pocs]      |
+-------------------------------------------------------------------------------+
```

---

## 🔄 Multi-Turn Session Continuity (`tools/engagement_runner.py`)

When an engagement starts, `engagement_runner.py` executes:

```bash
hermes chat -Q --max-turns 30 -m kimi-k3 -q "<Phase 1 Instructions>"
```

1. **Session Regex Capture**:
   Hermes outputs a unique session identifier during execution:
   ```text
   SESSION_ID: 8f9b2a10-4c3e-4b9a-8a12-009182371abc
   ```
2. **Session Resumption**:
   When Phase 2 begins, the runner passes the captured session ID:
   ```bash
   hermes chat -Q --max-turns 30 -m kimi-k3 --resume 8f9b2a10-4c3e-4b9a-8a12-009182371abc -q "<Phase 2 Instructions>"
   ```
   This ensures Hermes retains **100% of its working context** across all turns and phases without context truncation.

---

## 🎭 Agent Persona Hierarchy (`config/agents/`)

Hermes assumes specialized roles depending on the active phase:

### 1. **Core Engagement Roles**
- `bug-bounty.prompt`: Generalist lead security researcher for end-to-end scope testing.
- `recon.prompt`: Subdomain enumeration, port scanning, and service version fingerprinting.
- `web.prompt`: Dynamic path discovery, HTTP method testing, parameter fuzzing.
- `exploit.prompt`: PoC verification, payload crafting, and exploit execution.
- `report.prompt`: Executive markdown & JSON report synthesis.

### 2. **OWASP Top 10 Specialists**
- `owasp/injection.prompt`: SQLi, Command Injection, LDAP injection.
- `owasp/auth.prompt`: Session handling, credential stuffing, password policy checks.
- `owasp/access-control.prompt`: Broken object-level authorization (BOLA/IDOR), privilege escalation.
- `owasp/ssrf.prompt`: Internal network probing, cloud metadata IP access checks (`169.254.169.254`).

### 3. **MITRE ATT&CK Framework Roles**
- `mitre/recon.prompt`, `mitre/initial-access.prompt`, `mitre/credential-access.prompt`, `mitre/privilege-escalation.prompt`, `mitre/lateral-movement.prompt`.

### 4. **Supervision & Safety Roles**
- `adviser.prompt`: Loop detection mentor (triggers when a tool is invoked $\ge 5$ times in a row).
- `reflector.prompt`: Failure recovery analyst after 3 unsuccessful attempts.
- `barrier.prompt`: Enforces human-in-the-loop validation markers (`PHASE_COMPLETE` / `PHASE_BLOCKED`).

---

## 🏁 Phase Signaling Protocol

Hermes signals completion or blockage to `engagement_runner.py` via structured text tokens:

- `PHASE_COMPLETE: <phase_name>` $\rightarrow$ Execution runner parses token, saves phase loot, and triggers the next phase.
- `PHASE_BLOCKED: <phase_name> — <reason>` $\rightarrow$ Execution runner escalates attempt strategy or requests operator intervention.
