# 🛡️ anve-offsec: Autonomous Bug Bounty & Offensive Security Platform

[![Proudly Made in India](https://img.shields.io/badge/Proudly_Made_in-India_🇮🇳-FF9933.svg?style=flat)](https://github.com/ANVEAI/anve-offsec)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker](https://img.shields.io/badge/Docker-24.0+-0db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![Kali Linux](https://img.shields.io/badge/OS-Kali_Rolling-blueviolet.svg?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![FastAPI](https://img.shields.io/badge/Control_Plane-FastAPI-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![OpenClaw](https://img.shields.io/badge/Browser-OpenClaw_Sidecar-FF4500.svg)](https://openclaw.ai)
[![Qdrant](https://img.shields.io/badge/Memory-Qdrant_Vector_RAG-red.svg?logo=qdrant&logoColor=white)](https://qdrant.tech/)

> **anve-offsec** is an enterprise-grade, autonomous bug bounty and offensive-security operations platform **proudly developed in India 🇮🇳**. Built for long-running autonomous research and continuous self-evolution, it combines a stateful **Kali Linux core container**, the **Hermes AI Reasoning Brain**, **OpenClaw headless Chromium automation**, **OWASP ZAP vulnerability scanning**, and **Qdrant RAG memory** into a self-improving pentest ecosystem.

---

## 📸 Key Capabilities at a Glance

- ⏳ **Long-Running Autonomous Engagements**: Executes multi-phase pentests over hours or days with zero context loss and crash-safe state retention.
- 🧬 **Self-Evolving Pentest Engine**: Learns from every execution outcome. Stores successful attack paths in Qdrant RAG memory to automatically improve strategy on future targets.
- 🧠 **Hermes AI Reasoning Brain**: Multi-turn LLM agent executing complex terminal commands, security tools, and custom exploit payloads natively inside Kali Linux.
- 🌐 **OpenClaw Browser Sidecar**: Headless Chromium gateway for complex web interaction, authentication bypass testing, and dynamic DOM crawling.
- ⚡ **OWASP ZAP Integration**: Automated active/passive web application scanning, spidering, and REST API vulnerability discovery via sidecar daemon.
- 🛡️ **Defensive Guardrails & Scope Control**: Input/output protection against prompt injection, destructive shell commands, and out-of-scope testing with audit logs.
- 📊 **Real-Time Control Plane**: Modern FastAPI web interface featuring live Server-Sent Events (SSE) logs, real-time operator instruction injection, and instant run continuations.
- 🧪 **Built-in Lab Environment**: Ships with pre-configured isolated targets (**DVWA** and **Metasploitable2**) for safe local benchmarking and vulnerability research.

---

## 🧠 Deep Dive: The Hermes AI Reasoning Brain (`tools/engagement_runner.py`)

At the core of **anve-offsec** is **Hermes**—a specialized AI reasoning agent acting as the lead security researcher inside the Kali Linux environment.

```
       +-------------------------------------------------------------------+
       |                       Hermes AI Brain                             |
       |  - Analyzes target recon & attack paths                           |
       |  - Formulates phase-by-phase penetration strategy                 |
       |  - Invokes terminal commands & custom exploit frameworks           |
       |  - Maintains context via --resume <session_id> across phases       |
       +-------------------+-----------------------------------------------+
                           |
            +--------------+--------------+
            |                             |
            v                             v
+-----------------------+     +-----------------------+
|  Specialized Agents   |     |  Self-Evolution RAG   |
| - Bug Bounty Specialist|    | - Queries Qdrant DB   |
| - OWASP Top 10 Experts|     | - Injects past lessons|
| - MITRE ATT&CK Framework|   | - Optimizes strategy  |
+-----------------------+     +-----------------------+
```

### Key Hermes Engineering Mechanics:
1. **Multi-Turn Session Continuity**: Re-invokes Hermes with `--resume <session_id>` across turns, ensuring 100% of working context is preserved across multi-phase engagements.
2. **Specialized Persona Hierarchy**: Over 40+ prompt configurations in `config/agents/` allow Hermes to dynamically assume specialized roles:
   - **Core Roles**: `bug-bounty`, `recon`, `web`, `exploit`, `report`
   - **OWASP Specialists**: `owasp/injection`, `owasp/auth`, `owasp/access-control`, `owasp/ssrf`, `owasp/crypto`, `owasp/misconfig`
   - **MITRE ATT&CK**: `mitre/recon`, `mitre/initial-access`, `mitre/credential-access`, `mitre/privilege-escalation`, `mitre/lateral-movement`
   - **Supervision & Safety**: `adviser` (loop detection), `reflector` (failure recovery), `barrier` (human-in-the-loop control)
3. **Structured Phase Signaling**: Hermes outputs explicit regex tokens (`PHASE_COMPLETE: <name>` or `PHASE_BLOCKED: <name>`) to signal phase boundaries to the execution runner.

---

## ⏳ Long-Running Autonomous Research & Engagement Lifecycle

Traditional pentesting scripts fail on complex targets because they time out or lose context when an approach encounters an obstacle. **anve-offsec** is engineered specifically for **unattended, long-running security engagements**:

```mermaid
flowchart TD
    Start([🚀 Launch Engagement]) --> Phase1[Phase 1: Deep Recon & Asset Discovery]
    Phase1 --> Check1{Phase Outcome?}
    
    Check1 -->|Success| Phase2[Phase 2: Baseline & Vulnerability Scan]
    Check1 -->|Failure Attempt 1| Retry1[Attempt 2: Evasion Flags / Alternative Tooling]
    Retry1 --> Check1
    Check1 -->|Failure Attempt 2| Retry2[Attempt 3: Custom Python Exploit / Manual Bypass]
    Retry2 --> Check1
    
    Phase2 --> Check2{Phase Outcome?}
    Check2 -->|Success| Phase3[Phase 3: Exploitation & PoC Verification]
    Check2 -->|Failure| Adaptation[Self-Evolution Loop: Query Qdrant RAG Memory]
    Adaptation --> Phase2
    
    Phase3 --> Phase4[Phase 4: Synthesis & Reporting]
    Phase4 --> Complete([✅ Engagement Complete & Lessons Saved])
```

### Key Long-Running Features:
- **Adaptive 3-Attempt Retry Escalation**: When a phase fails, the runner escalates from standard tools $\rightarrow$ evasion parameters $\rightarrow$ custom Python exploits.
- **Crash-Safe State Persistence**: Saves engagement state after every turn to `/work/dashboard-logs/<run_id>.engagement.json`. Resumes automatically on container or host restart.
- **Live Mid-Run Operator Steering**: Inject instructions from the dashboard UI mid-engagement without interrupting LLM reasoning context.

---

## 🧬 Self-Evolving Pentest Architecture (`tools/evolution_engine.py`)

**anve-offsec** gets smarter with every target it tests. It builds an empirical strategy model stored in Qdrant vector memory:

```
                      +-----------------------------------+
                      |      Completed Engagement Run     |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------------------------+
                      |   Post-Run Evolution Engine       |
                      |  - Extracts scenario & techniques |
                      |  - Evaluates tool success rate    |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------------------------+
                      |    Qdrant RAG Memory Index        |
                      |  - Vector embeddings of strategies|
                      |  - Scenario confidence scores     |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------------------------+
                      |      Future Engagement Run        |
                      |  - Injects past empirical lessons |
                      |  - Prioritizes high-success tools |
                      +-----------------------------------+
```

### Self-Evolution Highlights:
1. **Scenario Classification**: Automatically categorizes target tasks into structured scenarios (`web-app:sql-injection`, `web-app:ssrf`, `api:idor`, `infra:ssh-enum`).
2. **Confidence Thresholding**:
   - `CONFIDENCE_THRESHOLD = 0.7`: RAG strategies above 70% confidence are injected into active prompts.
   - `AUTO_PROMPT_UPDATE_THRESHOLD = 0.85`: Strategies above 85% confidence automatically update static agent prompts (`config/agents/*.prompt`).
3. **Strategy Memory (`/work/memory/strategy.json`)**: Tracks real-world success rates, tool execution times, and common failure modes across runs.

---

## 🛡️ Defensive Guardrails & Governance (`tools/guardrails.py`)

`anve-offsec` provides comprehensive security controls to prevent unintended actions:

- **Input Guardrails**: Protects against prompt injection by scanning for adversarial patterns (`ignore previous instructions`, `<system>`, `<root>`) and decoding base64 / unicode homograph obfuscations.
- **Output Guardrails**: Intercepts dangerous terminal commands before execution inside Kali (`rm -rf /`, `mkfs`, fork bombs, system shutdown).
- **Data Exfiltration Prevention**: Blocks attempts to read host credentials (`/etc/shadow`, `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.git-credentials`).
- **Target Authorization Engine (`config/authorized-targets.json`)**: Enforces explicit legal scope checking (`lab`, `ctf`, `bug-bounty`, `self`, `client`). Unapproved target overrides require typed operator confirmation and are audited to `/work/memory/override-log.jsonl`.

---

## ⚖️ Feature Comparison Matrix

| Feature | `anve-offsec` | Traditional Scanners (ZAP/Nessus) | Generic LLM Wrappers |
|---|---|---|---|
| **Execution Engine** | Native Kali Linux Shell + Python | Pre-programmed Rules | Basic Script Generation |
| **Session Memory** | Stateful `--resume` across multi-hour runs | None | Single-turn context window |
| **Self-Evolution** | Qdrant Vector RAG + Strategy Learning | Manual Rule Updates | None |
| **Browser Automation** | OpenClaw Headless Chromium Sidecar | Simple HTTP Crawler | Basic Puppeteer Scripts |
| **Safety Governance** | Prompt Injection + Destructive Command Interception | Target URL Input | No Scope Controls |
| **Operator Steering** | Live Mid-Run Instruction Injection | Hard Stop / Start | Re-run Prompt |

---

## 🏗️ System Architecture & Infrastructure

```mermaid
graph TD
    User([👨‍💻 Security Researcher / Operator]) -->|HTTP / SSE :8000| Dash[📊 FastAPI Dashboard Control Plane]
    Dash -->|Orchestrates Runs| Engine[⚙️ Engagement Runner & Execution Engines]
    
    subgraph Core Platform Infrastructure
        Engine -->|Native Shell & Tools| Kali[🛡️ Kali Linux Core Container]
        Engine -->|API Automation :8090| ZAP[⚡ OWASP ZAP Scanner Sidecar]
        Engine -->|Headless Browser :18789| OpenClaw[🌐 OpenClaw Chromium Gateway]
        Engine -->|RAG Vector Memory :6333| Qdrant[🧠 Qdrant Vector Storage]
        Engine -->|Network Tunneling| VPN[🔒 OpenVPN Client Sidecar]
    end

    subgraph Safe Local Testing Sandbox
        Kali -. Authorized Testing .-> DVWA[🧪 DVWA Target - :8080]
        Kali -. Authorized Testing .-> Meta[🧪 Metasploitable2 Target - :8081]
    end
```

### Microservice Details:
- **Docker Socket Access**: `kali` container mounts `/var/run/docker.sock` to spawn ephemeral sub-worker containers.
- **Out-of-Band (OOB) Range (`28000–30000`)**: Port range reserved for reverse shells, DNS exfiltration, and out-of-band HTTP callbacks.

---

## 🔬 Benchmark Case Studies

### 📑 Case Study 1: Automated Assessment of Damn Vulnerable Web App (DVWA)
- **Target**: Local DVWA container (`http://dvwa:8080`)
- **Agent Assigned**: `bug-bounty` (Hermes Brain + OWASP Specialists)
- **Execution Flow**:
  1. Fingerprints PHP/Apache stack and maps endpoints.
  2. Runs OWASP ZAP spider via API (`zap_client.py`) to discover `/vulnerabilities/sqli/`, `/vulnerabilities/exec/`, `/vulnerabilities/fi/`.
  3. Verifies Command Injection (`127.0.0.1; id`), SQL Injection (`1' OR '1'='1`), and File Inclusion (`?page=include.php`).
  4. Generates executive Markdown & JSON report in `/work/loot/dvwa_report.md`.
- **Outcome**: 100% automated detection in under 8 minutes.

### 📑 Case Study 2: Metasploitable2 Infrastructure & Service Enumeration
- **Target**: Local Metasploitable2 container (`http://metasploitable2:8081`)
- **Agent Assigned**: `recon` + `exploit`
- **Execution Flow**:
  1. Identifies open ports: 21 (VSFTPD 2.3.4), 22 (OpenSSH 4.7p1), 80 (Apache 2.2.8), 6667 (UnrealIRCd).
  2. Queries local RAG knowledge base & CVE lookup tools for VSFTPD 2.3.4 backdoor exploit paths.
  3. Synthesizes custom Python exploit script (`/tools/exploit_framework.py`) to verify backdoor reactivity.
- **Outcome**: Identified 6 exploit paths and generated executive summary report.

### 📑 Case Study 3: Auth Wall Bypass & Dynamic Session Automation
- **Target**: Protected Client Staging Web Application
- **Agent Assigned**: `auth-wall` + OpenClaw Browser Sidecar
- **Execution Flow**:
  1. OpenClaw launches headless Chromium and completes dynamic login form.
  2. Extracts JWT Bearer token & session cookies, passing them to Hermes inside Kali.
  3. Hermes performs authenticated IDOR (`idor_scanner.py`) and API security testing (`api_tester.py`).
- **Outcome**: Discovered broken object-level authorization (BOLA) on user profile endpoints.

---

## 🚀 Quick Start Guide

### Prerequisites
- **Docker Desktop** (macOS Apple Silicon / Linux x86_64 / Windows WSL2).
- At least **25 GB** of free disk space (Kali image ~18 GB, OpenClaw ~3.5 GB).
- Python 3.11+ (if running scripts outside Docker).

### 1. Clone & Set Up Environment

```bash
git clone https://github.com/ANVEAI/anve-offsec.git
cd anve-offsec

# Copy environment configuration
cp .env.example .env

# Edit .env and insert your API keys (Kimi / OpenAI / Moonshot)
nano .env
```

### 2. Build & Launch Containers

```bash
# Build and start all microservices
docker compose up -d

# Initialize OpenClaw browser sidecar configurations
./scripts/setup-openclaw.sh
```

### 3. Open Control Plane Dashboard

Navigate to `http://127.0.0.1:8000` in your web browser.

```bash
# Launch a full bug bounty engagement via API or UI:
curl -X POST http://127.0.0.1:8000/api/agents/bug-bounty/run \
  -H "Content-Type: application/json" \
  -d '{"task":"Run a full bug bounty assessment on http://dvwa:8080"}'
```

### 4. Interactive Terminal Access (Hermes TUI)

Want direct terminal interaction with the Hermes AI agent inside Kali?

```bash
./scripts/hermes.sh
```

---

## 🧰 Microservice & Sidecar Reference

| Service | Container Image | Port | Description |
|---|---|---|---|
| **Kali Core** | `kali-ai:latest` | `28000-30000` (OOB) | Full Kali Linux rolling release with security tools and Docker socket access. |
| **Dashboard** | `kali-dashboard:latest` | `8000` | FastAPI control plane with SSE live streaming, targets manager, and scenario builders. |
| **OpenClaw** | `ghcr.io/openclaw/openclaw` | `18789` | Headless Chromium gateway for complex web crawling and interactive DOM automation. |
| **OWASP ZAP** | `ghcr.io/zaproxy/zaproxy:stable` | `8090` | Active & passive web application scanner exposed via REST API. |
| **Qdrant** | `qdrant/qdrant:latest` | `6333 / 6334` | Vector database for storing strategy patterns and past execution RAG memory. |
| **VPN Client** | `dperson/openvpn-client` | N/A | Isolated OpenVPN tunnel container for connecting to CTF lab networks. |
| **DVWA** | `vulnerables/web-dvwa` | `8080` | Damn Vulnerable Web Application local testing target. |
| **Metasploitable** | `tleemcjr/metasploitable2` | `8081` | Metasploitable2 vulnerable target container. |

---

## ⚙️ Configuration Reference

Key tunables can be configured inside `.env`:

| Parameter | Default | Purpose |
|---|---|---|
| `AGENT_TURN_TIMEOUT_SECONDS` | `1800` | Safety timeout for a single agent turn. |
| `AGENT_ENGAGEMENT_MAX_HOURS` | `6` | Wall-clock limit per engagement session (0 = unlimited). |
| `AGENT_MAX_PHASE_ATTEMPTS` | `3` | Maximum retry attempts per attack phase before flagging blocked. |
| `KIMI_API_KEY` | N/A | Kimi / Moonshot AI model API Key. |
| `OPENCLAW_GATEWAY_TOKEN` | N/A | Security secret token for the OpenClaw browser sidecar. |

---

## ⚠️ Legal Disclaimer

> **IMPORTANT**: `anve-offsec` is built strictly for authorized security assessments, penetration testing within explicit scope, educational research, and bug bounty hunting. Operating this software against targets without explicit written authorization is illegal. The creators and contributors assume no liability for misuse or damage caused by this platform.

---

## 📜 License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Proudly Made in India 🇮🇳 | Built with ❤️ for the Global AI & Cybersecurity Community</b><br>
  <i>Starred the repo? Give it a ⭐️ to support continuous development!</i>
</p>
