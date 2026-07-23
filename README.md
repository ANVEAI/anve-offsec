# 🛡️ anve-offsec: Autonomous Bug Bounty & Offensive Security Platform

[![Proudly Made in India](https://img.shields.io/badge/Proudly_Made_in-India_🇮🇳-FF9933.svg?style=flat)](https://github.com/ANVEAI/anve-offsec)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker](https://img.shields.io/badge/Docker-24.0+-0db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![Kali Linux](https://img.shields.io/badge/OS-Kali_Rolling-blueviolet.svg?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![FastAPI](https://img.shields.io/badge/Control_Plane-FastAPI-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![OpenClaw](https://img.shields.io/badge/Browser-OpenClaw_Sidecar-FF4500.svg)](https://openclaw.ai)
[![Qdrant](https://img.shields.io/badge/Memory-Qdrant_Vector_RAG-red.svg?logo=qdrant&logoColor=white)](https://qdrant.tech/)

> **anve-offsec** is an enterprise-grade, autonomous bug bounty and offensive-security operations platform **proudly developed in India 🇮🇳**. Designed for long-running autonomous research and continuous self-evolution, it combines a stateful **Kali Linux core container**, the **Hermes AI Reasoning Brain**, **OpenClaw headless Chromium automation**, **OWASP ZAP vulnerability scanning**, and **Qdrant RAG memory** into a self-improving pentest ecosystem.

---

## 📸 Key Capabilities at a Glance

- ⏳ **Long-Running Autonomous Engagements**: No engagement timeouts. Executes multi-phase pentests over hours or days with crash-safe session state retention.
- 🧬 **Self-Evolving Pentest Engine**: Learns from every execution outcome. Stores successful attack paths in Qdrant RAG memory to automatically improve strategy on future targets.
- 🧠 **Hermes AI Reasoning Brain**: Multi-turn LLM agent executing complex terminal commands, security tools, and custom exploit payloads natively inside Kali Linux.
- 🌐 **OpenClaw Browser Sidecar**: Headless Chromium gateway for complex web interaction, authentication bypass testing, and dynamic DOM crawling.
- ⚡ **OWASP ZAP Integration**: Automated active/passive web application scanning, spidering, and REST API vulnerability discovery via sidecar daemon.
- 🛡️ **Legal Target Authorization Engine**: Configurable target whitelist enforcing explicit legal scope (`lab`, `ctf`, `bug-bounty`, `self`, `client`) with strict override audit logging.
- 📊 **Real-Time Control Plane**: Modern FastAPI web interface featuring live Server-Sent Events (SSE) logs, real-time operator instruction injection, and instant run continuations.
- 🧪 **Built-in Lab Environment**: Ships with pre-configured isolated targets (**DVWA** and **Metasploitable2**) for safe local benchmarking and vulnerability research.

---

## ⏳ Long-Running Autonomous Research & Engagement Lifecycle

Traditional pentesting scripts fail on complex targets because they time out or lose context when an approach encounters a obstacle. **anve-offsec** is engineered specifically for **unattended, long-running security engagements**:

```mermaid
flowchart TD
    Start([🚀 Launch Engagement]) --> Phase1[Phase 1: Deep Recon & Asset Discovery]
    Phase1 --> Check1{Phase Outcome?}
    
    Check1 -->|Success| Phase2[Phase 2: Baseline & Vulnerability Scan]
    Check1 -->|Failure Attempt 1| Retry1[Attempt 2: Alternative Tooling / Parameters]
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

### 1. Zero Context Loss Across Phases
Each phase executes as part of a single continuous Hermes session (`--resume <session_id>`). The agent remembers every discovery, header, directory scan, and error encountered in earlier phases, avoiding duplicate work.

### 2. Adaptive 3-Attempt Strategy Escalation
When a phase faces roadblocks (e.g., WAF blocks or closed ports), the runner enforces a progressive retry escalation:
- **Attempt 1**: Standard tooling and default wordlists.
- **Attempt 2**: Evasion flags (e.g., `--tamper`, user-agent rotation, proxy routing).
- **Attempt 3**: Radically different approaches (e.g., custom Python payloads, out-of-band exfiltration, or custom exploit frameworks).

### 3. Crash-Safe Session Persistence
All state is written to `/work/dashboard-logs/<run_id>.engagement.json` after every turn. If Docker restarts or host power cycles, the engagement seamlessly resumes at the exact active phase with full LLM session memory restored.

### 4. Live Mid-Run Operator Steering
Operators can inject instructions from the dashboard UI in real time without interrupting the run:
- *"Focus on the `/api/v2/` endpoints"*
- *"Bypass cloudflare WAF using origin IP `192.168.1.50`"*
Instructions are queued and delivered to Hermes on its next decision turn.

---

## 🧬 Self-Evolving Pentest Architecture (RAG + Qdrant)

**anve-offsec** gets smarter with every target it tests. It doesn't rely on static templates; it builds a cumulative strategy model over time:

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

### Strategy Memory Architecture (`/work/memory/strategy.json`):
1. **Scenario Classification**: Indexes target types (e.g., `web-app:sql-injection`, `api:bbola`, `infra:ssh-enum`).
2. **Tool Effectiveness Tracking**: Calculates real success rates and average completion times for tools (`sqlmap`, `nmap`, `zap`, `gobuster`, `ffuf`, `nuclei`).
3. **Cross-Agent Knowledge Sharing**: Discoveries from a `recon` agent automatically seed strategy prompts for `owasp/injection` or `exploit` agents.

---

## 🧠 Deep Dive: The Hermes AI Reasoning Brain

At the core of **anve-offsec** is **Hermes**—a specialized AI reasoning agent acting as the lead security researcher inside the Kali Linux environment.

### Specialized Persona Hierarchy
Over 40+ prompt configurations in `config/agents/` allow Hermes to dynamically assume specialized roles:
- **Core Roles**: `bug-bounty`, `recon`, `web`, `exploit`, `report`
- **OWASP Specialists**: `owasp/injection`, `owasp/auth`, `owasp/access-control`, `owasp/ssrf`, `owasp/crypto`, `owasp/misconfig`
- **MITRE ATT&CK**: `mitre/recon`, `mitre/initial-access`, `mitre/credential-access`, `mitre/privilege-escalation`, `mitre/lateral-movement`
- **Supervision & Safety**: `adviser` (loop detection), `reflector` (failure recovery), `barrier` (human-in-the-loop control)

---

## ⚖️ Feature Comparison Matrix

| Feature | `anve-offsec` | Traditional Scanners (ZAP/Nessus) | Generic LLM Wrappers |
|---|---|---|---|
| **Execution Engine** | Native Kali Linux Shell + Python | Pre-programmed Rules | Basic Script Generation |
| **Session Memory** | Stateful `--resume` across multi-hour runs | None | Single-turn context window |
| **Self-Evolution** | Qdrant Vector RAG + Strategy Learning | Manual Rule Updates | None |
| **Browser Automation** | OpenClaw Headless Chromium Sidecar | Simple HTTP Crawler | Basic Puppeteer Scripts |
| **Safety Governance** | Explicit Target Authorization + Override Logs | Target URL Input | No Scope Controls |
| **Operator Steering** | Live Mid-Run Instruction Injection | Hard Stop / Start | Re-run Prompt |

---

## 🏗️ System Architecture

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

---

## 🔬 Benchmark Case Studies

### 📑 Case Study 1: Automated Assessment of Damn Vulnerable Web App (DVWA)

- **Target**: Local DVWA container (`http://dvwa:8080`)
- **Agent Assigned**: `bug-bounty` (Hermes Brain + OWASP Specialists)
- **Execution Flow**:
  1. **Phase 1 (Reconnaissance)**: Hermes runs `whatweb` and `curl` to fingerprint PHP/Apache stack and detect default cookie structures.
  2. **Phase 2 (ZAP Baseline & Crawler)**: Triggers ZAP spider via API (`zap_client.py`) to discover `/vulnerabilities/sqli/`, `/vulnerabilities/exec/`, `/vulnerabilities/fi/`.
  3. **Phase 3 (Targeted Vulnerability Testing)**:
     - Detects Command Injection on `/vulnerabilities/exec/` via IP input ping parameter (`127.0.0.1; id`).
     - Detects SQL Injection on `/vulnerabilities/sqli/` (`1' OR '1'='1`).
     - Verifies File Inclusion on `/vulnerabilities/fi/?page=include.php`.
  4. **Phase 4 (Reporting & Evidence Generation)**: Writes full JSON & Markdown vulnerability report with exact reproduction steps to `/work/loot/dvwa_report.md`.
- **Outcome**: 100% automated detection of high & critical vulnerabilities in under 8 minutes without human intervention.

---

### 📑 Case Study 2: Metasploitable2 Infrastructure & Service Enumeration

- **Target**: Local Metasploitable2 container (`http://metasploitable2:8081`)
- **Agent Assigned**: `recon` + `exploit`
- **Execution Flow**:
  1. **Phase 1 (Host & Service Discovery)**: Runs Nmap service version scan (`nmap -sV -sC`) to identify open ports: 21 (VSFTPD 2.3.4), 22 (OpenSSH 4.7p1), 80 (Apache 2.2.8), 6667 (UnrealIRCd).
  2. **Phase 2 (CVE Lookup & Vulnerability Matching)**: Queries local RAG knowledge base & CVE lookup tools for known exploits targeting VSFTPD 2.3.4 (backdoor execution) and UnrealIRCd.
  3. **Phase 3 (Verification & Proof-of-Concept)**: Synthesizes custom Python exploit script (`/tools/exploit_framework.py`) to safely verify backdoor reactivity.
- **Outcome**: Identified 6 exploit paths and generated executive summary report.

---

### 📑 Case Study 3: Auth Wall Bypass & Dynamic Session Automation

- **Target**: Protected Client Staging Web Application
- **Agent Assigned**: `auth-wall` + OpenClaw Browser Sidecar
- **Execution Flow**:
  1. **Phase 1 (Browser Navigation)**: OpenClaw sidecar launches headless Chromium, navigates to target login page, and fills credentials dynamically.
  2. **Phase 2 (Token Extraction & Session Injection)**: Extracts JWT Bearer token & session cookies from browser state, handing them off to Hermes inside Kali.
  3. **Phase 3 (Authenticated Vulnerability Testing)**: Hermes uses authenticated tokens to run IDOR scans (`idor_scanner.py`) and API checks (`api_tester.py`) against post-login endpoints.
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

## 🔒 Authorization & Ethical Safeguards

`anve-offsec` incorporates strict governance controls to prevent unauthorized testing:

- **Target Whitelisting (`config/authorized-targets.json`)**: Enforces explicit authorization categories:
  - `lab`: Local Docker targets (`127.0.0.1`, `dvwa`, `metasploitable2`).
  - `ctf`: Platforms like TryHackMe, HackTheBox, VulnHub.
  - `bug-bounty`: HackerOne, Bugcrowd, Intigriti scope.
  - `self` / `client`: Whitelisted domains.
- **Audit Logging**: Any manual target override requires explicit confirmation text and is permanently logged to `/work/memory/override-log.jsonl`.
- **Budgeting & Turn Limits**: Features automatic turn timeouts (`1800s`), max engagement hours (`6h`), price limiters, and infinite loop detection.

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
