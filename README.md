# 🛡️ anve-offsec: Autonomous Bug Bounty & Offensive Security Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker](https://img.shields.io/badge/Docker-24.0+-0db7ed.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![Kali Linux](https://img.shields.io/badge/OS-Kali_Rolling-blueviolet.svg?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![FastAPI](https://img.shields.io/badge/Control_Plane-FastAPI-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![OpenClaw](https://img.shields.io/badge/Browser-OpenClaw_Sidecar-FF4500.svg)](https://openclaw.ai)
[![Qdrant](https://img.shields.io/badge/Memory-Qdrant_Vector_RAG-red.svg?logo=qdrant&logoColor=white)](https://qdrant.tech/)

> **anve-offsec** is an enterprise-grade, autonomous bug bounty and offensive-security operations platform. It combines a stateful **Kali Linux core container**, the **Hermes AI Reasoning Brain**, **OpenClaw headless Chromium automation**, **OWASP ZAP vulnerability scanning**, and **Qdrant RAG memory** into a unified, self-evolving system.

---

## 📸 Key Features at a Glance

- 🧠 **Hermes Reasoning Engine**: Multi-turn LLM agent capable of executing complex terminal commands, tools, and custom exploits natively inside Kali Linux.
- 🌐 **OpenClaw Browser Sidecar**: Headless Chromium gateway for complex web interaction, authentication bypass testing, and dynamic web application crawling.
- ⚡ **OWASP ZAP Integration**: Automated active/passive web scanning, spidering, and REST API vulnerability discovery via sidecar daemon.
- 🧠 **Vector RAG Memory (Qdrant)**: Continuous self-learning engine that stores attack strategies, confidence scores, and historical execution outcomes.
- 🛡️ **Legal Target Authorization Engine**: Configurable target whitelist enforcing explicit legal scope (`lab`, `ctf`, `bug-bounty`, `self`, `client`) with strict override audit logging.
- 📊 **Real-Time Stream Dashboard**: Modern FastAPI web control plane featuring live Server-Sent Events (SSE) logs, real-time operator instruction injection, and instant run continuations.
- 🧪 **Built-in Lab Environment**: Ships with pre-configured isolated targets (**DVWA** and **Metasploitable2**) for safe local benchmarking and vulnerability research.

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

## 🧰 Microservice Components

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
  <b>Built with ❤️ for the AI & Cybersecurity Community</b><br>
  <i>Starred the repo? Give it a ⭐️ to support continuous development!</i>
</p>
