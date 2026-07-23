<p align="center">
  <img src="https://raw.githubusercontent.com/ANVEAI/anve-offsec/main/docs/assets/banner.png" alt="anve-offsec banner" width="100%" error="this.src='https://via.placeholder.com/1200x400/0d1117/58a6ff?text=anve-offsec+:+Autonomous+AI+Security+Engineer'"/>
</p>

<h1 align="center">🛡️ anve-offsec</h1>
<p align="center">
  <b>The Open-Source Autonomous AI Security Engineer & Bug Bounty Platform</b>
</p>

<p align="center">
  <i>Stateful Kali Linux Execution • Hermes AI Reasoning Brain • OpenClaw Chromium Gateway • Self-Evolving Qdrant RAG Memory</i>
</p>

<p align="center">
  <a href="https://github.com/ANVEAI/anve-offsec/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge&logo=apache" alt="License"></a>
  <a href="https://github.com/ANVEAI/anve-offsec"><img src="https://img.shields.io/badge/Proudly_Made_in-India_🇮🇳-FF9933.svg?style=for-the-badge" alt="Made in India"></a>
  <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/Docker-24.0+-0db7ed.svg?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"></a>
  <a href="https://www.kali.org/"><img src="https://img.shields.io/badge/OS-Kali_Rolling-blueviolet.svg?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux"></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/Control_Plane-FastAPI-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"></a>
  <a href="https://qdrant.tech/"><img src="https://img.shields.io/badge/Memory-Qdrant_Vector_RAG-red.svg?style=for-the-badge&logo=qdrant&logoColor=white" alt="Qdrant"></a>
</p>

<p align="center">
  <a href="#-what-is-anve-offsec">What is anve-offsec?</a> •
  <a href="#-see-it-in-action">Demo</a> •
  <a href="#-multipage-technical-documentation-index">Documentation</a> •
  <a href="#-why-anve-offsec-the-feature-matrix">Feature Matrix</a> •
  <a href="#-quick-start-up-in-60-seconds">Quick Start</a> •
  <a href="#%EF%B8%8F-project-roadmap">Roadmap</a>
</p>

---

## ⚡ What is `anve-offsec`?

**`anve-offsec`** is a production-grade, autonomous bug bounty and offensive security platform **proudly engineered in India 🇮🇳**. Unlike traditional vulnerability scanners that rely on static regex rules, or generic LLM wrappers that hallucinate commands, `anve-offsec` operates as a **full-fledged AI security engineer**.

It combines a **stateful Kali Linux core container** with the **Hermes AI Reasoning Brain**, **OpenClaw headless Chromium sidecar**, **OWASP ZAP scanning daemon**, and **Qdrant vector RAG memory**. It continuously researches target attack surfaces, dynamically writes custom exploits, retains 100% session context across multi-hour engagements, and **learns from every execution outcome**.

---

## 🎬 See it in Action

<p align="center">
  <img src="https://raw.githubusercontent.com/ANVEAI/anve-offsec/main/docs/assets/demo.gif" alt="anve-offsec Live Terminal & Hermes AI Execution" width="100%" />
</p>

```text
┌──(pentest㉿anve-offsec)-[/work]
└─$ ./scripts/hermes.sh --task "Run a full bug bounty assessment on http://dvwa:8080"

[🧠 Hermes Reasoning Engine] Analyzing target http://dvwa:8080...
[+] Initializing Recon Phase: Fingerprinting PHP/Apache stack...
[+] Invoking OpenClaw Chromium Gateway for authentication flow...
[+] Discovered endpoint: /vulnerabilities/sqli/ (SQL Injection)
[+] Crafting dynamic exploit payload: 1' OR '1'='1 ...
[+] Exploit Verified! Dumping database schema to /work/loot/sqli_dump.json
[+] Ingesting successful payload into Qdrant Vector Memory RAG...
[+] PHASE_COMPLETE: Recon -> Scan -> Exploit -> Report (Time: 7m 42s)
```

---

## 📚 Multipage Technical Documentation Index

Explore the complete sub-documentation system in [`docs/`](docs/):

- 🏗️ **[Architecture & Microservice Spec](docs/ARCHITECTURE.md)** — Sidecar topology, DinD workers, OOB listeners (`28000–30000`).
- 🧠 **[Hermes AI Reasoning Brain Spec](docs/HERMES_BRAIN.md)** — Multi-turn session persistence, 40+ agent prompts, phase completion signals.
- 🧬 **[Self-Evolution & Vector RAG Spec](docs/SELF_EVOLUTION.md)** — Qdrant vector memory indexing, confidence score heuristics (`0.7`/`0.85`), strategy prompt injection.
- 🛡️ **[Defensive Guardrails & Security](docs/GUARDRAILS_SECURITY.md)** — Prompt injection filters, destructive command interception, target scope auditing.
- 🔬 **[Benchmark Case Studies](docs/CASE_STUDIES.md)** — Comprehensive execution logs for DVWA, Metasploitable2, and Auth Wall OpenClaw bypass.
- 🤝 **[Contribution Guidelines](docs/CONTRIBUTING.md)** — How to add new specialized agents, tools, and submit pull requests.

---

## 🔥 Why `anve-offsec`? (The Feature Matrix)

| Capability | 🛡️ `anve-offsec` | 🐢 Traditional Scanners (ZAP/Nessus) | 🤖 Generic LLM Wrappers |
|---|---|---|---|
| **Execution Environment** | **Native Kali Linux Shell + Python** | Fixed Rule Scripts | Text Snippets Only |
| **Session Memory** | **Stateful `--resume` (Hours/Days)** | None | Single-Turn Context Limit |
| **Self-Evolution** | **Qdrant RAG Memory (Learns from runs)** | Static Signatures | None |
| **Browser Automation** | **OpenClaw Headless Chromium Sidecar** | Basic HTTP Crawling | Basic Puppeteer Scripts |
| **Adaptive Escalation** | **Standard $\rightarrow$ Evasion $\rightarrow$ Custom Exploit** | Single Pass Scan | Halts on Error |
| **Safety Governance** | **Prompt Injection Interception + Target Scope Audit** | Simple Scope Regex | No Guardrails |
| **Operator Steering** | **Real-Time Mid-Run Instruction Queue (SSE)** | Cancel Only | Restart Session |

---

## 🚀 Quick Start (Up in 60 Seconds)

### 1. One-Line Launch

```bash
# 1. Clone the repository
git clone https://github.com/ANVEAI/anve-offsec.git && cd anve-offsec

# 2. Configure runtime environment
cp .env.example .env && nano .env

# 3. Spin up all microservices with Docker Compose
docker compose up -d && ./scripts/setup-openclaw.sh
```

### 2. Open Control Plane Dashboard

Open **`http://127.0.0.1:8000`** in your browser to launch agent runs, view live SSE logs, inspect captured loot, and inject instructions in real time.

```bash
# Or trigger a run directly via REST API:
curl -X POST http://127.0.0.1:8000/api/agents/bug-bounty/run \
  -H "Content-Type: application/json" \
  -d '{"task":"Run full assessment on http://dvwa:8080"}'
```

---

## 🏗️ System Architecture & Microservice Sidecars

```mermaid
graph TD
    Operator([👨‍💻 Security Researcher / Operator]) -->|HTTP / SSE Stream :8000| ControlPlane[📊 FastAPI Control Plane - dashboard/app.py]
    ControlPlane -->|Orchestrates Runs| Runner[⚙️ Engagement Runner - tools/engagement_runner.py]
    
    subgraph Core Platform Microservices
        Runner -->|Native Terminal Shell| KaliCore[🛡️ Kali Linux Core Container]
        Runner -->|DinD Container Spawning| DinD[🐳 Docker Socket / var/run/docker.sock]
        Runner -->|API Web Scanning| ZAPDaemon[⚡ OWASP ZAP Daemon - :8090]
        Runner -->|Headless DOM Automation| OpenClawGateway[🌐 OpenClaw Chromium - :18789]
        Runner -->|Vector Strategy RAG| QdrantDB[🧠 Qdrant Vector DB - :6333]
        Runner -->|Lab VPN Tunneling| OpenVPN[🔒 OpenVPN Client Container]
    end

    subgraph Safe Local Testing Sandbox
        KaliCore -. Authorized Scans .-> DVWA[🧪 DVWA Target - :8080]
        KaliCore -. Authorized Scans .-> Meta[🧪 Metasploitable2 Target - :8081]
    end
```

- **DinD Worker Spawning**: Kali core mounts `/var/run/docker.sock` to spin up ephemeral sub-worker containers for isolated task flows.
- **OOB Callback Listeners (`28000-30000`)**: Dynamic host port allocation for handling reverse shell callbacks, out-of-band HTTP verification, and blind SSRF callbacks.

---

## 🧠 The Hermes AI Reasoning Engine (`tools/engagement_runner.py`)

Hermes acts as the stateful reasoning brain inside Kali Linux. It operates across **40+ specialized agent roles**:

```
                               ┌───────────────────────────┐
                               │   Hermes Reasoning Brain  │
                               └─────────────┬─────────────┘
                                             │
      ┌──────────────────────┬───────────────┴───────────────┬──────────────────────┐
      │                      │                               │                      │
      ▼                      ▼                               ▼                      ▼
┌───────────┐      ┌───────────────────┐           ┌───────────────────┐      ┌───────────┐
│ Core Roles│      │ OWASP Specialists │           │ MITRE ATT&CK      │      │ Safety    │
│ - Recon   │      │ - owasp/injection │           │ - initial-access  │      │ - adviser │
│ - Web     │      │ - owasp/auth      │           │ - cred-access     │      │ - reflect │
│ - Exploit │      │ - owasp/ssrf      │           │ - priv-escalation │      │ - barrier │
│ - Report  │      │ - owasp/idor      │           │ - lateral-move    │      │ (Human)   │
└───────────┘      └───────────────────┘           └───────────────────┘      └───────────┘
```

---

## 🧬 Self-Evolving Strategy RAG Engine (`tools/evolution_engine.py`)

Every engagement outcome is processed, embedded, and stored in **Qdrant Vector DB**:

```
[Completed Run] ──► [Scenario Matcher] ──► [Score Strategy] ──► [Qdrant RAG Ingestion]
                                                                        │
                                                                        ▼
[Next Target]  ◄── [Inject Past Lessons] ◄── [Query Vector DB] ◄────────┘
```

1. **Scenario Classification**: Automatically categorizes target tasks into structured scenarios (`web-app:sql-injection`, `web-app:ssrf`, `api:idor`, `infra:ssh-enum`).
2. **Confidence Thresholding**:
   - `CONFIDENCE_THRESHOLD = 0.7`: RAG strategies above 70% confidence are injected into active prompts.
   - `AUTO_PROMPT_UPDATE_THRESHOLD = 0.85`: Strategies above 85% confidence automatically update static agent prompts (`config/agents/*.prompt`).

---

## 🛡️ Defensive Guardrails & Safety Governance (`tools/guardrails.py`)

`anve-offsec` includes production-grade security controls:

- **Input Guardrails**: Protects against prompt injection by scanning for adversarial patterns (`ignore previous instructions`, `<system>`, `<root>`) and decoding base64 / unicode homographs.
- **Output Guardrails**: Intercepts dangerous terminal commands before execution inside Kali (`rm -rf /`, `mkfs`, fork bombs, system shutdown).
- **Data Exfiltration Interception**: Blocks access to sensitive host paths (`/etc/shadow`, `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.git-credentials`).
- **Target Scope Authorization Framework (`config/authorized-targets.json`)**: Enforces explicit legal target scope checking (`lab`, `ctf`, `bug-bounty`, `self`, `client`). Unapproved target overrides require typed operator confirmation and are audited to `/work/memory/override-log.jsonl`.

---

## 🔬 Benchmark Case Studies

| Benchmark Target | Assigned Agent | Automated Vulnerabilities Detected | Execution Time | Report Status |
|---|---|---|---|---|
| **DVWA** (`http://dvwa:8080`) | `bug-bounty` | Command Injection, SQLi, LFI, Stored XSS | **7m 42s** | Generated (`/work/loot/dvwa_report.md`) |
| **Metasploitable2** (`:8081`) | `recon` + `exploit` | VSFTPD 2.3.4 Backdoor, UnrealIRCd, SSH Enum | **11m 15s** | Verified PoC Exploit Generated |
| **Protected Staging Portal** | `auth-wall` + `openclaw` | Broken Object-Level Authorization (BOLA/IDOR) | **14m 20s** | Full API Assessment Complete |

---

## 🗺️ Project Roadmap

- [x] **Multi-Agent Architecture**: Stateful Hermes AI Reasoning Brain + OpenClaw headless Chromium browser sidecar.
- [x] **Self-Evolution Engine**: Qdrant vector RAG memory for continuous strategy learning across target runs.
- [x] **Real-Time Control Plane**: FastAPI web dashboard featuring real-time SSE streaming & mid-run operator steering.
- [x] **Defensive Guardrails**: Prompt injection interception, destructive command blocking, and legal scope auditing.
- [ ] **v1.5: Plug & Play Appliance System**: Zero-config auto-discovery of local network targets, pre-baked environment defaults, and hardware acceleration (Apple Silicon Metal / NVIDIA CUDA).
- [ ] **v2.0: Full AI OS Based GUI VM (Kali Native)**: Standalone Kali Linux ISO & OVA virtual machine appliance with built-in AI desktop control plane, QEMU/VMware snapshot rollback, and GUI assistant windows.
- [ ] **v2.5: One-Click Cloud Deployment**: 1-click Cloud launcher scripts & Terraform/Helm templates for AWS AMI, GCP Marketplace, DigitalOcean Droplet, and Azure.
- [ ] **v3.0: Distributed Swarm Worker Nodes**: Distributed agent worker nodes with mutual-TLS dind worker isolation across multi-region cloud providers.
- [ ] **v3.5: Enterprise Executive Reporting**: Automated PDF & HTML executive report synthesis with custom branding and visual PoC diffs.

---

## 🤝 Community & Support

- 💬 **[GitHub Discussions](https://github.com/ANVEAI/anve-offsec/discussions)** — Feature requests, feedback, and architecture ideas.
- 🐛 **[Issue Tracker](https://github.com/ANVEAI/anve-offsec/issues)** — Report bugs or request tool integrations.
- 🤝 **[Contributing Guide](docs/CONTRIBUTING.md)** — Guidelines for pull requests.

---

## ⚠️ Legal Disclaimer

> **IMPORTANT**: `anve-offsec` is built strictly for authorized security assessments, penetration testing within explicit scope, educational research, and bug bounty hunting. Operating this software against targets without explicit written authorization is illegal. The creators and contributors assume no liability for misuse or damage caused by this platform.

---

## 📜 License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Proudly Made in India 🇮🇳 | Built with ❤️ for the Global AI & Cybersecurity Community</b><br>
  <i>If you find anve-offsec useful, please give us a ⭐️ on GitHub to support continuous development!</i>
</p>
