[⬅️ Back to README](../README.md) | [Architecture](ARCHITECTURE.md) | [Hermes Brain](HERMES_BRAIN.md) | [Self-Evolution](SELF_EVOLUTION.md) | [Guardrails](GUARDRAILS_SECURITY.md) | [Case Studies](CASE_STUDIES.md) | **Contributing**

---

# 🤝 Contributing to anve-offsec

Thank you for your interest in contributing to **anve-offsec**! We welcome community pull requests, bug fixes, agent prompt enhancements, and new security tool integrations.

---

## 🛠️ Development Setup

1. **Fork & Clone Repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/anve-offsec.git
   cd anve-offsec
   ```

2. **Set Up Local Environment**:
   ```bash
   cp .env.example .env
   docker compose up -d
   ```

3. **Verify Environment Health**:
   - Check Dashboard at `http://127.0.0.1:8000`
   - Run a test scan against local DVWA target (`http://dvwa:8080`)

---

## 📐 How to Add a New Specialized Agent

Specialized agent personas live in `config/agents/`.

To add a new agent persona:
1. Create a prompt file: `config/agents/your-category/your-agent.prompt`.
2. Register the agent in `config/agents/models.json`:
   ```json
   "your-agent": {
     "description": "Specialized agent for testing custom vulnerabilities",
     "prompt_file": "config/agents/your-category/your-agent.prompt",
     "model": "kimi-k3"
   }
   ```
3. Test your agent from the Dashboard dropdown or via CLI.

---

## 📜 Pull Request Guidelines

- **Keep PRs Focused**: One feature or bug fix per pull request.
- **Do NOT Commit Secrets**: Make sure `.env`, `.ovpn` files, and personal credentials are not included.
- **Include Verification**: Provide terminal logs or screenshot proof of test runs.
- **License**: All contributions must be licensed under the Apache License 2.0.
