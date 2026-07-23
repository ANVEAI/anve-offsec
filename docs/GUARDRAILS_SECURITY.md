# 🛡️ Defensive Guardrails & Security Governance Specification (`tools/guardrails.py`)

This document details the multi-layered security controls, prompt injection filters, command interception rules, and target scope authorization framework in **anve-offsec**.

---

## 🔒 Security Layers Overview

```
[User Input / Prompt] ──► [Input Guardrails] ──► [Hermes Reasoning] ──► [Output Guardrails] ──► [Kali Shell Execution]
                                                                                │
                                                                                ▼
                                                                     [Target Scope Check]
```

---

## 1. 🛡️ Input Guardrails (Prompt Injection Prevention)

`tools/guardrails.py` analyzes incoming tasks and user input for adversarial prompt injection patterns:

### Intercepted Patterns:
- `ignore (previous|above|all) (instructions|prompts|rules)`
- `forget (everything|all|previous)`
- `you are now (a|an) (admin|root|system|god|master)`
- `<system>`, `<admin>`, `<root>`, `<god>`, `<master>` tags

### Obfuscation Checks:
- **Base64 Decode Verification**: Automatically decodes Base64 strings in user prompts to check for hidden prompt injections.
- **Unicode Homograph Resolution**: Normalizes lookalike Unicode characters before input processing.

---

## 2. ⚡ Output Guardrails (Destructive Command Interception)

Before executing any terminal string inside Kali, `guardrails.py` checks the command against a blacklist of destructive operations:

### Destructive Operations Blocked:
- File system destruction: `rm -rf /`, `rm -rf *`, `mkfs`, `dd if=/dev/zero of=/dev/sd*`
- Denial of Service / Fork Bombs: `:(){ :|:& };:`, `kill -9 -1`, `killall -9 init`
- Unauthorized Privileges: `chmod 777 /`, `chown root /`, `echo ... >> /etc/sudoers`
- System Shutdown / Reboot: `shutdown now`, `reboot`, `poweroff`, `init 0`, `init 6`
- Firewall Disabling: `iptables -F`, `ufw disable`, `systemctl stop firewalld`

---

## 3. 🔑 Data Exfiltration Prevention

Prevents LLM agents from reading sensitive host keys or user credentials during security assessments:

### Sensitive Paths Intercepted:
- `/etc/shadow`, `/etc/sudoers`
- `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`
- `~/.aws/credentials`, `~/.azure/credentials`, `~/.kube/config`
- `~/.docker/config.json`, `~/.git-credentials`, `~/.zsh_history`

---

## 4. 🎯 Target Authorization Framework (`config/authorized-targets.json`)

To prevent unauthorized target testing, **anve-offsec** enforces explicit domain scope validation:

### Authorization Categories:
- `lab`: Auto-authorizes local lab targets (`127.0.0.1`, `localhost`, `dvwa`, `metasploitable2`).
- `ctf`: Pre-approved CTF platforms (`*.tryhackme.com`, `*.hackthebox.com`, `*.vulnhub.com`).
- `bug-bounty`: Platform scopes from HackerOne, Bugcrowd, Intigriti, YesWeHack.
- `self` / `client`: Whitelisted client domains.

### Override Confirmation Audit:
Testing targets outside pre-approved categories requires explicit operator confirmation text:
> *"I confirm I am authorized to test <target> and accept all legal responsibility"*

All target overrides are logged to `/work/memory/override-log.jsonl` for legal auditability.
