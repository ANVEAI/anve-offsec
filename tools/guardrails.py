#!/usr/bin/env python3
"""
Guardrails for kali-ai.

Input/output protection against prompt injection and dangerous command execution.
Inspired by CAI's guardrails.

Usage: python3 /tools/guardrails.py <command> [args]
"""

import base64
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

GUARDRAILS_FILE = Path("/config/guardrails.json")

DEFAULT_GUARDRAILS = {
    "enabled": True,
    "input_guardrails": {
        "prompt_injection_patterns": [
            r"ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?)",
            r"forget\s+(everything|all|previous)",
            r"you\s+are\s+now\s+(a|an)\s+(admin|root|system|god|master)",
            r"do\s+not\s+(follow|obey|listen\s+to)\s+(the|any)\s+(rules?|instructions?|guidelines?)",
            r"system\s*:\s*you\s+(are|must|should|will)",
            r"<\s*system\s*>",
            r"<\s*admin\s*>",
            r"<\s*root\s*>",
            r"<\s*god\s*>",
            r"<\s*master\s*>",
        ],
        "unicode_homograph_check": True,
        "base64_decode_check": True,
        "max_input_length": 100000,
    },
    "output_guardrails": {
        "dangerous_commands": [
            r"rm\s+-rf\s+[/\*]",
            r"mkfs\s",
            r"dd\s+if=/dev/(zero|random)\s+of=/dev/(sd|hd|nvme|xvd)",
            r"fork\s*\(\s*\)\s*;\s*fork\s*\(\s*\)",
            r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;:",
            r"nc\s+-[elp]\s+\d+\s+-e\s+/bin/(ba|z)?sh",
            r"bash\s+-i\s+>&\s+/dev/tcp/",
            r"python3\s+-c\s+['\"]import\s+socket\s*,\s*subprocess\s*,\s*os\s*;\s*s\s*=\s*socket\s*\.\s*socket\s*\(\s*socket\s*\.\s*AF_INET\s*,\s*socket\s*\.\s*SOCK_STREAM\s*\)",
            r"powershell\s+-[eE]nc?\s+",
            r"certutil\s+-urlcache\s+-split\s+-f\s+https?://",
            r"curl\s+https?://[^\s]+\s*\|\s*(ba)?sh",
            r"wget\s+https?://[^\s]+\s*-O\s+[^\s]+\s*\|\s*(ba)?sh",
            r"chmod\s+777\s+[/\*]",
            r"chown\s+root\s+[/\*]",
            r"useradd\s+-m\s+-s\s+/bin/bash\s+-g\s+0",
            r"echo\s+[^\s]+\s*>>\s*/etc/passwd",
            r"echo\s+[^\s]+\s*>>\s*/etc/sudoers",
            r"iptables\s+-F",
            r"ip6tables\s+-F",
            r"ufw\s+disable",
            r"setenforce\s+0",
            r"systemctl\s+stop\s+(firewalld|iptables|ip6tables|ufw|selinux)",
            r"service\s+(firewalld|iptables|ip6tables|ufw|selinux)\s+stop",
            r"kill\s+-9\s+-1",
            r"killall\s+-9\s+(init|systemd|bash|sh)",
            r"pkill\s+-9\s+(init|systemd|bash|sh)",
            r"shutdown\s+(now|-h\s+now|-r\s+now)",
            r"reboot\s+now",
            r"halt\s+now",
            r"poweroff\s+now",
            r"init\s+0",
            r"init\s+6",
            r"telinit\s+0",
            r"telinit\s+6",
        ],
        "data_exfiltration_patterns": [
            r"cat\s+/etc/(passwd|shadow|sudoers)",
            r"cat\s+~/.ssh/id_rsa",
            r"cat\s+~/.aws/credentials",
            r"cat\s+~/.config/gcloud/credentials",
            r"cat\s+~/.azure/credentials",
            r"cat\s+~/.kube/config",
            r"cat\s+~/.docker/config\.json",
            r"cat\s+~/.npmrc",
            r"cat\s+~/.pypirc",
            r"cat\s+~/.git-credentials",
            r"cat\s+~/.gitconfig",
            r"cat\s+~/.netrc",
            r"cat\s+~/.pgpass",
            r"cat\s+~/.my\.cnf",
            r"cat\s+~/.bash_history",
            r"cat\s+~/.zsh_history",
            r"cat\s+~/.python_history",
            r"cat\s+~/.mysql_history",
            r"cat\s+~/.psql_history",
            r"cat\s+~/.sqlite_history",
            r"cat\s+~/.irb_history",
            r"cat\s+~/.node_repl_history",
            r"cat\s+~/.gh/hosts\.yml",
            r"cat\s+~/.config/gh/hosts\.yml",
            r"cat\s+~/.config/hub",
            r"cat\s+~/.gem/credentials",
            r"cat\s+~/.bundle/config",
            r"cat\s+~/.cargo/credentials",
            r"cat\s+~/.config/pip/pip\.conf",
            r"cat\s+~/.pip/pip\.conf",
            r"cat\s+~/.condarc",
            r"cat\s+~/.config/conda/condarc",
            r"cat\s+~/.jupyter/jupyter_notebook_config\.json",
            r"cat\s+~/.jupyter/jupyter_server_config\.json",
            r"cat\s+~/.ipython/profile_default/startup/[^/]+\.py",
            r"cat\s+~/.local/share/jupyter/runtime/[^/]+\.json",
            r"cat\s+~/.vscode-server/data/Machine/settings\.json",
            r"cat\s+~/.vscode/settings\.json",
            r"cat\s+~/.config/Code/User/settings\.json",
            r"cat\s+~/.config/Code\s*-\s*Insiders/User/settings\.json",
            r"cat\s+~/.config/VSCodium/User/settings\.json",
            r"cat\s+~/.config/atom/config\.cson",
            r"cat\s+~/.atom/config\.cson",
            r"cat\s+~/.config/sublime-text-3/Packages/User/Preferences\.sublime-settings",
            r"cat\s+~/.config/sublime-text/Packages/User/Preferences\.sublime-settings",
            r"cat\s+~/.config/notepad\+\+/config\.xml",
            r"cat\s+~/.config/notepadqq/preferences\.ini",
            r"cat\s+~/.config/geany/geany\.conf",
            r"cat\s+~/.config/kate/katerc",
            r"cat\s+~/.config/kdevelop/kdeveloprc",
            r"cat\s+~/.config/kdiff3/kdiff3rc",
            r"cat\s+~/.config/krusader/krusaderrc",
            r"cat\s+~/.config/dolphin/dolphinrc",
            r"cat\s+~/.config/konsole/konsolerc",
            r"cat\s+~/.config/yakuake/yakuakerc",
            r"cat\s+~/.config/terminator/config",
            r"cat\s+~/.config/tilix/tilix\.conf",
            r"cat\s+~/.config/guake/guake\.conf",
            r"cat\s+~/.config/tilda/tilda\.conf",
            r"cat\s+~/.config/xfce4/terminal/terminalrc",
            r"cat\s+~/.config/lxterminal/lxterminal\.conf",
            r"cat\s+~/.config/mate-terminal/mate-terminal\.conf",
            r"cat\s+~/.config/qterminal/qterminal\.ini",
            r"cat\s+~/.config/kitty/kitty\.conf",
            r"cat\s+~/.config/alacritty/alacritty\.yml",
            r"cat\s+~/.config/wezterm/wezterm\.lua",
            r"cat\s+~/.config/foot/foot\.ini",
            r"cat\s+~/.config/st/st\.conf",
            r"cat\s+~/.config/urxvt/Xresources",
            r"cat\s+~/.Xresources",
            r"cat\s+~/.Xdefaults",
            r"cat\s+~/.screenrc",
            r"cat\s+~/.tmux\.conf",
            r"cat\s+~/.byobu/screenrc",
            r"cat\s+~/.byobu/tmux\.conf",
            r"cat\s+~/.byobu/profile",
            r"cat\s+~/.byobu/color",
            r"cat\s+~/.byobu/keybindings",
            r"cat\s+~/.byobu/status",
            r"cat\s+~/.byobu/windows",
            r"cat\s+~/.byobu/presets",
            r"cat\s+~/.byobu/layouts",
            r"cat\s+~/.byobu/plugins",
            r"cat\s+~/.byobu/custom",
            r"cat\s+~/.byobu/local",
            r"cat\s+~/.byobu/remote",
            r"cat\s+~/.byobu/ssh",
            r"cat\s+~/.byobu/vim",
            r"cat\s+~/.byobu/emacs",
            r"cat\s+~/.byobu/nano",
            r"cat\s+~/.byobu/joe",
            r"cat\s+~/.byobu/pico",
            r"cat\s+~/.byobu/mcedit",
            r"cat\s+~/.byobu/kate",
            r"cat\s+~/.byobu/gedit",
            r"cat\s+~/.byobu/notepadqq",
            r"cat\s+~/.byobu/notepad\+\+",
            r"cat\s+~/.byobu/textpad",
            r"cat\s+~/.byobu/ultraedit",
            r"cat\s+~/.byobu/editplus",
            r"cat\s+~/.byobu/pspad",
            r"cat\s+~/.byobu/scite",
            r"cat\s+~/.byobu/geany",
            r"cat\s+~/.byobu/bluefish",
            r"cat\s+~/.byobu/komodo",
            r"cat\s+~/.byobu/zend",
            r"cat\s+~/.byobu/netbeans",
            r"cat\s+~/.byobu/android-studio",
            r"cat\s+~/.byobu/xcode",
            r"cat\s+~/.byobu/appcode",
            r"cat\s+~/.byobu/clion",
            r"cat\s+~/.byobu/datagrip",
            r"cat\s+~/.byobu/goland",
            r"cat\s+~/.byobu/phpstorm",
            r"cat\s+~/.byobu/pycharm",
            r"cat\s+~/.byobu/rider",
            r"cat\s+~/.byobu/rubymine",
            r"cat\s+~/.byobu/webstorm",
        ],
        "max_output_length": 1000000,
    },
}

from pathlib import Path


def _load_guardrails() -> Dict[str, Any]:
    if not GUARDRAILS_FILE.exists():
        return DEFAULT_GUARDRAILS
    try:
        return json.loads(GUARDRAILS_FILE.read_text())
    except Exception:
        return DEFAULT_GUARDRAILS


def _save_guardrails(guardrails: Dict[str, Any]) -> None:
    GUARDRAILS_FILE.write_text(json.dumps(guardrails, indent=2))


def _decode_base64(text: str) -> str:
    """Try to decode base64 text."""
    try:
        decoded = base64.b64decode(text).decode("utf-8", errors="replace")
        return decoded
    except Exception:
        return text


def _contains_homograph(text: str) -> bool:
    """Check for Unicode homograph attacks."""
    # Check for mixed scripts (Latin + Cyrillic, Latin + Greek, etc.)
    has_latin = any("a" <= c <= "z" or "A" <= c <= "Z" for c in text)
    has_cyrillic = any("\u0400" <= c <= "\u04FF" for c in text)
    has_greek = any("\u0370" <= c <= "\u03FF" for c in text)
    return (has_latin and has_cyrillic) or (has_latin and has_greek)


def check_input(text: str) -> Dict[str, Any]:
    """Check input for prompt injection and dangerous patterns."""
    guardrails = _load_guardrails()
    if not guardrails.get("enabled", True):
        return {"safe": True, "reason": "guardrails disabled"}

    input_config = guardrails.get("input_guardrails", {})
    issues = []

    # Check length
    max_length = input_config.get("max_input_length", 100000)
    if len(text) > max_length:
        issues.append({"type": "length", "severity": "high", "message": f"Input exceeds max length ({len(text)} > {max_length})"})

    # Check for prompt injection patterns
    patterns = input_config.get("prompt_injection_patterns", [])
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append({"type": "prompt_injection", "severity": "high", "message": f"Prompt injection pattern detected: {pattern}"})

    # Check for Unicode homographs
    if input_config.get("unicode_homograph_check", True) and _contains_homograph(text):
        issues.append({"type": "unicode_homograph", "severity": "medium", "message": "Unicode homograph attack detected (mixed scripts)"})

    # Check for base64-encoded payloads
    if input_config.get("base64_decode_check", True):
        # Look for base64-like strings
        b64_pattern = r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        for match in re.finditer(b64_pattern, text):
            decoded = _decode_base64(match.group())
            if decoded != match.group():
                # Check if decoded content contains dangerous patterns
                for pattern in patterns:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        issues.append({"type": "base64_payload", "severity": "high", "message": f"Base64-encoded prompt injection detected: {decoded[:100]}"})

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "severity": max([i["severity"] for i in issues], default="none"),
    }


def check_output(text: str) -> Dict[str, Any]:
    """Check output for dangerous commands and data exfiltration."""
    guardrails = _load_guardrails()
    if not guardrails.get("enabled", True):
        return {"safe": True, "reason": "guardrails disabled"}

    output_config = guardrails.get("output_guardrails", {})
    issues = []

    # Check length
    max_length = output_config.get("max_output_length", 1000000)
    if len(text) > max_length:
        issues.append({"type": "length", "severity": "high", "message": f"Output exceeds max length ({len(text)} > {max_length})"})

    # Check for dangerous commands
    dangerous_commands = output_config.get("dangerous_commands", [])
    for pattern in dangerous_commands:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append({"type": "dangerous_command", "severity": "critical", "message": f"Dangerous command detected: {pattern}"})

    # Check for data exfiltration patterns
    exfil_patterns = output_config.get("data_exfiltration_patterns", [])
    for pattern in exfil_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append({"type": "data_exfiltration", "severity": "high", "message": f"Data exfiltration pattern detected: {pattern}"})

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "severity": max([i["severity"] for i in issues], default="none"),
    }


def add_input_pattern(pattern: str) -> Dict[str, Any]:
    """Add a new input guardrail pattern."""
    guardrails = _load_guardrails()
    guardrails.setdefault("input_guardrails", {}).setdefault("prompt_injection_patterns", []).append(pattern)
    _save_guardrails(guardrails)
    return {"added": True, "pattern": pattern}


def add_output_pattern(pattern: str) -> Dict[str, Any]:
    """Add a new output guardrail pattern."""
    guardrails = _load_guardrails()
    guardrails.setdefault("output_guardrails", {}).setdefault("dangerous_commands", []).append(pattern)
    _save_guardrails(guardrails)
    return {"added": True, "pattern": pattern}


def add_exfil_pattern(pattern: str) -> Dict[str, Any]:
    """Add a new data exfiltration pattern."""
    guardrails = _load_guardrails()
    guardrails.setdefault("output_guardrails", {}).setdefault("data_exfiltration_patterns", []).append(pattern)
    _save_guardrails(guardrails)
    return {"added": True, "pattern": pattern}


def enable_guardrails() -> Dict[str, Any]:
    """Enable guardrails."""
    guardrails = _load_guardrails()
    guardrails["enabled"] = True
    _save_guardrails(guardrails)
    return {"enabled": True}


def disable_guardrails() -> Dict[str, Any]:
    """Disable guardrails."""
    guardrails = _load_guardrails()
    guardrails["enabled"] = False
    _save_guardrails(guardrails)
    return {"enabled": False}


def get_guardrails() -> Dict[str, Any]:
    """Get current guardrails configuration."""
    return _load_guardrails()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "check-input":
        if not args:
            print("Usage: guardrails.py check-input <text>")
            sys.exit(1)
        print(json.dumps(check_input(args[0]), indent=2))
    elif cmd == "check-output":
        if not args:
            print("Usage: guardrails.py check-output <text>")
            sys.exit(1)
        print(json.dumps(check_output(args[0]), indent=2))
    elif cmd == "add-input":
        if not args:
            print("Usage: guardrails.py add-input <pattern>")
            sys.exit(1)
        print(json.dumps(add_input_pattern(args[0]), indent=2))
    elif cmd == "add-output":
        if not args:
            print("Usage: guardrails.py add-output <pattern>")
            sys.exit(1)
        print(json.dumps(add_output_pattern(args[0]), indent=2))
    elif cmd == "add-exfil":
        if not args:
            print("Usage: guardrails.py add-exfil <pattern>")
            sys.exit(1)
        print(json.dumps(add_exfil_pattern(args[0]), indent=2))
    elif cmd == "enable":
        print(json.dumps(enable_guardrails(), indent=2))
    elif cmd == "disable":
        print(json.dumps(disable_guardrails(), indent=2))
    elif cmd == "get":
        print(json.dumps(get_guardrails(), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
