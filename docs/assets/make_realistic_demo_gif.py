#!/usr/bin/env python3
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# Assets directory
assets_dir = Path("/Users/adarshkant/Documents/kali-ai/docs/assets")
assets_dir.mkdir(parents=True, exist_ok=True)
gif_path = assets_dir / "demo.gif"

# Canvas dimensions
WIDTH, HEIGHT = 1200, 600

# Color Palette (GitHub Dark Mode & Cyber Aesthetics)
BG_MAIN = (13, 17, 23)          # #0d1117
PANEL_BG = (22, 27, 34)        # #161b22
HEADER_BG = (33, 38, 45)       # #21262d
BORDER_COLOR = (48, 54, 61)     # #30363d
TEXT_MAIN = (201, 209, 217)     # #c9d1d9
TEXT_MUTED = (139, 148, 158)   # #8b949e
ACCENT_MUTED = (139, 148, 158) # #8b949e
ACCENT_BLUE = (88, 166, 255)   # #58a6ff
ACCENT_GREEN = (46, 160, 67)   # #2ea643
ACCENT_PURPLE = (188, 140, 255)# #bc8cff
ACCENT_RED = (248, 81, 73)     # #f85149
ACCENT_ORANGE = (255, 153, 51) # #ff9933
ACCENT_YELLOW = (210, 153, 34) # #d29922

# Load System Fonts
try:
    font_title = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 15)
    font_bold = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 13)
    font_sm = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 11)
    font_mono = ImageFont.truetype("/System/Library/Fonts/Monaco.dfont", 12)
    font_mono_bold = ImageFont.truetype("/System/Library/Fonts/Monaco.dfont", 12)
except Exception:
    font_title = ImageFont.load_default()
    font_bold = ImageFont.load_default()
    font_sm = ImageFont.load_default()
    font_mono = ImageFont.load_default()
    font_mono_bold = ImageFont.load_default()

# 8 Storyboard Frame Scenarios
frames_data = [
    {
        "phase": 1,
        "phase_name": "Reconnaissance & Scope",
        "terminal_lines": [
            ("pentest@anve-offsec:~/work# ", ACCENT_BLUE, "./scripts/hermes.sh --task 'Full Assessment http://dvwa:8080'"),
            ("[SYSTEM] Target Scope Verification: http://dvwa:8080", ACCENT_MUTED),
            ("[AUTHORIZED] Target type: lab_mode (Scope Whitelist Matched)", ACCENT_GREEN),
            ("[HERMES_THOUGHT] Target stack fingerprinting via curl & nmap...", ACCENT_PURPLE),
            ("[SHELL_EXEC] whatweb http://dvwa:8080/login.php", ACCENT_BLUE),
            ("http://dvwa:8080 [200 OK] Apache[2.4.25], PHP[7.0.33], Cookies[PHPSESSID]", TEXT_MAIN),
            ("[+] Invoking OpenClaw Chromium Gateway for authentication...", ACCENT_GREEN),
        ],
        "sse_logs": [
            ("INFO", "Target scope validation complete: dvwa (lab_mode)", ACCENT_BLUE),
            ("RECON", "Fingerprinted Apache/2.4.25 PHP/7.0.33 backend", ACCENT_MUTED),
            ("OPENCLAW", "Chromium sidecar initialized on port 18789", ACCENT_PURPLE),
        ],
        "vuln_badge": None,
        "stepper": [1, 0, 0, 0, 0]
    },
    {
        "phase": 2,
        "phase_name": "OWASP ZAP Spidering",
        "terminal_lines": [
            ("[HERMES_THOUGHT] Triggering OWASP ZAP API daemon crawler...", ACCENT_PURPLE),
            ("[SHELL_EXEC] python3 /tools/zap_client.py --target http://dvwa:8080 --spider", ACCENT_BLUE),
            ("[ZAP_API] Active spidering endpoints across target...", ACCENT_MUTED),
            ("  Discovered: /vulnerabilities/exec/ (Ping Command Exec)", TEXT_MAIN),
            ("  Discovered: /vulnerabilities/sqli/ (SQL Injection)", TEXT_MAIN),
            ("  Discovered: /vulnerabilities/fi/?page=include.php (LFI)", TEXT_MAIN),
            ("[+] Discovered 14 endpoints across 4 web vulnerability modules.", ACCENT_GREEN),
        ],
        "sse_logs": [
            ("ZAP", "Spidering completed: 14 endpoints mapped", ACCENT_BLUE),
            ("DISCOVERY", "Endpoint found: /vulnerabilities/exec/", ACCENT_ORANGE),
            ("DISCOVERY", "Endpoint found: /vulnerabilities/sqli/", ACCENT_ORANGE),
        ],
        "vuln_badge": None,
        "stepper": [1, 1, 0, 0, 0]
    },
    {
        "phase": 3,
        "phase_name": "Targeted Vulnerability Testing",
        "terminal_lines": [
            ("[HERMES_THOUGHT] Testing Command Injection on /vulnerabilities/exec/...", ACCENT_PURPLE),
            ("[SHELL_EXEC] curl -s -d 'ip=127.0.0.1%3B+id&Submit=Submit' http://dvwa:8080/vulnerabilities/exec/", ACCENT_BLUE),
            ("[CRITICAL VULN VERIFIED] Output: uid=33(www-data) gid=33(www-data)", ACCENT_RED),
            ("[HERMES_THOUGHT] Testing SQL Injection on /vulnerabilities/sqli/...", ACCENT_PURPLE),
            ("[SHELL_EXEC] curl -s 'http://dvwa:8080/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271'", ACCENT_BLUE),
            ("[HIGH VULN VERIFIED] Returned full user accounts schema dump", ACCENT_RED),
            ("[+] 2 High/Critical vulnerabilities verified with dynamic payloads.", ACCENT_GREEN),
        ],
        "sse_logs": [
            ("CRITICAL", "Remote Code Execution verified on /vulnerabilities/exec/", ACCENT_RED),
            ("HIGH", "SQL Injection schema dump verified on /vulnerabilities/sqli/", ACCENT_RED),
            ("PROOF", "Extracted system context: uid=33(www-data)", ACCENT_GREEN),
        ],
        "vuln_badge": ("CRITICAL RCE DETECTED", ACCENT_RED),
        "stepper": [1, 1, 1, 0, 0]
    },
    {
        "phase": 4,
        "phase_name": "Self-Evolution RAG Loop",
        "terminal_lines": [
            ("[HERMES_THOUGHT] Ingesting execution outcomes into evolution engine...", ACCENT_PURPLE),
            ("[SHELL_EXEC] python3 /tools/evolution_engine.py --Ingest --run-id run-8912", ACCENT_BLUE),
            ("[EVOLUTION] Categorized scenario: web-app:command-injection", ACCENT_MUTED),
            ("[EVOLUTION] Categorized scenario: web-app:sql-injection", ACCENT_MUTED),
            ("[QDRANT_RAG] Stored strategy vector embedding in Qdrant (Port 6333)", ACCENT_GREEN),
            ("[+] Strategy Confidence Score: 0.92 (Updated static agent prompts)", ACCENT_GREEN),
            ("[+] Cross-agent payload sharing active for future targets.", ACCENT_GREEN),
        ],
        "sse_logs": [
            ("EVOLUTION", "Ingested 2 verified exploits into Qdrant RAG Memory", ACCENT_PURPLE),
            ("QDRANT", "Vector embedding indexed (Confidence: 0.92)", ACCENT_GREEN),
            ("PROMPT", "Agent prompt updated with tamper bypass rules", ACCENT_BLUE),
        ],
        "vuln_badge": ("RAG MEMORY UPDATED (CONF: 0.92)", ACCENT_PURPLE),
        "stepper": [1, 1, 1, 1, 0]
    },
    {
        "phase": 5,
        "phase_name": "Mid-Run Operator Steering",
        "terminal_lines": [
            ("[OPERATOR_INSTRUCTION] 'Focus on database dump and format executive report'", ACCENT_ORANGE),
            ("[HERMES_THOUGHT] Prioritizing executive markdown report generation...", ACCENT_PURPLE),
            ("[SHELL_EXEC] python3 /tools/reporting_engine.py --run-id run-8912", ACCENT_BLUE),
            ("[+] Formatting vulnerability reproduction steps & curl PoCs...", ACCENT_MUTED),
            ("[+] Saving Markdown Report: /work/loot/dvwa_report.md", ACCENT_GREEN),
            ("[+] Saving JSON Evidence Bundle: /work/loot/dvwa_evidence.json", ACCENT_GREEN),
            ("[+] Report Generation Complete (100% Automated).", ACCENT_GREEN),
        ],
        "sse_logs": [
            ("OPERATOR", "Instruction injected: Extract DB & format report", ACCENT_ORANGE),
            ("REPORT", "Executive Markdown report generated in /work/loot/", ACCENT_GREEN),
            ("EVIDENCE", "JSON PoC evidence bundle created", ACCENT_BLUE),
        ],
        "vuln_badge": ("OPERATOR STEERING ACTIVE", ACCENT_ORANGE),
        "stepper": [1, 1, 1, 1, 1]
    },
    {
        "phase": 6,
        "phase_name": "Engagement Complete & Platform Summary",
        "terminal_lines": [
            ("==================================================================", ACCENT_ORANGE),
            ("  anve-offsec ENGAGEMENT COMPLETE | 100% VULNERABILITY SCORE", ACCENT_GREEN),
            ("  Target: http://dvwa:8080 | Status: Success | Time: 7m 42s", TEXT_MAIN),
            ("  Vulnerabilities: 1 Critical RCE, 1 High SQLi, 1 Medium LFI", ACCENT_RED),
            ("  Self-Evolution: Strategy saved to Qdrant Vector Memory", ACCENT_PURPLE),
            ("  Proudly Made in India 🇮🇳 | Star us on GitHub!", ACCENT_ORANGE),
            ("==================================================================", ACCENT_ORANGE),
        ],
        "sse_logs": [
            ("COMPLETE", "Engagement finished cleanly in 7m 42s", ACCENT_GREEN),
            ("SUMMARY", "1 Critical, 1 High, 1 Medium vulnerability verified", ACCENT_RED),
            ("INDIA", "Proudly Made in India 🇮🇳 | anve-offsec v1.0", ACCENT_ORANGE),
        ],
        "vuln_badge": ("100% ASSESSMENT COMPLETE 🇮🇳", ACCENT_GREEN),
        "stepper": [1, 1, 1, 1, 1]
    }
]

images = []

for frame in frames_data:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_MAIN)
    draw = ImageDraw.Draw(img)

    # -------------------------------------------------------------------------
    # LEFT PANEL: Kali Terminal (Width: 570, Height: 560)
    # -------------------------------------------------------------------------
    t_left, t_top, t_right, t_bottom = 20, 20, 585, 580
    draw.rectangle([t_left, t_top, t_right, t_bottom], fill=PANEL_BG, outline=BORDER_COLOR, width=1)
    
    # Terminal Header Bar
    draw.rectangle([t_left, t_top, t_right, t_top + 35], fill=HEADER_BG)
    draw.ellipse([t_left + 12, t_top + 12, t_left + 22, t_top + 22], fill=ACCENT_RED)
    draw.ellipse([t_left + 28, t_top + 12, t_left + 38, t_top + 22], fill=ACCENT_ORANGE)
    draw.ellipse([t_left + 44, t_top + 12, t_left + 54, t_top + 22], fill=ACCENT_GREEN)
    draw.text((t_left + 65, t_top + 9), "🛡️ pentest@anve-offsec: ~/work (Kali Core Shell)", fill=TEXT_MAIN, font=font_bold)

    # Terminal Content Lines
    y_line = t_top + 45
    for line_tuple in frame["terminal_lines"]:
        if len(line_tuple) == 3:
            prefix, color1, text = line_tuple
            draw.text((t_left + 15, y_line), prefix, fill=color1, font=font_mono)
            prefix_w = draw.textlength(prefix, font=font_mono)
            draw.text((t_left + 15 + prefix_w, y_line), text, fill=TEXT_MAIN, font=font_mono)
        else:
            text, color = line_tuple
            draw.text((t_left + 15, y_line), text, fill=color, font=font_mono)
        y_line += 24

    # -------------------------------------------------------------------------
    # RIGHT PANEL: FastAPI Control Plane Dashboard (Width: 570, Height: 560)
    # -------------------------------------------------------------------------
    d_left, d_top, d_right, d_bottom = 615, 20, 1180, 580
    draw.rectangle([d_left, d_top, d_right, d_bottom], fill=PANEL_BG, outline=BORDER_COLOR, width=1)
    
    # Dashboard Header / URL Bar
    draw.rectangle([d_left, d_top, d_right, d_top + 35], fill=HEADER_BG)
    draw.text((d_left + 15, d_top + 9), "🔒 http://127.0.0.1:8000 (anve-offsec Control Plane)", fill=ACCENT_BLUE, font=font_bold)
    draw.text((d_right - 130, d_top + 9), "🇮🇳 Made in India", fill=ACCENT_ORANGE, font=font_bold)

    # Status Indicators Bar (ZAP, Qdrant, Target, VPN)
    s_top = d_top + 45
    badges = [
        ("ZAP: ONLINE", ACCENT_GREEN),
        ("QDRANT: READY", ACCENT_GREEN),
        ("DVWA: LAB", ACCENT_BLUE),
        ("VPN: ACTIVE", ACCENT_PURPLE),
    ]
    x_badge = d_left + 15
    for b_text, b_color in badges:
        bw = draw.textlength(b_text, font=font_sm) + 16
        draw.rectangle([x_badge, s_top, x_badge + bw, s_top + 22], fill=PANEL_BG, outline=b_color, width=1)
        draw.text((x_badge + 8, s_top + 4), b_text, fill=b_color, font=font_sm)
        x_badge += bw + 10

    # Methodology Stepper Bar
    m_top = s_top + 32
    draw.text((d_left + 15, m_top), "METHODOLOGY PROGRESS:", fill=TEXT_MUTED, font=font_sm)
    m_steps = ["1. Recon", "2. ZAP Scan", "3. Exploit", "4. RAG Save", "5. Report"]
    x_step = d_left + 15
    y_step_box = m_top + 18
    for s_idx, s_name in enumerate(m_steps):
        is_active = frame["stepper"][s_idx] == 1
        s_bg = ACCENT_GREEN if is_active else HEADER_BG
        s_fg = (255, 255, 255) if is_active else TEXT_MUTED
        sw = draw.textlength(s_name, font=font_sm) + 14
        draw.rectangle([x_step, y_step_box, x_step + sw, y_step_box + 22], fill=s_bg)
        draw.text((x_step + 7, y_step_box + 4), s_name, fill=s_fg, font=font_sm)
        x_step += sw + 6

    # Optional Highlight Vulnerability Banner
    v_top = y_step_box + 30
    if frame["vuln_badge"]:
        v_text, v_color = frame["vuln_badge"]
        draw.rectangle([d_left + 15, v_top, d_right - 15, v_top + 28], fill=HEADER_BG, outline=v_color, width=1)
        draw.text((d_left + 25, v_top + 6), f"⚡ STATUS ALERT: {v_text}", fill=v_color, font=font_bold)
        v_top += 38

    # Live SSE Stream Log Cards
    draw.text((d_left + 15, v_top), "LIVE STREAMING EVENT LOGS (SSE):", fill=TEXT_MUTED, font=font_sm)
    y_card = v_top + 18
    for log_tag, log_msg, log_color in frame["sse_logs"]:
        draw.rectangle([d_left + 15, y_card, d_right - 15, y_card + 36], fill=HEADER_BG, outline=BORDER_COLOR, width=1)
        # Tag Badge
        tw = draw.textlength(log_tag, font=font_sm) + 12
        draw.rectangle([d_left + 22, y_card + 7, d_left + 22 + tw, y_card + 27], fill=log_color)
        draw.text((d_left + 28, y_card + 10), log_tag, fill=(0, 0, 0), font=font_bold)
        # Log Text
        draw.text((d_left + 30 + tw, y_card + 10), log_msg[:50], fill=TEXT_MAIN, font=font_sm)
        y_card += 42

    # Bottom Control Bar Buttons
    c_top = d_bottom - 45
    draw.rectangle([d_left + 15, c_top, d_left + 120, c_top + 28], fill=ACCENT_BLUE)
    draw.text((d_left + 32, c_top + 7), "PAUSE RUN", fill=(0, 0, 0), font=font_bold)

    draw.rectangle([d_left + 130, c_top, d_left + 280, c_top + 28], fill=ACCENT_ORANGE)
    draw.text((d_left + 142, c_top + 7), "INJECT INSTRUCTION", fill=(0, 0, 0), font=font_bold)

    draw.rectangle([d_left + 290, c_top, d_right - 15, c_top + 28], fill=ACCENT_GREEN)
    draw.text((d_left + 310, c_top + 7), "EXPORT REPORT (MD/JSON)", fill=(255, 255, 255), font=font_bold)

    images.append(img)

# Save high-resolution animated GIF
images[0].save(
    gif_path,
    save_all=True,
    append_images=images[1:],
    duration=1500,
    loop=0
)

print(f"Successfully generated hyper-realistic dual-panel GIF at: {gif_path}")
