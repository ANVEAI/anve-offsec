#!/usr/bin/env python3
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# Ensure directory exists
assets_dir = Path("/Users/adarshkant/Documents/kali-ai/docs/assets")
assets_dir.mkdir(parents=True, exist_ok=True)
gif_path = assets_dir / "demo.gif"

# Canvas dimensions
WIDTH, HEIGHT = 900, 450
BG_COLOR = (13, 17, 23)        # GitHub Dark BG #0d1117
TERM_BG = (22, 27, 34)        # Dark Terminal Container #161b22
HEADER_BG = (33, 38, 45)      # Top Header Bar #21262d
TEXT_COLOR = (201, 209, 217)    # Off-white text #c9d1d9
GREEN_COLOR = (46, 160, 67)     # Green success #2ea643
BLUE_COLOR = (88, 166, 255)     # Accent Blue #58a6ff
ORANGE_COLOR = (255, 153, 51)   # India Flag Orange #ff9933
RED_COLOR = (248, 81, 73)       # Red vulnerability #f85149
PURPLE_COLOR = (188, 140, 255)  # Purple Hermes #bc8cff

# Load standard font
try:
    font_large = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 18)
    font_medium = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 14)
    font_mono = ImageFont.truetype("/System/Library/Fonts/Monaco.dfont", 13)
except Exception:
    font_large = ImageFont.load_default()
    font_medium = ImageFont.load_default()
    font_mono = ImageFont.load_default()

frames_text = [
    [
        "┌──(pentest㉿anve-offsec)-[/work]",
        "└─$ ./scripts/hermes.sh --task 'Full Assessment http://dvwa:8080'",
        "",
        "[🧠 Hermes Reasoning Engine] Initializing target assessment...",
        "[+] Status: Connecting to Kali Linux Core Container...",
        "[+] Target Whitelist Check: http://dvwa:8080 [AUTHORIZED: LAB MODE]",
    ],
    [
        "┌──(pentest㉿anve-offsec)-[/work]",
        "└─$ ./scripts/hermes.sh --task 'Full Assessment http://dvwa:8080'",
        "",
        "[🧠 Hermes Reasoning Engine] Initializing target assessment...",
        "[+] Phase 1: Deep Reconnaissance & Web Fingerprinting",
        "[+] Invoking OpenClaw Chromium Gateway for auth flow...",
        "[+] Discovered endpoints: /vulnerabilities/sqli/ | /vulnerabilities/exec/",
    ],
    [
        "┌──(pentest㉿anve-offsec)-[/work]",
        "└─$ ./scripts/hermes.sh --task 'Full Assessment http://dvwa:8080'",
        "",
        "[🧠 Hermes Reasoning Engine] Running targeted OWASP scanning...",
        "[+] Phase 2: Vulnerability Verification & Exploit Payload Synthesis",
        "[⚡ VULN DETECTED] Command Injection on /vulnerabilities/exec/ (ip=127.0.0.1; id)",
        "[⚡ VULN DETECTED] SQL Injection on /vulnerabilities/sqli/ (id=1' OR '1'='1)",
    ],
    [
        "┌──(pentest㉿anve-offsec)-[/work]",
        "└─$ ./scripts/hermes.sh --task 'Full Assessment http://dvwa:8080'",
        "",
        "[🧠 Hermes Reasoning Engine] Executing proof-of-concept verification...",
        "[+] Output: uid=33(www-data) gid=33(www-data)",
        "[+] Dumping database tables to /work/loot/dvwa_sqli_dump.json",
        "[+] Synthesizing Executive Markdown Report: /work/loot/dvwa_report.md",
    ],
    [
        "┌──(pentest㉿anve-offsec)-[/work]",
        "└─$ ./scripts/hermes.sh --task 'Full Assessment http://dvwa:8080'",
        "",
        "[🧠 Self-Evolution RAG Loop] Processing execution outcome...",
        "[+] Ingesting successful payload into Qdrant Vector Memory RAG...",
        "[+] Strategy Confidence Score: 0.92 (Added to web-app:sql-injection)",
        "[+] Updated agent prompts with WAF tamper bypass rules",
    ],
    [
        "┌──(pentest㉿anve-offsec)-[/work]",
        "└─$ ./scripts/hermes.sh --task 'Full Assessment http://dvwa:8080'",
        "",
        "===================================================================",
        "  anve-offsec ENGAGEMENT COMPLETE | 100% VULNERABILITY SCORE",
        "  Time Elapsed: 7m 42s | Status: Success | Proudly Made in India 🇮🇳",
        "===================================================================",
    ]
]

images = []

for idx, lines in enumerate(frames_text):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Draw Terminal Outer Frame
    draw.rectangle([20, 20, WIDTH - 20, HEIGHT - 20], fill=TERM_BG, outline=HEADER_BG, width=2)
    
    # Top Header Bar
    draw.rectangle([20, 20, WIDTH - 20, 55], fill=HEADER_BG)
    
    # Window Control Dots
    draw.ellipse([35, 33, 47, 45], fill=RED_COLOR)
    draw.ellipse([55, 33, 67, 45], fill=ORANGE_COLOR)
    draw.ellipse([75, 33, 87, 45], fill=GREEN_COLOR)
    
    # Window Title Text
    draw.text((100, 31), "🛡️ anve-offsec — Hermes AI Execution Terminal (Kali Core)", fill=TEXT_COLOR, font=font_medium)
    draw.text((WIDTH - 180, 31), "🇮🇳 Made in India", fill=ORANGE_COLOR, font=font_medium)

    # Draw Terminal Lines
    y_pos = 75
    for line in lines:
        if line.startswith("┌──") or line.startswith("└─$"):
            color = BLUE_COLOR
        elif "[🧠" in line:
            color = PURPLE_COLOR
        elif "[⚡ VULN" in line:
            color = RED_COLOR
        elif "[+]" in line or "100%" in line:
            color = GREEN_COLOR
        elif "=====================" in line:
            color = ORANGE_COLOR
        else:
            color = TEXT_COLOR
        
        draw.text((40, y_pos), line, fill=color, font=font_mono)
        y_pos += 26

    # Bottom Dashboard Status Bar
    draw.rectangle([20, HEIGHT - 45, WIDTH - 20, HEIGHT - 20], fill=HEADER_BG)
    progress_w = int(((idx + 1) / len(frames_text)) * (WIDTH - 250))
    draw.rectangle([35, HEIGHT - 35, 35 + progress_w, HEIGHT - 30], fill=GREEN_COLOR)
    draw.text((WIDTH - 200, HEIGHT - 38), f"Phase {idx+1}/6 Progress: {int((idx+1)/6*100)}%", fill=TEXT_COLOR, font=font_medium)

    images.append(img)

# Save as animated GIF (duration=1200ms per frame)
images[0].save(
    gif_path,
    save_all=True,
    append_images=images[1:],
    duration=1200,
    loop=0
)

print(f"Successfully generated animated demo GIF at: {gif_path}")
