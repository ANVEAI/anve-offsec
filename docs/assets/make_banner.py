#!/usr/bin/env python3
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# Assets directory
assets_dir = Path("/Users/adarshkant/Documents/kali-ai/docs/assets")
assets_dir.mkdir(parents=True, exist_ok=True)
banner_path = assets_dir / "banner.png"

# Canvas dimensions
WIDTH, HEIGHT = 1200, 400

# Color Palette (Dark Mode Cyber Aesthetics)
BG_COLOR = (13, 17, 23)        # #0d1117
CARD_BG = (22, 27, 34)        # #161b22
BORDER_COLOR = (48, 54, 61)     # #30363d
TEXT_WHITE = (240, 246, 252)   # #f0f4fc
TEXT_MUTED = (139, 148, 158)   # #8b949e
ACCENT_BLUE = (88, 166, 255)   # #58a6ff
ACCENT_PURPLE = (188, 140, 255)# #bc8cff
ACCENT_GREEN = (46, 160, 67)   # #2ea643
ACCENT_ORANGE = (255, 153, 51) # #ff9933
ACCENT_RED = (248, 81, 73)     # #f85149

# Load System Fonts
try:
    font_hero = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 52)
    font_sub = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 20)
    font_badge = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 13)
    font_code = ImageFont.truetype("/System/Library/Fonts/Monaco.dfont", 14)
except Exception:
    font_hero = ImageFont.load_default()
    font_sub = ImageFont.load_default()
    font_badge = ImageFont.load_default()
    font_code = ImageFont.load_default()

# Create Base Image
img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
draw = ImageDraw.Draw(img)

# Draw Cyber Grid & Border Highlights
for x in range(0, WIDTH, 40):
    draw.line([(x, 0), (x, HEIGHT)], fill=(22, 27, 34), width=1)
for y in range(0, HEIGHT, 40):
    draw.line([(0, y), (WIDTH, y)], fill=(22, 27, 34), width=1)

# Outer Frame Border
draw.rectangle([10, 10, WIDTH - 10, HEIGHT - 10], outline=BORDER_COLOR, width=2)
draw.rectangle([15, 15, WIDTH - 15, HEIGHT - 15], outline=(33, 38, 45), width=1)

# Top Corner Accent Bar
draw.rectangle([15, 15, 300, 19], fill=ACCENT_BLUE)
draw.rectangle([300, 15, 450, 19], fill=ACCENT_PURPLE)
draw.rectangle([450, 15, 600, 19], fill=ACCENT_ORANGE)

# Main Title Logo Box
draw.text((60, 60), "🛡️ anve-offsec", fill=TEXT_WHITE, font=font_hero)
draw.text((60, 125), "Autonomous AI Security Engineer & Bug Bounty Platform", fill=ACCENT_BLUE, font=font_sub)

# Subtitle / Tagline
draw.text((60, 160), "Stateful Kali Linux Execution • Hermes AI Brain • OpenClaw Chromium • Qdrant Vector RAG", fill=TEXT_MUTED, font=font_sub)

# Feature Badges Bar
badges = [
    ("🛡️ Kali Linux Core", ACCENT_BLUE),
    ("🧠 Hermes AI Brain", ACCENT_PURPLE),
    ("🌐 OpenClaw Chromium", ACCENT_ORANGE),
    ("⚡ OWASP ZAP Daemon", ACCENT_YELLOW := (210, 153, 34)),
    ("🧠 Qdrant Vector RAG", ACCENT_RED),
    ("🇮🇳 Proudly Made in India", ACCENT_ORANGE),
]

x_b = 60
y_b = 215
for b_text, b_color in badges:
    bw = draw.textlength(b_text, font=font_badge) + 20
    draw.rectangle([x_b, y_b, x_b + bw, y_b + 30], fill=CARD_BG, outline=b_color, width=1)
    draw.text((x_b + 10, y_b + 7), b_text, fill=b_color, font=font_badge)
    x_b += bw + 12
    if x_b > WIDTH - 200:
        x_b = 60
        y_b += 40

# Bottom Terminal Prompt Box
draw.rectangle([60, 290, WIDTH - 60, 350], fill=CARD_BG, outline=BORDER_COLOR, width=1)
draw.text((80, 308), "pentest@anve-offsec:~$", fill=ACCENT_BLUE, font=font_code)
draw.text((275, 308), "./scripts/hermes.sh --task 'Full Assessment http://dvwa:8080'", fill=TEXT_WHITE, font=font_code)
draw.text((WIDTH - 240, 308), "[STATUS: 100% READY]", fill=ACCENT_GREEN, font=font_code)

# Save image
img.save(banner_path, "PNG")
print(f"Successfully generated banner PNG at: {banner_path}")
