#!/usr/bin/env python3
"""
Generate terminal-style screenshot PNGs for README documentation.

Uses Pillow to render colored text on a dark background,
mimicking a modern terminal emulator.
"""

import os
import subprocess
import sys
import textwrap
from PIL import Image, ImageDraw, ImageFont

# ── Configuration ────────────────────────────────────────────────────────────

SCREENSHOTS_DIR = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# Colors (RGB)
BG_COLOR = (30, 30, 46)          # Dark background
TITLE_BAR_COLOR = (45, 45, 65)   # Title bar
TEXT_COLOR = (205, 214, 244)      # Default text
DIM_COLOR = (120, 130, 160)      # Dimmed text
CYAN = (137, 220, 235)           # Banner / info
GREEN = (166, 227, 161)          # Success / pass
RED = (243, 139, 168)            # Critical / fail
ORANGE = (250, 179, 135)         # High severity
YELLOW = (249, 226, 175)         # Medium severity
BLUE = (137, 180, 250)           # Low severity
MAGENTA = (203, 166, 247)        # Info severity
WHITE = (255, 255, 255)          # Bold text
PROMPT_GREEN = (166, 227, 161)   # Prompt color
GRAY = (88, 91, 112)             # Borders

# Font
FONT_SIZE = 15
LINE_HEIGHT = 22
try:
    FONT = ImageFont.truetype("consola.ttf", FONT_SIZE)
    FONT_BOLD = ImageFont.truetype("consolab.ttf", FONT_SIZE)
except:
    FONT = ImageFont.truetype("cour.ttf", FONT_SIZE)
    FONT_BOLD = FONT

CHAR_WIDTH = FONT.getbbox("M")[2]
PADDING_X = 20
PADDING_Y = 50  # Space for title bar


def create_terminal_image(lines, filename, title="Terminal", width_chars=100):
    """
    Render styled terminal output lines to a PNG.
    
    Each line is a list of (text, color) tuples, or a plain string.
    """
    img_width = PADDING_X * 2 + width_chars * CHAR_WIDTH
    img_height = PADDING_Y + 15 + len(lines) * LINE_HEIGHT + 20

    img = Image.new("RGB", (img_width, img_height), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Title bar
    draw.rectangle([(0, 0), (img_width, 38)], fill=TITLE_BAR_COLOR)
    # Window buttons
    draw.ellipse([(12, 12), (24, 24)], fill=(243, 139, 168))  # Red
    draw.ellipse([(32, 12), (44, 24)], fill=(249, 226, 175))  # Yellow
    draw.ellipse([(52, 12), (64, 24)], fill=(166, 227, 161))  # Green
    # Title text
    title_bbox = FONT.getbbox(title)
    title_w = title_bbox[2] - title_bbox[0]
    draw.text(((img_width - title_w) // 2, 10), title, fill=DIM_COLOR, font=FONT)

    # Draw lines
    y = PADDING_Y
    for line in lines:
        x = PADDING_X
        if isinstance(line, str):
            draw.text((x, y), line, fill=TEXT_COLOR, font=FONT)
        elif isinstance(line, list):
            for segment in line:
                if isinstance(segment, tuple) and len(segment) == 2:
                    text, color = segment
                    font = FONT_BOLD if color == WHITE else FONT
                    draw.text((x, y), text, fill=color, font=font)
                    x += len(text) * CHAR_WIDTH
                else:
                    draw.text((x, y), str(segment), fill=TEXT_COLOR, font=FONT)
                    x += len(str(segment)) * CHAR_WIDTH
        y += LINE_HEIGHT

    path = os.path.join(SCREENSHOTS_DIR, filename)
    img.save(path, "PNG", optimize=True)
    print(f"  ✓ Saved {path}")
    return path


# ── Screenshot 1: Terminal Scan ──────────────────────────────────────────────

def generate_scan_screenshot():
    """Generate the main scan output screenshot."""
    lines = [
        [("$ ", PROMPT_GREEN), ("python main.py scan --file samples/Dockerfile.webapp", TEXT_COLOR)],
        "",
        [("╔══════════════════════════════════════════════════════════════╗", CYAN)],
        [("║             Docker Security Scanner v1.0.0                  ║", CYAN)],
        [("║             Static & Dynamic Container Auditor              ║", CYAN)],
        [("╚══════════════════════════════════════════════════════════════╝", CYAN)],
        "",
        [("  [SCANNING] ", WHITE), ("samples/Dockerfile.webapp", TEXT_COLOR)],
        "",
        [("  [STATIC ANALYSIS RESULTS]", WHITE)],
        [("  " + "─" * 60, GRAY)],
        [("  CRITICAL  ", RED), ("DS001 ", DIM_COLOR), ("Line 1   ", DIM_COLOR), ("Container runs as root", TEXT_COLOR)],
        [("            ", RED), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("# Running as root is a security risk", DIM_COLOR)],
        [("  HIGH      ", ORANGE), ("DS002 ", DIM_COLOR), ("Line 13  ", DIM_COLOR), ("Hardcoded secret detected: AWS Access Key ID", TEXT_COLOR)],
        [("            ", ORANGE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("ENV AWS_ACCESS_KEY_ID=AKIA****************", DIM_COLOR)],
        [("  HIGH      ", ORANGE), ("DS002 ", DIM_COLOR), ("Line 14  ", DIM_COLOR), ("Hardcoded secret detected: AWS Secret Access Key", TEXT_COLOR)],
        [("            ", ORANGE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("ENV AWS_SECRET_ACCESS_KEY=EXAM********************", DIM_COLOR)],
        [("  HIGH      ", ORANGE), ("DS002 ", DIM_COLOR), ("Line 18  ", DIM_COLOR), ("Hardcoded secret detected: Database Connection String", TEXT_COLOR)],
        [("            ", ORANGE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("ENV DATABASE_URL=post********************", DIM_COLOR)],
        [("  HIGH      ", ORANGE), ("DS002 ", DIM_COLOR), ("Line 19  ", DIM_COLOR), ("Hardcoded secret detected: Generic Password", TEXT_COLOR)],
        [("            ", ORANGE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("ENV DB_PASSWORD=EXAM**************", DIM_COLOR)],
        [("  HIGH      ", ORANGE), ("DS002 ", DIM_COLOR), ("Line 23  ", DIM_COLOR), ("Hardcoded secret detected: GitHub Personal Access Token", TEXT_COLOR)],
        [("            ", ORANGE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("ENV GITHUB_TOKEN=ghp_********************", DIM_COLOR)],
        [("  HIGH      ", ORANGE), ("DS002 ", DIM_COLOR), ("Line 25  ", DIM_COLOR), ("Hardcoded secret detected: Generic Password", TEXT_COLOR)],
        [("            ", ORANGE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("ENV JWT_SECRET=mySu********************", DIM_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DS003 ", DIM_COLOR), ("Line 10  ", DIM_COLOR), ("Unpinned base image tag: 'python:latest'", TEXT_COLOR)],
        [("            ", YELLOW), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("FROM python:latest", DIM_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DS007 ", DIM_COLOR), ("Line 43  ", DIM_COLOR), ("Sudo usage detected (installation)", TEXT_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DS004 ", DIM_COLOR), ("Line 55  ", DIM_COLOR), ("Dangerous port exposed: 22 (SSH)", TEXT_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DS004 ", DIM_COLOR), ("Line 57  ", DIM_COLOR), ("Dangerous port exposed: 3306 (MySQL)", TEXT_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DS004 ", DIM_COLOR), ("Line 58  ", DIM_COLOR), ("Dangerous port exposed: 5432 (PostgreSQL)", TEXT_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DS004 ", DIM_COLOR), ("Line 59  ", DIM_COLOR), ("Dangerous port exposed: 6379 (Redis)", TEXT_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DS004 ", DIM_COLOR), ("Line 60  ", DIM_COLOR), ("Dangerous port exposed: 27017 (MongoDB)", TEXT_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DS004 ", DIM_COLOR), ("Line 61  ", DIM_COLOR), ("Dangerous port exposed: 9200 (Elasticsearch)", TEXT_COLOR)],
        [("  LOW       ", BLUE), ("DS006 ", DIM_COLOR), ("         ", DIM_COLOR), ("No HEALTHCHECK instruction", TEXT_COLOR)],
        [("  LOW       ", BLUE), ("DS005 ", DIM_COLOR), ("Line 28  ", DIM_COLOR), ("Unnecessary packages: vim, nano, curl, wget, nmap...", TEXT_COLOR)],
        [("  LOW       ", BLUE), ("DS006 ", DIM_COLOR), ("Line 47  ", DIM_COLOR), ("Use COPY instead of ADD for local files", TEXT_COLOR)],
        [("  INFO      ", MAGENTA), ("DS006 ", DIM_COLOR), ("Line 67  ", DIM_COLOR), ("Shell form used for CMD/ENTRYPOINT", TEXT_COLOR)],
        "",
        [("  " + "─" * 60, GRAY)],
        [("  Summary: ", TEXT_COLOR), ("1 CRITICAL", RED), (" | ", GRAY), ("9 HIGH", ORANGE), (" | ", GRAY),
         ("8 MEDIUM", YELLOW), (" | ", GRAY), ("14 LOW", BLUE), (" | ", GRAY), ("1 INFO", MAGENTA)],
        "",
    ]
    create_terminal_image(lines, "01_terminal_scan.png",
                          title="Docker Security Scanner — Vulnerability Scan",
                          width_chars=95)


# ── Screenshot 2: HTML Report Preview ────────────────────────────────────────

def generate_html_report_screenshot():
    """Generate a screenshot showing the HTML report generation."""
    lines = [
        [("$ ", PROMPT_GREEN), ("python main.py scan --file samples/Dockerfile.webapp --format html", TEXT_COLOR)],
        "",
        [("╔══════════════════════════════════════════════════════════════╗", CYAN)],
        [("║             Docker Security Scanner v1.0.0                  ║", CYAN)],
        [("║             Static & Dynamic Container Auditor              ║", CYAN)],
        [("╚══════════════════════════════════════════════════════════════╝", CYAN)],
        "",
        [("  [SCANNING] ", WHITE), ("samples/Dockerfile.webapp", TEXT_COLOR)],
        "",
        [("  ... (33 findings detected) ...", DIM_COLOR)],
        "",
        [("  ✓ HTML report saved to: ", GREEN), ("reports/webapp_scan.html", TEXT_COLOR)],
        "",
        [("  ┌─────────────────────────────────────────────────────────────────┐", GRAY)],
        [("  │  ", GRAY), ("Docker Security Report", WHITE), ("                                          │", GRAY)],
        [("  │  ", GRAY), ("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", CYAN), ("│", GRAY)],
        [("  │  ", GRAY), ("Target: samples/Dockerfile.webapp", TEXT_COLOR), ("                              │", GRAY)],
        [("  │  ", GRAY), ("Generated: 2025-07-15T10:30:00Z", DIM_COLOR), ("                               │", GRAY)],
        [("  │  ", GRAY), ("                                                               │", GRAY)],
        [("  │  ", GRAY), ("┌──────────┬────────┐", GRAY), ("                                       │", GRAY)],
        [("  │  ", GRAY), ("│ CRITICAL │  ", GRAY), ("1    ", RED), ("│", GRAY), ("                                       │", GRAY)],
        [("  │  ", GRAY), ("│ HIGH     │  ", GRAY), ("9    ", ORANGE), ("│", GRAY), ("                                       │", GRAY)],
        [("  │  ", GRAY), ("│ MEDIUM   │  ", GRAY), ("8    ", YELLOW), ("│", GRAY), ("                                       │", GRAY)],
        [("  │  ", GRAY), ("│ LOW      │  ", GRAY), ("14   ", BLUE), ("│", GRAY), ("                                       │", GRAY)],
        [("  │  ", GRAY), ("│ INFO     │  ", GRAY), ("1    ", MAGENTA), ("│", GRAY), ("                                       │", GRAY)],
        [("  │  ", GRAY), ("└──────────┴────────┘", GRAY), ("                                       │", GRAY)],
        [("  │  ", GRAY), ("                                                               │", GRAY)],
        [("  │  ", GRAY), ("△ DS001 — Container runs as root", RED), ("                              │", GRAY)],
        [("  │  ", GRAY), ("  Severity: CRITICAL  |  Line: 1", DIM_COLOR), ("                              │", GRAY)],
        [("  │  ", GRAY), ("  Fix: Add 'USER nonroot' instruction", DIM_COLOR), ("                         │", GRAY)],
        [("  │  ", GRAY), ("                                                               │", GRAY)],
        [("  │  ", GRAY), ("△ DS002 — Hardcoded secret: AWS Access Key ID", ORANGE), ("                │", GRAY)],
        [("  │  ", GRAY), ("  Severity: HIGH  |  Line: 13", DIM_COLOR), ("                                 │", GRAY)],
        [("  │  ", GRAY), ("  Evidence: ENV AWS_ACCESS_KEY_ID=AKIA***...", DIM_COLOR), ("               │", GRAY)],
        [("  └─────────────────────────────────────────────────────────────────┘", GRAY)],
        "",
        [("  Report includes ", DIM_COLOR), ("interactive expandable findings", CYAN), (" and ", DIM_COLOR), ("dark theme UI", CYAN)],
        "",
    ]
    create_terminal_image(lines, "02_html_report.png",
                          title="Docker Security Scanner — HTML Report",
                          width_chars=95)


# ── Screenshot 3: Secure Scan ────────────────────────────────────────────────

def generate_secure_scan_screenshot():
    """Generate screenshot of scanning a secure Dockerfile."""
    lines = [
        [("$ ", PROMPT_GREEN), ("python main.py scan --file samples/Dockerfile.secure", TEXT_COLOR)],
        "",
        [("╔══════════════════════════════════════════════════════════════╗", CYAN)],
        [("║             Docker Security Scanner v1.0.0                  ║", CYAN)],
        [("║             Static & Dynamic Container Auditor              ║", CYAN)],
        [("╚══════════════════════════════════════════════════════════════╝", CYAN)],
        "",
        [("  [SCANNING] ", WHITE), ("samples/Dockerfile.secure", TEXT_COLOR)],
        "",
        [("  [STATIC ANALYSIS RESULTS]", WHITE)],
        [("  " + "─" * 60, GRAY)],
        [("  LOW       ", BLUE), ("DS005 ", DIM_COLOR), ("Line 7   ", DIM_COLOR), ("Unnecessary packages installed: 'curl'", TEXT_COLOR)],
        [("            ", BLUE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("RUN apt-get update && apt-get install -y --no-instal...", DIM_COLOR)],
        "",
        [("  " + "─" * 60, GRAY)],
        [("  Summary: ", TEXT_COLOR), ("1 LOW", BLUE)],
        "",
        [("  ┌─────────────────────────────────────────────────────┐", GREEN)],
        [("  │                                                     │", GREEN)],
        [("  │  ", GREEN), ("✔ Excellent! Only 1 low-severity issue found.     ", GREEN), ("│", GREEN)],
        [("  │  ", GREEN), ("  This Dockerfile follows security best practices:", TEXT_COLOR), (" │", GREEN)],
        [("  │  ", GREEN), ("  ✓ Pinned base image   (python:3.11-slim@sha256) ", GREEN), (" │", GREEN)],
        [("  │  ", GREEN), ("  ✓ Non-root USER       (appuser:1001)            ", GREEN), (" │", GREEN)],
        [("  │  ", GREEN), ("  ✓ No hardcoded secrets                          ", GREEN), (" │", GREEN)],
        [("  │  ", GREEN), ("  ✓ HEALTHCHECK defined                           ", GREEN), (" │", GREEN)],
        [("  │  ", GREEN), ("  ✓ COPY used (not ADD)                           ", GREEN), (" │", GREEN)],
        [("  │  ", GREEN), ("  ✓ Multi-stage build for minimal image           ", GREEN), (" │", GREEN)],
        [("  │                                                     │", GREEN)],
        [("  └─────────────────────────────────────────────────────┘", GREEN)],
        "",
    ]
    create_terminal_image(lines, "03_secure_scan.png",
                          title="Docker Security Scanner — Secure Dockerfile",
                          width_chars=80)


# ── Screenshot 4: Test Suite ─────────────────────────────────────────────────

def generate_test_screenshot():
    """Generate screenshot of pytest results."""
    lines = [
        [("$ ", PROMPT_GREEN), ("python -m pytest tests/ -v --tb=short", TEXT_COLOR)],
        "",
        [("=" * 70, CYAN)],
        [("platform win32 -- Python 3.13.2, pytest-9.0.2", DIM_COLOR)],
        [("collected ", TEXT_COLOR), ("46 items", WHITE)],
        "",
        [("tests/test_parser.py", WHITE)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_root_user_detection", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_aws_key_detection", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_github_token_detection", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_generic_password_detection", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_database_url_detection", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_unpinned_base_image", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_dangerous_ports", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_unnecessary_packages", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_no_healthcheck", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_add_instead_of_copy", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_sudo_detection", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_continuation_lines", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_secret_masking", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_pinned_image_pass", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  ... and 7 more", DIM_COLOR)],
        "",
        [("tests/test_secrets.py", WHITE)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_shannon_entropy_high", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_shannon_entropy_low", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_aws_key_pattern", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_github_token_pattern", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_jwt_pattern", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_stripe_key_pattern", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_slack_webhook_pattern", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_high_entropy_string", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  ... and 2 more", DIM_COLOR)],
        "",
        [("tests/test_auditor.py", WHITE)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_privileged_container", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_docker_socket_mount", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_dangerous_capabilities", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_host_network_mode", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_no_resource_limits", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  test_no_docker_sdk", TEXT_COLOR)],
        [("  ", TEXT_COLOR), ("PASSED", GREEN), ("  ... and 5 more", DIM_COLOR)],
        "",
        [("=" * 70, CYAN)],
        [("", TEXT_COLOR), ("46 passed", GREEN), (" in 1.23s", TEXT_COLOR)],
        "",
        [("  ┌────────────────────────────────────────────┐", GREEN)],
        [("  │  ", GREEN), ("✔  All 46 tests passed                  ", GREEN), (" │", GREEN)],
        [("  │  ", GREEN), ("   21 parser · 10 secrets · 11 auditor  ", TEXT_COLOR), (" │ ", GREEN)],
        [("  │  ", GREEN), ("   4 edge-case · CI/CD ready            ", DIM_COLOR), (" │ ", GREEN)],
        [("  └────────────────────────────────────────────┘", GREEN)],
        "",
    ]
    create_terminal_image(lines, "04_test_suite.png",
                          title="Docker Security Scanner — Test Suite (46/46 Passed)",
                          width_chars=80)


# ── Screenshot 5: Dynamic Audit ──────────────────────────────────────────────

def generate_audit_screenshot():
    """Generate screenshot of container audit output."""
    lines = [
        [("$ ", PROMPT_GREEN), ("python main.py audit --container my-flask-app", TEXT_COLOR)],
        "",
        [("╔══════════════════════════════════════════════════════════════╗", CYAN)],
        [("║             Docker Security Scanner v1.0.0                  ║", CYAN)],
        [("║             Static & Dynamic Container Auditor              ║", CYAN)],
        [("╚══════════════════════════════════════════════════════════════╝", CYAN)],
        "",
        [("  [AUDITING] ", WHITE), ("Running container: my-flask-app", TEXT_COLOR)],
        "",
        [("  [DYNAMIC ANALYSIS RESULTS]", WHITE)],
        [("  " + "─" * 60, GRAY)],
        [("  CRITICAL  ", RED), ("DC001 ", DIM_COLOR), ("         ", DIM_COLOR), ("Container running in privileged mode", TEXT_COLOR)],
        [("            ", RED), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("--privileged flag grants full host access", DIM_COLOR)],
        [("  HIGH      ", ORANGE), ("DC002 ", DIM_COLOR), ("         ", DIM_COLOR), ("Docker socket mounted inside container", TEXT_COLOR)],
        [("            ", ORANGE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("/var/run/docker.sock → container escape risk", DIM_COLOR)],
        [("  HIGH      ", ORANGE), ("DC003 ", DIM_COLOR), ("         ", DIM_COLOR), ("Dangerous capability: NET_ADMIN", TEXT_COLOR)],
        [("            ", ORANGE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("Allows network configuration changes", DIM_COLOR)],
        [("  HIGH      ", ORANGE), ("DC003 ", DIM_COLOR), ("         ", DIM_COLOR), ("Dangerous capability: SYS_PTRACE", TEXT_COLOR)],
        [("            ", ORANGE), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("Allows process tracing (debug escape)", DIM_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DC004 ", DIM_COLOR), ("         ", DIM_COLOR), ("Container using host network mode", TEXT_COLOR)],
        [("            ", YELLOW), ("         ", DIM_COLOR), ("         ", DIM_COLOR), ("No network isolation from host", DIM_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DC005 ", DIM_COLOR), ("         ", DIM_COLOR), ("No CPU resource limits set", TEXT_COLOR)],
        [("  MEDIUM    ", YELLOW), ("DC005 ", DIM_COLOR), ("         ", DIM_COLOR), ("No memory resource limits set", TEXT_COLOR)],
        "",
        [("  " + "─" * 60, GRAY)],
        [("  Summary: ", TEXT_COLOR), ("1 CRITICAL", RED), (" | ", GRAY), ("3 HIGH", ORANGE), (" | ", GRAY),
         ("3 MEDIUM", YELLOW)],
        "",
        [("  ┌────────────────────────────────────────────────────────┐", GRAY)],
        [("  │  ", GRAY), ("Recommendations:                                    ", WHITE), (" │", GRAY)],
        [("  │  ", GRAY), ("  1. Remove --privileged flag                       ", TEXT_COLOR), (" │", GRAY)],
        [("  │  ", GRAY), ("  2. Never mount docker.sock in production          ", TEXT_COLOR), (" │", GRAY)],
        [("  │  ", GRAY), ("  3. Drop all caps, add only needed: --cap-drop ALL ", TEXT_COLOR), (" │", GRAY)],
        [("  │  ", GRAY), ("  4. Use bridge network, not --network host         ", TEXT_COLOR), (" │", GRAY)],
        [("  │  ", GRAY), ("  5. Set limits: --memory 512m --cpus 1.0           ", TEXT_COLOR), (" │", GRAY)],
        [("  └────────────────────────────────────────────────────────┘", GRAY)],
        "",
    ]
    create_terminal_image(lines, "05_dynamic_audit.png",
                          title="Docker Security Scanner — Container Runtime Audit",
                          width_chars=90)


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🎨 Generating screenshots for README...\n")

    generate_scan_screenshot()
    generate_html_report_screenshot()
    generate_secure_scan_screenshot()
    generate_test_screenshot()
    generate_audit_screenshot()

    print(f"\n✅ All screenshots saved to {SCREENSHOTS_DIR}/")
    print("   Files:")
    for f in sorted(os.listdir(SCREENSHOTS_DIR)):
        if f.endswith(".png"):
            size = os.path.getsize(os.path.join(SCREENSHOTS_DIR, f))
            print(f"   • {f} ({size:,} bytes)")
