"""
Report generator for Docker Security Scanner.

Outputs scan results in:
  - Terminal (colored table)
  - JSON
  - HTML (standalone, no external dependencies)
"""

import json
import os
from datetime import datetime, timezone
from typing import List

from .rules import Finding, Severity


# ── Terminal Colors ──────────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _supports_color() -> bool:
    """Check if the terminal supports ANSI color codes."""
    if os.name == "nt":
        # Windows 10+ supports ANSI via virtual terminal processing
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return os.environ.get("TERM_PROGRAM") is not None
    return hasattr(os.sys.stdout, "isatty") and os.sys.stdout.isatty()


USE_COLOR = _supports_color()


def _c(text: str, color: str) -> str:
    """Wrap text in ANSI color codes if supported."""
    if USE_COLOR:
        return f"{color}{text}{RESET}"
    return text


# ── Terminal Report ──────────────────────────────────────────────────────────

def print_banner() -> None:
    """Print the scanner banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║             Docker Security Scanner v1.0.0                  ║
║             Static & Dynamic Container Auditor              ║
╚══════════════════════════════════════════════════════════════╝"""
    print(_c(banner, "\033[96m"))


def print_findings(findings: List[Finding], title: str = "Scan Results") -> None:
    """
    Print findings to terminal with color-coded severity.

    Args:
        findings: List of Finding objects to display.
        title: Section header.
    """
    if not findings:
        print(f"\n  {_c('✔ No issues found!', '\033[92m')}\n")
        return

    print(f"\n{_c(f'  [{title.upper()}]', BOLD)}")
    print(f"  {'─' * 60}")

    for f in findings:
        sev = f.severity
        sev_display = f"  {_c(sev.value.ljust(10), sev.color)}"
        rule = _c(f.rule_id.ljust(6), DIM)

        line_info = ""
        if f.line_number:
            line_info = _c(f"Line {str(f.line_number).ljust(4)}", DIM)

        print(f"{sev_display}{rule}{line_info}{f.title}")

        if f.line_content:
            content = f.line_content.strip()
            if len(content) > 80:
                content = content[:77] + "..."
            print(f"  {'':10}{'':6}{'':9}{_c(content, DIM)}")

    # Summary
    print(f"\n  {'─' * 60}")
    summary_parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = sum(1 for f in findings if f.severity == sev)
        if count > 0:
            summary_parts.append(_c(f"{count} {sev.value}", sev.color))

    print(f"  Summary: {' | '.join(summary_parts)}")
    print()


# ── JSON Report ──────────────────────────────────────────────────────────────

def generate_json_report(
    findings: List[Finding],
    output_path: str,
    scan_target: str = "",
) -> str:
    """
    Generate a JSON report file.

    Args:
        findings: List of Finding objects.
        output_path: File path for the JSON output.
        scan_target: The scanned Dockerfile or "running containers".

    Returns:
        Absolute path of the generated report.
    """
    report = {
        "scanner": "Docker Security Scanner v1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": scan_target,
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
        },
        "findings": [f.to_dict() for f in findings],
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)

    return os.path.abspath(output_path)


# ── HTML Report ──────────────────────────────────────────────────────────────

def generate_html_report(
    findings: List[Finding],
    output_path: str,
    scan_target: str = "",
) -> str:
    """
    Generate a standalone HTML report with embedded CSS.

    Args:
        findings: List of Finding objects.
        output_path: File path for the HTML output.
        scan_target: The scanned Dockerfile or "running containers".

    Returns:
        Absolute path of the generated report.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    severity_counts = {}
    for sev in Severity:
        severity_counts[sev.value] = sum(1 for f in findings if f.severity == sev)

    # Build findings HTML rows
    rows_html = ""
    for f in findings:
        sev_class = f.severity.value.lower()
        line_display = f"Line {f.line_number}" if f.line_number else "—"
        content_display = ""
        if f.line_content:
            import html as html_mod
            content_display = f'<code>{html_mod.escape(f.line_content[:120])}</code>'

        rows_html += f"""
        <tr class="finding-row {sev_class}">
            <td><span class="badge {sev_class}">{f.severity.value}</span></td>
            <td><strong>{f.rule_id}</strong></td>
            <td>{line_display}</td>
            <td>
                <strong>{_html_escape(f.title)}</strong>
                {f'<br>{content_display}' if content_display else ''}
            </td>
            <td class="detail-cell">
                <details>
                    <summary>Details</summary>
                    <p><strong>Description:</strong> {_html_escape(f.description)}</p>
                    <p><strong>Remediation:</strong> {_html_escape(f.remediation)}</p>
                    {f'<p><strong>CIS Reference:</strong> {_html_escape(f.cis_ref)}</p>' if f.cis_ref else ''}
                </details>
            </td>
        </tr>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Docker Security Scan Report</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-dim: #8b949e;
            --critical: #f85149;
            --high: #da3633;
            --medium: #d29922;
            --low: #58a6ff;
            --info: #8b949e;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}
        .header h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
        .header .meta {{ color: var(--text-dim); font-size: 0.9rem; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}
        .summary-card .count {{ font-size: 2rem; font-weight: bold; }}
        .summary-card.critical .count {{ color: var(--critical); }}
        .summary-card.high .count {{ color: var(--high); }}
        .summary-card.medium .count {{ color: var(--medium); }}
        .summary-card.low .count {{ color: var(--low); }}
        .summary-card.info .count {{ color: var(--info); }}
        .summary-card .label {{ color: var(--text-dim); font-size: 0.85rem; text-transform: uppercase; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #1c2128;
            padding: 0.75rem 1rem;
            text-align: left;
            font-size: 0.85rem;
            text-transform: uppercase;
            color: var(--text-dim);
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }}
        .badge.high {{ background: rgba(218,54,51,0.15); color: var(--high); border: 1px solid var(--high); }}
        .badge.medium {{ background: rgba(210,153,34,0.15); color: var(--medium); border: 1px solid var(--medium); }}
        .badge.low {{ background: rgba(88,166,255,0.15); color: var(--low); border: 1px solid var(--low); }}
        .badge.info {{ background: rgba(139,148,158,0.15); color: var(--info); border: 1px solid var(--info); }}
        code {{
            background: #1c2128;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.85rem;
            color: var(--text-dim);
        }}
        details {{ margin-top: 0.5rem; }}
        details summary {{
            cursor: pointer;
            color: var(--low);
            font-size: 0.85rem;
        }}
        details p {{ margin: 0.5rem 0; font-size: 0.9rem; }}
        .footer {{
            text-align: center;
            margin-top: 2rem;
            color: var(--text-dim);
            font-size: 0.8rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐳 Docker Security Scan Report</h1>
            <p class="meta">Target: <strong>{_html_escape(scan_target)}</strong></p>
            <p class="meta">Scanned: {timestamp} | Total findings: {len(findings)}</p>
        </div>

        <div class="summary">
            <div class="summary-card critical">
                <div class="count">{severity_counts.get('CRITICAL', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{severity_counts.get('HIGH', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{severity_counts.get('MEDIUM', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{severity_counts.get('LOW', 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{severity_counts.get('INFO', 0)}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Location</th>
                    <th>Finding</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {rows_html if rows_html else '<tr><td colspan="5" style="text-align:center; padding:2rem;">✔ No issues found</td></tr>'}
            </tbody>
        </table>

        <div class="footer">
            <p>Generated by Docker Security Scanner v1.0.0 | {timestamp}</p>
        </div>
    </div>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(html_content)

    return os.path.abspath(output_path)


def _html_escape(text: str) -> str:
    """Escape HTML special characters."""
    import html as html_mod
    return html_mod.escape(text).replace("\n", "<br>")
