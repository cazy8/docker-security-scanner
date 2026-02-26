#!/usr/bin/env python3
"""
Docker Security Scanner — CLI Entry Point

A security scanner that performs static analysis on Dockerfiles and
dynamic auditing of running containers to detect misconfigurations,
hardcoded secrets, and security anti-patterns.

Usage:
    python main.py scan --file <Dockerfile>           # Static analysis
    python main.py audit                               # Running container audit
    python main.py scan --file <Dockerfile> --format html --output report.html
"""

import argparse
import sys
import os

# Add project root to path for clean imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.dockerfile_parser import DockerfileParser
from scanner.container_auditor import ContainerAuditor
from scanner.report import (
    print_banner,
    print_findings,
    generate_json_report,
    generate_html_report,
)


def cmd_scan(args: argparse.Namespace) -> int:
    """Handle the 'scan' subcommand — static Dockerfile analysis."""
    print_banner()

    filepath = args.file

    try:
        parser = DockerfileParser(filepath)
    except FileNotFoundError as e:
        print(f"\n  \033[91mError:\033[0m {e}")
        return 1

    print(f"\n  \033[96m[SCANNING]\033[0m {filepath}")
    findings = parser.analyze()

    # Terminal output (always shown)
    print_findings(findings, title="Static Analysis Results")

    # Optional file outputs
    if args.output:
        fmt = args.format or _infer_format(args.output)

        if fmt == "json":
            path = generate_json_report(findings, args.output, scan_target=filepath)
            print(f"  \033[92m✔\033[0m JSON report saved: {path}")
        elif fmt == "html":
            path = generate_html_report(findings, args.output, scan_target=filepath)
            print(f"  \033[92m✔\033[0m HTML report saved: {path}")
        else:
            print(f"  \033[91m✖\033[0m Unknown format: {fmt}")
            return 1

    # Return non-zero if critical/high findings exist
    severe = sum(1 for f in findings if f.severity.weight >= 4)
    return 1 if severe > 0 else 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Handle the 'audit' subcommand — dynamic container inspection."""
    print_banner()

    print(f"\n  \033[96m[AUDITING]\033[0m Running containers...")

    auditor = ContainerAuditor()
    findings = auditor.audit()

    # Show container summary if connected
    if auditor.is_connected:
        summaries = auditor.get_container_summary()
        if summaries:
            print(f"\n  Found {len(summaries)} running container(s):")
            for s in summaries:
                print(f"    • {s['name']} ({s['id']}) — {s['image']}")

    print_findings(findings, title="Dynamic Audit Results")

    # Optional file outputs
    if args.output:
        fmt = args.format or _infer_format(args.output)

        if fmt == "json":
            path = generate_json_report(findings, args.output, scan_target="running containers")
            print(f"  \033[92m✔\033[0m JSON report saved: {path}")
        elif fmt == "html":
            path = generate_html_report(findings, args.output, scan_target="running containers")
            print(f"  \033[92m✔\033[0m HTML report saved: {path}")
        else:
            print(f"  \033[91m✖\033[0m Unknown format: {fmt}")
            return 1

    severe = sum(1 for f in findings if f.severity.weight >= 4)
    return 1 if severe > 0 else 0


def cmd_full(args: argparse.Namespace) -> int:
    """Handle the 'full' subcommand — both static and dynamic analysis."""
    print_banner()

    all_findings = []

    # Static analysis
    if args.file:
        try:
            parser = DockerfileParser(args.file)
            print(f"\n  \033[96m[SCANNING]\033[0m {args.file}")
            static_findings = parser.analyze()
            all_findings.extend(static_findings)
            print_findings(static_findings, title="Static Analysis Results")
        except FileNotFoundError as e:
            print(f"\n  \033[91mError:\033[0m {e}")

    # Dynamic analysis
    print(f"\n  \033[96m[AUDITING]\033[0m Running containers...")
    auditor = ContainerAuditor()
    dynamic_findings = auditor.audit()
    all_findings.extend(dynamic_findings)
    print_findings(dynamic_findings, title="Dynamic Audit Results")

    # Optional file outputs
    if args.output:
        fmt = args.format or _infer_format(args.output)
        target = args.file or "full scan"

        if fmt == "json":
            path = generate_json_report(all_findings, args.output, scan_target=target)
            print(f"  \033[92m✔\033[0m JSON report saved: {path}")
        elif fmt == "html":
            path = generate_html_report(all_findings, args.output, scan_target=target)
            print(f"  \033[92m✔\033[0m HTML report saved: {path}")

    severe = sum(1 for f in all_findings if f.severity.weight >= 4)
    return 1 if severe > 0 else 0


def _infer_format(output_path: str) -> str:
    """Infer report format from file extension."""
    ext = os.path.splitext(output_path)[1].lower()
    return {"json": "json", ".json": "json", ".html": "html", ".htm": "html"}.get(ext, "json")


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="docker-security-scanner",
        description="Docker Security Scanner — Static & Dynamic Container Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan --file Dockerfile
  python main.py scan --file Dockerfile --format html --output report.html
  python main.py audit
  python main.py audit --format json --output audit.json
  python main.py full --file Dockerfile --output full_report.html
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Scanner mode")

    # ── scan subcommand ──
    scan_parser = subparsers.add_parser("scan", help="Static analysis of a Dockerfile")
    scan_parser.add_argument(
        "--file", "-f", required=True,
        help="Path to the Dockerfile to scan",
    )
    scan_parser.add_argument(
        "--format", choices=["json", "html"],
        help="Output report format (default: inferred from --output extension)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Path for the output report file",
    )

    # ── audit subcommand ──
    audit_parser = subparsers.add_parser("audit", help="Dynamic audit of running containers")
    audit_parser.add_argument(
        "--format", choices=["json", "html"],
        help="Output report format",
    )
    audit_parser.add_argument(
        "--output", "-o",
        help="Path for the output report file",
    )

    # ── full subcommand ──
    full_parser = subparsers.add_parser("full", help="Run both static and dynamic analysis")
    full_parser.add_argument(
        "--file", "-f",
        help="Path to the Dockerfile to scan (optional)",
    )
    full_parser.add_argument(
        "--format", choices=["json", "html"],
        help="Output report format",
    )
    full_parser.add_argument(
        "--output", "-o",
        help="Path for the output report file",
    )

    return parser


def main() -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    handlers = {
        "scan": cmd_scan,
        "audit": cmd_audit,
        "full": cmd_full,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
