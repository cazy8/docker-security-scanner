"""
Dockerfile Static Analysis Engine.

Parses a Dockerfile line-by-line and applies security rules from rules.py
to detect misconfigurations, hardcoded secrets, and anti-patterns.
"""

import re
from pathlib import Path
from typing import List, Optional

from .rules import (
    STATIC_RULES,
    DANGEROUS_PORTS,
    UNNECESSARY_PACKAGES,
    Severity,
    Finding,
)
from .secret_patterns import scan_line_for_secrets, is_high_entropy_string


class DockerfileParser:
    """
    Static security analyzer for Dockerfiles.

    Usage:
        parser = DockerfileParser("path/to/Dockerfile")
        findings = parser.analyze()
        for f in findings:
            print(f"{f.severity.value}  {f.rule_id}  Line {f.line_number}  {f.title}")
    """

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.lines: List[str] = []
        self.findings: List[Finding] = []

        if not self.filepath.exists():
            raise FileNotFoundError(f"Dockerfile not found: {self.filepath}")

        self.lines = self.filepath.read_text(encoding="utf-8").splitlines()

    # ── Public API ───────────────────────────────────────────────────────

    def analyze(self) -> List[Finding]:
        """Run all static analysis checks and return findings."""
        self.findings.clear()

        self._check_root_user()        # DS001
        self._check_secrets()           # DS002
        self._check_base_image()        # DS003
        self._check_exposed_ports()     # DS004
        self._check_packages()          # DS005
        self._check_best_practices()    # DS006
        self._check_sudo()              # DS007

        # Sort by severity (most critical first), then by line number
        self.findings.sort(key=lambda f: (-f.severity.weight, f.line_number or 0))
        return self.findings

    # ── DS001: Running as Root ───────────────────────────────────────────

    def _check_root_user(self) -> None:
        """Flag if no USER directive exists to switch away from root."""
        user_found = False
        last_user_line = None

        for i, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith("USER "):
                user_value = stripped[5:].strip()
                if user_value.lower() not in ("root", "0"):
                    user_found = True
                    last_user_line = i

        if not user_found:
            rule = STATIC_RULES["DS001"]
            self.findings.append(Finding(
                rule_id="DS001",
                severity=rule["severity"],
                title=rule["title"],
                description=rule["description"],
                remediation=rule["remediation"],
                category=rule["category"],
                cis_ref=rule["cis_ref"],
                line_number=1,
                line_content=self.lines[0] if self.lines else "",
                file_path=str(self.filepath),
            ))

    # ── DS002: Hardcoded Secrets ─────────────────────────────────────────

    def _check_secrets(self) -> None:
        """Scan ENV, ARG, and LABEL directives for hardcoded secrets."""
        rule = STATIC_RULES["DS002"]

        for i, line in enumerate(self.lines, start=1):
            stripped = line.strip()

            # Skip comments and blank lines
            if not stripped or stripped.startswith("#"):
                continue

            # Focus on lines that set values
            is_env = stripped.upper().startswith("ENV ")
            is_arg = stripped.upper().startswith("ARG ")
            is_label = stripped.upper().startswith("LABEL ")
            is_run = stripped.upper().startswith("RUN ")

            if not (is_env or is_arg or is_label or is_run):
                continue

            # Pattern-based secret detection
            secret_matches = scan_line_for_secrets(stripped)
            for match_name in secret_matches:
                # Mask the actual secret value in the output
                display_line = self._mask_secret(stripped)
                self.findings.append(Finding(
                    rule_id="DS002",
                    severity=rule["severity"],
                    title=f"{rule['title']}: {match_name}",
                    description=rule["description"],
                    remediation=rule["remediation"],
                    category=rule["category"],
                    cis_ref=rule["cis_ref"],
                    line_number=i,
                    line_content=display_line,
                    file_path=str(self.filepath),
                ))

            # Entropy-based fallback for ENV/ARG values
            if (is_env or is_arg) and not secret_matches:
                value = self._extract_env_value(stripped)
                if value and is_high_entropy_string(value):
                    self.findings.append(Finding(
                        rule_id="DS002",
                        severity=Severity.MEDIUM,
                        title=f"{rule['title']}: High-entropy string",
                        description=(
                            "A high-entropy string was found that may be a secret. "
                            "Shannon entropy analysis flagged this value as potentially "
                            "sensitive."
                        ),
                        remediation=rule["remediation"],
                        category=rule["category"],
                        cis_ref=rule["cis_ref"],
                        line_number=i,
                        line_content=self._mask_secret(stripped),
                        file_path=str(self.filepath),
                    ))

    # ── DS003: Unpinned Base Image ───────────────────────────────────────

    def _check_base_image(self) -> None:
        """Flag FROM directives using :latest or no tag."""
        rule = STATIC_RULES["DS003"]

        for i, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                continue

            # Parse: FROM [--platform=...] image[:tag] [AS alias]
            parts = stripped.split()
            image_part = None
            for part in parts[1:]:
                if part.startswith("--"):
                    continue
                if part.upper() == "AS":
                    break
                image_part = part
                break

            if not image_part:
                continue

            # Check if tag is :latest or missing
            if ":" not in image_part:
                self.findings.append(Finding(
                    rule_id="DS003",
                    severity=rule["severity"],
                    title=f"{rule['title']}: '{image_part}' (no tag specified)",
                    description=rule["description"],
                    remediation=rule["remediation"],
                    category=rule["category"],
                    cis_ref=rule["cis_ref"],
                    line_number=i,
                    line_content=stripped,
                    file_path=str(self.filepath),
                ))
            elif image_part.endswith(":latest"):
                self.findings.append(Finding(
                    rule_id="DS003",
                    severity=rule["severity"],
                    title=f"{rule['title']}: '{image_part}'",
                    description=rule["description"],
                    remediation=rule["remediation"],
                    category=rule["category"],
                    cis_ref=rule["cis_ref"],
                    line_number=i,
                    line_content=stripped,
                    file_path=str(self.filepath),
                ))

    # ── DS004: Dangerous Ports ───────────────────────────────────────────

    def _check_exposed_ports(self) -> None:
        """Flag EXPOSE directives for dangerous/sensitive ports."""
        rule = STATIC_RULES["DS004"]

        for i, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            if not stripped.upper().startswith("EXPOSE "):
                continue

            # EXPOSE can list multiple ports: EXPOSE 80 443 3306
            ports_str = stripped[7:].strip()
            for token in ports_str.split():
                # Handle port/protocol format: 8080/tcp
                port_str = token.split("/")[0]
                try:
                    port = int(port_str)
                except ValueError:
                    continue

                if port in DANGEROUS_PORTS:
                    service = DANGEROUS_PORTS[port]
                    self.findings.append(Finding(
                        rule_id="DS004",
                        severity=rule["severity"],
                        title=f"{rule['title']}: {port} ({service})",
                        description=rule["description"],
                        remediation=rule["remediation"],
                        category=rule["category"],
                        cis_ref=rule["cis_ref"],
                        line_number=i,
                        line_content=stripped,
                        file_path=str(self.filepath),
                    ))

    # ── DS005: Unnecessary Packages ──────────────────────────────────────

    def _check_packages(self) -> None:
        """Flag installation of unnecessary tools in the final image."""
        rule = STATIC_RULES["DS005"]

        # Track if this is a multi-stage build
        from_count = sum(
            1 for line in self.lines if line.strip().upper().startswith("FROM ")
        )
        is_multistage = from_count > 1

        # In multi-stage builds, only check lines after the last FROM
        start_idx = 0
        if is_multistage:
            for i, line in enumerate(self.lines):
                if line.strip().upper().startswith("FROM "):
                    start_idx = i

        # Join continuation lines for RUN directives
        merged_lines = self._merge_continuation_lines(start_idx)

        for line_num, merged_line in merged_lines:
            stripped = merged_line.strip()
            if not stripped.upper().startswith("RUN "):
                continue

            # Check for package install commands
            lower_line = stripped.lower()
            has_install = any(cmd in lower_line for cmd in [
                "apt-get install", "apt install",
                "yum install", "dnf install",
                "apk add", "pip install",
                "npm install", "gem install",
            ])

            if not has_install:
                continue

            for pkg in UNNECESSARY_PACKAGES:
                # Word boundary check to avoid false positives
                pattern = rf"\b{re.escape(pkg)}\b"
                if re.search(pattern, lower_line):
                    self.findings.append(Finding(
                        rule_id="DS005",
                        severity=rule["severity"],
                        title=f"{rule['title']}: '{pkg}'",
                        description=rule["description"],
                        remediation=rule["remediation"],
                        category=rule["category"],
                        cis_ref=rule["cis_ref"],
                        line_number=line_num,
                        line_content=stripped[:120] + ("..." if len(stripped) > 120 else ""),
                        file_path=str(self.filepath),
                    ))

    # ── DS006: Build Best Practices ──────────────────────────────────────

    def _check_best_practices(self) -> None:
        """Check for generic Dockerfile best-practice violations."""
        rule = STATIC_RULES["DS006"]

        has_healthcheck = False

        for i, line in enumerate(self.lines, start=1):
            stripped = line.strip()

            # Check ADD vs COPY for local files
            if stripped.upper().startswith("ADD "):
                parts = stripped.split()
                if len(parts) >= 2:
                    src = parts[1]
                    # ADD is fine for URLs and tar extraction; flag for local copies
                    if not src.startswith(("http://", "https://")) and not src.endswith((".tar", ".tar.gz", ".tgz")):
                        self.findings.append(Finding(
                            rule_id="DS006",
                            severity=rule["severity"],
                            title="Use COPY instead of ADD for local files",
                            description=(
                                "ADD has extra functionality (URL fetching, tar extraction) "
                                "that can lead to unexpected behavior. Use COPY for simple "
                                "file copying."
                            ),
                            remediation="Replace ADD with COPY for local file operations.",
                            category=rule["category"],
                            line_number=i,
                            line_content=stripped,
                            file_path=str(self.filepath),
                        ))

            # Track HEALTHCHECK
            if stripped.upper().startswith("HEALTHCHECK "):
                has_healthcheck = True

            # Check CMD/ENTRYPOINT form (shell vs exec)
            if stripped.upper().startswith(("CMD ", "ENTRYPOINT ")):
                if not stripped.split(None, 1)[1].strip().startswith("["):
                    self.findings.append(Finding(
                        rule_id="DS006",
                        severity=Severity.INFO,
                        title="Shell form used for CMD/ENTRYPOINT",
                        description=(
                            "Shell form (CMD command arg1) doesn't receive Unix signals "
                            "properly. The exec form (CMD [\"command\", \"arg1\"]) is preferred "
                            "for proper signal handling and graceful shutdown."
                        ),
                        remediation='Use exec form: CMD ["executable", "param1", "param2"]',
                        category=rule["category"],
                        line_number=i,
                        line_content=stripped,
                        file_path=str(self.filepath),
                    ))

        # Missing HEALTHCHECK
        if not has_healthcheck:
            self.findings.append(Finding(
                rule_id="DS006",
                severity=Severity.LOW,
                title="No HEALTHCHECK instruction",
                description=(
                    "No HEALTHCHECK is defined. Docker cannot detect if the application "
                    "inside the container has crashed or become unresponsive."
                ),
                remediation='Add: HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1',
                category=rule["category"],
                line_number=None,
                line_content=None,
                file_path=str(self.filepath),
            ))

    # ── DS007: Sudo Detection ────────────────────────────────────────────

    def _check_sudo(self) -> None:
        """Flag sudo installation or usage."""
        rule = STATIC_RULES["DS007"]

        for i, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            lower = stripped.lower()

            if stripped.startswith("#"):
                continue

            # Check for sudo installation
            if re.search(r"\b(apt-get|apt|yum|dnf|apk)\b.*\binstall\b.*\bsudo\b", lower):
                self.findings.append(Finding(
                    rule_id="DS007",
                    severity=rule["severity"],
                    title=f"{rule['title']} (installation)",
                    description=rule["description"],
                    remediation=rule["remediation"],
                    category=rule["category"],
                    line_number=i,
                    line_content=stripped,
                    file_path=str(self.filepath),
                ))

            # Check for sudo usage in RUN
            elif stripped.upper().startswith("RUN ") and re.search(r"\bsudo\b", lower):
                self.findings.append(Finding(
                    rule_id="DS007",
                    severity=rule["severity"],
                    title=f"{rule['title']} (usage)",
                    description=rule["description"],
                    remediation=rule["remediation"],
                    category=rule["category"],
                    line_number=i,
                    line_content=stripped,
                    file_path=str(self.filepath),
                ))

    # ── Helper Methods ───────────────────────────────────────────────────

    @staticmethod
    def _mask_secret(line: str) -> str:
        """Mask secret values in output for safe display."""
        # Mask values after = in ENV/ARG lines
        result = re.sub(
            r"(=\s*['\"]?)([^\s'\"]{4})([^\s'\"]+)(['\"]?)",
            lambda m: f"{m.group(1)}{m.group(2)}{'*' * min(len(m.group(3)), 20)}{m.group(4)}",
            line,
        )
        return result

    @staticmethod
    def _extract_env_value(line: str) -> Optional[str]:
        """Extract the value portion from an ENV or ARG directive."""
        # ENV KEY=VALUE or ENV KEY VALUE
        match = re.match(r"(?:ENV|ARG)\s+\w+[=\s]\s*['\"]?(.+?)['\"]?\s*$", line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def _merge_continuation_lines(self, start_idx: int = 0) -> List[tuple]:
        """
        Merge backslash-continuation lines into single logical lines.

        Returns list of (first_line_number, merged_content) tuples.
        """
        merged = []
        current_line = ""
        current_line_num = start_idx + 1

        for i in range(start_idx, len(self.lines)):
            line = self.lines[i]
            stripped = line.rstrip()

            if not current_line:
                current_line_num = i + 1

            if stripped.endswith("\\"):
                current_line += stripped[:-1] + " "
            else:
                current_line += stripped
                if current_line.strip():
                    merged.append((current_line_num, current_line))
                current_line = ""

        if current_line.strip():
            merged.append((current_line_num, current_line))

        return merged
