"""
Security rules and severity definitions for Docker Security Scanner.

Each rule has:
    - id:          Unique check identifier (DS### for static, DC### for dynamic)
    - category:    High-level risk category
    - severity:    CRITICAL | HIGH | MEDIUM | LOW | INFO
    - title:       Short human-readable name
    - description: Detailed explanation of the risk
    - remediation: How to fix the issue
    - cis_ref:     CIS Docker Benchmark reference (where applicable)
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(Enum):
    """Risk severity levels aligned with CVSS qualitative ratings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "\033[91m",  # bright red
            "HIGH": "\033[31m",      # red
            "MEDIUM": "\033[33m",    # yellow
            "LOW": "\033[36m",       # cyan
            "INFO": "\033[37m",      # white
        }[self.value]

    @property
    def weight(self) -> int:
        """Numeric weight for sorting (higher = more severe)."""
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


@dataclass
class Finding:
    """A single security finding produced by a scan."""
    rule_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    line_number: Optional[int] = None
    line_content: Optional[str] = None
    file_path: Optional[str] = None
    category: str = ""
    cis_ref: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "file_path": self.file_path,
            "cis_ref": self.cis_ref,
        }


# ── Static Analysis Rules (Dockerfile) ──────────────────────────────────────

STATIC_RULES = {
    "DS001": {
        "category": "Privilege Escalation",
        "severity": Severity.CRITICAL,
        "title": "Container runs as root",
        "description": (
            "No USER directive found. The container will run as root by default. "
            "If an attacker compromises the application, they gain root-level access "
            "inside the container, making privilege escalation and container escape easier."
        ),
        "remediation": (
            "Add a USER directive before the final CMD/ENTRYPOINT:\n"
            "  RUN groupadd -r appuser && useradd -r -g appuser appuser\n"
            "  USER appuser"
        ),
        "cis_ref": "CIS 4.1 - Ensure a user for the container has been created",
    },
    "DS002": {
        "category": "Secret Exposure",
        "severity": Severity.HIGH,
        "title": "Hardcoded secret detected",
        "description": (
            "A potential secret (API key, password, token) was found hardcoded in the "
            "Dockerfile. Secrets baked into images persist in every layer and can be "
            "extracted by anyone with access to the image."
        ),
        "remediation": (
            "Remove secrets from the Dockerfile. Use Docker secrets, environment files, "
            "or a vault service (HashiCorp Vault, AWS Secrets Manager) to inject secrets "
            "at runtime."
        ),
        "cis_ref": "CIS 4.10 - Ensure secrets are not stored in Dockerfiles",
    },
    "DS003": {
        "category": "Supply Chain",
        "severity": Severity.MEDIUM,
        "title": "Unpinned base image tag",
        "description": (
            "The base image uses ':latest' or no tag. This means builds are not "
            "reproducible and a compromised or broken upstream image could silently "
            "break your application or introduce vulnerabilities."
        ),
        "remediation": (
            "Pin your base image to a specific version and digest:\n"
            "  FROM python:3.11-slim-bookworm@sha256:abc123..."
        ),
        "cis_ref": "CIS 4.2 - Ensure that containers use only trusted base images",
    },
    "DS004": {
        "category": "Network Exposure",
        "severity": Severity.MEDIUM,
        "title": "Dangerous port exposed",
        "description": (
            "A port commonly associated with sensitive services is exposed. Exposing "
            "database ports, SSH, or administrative interfaces directly increases the "
            "container's attack surface."
        ),
        "remediation": (
            "Remove unnecessary EXPOSE directives. Use Docker networks for inter-container "
            "communication and only expose ports that must face the public internet."
        ),
        "cis_ref": "CIS 5.8 - Ensure that only needed ports are open",
    },
    "DS005": {
        "category": "Attack Surface",
        "severity": Severity.LOW,
        "title": "Unnecessary packages installed",
        "description": (
            "Development tools, compilers, or network utilities are installed in the "
            "final image. These increase the attack surface and image size, and can "
            "assist an attacker post-compromise."
        ),
        "remediation": (
            "Use multi-stage builds to separate build and runtime. Remove dev tools from "
            "the final image. Use '--no-install-recommends' with apt-get."
        ),
        "cis_ref": "CIS 4.3 - Ensure unnecessary packages are not installed",
    },
    "DS006": {
        "category": "Build Hygiene",
        "severity": Severity.LOW,
        "title": "Dockerfile best-practice violation",
        "description": (
            "A general best-practice rule was violated (e.g., using ADD instead of COPY "
            "for local files, missing HEALTHCHECK, shell form instead of exec form for CMD)."
        ),
        "remediation": "Follow Docker best practices: https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
        "cis_ref": "",
    },
    "DS007": {
        "category": "Privilege",
        "severity": Severity.MEDIUM,
        "title": "Sudo usage detected",
        "description": (
            "The package 'sudo' is installed or invoked inside the container. Sudo inside "
            "a container undermines the principle of least privilege and can enable "
            "trivial privilege escalation."
        ),
        "remediation": (
            "Remove sudo from the container. If elevated privileges are needed for setup, "
            "perform those steps before the USER directive, then switch to a non-root user."
        ),
        "cis_ref": "",
    },
}


# ── Dynamic Analysis Rules (Running Containers) ─────────────────────────────

DYNAMIC_RULES = {
    "DC001": {
        "category": "Container Escape",
        "severity": Severity.CRITICAL,
        "title": "Container running in privileged mode",
        "description": (
            "The container is running with --privileged flag. This gives it full access "
            "to host devices and effectively disables container isolation. An attacker "
            "can trivially escape to the host."
        ),
        "remediation": (
            "Remove the --privileged flag. Grant only specific capabilities needed "
            "using --cap-add instead."
        ),
        "cis_ref": "CIS 5.4 - Ensure privileged containers are not used",
    },
    "DC002": {
        "category": "Host Takeover",
        "severity": Severity.CRITICAL,
        "title": "Docker socket mounted inside container",
        "description": (
            "The Docker socket (/var/run/docker.sock) is mounted inside this container. "
            "Anyone who compromises this container can use the socket to control the "
            "Docker daemon — spinning up new privileged containers, accessing host "
            "filesystems, or pulling sensitive images."
        ),
        "remediation": (
            "Remove the Docker socket mount. If Docker-in-Docker is needed, use a "
            "dedicated DinD sidecar with proper access controls."
        ),
        "cis_ref": "CIS 5.31 - Ensure the Docker socket is not mounted inside any containers",
    },
    "DC003": {
        "category": "Capability Abuse",
        "severity": Severity.HIGH,
        "title": "Dangerous Linux capability added",
        "description": (
            "The container has been granted a dangerous Linux capability that can be "
            "abused for privilege escalation or host escape (e.g., SYS_ADMIN, SYS_PTRACE, "
            "NET_RAW, DAC_OVERRIDE)."
        ),
        "remediation": (
            "Drop all capabilities and add back only what is strictly required:\n"
            "  docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ..."
        ),
        "cis_ref": "CIS 5.3 - Ensure Linux kernel capabilities are restricted",
    },
    "DC004": {
        "category": "Network Isolation",
        "severity": Severity.HIGH,
        "title": "Container using host network mode",
        "description": (
            "The container is using --net=host, which bypasses Docker's network isolation. "
            "The container shares the host's network stack and can interact with all host "
            "services directly."
        ),
        "remediation": (
            "Use bridge networking (default) or custom Docker networks. Only use host "
            "networking when absolutely required and document the reason."
        ),
        "cis_ref": "CIS 5.9 - Ensure the host's network namespace is not shared",
    },
    "DC005": {
        "category": "Resource Limits",
        "severity": Severity.MEDIUM,
        "title": "No resource limits configured",
        "description": (
            "The container has no memory or CPU limits. A compromised or misbehaving "
            "container can consume all host resources, causing denial-of-service for "
            "other containers and the host itself."
        ),
        "remediation": (
            "Set memory and CPU limits:\n"
            "  docker run --memory=512m --cpus=1.0 ..."
        ),
        "cis_ref": "CIS 5.10 - Ensure memory usage is limited",
    },
}


# ── Dangerous ports mapping ──────────────────────────────────────────────────

DANGEROUS_PORTS = {
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    135:  "MS-RPC",
    139:  "NetBIOS",
    445:  "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker API (unencrypted)",
    2376: "Docker API",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8443: "HTTPS-Alt/Admin",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


# ── Unnecessary packages for production ──────────────────────────────────────

UNNECESSARY_PACKAGES = {
    "vim", "nano", "vi", "emacs",
    "gcc", "g++", "make", "cmake", "build-essential",
    "gdb", "strace", "ltrace",
    "net-tools", "nmap", "tcpdump", "telnet", "netcat", "nc",
    "ssh", "openssh-server", "openssh-client",
    "curl", "wget",  # debatable in prod — flagged as LOW
    "git", "svn", "mercurial",
    "python3-dev", "python-dev",
}


# ── Dangerous Linux capabilities ─────────────────────────────────────────────

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_RAWIO",
    "SYS_MODULE",
    "NET_ADMIN",
    "NET_RAW",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "SETUID",
    "SETGID",
    "SYS_CHROOT",
    "MKNOD",
    "AUDIT_WRITE",
}
