"""
Dynamic Container Auditor for Docker Security Scanner.

Uses the Docker SDK for Python to inspect running containers and
detect runtime security misconfigurations.

Requires Docker to be installed and the Docker daemon to be running.
"""

from typing import List, Optional

from .rules import (
    DYNAMIC_RULES,
    DANGEROUS_CAPABILITIES,
    Severity,
    Finding,
)

# Docker SDK is optional — gracefully degrade if not available
try:
    import docker
    from docker.errors import DockerException

    DOCKER_SDK_AVAILABLE = True
except ImportError:
    DOCKER_SDK_AVAILABLE = False


class ContainerAuditor:
    """
    Dynamic security auditor for running Docker containers.

    Connects to the local Docker daemon and inspects all running containers
    for security misconfigurations.

    Usage:
        auditor = ContainerAuditor()
        findings = auditor.audit()
        for f in findings:
            print(f"{f.severity.value}  {f.rule_id}  {f.title}")
    """

    def __init__(self):
        self.client: Optional[object] = None
        self.findings: List[Finding] = []

        if not DOCKER_SDK_AVAILABLE:
            return

        try:
            self.client = docker.from_env()
            # Test the connection
            self.client.ping()
        except Exception:
            self.client = None

    @property
    def is_connected(self) -> bool:
        """Check if we have a working Docker connection."""
        return self.client is not None

    # ── Public API ───────────────────────────────────────────────────────

    def audit(self) -> List[Finding]:
        """
        Audit all running containers for security misconfigurations.

        Returns:
            List of Finding objects sorted by severity.
        """
        self.findings.clear()

        if not DOCKER_SDK_AVAILABLE:
            self.findings.append(Finding(
                rule_id="DC000",
                severity=Severity.INFO,
                title="Docker SDK not installed",
                description=(
                    "The 'docker' Python package is not installed. "
                    "Dynamic container auditing requires the Docker SDK."
                ),
                remediation="Install with: pip install docker",
                category="Setup",
            ))
            return self.findings

        if not self.is_connected:
            self.findings.append(Finding(
                rule_id="DC000",
                severity=Severity.INFO,
                title="Cannot connect to Docker daemon",
                description=(
                    "Could not connect to the Docker daemon. Ensure Docker is "
                    "installed and running. On Linux, your user may need to be "
                    "in the 'docker' group."
                ),
                remediation="Start Docker: 'sudo systemctl start docker' or open Docker Desktop.",
                category="Setup",
            ))
            return self.findings

        containers = self.client.containers.list()

        if not containers:
            self.findings.append(Finding(
                rule_id="DC000",
                severity=Severity.INFO,
                title="No running containers found",
                description="No containers are currently running on this Docker host.",
                remediation="Start a container and re-run the audit.",
                category="Setup",
            ))
            return self.findings

        for container in containers:
            self._audit_container(container)

        # Sort by severity
        self.findings.sort(key=lambda f: (-f.severity.weight, f.rule_id))
        return self.findings

    def get_container_summary(self) -> List[dict]:
        """Get a summary of all running containers."""
        if not self.is_connected:
            return []

        summaries = []
        for container in self.client.containers.list():
            info = container.attrs
            summaries.append({
                "id": container.short_id,
                "name": container.name,
                "image": container.image.tags[0] if container.image.tags else "unknown",
                "status": container.status,
                "created": info.get("Created", "unknown"),
                "ports": info.get("NetworkSettings", {}).get("Ports", {}),
            })
        return summaries

    # ── Private Audit Checks ─────────────────────────────────────────────

    def _audit_container(self, container) -> None:
        """Run all dynamic checks against a single container."""
        container_name = container.name
        container_id = container.short_id

        # Fetch detailed inspection data
        info = container.attrs
        host_config = info.get("HostConfig", {})

        self._check_privileged(container_name, container_id, host_config)     # DC001
        self._check_docker_socket(container_name, container_id, host_config)  # DC002
        self._check_capabilities(container_name, container_id, host_config)   # DC003
        self._check_network_mode(container_name, container_id, host_config)   # DC004
        self._check_resource_limits(container_name, container_id, host_config)  # DC005

    def _check_privileged(self, name: str, cid: str, host_config: dict) -> None:
        """DC001: Check if container runs in privileged mode."""
        if host_config.get("Privileged", False):
            rule = DYNAMIC_RULES["DC001"]
            self.findings.append(Finding(
                rule_id="DC001",
                severity=rule["severity"],
                title=f"{rule['title']}: {name} ({cid})",
                description=rule["description"],
                remediation=rule["remediation"],
                category=rule["category"],
                cis_ref=rule["cis_ref"],
            ))

    def _check_docker_socket(self, name: str, cid: str, host_config: dict) -> None:
        """DC002: Check if Docker socket is mounted."""
        binds = host_config.get("Binds") or []
        mounts = host_config.get("Mounts") or []

        # Check Binds
        for bind in binds:
            if "/var/run/docker.sock" in bind or "docker.sock" in bind:
                rule = DYNAMIC_RULES["DC002"]
                self.findings.append(Finding(
                    rule_id="DC002",
                    severity=rule["severity"],
                    title=f"{rule['title']}: {name} ({cid})",
                    description=rule["description"],
                    remediation=rule["remediation"],
                    category=rule["category"],
                    cis_ref=rule["cis_ref"],
                    line_content=f"Mount: {bind}",
                ))
                return

        # Check Mounts
        for mount in mounts:
            source = mount.get("Source", "") if isinstance(mount, dict) else ""
            if "docker.sock" in source:
                rule = DYNAMIC_RULES["DC002"]
                self.findings.append(Finding(
                    rule_id="DC002",
                    severity=rule["severity"],
                    title=f"{rule['title']}: {name} ({cid})",
                    description=rule["description"],
                    remediation=rule["remediation"],
                    category=rule["category"],
                    cis_ref=rule["cis_ref"],
                    line_content=f"Mount: {source}",
                ))
                return

    def _check_capabilities(self, name: str, cid: str, host_config: dict) -> None:
        """DC003: Check for dangerous Linux capabilities."""
        cap_add = host_config.get("CapAdd") or []

        for cap in cap_add:
            cap_upper = cap.upper()
            if cap_upper in DANGEROUS_CAPABILITIES:
                rule = DYNAMIC_RULES["DC003"]
                self.findings.append(Finding(
                    rule_id="DC003",
                    severity=rule["severity"],
                    title=f"{rule['title']}: {cap_upper} on {name} ({cid})",
                    description=rule["description"],
                    remediation=rule["remediation"],
                    category=rule["category"],
                    cis_ref=rule["cis_ref"],
                ))

    def _check_network_mode(self, name: str, cid: str, host_config: dict) -> None:
        """DC004: Check for host network mode."""
        network_mode = host_config.get("NetworkMode", "")

        if network_mode == "host":
            rule = DYNAMIC_RULES["DC004"]
            self.findings.append(Finding(
                rule_id="DC004",
                severity=rule["severity"],
                title=f"{rule['title']}: {name} ({cid})",
                description=rule["description"],
                remediation=rule["remediation"],
                category=rule["category"],
                cis_ref=rule["cis_ref"],
            ))

    def _check_resource_limits(self, name: str, cid: str, host_config: dict) -> None:
        """DC005: Check for missing resource limits."""
        memory = host_config.get("Memory", 0)
        cpu_quota = host_config.get("CpuQuota", 0)
        nano_cpus = host_config.get("NanoCpus", 0)

        has_memory_limit = memory > 0
        has_cpu_limit = cpu_quota > 0 or nano_cpus > 0

        if not has_memory_limit or not has_cpu_limit:
            rule = DYNAMIC_RULES["DC005"]
            missing = []
            if not has_memory_limit:
                missing.append("memory")
            if not has_cpu_limit:
                missing.append("CPU")

            self.findings.append(Finding(
                rule_id="DC005",
                severity=rule["severity"],
                title=f"{rule['title']}: {name} ({cid}) — no {'/'.join(missing)} limit",
                description=rule["description"],
                remediation=rule["remediation"],
                category=rule["category"],
                cis_ref=rule["cis_ref"],
            ))
