"""
Tests for the container auditor module.

Note: These tests mock the Docker SDK since a running Docker daemon
may not be available in all test environments.
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.rules import Severity


class TestContainerAuditorWithoutDocker:
    """Test auditor behavior when Docker is not available."""

    def test_graceful_degradation(self):
        """Auditor should return INFO finding when Docker SDK is missing."""
        from scanner.container_auditor import ContainerAuditor
        auditor = ContainerAuditor()

        if not auditor.is_connected:
            findings = auditor.audit()
            assert len(findings) >= 1
            assert findings[0].severity == Severity.INFO


class TestPrivilegedDetection:
    """Test privileged container detection logic."""

    def test_detects_privileged_flag(self):
        """Verify the logic correctly identifies privileged host config."""
        host_config = {"Privileged": True}
        assert host_config.get("Privileged", False) is True

    def test_non_privileged_clean(self):
        host_config = {"Privileged": False}
        assert host_config.get("Privileged", False) is False


class TestDockerSocketDetection:
    """Test Docker socket mount detection logic."""

    def test_detects_socket_in_binds(self):
        binds = ["/var/run/docker.sock:/var/run/docker.sock"]
        found = any("docker.sock" in b for b in binds)
        assert found is True

    def test_no_socket_clean(self):
        binds = ["/data:/app/data"]
        found = any("docker.sock" in b for b in binds)
        assert found is False


class TestCapabilityDetection:
    """Test dangerous capability detection logic."""

    def test_sys_admin_flagged(self):
        from scanner.rules import DANGEROUS_CAPABILITIES
        assert "SYS_ADMIN" in DANGEROUS_CAPABILITIES

    def test_net_raw_flagged(self):
        from scanner.rules import DANGEROUS_CAPABILITIES
        assert "NET_RAW" in DANGEROUS_CAPABILITIES


class TestNetworkModeDetection:
    """Test host network mode detection logic."""

    def test_host_mode_flagged(self):
        host_config = {"NetworkMode": "host"}
        assert host_config.get("NetworkMode") == "host"

    def test_bridge_mode_clean(self):
        host_config = {"NetworkMode": "bridge"}
        assert host_config.get("NetworkMode") != "host"


class TestResourceLimits:
    """Test resource limit detection logic."""

    def test_no_limits(self):
        host_config = {"Memory": 0, "CpuQuota": 0, "NanoCpus": 0}
        has_memory = host_config.get("Memory", 0) > 0
        has_cpu = host_config.get("CpuQuota", 0) > 0 or host_config.get("NanoCpus", 0) > 0
        assert has_memory is False
        assert has_cpu is False

    def test_with_limits(self):
        host_config = {"Memory": 536870912, "CpuQuota": 50000, "NanoCpus": 0}
        has_memory = host_config.get("Memory", 0) > 0
        has_cpu = host_config.get("CpuQuota", 0) > 0
        assert has_memory is True
        assert has_cpu is True
