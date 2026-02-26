"""
Tests for the Dockerfile static analysis parser.
"""

import os
import sys
import tempfile

import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.dockerfile_parser import DockerfileParser
from scanner.rules import Severity


# ── Helpers ──────────────────────────────────────────────────────────────────

def _create_temp_dockerfile(content: str) -> str:
    """Write Dockerfile content to a temp file and return its path."""
    fd, path = tempfile.mkstemp(prefix="Dockerfile_test_", suffix="")
    os.close(fd)  # Close the file descriptor before writing
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# ── DS001: Root User Detection ──────────────────────────────────────────────

class TestDS001RootUser:
    """Test detection of containers running as root."""

    def test_no_user_directive(self):
        path = _create_temp_dockerfile("FROM ubuntu:22.04\nRUN echo hello\nCMD [\"bash\"]")
        findings = DockerfileParser(path).analyze()
        ds001 = [f for f in findings if f.rule_id == "DS001"]
        assert len(ds001) == 1
        assert ds001[0].severity == Severity.CRITICAL
        os.unlink(path)

    def test_user_directive_present(self):
        content = "FROM ubuntu:22.04\nRUN groupadd -r app && useradd -r -g app app\nUSER app\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds001 = [f for f in findings if f.rule_id == "DS001"]
        assert len(ds001) == 0
        os.unlink(path)

    def test_user_root_still_flags(self):
        content = "FROM ubuntu:22.04\nUSER root\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds001 = [f for f in findings if f.rule_id == "DS001"]
        assert len(ds001) == 1  # USER root should still flag
        os.unlink(path)


# ── DS002: Secret Detection ─────────────────────────────────────────────────

class TestDS002Secrets:
    """Test detection of hardcoded secrets."""

    def test_aws_key_detected(self):
        content = "FROM python:3.11\nENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nCMD [\"python\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds002 = [f for f in findings if f.rule_id == "DS002"]
        assert len(ds002) >= 1
        assert any("AWS" in f.title for f in ds002)
        os.unlink(path)

    def test_github_token_detected(self):
        content = "FROM python:3.11\nENV GITHUB_TOKEN=ghp_EXAMPLETOKEN000000000000000000000000\nCMD [\"python\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds002 = [f for f in findings if f.rule_id == "DS002"]
        assert len(ds002) >= 1
        os.unlink(path)

    def test_password_in_env(self):
        content = "FROM python:3.11\nENV DB_PASSWORD=MySecretPass123\nCMD [\"python\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds002 = [f for f in findings if f.rule_id == "DS002"]
        assert len(ds002) >= 1
        os.unlink(path)

    def test_no_secrets_clean(self):
        content = "FROM python:3.11\nENV APP_NAME=myapp\nENV PORT=8080\nCMD [\"python\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds002 = [f for f in findings if f.rule_id == "DS002"]
        assert len(ds002) == 0
        os.unlink(path)


# ── DS003: Unpinned Base Image ──────────────────────────────────────────────

class TestDS003BaseImage:
    """Test detection of unpinned base images."""

    def test_latest_tag_flagged(self):
        content = "FROM ubuntu:latest\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds003 = [f for f in findings if f.rule_id == "DS003"]
        assert len(ds003) == 1
        os.unlink(path)

    def test_no_tag_flagged(self):
        content = "FROM ubuntu\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds003 = [f for f in findings if f.rule_id == "DS003"]
        assert len(ds003) == 1
        os.unlink(path)

    def test_pinned_tag_clean(self):
        content = "FROM python:3.11-slim-bookworm\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds003 = [f for f in findings if f.rule_id == "DS003"]
        assert len(ds003) == 0
        os.unlink(path)


# ── DS004: Dangerous Ports ──────────────────────────────────────────────────

class TestDS004Ports:
    """Test detection of dangerous exposed ports."""

    def test_ssh_port_flagged(self):
        content = "FROM python:3.11\nEXPOSE 22\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds004 = [f for f in findings if f.rule_id == "DS004"]
        assert len(ds004) == 1
        assert "SSH" in ds004[0].title
        os.unlink(path)

    def test_mysql_port_flagged(self):
        content = "FROM python:3.11\nEXPOSE 3306\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds004 = [f for f in findings if f.rule_id == "DS004"]
        assert len(ds004) == 1
        assert "MySQL" in ds004[0].title
        os.unlink(path)

    def test_safe_port_clean(self):
        content = "FROM python:3.11\nEXPOSE 8080\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds004 = [f for f in findings if f.rule_id == "DS004"]
        assert len(ds004) == 0
        os.unlink(path)

    def test_multiple_ports(self):
        content = "FROM python:3.11\nEXPOSE 22 80 3306\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds004 = [f for f in findings if f.rule_id == "DS004"]
        assert len(ds004) == 2  # SSH and MySQL flagged, 80 is not dangerous
        os.unlink(path)


# ── DS007: Sudo Detection ──────────────────────────────────────────────────

class TestDS007Sudo:
    """Test detection of sudo usage."""

    def test_sudo_install_flagged(self):
        content = "FROM ubuntu:22.04\nRUN apt-get install -y sudo\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds007 = [f for f in findings if f.rule_id == "DS007"]
        assert len(ds007) >= 1
        os.unlink(path)


# ── DS006: Best Practices ──────────────────────────────────────────────────

class TestDS006BestPractices:
    """Test best-practice violations."""

    def test_add_instead_of_copy(self):
        content = "FROM python:3.11\nADD ./app /app\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds006 = [f for f in findings if f.rule_id == "DS006" and "COPY" in f.title]
        assert len(ds006) == 1
        os.unlink(path)

    def test_no_healthcheck(self):
        content = "FROM python:3.11\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds006 = [f for f in findings if f.rule_id == "DS006" and "HEALTHCHECK" in f.title]
        assert len(ds006) == 1
        os.unlink(path)

    def test_healthcheck_present(self):
        content = "FROM python:3.11\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nCMD [\"bash\"]"
        path = _create_temp_dockerfile(content)
        findings = DockerfileParser(path).analyze()
        ds006 = [f for f in findings if f.rule_id == "DS006" and "HEALTHCHECK" in f.title]
        assert len(ds006) == 0
        os.unlink(path)


# ── Integration: Vulnerable Dockerfile ──────────────────────────────────────

class TestVulnerableDockerfile:
    """Integration test against the sample vulnerable Dockerfile."""

    @pytest.fixture
    def sample_path(self):
        return os.path.join(os.path.dirname(__file__), "..", "samples", "Dockerfile.vulnerable")

    def test_finds_multiple_issues(self, sample_path):
        if not os.path.exists(sample_path):
            pytest.skip("Sample Dockerfile.vulnerable not found")
        findings = DockerfileParser(sample_path).analyze()
        assert len(findings) >= 5  # Should find many issues

    def test_finds_critical_root(self, sample_path):
        if not os.path.exists(sample_path):
            pytest.skip("Sample Dockerfile.vulnerable not found")
        findings = DockerfileParser(sample_path).analyze()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


class TestSecureDockerfile:
    """Integration test against the sample secure Dockerfile."""

    @pytest.fixture
    def sample_path(self):
        return os.path.join(os.path.dirname(__file__), "..", "samples", "Dockerfile.secure")

    def test_minimal_findings(self, sample_path):
        if not os.path.exists(sample_path):
            pytest.skip("Sample Dockerfile.secure not found")
        findings = DockerfileParser(sample_path).analyze()
        # Secure Dockerfile should have zero CRITICAL/HIGH
        severe = [f for f in findings if f.severity.weight >= 4]
        assert len(severe) == 0
