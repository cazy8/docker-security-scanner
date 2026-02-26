"""
Tests for the secret detection module.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.secret_patterns import (
    shannon_entropy,
    is_high_entropy_string,
    scan_line_for_secrets,
)


class TestShannonEntropy:
    """Test the entropy calculation."""

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        entropy = shannon_entropy("aB3$kL9mNz2pQw8x")
        assert entropy > 3.5

    def test_low_entropy(self):
        entropy = shannon_entropy("aaabbbccc")
        assert entropy < 2.0


class TestSecretPatterns:
    """Test regex-based secret detection."""

    def test_aws_key(self):
        matches = scan_line_for_secrets("ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        assert any("AWS" in m for m in matches)

    def test_github_token(self):
        matches = scan_line_for_secrets("ENV TOKEN=ghp_EXAMPLETOKEN000000000000000000000000")
        assert any("GitHub" in m for m in matches)

    def test_generic_password(self):
        matches = scan_line_for_secrets("ENV PASSWORD=MySuper$ecretP4ss!")
        assert len(matches) >= 1

    def test_clean_line(self):
        matches = scan_line_for_secrets("ENV APP_NAME=myapp")
        assert len(matches) == 0

    def test_connection_string(self):
        matches = scan_line_for_secrets("ENV DB_URL=postgres://admin:secret@localhost:5432/db")
        assert len(matches) >= 1


class TestHighEntropy:
    """Test entropy-based secret detection."""

    def test_obvious_secret(self):
        assert is_high_entropy_string("wJalrXUtnFEMI7MDENGK") is True

    def test_normal_value(self):
        assert is_high_entropy_string("myapp") is False

    def test_short_string(self):
        assert is_high_entropy_string("abc") is False

    def test_url_not_flagged(self):
        assert is_high_entropy_string("https://example.com/api/v1") is False

    def test_path_not_flagged(self):
        assert is_high_entropy_string("/usr/local/bin/python") is False
