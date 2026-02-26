"""
Secret detection patterns for Docker Security Scanner.

Uses a combination of:
  1. Known regex patterns for specific providers (AWS, GitHub, Slack, etc.)
  2. Generic high-entropy string detection (Shannon entropy)
  3. Common password variable name patterns
"""

import re
import math
from typing import List, Tuple


# ── Provider-Specific Secret Patterns ────────────────────────────────────────
# Each tuple: (pattern_name, compiled_regex)

SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # AWS
    (
        "AWS Access Key ID",
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
    ),
    (
        "AWS Secret Access Key",
        re.compile(r"""(?:aws)?_?(?:secret)?_?(?:access)?_?key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", re.IGNORECASE),
    ),
    # GitHub
    (
        "GitHub Personal Access Token",
        re.compile(r"ghp_[A-Za-z0-9]{36}", re.IGNORECASE),
    ),
    (
        "GitHub OAuth Access Token",
        re.compile(r"gho_[A-Za-z0-9]{36}", re.IGNORECASE),
    ),
    # Slack
    (
        "Slack Bot Token",
        re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", re.IGNORECASE),
    ),
    (
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", re.IGNORECASE),
    ),
    # Google
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}", re.IGNORECASE),
    ),
    # Stripe
    (
        "Stripe Secret Key",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}", re.IGNORECASE),
    ),
    (
        "Stripe Publishable Key",
        re.compile(r"pk_live_[0-9a-zA-Z]{24,}", re.IGNORECASE),
    ),
    # Generic Private Keys
    (
        "RSA/SSH Private Key",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", re.IGNORECASE),
    ),
    # Generic password assignments
    (
        "Generic Password Assignment",
        re.compile(
            r"""(?:password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?token|access[_-]?key)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?""",
            re.IGNORECASE,
        ),
    ),
    # Database connection strings
    (
        "Database Connection String",
        re.compile(
            r"""(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s'"]+:[^\s'"]+@""",
            re.IGNORECASE,
        ),
    ),
    # JWT tokens
    (
        "JSON Web Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    ),
]


# ── Entropy-Based Detection ──────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    High-entropy strings (> 4.5 for hex, > 4.0 for base64) are likely
    to be secrets, keys, or tokens rather than natural language.

    Args:
        data: The string to analyze.

    Returns:
        Shannon entropy value (bits per character).
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    char_counts: dict[str, int] = {}

    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1

    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


# Character sets for entropy analysis
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

# Entropy thresholds
HEX_ENTROPY_THRESHOLD = 3.0
BASE64_ENTROPY_THRESHOLD = 4.0


def is_high_entropy_string(value: str) -> bool:
    """
    Check if a string has suspiciously high entropy (likely a secret).

    Args:
        value: The string to check.

    Returns:
        True if the string's entropy exceeds thresholds for its character set.
    """
    if len(value) < 8:
        return False

    # Skip obvious non-secrets
    skip_prefixes = ("http://", "https://", "/usr", "/bin", "/etc", "/var", "/app")
    if value.lower().startswith(skip_prefixes):
        return False

    # Check hex strings
    hex_part = "".join(c for c in value if c in HEX_CHARS)
    if len(hex_part) >= 16 and shannon_entropy(hex_part) > HEX_ENTROPY_THRESHOLD:
        return True

    # Check base64 strings
    b64_part = "".join(c for c in value if c in BASE64_CHARS)
    if len(b64_part) >= 16 and shannon_entropy(b64_part) > BASE64_ENTROPY_THRESHOLD:
        return True

    return False


def scan_line_for_secrets(line: str) -> List[str]:
    """
    Scan a single line of text for potential secrets.

    Args:
        line: A line from a Dockerfile or config file.

    Returns:
        List of matched pattern names.
    """
    matches = []

    for pattern_name, regex in SECRET_PATTERNS:
        if regex.search(line):
            matches.append(pattern_name)

    return matches
