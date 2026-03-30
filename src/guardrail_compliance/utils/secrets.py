from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------
# Each entry is (human-readable name, compiled pattern).
# Patterns deliberately avoid false positives on Terraform variable references
# like ${var.password} or template expressions.

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS access key IDs (AKIA…, ABIA…, ACCA…, ASIA…)
    (
        "AWS access key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    # AWS secret access keys (40-char base64 after common key labels)
    (
        "AWS secret access key",
        re.compile(
            r"(?i)aws[_\-\s.]*secret[_\-\s.]*(?:access[_\-\s.]*)?key[_\-\s]*[=:\"'\s]+(?!\$\{)[A-Za-z0-9/+=]{40}"
        ),
    ),
    # PEM private keys
    (
        "private key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    # Generic high-entropy password assignments (skip Terraform interpolations)
    (
        "password value",
        re.compile(
            r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"']?(?!\$\{)(?![\"']\s*$)[^\s\"'$]{8,}[\"']?"
        ),
    ),
    # API / auth tokens
    (
        "API token",
        re.compile(
            r"(?i)(?:api[_\-]?(?:key|token)|auth[_\-]?token|access[_\-]?token)\s*[=:]\s*[\"']?(?!\$\{)[A-Za-z0-9\-._~+/]{20,}[\"']?"
        ),
    ),
]

_REDACTED = "[REDACTED]"


def redact_secrets(text: str) -> tuple[str, list[str]]:
    """Scan *text* for known secret patterns and replace matches with ``[REDACTED]``.

    Returns ``(redacted_text, detected_types)`` where *detected_types* is a
    (possibly empty) list of human-readable names for the patterns that fired.
    """
    detected: list[str] = []
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            detected.append(name)
            text = pattern.sub(_REDACTED, text)
    return text, detected
