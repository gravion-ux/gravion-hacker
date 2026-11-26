"""Local secret scanning with redacted findings only."""

from __future__ import annotations

import re

from .findings import Finding

_PATTERNS = [
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Bearer token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
    (
        "Generic API key assignment",
        re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    ),
    ("JWT-shaped token", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
]


def redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:3]}***{value[-2:]} (len {len(value)})"


def scan_secrets(text: str, *, source: str = "input") -> list[Finding]:
    findings: list[Finding] = []
    for label, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    "secrets",
                    f"Possible secret: {label}",
                    "high",
                    f"{source}: {redact(match.group(0))}",
                    "Remove the secret from source, rotate it, and load it from a secret manager.",
                )
            )
    return findings
