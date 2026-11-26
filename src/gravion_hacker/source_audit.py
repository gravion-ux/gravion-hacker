"""Defensive source-code risky-pattern review for local files."""

from __future__ import annotations

import re

from .findings import Finding
from .secrets import scan_secrets

_PATTERNS = [
    (
        "eval/exec usage",
        re.compile(r"\b(?:eval|exec)\s*\("),
        "high",
        "Avoid eval/exec on untrusted input; use safe parsers.",
    ),
    (
        "Unsafe deserialization",
        re.compile(
            r"\b(?:pickle\.loads?|yaml\.load\s*\((?![^)]*Loader\s*=\s*SafeLoader)|marshal\.loads?|unserialize\s*\()"
        ),
        "high",
        "Never deserialize untrusted data with unsafe loaders.",
    ),
    (
        "Shell command execution",
        re.compile(
            r"\b(?:os\.system|subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True|child_process\.exec\s*\()"
        ),
        "medium",
        "Avoid shell=True; pass argument arrays and validate input.",
    ),
    (
        "SQL string formatting",
        re.compile(r"(?i)(?:execute|query)\s*\(\s*(?:f['\"]|['\"][^'\"]*%s|['\"][^'\"]*\+)"),
        "high",
        "Use parameterized queries; never build SQL by string formatting.",
    ),
    (
        "innerHTML assignment",
        re.compile(r"\.innerHTML\s*="),
        "medium",
        "Prefer textContent or a sanitizer to prevent XSS.",
    ),
    (
        "Disabled TLS verification",
        re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false"),
        "high",
        "Never disable TLS certificate verification in production.",
    ),
    (
        "Weak hash for security",
        re.compile(r"\b(?:md5|sha1)\s*\("),
        "low",
        "Use SHA-256+ for integrity and a password KDF for passwords.",
    ),
    ("Debug mode enabled", re.compile(r"(?i)debug\s*[:=]\s*(?:true|1)"), "medium", "Disable debug mode in production."),
]


def audit_source(text: str, *, source: str = "input") -> list[Finding]:
    findings: list[Finding] = []
    for label, pattern, severity, fix in _PATTERNS:
        for match in pattern.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            findings.append(Finding("source", label, severity, f"{source}:{line_no}", fix))
    findings.extend(scan_secrets(text, source=source))
    return findings
