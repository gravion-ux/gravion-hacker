"""HTTP security header audit from supplied header text."""

from __future__ import annotations

from .findings import Finding

_REQUIRED = {
    "strict-transport-security": ("high", "Add Strict-Transport-Security with a long max-age and includeSubDomains."),
    "content-security-policy": (
        "medium",
        "Add a restrictive Content-Security-Policy; avoid unsafe-inline where possible.",
    ),
    "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("low", "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin."),
    "permissions-policy": ("low", "Set Permissions-Policy to disable unused browser features."),
}


def parse_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        if name:
            headers[name] = value.strip()
    return headers


def audit_headers(text: str) -> list[Finding]:
    headers = parse_headers(text)
    findings: list[Finding] = []
    for name, (severity, fix) in _REQUIRED.items():
        if name not in headers:
            findings.append(Finding("headers", f"Missing {name} header", severity, f"{name} not present", fix))
    csp = headers.get("content-security-policy", "")
    if "unsafe-inline" in csp:
        findings.append(
            Finding(
                "headers",
                "CSP allows unsafe-inline",
                "medium",
                "Content-Security-Policy contains unsafe-inline",
                "Remove unsafe-inline; use nonces or hashes.",
            )
        )
    if "unsafe-eval" in csp:
        findings.append(
            Finding(
                "headers",
                "CSP allows unsafe-eval",
                "medium",
                "Content-Security-Policy contains unsafe-eval",
                "Remove unsafe-eval and refactor eval-like code.",
            )
        )
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        findings.append(
            Finding(
                "headers",
                "Missing clickjacking protection",
                "medium",
                "No X-Frame-Options and no CSP frame-ancestors",
                "Set X-Frame-Options or CSP frame-ancestors.",
            )
        )
    server = headers.get("server", "")
    if any(ch.isdigit() for ch in server):
        findings.append(
            Finding(
                "headers",
                "Server header discloses version",
                "low",
                f"Server: {server}",
                "Remove version details from the Server header.",
            )
        )
    return findings
