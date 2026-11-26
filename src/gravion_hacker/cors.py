"""CORS policy audit from supplied headers."""

from __future__ import annotations

from .findings import Finding
from .headers import parse_headers


def audit_cors(text: str) -> list[Finding]:
    headers = parse_headers(text)
    findings: list[Finding] = []
    origin = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").lower()
    if origin == "*" and credentials == "true":
        findings.append(
            Finding(
                "cors",
                "Wildcard CORS with credentials",
                "high",
                "Access-Control-Allow-Origin: * with credentials enabled",
                "Never combine wildcard origin with credentials; allow-list exact origins.",
            )
        )
    elif origin == "*":
        findings.append(
            Finding(
                "cors",
                "Wildcard CORS origin",
                "low",
                "Access-Control-Allow-Origin: *",
                "Restrict CORS to trusted origins if the API returns sensitive data.",
            )
        )
    if origin and origin != "*" and "access-control-allow-origin" in headers and "vary" not in headers:
        findings.append(
            Finding(
                "cors",
                "CORS response missing Vary: Origin",
                "low",
                "Specific CORS origin without Vary header",
                "Add Vary: Origin to prevent cache confusion.",
            )
        )
    methods = headers.get("access-control-allow-methods", "")
    if "delete" in methods.lower() and origin == "*":
        findings.append(
            Finding(
                "cors",
                "Wildcard CORS allows DELETE",
                "medium",
                "DELETE allowed for wildcard origin",
                "Limit methods per origin and require authorization checks server-side.",
            )
        )
    return findings
