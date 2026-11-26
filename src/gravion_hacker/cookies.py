"""Cookie flag audit from supplied Set-Cookie header text."""

from __future__ import annotations

from .findings import Finding


def _cookie_lines(text: str) -> list[str]:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("set-cookie:"):
            lines.append(stripped.split(":", 1)[1].strip())
        elif "=" in stripped and ";" in stripped:
            lines.append(stripped)
    return lines


def audit_cookies(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for cookie in _cookie_lines(text):
        name = cookie.split("=", 1)[0].strip() or "cookie"
        lower = cookie.lower()
        if "secure" not in lower:
            findings.append(
                Finding(
                    "cookies",
                    f"Cookie {name} missing Secure",
                    "medium",
                    f"{name} has no Secure attribute",
                    "Add Secure so the cookie is sent only over HTTPS.",
                )
            )
        if "httponly" not in lower:
            findings.append(
                Finding(
                    "cookies",
                    f"Cookie {name} missing HttpOnly",
                    "medium",
                    f"{name} has no HttpOnly attribute",
                    "Add HttpOnly for session/auth cookies.",
                )
            )
        if "samesite" not in lower:
            findings.append(
                Finding(
                    "cookies",
                    f"Cookie {name} missing SameSite",
                    "low",
                    f"{name} has no SameSite attribute",
                    "Set SameSite=Lax or Strict as appropriate.",
                )
            )
        if "samesite=none" in lower and "secure" not in lower:
            findings.append(
                Finding(
                    "cookies",
                    f"Cookie {name} uses SameSite=None without Secure",
                    "high",
                    f"{name} combines SameSite=None with no Secure",
                    "SameSite=None cookies must also be Secure.",
                )
            )
    return findings
