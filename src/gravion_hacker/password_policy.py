"""Password policy strength checker (policy review only, no cracking)."""

from __future__ import annotations

from .findings import Finding


def audit_password_policy(policy: dict) -> list[Finding]:
    findings: list[Finding] = []
    min_length = int(policy.get("min_length", 0) or 0)
    if min_length < 12:
        findings.append(
            Finding(
                "password-policy",
                "Minimum length below 12",
                "medium",
                f"min_length={min_length}",
                "Require at least 12 characters; encourage passphrases.",
            )
        )
    if not policy.get("allow_passphrases", False):
        findings.append(
            Finding(
                "password-policy",
                "Passphrases not explicitly allowed",
                "low",
                "allow_passphrases=false",
                "Allow long passphrases and spaces.",
            )
        )
    if not policy.get("breached_password_check", False):
        findings.append(
            Finding(
                "password-policy",
                "No breached-password screening",
                "medium",
                "breached_password_check=false",
                "Screen new passwords against known breached corpora.",
            )
        )
    if not policy.get("mfa_available", False):
        findings.append(
            Finding(
                "password-policy",
                "MFA not available",
                "high",
                "mfa_available=false",
                "Offer MFA, preferably phishing-resistant options.",
            )
        )
    if policy.get("forced_rotation_days"):
        findings.append(
            Finding(
                "password-policy",
                "Forced periodic rotation",
                "low",
                f"forced_rotation_days={policy['forced_rotation_days']}",
                "Rotate on evidence of compromise rather than on a fixed schedule.",
            )
        )
    if not policy.get("rate_limiting", False):
        findings.append(
            Finding(
                "password-policy",
                "No login rate limiting declared",
                "high",
                "rate_limiting=false",
                "Rate-limit and monitor authentication attempts.",
            )
        )
    return findings


def password_strength_hint(password: str) -> dict:
    """Rough local strength hint for a user-typed sample; stores nothing."""
    checks = {
        "length_12_plus": len(password) >= 12,
        "has_lower": any(ch.islower() for ch in password),
        "has_upper": any(ch.isupper() for ch in password),
        "has_digit": any(ch.isdigit() for ch in password),
        "has_symbol": any(not ch.isalnum() for ch in password),
    }
    score = sum(checks.values())
    label = "weak" if score <= 2 else "fair" if score <= 3 else "strong"
    return {"score": score, "label": label, "checks": checks}
