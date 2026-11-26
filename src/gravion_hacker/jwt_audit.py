"""Offline JWT audit. Decodes only; never cracks or forges tokens."""

from __future__ import annotations

import base64
import json
import time

from .findings import Finding


def _b64url_decode(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(segment + padding)
    return json.loads(raw.decode("utf-8"))


def decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three segments")
    return _b64url_decode(parts[0]), _b64url_decode(parts[1])


def audit_jwt(token: str, *, now: int | None = None) -> list[Finding]:
    findings: list[Finding] = []
    try:
        header, payload = decode_jwt(token)
    except Exception as exc:  # noqa: BLE001 - report parse failure as finding
        return [
            Finding(
                "jwt",
                "JWT could not be decoded",
                "info",
                str(exc),
                "Provide a valid three-segment JWT for offline review.",
            )
        ]
    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        findings.append(
            Finding(
                "jwt",
                "JWT uses alg=none or missing alg",
                "critical",
                f"alg={header.get('alg')}",
                "Reject alg=none; require a strong signing algorithm.",
            )
        )
    if alg.startswith("hs"):
        findings.append(
            Finding(
                "jwt",
                "JWT uses HMAC signing",
                "low",
                f"alg={header.get('alg')}",
                "Ensure the HMAC secret is long, random and rotated; prefer asymmetric signing.",
            )
        )
    current = int(time.time()) if now is None else now
    exp = payload.get("exp")
    if exp is None:
        findings.append(
            Finding(
                "jwt",
                "JWT has no expiry",
                "medium",
                "exp claim missing",
                "Set a short exp claim and enforce it server-side.",
            )
        )
    elif isinstance(exp, (int, float)) and exp < current:
        findings.append(
            Finding(
                "jwt",
                "JWT is expired",
                "info",
                f"exp={int(exp)}",
                "Expired tokens must be rejected; issue a fresh token after re-authentication.",
            )
        )
    for claim in ("iss", "aud", "sub"):
        if claim not in payload:
            findings.append(
                Finding(
                    "jwt",
                    f"JWT missing {claim} claim",
                    "low",
                    f"{claim} claim missing",
                    f"Include and validate the {claim} claim.",
                )
            )
    sensitive = [key for key in payload if key.lower() in ("password", "secret", "token", "ssn", "card")]
    if sensitive:
        findings.append(
            Finding(
                "jwt",
                "JWT payload contains sensitive-looking claims",
                "high",
                f"claims: {', '.join(sorted(sensitive))}",
                "Remove secrets and sensitive personal data from JWT payloads.",
            )
        )
    return findings
