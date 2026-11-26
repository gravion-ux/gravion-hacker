"""TLS/certificate and DNS snapshot audits from supplied data only."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import Finding


def audit_tls_snapshot(text: str) -> list[Finding]:
    """Audit a supplied certificate summary (JSON or key: value text)."""
    findings: list[Finding] = []
    data: dict = {}
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            data = {str(k).lower(): v for k, v in parsed.items()}
    except json.JSONDecodeError:
        for line in text.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                data[key.strip().lower()] = value.strip()
    protocols = str(data.get("protocols", "")).lower()
    for weak in ("sslv3", "tls1.0", "tls 1.0", "tls1.1", "tls 1.1"):
        if weak in protocols:
            findings.append(
                Finding(
                    "tls",
                    f"Weak protocol enabled: {weak}",
                    "medium",
                    f"protocols include {weak}",
                    "Disable SSLv3/TLS 1.0/TLS 1.1; require TLS 1.2+.",
                )
            )
            break
    expiry = data.get("not_after") or data.get("expiry") or data.get("expires")
    if expiry:
        try:
            expiry_dt = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            days = (expiry_dt - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(
                    Finding(
                        "tls",
                        "Certificate expired",
                        "high",
                        f"not_after={expiry}",
                        "Renew the certificate immediately.",
                    )
                )
            elif days < 30:
                findings.append(
                    Finding(
                        "tls",
                        "Certificate expires soon",
                        "medium",
                        f"expires in {days} days",
                        "Renew the certificate before expiry and automate renewal.",
                    )
                )
        except ValueError:
            findings.append(
                Finding(
                    "tls",
                    "Certificate expiry could not be parsed",
                    "info",
                    f"expiry={expiry}",
                    "Provide expiry in ISO-8601 format for automated checks.",
                )
            )
    hostname = str(data.get("hostname", ""))
    sans = str(data.get("sans", "") or data.get("subject_alt_names", ""))
    if hostname and sans and hostname not in sans:
        findings.append(
            Finding(
                "tls",
                "Hostname not covered by certificate SANs",
                "high",
                f"hostname {hostname} not in SANs",
                "Issue a certificate covering every served hostname.",
            )
        )
    if str(data.get("self_signed", "")).lower() in ("true", "yes", "1"):
        findings.append(
            Finding(
                "tls",
                "Self-signed certificate",
                "medium",
                "self_signed=true",
                "Use a publicly trusted CA certificate for production.",
            )
        )
    return findings


def audit_dns_snapshot(text: str) -> list[Finding]:
    """Audit supplied DNS records text (one record per line)."""
    findings: list[Finding] = []
    upper = text.upper()
    if "SPF" not in upper and "V=SPF1" not in upper:
        findings.append(
            Finding(
                "dns",
                "No SPF record found in snapshot",
                "medium",
                "SPF record absent",
                "Publish an SPF record listing authorised senders.",
            )
        )
    if "DMARC" not in upper and "V=DMARC1" not in upper:
        findings.append(
            Finding(
                "dns",
                "No DMARC record found in snapshot",
                "medium",
                "DMARC record absent",
                "Publish a DMARC record, starting with p=none and moving to quarantine/reject.",
            )
        )
    if "DKIM" not in upper and "V=DKIM1" not in upper:
        findings.append(
            Finding(
                "dns",
                "No DKIM record found in snapshot",
                "low",
                "DKIM record absent",
                "Enable DKIM signing for outbound mail.",
            )
        )
    for line in text.splitlines():
        if "CNAME" in line.upper() and any(
            word in line.lower() for word in ("nxdomain", "not found", "dangling", "unclaimed")
        ):
            findings.append(
                Finding(
                    "dns",
                    "Possible dangling CNAME",
                    "high",
                    line.strip(),
                    "Remove or repoint CNAMEs whose targets no longer exist to prevent subdomain takeover.",
                )
            )
    return findings
