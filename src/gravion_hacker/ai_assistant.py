"""AI assistance modes for local findings only.

Built-in mode is deterministic and offline. BYO mode prepares a generic
endpoint/model/key configuration and a local-findings prompt; it never runs
attacks, never bypasses scope gates, and never includes keys in reports.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .findings import Finding, severity_counts
from .report import ETHICAL_NOTE

AI_SAFETY_NOTE = (
    "AI mode only analyses local findings/text you provide. It does not run attacks, "
    "does not contact targets, and does not bypass authorization or scope gates."
)
KEY_WARNING = (
    "Never commit API keys. Keep keys only in local browser storage, "
    "a local config file outside git, or environment variables."
)


@dataclass
class ByoAiConfig:
    endpoint: str = ""
    model: str = ""
    api_key: str = ""

    @classmethod
    def from_env(cls) -> ByoAiConfig:
        return cls(
            endpoint=os.environ.get("GRAVION_AI_ENDPOINT", ""),
            model=os.environ.get("GRAVION_AI_MODEL", ""),
            api_key=os.environ.get("GRAVION_AI_KEY", ""),
        )

    def validate(self) -> list[str]:
        problems: list[str] = []
        if not self.endpoint:
            problems.append("endpoint is required")
        elif not (
            self.endpoint.startswith("https://")
            or self.endpoint.startswith("http://localhost")
            or self.endpoint.startswith("http://127.0.0.1")
        ):
            problems.append("endpoint must use https:// or a localhost http:// address")
        if not self.model:
            problems.append("model is required")
        if not self.api_key:
            problems.append("api key is required (set GRAVION_AI_KEY locally; never commit it)")
        return problems

    def redacted(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "model": self.model,
            "api_key": "***" if self.api_key else "",
            "warning": KEY_WARNING,
        }


def explain_findings(findings: list[Finding]) -> str:
    counts = severity_counts(findings)
    if not findings:
        return "No findings were supplied. Keep current controls in place and re-check after changes."
    top = findings[0]
    lines = [
        "Offline assistant summary",
        f"- Findings: {len(findings)} (critical {counts['critical']}, high {counts['high']}, "
        f"medium {counts['medium']}, low {counts['low']}, info {counts['info']})",
        f"- Start with: [{top.severity}] {top.title}",
        f"- Why it matters: evidence is '{top.evidence}'. Validate impact manually inside the authorized scope.",
        f"- Fix first: {top.remediation}",
        "- Next authorized checks: re-run the same local preset after fixes, confirm scope/dedupe, "
        "and keep evidence minimal and redacted.",
    ]
    return "\n".join(lines)


def next_authorized_checks(findings: list[Finding]) -> list[str]:
    checks = ["Re-read scope, exclusions and rate limits before any further testing."]
    modules = {f.module for f in findings}
    if any("headers" in m or "cookies" in m or "cors" in m for m in modules):
        checks.append("Re-capture headers from your own authorized session after fixes and re-run Quick preset.")
    if any("secrets" in m for m in modules):
        checks.append("Rotate any exposed secret locally, remove it from history/config, then re-scan the local files.")
    if any("jwt" in m for m in modules):
        checks.append("Use only your own test-account tokens and verify expiry/claims after the auth fix.")
    if any(m.startswith("import:") for m in modules):
        checks.append(
            "Manually validate imported findings inside scope; do not re-run external tools outside authorization."
        )
    checks.append("Export the executive + technical report and keep submission manual.")
    return checks


def draft_report_section(finding: Finding, *, scope_name: str = "local-lab") -> str:
    return "\n".join(
        [
            f"Title: {finding.title}",
            f"Scope: {scope_name}",
            f"Severity: {finding.severity}",
            f"Summary: {finding.title} was identified from authorized local evidence.",
            f"Evidence: {finding.evidence}",
            "Impact: Validate impact manually inside the authorized scope before submission.",
            f"Remediation: {finding.remediation}",
            "Submission note: Draft only — review manually, dedupe, and submit yourself if valid.",
        ]
    )


def build_byo_prompt(
    findings: list[Finding],
    *,
    scope_name: str = "local-lab",
    question: str = "Explain these findings and suggest next authorized checks.",
) -> dict:
    """Build a generic BYO request payload from local findings only (no key inside)."""
    local_text = "\n".join(f"- [{f.severity}] {f.title}: {f.evidence} | Fix: {f.remediation}" for f in findings[:25])
    return {
        "system": f"You are assisting with authorized security assessment reporting. {ETHICAL_NOTE} {AI_SAFETY_NOTE}",
        "user": f"Scope: {scope_name}\nQuestion: {question}\nLocal findings:\n{local_text or 'No findings supplied.'}",
        "safety": AI_SAFETY_NOTE,
    }
