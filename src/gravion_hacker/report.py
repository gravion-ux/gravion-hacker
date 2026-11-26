"""Report generation: executive + technical JSON/Markdown export."""

from __future__ import annotations

import json

from .correlate import correlate_findings
from .findings import Finding, severity_counts

ETHICAL_NOTE = (
    "Use this tool only ethically and lawfully, on systems you own or are "
    "explicitly authorized to test. Any misuse is solely the responsibility "
    "of the person using it."
)


def _executive_summary(findings: list[Finding]) -> dict:
    counts = severity_counts(findings)
    top = findings[0] if findings else None
    return {
        "total_findings": len(findings),
        "severity_counts": counts,
        "highest_priority": top.title if top else "No findings from the supplied local data.",
        "recommended_next_step": (
            "Fix critical/high items first, validate manually inside the authorized scope, "
            "then re-run the same local checks."
            if findings
            else "Keep the supplied controls in place and re-check after changes."
        ),
    }


def bug_bounty_sections(findings: list[Finding], *, scope_name: str = "local-lab") -> list[dict]:
    sections = []
    for finding in findings[:10]:
        sections.append(
            {
                "title": finding.title,
                "scope": scope_name,
                "severity": finding.severity,
                "summary": f"{finding.title} was identified from authorized local evidence.",
                "evidence": finding.evidence,
                "impact": "Validate impact manually inside the authorized scope before submission.",
                "remediation": finding.remediation,
                "submission_note": "Draft only — review manually, dedupe, and submit yourself if valid.",
            }
        )
    return sections


def build_report(
    findings: list[Finding],
    *,
    scope_name: str = "local-lab",
    tool: str = "Gravion Hacker",
    authorization: dict | None = None,
    performance: dict | None = None,
) -> dict:
    ordered = correlate_findings(list(findings))
    return {
        "tool": tool,
        "scope": scope_name,
        "ethical_use": ETHICAL_NOTE,
        "authorization": authorization or {"scope_name": scope_name, "recorded": False},
        "executive_summary": _executive_summary(ordered),
        "summary": severity_counts(ordered),
        "performance": performance or {},
        "findings": [f.to_dict() for f in ordered],
        "bug_bounty_draft_sections": bug_bounty_sections(ordered, scope_name=scope_name),
    }


def report_json(
    findings: list[Finding],
    *,
    scope_name: str = "local-lab",
    authorization: dict | None = None,
    performance: dict | None = None,
) -> str:
    return json.dumps(
        build_report(findings, scope_name=scope_name, authorization=authorization, performance=performance), indent=2
    )


def report_markdown(
    findings: list[Finding],
    *,
    scope_name: str = "local-lab",
    authorization: dict | None = None,
    performance: dict | None = None,
) -> str:
    report = build_report(findings, scope_name=scope_name, authorization=authorization, performance=performance)
    summary = report["executive_summary"]
    lines = [
        "# Gravion Hacker — Security Assessment Report",
        "",
        f"**Scope:** {scope_name}",
        "",
        f"> {ETHICAL_NOTE}",
        "",
        "## Executive summary",
        "",
        f"- Total findings: {summary['total_findings']}",
        f"- Highest priority: {summary['highest_priority']}",
        f"- Recommended next step: {summary['recommended_next_step']}",
        "",
        "## Authorization record",
        "",
        f"- Scope name: {report['authorization'].get('scope_name', scope_name)}",
        f"- Recorded: {report['authorization'].get('recorded', False)}",
        "",
        "## Severity summary",
        "",
    ]
    for severity, count in report["summary"].items():
        lines.append(f"- {severity}: {count}")
    if performance:
        lines += [
            "",
            "## Performance",
            "",
            f"- Preset: {performance.get('preset', '')}",
            f"- Elapsed ms: {performance.get('elapsed_ms', '')}",
        ]
        cache = performance.get("cache") or {}
        if cache:
            lines.append(f"- Cache hits/misses: {cache.get('hits', 0)}/{cache.get('misses', 0)}")
    lines += ["", "## Technical findings", ""]
    if not report["findings"]:
        lines.append("No findings from the supplied local data.")
    for item in report["findings"]:
        lines += [
            f"### [{item['severity'].upper()}] {item['title']}",
            "",
            f"- Module: {item['module']}",
            f"- Score: {item['score']} · Confidence: {item['confidence']} · Priority: {item['priority']}",
            f"- Sources: {', '.join(item['sources'])}",
            f"- Remediation effort: {item['remediation_effort']}",
            f"- Evidence: {item['evidence']}",
            f"- Remediation: {item['remediation']}",
            "",
        ]
    lines += ["## Copy-ready bug bounty draft sections", ""]
    if not report["bug_bounty_draft_sections"]:
        lines.append("No draft sections generated.")
    for section in report["bug_bounty_draft_sections"]:
        lines += [
            f"### {section['title']}",
            "",
            f"**Summary:** {section['summary']}",
            "",
            f"**Evidence:** {section['evidence']}",
            "",
            f"**Impact:** {section['impact']}",
            "",
            f"**Remediation:** {section['remediation']}",
            "",
            f"_{section['submission_note']}_",
            "",
        ]
    return "\n".join(lines)
