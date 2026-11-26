"""Smart correlation: dedupe, corroboration confidence and prioritisation."""

from __future__ import annotations

import re
from collections import OrderedDict

from .findings import SEVERITIES, Finding, sort_findings

_SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}
_EFFORT_PENALTY = {"low": 0.0, "medium": 0.25, "high": 0.6}


def _normalise(text: str) -> str:
    text = re.sub(r"https?://\S+", "url", text.lower())
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "ip", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def _key(finding: Finding) -> str:
    title = _normalise(finding.title)
    evidence = _normalise(finding.evidence)
    # Evidence is often noisy across tools; the normalised title is the stable
    # correlation anchor, with a short evidence prefix to avoid over-merging.
    return f"{title}|{evidence[:80]}"


def _effort_for(finding: Finding) -> str:
    haystack = f"{finding.module} {finding.title} {finding.remediation}".lower()
    if any(word in haystack for word in ("header", "cookie", "samesite", "httponly", "secure flag", "csp")):
        return "low"
    if any(word in haystack for word in ("rotate", "upgrade", "migration", "architecture", "redesign")):
        return "high"
    return finding.remediation_effort or "medium"


def _context_boost(finding: Finding) -> float:
    haystack = f"{finding.title} {finding.evidence}".lower()
    boost = 0.0
    if any(word in haystack for word in ("unauthenticated", "public", "internet", "exposed", "remote")):
        boost += 0.7
    if any(word in haystack for word in ("credential", "secret", "token", "password", "session")):
        boost += 0.5
    if any(word in haystack for word in ("admin", "privilege", "authorization", "idor", "bola")):
        boost += 0.5
    if "requires auth" in haystack or "authenticated" in haystack:
        boost -= 0.4
    return boost


def _priority(finding: Finding) -> float:
    effort = _EFFORT_PENALTY.get(finding.remediation_effort, 0.25)
    value = float(finding.score) * float(finding.confidence) + _context_boost(finding) - effort
    return round(max(0.0, min(10.0, value)), 2)


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    """Merge duplicates and rank by severity, confidence, context and effort."""
    merged: OrderedDict[str, Finding] = OrderedDict()
    for finding in findings:
        finding.remediation_effort = _effort_for(finding)
        key = _key(finding)
        if key not in merged:
            finding.priority = _priority(finding)
            merged[key] = finding
            continue
        existing = merged[key]
        sources = list(dict.fromkeys([*existing.sources, *finding.sources, existing.module, finding.module]))
        existing.sources = sources
        if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[existing.severity]:
            existing.severity = finding.severity
        existing.score = max(float(existing.score), float(finding.score))
        corroboration = 0.15 * max(0, len(sources) - 1)
        existing.confidence = round(min(0.98, max(existing.confidence, finding.confidence) + corroboration), 2)
        evidences = []
        for item in (existing.evidence, finding.evidence):
            if item and item not in evidences:
                evidences.append(item)
        existing.evidence = " | ".join(evidences)[:600]
        if len(finding.remediation) > len(existing.remediation):
            existing.remediation = finding.remediation
        existing.references = list(dict.fromkeys([*existing.references, *finding.references]))
        existing.remediation_effort = _effort_for(existing)
        existing.priority = _priority(existing)
    return sort_findings(list(merged.values()))
