"""Finding model and severity scoring helpers."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")

_SEVERITY_BASE = {"info": 0.0, "low": 3.0, "medium": 5.5, "high": 7.5, "critical": 9.0}
_SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    module: str
    title: str
    severity: str
    evidence: str
    remediation: str
    score: float = 0.0
    references: list[str] = field(default_factory=list)
    confidence: float = 0.6
    sources: list[str] = field(default_factory=list)
    priority: float = 0.0
    remediation_effort: str = "medium"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity}")
        if not self.score:
            self.score = _SEVERITY_BASE[self.severity]
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if not self.sources:
            self.sources = [self.module]
        if not self.priority:
            self.priority = round(float(self.score) * self.confidence, 2)

    @property
    def severity_rank(self) -> int:
        return _SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "title": self.title,
            "severity": self.severity,
            "score": round(float(self.score), 1),
            "confidence": round(float(self.confidence), 2),
            "priority": round(float(self.priority), 2),
            "remediation_effort": self.remediation_effort,
            "sources": list(dict.fromkeys(self.sources)),
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
        }


def cvss_style_score(
    severity: str,
    *,
    network_reachable: bool = False,
    requires_auth: bool = False,
    user_interaction: bool = False,
    data_impact: bool = False,
) -> float:
    """Small CVSS-style helper for triage (not an official CVSS calculator)."""
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity: {severity}")
    score = _SEVERITY_BASE[severity]
    if network_reachable:
        score += 0.6
    if data_impact:
        score += 0.6
    if requires_auth:
        score -= 0.7
    if user_interaction:
        score -= 0.5
    return round(max(0.0, min(10.0, score)), 1)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic priority ordering: priority, severity, score, module, title."""
    return sorted(
        findings,
        key=lambda f: (-f.priority, -f.severity_rank, -f.score, f.module.lower(), f.title.lower(), f.evidence.lower()),
    )
