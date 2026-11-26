"""Importers for authorized tool outputs the user already generated elsewhere.

These parsers only read supplied output text/JSON. They never execute Gobuster,
ffuf, Nuclei, Nikto, sqlmap, curl or any other external tool, and they never
contact a target.
"""

from __future__ import annotations

import json
import re

from .findings import Finding

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}


def _severity(value: object, default: str = "info") -> str:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), default)


def _clip(text: object, limit: int = 320) -> str:
    value = " ".join(str(text or "").split())
    return value if len(value) <= limit else f"{value[: limit - 3]}..."


def _finding(tool: str, title: str, severity: str, evidence: str, remediation: str, confidence: float) -> Finding:
    return Finding(
        module=f"import:{tool}",
        title=_clip(title, 180) or f"{tool} finding",
        severity=severity,
        evidence=_clip(evidence),
        remediation=remediation,
        confidence=confidence,
        sources=[tool],
    )


def parse_nuclei_jsonl(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        title = info.get("name") or row.get("template-id") or row.get("templateID") or "Nuclei finding"
        severity = _severity(info.get("severity") or row.get("severity"), "info")
        target = row.get("matched-at") or row.get("host") or row.get("url") or ""
        evidence = f"{row.get('template-id') or row.get('templateID') or ''} {target}".strip()
        findings.append(
            _finding(
                "nuclei",
                str(title),
                severity,
                evidence or _clip(row),
                "Validate in the authorized scope, fix the root cause, then re-run the same template "
                "to confirm closure.",
                0.78,
            )
        )
    return findings


def parse_ffuf_json(text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows = data.get("results", []) if isinstance(data, dict) else []
    findings: list[Finding] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = row.get("url") or row.get("input") or "discovered path"
        status = row.get("status", "")
        severity = "medium" if str(status).startswith("2") else "info"
        findings.append(
            _finding(
                "ffuf",
                f"Discovered route returned HTTP {status}".strip(),
                severity,
                f"{url} status={status} length={row.get('length', '')}",
                "Confirm the route belongs in the authorized scope; remove or protect unintended exposed routes.",
                0.62,
            )
        )
    return findings


def parse_gobuster_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"^(\S+)\s+\(Status:\s*(\d{3})\)", re.MULTILINE)
    for path, status in pattern.findall(text):
        severity = "medium" if status.startswith("2") else "info"
        findings.append(
            _finding(
                "gobuster",
                f"Discovered path returned HTTP {status}",
                severity,
                f"{path} status={status}",
                "Confirm the path is intended and in scope; remove or protect unintended exposed content.",
                0.58,
            )
        )
    return findings


def parse_nikto(text: str) -> list[Finding]:
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            rows = data if isinstance(data, list) else data.get("vulnerabilities") or data.get("findings") or []
            findings = []
            for row in rows:
                if isinstance(row, dict):
                    title = row.get("msg") or row.get("message") or row.get("title") or "Nikto finding"
                    findings.append(
                        _finding(
                            "nikto",
                            str(title),
                            _severity(row.get("severity"), "low"),
                            str(row.get("url") or row.get("uri") or row.get("evidence") or ""),
                            "Validate manually in scope and apply the vendor/configuration fix.",
                            0.55,
                        )
                    )
            return findings
    findings = []
    for line in text.splitlines():
        clean = line.strip()
        if clean.startswith("+") and len(clean) > 3 and "Target" not in clean and "Start Time" not in clean:
            findings.append(
                _finding(
                    "nikto",
                    clean[1:].strip(),
                    "low",
                    clean,
                    "Validate manually in scope and apply the vendor/configuration fix.",
                    0.5,
                )
            )
    return findings


def parse_sqlmap_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lower = text.lower()
    if "is vulnerable" in lower or "sql injection" in lower:
        title = "Possible SQL injection reported by supplied sqlmap output"
        severity = "high" if "is vulnerable" in lower else "medium"
        evidence_lines = [
            line.strip() for line in text.splitlines() if "vulnerable" in line.lower() or "parameter" in line.lower()
        ]
        findings.append(
            _finding(
                "sqlmap",
                title,
                severity,
                " | ".join(evidence_lines[:3]) or "SQL injection indicator present in supplied output",
                "Use parameterized queries/prepared statements, validate manually with safe lab data, and retest.",
                0.72,
            )
        )
    if "back-end dbms" in lower:
        line = next((item.strip() for item in text.splitlines() if "back-end dbms" in item.lower()), "")
        findings.append(
            _finding(
                "sqlmap",
                "Database technology disclosed in supplied output",
                "info",
                line,
                "Avoid unnecessary technology disclosure in errors and banners.",
                0.65,
            )
        )
    return findings


def detect_import_format(text: str) -> str:
    stripped = text.strip()
    if '"template-id"' in text or '"matched-at"' in text:
        return "nuclei"
    if stripped.startswith("{") and '"results"' in text:
        return "ffuf"
    if "(Status:" in text:
        return "gobuster"
    if "sqlmap" in text.lower() or "back-end dbms" in text.lower():
        return "sqlmap"
    return "nikto"


def import_output(text: str, tool: str = "auto") -> list[Finding]:
    chosen = detect_import_format(text) if tool == "auto" else tool.lower()
    parsers = {
        "nuclei": parse_nuclei_jsonl,
        "ffuf": parse_ffuf_json,
        "gobuster": parse_gobuster_text,
        "nikto": parse_nikto,
        "sqlmap": parse_sqlmap_text,
    }
    if chosen not in parsers:
        raise ValueError(f"unknown import tool: {tool}")
    return parsers[chosen](text)
