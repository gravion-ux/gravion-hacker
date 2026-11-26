"""Dependency manifest audit for supplied manifest text."""

from __future__ import annotations

import json
import re

from .findings import Finding


def audit_package_json(text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [Finding("manifests", "package.json could not be parsed", "info", "invalid JSON", "Provide valid JSON.")]
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            version = str(version)
            if version in ("*", "latest"):
                findings.append(
                    Finding(
                        "manifests",
                        f"Unpinned dependency: {name}",
                        "medium",
                        f"{name}: {version}",
                        "Pin dependencies to exact versions and use a lockfile.",
                    )
                )
            elif version.startswith(("^", "~", ">", "<")):
                findings.append(
                    Finding(
                        "manifests",
                        f"Loose version range: {name}",
                        "low",
                        f"{name}: {version}",
                        "Prefer exact pins with a committed lockfile for reproducible builds.",
                    )
                )
            if "git+" in version or "http" in version:
                findings.append(
                    Finding(
                        "manifests",
                        f"Dependency from URL/VCS: {name}",
                        "medium",
                        f"{name}: {version}",
                        "Prefer registry releases with integrity hashes.",
                    )
                )
    return findings


def audit_requirements(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "==" not in stripped:
            findings.append(
                Finding(
                    "manifests",
                    "Unpinned Python requirement",
                    "medium",
                    stripped,
                    "Pin with == and record hashes where possible.",
                )
            )
        if stripped.startswith(("http://", "git+")):
            findings.append(
                Finding(
                    "manifests", "Requirement from URL/VCS", "medium", stripped, "Prefer PyPI releases with hashes."
                )
            )
    return findings


def audit_pyproject(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r'"([A-Za-z0-9_.\-]+)([^"]*)"', text):
        name, spec = match.group(1), match.group(2)
        if name.lower() in ("name", "version", "description"):
            continue
        if spec and "==" not in spec and any(op in spec for op in (">=", "<=", "~=", ">", "<")):
            findings.append(
                Finding(
                    "manifests",
                    f"Loose Python dependency range: {name}",
                    "low",
                    f"{name}{spec}",
                    "Consider exact pins or a lockfile for applications.",
                )
            )
    return findings


def audit_manifest(filename: str, text: str) -> list[Finding]:
    lower = filename.lower()
    if lower.endswith("package.json"):
        return audit_package_json(text)
    if lower.endswith("requirements.txt"):
        return audit_requirements(text)
    if lower.endswith("pyproject.toml"):
        return audit_pyproject(text)
    return [
        Finding(
            "manifests",
            "Unsupported manifest type",
            "info",
            filename,
            "Supported: package.json, requirements.txt, pyproject.toml.",
        )
    ]
