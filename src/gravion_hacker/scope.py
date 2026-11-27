"""Scope inventory and authorization record helpers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AuthorizationRecord:
    scope_name: str
    owner: str
    targets: list[str] = field(default_factory=list)
    authorized: bool = False
    notes: str = ""

    def validate(self) -> list[str]:
        problems: list[str] = []
        if not self.scope_name.strip():
            problems.append("scope name is required")
        if not self.owner.strip():
            problems.append("asset owner is required")
        if not [t for t in self.targets if str(t).strip()]:
            problems.append("at least one in-scope target is required")
        if not self.authorized:
            problems.append("explicit authorization confirmation is required")
        return problems

    def to_dict(self) -> dict:
        return {
            "scope_name": self.scope_name,
            "owner": self.owner,
            "targets": list(self.targets),
            "authorized": self.authorized,
            "notes": self.notes,
        }


def require_authorization(record: AuthorizationRecord) -> None:
    problems = record.validate()
    if problems:
        raise PermissionError("Authorization gate: " + "; ".join(problems))
