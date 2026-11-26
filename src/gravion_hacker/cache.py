"""Incremental content-hash cache for repeat local analyses."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding

CACHE_VERSION = "2"


def content_key(analyser: str, content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    return f"{CACHE_VERSION}:{analyser}:{digest}"


@dataclass
class AnalysisCache:
    """In-memory cache with optional JSON persistence.

    Cache keys are SHA-256 hashes of the exact supplied content plus the analyser
    name, so unchanged files/snapshots return instantly and changed content is
    always re-analysed.
    """

    path: Path | None = None
    _store: dict[str, list[dict]] = field(default_factory=dict)
    hits: int = 0
    misses: int = 0

    def __post_init__(self) -> None:
        if self.path and self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._store = {str(k): list(v) for k, v in data.items() if isinstance(v, list)}
            except (OSError, json.JSONDecodeError):
                self._store = {}

    def get(self, analyser: str, content: str) -> list[Finding] | None:
        key = content_key(analyser, content)
        rows = self._store.get(key)
        if rows is None:
            self.misses += 1
            return None
        self.hits += 1
        return [_finding_from_dict(row) for row in rows]

    def put(self, analyser: str, content: str, findings: list[Finding]) -> None:
        self._store[content_key(analyser, content)] = [f.to_dict() for f in findings]
        self.save()

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._store, indent=2, sort_keys=True), encoding="utf-8")

    def stats(self) -> dict[str, int]:
        return {"hits": self.hits, "misses": self.misses, "entries": len(self._store)}


def _finding_from_dict(row: dict) -> Finding:
    return Finding(
        module=str(row.get("module", "cache")),
        title=str(row.get("title", "Cached finding")),
        severity=str(row.get("severity", "info")),
        evidence=str(row.get("evidence", "")),
        remediation=str(row.get("remediation", "")),
        score=float(row.get("score", 0.0) or 0.0),
        references=list(row.get("references", [])),
        confidence=float(row.get("confidence", 0.6) or 0.6),
        sources=list(row.get("sources", [])),
        priority=float(row.get("priority", 0.0) or 0.0),
        remediation_effort=str(row.get("remediation_effort", "medium")),
    )
