"""Fast parallel local analysis engine with deterministic ordering and timing."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .cache import AnalysisCache
from .cookies import audit_cookies
from .correlate import correlate_findings
from .cors import audit_cors
from .findings import Finding
from .headers import audit_headers
from .importers import import_output
from .jwt_audit import audit_jwt
from .manifests import audit_manifest
from .password_policy import audit_password_policy
from .secrets import scan_secrets
from .source_audit import audit_source
from .tls_dns import audit_dns_snapshot, audit_tls_snapshot

Analyser = Callable[[str], list[Finding]]

TEXT_ANALYSERS: dict[str, Analyser] = {
    "headers": audit_headers,
    "cookies": audit_cookies,
    "cors": audit_cors,
    "tls": audit_tls_snapshot,
    "dns": audit_dns_snapshot,
    "jwt": audit_jwt,
    "secrets": scan_secrets,
    "source": audit_source,
}

PRESETS: dict[str, tuple[str, ...]] = {
    "quick": ("headers", "cookies", "cors", "jwt", "secrets"),
    "full": (
        "headers",
        "cookies",
        "cors",
        "tls",
        "dns",
        "jwt",
        "secrets",
        "source",
        "manifest",
        "password-policy",
        "imports",
    ),
    "report-only": ("imports",),
}


@dataclass
class AnalysisResult:
    findings: list[Finding]
    timings_ms: dict[str, float] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    cache_stats: dict[str, int] = field(default_factory=dict)
    preset: str = "full"
    modules_run: list[str] = field(default_factory=list)

    def performance(self) -> dict:
        return {
            "preset": self.preset,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "modules_run": list(self.modules_run),
            "timings_ms": {key: round(value, 3) for key, value in sorted(self.timings_ms.items())},
            "cache": dict(self.cache_stats),
        }


class LocalAnalysisEngine:
    """Runs independent local analysers in parallel; output order is deterministic."""

    def __init__(self, *, cache: AnalysisCache | None = None, workers: int = 4) -> None:
        self.cache = cache or AnalysisCache()
        self.workers = max(1, workers)

    def _run_one(self, name: str, content: str) -> tuple[str, list[Finding], float]:
        cached = self.cache.get(name, content)
        if cached is not None:
            return name, cached, 0.0
        start = time.perf_counter()
        findings = TEXT_ANALYSERS[name](content)
        elapsed = (time.perf_counter() - start) * 1000
        self.cache.put(name, content, findings)
        return name, findings, elapsed

    def analyse_texts(self, inputs: dict[str, str], *, preset: str = "full") -> AnalysisResult:
        if preset not in PRESETS:
            raise ValueError(f"unknown preset: {preset}")
        started = time.perf_counter()
        wanted = [name for name in PRESETS[preset] if name in TEXT_ANALYSERS and inputs.get(name)]
        results: dict[str, list[Finding]] = {}
        timings: dict[str, float] = {}
        if wanted:
            with ThreadPoolExecutor(max_workers=min(self.workers, len(wanted))) as pool:
                futures = {pool.submit(self._run_one, name, inputs[name]): name for name in wanted}
                for future in as_completed(futures):
                    name, findings, elapsed = future.result()
                    results[name] = findings
                    timings[name] = elapsed
        ordered: list[Finding] = []
        for name in wanted:  # preset order, not completion order: deterministic output
            ordered.extend(results.get(name, []))
        correlated = correlate_findings(ordered)
        return AnalysisResult(
            findings=correlated,
            timings_ms=timings,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            cache_stats=self.cache.stats(),
            preset=preset,
            modules_run=wanted,
        )

    def analyse_bundle(
        self,
        *,
        texts: dict[str, str] | None = None,
        manifest_name: str = "",
        manifest_text: str = "",
        password_policy: dict | None = None,
        imports: list[tuple[str, str]] | None = None,
        preset: str = "full",
    ) -> AnalysisResult:
        started = time.perf_counter()
        result = self.analyse_texts(texts or {}, preset=preset)
        extra: list[Finding] = []
        timings = dict(result.timings_ms)
        modules = list(result.modules_run)
        if preset == "full" and manifest_text:
            start = time.perf_counter()
            extra.extend(audit_manifest(manifest_name or "package.json", manifest_text))
            timings["manifest"] = (time.perf_counter() - start) * 1000
            modules.append("manifest")
        if preset == "full" and password_policy is not None:
            start = time.perf_counter()
            extra.extend(audit_password_policy(password_policy))
            timings["password-policy"] = (time.perf_counter() - start) * 1000
            modules.append("password-policy")
        if preset in {"full", "report-only"} and imports:
            start = time.perf_counter()
            for tool, content in imports:
                extra.extend(import_output(content, tool))
            timings["imports"] = (time.perf_counter() - start) * 1000
            modules.append("imports")
        findings = correlate_findings([*result.findings, *extra])
        return AnalysisResult(
            findings=findings,
            timings_ms=timings,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            cache_stats=self.cache.stats(),
            preset=preset,
            modules_run=modules,
        )


def benchmark_synthetic(repeats: int = 3) -> dict:
    """Honest local benchmark on synthetic data only."""
    headers = "Server: Demo/1.0\nSet-Cookie: session=synthetic; Path=/\nAccess-Control-Allow-Origin: *\n"
    source = "eval(user_input)\npassword = 'synthetic-secret-value'\n" * 40
    engine = LocalAnalysisEngine(workers=4)
    first = engine.analyse_texts(
        {"headers": headers, "cookies": headers, "cors": headers, "source": source, "secrets": source}, preset="full"
    )
    cached_runs = []
    for _ in range(max(1, repeats)):
        cached_runs.append(
            engine.analyse_texts(
                {"headers": headers, "cookies": headers, "cors": headers, "source": source, "secrets": source},
                preset="full",
            ).elapsed_ms
        )
    return {
        "data": "synthetic local headers/source only",
        "first_run_ms": round(first.elapsed_ms, 3),
        "cached_run_ms_min": round(min(cached_runs), 3),
        "cached_run_ms_max": round(max(cached_runs), 3),
        "findings": len(first.findings),
        "cache": engine.cache.stats(),
    }


def benchmark_json() -> str:
    return json.dumps(benchmark_synthetic(), indent=2)
