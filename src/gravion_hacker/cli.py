"""CLI for local file/snapshot checks. Offline by design; no network calls."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .ai_assistant import ByoAiConfig, build_byo_prompt, draft_report_section, explain_findings, next_authorized_checks
from .bounty import DEDUPE_CHECKLIST, SCOPE_CHECKLIST, SEVEN_QUESTION_GATE
from .cache import AnalysisCache
from .cookies import audit_cookies
from .correlate import correlate_findings
from .cors import audit_cors
from .engine import PRESETS, LocalAnalysisEngine, benchmark_json
from .findings import Finding
from .headers import audit_headers
from .importers import import_output
from .jwt_audit import audit_jwt
from .manifests import audit_manifest
from .password_policy import audit_password_policy
from .report import ETHICAL_NOTE, report_json, report_markdown
from .scope import AuthorizationRecord, require_authorization
from .secrets import scan_secrets
from .source_audit import audit_source
from .tls_dns import audit_dns_snapshot, audit_tls_snapshot


def _read(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    return sys.stdin.read()


def _emit(
    findings: list[Finding], fmt: str, scope: str, *, performance: dict | None = None, authorized: bool = False
) -> int:
    authorization = {"scope_name": scope, "recorded": authorized}
    correlated = correlate_findings(findings)
    if fmt == "json":
        print(report_json(correlated, scope_name=scope, authorization=authorization, performance=performance))
    elif fmt == "markdown":
        print(report_markdown(correlated, scope_name=scope, authorization=authorization, performance=performance))
    else:
        for finding in correlated:
            print(
                f"[{finding.severity}] {finding.module}: {finding.title} "
                f"(priority {finding.priority}, confidence {finding.confidence}) — {finding.evidence}"
            )
        if not correlated:
            print("No findings from the supplied local data.")
        if performance:
            print(
                f"Timing: {performance.get('elapsed_ms')} ms · preset {performance.get('preset')} · "
                f"cache {performance.get('cache')}",
                file=sys.stderr,
            )
    return 0


def _require_import_authorization(args: argparse.Namespace) -> int | None:
    if not getattr(args, "authorized_confirm", False):
        print(
            "Imported tool outputs can describe live targets. Re-run with --authorized-confirm only for outputs "
            "from systems you own or are explicitly authorized to test.",
            file=sys.stderr,
        )
        return 2
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gravion-hacker",
        description=f"Authorized, offline-first security assessment suite. {ETHICAL_NOTE}",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--scope", default="local-lab", help="Scope/authorization record name for the report")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("headers", "cookies", "cors", "tls", "dns", "secrets", "source"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--file", help="Local file to analyse (default: stdin)")

    jwt_cmd = sub.add_parser("jwt")
    jwt_cmd.add_argument("token", help="JWT to decode and audit offline")

    manifest_cmd = sub.add_parser("manifest")
    manifest_cmd.add_argument("--file", required=True, help="package.json / requirements.txt / pyproject.toml")

    policy_cmd = sub.add_parser("password-policy")
    policy_cmd.add_argument("--file", required=True, help="JSON policy file")

    import_cmd = sub.add_parser("import", help="Import an authorized tool output you already generated")
    import_cmd.add_argument("--tool", choices=("auto", "nuclei", "ffuf", "gobuster", "nikto", "sqlmap"), default="auto")
    import_cmd.add_argument("--file", required=True, help="Local output file to parse (never executed)")
    import_cmd.add_argument(
        "--authorized-confirm", action="store_true", help="Confirm the output is from an authorized scope"
    )

    analyze_cmd = sub.add_parser("analyze", help="Run a fast parallel local preset")
    analyze_cmd.add_argument("--preset", choices=tuple(PRESETS), default="quick")
    analyze_cmd.add_argument("--workers", type=int, default=4)
    analyze_cmd.add_argument("--cache-file", help="Optional JSON cache file for repeat scans")
    analyze_cmd.add_argument("--headers-file")
    analyze_cmd.add_argument("--cookies-file")
    analyze_cmd.add_argument("--cors-file")
    analyze_cmd.add_argument("--tls-file")
    analyze_cmd.add_argument("--dns-file")
    analyze_cmd.add_argument("--secrets-file")
    analyze_cmd.add_argument("--source-file")
    analyze_cmd.add_argument("--jwt-token")
    analyze_cmd.add_argument("--manifest-file")
    analyze_cmd.add_argument("--password-policy-file")
    analyze_cmd.add_argument(
        "--import", dest="imports", action="append", default=[], help="tool:path or path (repeatable)"
    )
    analyze_cmd.add_argument("--authorized-confirm", action="store_true", help="Required when importing tool outputs")

    ai_cmd = sub.add_parser("ai", help="Offline/BYO AI assistance for local findings only")
    ai_sub = ai_cmd.add_subparsers(dest="ai_command", required=True)
    ai_explain = ai_sub.add_parser("explain", help="Explain findings from a Gravion Hacker JSON report offline")
    ai_explain.add_argument("--file", required=True, help="JSON report file")
    ai_draft = ai_sub.add_parser("draft", help="Draft report sections from a JSON report offline")
    ai_draft.add_argument("--file", required=True, help="JSON report file")
    ai_prompt = ai_sub.add_parser("prompt", help="Build a BYO prompt from local findings (no key included)")
    ai_prompt.add_argument("--file", required=True, help="JSON report file")
    ai_prompt.add_argument("--question", default="Explain these findings and suggest next authorized checks.")
    ai_sub.add_parser(
        "config-check", help="Validate GRAVION_AI_ENDPOINT/GRAVION_AI_MODEL/GRAVION_AI_KEY without printing the key"
    )

    sub.add_parser("benchmark", help="Run the synthetic local benchmark")
    sub.add_parser("checklists", help="Print scope, dedupe and 7-question gate checklists")

    auth_cmd = sub.add_parser("authorize", help="Validate an authorization record JSON file")
    auth_cmd.add_argument("--file", required=True)
    return parser


def _parse_import_spec(spec: str) -> tuple[str, str]:
    if ":" in spec and not Path(spec).exists():
        tool, path = spec.split(":", 1)
        return tool, path
    return "auto", spec


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command
    if command == "checklists":
        print("Scope checklist:")
        for item in SCOPE_CHECKLIST:
            print(f"- {item}")
        print("\nDedupe checklist:")
        for item in DEDUPE_CHECKLIST:
            print(f"- {item}")
        print("\n7-question gate:")
        for item in SEVEN_QUESTION_GATE:
            print(f"- {item}")
        return 0
    if command == "benchmark":
        print(benchmark_json())
        return 0
    if command == "ai":
        if args.ai_command == "config-check":
            config = ByoAiConfig.from_env()
            problems = config.validate()
            print(json.dumps({"config": config.redacted(), "problems": problems}, indent=2))
            return 2 if problems else 0
        data = json.loads(_read(args.file))
        findings = [
            Finding(
                module=str(row.get("module", "report")),
                title=str(row.get("title", "Finding")),
                severity=str(row.get("severity", "info")),
                evidence=str(row.get("evidence", "")),
                remediation=str(row.get("remediation", "")),
                score=float(row.get("score", 0.0) or 0.0),
                confidence=float(row.get("confidence", 0.6) or 0.6),
                sources=list(row.get("sources", [])),
            )
            for row in data.get("findings", [])
            if isinstance(row, dict)
        ]
        if args.ai_command == "explain":
            print(explain_findings(findings))
            print("\nNext authorized checks:")
            for item in next_authorized_checks(findings):
                print(f"- {item}")
            return 0
        if args.ai_command == "draft":
            for finding in findings[:10]:
                print(draft_report_section(finding, scope_name=args.scope))
                print("\n---\n")
            return 0
        if args.ai_command == "prompt":
            print(json.dumps(build_byo_prompt(findings, scope_name=args.scope, question=args.question), indent=2))
            return 0
    if command == "authorize":
        data = json.loads(_read(args.file))
        record = AuthorizationRecord(
            scope_name=str(data.get("scope_name", "")),
            owner=str(data.get("owner", "")),
            targets=list(data.get("targets", [])),
            authorized=bool(data.get("authorized", False)),
            notes=str(data.get("notes", "")),
        )
        try:
            require_authorization(record)
        except PermissionError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print("Authorization record is complete for the declared scope.")
        return 0
    if command == "import":
        blocked = _require_import_authorization(args)
        if blocked is not None:
            return blocked
        return _emit(import_output(_read(args.file), args.tool), args.format, args.scope, authorized=True)
    if command == "analyze":
        imports: list[tuple[str, str]] = []
        if args.imports:
            blocked = _require_import_authorization(args)
            if blocked is not None:
                return blocked
            for spec in args.imports:
                tool, path = _parse_import_spec(spec)
                imports.append((tool, _read(path)))
        texts = {
            "headers": _read(args.headers_file) if args.headers_file else "",
            "cookies": _read(args.cookies_file) if args.cookies_file else "",
            "cors": _read(args.cors_file) if args.cors_file else "",
            "tls": _read(args.tls_file) if args.tls_file else "",
            "dns": _read(args.dns_file) if args.dns_file else "",
            "secrets": _read(args.secrets_file) if args.secrets_file else "",
            "source": _read(args.source_file) if args.source_file else "",
            "jwt": args.jwt_token or "",
        }
        cache = AnalysisCache(Path(args.cache_file) if args.cache_file else None)
        engine = LocalAnalysisEngine(cache=cache, workers=args.workers)
        result = engine.analyse_bundle(
            texts=texts,
            manifest_name=Path(args.manifest_file).name if args.manifest_file else "",
            manifest_text=_read(args.manifest_file) if args.manifest_file else "",
            password_policy=json.loads(_read(args.password_policy_file)) if args.password_policy_file else None,
            imports=imports,
            preset=args.preset,
        )
        return _emit(
            result.findings, args.format, args.scope, performance=result.performance(), authorized=bool(imports)
        )
    if command == "jwt":
        return _emit(audit_jwt(args.token), args.format, args.scope)
    if command == "manifest":
        return _emit(audit_manifest(args.file, _read(args.file)), args.format, args.scope)
    if command == "password-policy":
        return _emit(audit_password_policy(json.loads(_read(args.file))), args.format, args.scope)

    text = _read(args.file)
    analysers = {
        "headers": audit_headers,
        "cookies": audit_cookies,
        "cors": audit_cors,
        "tls": audit_tls_snapshot,
        "dns": audit_dns_snapshot,
        "secrets": scan_secrets,
        "source": audit_source,
    }
    return _emit(analysers[command](text), args.format, args.scope)


if __name__ == "__main__":
    raise SystemExit(main())
