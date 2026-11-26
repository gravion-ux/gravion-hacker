# Changelog

## 1.1.0 — 2026-11-26

- Renamed the product to Gravion Hacker (folder, package, CLI, README and web branding).
- Smarter/faster local intelligence: parallel analysis engine with deterministic ordering and timing,
  content-hash incremental cache, Quick/Full A–Z/Report-only presets.
- Authorized-output importers for Nuclei JSONL, ffuf JSON, Gobuster text, Nikto text/JSON and sqlmap
  text summaries; importers parse supplied output only and never execute external tools.
- Smart correlation: duplicate merging, corroboration confidence, priority by severity/confidence/
  context/remediation effort; executive + technical Markdown/JSON reports with bounty draft sections.
- AI mode: built-in offline assistant plus generic BYO endpoint/model/key mode for local findings only,
  with key-safety warnings and no scope-gate bypass.
- Premium web UI: animated hero, glass/3D-tilt cards, live-feeling scan console, severity visuals,
  filters, report export and an animated hacker pet reacting to scan states.
- Tests: 35 Python tests and 10 web tests passing; ruff clean. Synthetic benchmark: first run
  5.674 ms, cached runs 3.401–4.680 ms on the local sample.

## 1.0.0 — 2026-11-26

- Initial release of Gravion Hacker by Priyanshu Kumar Thakur.
- Offline-first A–Z authorized assessment modules: scope/authorization gate, HTTP headers, cookies,
  CORS, TLS/DNS snapshots, JWT audit, redacted secret scan, dependency manifests, source review,
  password policy, CVSS-style scoring, JSON/Markdown reporting.
- Bug bounty workflow helpers: scope checklist, dedupe checklist, 7-question gate, manual report drafts.
- Static web UI with authorization gate, severity badges and report export.
- CLI (`gravion-hacker`) for local file/snapshot checks.
- Full Python and web test suites; SHA-pinned CI.
