<img src="assets/banner.svg" alt="Gravion Hacker" width="100%"/>

# ⚔️ Gravion Hacker

**A–Z authorized security assessment suite — offline-first, evidence-driven, report-ready.**

By **Priyanshu Kumar Thakur**.

> ## Ethical use — read this first
>
> Use this tool only ethically and lawfully, on systems you own or are explicitly authorized to test.
> Any misuse is solely the responsibility of the person using it.
>
> Gravion Hacker is built for authorized security testing: your own systems, your local lab, and
> in-scope bug bounty programs where you hold explicit permission. It deliberately contains **no exploit
> payloads, no authentication bypass, no brute force or credential attacks, no malware, no evasion
> features and no aggressive third-party scanning**. Its power comes from coverage, automation,
> evidence quality, scoring and reporting inside an authorized scope.

## Why it exists

Professional red-team and bug bounty work is mostly disciplined assessment: inventory the scope,
check the basics everywhere, collect clean evidence, score honestly, and write a report a triager can
act on. Gravion Hacker packages that workflow into one offline-first suite with a CLI and a web UI.

## Safety model (built in, not bolted on)

- **Offline/local by default.** Analysers work on data you supply: pasted headers, uploaded snapshots,
  local files, synthetic lab data.
- **Authorization gate.** Scope records must name the scope, owner and targets and carry an explicit
  authorization confirmation. The web UI keeps the URL field locked until that gate is satisfied, and
  even then it performs no scanning — you paste headers captured from your own authorized session.
  Importing tool outputs that describe live targets also requires an explicit authorization confirmation.
- **Read-only checks only.** Headers, cookie flags, CORS policy, TLS/DNS snapshots, JWT structure,
  dependency manifests, local source review, password policy.
- **Redacted evidence.** Secret findings never print the secret itself.
- **Manual submission.** Bug bounty helpers produce checklists and drafts only. Nothing auto-submits.

## Smarter and faster than single-purpose tools

Single-purpose tools stop at raw output. Gravion Hacker adds a local intelligence layer on top of
authorized data you already have:

- **Parallel local engine** with deterministic ordering and per-module timing.
- **Content-hash cache** so repeat scans of unchanged files/snapshots return near-instantly.
- **Authorized-output importers** for Nuclei JSONL, ffuf JSON, Gobuster text, Nikto text/JSON and
  sqlmap text summaries. Importers only parse supplied output; they never execute those tools.
- **Smart correlation** that merges duplicates, boosts confidence when sources corroborate, and
  prioritises by severity, confidence, exploitability context and remediation effort.
- **Presets**: Quick, Full A–Z and Report-only imports in the CLI and web UI.
- **One-click reports**: executive summary + technical findings + copy-ready bug bounty draft
  sections in Markdown/JSON, always carrying the ethical-use note and scope record.

Synthetic local benchmark (headers/source sample only, this machine): first run **5.674 ms**,
cached runs **3.401–4.680 ms**, 52 correlated findings, cache 15 hits / 5 misses. Re-run with
`gravion-hacker benchmark`; numbers vary by machine and input size.

## AI mode

- **Built-in offline assistant**: deterministic local helper that explains findings, suggests next
  authorized checks and drafts report sections from local findings. It never calls the network.
- **BYO API mode**: generic endpoint + model + key fields with no third-party brand names. Keys stay
  only in browser local storage, a local config outside git, or environment variables — **never
  commit keys**. AI mode only analyses local findings/text you provide; it must not run attacks or
  bypass scope gates.

## Hacker pet

The web UI includes an animated hacker pet (orb guardian, fox scout and bot buddy styles) with idle
float/blink, scan pulse, alert and celebrate states driven by finding severity. It is lightweight,
offline and family-friendly.

## Modules (A–Z coverage)

| Area | Module | What it checks |
| --- | --- | --- |
| Scope | Asset & authorization record | Scope name, owner, targets, explicit authorization gate |
| Web | HTTP headers audit | HSTS, CSP weaknesses, clickjacking, version disclosure |
| Web | Cookie audit | Secure, HttpOnly, SameSite, SameSite=None misuse |
| Web | CORS audit | Wildcard origin, wildcard + credentials, missing Vary |
| Crypto | TLS/certificate snapshot | Weak protocols, expiry, SAN coverage, self-signed |
| DNS | DNS snapshot audit | SPF, DMARC, DKIM presence, dangling CNAME hints |
| Auth | JWT offline audit | alg=none, expiry, missing claims, sensitive claims (decode only) |
| Secrets | Local secret scan | Keys/tokens/private keys — redacted findings only |
| Supply chain | Manifest audit | package.json, requirements.txt, pyproject.toml pinning risks |
| Code | Source risky-pattern review | eval/exec, unsafe deserialization, shell=True, SQL formatting, TLS-off |
| Auth | Password policy checker | Length, MFA, breached-password screening, rate limiting |
| Reporting | Report generator | Executive + technical JSON/Markdown export, priority/confidence, bounty drafts |
| Intelligence | Engine + cache + correlation | Parallel local analysis, hash cache, dedupe/corroboration, timing |
| Imports | Authorized-output importers | Nuclei, ffuf, Gobuster, Nikto, sqlmap output parsing (never executed) |
| AI | Offline assistant + BYO mode | Local explanations/next checks/drafts; generic endpoint/model/key config |
| Workflow | Bug bounty helpers | Scope checklist, dedupe checklist, 7-question gate, report draft template |

## Quick start

### Web UI (static, offline-friendly)

```bash
cd web
python3 -m http.server 8000
# open http://localhost:8000
```

Paste headers/JWT/local text into a module card and run the check locally in your browser.
Export findings as JSON or Markdown.

### CLI

```bash
pip install -e .
gravion-hacker --help
gravion-hacker headers --file examples/headers-sample.txt
gravion-hacker --format markdown headers --file examples/headers-sample.txt
gravion-hacker authorize --file examples/authorization-sample.json
gravion-hacker checklists
gravion-hacker analyze --preset quick --headers-file examples/headers-sample.txt --format markdown
gravion-hacker import --tool nuclei --file authorized-output.jsonl --authorized-confirm
gravion-hacker benchmark
gravion-hacker ai explain --file report.json
gravion-hacker ai config-check
```

Without installing:

```bash
PYTHONPATH=src python3 -m gravion_hacker.cli headers --file examples/headers-sample.txt
```

## Examples (synthetic lab data only)

`examples/headers-sample.txt` contains synthetic headers that intentionally miss security controls,
so the header/cookie/CORS analysers produce findings. `examples/authorization-sample.json` shows a
complete local-lab authorization record. `examples/password-policy-sample.json` shows a strong policy.

## Tests

```bash
python3 -m unittest discover -s tests -v
node --test web/tests/web.test.mjs
```

## Project layout

```text
src/gravion_hacker/   Python analysers, scoring, reporting, CLI
web/                      Static web UI (no network calls)
tests/                    Python test suite
examples/                 Synthetic lab samples
```

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Priyanshu Kumar Thakur.
