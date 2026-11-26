"use strict";
/* Gravion Hacker — offline browser analysers. No network calls. */

const ETHICAL_NOTE =
  "Use this tool only ethically and lawfully, on systems you own or are explicitly authorized to test. " +
  "Any misuse is solely the responsibility of the person using it.";

let findings = [];
let lastTimingMs = 0;
const SEVERITY_SCORE = { info: 0, low: 3, medium: 5.5, high: 7.5, critical: 9 };
const PRESETS = {
  quick: ["headers", "cookies", "jwt", "secrets"],
  full: ["headers", "cookies", "jwt", "secrets", "password", "imports"],
  "report-only": ["imports"],
};

function withScore(finding) {
  const score = SEVERITY_SCORE[finding.severity] ?? 0;
  const confidence = finding.confidence ?? 0.6;
  return { ...finding, score, confidence, sources: finding.sources || [finding.module], priority: Math.round(score * confidence * 100) / 100 };
}

function correlateFindings(input) {
  const merged = new Map();
  for (const raw of input.map(withScore)) {
    const key = `${raw.title.toLowerCase()}|${String(raw.evidence || "").toLowerCase().slice(0, 80)}`;
    if (!merged.has(key)) {
      merged.set(key, raw);
      continue;
    }
    const existing = merged.get(key);
    existing.sources = [...new Set([...(existing.sources || []), ...(raw.sources || []), existing.module, raw.module])];
    if ((SEVERITY_SCORE[raw.severity] || 0) > (SEVERITY_SCORE[existing.severity] || 0)) existing.severity = raw.severity;
    existing.score = Math.max(existing.score || 0, raw.score || 0);
    existing.confidence = Math.min(0.98, Math.max(existing.confidence || 0.6, raw.confidence || 0.6) + 0.15 * Math.max(0, existing.sources.length - 1));
    existing.priority = Math.round(existing.score * existing.confidence * 100) / 100;
    if (raw.evidence && !existing.evidence.includes(raw.evidence)) existing.evidence = `${existing.evidence} | ${raw.evidence}`.slice(0, 600);
  }
  return [...merged.values()].sort((a, b) => (b.priority - a.priority) || a.module.localeCompare(b.module) || a.title.localeCompare(b.title));
}

function parseNucleiJsonl(text) {
  const out = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line);
      const info = row.info || {};
      out.push(withScore({ module: "import:nuclei", title: info.name || row["template-id"] || "Nuclei finding", severity: info.severity || "info", evidence: `${row["template-id"] || ""} ${row["matched-at"] || row.host || ""}`.trim(), remediation: "Validate in the authorized scope, fix the root cause, then re-run the same template.", confidence: 0.78, sources: ["nuclei"] }));
    } catch (err) {
      // Ignore malformed lines in pasted authorized output.
    }
  }
  return out;
}

function parseImportedOutput(text) {
  const trimmed = String(text || "").trim();
  if (trimmed.includes('"template-id"') || trimmed.includes('"matched-at"')) return parseNucleiJsonl(trimmed);
  try {
    const data = JSON.parse(trimmed);
    if (Array.isArray(data.results)) {
      return data.results.map((row) => withScore({ module: "import:ffuf", title: `Discovered route returned HTTP ${row.status || ""}`.trim(), severity: String(row.status || "").startsWith("2") ? "medium" : "info", evidence: `${row.url || ""} status=${row.status || ""}`, remediation: "Confirm the route belongs in the authorized scope; remove or protect unintended exposed routes.", confidence: 0.62, sources: ["ffuf"] }));
    }
  } catch (err) {
    // Fall through to text parsers.
  }
  const out = [];
  for (const match of trimmed.matchAll(/^(\S+)\s+\(Status:\s*(\d{3})\)/gm)) {
    out.push(withScore({ module: "import:gobuster", title: `Discovered path returned HTTP ${match[2]}`, severity: match[2].startsWith("2") ? "medium" : "info", evidence: `${match[1]} status=${match[2]}`, remediation: "Confirm the path is intended and in scope; remove or protect unintended exposed content.", confidence: 0.58, sources: ["gobuster"] }));
  }
  if (/is vulnerable|sql injection/i.test(trimmed)) {
    out.push(withScore({ module: "import:sqlmap", title: "Possible SQL injection reported by supplied sqlmap output", severity: /is vulnerable/i.test(trimmed) ? "high" : "medium", evidence: "SQL injection indicator present in supplied output", remediation: "Use parameterized queries/prepared statements, validate manually with safe lab data, and retest.", confidence: 0.72, sources: ["sqlmap"] }));
  }
  return out;
}

function petStateForFindings(input) {
  if (!input.length) return "celebrate";
  if (input.some((f) => f.severity === "critical" || f.severity === "high")) return "alert";
  return "scan";
}

function explainFindingsOffline(input) {
  if (!input.length) return "No findings supplied. Keep current controls in place and re-check after changes.";
  const counts = input.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {});
  const top = input[0];
  return [
    "Offline assistant summary",
    `- Findings: ${input.length} (critical ${counts.critical || 0}, high ${counts.high || 0}, medium ${counts.medium || 0}, low ${counts.low || 0}, info ${counts.info || 0})`,
    `- Start with: [${top.severity}] ${top.title}`,
    `- Why it matters: evidence is '${top.evidence}'. Validate impact manually inside the authorized scope.`,
    `- Fix first: ${top.remediation}`,
    "- Next authorized checks: re-run the same preset after fixes, confirm scope/dedupe, keep evidence minimal and redacted.",
  ].join("\n");
}

function buildByoPrompt(input, scope) {
  const localText = input.slice(0, 25).map((f) => `- [${f.severity}] ${f.title}: ${f.evidence} | Fix: ${f.remediation}`).join("\n");
  return {
    system: `You are assisting with authorized security assessment reporting. ${ETHICAL_NOTE} AI mode only analyses local findings/text provided; it does not run attacks or bypass scope gates.`,
    user: `Scope: ${scope}\nQuestion: Explain these findings and suggest next authorized checks.\nLocal findings:\n${localText || "No findings supplied."}`,
  };
}

function runPreset(preset, values) {
  const modules = PRESETS[preset] || PRESETS.quick;
  const started = performance.now();
  let out = [];
  if (modules.includes("headers")) out = out.concat(auditHeaders(values.headers || ""));
  if (modules.includes("cookies")) out = out.concat(auditCookiesCors(values.cookies || ""));
  if (modules.includes("jwt") && values.jwt) out = out.concat(auditJwt(values.jwt));
  if (modules.includes("secrets")) out = out.concat(scanSecrets(values.secrets || ""));
  if (modules.includes("password") && values.password) out = out.concat(auditPasswordPolicy(values.password));
  if (modules.includes("imports") && values.imports) out = out.concat(parseImportedOutput(values.imports));
  return { findings: correlateFindings(out), elapsedMs: performance.now() - started, modules };
}

function parseHeaders(text) {
  const headers = {};
  for (const line of String(text || "").split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx > 0) headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
  }
  return headers;
}

function auditHeaders(text) {
  const headers = parseHeaders(text);
  const out = [];
  const required = {
    "strict-transport-security": "high",
    "content-security-policy": "medium",
    "x-content-type-options": "low",
    "referrer-policy": "low",
    "permissions-policy": "low",
  };
  for (const [name, severity] of Object.entries(required)) {
    if (!headers[name]) out.push({ module: "headers", title: `Missing ${name} header`, severity, evidence: `${name} not present`, remediation: `Add the ${name} header.` });
  }
  const csp = headers["content-security-policy"] || "";
  if (csp.includes("unsafe-inline")) out.push({ module: "headers", title: "CSP allows unsafe-inline", severity: "medium", evidence: "CSP contains unsafe-inline", remediation: "Remove unsafe-inline; use nonces or hashes." });
  if (!headers["x-frame-options"] && !csp.includes("frame-ancestors")) out.push({ module: "headers", title: "Missing clickjacking protection", severity: "medium", evidence: "No X-Frame-Options / frame-ancestors", remediation: "Set X-Frame-Options or CSP frame-ancestors." });
  return out;
}

function auditCookiesCors(text) {
  const out = [];
  const headers = parseHeaders(text);
  for (const line of String(text || "").split(/\r?\n/)) {
    if (!line.toLowerCase().startsWith("set-cookie:")) continue;
    const cookie = line.split(":").slice(1).join(":");
    const name = cookie.split("=")[0].trim() || "cookie";
    const lower = cookie.toLowerCase();
    if (!lower.includes("secure")) out.push({ module: "cookies", title: `Cookie ${name} missing Secure`, severity: "medium", evidence: `${name} has no Secure`, remediation: "Add Secure." });
    if (!lower.includes("httponly")) out.push({ module: "cookies", title: `Cookie ${name} missing HttpOnly`, severity: "medium", evidence: `${name} has no HttpOnly`, remediation: "Add HttpOnly for session cookies." });
    if (!lower.includes("samesite")) out.push({ module: "cookies", title: `Cookie ${name} missing SameSite`, severity: "low", evidence: `${name} has no SameSite`, remediation: "Set SameSite=Lax or Strict." });
  }
  const origin = headers["access-control-allow-origin"] || "";
  const creds = (headers["access-control-allow-credentials"] || "").toLowerCase();
  if (origin === "*" && creds === "true") out.push({ module: "cors", title: "Wildcard CORS with credentials", severity: "high", evidence: "Origin * with credentials", remediation: "Allow-list exact origins; never combine * with credentials." });
  else if (origin === "*") out.push({ module: "cors", title: "Wildcard CORS origin", severity: "low", evidence: "Origin *", remediation: "Restrict CORS to trusted origins for sensitive APIs." });
  return out;
}

function decodeJwtPart(segment) {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (segment.length % 4)) % 4);
  return JSON.parse(atob(padded));
}

function auditJwt(token) {
  const out = [];
  const parts = String(token || "").trim().split(".");
  if (parts.length !== 3) return [{ module: "jwt", title: "JWT could not be decoded", severity: "info", evidence: "expected 3 segments", remediation: "Provide a valid JWT from your own test account." }];
  let header, payload;
  try {
    header = decodeJwtPart(parts[0]);
    payload = decodeJwtPart(parts[1]);
  } catch (err) {
    return [{ module: "jwt", title: "JWT could not be decoded", severity: "info", evidence: String(err), remediation: "Provide a valid JWT." }];
  }
  const alg = String(header.alg || "").toLowerCase();
  if (alg === "none" || alg === "") out.push({ module: "jwt", title: "JWT uses alg=none or missing alg", severity: "critical", evidence: `alg=${header.alg}`, remediation: "Reject alg=none; require strong signing." });
  if (!payload.exp) out.push({ module: "jwt", title: "JWT has no expiry", severity: "medium", evidence: "exp missing", remediation: "Set a short exp and enforce it." });
  for (const claim of ["iss", "aud", "sub"]) {
    if (!(claim in payload)) out.push({ module: "jwt", title: `JWT missing ${claim} claim`, severity: "low", evidence: `${claim} missing`, remediation: `Include and validate ${claim}.` });
  }
  return out;
}

function redact(value) {
  return value.length <= 8 ? "***" : `${value.slice(0, 3)}***${value.slice(-2)} (len ${value.length})`;
}

function scanSecrets(text) {
  const out = [];
  const patterns = [
    ["AWS access key id", /AKIA[0-9A-Z]{16}/g],
    ["Private key block", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
    ["Generic API key assignment", /(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"][^'"]{8,}['"]/gi],
    ["JWT-shaped token", /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
  ];
  for (const [label, pattern] of patterns) {
    for (const match of String(text || "").matchAll(pattern)) {
      out.push({ module: "secrets", title: `Possible secret: ${label}`, severity: "high", evidence: redact(match[0]), remediation: "Remove, rotate, and load from a secret manager." });
    }
  }
  return out;
}

function auditPasswordPolicy(policy) {
  const out = [];
  if ((policy.min_length || 0) < 12) out.push({ module: "password-policy", title: "Minimum length below 12", severity: "medium", evidence: `min_length=${policy.min_length}`, remediation: "Require at least 12 characters." });
  if (!policy.mfa_available) out.push({ module: "password-policy", title: "MFA not available", severity: "high", evidence: "mfa_available=false", remediation: "Offer MFA." });
  if (!policy.breached_password_check) out.push({ module: "password-policy", title: "No breached-password screening", severity: "medium", evidence: "breached_password_check=false", remediation: "Screen against breached corpora." });
  if (!policy.rate_limiting) out.push({ module: "password-policy", title: "No login rate limiting declared", severity: "high", evidence: "rate_limiting=false", remediation: "Rate-limit authentication attempts." });
  return out;
}

function filteredFindings() {
  const severityEl = document.getElementById("severity-filter");
  const moduleEl = document.getElementById("module-filter");
  const severity = severityEl ? severityEl.value : "all";
  const moduleName = moduleEl ? moduleEl.value : "all";
  return findings.filter((f) => (severity === "all" || f.severity === severity) && (moduleName === "all" || f.module === moduleName));
}

function updatePet(state) {
  const pet = document.getElementById("hacker-pet");
  const status = document.getElementById("pet-status");
  if (!pet) return;
  pet.classList.remove("scan", "alert", "celebrate");
  if (state !== "idle") pet.classList.add(state);
  if (status) {
    status.textContent = state === "alert" ? "Alert — high severity needs attention." : state === "celebrate" ? "Celebrating — no findings from supplied local data." : state === "scan" ? "Scanning local findings and correlating evidence." : "Idle — paste local data and run a preset.";
  }
}

function updateConsole(lines) {
  const box = document.getElementById("scan-console");
  if (box) box.innerHTML = `${lines.join("\n")}\n<span class="cursor"></span>`;
}

function renderSeverityBars() {
  const box = document.getElementById("severity-bars");
  if (!box) return;
  const counts = findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {});
  const max = Math.max(1, ...Object.values(counts));
  box.innerHTML = ["critical", "high", "medium", "low", "info"].map((sev) => {
    const count = counts[sev] || 0;
    return `<div class="sev-row"><span>${sev}</span><div class="sev-track"><div class="sev-fill sev-${sev}" style="width:${(count / max) * 100}%"></div></div><strong>${count}</strong></div>`;
  }).join("");
}

function render() {
  const box = document.getElementById("results");
  if (!box) return;
  const timing = document.getElementById("timing");
  if (timing) timing.textContent = findings.length ? `${findings.length} correlated finding(s) · last run ${lastTimingMs.toFixed(1)} ms` : "";
  updatePet(findings.length || lastTimingMs ? petStateForFindings(findings) : "idle");
  renderSeverityBars();
  const visible = filteredFindings();
  if (!visible.length) {
    box.innerHTML = '<p class="muted">No findings from the supplied local data.</p>';
    return;
  }
  box.innerHTML = visible.map((f) =>
    `<div class="finding"><span class="badge badge-${f.severity}">${f.severity}</span> <strong>${f.title}</strong>` +
    `<div class="muted">${f.module} · priority ${f.priority ?? ""} · confidence ${f.confidence ?? ""} · ${(f.sources || []).join(", ")}</div>` +
    `<div class="muted">${f.evidence}</div><div>${f.remediation}</div></div>`
  ).join("");
}

function bountyDraftText() {
  return findings.slice(0, 10).map((f) => [
    `Title: ${f.title}`,
    `Scope: ${scopeName()}`,
    `Severity: ${f.severity}`,
    `Summary: ${f.title} was identified from authorized local evidence.`,
    `Evidence: ${f.evidence}`,
    "Impact: Validate impact manually inside the authorized scope before submission.",
    `Remediation: ${f.remediation}`,
    "Submission note: Draft only — review manually, dedupe, and submit yourself if valid.",
  ].join("\n")).join("\n\n---\n\n");
}

function download(name, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function scopeName() {
  const el = document.getElementById("scope-name");
  return (el && el.value.trim()) || "local-lab";
}

function wire() {
  const gate = () => {
    const scope = document.getElementById("scope-name").value.trim();
    const confirmed = document.getElementById("auth-confirm").checked;
    const url = document.getElementById("target-url");
    const status = document.getElementById("gate-status");
    const ok = Boolean(scope && confirmed);
    url.disabled = !ok;
    status.textContent = ok
      ? "Authorization gate satisfied for the declared scope. Paste headers from your authorized session — this page still performs no scanning."
      : "URL field locked — complete the authorization gate to enable it.";
  };
  document.getElementById("scope-name").addEventListener("input", gate);
  document.getElementById("auth-confirm").addEventListener("change", gate);

  const collectValues = () => ({
    headers: document.getElementById("headers-input").value,
    cookies: document.getElementById("cookies-input").value,
    jwt: document.getElementById("jwt-input").value,
    secrets: document.getElementById("secrets-input").value,
    imports: document.getElementById("imports-input") ? document.getElementById("imports-input").value : "",
    password: {
      min_length: Number(document.getElementById("pw-min").value || 0),
      mfa_available: document.getElementById("pw-mfa").checked,
      breached_password_check: document.getElementById("pw-breached").checked,
      rate_limiting: document.getElementById("pw-rate").checked,
    },
  });

  document.querySelectorAll("[data-run]").forEach((button) => {
    button.addEventListener("click", () => {
      const started = performance.now();
      const kind = button.getAttribute("data-run");
      const values = collectValues();
      if (kind === "headers") findings = findings.concat(auditHeaders(values.headers));
      if (kind === "cookies") findings = findings.concat(auditCookiesCors(values.cookies));
      if (kind === "jwt") findings = findings.concat(auditJwt(values.jwt));
      if (kind === "secrets") findings = findings.concat(scanSecrets(values.secrets));
      if (kind === "imports") findings = findings.concat(parseImportedOutput(values.imports));
      if (kind === "password") findings = findings.concat(auditPasswordPolicy(values.password));
      findings = correlateFindings(findings);
      lastTimingMs = performance.now() - started;
      render();
    });
  });

  document.querySelectorAll("[data-preset]").forEach((button) => {
    button.addEventListener("click", () => {
      updatePet("scan");
      updateConsole(["gravion-hacker scanning local data", `preset: ${button.getAttribute("data-preset")}`, "mode: offline correlation"]);
      const result = runPreset(button.getAttribute("data-preset"), collectValues());
      findings = result.findings;
      lastTimingMs = result.elapsedMs;
      updateConsole(["gravion-hacker scan complete", `findings: ${findings.length}`, `elapsed: ${lastTimingMs.toFixed(1)} ms`, "next: review priority order, fix, re-run"]);
      render();
    });
  });

  const petStyle = document.getElementById("pet-style");
  if (petStyle) petStyle.addEventListener("change", () => {
    const pet = document.getElementById("hacker-pet");
    pet.classList.remove("pet-fox", "pet-bot");
    if (petStyle.value === "fox") pet.classList.add("pet-fox");
    if (petStyle.value === "bot") pet.classList.add("pet-bot");
    pet.textContent = petStyle.value === "fox" ? "F" : petStyle.value === "bot" ? "B" : "G";
  });

  const aiOutput = document.getElementById("ai-output");
  const aiExplain = document.getElementById("ai-explain");
  if (aiExplain) aiExplain.addEventListener("click", () => { aiOutput.textContent = explainFindingsOffline(findings); });
  const aiDraft = document.getElementById("ai-draft");
  if (aiDraft) aiDraft.addEventListener("click", () => { aiOutput.textContent = bountyDraftText() || "Run a preset first to draft report sections."; });
  const aiSave = document.getElementById("ai-save");
  if (aiSave) aiSave.addEventListener("click", () => {
    localStorage.setItem("gravion-hacker-ai-config", JSON.stringify({
      endpoint: document.getElementById("ai-endpoint").value.trim(),
      model: document.getElementById("ai-model").value.trim(),
      key: document.getElementById("ai-key").value,
    }));
    aiOutput.textContent = "BYO config saved only in this browser local storage. Never commit API keys.";
  });
  const aiPrompt = document.getElementById("ai-prompt");
  if (aiPrompt) aiPrompt.addEventListener("click", () => {
    aiOutput.textContent = JSON.stringify(buildByoPrompt(findings, scopeName()), null, 2);
  });
  try {
    const saved = JSON.parse(localStorage.getItem("gravion-hacker-ai-config") || "{}");
    if (saved.endpoint) document.getElementById("ai-endpoint").value = saved.endpoint;
    if (saved.model) document.getElementById("ai-model").value = saved.model;
    if (saved.key) document.getElementById("ai-key").value = saved.key;
  } catch (err) {
    // Ignore malformed local config.
  }

  ["severity-filter", "module-filter"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", render);
  });

  document.getElementById("clear-results").addEventListener("click", () => { findings = []; render(); });
  const copyBounty = document.getElementById("copy-bounty");
  if (copyBounty) copyBounty.addEventListener("click", async () => {
    const text = bountyDraftText();
    if (navigator.clipboard) await navigator.clipboard.writeText(text);
    const timing = document.getElementById("timing");
    if (timing) timing.textContent = "Bug bounty draft sections copied.";
  });
  document.getElementById("export-json").addEventListener("click", () => {
    download("gravion-hacker-report.json", JSON.stringify({ tool: "Gravion Hacker", scope: scopeName(), ethical_use: ETHICAL_NOTE, authorization: { scope_name: scopeName(), recorded: document.getElementById("auth-confirm").checked }, performance: { elapsed_ms: Math.round(lastTimingMs * 1000) / 1000 }, findings, bug_bounty_draft_sections: bountyDraftText() }, null, 2), "application/json");
  });
  document.getElementById("export-md").addEventListener("click", () => {
    const lines = ["# Gravion Hacker — Security Assessment Report", "", `**Scope:** ${scopeName()}`, "", `> ${ETHICAL_NOTE}`, "", "## Executive summary", "", `- Total findings: ${findings.length}`, `- Last run ms: ${lastTimingMs.toFixed(1)}`, "", "## Technical findings", ""];
    for (const f of findings) lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`, "", `- Module: ${f.module}`, `- Priority: ${f.priority ?? ""} · Confidence: ${f.confidence ?? ""}`, `- Evidence: ${f.evidence}`, `- Remediation: ${f.remediation}`, "");
    lines.push("## Copy-ready bug bounty draft sections", "", bountyDraftText());
    download("gravion-hacker-report.md", lines.join("\n"), "text/markdown");
  });
}

if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", wire);
if (typeof module !== "undefined") module.exports = { auditHeaders, auditCookiesCors, auditJwt, scanSecrets, auditPasswordPolicy, redact, parseHeaders, correlateFindings, parseNucleiJsonl, parseImportedOutput, runPreset, PRESETS, petStateForFindings, explainFindingsOffline, buildByoPrompt };
