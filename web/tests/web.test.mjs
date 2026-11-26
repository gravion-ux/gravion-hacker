import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const app = require("../app.js");

test("headers audit flags missing HSTS", () => {
  const findings = app.auditHeaders("Server: Demo/1.0");
  assert.ok(findings.some((f) => f.title.includes("strict-transport-security")));
});

test("cors wildcard with credentials is high", () => {
  const findings = app.auditCookiesCors("Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true");
  assert.equal(findings[0].severity, "high");
});

test("jwt alg none is critical", () => {
  const findings = app.auditJwt("eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ.synthetic");
  assert.ok(findings.some((f) => f.severity === "critical"));
});

test("secret scan redacts evidence", () => {
  const findings = app.scanSecrets("api_key = 'synthetic-secret-value-123'");
  assert.ok(findings.length > 0);
  assert.ok(!findings[0].evidence.includes("synthetic-secret-value-123"));
});

test("password policy flags missing MFA", () => {
  const findings = app.auditPasswordPolicy({ min_length: 14 });
  assert.ok(findings.some((f) => f.title.includes("MFA")));
});

test("nuclei import parses authorized JSONL output", () => {
  const findings = app.parseNucleiJsonl('{"template-id":"missing-hsts","info":{"name":"Missing HSTS","severity":"medium"},"matched-at":"https://lab.example"}');
  assert.equal(findings[0].severity, "medium");
  assert.deepEqual(findings[0].sources, ["nuclei"]);
});

test("correlation merges duplicate findings", () => {
  const merged = app.correlateFindings([
    { module: "headers", title: "Missing HSTS", severity: "medium", evidence: "missing", remediation: "Add", confidence: 0.6, sources: ["headers"] },
    { module: "import:nuclei", title: "Missing HSTS", severity: "high", evidence: "missing", remediation: "Add HSTS", confidence: 0.7, sources: ["nuclei"] },
  ]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].severity, "high");
  assert.ok(merged[0].confidence > 0.7);
});

test("quick preset runs local modules with timing", () => {
  const result = app.runPreset("quick", { headers: "Server: Demo/1.0", cookies: "", jwt: "", secrets: "" });
  assert.ok(result.findings.length > 0);
  assert.ok(result.elapsedMs >= 0);
  assert.deepEqual(result.modules, app.PRESETS.quick);
});

test("pet state reacts to severity", () => {
  assert.equal(app.petStateForFindings([]), "celebrate");
  assert.equal(app.petStateForFindings([{ severity: "high" }]), "alert");
  assert.equal(app.petStateForFindings([{ severity: "low" }]), "scan");
});

test("offline AI explain and BYO prompt stay local", () => {
  const findings = [{ module: "headers", title: "Missing HSTS", severity: "medium", evidence: "missing", remediation: "Add HSTS", confidence: 0.8 }];
  assert.ok(app.explainFindingsOffline(findings).includes("Offline assistant summary"));
  const prompt = app.buildByoPrompt(findings, "lab");
  assert.ok(prompt.system.includes("does not run attacks"));
  assert.ok(!JSON.stringify(prompt).toLowerCase().includes("api_key"));
});
