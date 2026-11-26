import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gravion_hacker.cookies import audit_cookies
from gravion_hacker.cors import audit_cors
from gravion_hacker.findings import Finding, cvss_style_score, severity_counts
from gravion_hacker.headers import audit_headers, parse_headers
from gravion_hacker.jwt_audit import audit_jwt
from gravion_hacker.manifests import audit_manifest
from gravion_hacker.password_policy import audit_password_policy, password_strength_hint
from gravion_hacker.secrets import redact, scan_secrets
from gravion_hacker.source_audit import audit_source
from gravion_hacker.tls_dns import audit_dns_snapshot, audit_tls_snapshot


def make_jwt(header: dict, payload: dict) -> str:
    def enc(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{enc(header)}.{enc(payload)}.syntheticsignature"


class HeadersCookiesCorsTests(unittest.TestCase):
    def test_parse_headers(self):
        self.assertEqual(parse_headers("X-Test: 1\nServer: demo")["x-test"], "1")

    def test_missing_headers_flagged(self):
        titles = [f.title for f in audit_headers("Server: Demo/1.0")]
        self.assertIn("Missing strict-transport-security header", titles)
        self.assertIn("Missing clickjacking protection", titles)

    def test_cookie_flags(self):
        findings = audit_cookies("Set-Cookie: session=abc; Path=/")
        titles = [f.title for f in findings]
        self.assertIn("Cookie session missing Secure", titles)
        self.assertIn("Cookie session missing HttpOnly", titles)

    def test_cors_wildcard_credentials(self):
        findings = audit_cors("Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true")
        self.assertEqual(findings[0].severity, "high")


class JwtSecretsTests(unittest.TestCase):
    def test_jwt_none_alg(self):
        token = make_jwt({"alg": "none"}, {"sub": "lab-user"})
        severities = [f.severity for f in audit_jwt(token, now=1_700_000_000)]
        self.assertIn("critical", severities)

    def test_jwt_expired(self):
        token = make_jwt({"alg": "RS256"}, {"sub": "u", "iss": "lab", "aud": "lab", "exp": 100})
        titles = [f.title for f in audit_jwt(token, now=200)]
        self.assertIn("JWT is expired", titles)

    def test_secret_redaction(self):
        findings = scan_secrets("api_key = 'synthetic-secret-value-123'")
        self.assertTrue(findings)
        self.assertNotIn("synthetic-secret-value-123", findings[0].evidence)
        self.assertEqual(redact("short"), "***")


class ManifestSourcePolicyTests(unittest.TestCase):
    def test_package_json_unpinned(self):
        findings = audit_manifest("package.json", json.dumps({"dependencies": {"demo": "*"}}))
        self.assertEqual(findings[0].severity, "medium")

    def test_requirements_unpinned(self):
        findings = audit_manifest("requirements.txt", "requests>=2\n")
        self.assertTrue(findings)

    def test_source_patterns(self):
        findings = audit_source("eval(user_input)\nrequests.get(url, verify=False)")
        titles = [f.title for f in findings]
        self.assertIn("eval/exec usage", titles)
        self.assertIn("Disabled TLS verification", titles)

    def test_password_policy(self):
        findings = audit_password_policy({"min_length": 8})
        titles = [f.title for f in findings]
        self.assertIn("Minimum length below 12", titles)
        self.assertIn("MFA not available", titles)
        self.assertEqual(password_strength_hint("Correct-Horse-Battery-9!")["label"], "strong")


class TlsDnsScoringTests(unittest.TestCase):
    def test_tls_weak_protocol(self):
        findings = audit_tls_snapshot(json.dumps({"protocols": "TLS1.0 TLS1.2", "self_signed": True}))
        titles = [f.title for f in findings]
        self.assertTrue(any("Weak protocol" in t for t in titles))
        self.assertIn("Self-signed certificate", titles)

    def test_dns_missing_records(self):
        titles = [f.title for f in audit_dns_snapshot("example.test A 192.0.2.10")]
        self.assertIn("No SPF record found in snapshot", titles)
        self.assertIn("No DMARC record found in snapshot", titles)

    def test_scoring_bounds(self):
        self.assertLessEqual(cvss_style_score("critical", network_reachable=True, data_impact=True), 10.0)
        counts = severity_counts([Finding("m", "t", "low", "e", "r")])
        self.assertEqual(counts["low"], 1)


if __name__ == "__main__":
    unittest.main()
