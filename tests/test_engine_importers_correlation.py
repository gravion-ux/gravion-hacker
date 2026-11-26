import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gravion_hacker.cache import AnalysisCache
from gravion_hacker.cli import main
from gravion_hacker.correlate import correlate_findings
from gravion_hacker.engine import PRESETS, LocalAnalysisEngine, benchmark_synthetic
from gravion_hacker.findings import Finding
from gravion_hacker.importers import import_output
from gravion_hacker.report import report_json, report_markdown


class ImporterTests(unittest.TestCase):
    def test_nuclei_jsonl_import(self):
        text = json.dumps(
            {
                "template-id": "missing-hsts",
                "info": {"name": "Missing HSTS", "severity": "medium"},
                "matched-at": "https://lab.example",
            }
        )
        findings = import_output(text, "nuclei")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].sources, ["nuclei"])

    def test_ffuf_and_gobuster_imports(self):
        ffuf = json.dumps({"results": [{"url": "https://lab.example/admin", "status": 200, "length": 123}]})
        self.assertEqual(import_output(ffuf, "ffuf")[0].severity, "medium")
        gobuster = "/admin (Status: 200) [Size: 123]"
        self.assertEqual(import_output(gobuster, "gobuster")[0].sources, ["gobuster"])

    def test_nikto_and_sqlmap_imports(self):
        self.assertTrue(import_output("+ /admin/: Admin login page found", "nikto"))
        sqlmap = "Parameter: id (GET) is vulnerable. back-end DBMS: MySQL"
        findings = import_output(sqlmap, "sqlmap")
        self.assertTrue(any(f.severity == "high" for f in findings))

    def test_auto_detect_nuclei(self):
        text = '{"template-id":"x","info":{"name":"Demo","severity":"low"},"matched-at":"https://lab.example"}'
        self.assertEqual(import_output(text)[0].sources, ["nuclei"])


class CorrelationCacheEngineTests(unittest.TestCase):
    def test_correlation_merges_and_boosts_confidence(self):
        one = Finding(
            "headers", "Missing HSTS header", "medium", "hsts missing", "Add HSTS", confidence=0.6, sources=["headers"]
        )
        two = Finding(
            "import:nuclei",
            "Missing HSTS header",
            "high",
            "hsts missing",
            "Add HSTS header",
            confidence=0.7,
            sources=["nuclei"],
        )
        merged = correlate_findings([one, two])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].severity, "high")
        self.assertGreater(merged[0].confidence, 0.7)
        self.assertIn("nuclei", merged[0].sources)

    def test_cache_hit_on_repeat_content(self):
        cache = AnalysisCache()
        engine = LocalAnalysisEngine(cache=cache, workers=2)
        first = engine.analyse_texts({"headers": "Server: Demo/1.0"}, preset="quick")
        second = engine.analyse_texts({"headers": "Server: Demo/1.0"}, preset="quick")
        self.assertTrue(first.findings)
        self.assertEqual([f.title for f in first.findings], [f.title for f in second.findings])
        self.assertGreaterEqual(cache.stats()["hits"], 1)

    def test_presets_and_deterministic_order(self):
        self.assertIn("quick", PRESETS)
        engine = LocalAnalysisEngine(workers=4)
        result = engine.analyse_texts(
            {"headers": "Server: Demo/1.0", "secrets": "api_key = 'synthetic-secret-value'"},
            preset="quick",
        )
        self.assertEqual(result.modules_run, ["headers", "secrets"])
        self.assertGreaterEqual(result.elapsed_ms, 0)

    def test_report_export_has_executive_and_bounty_sections(self):
        finding = Finding("headers", "Missing HSTS", "medium", "evidence", "Add HSTS", confidence=0.8)
        data = json.loads(report_json([finding], scope_name="lab", performance={"preset": "quick", "elapsed_ms": 1.2}))
        self.assertIn("executive_summary", data)
        self.assertTrue(data["bug_bounty_draft_sections"])
        md = report_markdown([finding], scope_name="lab")
        self.assertIn("Executive summary", md)
        self.assertIn("Copy-ready bug bounty draft sections", md)

    def test_cli_import_requires_authorization_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nuclei.jsonl"
            path.write_text(
                '{"template-id":"x","info":{"name":"Demo","severity":"low"},"matched-at":"https://lab.example"}'
            )
            self.assertEqual(main(["import", "--tool", "nuclei", "--file", str(path)]), 2)
            self.assertEqual(main(["import", "--tool", "nuclei", "--file", str(path), "--authorized-confirm"]), 0)

    def test_benchmark_synthetic_shape(self):
        data = benchmark_synthetic(repeats=1)
        self.assertIn("first_run_ms", data)
        self.assertIn("cached_run_ms_min", data)
        self.assertGreaterEqual(data["findings"], 1)


if __name__ == "__main__":
    unittest.main()
