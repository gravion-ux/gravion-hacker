import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gravion_hacker.ai_assistant import ByoAiConfig, build_byo_prompt, explain_findings, next_authorized_checks
from gravion_hacker.cli import main
from gravion_hacker.findings import Finding


class AiAssistantTests(unittest.TestCase):
    def test_offline_explain_and_next_checks(self):
        finding = Finding("headers", "Missing HSTS", "medium", "hsts missing", "Add HSTS", confidence=0.8)
        text = explain_findings([finding])
        self.assertIn("Offline assistant summary", text)
        self.assertTrue(next_authorized_checks([finding]))

    def test_byo_prompt_has_no_key_and_keeps_safety_note(self):
        finding = Finding("secrets", "Possible secret", "high", "redacted", "Rotate", confidence=0.7)
        prompt = build_byo_prompt([finding], scope_name="lab")
        self.assertIn("does not run attacks", prompt["system"])
        self.assertNotIn("api_key", json.dumps(prompt).lower())

    def test_byo_config_validation_redacts_key(self):
        config = ByoAiConfig(endpoint="https://endpoint.example", model="model-x", api_key="secret")
        self.assertEqual(config.validate(), [])
        self.assertEqual(config.redacted()["api_key"], "***")
        bad = ByoAiConfig(endpoint="http://example.com", model="", api_key="")
        self.assertTrue(bad.validate())

    def test_cli_ai_explain_from_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "module": "headers",
                                "title": "Demo",
                                "severity": "low",
                                "evidence": "e",
                                "remediation": "r",
                            }
                        ]
                    }
                )
            )
            self.assertEqual(main(["ai", "explain", "--file", str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
