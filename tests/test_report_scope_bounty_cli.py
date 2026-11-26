import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gravion_hacker.bounty import SEVEN_QUESTION_GATE, report_draft
from gravion_hacker.cli import main
from gravion_hacker.findings import Finding
from gravion_hacker.report import ETHICAL_NOTE, report_json, report_markdown
from gravion_hacker.scope import AuthorizationRecord, require_authorization


class ReportTests(unittest.TestCase):
    def test_json_report_has_ethics_and_counts(self):
        data = json.loads(report_json([Finding("headers", "Demo", "low", "e", "r")], scope_name="lab"))
        self.assertEqual(data["scope"], "lab")
        self.assertEqual(data["summary"]["low"], 1)
        self.assertIn("authorized", data["ethical_use"])

    def test_markdown_report(self):
        text = report_markdown([], scope_name="lab")
        self.assertIn("Gravion Hacker", text)
        self.assertIn(ETHICAL_NOTE, text)


class ScopeBountyTests(unittest.TestCase):
    def test_authorization_gate_blocks_incomplete_record(self):
        with self.assertRaises(PermissionError):
            require_authorization(AuthorizationRecord(scope_name="", owner="", targets=[], authorized=False))

    def test_authorization_gate_passes_complete_record(self):
        require_authorization(
            AuthorizationRecord(
                scope_name="lab", owner="Priyanshu Kumar Thakur", targets=["localhost"], authorized=True
            )
        )

    def test_report_draft_is_manual_only(self):
        draft = report_draft(
            title="Demo finding",
            program="Lab program",
            asset="localhost",
            severity="low",
            summary="Synthetic summary.",
            steps=["Open the local lab page."],
            impact="No real-world impact.",
            remediation="Apply the fix.",
        )
        self.assertIn("manual review and submission", draft)
        self.assertEqual(len(SEVEN_QUESTION_GATE), 7)


class CliTests(unittest.TestCase):
    def test_cli_checklists(self):
        self.assertEqual(main(["checklists"]), 0)

    def test_cli_jwt(self):
        token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ.synthetic"
        self.assertEqual(main(["jwt", token]), 0)


if __name__ == "__main__":
    unittest.main()
