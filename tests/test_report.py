import json
import tempfile
import unittest
from pathlib import Path

from sentinel.analysis import MockAnalysisProvider, assess
from sentinel.report import write_json, write_markdown


class ReportTest(unittest.TestCase):
    def test_reports_include_evidence(self) -> None:
        assessment = assess(
            {
                "project": "backend-lab",
                "commit": "abc123",
                "checks": [
                    {
                        "name": "tests",
                        "status": "passed",
                        "evidence": "42 tests passed",
                    }
                ],
            },
            MockAnalysisProvider(),
        )

        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "assessment.json"
            markdown_path = Path(directory) / "assessment.md"
            write_json(assessment, json_path)
            write_markdown(assessment, markdown_path)

            self.assertEqual(json.loads(json_path.read_text())["risk"], "low")
            self.assertIn("42 tests passed", markdown_path.read_text())
