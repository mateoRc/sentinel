import unittest
from datetime import UTC, datetime

from sentinel.analysis import MockAnalysisProvider, assess
from sentinel.models import Risk


class AnalysisTest(unittest.TestCase):
    def test_passed_checks_produce_low_risk(self) -> None:
        result = assess(
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
            analyzed_at=datetime(2026, 7, 4, 12, 0, tzinfo=UTC),
        )

        self.assertEqual(result.risk, Risk.LOW)
        self.assertEqual(result.provider, "mock")
        self.assertEqual(result.decision, "advisory")
        self.assertEqual(result.analyzed_at, "2026-07-04T12:00:00Z")
        self.assertIn("passed all supplied checks", result.summary)

    def test_failed_check_produces_high_risk(self) -> None:
        result = assess(
            {
                "project": "backend-lab",
                "commit": "abc123",
                "checks": [
                    {
                        "name": "security",
                        "status": "failed",
                        "evidence": "critical finding",
                    }
                ],
            },
            MockAnalysisProvider(),
        )

        self.assertEqual(result.risk, Risk.HIGH)
        self.assertIn("security", result.summary)

    def test_empty_checks_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty list"):
            assess(
                {"project": "backend-lab", "commit": "abc123", "checks": []},
                MockAnalysisProvider(),
            )
