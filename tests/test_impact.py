import json
import tempfile
import unittest
from pathlib import Path

from sentinel.impact import analyze, write_impact


class ImpactTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = {
            "repositories": {
                "lab": ["lab/**"],
                "vaultsh": ["vaultsh/**"],
            },
            "services": {
                "atlas": ["atlas/**", "lab/content/**"],
                "vaultsh": ["vaultsh/**", "lab/content/**"],
            },
            "checks": {
                "contracts": ["lab/content/**", "lab/docker-compose*.yml"],
                "deployment": ["lab/docker-compose*.yml"],
            },
        }

    def test_shared_content_affects_both_consumers(self) -> None:
        impact = analyze(["lab/content/docs/api.md"], self.rules)

        self.assertEqual(impact.repositories, ("lab",))
        self.assertEqual(impact.services, ("atlas", "vaultsh"))
        self.assertEqual(impact.checks, ("contracts",))

    def test_results_are_sorted_and_serializable(self) -> None:
        impact = analyze(["vaultsh/web/index.html", "lab/docker-compose.prod.yml"], self.rules)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "impact.json"
            write_impact(impact, path)
            value = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(value["repositories"], ["lab", "vaultsh"])
        self.assertEqual(value["checks"], ["contracts", "deployment"])

    def test_escaping_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "escapes"):
            analyze(["../secret"], self.rules)
