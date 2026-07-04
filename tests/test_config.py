import tempfile
import unittest
from pathlib import Path

from sentinel.config import load_configuration

VALID_CONFIGURATION = """
schema: sentinel.dev/v1alpha1
project:
  name: backend-lab
  default_branch: main
repositories:
  - name: lab
    path: .
checks:
  regression:
    enabled: true
  security:
    enabled: true
  deployment:
    enabled: true
policy:
  block_on_check_failure: true
  block_on_critical_security_finding: true
  require_approval_for_high_risk: true
agent:
  enabled: true
  provider: mock
  advisory_only: true
  allow_repository_writes: false
  allow_deployment: false
report:
  format: markdown
  include_file_references: true
  include_check_evidence: true
"""


class ConfigurationTest(unittest.TestCase):
    def test_valid_configuration_is_loaded(self) -> None:
        configuration = self._load(VALID_CONFIGURATION)

        self.assertEqual(configuration.project_name, "backend-lab")
        self.assertEqual(configuration.enabled_checks, {"regression", "security", "deployment"})
        self.assertTrue(configuration.agent.advisory_only)

    def test_unknown_field_is_rejected(self) -> None:
        invalid = VALID_CONFIGURATION.replace(
            "  default_branch: main",
            "  default_branch: main\n  unexpected: true",
        )

        with self.assertRaisesRegex(ValueError, "unknown fields"):
            self._load(invalid)

    def test_agent_cannot_write_or_deploy(self) -> None:
        invalid = VALID_CONFIGURATION.replace(
            "  allow_deployment: false",
            "  allow_deployment: true",
        )

        with self.assertRaisesRegex(ValueError, "deployment is not supported"):
            self._load(invalid)

    def _load(self, content: str):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sentinel.yml"
            path.write_text(content, encoding="utf-8")
            return load_configuration(path)
