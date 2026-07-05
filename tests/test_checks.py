import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinel.checks import (
    CommandCheckAdapter,
    ExternalResultAdapter,
    FilePolicyAdapter,
    HTTPJSONCheckAdapter,
)
from sentinel.models import CheckStatus


class CommandCheckAdapterTest(unittest.TestCase):
    def test_success_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "sentinel.checks.subprocess.run",
                return_value=subprocess.CompletedProcess(["docker"], 0),
            ):
                check = CommandCheckAdapter().run(
                    {
                        "name": "container-tests",
                        "command": ["docker", "build", "."],
                        "working_directory": ".",
                    },
                    Path(directory),
                )

        self.assertEqual(check.status, CheckStatus.PASSED)
        self.assertEqual(check.source, "docker build .")

    def test_unapproved_executable_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "not allowed"):
                CommandCheckAdapter().run(
                    {
                        "name": "unsafe",
                        "command": ["sh", "-c", "echo unsafe"],
                    },
                    Path(directory),
                )

    def test_expected_nonzero_exit_is_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "sentinel.checks.subprocess.run",
                return_value=subprocess.CompletedProcess(["docker"], 1),
            ):
                check = CommandCheckAdapter().run(
                    {
                        "name": "invalid-token-rejected",
                        "command": ["docker", "compose", "exec", "service"],
                        "expected_exit_code": 1,
                    },
                    Path(directory),
                )

        self.assertEqual(check.status, CheckStatus.PASSED)
        self.assertIn("expected exit 1", check.evidence)

    def test_expected_exit_code_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "between 0 and 255"):
                CommandCheckAdapter().run(
                    {
                        "name": "invalid",
                        "command": ["docker", "version"],
                        "expected_exit_code": 256,
                    },
                    Path(directory),
                )

    def test_working_directory_cannot_escape_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "escapes"):
                CommandCheckAdapter().run(
                    {
                        "name": "unsafe",
                        "command": ["docker", "version"],
                        "working_directory": "..",
                    },
                    Path(directory),
                )

    def test_failure_output_redacts_environment_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "sentinel.checks.subprocess.run",
                side_effect=OSError("token local-secret-value rejected"),
            ):
                check = CommandCheckAdapter().run(
                    {
                        "name": "container-tests",
                        "command": ["docker", "build", "."],
                        "environment": {"AUTH_TOKEN": "local-secret-value"},
                    },
                    Path(directory),
                )

        self.assertNotIn("local-secret-value", check.evidence)


class ExternalResultAdapterTest(unittest.TestCase):
    def test_external_failure_is_normalized(self) -> None:
        check = ExternalResultAdapter().run(
            {
                "name": "dependency-scan",
                "status": "failed",
                "evidence": "high-severity vulnerability found",
                "source": "Trivy",
            },
            Path("."),
        )

        self.assertEqual(check.status, CheckStatus.FAILED)
        self.assertEqual(check.source, "Trivy")


class FilePolicyAdapterTest(unittest.TestCase):
    def test_required_markers_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Caddyfile"
            path.write_text('Strict-Transport-Security "max-age=31536000"')

            check = FilePolicyAdapter().run(
                {
                    "name": "security-headers",
                    "path": "Caddyfile",
                    "required": ["Strict-Transport-Security", "max-age=31536000"],
                    "forbidden": ["Server"],
                },
                Path(directory),
            )

        self.assertEqual(check.status, CheckStatus.PASSED)


class HTTPJSONCheckAdapterTest(unittest.TestCase):
    def test_expected_json_fields_are_checked(self) -> None:
        response = MagicMock()
        response.read.return_value = b'{"exit_code":0,"output":"# About"}'
        response.__enter__.return_value = response
        with patch("sentinel.checks.urllib.request.urlopen", return_value=response):
            check = HTTPJSONCheckAdapter().run(
                {
                    "name": "vault-contract",
                    "url": "http://127.0.0.1:8080/api/exec",
                    "json": {"line": "cat /cv/about.md"},
                    "expected": {"exit_code": 0},
                    "contains": {"output": "# About"},
                },
                Path("."),
            )

        self.assertEqual(check.status, CheckStatus.PASSED)

    def test_non_local_url_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "local HTTP"):
            HTTPJSONCheckAdapter().run(
                {
                    "name": "unsafe",
                    "url": "https://example.com",
                    "json": {},
                    "expected": {"ok": True},
                },
                Path("."),
            )
