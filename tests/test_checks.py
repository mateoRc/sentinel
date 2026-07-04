import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.checks import CommandCheckAdapter, ExternalResultAdapter, FilePolicyAdapter
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
