import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.checks import CommandCheckAdapter
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
