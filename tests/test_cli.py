import unittest

from sentinel import __version__
from sentinel.cli import build_parser, main


class CliTest(unittest.TestCase):
    def test_version_is_defined(self) -> None:
        self.assertEqual(__version__, "0.1.0.dev0")

    def test_program_name(self) -> None:
        self.assertEqual(build_parser().prog, "sentinel")

    def test_empty_invocation_succeeds(self) -> None:
        self.assertEqual(main([]), 0)


if __name__ == "__main__":
    unittest.main()
