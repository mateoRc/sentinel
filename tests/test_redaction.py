import unittest

from sentinel.redaction import redact


class RedactionTest(unittest.TestCase):
    def test_common_secret_formats_are_redacted(self) -> None:
        value = redact(
            "Authorization: Bearer abcdefghijklmnop "
            "API_KEY=super-secret-value "
            "github_pat_abcdefghijklmnopqrstuvwxyz"
        )

        self.assertNotIn("abcdefghijklmnop", value)
        self.assertNotIn("super-secret-value", value)
        self.assertNotIn("github_pat_", value)
        self.assertGreaterEqual(value.count("[REDACTED]"), 3)

    def test_explicit_values_are_redacted(self) -> None:
        self.assertEqual(
            redact("failed with local-token", ("local-token",)),
            "failed with [REDACTED]",
        )
