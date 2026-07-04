import unittest

from sentinel.config import PolicyConfig
from sentinel.models import Check, CheckStatus, Risk
from sentinel.policy import Decision, evaluate


class PolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PolicyConfig(
            block_on_check_failure=True,
            block_on_critical_security_finding=True,
            require_approval_for_high_risk=True,
        )

    def test_advisory_mode_never_blocks(self) -> None:
        decision = evaluate(
            (Check("security", CheckStatus.FAILED, "finding", "scanner"),),
            Risk.HIGH,
            self.policy,
            advisory_only=True,
        )

        self.assertEqual(decision, Decision.ADVISORY)

    def test_enforced_failure_is_blocked(self) -> None:
        decision = evaluate(
            (Check("tests", CheckStatus.FAILED, "failure", "runner"),),
            Risk.HIGH,
            self.policy,
            advisory_only=False,
        )

        self.assertEqual(decision, Decision.BLOCKED)

    def test_clean_release_is_approved(self) -> None:
        decision = evaluate(
            (Check("tests", CheckStatus.PASSED, "passed", "runner"),),
            Risk.LOW,
            self.policy,
            advisory_only=False,
        )

        self.assertEqual(decision, Decision.APPROVED)
