from enum import StrEnum

from sentinel.config import PolicyConfig
from sentinel.models import Check, CheckStatus, Risk


class Decision(StrEnum):
    ADVISORY = "advisory"
    APPROVED = "approved"
    BLOCKED = "blocked"
    APPROVAL_REQUIRED = "approval_required"


def evaluate(
    checks: tuple[Check, ...],
    risk: Risk,
    policy: PolicyConfig,
    advisory_only: bool,
) -> Decision:
    if advisory_only:
        return Decision.ADVISORY

    failures = tuple(check for check in checks if check.status == CheckStatus.FAILED)
    if policy.block_on_check_failure and failures:
        return Decision.BLOCKED

    security_failure = any(
        "security" in check.name and check.status == CheckStatus.FAILED
        for check in checks
    )
    if policy.block_on_critical_security_finding and security_failure:
        return Decision.BLOCKED

    if policy.require_approval_for_high_risk and risk == Risk.HIGH:
        return Decision.APPROVAL_REQUIRED
    return Decision.APPROVED
