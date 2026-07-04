from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol

from sentinel.config import PolicyConfig
from sentinel.models import Assessment, Check, CheckStatus, Risk
from sentinel.policy import evaluate


class AnalysisProvider(Protocol):
    name: str

    def summarize(
        self,
        project: str,
        commit: str,
        risk: Risk,
        checks: tuple[Check, ...],
    ) -> str: ...


class MockAnalysisProvider:
    name = "mock"

    def summarize(
        self,
        project: str,
        commit: str,
        risk: Risk,
        checks: tuple[Check, ...],
    ) -> str:
        del commit
        failed = [check.name for check in checks if check.status == CheckStatus.FAILED]
        warnings = [
            check.name for check in checks if check.status == CheckStatus.WARNING
        ]
        if failed:
            labels = ", ".join(_label(name) for name in failed)
            return (
                f"{len(failed)} of {len(checks)} {_plural(len(checks))} failed: "
                f"{labels}."
            )
        if warnings:
            labels = ", ".join(_label(name) for name in warnings)
            return (
                f"{len(warnings)} of {len(checks)} {_plural(len(checks))} warned: "
                f"{labels}."
            )
        return f"All {len(checks)} {_plural(len(checks))} passed."


def assess(
    payload: Mapping[str, object],
    provider: AnalysisProvider,
    policy: PolicyConfig | None = None,
    advisory_only: bool = True,
    analyzed_at: datetime | None = None,
) -> Assessment:
    project = _required_text(payload, "project")
    commit = _required_text(payload, "commit")
    raw_checks = payload.get("checks")

    if not isinstance(raw_checks, list) or not raw_checks:
        raise ValueError("checks must be a non-empty list")

    checks = tuple(_parse_check(item) for item in raw_checks)
    risk = _risk(checks)
    configured_policy = policy or PolicyConfig(True, True, True)
    decision = evaluate(checks, risk, configured_policy, advisory_only)
    summary = provider.summarize(project, commit, risk, checks)
    actions = _recommended_actions(checks)
    timestamp = (analyzed_at or datetime.now(UTC)).astimezone(UTC)

    return Assessment(
        project,
        commit,
        timestamp.isoformat().replace("+00:00", "Z"),
        risk,
        decision,
        checks,
        summary,
        actions,
        provider.name,
    )


def _parse_check(value: object) -> Check:
    if not isinstance(value, dict):
        raise ValueError("each check must be an object")
    name = _required_text(value, "name")
    evidence = _required_text(value, "evidence")
    source = value.get("source", "supplied evidence")
    if not isinstance(source, str) or not source.strip():
        raise ValueError(f"source must be a non-empty string for check {name}")

    try:
        status = CheckStatus(_required_text(value, "status"))
    except ValueError as error:
        raise ValueError(f"invalid status for check {name}") from error

    return Check(name, status, evidence, source.strip())


def _required_text(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{key} must be a non-empty string")

    return item.strip()


def _risk(checks: tuple[Check, ...]) -> Risk:
    statuses = {check.status for check in checks}

    if CheckStatus.FAILED in statuses:
        return Risk.HIGH

    if CheckStatus.WARNING in statuses:
        return Risk.MEDIUM
    return Risk.LOW


def _recommended_actions(checks: tuple[Check, ...]) -> tuple[str, ...]:
    actions: list[str] = []
    for check in checks:
        if check.status == CheckStatus.PASSED:
            continue
        if "image-security" in check.name:
            action = (
                "Update affected packages or base images to listed fixed versions, "
                "then rebuild and rescan."
            )
        elif check.name == "repository-security":
            action = (
                "Update vulnerable dependencies and rotate or remove detected secrets."
            )
        elif check.name.endswith("-tests"):
            action = "Inspect the failed test build, fix it, and rerun the release checks."
        elif check.name.startswith("compose-"):
            action = "Correct the Compose configuration and validate it locally."
        elif check.name == "security-headers":
            action = "Restore the missing security headers in the Caddy configuration."
        elif check.name == "internal-network":
            action = "Remove exposed backend ports and restore the internal network."
        else:
            action = f"Inspect evidence for {_label(check.name)} and rerun the check."
        if action not in actions:
            actions.append(action)
    return tuple(actions)


def _label(name: str) -> str:
    return name.replace("-", " ")


def _plural(count: int) -> str:
    return "check" if count == 1 else "checks"
