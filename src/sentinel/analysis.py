from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol

from sentinel.models import Assessment, Check, CheckStatus, Risk


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
            return f"{project} has failed checks: {', '.join(failed)}."
        if warnings:
            return f"{project} passed with warnings: {', '.join(warnings)}."
        return f"{project} passed all supplied checks."


def assess(
    payload: Mapping[str, object],
    provider: AnalysisProvider,
    analyzed_at: datetime | None = None,
) -> Assessment:
    project = _required_text(payload, "project")
    commit = _required_text(payload, "commit")
    raw_checks = payload.get("checks")

    if not isinstance(raw_checks, list) or not raw_checks:
        raise ValueError("checks must be a non-empty list")

    checks = tuple(_parse_check(item) for item in raw_checks)
    risk = _risk(checks)
    summary = provider.summarize(project, commit, risk, checks)
    timestamp = (analyzed_at or datetime.now(UTC)).astimezone(UTC)

    return Assessment(
        project,
        commit,
        timestamp.isoformat().replace("+00:00", "Z"),
        risk,
        checks,
        summary,
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
