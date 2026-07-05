import json
from dataclasses import asdict
from pathlib import Path

from sentinel.checks import CheckRegistry
from sentinel.redaction import redact


def collect(
    plan: dict[str, object],
    workspace: Path,
    registry: CheckRegistry,
) -> dict[str, object]:
    project = _required_text(plan, "project")
    commit = _required_text(plan, "commit")
    specifications = plan.get("checks")
    if not isinstance(specifications, list) or not specifications:
        raise ValueError("checks must be a non-empty list")
    checks = tuple(
        type(check)(
            redact(check.name),
            check.status,
            redact(check.evidence),
            redact(check.source),
        )
        for check in registry.run_all(specifications, workspace)
    )
    return {
        "project": project,
        "commit": commit,
        "checks": [asdict(check) for check in checks],
    }


def write_evidence(evidence: dict[str, object], path: Path) -> None:
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def _required_text(value: dict[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return item.strip()
