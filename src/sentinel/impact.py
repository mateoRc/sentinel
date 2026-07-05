import fnmatch
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Impact:
    changed_paths: tuple[str, ...]
    repositories: tuple[str, ...]
    services: tuple[str, ...]
    checks: tuple[str, ...]


def analyze(changes: list[object], rules: dict[str, object]) -> Impact:
    paths = _paths(changes)
    repositories = _matches(paths, rules.get("repositories"), "repositories")
    services = _matches(paths, rules.get("services"), "services")
    checks = _matches(paths, rules.get("checks"), "checks")
    return Impact(paths, repositories, services, checks)


def write_impact(impact: Impact, path: Path) -> None:
    path.write_text(json.dumps(asdict(impact), indent=2) + "\n", encoding="utf-8")


def _paths(changes: list[object]) -> tuple[str, ...]:
    normalized: set[str] = set()
    for item in changes:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("changes must be a list of non-empty paths")
        path = item.strip().replace("\\", "/")
        if path.startswith("../") or path == "..":
            raise ValueError("changed path escapes the workspace")
        if path.startswith("/"):
            raise ValueError("changed path must be relative")
        while path.startswith("./"):
            path = path[2:]
        if not path:
            raise ValueError("changed path must not be empty")
        normalized.add(path)
    if not normalized:
        raise ValueError("changes must not be empty")
    return tuple(sorted(normalized))


def _matches(
    paths: tuple[str, ...],
    value: object,
    field: str,
) -> tuple[str, ...]:
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{field} must be a non-empty object")
    matched: list[str] = []
    for name, patterns in value.items():
        if not isinstance(name, str) or not name:
            raise ValueError(f"{field} names must be non-empty strings")
        if (
            not isinstance(patterns, list)
            or not patterns
            or any(not isinstance(pattern, str) or not pattern for pattern in patterns)
        ):
            raise ValueError(f"{field}.{name} must be a non-empty string list")
        if any(
            fnmatch.fnmatchcase(path, pattern)
            for path in paths
            for pattern in patterns
        ):
            matched.append(name)
    return tuple(sorted(matched))
