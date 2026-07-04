from dataclasses import dataclass
from pathlib import Path

import yaml

_SCHEMA = "sentinel.dev/v1alpha1"


@dataclass(frozen=True)
class PolicyConfig:
    block_on_check_failure: bool
    block_on_critical_security_finding: bool
    require_approval_for_high_risk: bool


@dataclass(frozen=True)
class AgentConfig:
    enabled: bool
    provider: str
    advisory_only: bool


@dataclass(frozen=True)
class Configuration:
    project_name: str
    default_branch: str
    repositories: tuple[str, ...]
    enabled_checks: frozenset[str]
    policy: PolicyConfig
    agent: AgentConfig


def load_configuration(path: Path) -> Configuration:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ValueError(f"invalid YAML: {error}") from error
    root = _mapping(value, "configuration")
    _exact_keys(
        root,
        {
            "schema",
            "project",
            "repositories",
            "checks",
            "policy",
            "agent",
            "report",
        },
        "configuration",
    )
    if root["schema"] != _SCHEMA:
        raise ValueError(f"schema must be {_SCHEMA}")

    project = _mapping(root["project"], "project")
    _exact_keys(project, {"name", "default_branch"}, "project")
    project_name = _text(project["name"], "project.name")
    default_branch = _text(project["default_branch"], "project.default_branch")

    repositories = _repositories(root["repositories"])
    enabled_checks = _checks(root["checks"])
    policy = _policy(root["policy"])
    agent = _agent(root["agent"])
    _report(root["report"])
    return Configuration(
        project_name,
        default_branch,
        repositories,
        enabled_checks,
        policy,
        agent,
    )


def _repositories(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("repositories must be a non-empty list")
    names: list[str] = []
    for index, item in enumerate(value):
        repository = _mapping(item, f"repositories[{index}]")
        _exact_keys(repository, {"name", "path"}, f"repositories[{index}]")
        name = _text(repository["name"], f"repositories[{index}].name")
        _text(repository["path"], f"repositories[{index}].path")
        if name in names:
            raise ValueError(f"duplicate repository name: {name}")
        names.append(name)
    return tuple(names)


def _checks(value: object) -> frozenset[str]:
    checks = _mapping(value, "checks")
    _exact_keys(checks, {"regression", "security", "deployment"}, "checks")
    enabled: set[str] = set()
    for name, value in checks.items():
        options = _mapping(value, f"checks.{name}")
        _exact_keys(options, {"enabled"}, f"checks.{name}")
        if _boolean(options["enabled"], f"checks.{name}.enabled"):
            enabled.add(name)
    return frozenset(enabled)


def _policy(value: object) -> PolicyConfig:
    policy = _mapping(value, "policy")
    fields = {
        "block_on_check_failure",
        "block_on_critical_security_finding",
        "require_approval_for_high_risk",
    }
    _exact_keys(policy, fields, "policy")
    return PolicyConfig(
        block_on_check_failure=_boolean(
            policy["block_on_check_failure"],
            "policy.block_on_check_failure",
        ),
        block_on_critical_security_finding=_boolean(
            policy["block_on_critical_security_finding"],
            "policy.block_on_critical_security_finding",
        ),
        require_approval_for_high_risk=_boolean(
            policy["require_approval_for_high_risk"],
            "policy.require_approval_for_high_risk",
        ),
    )


def _agent(value: object) -> AgentConfig:
    agent = _mapping(value, "agent")
    fields = {
        "enabled",
        "provider",
        "advisory_only",
        "allow_repository_writes",
        "allow_deployment",
    }
    _exact_keys(agent, fields, "agent")
    enabled = _boolean(agent["enabled"], "agent.enabled")
    provider = _text(agent["provider"], "agent.provider")
    if provider != "mock":
        raise ValueError("agent.provider must be mock before v1")
    if _boolean(agent["allow_repository_writes"], "agent.allow_repository_writes"):
        raise ValueError("repository writes are not supported")
    if _boolean(agent["allow_deployment"], "agent.allow_deployment"):
        raise ValueError("agent deployment is not supported")
    return AgentConfig(
        enabled,
        provider,
        _boolean(agent["advisory_only"], "agent.advisory_only"),
    )


def _report(value: object) -> None:
    report = _mapping(value, "report")
    fields = {"format", "include_file_references", "include_check_evidence"}
    _exact_keys(report, fields, "report")
    if report["format"] != "markdown":
        raise ValueError("report.format must be markdown")
    _boolean(report["include_file_references"], "report.include_file_references")
    _boolean(report["include_check_evidence"], "report.include_check_evidence")


def _mapping(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{path} must be an object")
    return value


def _exact_keys(value: dict[str, object], expected: set[str], path: str) -> None:
    missing = expected - value.keys()
    unknown = value.keys() - expected
    if missing:
        raise ValueError(f"{path} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{path} unknown fields: {', '.join(sorted(unknown))}")


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    return value.strip()


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{path} must be a boolean")
    return value
