import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, Protocol

from sentinel.models import Check, CheckStatus
from sentinel.redaction import redact

_ALLOWED_EXECUTABLES = frozenset({"docker"})
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_MAX_COMMAND_PARTS = 32
_MAX_TIMEOUT_SECONDS = 1200
_EVIDENCE_TAIL_BYTES = 1000


class CheckAdapter(Protocol):
    kind: str

    def run(self, specification: Mapping[str, object], workspace: Path) -> Check: ...


class CheckRegistry:
    def __init__(self, adapters: tuple[CheckAdapter, ...]) -> None:
        self._adapters = {adapter.kind: adapter for adapter in adapters}

    def run_all(
        self,
        specifications: list[object],
        workspace: Path,
    ) -> tuple[Check, ...]:
        checks: list[Check] = []
        for specification in specifications:
            if not isinstance(specification, dict):
                raise ValueError("each check specification must be an object")
            kind = _required_text(specification, "kind")
            adapter = self._adapters.get(kind)
            if adapter is None:
                raise ValueError(f"unsupported check adapter: {kind}")
            checks.append(adapter.run(specification, workspace))
        return tuple(checks)


class CommandCheckAdapter:
    kind = "command"

    def run(self, specification: Mapping[str, object], workspace: Path) -> Check:
        name = _required_text(specification, "name")
        command = _command(specification.get("command"))
        working_directory = _working_directory(
            workspace,
            specification.get("working_directory", "."),
        )
        timeout = _timeout(specification.get("timeout_seconds", 600))
        environment = _environment(specification.get("environment", {}))

        started = time.monotonic()
        with tempfile.TemporaryFile() as output:
            try:
                completed = subprocess.run(
                    command,
                    cwd=working_directory,
                    env={**os.environ, **environment},
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                    check=False,
                )
                duration = time.monotonic() - started
                if completed.returncode == 0:
                    return Check(
                        name,
                        CheckStatus.PASSED,
                        f"completed in {duration:.1f}s",
                        " ".join(command),
                    )
                return Check(
                    name,
                    CheckStatus.FAILED,
                    redact(
                        f"exit {completed.returncode}: {_tail(output)}",
                        environment.values(),
                    ),
                    redact(" ".join(command), environment.values()),
                )
            except subprocess.TimeoutExpired:
                return Check(
                    name,
                    CheckStatus.FAILED,
                    f"timed out after {timeout}s",
                    " ".join(command),
                )
            except OSError as error:
                return Check(
                    name,
                    CheckStatus.FAILED,
                    f"could not start: {error}",
                    redact(" ".join(command), environment.values()),
                )


class ExternalResultAdapter:
    kind = "external"

    def run(self, specification: Mapping[str, object], workspace: Path) -> Check:
        del workspace
        name = _required_text(specification, "name")
        evidence = redact(_required_text(specification, "evidence"))
        source = redact(_required_text(specification, "source"))
        try:
            status = CheckStatus(_required_text(specification, "status"))
        except ValueError as error:
            raise ValueError(f"invalid status for check {name}") from error
        return Check(name, status, evidence, source)


class HTTPJSONCheckAdapter:
    kind = "http_json"

    def run(self, specification: Mapping[str, object], workspace: Path) -> Check:
        del workspace
        name = _required_text(specification, "name")
        url = _local_url(_required_text(specification, "url"))
        payload = specification.get("json")
        if not isinstance(payload, dict):
            raise ValueError("json must be an object")
        expected = specification.get("expected")
        if not isinstance(expected, dict) or not expected:
            raise ValueError("expected must be a non-empty object")
        contains = specification.get("contains", {})
        if not isinstance(contains, dict):
            raise ValueError("contains must be an object")
        timeout = _timeout(specification.get("timeout_seconds", 10))
        request = urllib.request.Request(
            url,
            data=json_bytes(payload),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                value = json_load(response.read())
        except (OSError, urllib.error.URLError, ValueError) as error:
            return Check(
                name,
                CheckStatus.FAILED,
                redact(f"request failed: {error}"),
                url,
            )
        mismatches = _mismatches(value, expected, contains)
        if mismatches:
            return Check(
                name,
                CheckStatus.FAILED,
                redact("; ".join(mismatches)),
                url,
            )
        return Check(
            name,
            CheckStatus.PASSED,
            f"{len(expected) + len(contains)} response assertions passed",
            url,
        )


class FilePolicyAdapter:
    kind = "file_policy"

    def run(self, specification: Mapping[str, object], workspace: Path) -> Check:
        name = _required_text(specification, "name")
        relative_path = _required_text(specification, "path")
        path = _workspace_file(workspace, relative_path)
        required = specification.get("required")
        if (
            not isinstance(required, list)
            or not required
            or any(not isinstance(item, str) or not item for item in required)
        ):
            raise ValueError("required must be a non-empty string list")
        forbidden = specification.get("forbidden", [])
        if not isinstance(forbidden, list) or any(
            not isinstance(item, str) or not item for item in forbidden
        ):
            raise ValueError("forbidden must be a string list")

        content = path.read_text(encoding="utf-8")
        missing = [item for item in required if item not in content]
        present = [item for item in forbidden if item in content]
        if missing or present:
            details: list[str] = []
            if missing:
                details.append(f"missing: {', '.join(missing)}")
            if present:
                details.append(f"forbidden: {', '.join(present)}")
            return Check(
                name,
                CheckStatus.FAILED,
                "; ".join(details),
                relative_path,
            )
        return Check(
            name,
            CheckStatus.PASSED,
            f"{len(required)} required and {len(forbidden)} forbidden markers checked",
            relative_path,
        )


def default_registry() -> CheckRegistry:
    return CheckRegistry(
        (
            CommandCheckAdapter(),
            ExternalResultAdapter(),
            FilePolicyAdapter(),
            HTTPJSONCheckAdapter(),
        )
    )


def _command(value: object) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > _MAX_COMMAND_PARTS:
        raise ValueError("command must be a non-empty string list")
    command: list[str] = []
    for part in value:
        if not isinstance(part, str) or not part:
            raise ValueError("command must be a non-empty string list")
        command.append(part)
    if command[0] not in _ALLOWED_EXECUTABLES:
        raise ValueError(f"executable is not allowed: {command[0]}")
    return command


def _working_directory(workspace: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("working_directory must be a non-empty string")
    root = workspace.resolve()
    candidate = (root / value).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("working_directory escapes the workspace")
    if not candidate.is_dir():
        raise ValueError(f"working_directory does not exist: {value}")
    return candidate


def _workspace_file(workspace: Path, value: str) -> Path:
    root = workspace.resolve()
    candidate = (root / value).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("path escapes the workspace")
    if not candidate.is_file():
        raise ValueError(f"file does not exist: {value}")
    return candidate


def _timeout(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("timeout_seconds must be an integer")
    if value <= 0 or value > _MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds must be between 1 and {_MAX_TIMEOUT_SECONDS}")
    return value


def _environment(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("environment must be an object")
    environment: dict[str, str] = {}
    for name, item in value.items():
        if (
            not isinstance(name, str)
            or not _ENVIRONMENT_NAME.fullmatch(name)
            or not isinstance(item, str)
        ):
            raise ValueError("environment entries must be uppercase string pairs")
        environment[name] = item
    return environment


def _required_text(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return item.strip()


def _tail(output: BinaryIO) -> str:
    output.seek(0, os.SEEK_END)
    size = output.tell()
    output.seek(max(0, size - _EVIDENCE_TAIL_BYTES))
    text = output.read().decode("utf-8", errors="replace")
    return " ".join(text.split()) or "no output"


def _local_url(value: str) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("http_json URL must use local HTTP")
    return value


def json_bytes(value: dict[str, object]) -> bytes:
    import json

    return json.dumps(value).encode("utf-8")


def json_load(value: bytes) -> dict[str, object]:
    import json

    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise ValueError("response must be a JSON object")
    return decoded


def _mismatches(
    value: dict[str, object],
    expected: dict[object, object],
    contains: dict[object, object],
) -> list[str]:
    mismatches: list[str] = []
    for key, item in expected.items():
        if not isinstance(key, str):
            raise ValueError("expected keys must be strings")
        if value.get(key) != item:
            mismatches.append(f"{key} did not equal expected value")
    for key, item in contains.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError("contains entries must be string pairs")
        actual = value.get(key)
        if not isinstance(actual, str) or item not in actual:
            mismatches.append(f"{key} did not contain expected text")
    return mismatches
