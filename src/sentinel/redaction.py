import re
from collections.abc import Iterable

_REPLACEMENT = "[REDACTED]"
_PATTERNS = (
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)\b("
        r"authorization|api[_-]?key|access[_-]?token|auth[_-]?token|"
        r"password|passwd|secret"
        r")(\s*[:=]\s*)([^\s,;]+)"
    ),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
)


def redact(value: str, secrets: Iterable[str] = ()) -> str:
    result = value
    explicit = sorted(
        {secret for secret in secrets if len(secret) >= 4},
        key=len,
        reverse=True,
    )
    for secret in explicit:
        result = result.replace(secret, _REPLACEMENT)
    result = _PATTERNS[0].sub(r"\1 " + _REPLACEMENT, result)
    result = _PATTERNS[1].sub(
        lambda match: f"{match.group(1)}{match.group(2)}{_REPLACEMENT}",
        result,
    )
    result = _PATTERNS[2].sub(_REPLACEMENT, result)
    return result
