from dataclasses import dataclass
from enum import StrEnum


class CheckStatus(StrEnum):
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Check:
    name: str
    status: CheckStatus
    evidence: str
    source: str


@dataclass(frozen=True)
class Assessment:
    project: str
    commit: str
    analyzed_at: str
    risk: Risk
    checks: tuple[Check, ...]
    summary: str
    provider: str
