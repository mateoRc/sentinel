import json
from dataclasses import asdict
from pathlib import Path

from sentinel.models import Assessment


def write_json(assessment: Assessment, path: Path) -> None:
    path.write_text(
        json.dumps(asdict(assessment), indent=2) + "\n",
        encoding="utf-8",
    )


def write_markdown(assessment: Assessment, path: Path) -> None:
    rows = [
        "# Sentinel assessment",
        "",
        f"- Project: `{assessment.project}`",
        f"- Commit: `{assessment.commit}`",
        f"- Risk: **{assessment.risk}**",
        f"- Analysis provider: `{assessment.provider}`",
        "",
        assessment.summary,
        "",
        "## Evidence",
        "",
        "| Check | Status | Evidence |",
        "| --- | --- | --- |",
    ]
    rows.extend(
        f"| {check.name} | {check.status} | {check.evidence} |"
        for check in assessment.checks
    )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
