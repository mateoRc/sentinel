import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from sentinel import __version__
from sentinel.analysis import MockAnalysisProvider, assess
from sentinel.checks import default_registry
from sentinel.collection import collect, write_evidence
from sentinel.config import load_configuration
from sentinel.policy import Decision
from sentinel.report import write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Evidence-based CI/CD release risk analysis.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")
    collect_parser = subparsers.add_parser(
        "collect",
        help="Run deterministic checks and write normalized evidence.",
    )
    collect_parser.add_argument("--plan", type=Path, required=True)
    collect_parser.add_argument("--workspace", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    assess_parser = subparsers.add_parser(
        "assess",
        help="Assess check evidence and produce release reports.",
    )
    assess_parser.add_argument("--input", type=Path, required=True)
    assess_parser.add_argument("--config", type=Path, required=True)
    assess_parser.add_argument("--provider", choices=("mock",), default="mock")
    assess_parser.add_argument("--json-output", type=Path, required=True)
    assess_parser.add_argument("--markdown-output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "collect":
        try:
            plan = json.loads(arguments.plan.read_text(encoding="utf-8"))
            if not isinstance(plan, dict):
                raise ValueError("plan must be a JSON object")
            evidence = collect(plan, arguments.workspace, default_registry())
            write_evidence(evidence, arguments.output)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            parser.error(str(error))
        return 0
    if arguments.command != "assess":
        return 0

    try:
        payload = json.loads(arguments.input.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("input must be a JSON object")
        configuration = load_configuration(arguments.config)
        if payload.get("project") != configuration.project_name:
            raise ValueError("evidence project does not match configuration")
        if arguments.provider != configuration.agent.provider:
            raise ValueError("provider does not match configuration")
        assessment = assess(
            payload,
            MockAnalysisProvider(),
            configuration.policy,
            configuration.agent.advisory_only,
        )
        write_json(assessment, arguments.json_output)
        write_markdown(assessment, arguments.markdown_output)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    if assessment.decision in {Decision.BLOCKED, Decision.APPROVAL_REQUIRED}:
        return 1
    return 0
