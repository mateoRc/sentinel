import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from sentinel import __version__
from sentinel.analysis import MockAnalysisProvider, assess
from sentinel.report import write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Evidence-based CI/CD release risk analysis.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command")
    assess_parser = subparsers.add_parser(
        "assess",
        help="Assess check evidence and produce release reports.",
    )
    assess_parser.add_argument("--input", type=Path, required=True)
    assess_parser.add_argument("--provider", choices=("mock",), default="mock")
    assess_parser.add_argument("--json-output", type=Path, required=True)
    assess_parser.add_argument("--markdown-output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.command != "assess":
        return 0

    try:
        payload = json.loads(arguments.input.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("input must be a JSON object")
        assessment = assess(payload, MockAnalysisProvider())
        write_json(assessment, arguments.json_output)
        write_markdown(assessment, arguments.markdown_output)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    return 0
