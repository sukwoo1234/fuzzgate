#!/usr/bin/env python3
"""Run one explicit format-acceptance suite and preserve fail-closed evidence."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from lib.format_acceptance import ConfigurationError, run_acceptance  # noqa: E402


SUITES = (
    "unit",
    "oracle",
    "engine",
    "coverage",
    "integration",
    "performance",
    "soak",
    "install",
)


def _safe_error_text(error: BaseException) -> str:
    return str(error).encode("utf-8", "backslashreplace").decode("utf-8")


class ContractArgumentParser(argparse.ArgumentParser):
    """Map invocation errors to the validator's documented rc=64 contract."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = ContractArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="exact target_id from the profile")
    parser.add_argument(
        "--profile",
        required=True,
        type=Path,
        help="absolute immutable target profile path",
    )
    parser.add_argument("--suite", required=True, choices=SUITES)
    parser.add_argument(
        "--requirements",
        required=True,
        type=Path,
        help="absolute suite/requirements JSON path",
    )
    parser.add_argument(
        "--evidence-dir",
        required=True,
        type=Path,
        help="absolute path to a new evidence directory",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run_acceptance(
            target=args.target,
            profile_path=args.profile,
            suite=args.suite,
            evidence_dir=args.evidence_dir,
            requirements_path=args.requirements,
            entrypoint_path=Path(__file__).resolve(),
        )
    except ConfigurationError as error:
        print(
            f"format-acceptance: configuration error: {_safe_error_text(error)}",
            file=sys.stderr,
        )
        return 64
    except Exception as error:
        print(
            "format-acceptance: evidence incomplete: internal error: "
            f"{_safe_error_text(error)}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
