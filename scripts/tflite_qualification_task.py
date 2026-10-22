#!/usr/bin/env python3
"""FND-03 child for one TFLite qualification requirement."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


RESULT_ENV = "FORMAT_ACCEPTANCE_RESULT_PATH"
VALIDATION_ENV = "TOOL_VALIDATION_RUN"
FORWARDED_ENV = (
    "PROJECT_ROOT",
    "TOOL_BIN",
    "TFLITE_TARGET_ROOT",
    "TFLITE_REPLAY",
    "TFLITE_FUZZER",
    "TFLITE_MUTATOR",
    "TFLITE_GUIDED_BUILD_DIR",
    "TFLITE_COVERAGE_BUILD_DIR",
    "NM",
)


def emit(status: str, reason: str, expected: Any, observed: Any) -> None:
    result_path_value = os.environ.get(RESULT_ENV)
    validation_run = os.environ.get(VALIDATION_ENV)
    if not result_path_value or not validation_run:
        raise RuntimeError("FND-03 result or validation identity is missing")
    result_path = Path(result_path_value)
    value = {
        "schema_version": "1",
        "status": status,
        "reason": reason,
        "expected": expected,
        "observed": observed,
        "validation_run_id": validation_run,
        "corpus_index_sha256": None,
        "artifacts": [],
    }
    payload = (
        json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(result_path, flags, 0o600)
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    gate = subparsers.add_parser("gate")
    gate.add_argument("--checker", required=True, type=Path)
    gate.add_argument("--marker", required=True)
    gate.add_argument("--isolated-cwd", action="store_true")
    blocked = subparsers.add_parser("blocked")
    blocked.add_argument("--reason", required=True)
    evidence = subparsers.add_parser("evidence")
    evidence.add_argument("--bundle", required=True, type=Path)
    evidence.add_argument("--requirement", required=True, choices=("Q10", "Q11"))
    evidence.add_argument("--expected-commit", required=True)
    evidence.add_argument("--expected-profile-sha256", required=True)
    evidence.add_argument("--require-current-aa", action="store_true")
    args = parser.parse_args()

    if args.mode == "blocked":
        emit("blocked", args.reason, "independent measured evidence", None)
        return 0

    if args.mode == "evidence":
        import collect_tflite_evidence as tflite_evidence

        try:
            identities = tflite_evidence.validate_bundle(
                args.bundle,
                requirement=args.requirement,
                expected_commit=args.expected_commit,
                expected_profile_sha256=args.expected_profile_sha256,
                require_current_aa=args.require_current_aa,
            )
        except tflite_evidence.EvidenceError as error:
            emit(
                "fail",
                "complete Q10/Q11 bundle failed full revalidation",
                {"requirement": args.requirement, "verdict": "pass"},
                {"error": str(error)},
            )
            return 0
        emit(
            "pass",
            "complete Q10/Q11 bundle passed full revalidation",
            {"requirement": args.requirement, "verdict": "pass"},
            {"identity_file_count": len(identities)},
        )
        return 0

    checker = args.checker
    if not checker.is_absolute() or not checker.is_file() or checker.is_symlink():
        emit("fail", "checker is not a regular absolute file", str(checker), None)
        return 0
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    for name in FORWARDED_ENV:
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value
    if args.isolated_cwd:
        cwd_scope = tempfile.TemporaryDirectory(prefix="tflite-qualification-cwd-")
        checker_cwd = cwd_scope.name
    else:
        cwd_scope = None
        checker_cwd = os.environ.get("PROJECT_ROOT", "/")
    try:
        completed = subprocess.run(
            ["/usr/bin/bash", "-p", str(checker)],
            cwd=checker_cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    finally:
        if cwd_scope is not None:
            cwd_scope.cleanup()
    sys.stdout.buffer.write(completed.stdout)
    sys.stderr.buffer.write(completed.stderr)
    marker_found = args.marker.encode() in completed.stdout.splitlines()
    status = "pass" if completed.returncode == 0 and marker_found else "fail"
    emit(
        status,
        "checker returned rc0 with the exact terminal marker" if status == "pass" else "checker failed or omitted its exact terminal marker",
        {"exit_code": 0, "marker": args.marker},
        {"exit_code": completed.returncode, "marker_found": marker_found},
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
