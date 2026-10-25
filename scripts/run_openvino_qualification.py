#!/usr/bin/env python3
"""Run OVI-07 FND-03 suites and assemble the honest qualification state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import collect_openvino_evidence as openvino_evidence


SUITES: dict[str, tuple[tuple[str, str | None, str], ...]] = {
    "unit": (
        (
            "Q01",
            "gate_openvino_qualification_profile.sh",
            "[openvino-qualification-profile] pass=2 fail=0",
        ),
        ("Q05", "check_openvino_mutation.sh", "[openvino-mutation] pass=18 fail=0"),
    ),
    "oracle": (
        ("Q02", "check_openvino_fixtures.sh", "[openvino-fixtures] pass=14 fail=0"),
        ("Q03", "check_openvino_loader.sh", "[openvino-loader] pass=10 fail=0"),
        ("Q04", "check_openvino_loader.sh", "[openvino-loader] pass=10 fail=0"),
    ),
    "engine": (
        (
            "Q06",
            "check_openvino_instrumentation.sh",
            "[openvino-instrumentation] pass=1 fail=0 blocked=0",
        ),
    ),
    "coverage": (
        (
            "Q07",
            "check_openvino_instrumentation.sh",
            "[openvino-instrumentation] pass=1 fail=0 blocked=0",
        ),
    ),
    "integration": (
        (
            "Q08",
            "check_openvino_integration.sh",
            "[openvino-integration] pass=15 fail=0 blocked=0",
        ),
        (
            "Q09",
            "gate_openvino_qualification_regressions.sh",
            "[openvino-qualification-regressions] pass=2 fail=0",
        ),
    ),
    "performance": (
        ("Q10", None, "actual parser paired 60-second measurements remain pending"),
    ),
    "soak": (
        ("Q11", None, "V7 long-running operation evidence remains pending"),
    ),
    "install": (
        (
            "Q12",
            "check_openvino_integration.sh",
            "[openvino-integration] pass=15 fail=0 blocked=0",
        ),
    ),
}
SYSTEM_COMMANDS = (
    "awk",
    "bash",
    "cmp",
    "cp",
    "cut",
    "env",
    "find",
    "grep",
    "head",
    "mkdir",
    "mktemp",
    "python3",
    "readlink",
    "realpath",
    "sed",
    "sha256sum",
    "sort",
    "stat",
    "tail",
    "timeout",
)
EXTRA_SCRIPT_DEPENDENCIES = (
    "build_openvino_profiles.sh",
    "check_openvino_fixtures.py",
    "check_openvino_instrumentation.py",
    "check_openvino_loader.py",
    "check_openvino_mutation.py",
    "collect_openvino_evidence.py",
    "collect_tflite_evidence.py",
    "measure_format_baseline.py",
    "model_bundle.py",
    "qualify_tflite.py",
    "run_coverage_openvino.sh",
)


class RunError(Exception):
    pass


def canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def regular_identity(path: Path) -> dict[str, str]:
    resolved = path.resolve(strict=True)
    if resolved != Path(os.path.abspath(path)) or not resolved.is_file():
        raise RunError(f"identity path is not a canonical regular file: {path}")
    return {"path": str(resolved), "sha256": digest(resolved)}


def command_path(name: str) -> Path:
    value = shutil.which(name, path="/usr/bin:/bin")
    if value is None:
        raise RunError(f"required command is unavailable: {name}")
    return Path(value).resolve(strict=True)


def add_if_file(paths: set[Path], path: Path) -> None:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return
    if resolved.is_file():
        paths.add(resolved)


def identity_paths(
    project_root: Path,
    target_root: Path,
    checker: Path | None,
    bundle_files: list[Path] | None = None,
) -> list[Path]:
    paths: set[Path] = {
        (project_root / "scripts/openvino_qualification_task.py").resolve(strict=True),
    }
    if bundle_files is not None:
        paths.update(
            {
                (project_root / "scripts/collect_openvino_evidence.py").resolve(strict=True),
                (project_root / "scripts/collect_tflite_evidence.py").resolve(strict=True),
                (project_root / "scripts/measure_format_baseline.py").resolve(strict=True),
                *bundle_files,
            }
        )
    else:
        paths.update(command_path(name) for name in SYSTEM_COMMANDS)
    if checker is not None:
        paths.add(checker.resolve(strict=True))
    if bundle_files is None:
        for name in EXTRA_SCRIPT_DEPENDENCIES:
            add_if_file(paths, project_root / "scripts" / name)
        for path in (
            project_root / "target/debug/tool",
            project_root / "src/main.rs",
            target_root / "profile.json",
            target_root / "build-profile.json",
            target_root / "linkage-manifest.json",
            target_root / "guided-instrumentation.json",
            target_root / "coverage-instrumentation.json",
            target_root / "instrumentation-evidence/coverage/coverage.json",
        ):
            add_if_file(paths, path)
        fixtures = target_root / "instrumentation-fixtures"
        if fixtures.is_dir():
            for path in fixtures.iterdir():
                add_if_file(paths, path)
    ordered = sorted(paths, key=str)
    if len(ordered) > 64:
        raise RunError(f"task identity inventory exceeds FND-03 limit: {len(ordered)}")
    return ordered


def task(
    project_root: Path,
    target_root: Path,
    python: Path,
    requirement: str,
    checker_name: str | None,
    marker_or_reason: str,
    allowed_env: dict[str, str],
    evidence_bundle: Path | None,
    evidence_files: list[Path] | None,
    expected_commit: str,
    expected_profile_sha256: str,
) -> dict[str, Any]:
    helper = (project_root / "scripts/openvino_qualification_task.py").resolve(
        strict=True
    )
    task_id = f"{requirement.lower()}-openvino"
    checker = (
        (project_root / "scripts" / checker_name).resolve(strict=True)
        if checker_name
        else None
    )
    if evidence_bundle is not None:
        argv = [
            str(python),
            "-B",
            str(helper),
            "evidence",
            "--bundle",
            str(evidence_bundle),
            "--requirement",
            requirement,
            "--expected-commit",
            expected_commit,
            "--expected-profile-sha256",
            expected_profile_sha256,
            "--require-current-aa",
        ]
    elif checker is None:
        argv = [str(python), "-B", str(helper), "blocked", "--reason", marker_or_reason]
    else:
        argv = [
            str(python),
            "-B",
            str(helper),
            "gate",
            "--checker",
            str(checker),
            "--marker",
            marker_or_reason,
        ]
        if requirement == "Q12":
            argv.append("--isolated-cwd")
    return {
        "task_id": task_id,
        "requirement_id": requirement,
        "command_argv": argv,
        "cwd": str(project_root),
        "identity_files": [
            regular_identity(path)
            for path in identity_paths(
                project_root, target_root, checker, evidence_files
            )
        ],
        "allowed_env": allowed_env,
        "timeout_ms": 900000,
        "stdout_limit_bytes": 8 * 1024 * 1024,
        "stderr_limit_bytes": 8 * 1024 * 1024,
        "depends_on": [],
        "corpus_index_sha256": None,
        "artifacts": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--requirements-root", required=True, type=Path)
    parser.add_argument("--qualification-output", required=True, type=Path)
    parser.add_argument("--q10-evidence", type=Path)
    parser.add_argument("--q11-evidence", type=Path)
    parser.add_argument(
        "--status", choices=("smoke_passed", "verified"), default="smoke_passed"
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    profile = args.profile.resolve(strict=True)
    target_root = args.target_root.resolve(strict=True)
    evidence_root = args.evidence_root.absolute()
    requirements_root = args.requirements_root.absolute()
    qualification_output = args.qualification_output.absolute()
    if evidence_root.exists() or requirements_root.exists():
        raise RunError("evidence and requirements roots must be new paths")
    profile_hash = digest(profile)
    expected_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
    evidence_by_requirement: dict[str, tuple[Path, list[Path]]] = {}
    for requirement, value in (("Q10", args.q10_evidence), ("Q11", args.q11_evidence)):
        if value is None:
            continue
        bundle = value.resolve(strict=True)
        try:
            files = openvino_evidence.validate_bundle(
                bundle,
                requirement=requirement,
                expected_commit=expected_commit,
                expected_profile_sha256=profile_hash,
                require_current_aa=True,
            )
        except openvino_evidence.EvidenceError as error:
            raise RunError(f"{requirement} evidence bundle is invalid: {error}") from error
        evidence_by_requirement[requirement] = (bundle, files)
    evidence_root.mkdir(mode=0o700, parents=False)
    requirements_root.mkdir(mode=0o700, parents=False)
    python = Path(sys.executable).resolve(strict=True)
    acceptance = (project_root / "scripts/check_format_acceptance.py").resolve(strict=True)
    assembler = (project_root / "scripts/qualify_openvino.py").resolve(strict=True)

    allowed_env = {
        "LC_ALL": "C",
        "PROJECT_ROOT": str(project_root),
        "TOOL_BIN": str((project_root / "target/debug/tool").resolve(strict=True)),
        "OPENVINO_TARGET_ROOT": str(target_root),
        "OPENVINO_PROFILE": str(profile),
        "OPENVINO_GUIDED_BUILD_DIR": os.environ.get(
            "OPENVINO_GUIDED_BUILD_DIR", str(target_root / "build/guided-harness")
        ),
        "OPENVINO_COVERAGE_BUILD_DIR": os.environ.get(
            "OPENVINO_COVERAGE_BUILD_DIR", str(target_root / "build/coverage-harness")
        ),
    }
    if "NM" in os.environ:
        allowed_env["NM"] = os.environ["NM"]

    for suite, entries in SUITES.items():
        tasks = []
        suite_is_blocked = False
        for requirement, checker, marker in entries:
            evidence = evidence_by_requirement.get(requirement)
            if checker is None and evidence is None:
                suite_is_blocked = True
            tasks.append(
                task(
                    project_root,
                    target_root,
                    python,
                    requirement,
                    checker,
                    marker,
                    allowed_env,
                    evidence[0] if evidence is not None else None,
                    evidence[1] if evidence is not None else None,
                    expected_commit,
                    profile_hash,
                )
            )
        requirements = {
            "schema_version": "1",
            "target_id": "openvino-ir",
            "suite": suite,
            "profile_sha256": profile_hash,
            "requirements": [
                {
                    "requirement_id": requirement,
                    "required_task_ids": [f"{requirement.lower()}-openvino"],
                }
                for requirement, _checker, _marker in entries
            ],
            "tasks": tasks,
        }
        requirements_path = requirements_root / f"{suite}.json"
        requirements_path.write_bytes(canonical(requirements))
        evidence_dir = evidence_root / suite
        completed = subprocess.run(
            [
                str(python),
                "-B",
                str(acceptance),
                "--target",
                "openvino-ir",
                "--profile",
                str(profile),
                "--suite",
                suite,
                "--requirements",
                str(requirements_path),
                "--evidence-dir",
                str(evidence_dir),
            ],
            cwd=project_root,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        expected_rc = 2 if suite_is_blocked else 0
        if completed.returncode != expected_rc:
            raise RunError(
                f"{suite} acceptance suite returned rc={completed.returncode}, "
                f"expected {expected_rc}"
            )
        print(f"OVI07_SUITE_OK=yes suite={suite} rc={completed.returncode}")

    completed = subprocess.run(
        [
            str(python),
            "-B",
            str(assembler),
            "--profile",
            str(profile),
            "--evidence-root",
            str(evidence_root),
            "--output",
            str(qualification_output),
            "--status",
            args.status,
        ],
        cwd=project_root,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        check=False,
    )
    if completed.returncode != 0:
        raise RunError(f"qualification assembler returned rc={completed.returncode}")
    print(
        "OVI07_RUN_OK=yes "
        f"status={args.status} evidence={evidence_root} "
        f"requirements={requirements_root} qualification={qualification_output}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RunError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"[openvino-qualification-run] fail: {error}", file=sys.stderr)
        raise SystemExit(1)
