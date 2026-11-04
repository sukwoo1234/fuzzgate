#!/usr/bin/env python3
"""Run HDF-07 FND-03 suites and assemble the honest qualification state."""

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

import collect_hdf5_evidence as hdf5_evidence


SUITES: dict[str, tuple[tuple[str, str | None, str], ...]] = {
    "unit": (
        (
            "Q01",
            "gate_hdf5_qualification_profile.sh",
            "[hdf5-qualification-profile] pass=3 fail=0",
        ),
        ("Q05", "check_hdf5_mutation.sh", "[hdf5-mutation] pass=34 fail=0"),
    ),
    "oracle": (
        ("Q02", "check_hdf5_fixtures.sh", "[hdf5-fixtures] pass=15 fail=0"),
        ("Q03", "check_hdf5_loader.sh", "[hdf5-loader] pass=19 fail=0"),
        ("Q04", "check_hdf5_loader.sh", "[hdf5-loader] pass=19 fail=0"),
    ),
    "engine": (
        (
            "Q06",
            "gate_hdf5_qualification_instrumentation.sh",
            "[hdf5-qualification-instrumentation] pass=2 fail=0",
        ),
    ),
    "coverage": (
        (
            "Q07",
            "gate_hdf5_qualification_instrumentation.sh",
            "[hdf5-qualification-instrumentation] pass=2 fail=0",
        ),
    ),
    "integration": (
        (
            "Q08",
            "check_hdf5_integration.sh",
            "[hdf5-integration] pass=15 fail=0 blocked=0",
        ),
        (
            "Q09",
            "gate_hdf5_qualification_regressions.sh",
            "[hdf5-qualification-regressions] pass=5 fail=0",
        ),
    ),
    "performance": (
        ("Q10", None, "actual parser paired 60-second measurements remain pending"),
    ),
    "soak": (("Q11", None, "V7 long-running operation evidence remains pending"),),
    "install": (
        (
            "Q12",
            "check_hdf5_integration.sh",
            "[hdf5-integration] pass=15 fail=0 blocked=0",
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
    "kill",
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
    "build_hdf5_profiles.sh",
    "check_hdf5_fixtures.py",
    "check_hdf5_instrumentation.py",
    "check_hdf5_instrumentation.sh",
    "check_hdf5_loader.py",
    "check_hdf5_mutation.py",
    "check_hdf5_profile.py",
    "check_hdf5_scope.py",
    "check_format_dispatch.sh",
    "check_gguf_oracle_verdicts.sh",
    "check_onnx_coverage_source_scope.sh",
    "check_safetensors_engine_check.sh",
    "check_target_registry_consumers.sh",
    "collect_hdf5_evidence.py",
    "collect_tflite_evidence.py",
    "measure_format_baseline.py",
    "qualify_hdf5.py",
    "qualify_tflite.py",
    "run_coverage_hdf5.sh",
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
    profile: Path,
    target_spec: Path,
    coverage_evidence: Path,
    checker: Path | None,
    bundle_files: list[Path] | None = None,
) -> list[Path]:
    paths: set[Path] = {
        (project_root / "scripts/hdf5_qualification_task.py").resolve(strict=True),
    }
    if bundle_files is not None:
        paths.update(
            {
                (project_root / "scripts/collect_hdf5_evidence.py").resolve(strict=True),
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
            profile,
            target_spec,
            target_root / "build-profile.json",
            target_root / "linkage-manifest.json",
            target_root / "guided-instrumentation.json",
            target_root / "coverage-instrumentation.json",
            coverage_evidence,
        ):
            add_if_file(paths, path)
        fixtures = target_root / "execution-fixtures"
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
    profile: Path,
    target_spec: Path,
    coverage_evidence: Path,
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
    helper = (project_root / "scripts/hdf5_qualification_task.py").resolve(strict=True)
    task_id = f"{requirement.lower()}-hdf5"
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
                project_root,
                target_root,
                profile,
                target_spec,
                coverage_evidence,
                checker,
                evidence_files,
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
    parser.add_argument("--coverage-evidence", required=True, type=Path)
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
    coverage_evidence = args.coverage_evidence.resolve(strict=True)
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
            files = hdf5_evidence.validate_bundle(
                bundle,
                requirement=requirement,
                expected_commit=expected_commit,
                expected_profile_sha256=profile_hash,
                require_current_aa=True,
            )
        except hdf5_evidence.EvidenceError as error:
            raise RunError(f"{requirement} evidence bundle is invalid: {error}") from error
        evidence_by_requirement[requirement] = (bundle, files)
    evidence_root.mkdir(mode=0o700, parents=False)
    requirements_root.mkdir(mode=0o700, parents=False)
    python = Path(sys.executable).resolve(strict=True)
    acceptance = (project_root / "scripts/check_format_acceptance.py").resolve(strict=True)
    assembler = (project_root / "scripts/qualify_hdf5.py").resolve(strict=True)
    tool = (project_root / "target/debug/tool").resolve(strict=True)
    target_spec = requirements_root / "hdf5-target-spec.json"
    completed = subprocess.run(
        [str(tool), "target-spec", "--target", "hdf5-weights", "--format", "json"],
        cwd=project_root,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout:
        raise RunError(
            "could not snapshot the hdf5-weights target spec: "
            + completed.stderr.decode(errors="replace")
        )
    target_spec.write_bytes(completed.stdout)

    allowed_env = {
        "LC_ALL": "C",
        "PROJECT_ROOT": str(project_root),
        "TOOL_BIN": str(tool),
        "HDF5_TARGET_ROOT": str(target_root),
        "HDF5_PROFILE": str(profile),
        "HDF5_TARGET_SPEC": str(target_spec),
        "HDF5_GUIDED_BUILD_DIR": os.environ.get(
            "HDF5_GUIDED_BUILD_DIR", str(target_root / "build/guided-harness")
        ),
        "HDF5_COVERAGE_BUILD_DIR": os.environ.get(
            "HDF5_COVERAGE_BUILD_DIR", str(target_root / "build/coverage-harness")
        ),
        "HDF5_COVERAGE_EVIDENCE": str(coverage_evidence),
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
                    profile,
                    target_spec,
                    coverage_evidence,
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
            "target_id": "hdf5-weights",
            "suite": suite,
            "profile_sha256": profile_hash,
            "requirements": [
                {
                    "requirement_id": requirement,
                    "required_task_ids": [f"{requirement.lower()}-hdf5"],
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
                "hdf5-weights",
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
        print(f"HDF07_SUITE_OK=yes suite={suite} rc={completed.returncode}")

    completed = subprocess.run(
        [
            str(python),
            "-B",
            str(assembler),
            "--profile",
            str(profile),
            "--build-profile",
            str(target_root / "build-profile.json"),
            "--target-spec",
            str(target_spec),
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
        "HDF07_RUN_OK=yes "
        f"status={args.status} evidence={evidence_root} "
        f"requirements={requirements_root} qualification={qualification_output}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RunError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"[hdf5-qualification-run] fail: {error}", file=sys.stderr)
        raise SystemExit(1)
