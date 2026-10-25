#!/usr/bin/env python3
"""Isolated negative controls for the TFL-07 qualification assembler."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any


SUITE_REQUIREMENTS = {
    "unit": ("Q01", "Q05"),
    "oracle": ("Q02", "Q03", "Q04"),
    "engine": ("Q06",),
    "coverage": ("Q07",),
    "integration": ("Q08", "Q09"),
    "performance": ("Q10",),
    "soak": ("Q11",),
    "install": ("Q12",),
}
COMMIT = "1" * 40


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


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def write_json(path: Path, value: Any) -> str:
    payload = canonical(value)
    path.write_bytes(payload)
    return digest_bytes(payload)


def make_profile(root: Path, target_id: str = "tflite") -> Path:
    identity = root / "identity.bin"
    identity.write_bytes(b"tflite-qualification-selftest\n")
    identity.chmod(0o700)
    identity_hash = digest(identity)
    openvino = target_id == "openvino-ir"
    profile = {
        "schema_version": "1",
        "target_id": target_id,
        "format_revision": "ir-v11" if openvino else "3",
        "loader_id": "openvino-ir-frontend" if openvino else "tensorflow-lite",
        "loader_version": "2026.4.1" if openvino else "v2.20.0",
        "source_artifacts": [
            {
                "url": "https://github.com/openvinotoolkit/openvino/archive/refs/tags/2026.4.1.tar.gz"
                if openvino
                else "https://github.com/tensorflow/tensorflow/archive/refs/tags/v2.20.0.tar.gz",
                "tag": "2026.4.1" if openvino else "v2.20.0",
                "resolved_commit": "e213a14725769a6a2bf86fc86650aa78a9c05d3e"
                if openvino
                else "72fbba3d20f4616d7312b5e2b7f79daf6e82f2fa",
                "sha256": "1ee85264556025486a4745a2d452ea823c578b3d162768bfef590366d2e6c539"
                if openvino
                else "2" * 64,
                "size_bytes": 71349787 if openvino else 1,
            }
        ],
        "patches": []
        if openvino
        else [{"order": 1, "path": str(identity), "sha256": identity_hash}],
        "toolchain": {
            "compiler": {"version": "1", "path": str(identity), "sha256": identity_hash},
            "linker": {"version": "1", "path": str(identity), "sha256": identity_hash},
            "engine": {"version": "1", "path": str(identity), "sha256": identity_hash},
            "python": None,
            "rust": None,
            "environment": {},
        },
        "sanitizer_policy": {
            "compile_flags": ["-O1"],
            "recovery": "abort",
            "runtime_env": {"LC_ALL": "C"},
            "rust_panic": "abort",
        },
        "binaries": [
            {
                "role": "replay",
                "path": str(identity),
                "sha256": identity_hash,
                "argv": ["{input}"],
                "linked_libraries": [],
            }
        ]
        + (
            [
                {
                    "role": "fuzzer",
                    "path": str(identity),
                    "sha256": identity_hash,
                    "argv": ["{corpus_dir}"],
                    "linked_libraries": [],
                }
            ]
            if openvino
            else []
        ),
        "input_kind": {
            "kind": "fzb1" if openvino else "single",
            "extensions": ["fzb" if openvino else "tflite"],
            "subformats": ["model.bin", "model.xml"] if openvino else [],
        },
        "depth": "read-validate-constants" if openvino else "load-allocate-access",
        "engine_capabilities": [
            {
                "backend": "local-harness",
                "binary_role": "replay",
                "required_mode": "native",
                "instrumentation_scope": "openvino-core+ir-frontend"
                if openvino
                else "tensorflow/lite",
            }
        ],
        "limits": {
            "max_input_bytes": 1024,
            "memory_bytes": 1048576,
            "input_timeout_ms": 1000,
            "block_timeout_ms": 2000,
            "threads": 1,
            "workers": 1,
        },
        "coverage_scope": {
            "unit": "source-line",
            "include_sources": ["src/core", "src/frontends/ir"]
            if openvino
            else ["tensorflow/lite/**"],
            "exclude_sources": [] if openvino else ["**/*_test.cc"],
        },
    }
    path = root / "profile.json"
    write_json(path, profile)
    return path


def make_suite(
    evidence_root: Path,
    suite: str,
    profile_hash: str,
    task_identity: Path,
    *,
    dirty: str | None = None,
    commit: str = COMMIT,
    incomplete: set[str] | None = None,
    target_id: str = "tflite",
) -> None:
    incomplete = incomplete or set()
    root = evidence_root / suite
    for name in ("records", "logs", "tasks", "requirements"):
        (root / name).mkdir(parents=True, exist_ok=True)
    requirement_ids = list(SUITE_REQUIREMENTS[suite])
    task_ids = [f"{requirement.lower()}-task" for requirement in requirement_ids]
    run = {
        "schema_version": "1",
        "state": "incomplete",
        "target_id": target_id,
        "suite": suite,
        "profile_path": "/fixture/profile.json",
        "profile_sha256": profile_hash,
        "requirements_path": "/fixture/requirements.json",
        "requirements_sha256": "3" * 64,
        "required_requirement_ids": requirement_ids,
        "required_task_ids": task_ids,
        "validator": "format-acceptance-v1",
        "tool_commit": commit,
        "dirty_diff_sha256": dirty,
        "validation_run_id": f"FND03-{suite}-fixture",
        "start_utc": "2026-10-21T00:00:00.000000Z",
    }
    run_hash = write_json(root / "run.json", run)
    record_hashes: dict[str, str] = {}
    requirement_hashes: dict[str, str] = {}
    counts = {name: 0 for name in ("pass", "fail", "blocked", "not_run", "inconclusive")}
    overall = "pass"
    task_identity_hash = digest(task_identity)
    task_identity_size = task_identity.stat().st_size

    for requirement, task_id in zip(requirement_ids, task_ids, strict=True):
        status = "blocked" if requirement in incomplete else "pass"
        if status != "pass":
            overall = "incomplete"
        counts[status] += 1
        stdout = b"fixture evidence\n"
        stderr = b""
        (root / "logs" / f"{task_id}.stdout").write_bytes(stdout)
        (root / "logs" / f"{task_id}.stderr").write_bytes(stderr)
        task_dir = root / "tasks" / task_id
        task_dir.mkdir()
        result = {
            "schema_version": "1",
            "status": status,
            "reason": "fixture",
            "expected": "pass",
            "observed": status,
            "validation_run_id": f"FND03-{suite}-fixture-child",
            "corpus_index_sha256": None,
            "artifacts": [],
        }
        result_hash = write_json(task_dir / "result.json", result)
        record = {
            "schema_version": "1",
            "requirement_id": requirement,
            "task_id": task_id,
            "status": status,
            "reason": "fixture",
            "expected": "pass",
            "observed": status,
            "command_argv": [str(task_identity)],
            "command_executable": {
                "path": str(task_identity),
                "sha256": task_identity_hash,
                "size_bytes": task_identity_size,
            },
            "identity_files": [
                {
                    "path": str(task_identity),
                    "sha256": task_identity_hash,
                    "size_bytes": task_identity_size,
                }
            ],
            "cwd": "/fixture",
            "allowed_env": {},
            "tool_commit": commit,
            "dirty_diff_sha256": dirty,
            "validation_run_id": result["validation_run_id"],
            "profile_sha256": profile_hash,
            "corpus_index_sha256": None,
            "start_utc": "2026-10-21T00:00:00.000000Z",
            "end_utc": "2026-10-21T00:00:01.000000Z",
            "elapsed_ms": 1000,
            "exit_code": 0,
            "signal": None,
            "stdout": {
                "path": f"logs/{task_id}.stdout",
                "sha256": digest_bytes(stdout),
                "size_bytes": len(stdout),
                "truncated": False,
            },
            "stderr": {
                "path": f"logs/{task_id}.stderr",
                "sha256": digest_bytes(stderr),
                "size_bytes": len(stderr),
                "truncated": False,
            },
            "result": {
                "path": f"tasks/{task_id}/result.json",
                "sha256": result_hash,
                "size_bytes": (task_dir / "result.json").stat().st_size,
                "missing": False,
                "error": None,
            },
            "artifacts": [],
        }
        record_hash = write_json(root / "records" / f"{task_id}.json", record)
        record_hashes[task_id] = record_hash
        aggregate = {
            "schema_version": "1",
            "requirement_id": requirement,
            "status": "incomplete" if status != "pass" else "pass",
            "profile_sha256": profile_hash,
            "requirements_sha256": run["requirements_sha256"],
            "run_manifest_sha256": run_hash,
            "validation_run_id": run["validation_run_id"],
            "suite": suite,
            "validator": run["validator"],
            "records": [{"task_id": task_id, "record_sha256": record_hash}],
        }
        requirement_hashes[requirement] = write_json(
            root / "requirements" / f"{requirement}.json", aggregate
        )

    summary = {
        "schema_version": "1",
        "state": "complete",
        "overall_status": overall,
        "counts": counts,
        "target_id": target_id,
        "suite": suite,
        "profile_sha256": profile_hash,
        "requirements_sha256": run["requirements_sha256"],
        "run_manifest_sha256": run_hash,
        "validation_run_id": run["validation_run_id"],
        "required_requirement_ids": requirement_ids,
        "required_task_ids": task_ids,
        "record_sha256": record_hashes,
        "requirement_evidence_sha256": requirement_hashes,
        "validator": run["validator"],
        "identity_error": None,
        "qualification_candidate": None,
        "start_utc": run["start_utc"],
        "end_utc": "2026-10-21T00:00:02.000000Z",
    }
    write_json(root / "summary.json", summary)


def make_evidence(
    root: Path,
    profile_hash: str,
    task_identity: Path,
    target_id: str = "tflite",
) -> Path:
    evidence = root / "evidence"
    for suite in SUITE_REQUIREMENTS:
        make_suite(
            evidence, suite, profile_hash, task_identity, target_id=target_id
        )
    return evidence


class Selftest:
    def __init__(self, assembler: Path, label: str) -> None:
        self.assembler = assembler
        self.label = label
        self.pass_count = 0
        self.fail_count = 0

    def ok(self, label: str) -> None:
        self.pass_count += 1
        print(f"[{self.label}-qualification] ok: {label}")

    def bad(self, label: str, detail: str) -> None:
        self.fail_count += 1
        print(f"[{self.label}-qualification] fail: {label}: {detail}", file=sys.stderr)

    def run(self, profile: Path, evidence: Path, output: Path, status: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(self.assembler),
                "--profile",
                str(profile),
                "--evidence-root",
                str(evidence),
                "--output",
                str(output),
                "--status",
                status,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def expect(self, label: str, completed: subprocess.CompletedProcess[str], rc: int, needle: str) -> None:
        output = completed.stdout + completed.stderr
        if completed.returncode == rc and needle in output:
            self.ok(label)
        else:
            self.bad(label, f"rc={completed.returncode}, output={output[-600:]!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assembler", required=True, type=Path)
    parser.add_argument(
        "--target-id", choices=("tflite", "openvino-ir"), default="tflite"
    )
    args = parser.parse_args()
    label = "openvino" if args.target_id == "openvino-ir" else "tflite"
    test = Selftest(args.assembler.resolve(), label)
    if not test.assembler.is_file():
        test.bad("assembler precondition", f"missing file: {test.assembler}")
        print(f"[{label}-qualification] pass={test.pass_count} fail={test.fail_count}")
        return 1

    with tempfile.TemporaryDirectory(prefix="tflite-qualification-") as temporary:
        root = Path(temporary)
        profile = make_profile(root, args.target_id)
        profile_hash = digest(profile)
        task_identity = root / "task-identity.py"
        task_identity.write_bytes(b"#!/usr/bin/env python3\n")
        task_identity.chmod(0o700)
        os.link(task_identity, root / "task-identity-alias.py")

        evidence = make_evidence(
            root / "valid", profile_hash, task_identity, args.target_id
        )
        completed = test.run(profile, evidence, root / "verified.json", "verified")
        test.expect("all twelve clean requirements issue verified", completed, 0, "status=verified")

        original_task_identity = task_identity.read_bytes()
        task_identity.write_bytes(b"#!/usr/bin/env python3\n# changed after validation\n")
        completed = test.run(
            profile,
            evidence,
            root / "changed-task-identity.json",
            "verified",
        )
        test.expect(
            "changed task identity is refused",
            completed,
            1,
            "hash mismatch",
        )
        task_identity.write_bytes(original_task_identity)

        missing = root / "missing"
        shutil.copytree(evidence, missing)
        shutil.rmtree(missing / "performance")
        completed = test.run(profile, missing, root / "missing.json", "verified")
        test.expect("missing Q10 suite is refused", completed, 1, "missing suite")

        tampered = root / "tampered"
        shutil.copytree(evidence, tampered)
        requirement = tampered / "oracle" / "requirements" / "Q03.json"
        requirement.write_bytes(requirement.read_bytes() + b" ")
        completed = test.run(profile, tampered, root / "tampered.json", "verified")
        test.expect("tampered requirement evidence is refused", completed, 1, "hash mismatch")

        dirty = root / "dirty"
        shutil.copytree(evidence, dirty)
        shutil.rmtree(dirty / "performance")
        make_suite(
            dirty,
            "performance",
            profile_hash,
            task_identity,
            dirty="5" * 64,
            target_id=args.target_id,
        )
        completed = test.run(profile, dirty, root / "dirty.json", "verified")
        test.expect("dirty source identity is refused for verified", completed, 1, "dirty source")

        mixed = root / "mixed"
        shutil.copytree(evidence, mixed)
        shutil.rmtree(mixed / "soak")
        make_suite(
            mixed,
            "soak",
            profile_hash,
            task_identity,
            commit="6" * 40,
            target_id=args.target_id,
        )
        completed = test.run(profile, mixed, root / "mixed.json", "verified")
        test.expect("mixed tool commits are refused", completed, 1, "tool commit mismatch")

        partial = root / "partial"
        shutil.copytree(evidence, partial)
        for suite, requirement in (("performance", "Q10"), ("soak", "Q11")):
            shutil.rmtree(partial / suite)
            make_suite(
                partial,
                suite,
                profile_hash,
                task_identity,
                incomplete={requirement},
                target_id=args.target_id,
            )
        completed = test.run(profile, partial, root / "smoke.json", "smoke_passed")
        test.expect("partial evidence stays smoke-passed", completed, 0, "pending=Q10,Q11")
        if completed.returncode == 0:
            value = json.loads((root / "smoke.json").read_text(encoding="utf-8"))
            observed = {row["requirement_id"] for row in value["gate_evidence"]}
            if value["status"] == "smoke_passed" and observed == {
                f"Q{number:02}" for number in range(1, 13)
            } - {"Q10", "Q11"}:
                test.ok("smoke qualification contains only passing evidence")
            else:
                test.bad("smoke qualification contains only passing evidence", repr(value))

        no_replace = test.run(profile, evidence, root / "verified.json", "verified")
        test.expect("existing qualification is never overwritten", no_replace, 1, "already exists")

    print(f"[{label}-qualification] pass={test.pass_count} fail={test.fail_count}")
    return 0 if test.fail_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
