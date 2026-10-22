#!/usr/bin/env python3
"""Collect, supervise, publish, and revalidate TFL Q10/Q11 evidence.

The collector never turns a child process's claimed status into a verdict.  Raw
operation records are re-derived by measure_format_baseline.py, and complete
bundles are reconstructed from their indexed files before FND-03 consumes them.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import select
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Sequence

import measure_format_baseline as baseline


MAX_JSON_BYTES = 64 * 1024 * 1024
SUPERVISOR_READY = b"READY\n"
SUPERVISOR_READY_TIMEOUT_SECONDS = 10.0
OPERATION_NAMES = (
    "actual_parser_performance",
    "engine_smoke",
    "single_worker_soak",
    "parallel_soak",
    "fault_injection",
)
BACKGROUND_OPERATIONS = OPERATION_NAMES[1:]
PERFORMANCE_SOURCE_PATHS = (
    "harnesses/tflite/loader.cc",
    "harnesses/tflite/loader.h",
    "harnesses/tflite/replay.cc",
    "scripts/collect_tflite_evidence.py",
    "scripts/measure_format_baseline.py",
)
LOAD_EVENT = "LoadAndAllocate"
LOAD_MARKER = re.compile(rb"(?m)^TFLITE_LOAD_(?:OK|REJECT)\b")
LOAD_OK_MARKER = re.compile(rb"(?m)^TFLITE_LOAD_OK\b")
LOAD_REJECT_MARKER = re.compile(rb"(?m)^TFLITE_LOAD_REJECT\b")
ACCESS_OK_MARKER = re.compile(rb"(?m)^TFLITE_ACCESS_OK\b")
LIBFUZZER_EXECUTED_UNITS = re.compile(
    rb"(?m)^stat::number_of_executed_units:\s*([0-9]+)\s*$"
)
ACTIVE_SCRIPT = re.compile(
    r"^(?:run_campaign|run_long|run_backend_loop|fuzz-loop[^ /]*)\.sh$"
)


class EvidenceError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as error:
        raise EvidenceError(f"could not serialize evidence: {error}") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{label} must be a non-empty relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value or value == "index.json":
        raise EvidenceError(f"{label} is unsafe: {value!r}")
    return value


def regular_bytes(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise EvidenceError(f"could not inspect {label}: {path}: {error}") from error
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        kind = "symlink" if stat.S_ISLNK(before.st_mode) else "non-private regular file"
        raise EvidenceError(f"{label} must be a private regular file, not {kind}: {path}")
    if before.st_size < 0 or before.st_size > maximum:
        raise EvidenceError(f"{label} exceeds {maximum} bytes: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(f"could not open {label} without following symlinks: {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise EvidenceError(f"{label} changed while opening: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise EvidenceError(f"{label} ended while being read: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise EvidenceError(f"{label} grew while being read: {path}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if baseline._source_metadata(before) != baseline._source_metadata(after):
        raise EvidenceError(f"{label} changed while being read: {path}")
    return b"".join(chunks)


def read_json(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    payload = regular_bytes(path, label, maximum)
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{label} is not UTF-8: {path}") from error
    try:
        value = baseline._parse_json_text(text, label)
    except baseline.ContractError as error:
        raise EvidenceError(str(error)) from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} root must be an object")
    return value, payload


def exclusive_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    if not path.is_absolute():
        raise EvidenceError(f"output path must be absolute: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise EvidenceError(f"could not create output without replacement: {path}: {error}") from error
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)


def mkdir_new(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise EvidenceError(f"{label} must be absolute: {path}")
    try:
        path.mkdir(mode=0o700, parents=False)
    except OSError as error:
        raise EvidenceError(f"could not create new {label}: {path}: {error}") from error


def directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError(f"could not inspect {label}: {path}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError(f"{label} must be a directory, not a symlink: {path}")


def require_wsl_ext4(path: Path, label: str) -> None:
    text = str(path)
    if text == "/mnt" or text.startswith("/mnt/"):
        raise EvidenceError(f"{label} must be on the WSL ext4 filesystem: {path}")


def read_ref(bundle: Path, reference: Any, label: str) -> dict[str, Any]:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise EvidenceError(f"{label} reference is invalid")
    relative = safe_relative(reference["path"], f"{label}.path")
    payload = regular_bytes(bundle / relative, label)
    if sha256_bytes(payload) != reference["sha256"]:
        raise EvidenceError(f"{label} hash mismatch")
    try:
        value = baseline._parse_json_text(payload.decode("utf-8", "strict"), label)
    except (UnicodeDecodeError, baseline.ContractError) as error:
        raise EvidenceError(f"{label} is not strict JSON: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} root must be an object")
    return value


def _bundle_inventory(bundle: Path) -> set[str]:
    actual: set[str] = set()
    for current, directories, files in os.walk(bundle, followlinks=False):
        current_path = Path(current)
        for name in directories:
            metadata = (current_path / name).lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise EvidenceError(f"bundle contains a symlinked directory: {current_path / name}")
        for name in files:
            path = current_path / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise EvidenceError(f"bundle member must be a private regular file, not a symlink: {path}")
            actual.add(path.relative_to(bundle).as_posix())
    return actual


def reconstruct_observation(bundle: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest, _ = read_json(bundle / "manifest.json", "bundle manifest")
    evaluation, _ = read_json(bundle / "evaluation.json", "bundle evaluation")
    baseline_arm, _ = read_json(bundle / "baseline.json", "bundle baseline arm")
    candidate_arm, _ = read_json(bundle / "candidate.json", "bundle candidate arm")
    calibration, _ = read_json(bundle / "calibration.json", "bundle calibration")
    pairs, _ = read_json(bundle / "pairs.json", "bundle pairs")

    profile_snapshots = manifest.get("profile_snapshots")
    correctness_snapshots = manifest.get("correctness_snapshots")
    corpus_snapshot = manifest.get("corpus_index_snapshot")
    if not isinstance(profile_snapshots, dict) or not isinstance(correctness_snapshots, dict):
        raise EvidenceError("bundle manifest snapshot inventory is invalid")
    if not isinstance(corpus_snapshot, dict):
        raise EvidenceError("bundle manifest corpus snapshot is invalid")
    profile_raw: dict[str, str] = {}
    profiles: dict[str, Any] = {}
    correctness_raw: dict[str, str] = {}
    for arm in ("baseline", "candidate"):
        profile_ref = profile_snapshots.get(arm)
        correctness_ref = correctness_snapshots.get(arm)
        if not isinstance(profile_ref, dict) or set(profile_ref) != {"path", "sha256"}:
            raise EvidenceError(f"bundle {arm} profile reference is invalid")
        if not isinstance(correctness_ref, dict) or set(correctness_ref) != {"path", "sha256"}:
            raise EvidenceError(f"bundle {arm} correctness reference is invalid")
        profile_payload = regular_bytes(
            bundle / safe_relative(profile_ref["path"], f"{arm} profile path"),
            f"{arm} profile",
        )
        correctness_payload = regular_bytes(
            bundle / safe_relative(correctness_ref["path"], f"{arm} correctness path"),
            f"{arm} correctness",
        )
        if sha256_bytes(profile_payload) != profile_ref["sha256"]:
            raise EvidenceError(f"{arm} profile hash mismatch")
        if sha256_bytes(correctness_payload) != correctness_ref["sha256"]:
            raise EvidenceError(f"{arm} correctness hash mismatch")
        try:
            profile_raw[arm] = profile_payload.decode("utf-8", "strict")
            correctness_raw[arm] = correctness_payload.decode("utf-8", "strict")
            profiles[arm] = baseline._parse_json_text(profile_raw[arm], f"{arm} profile")
        except (UnicodeDecodeError, baseline.ContractError) as error:
            raise EvidenceError(f"bundle {arm} snapshot is invalid: {error}") from error
    corpus_payload = regular_bytes(
        bundle / safe_relative(corpus_snapshot.get("path"), "corpus snapshot path"),
        "corpus snapshot",
    )
    if sha256_bytes(corpus_payload) != corpus_snapshot.get("sha256"):
        raise EvidenceError("corpus snapshot hash mismatch")
    try:
        corpus_raw = corpus_payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise EvidenceError("corpus snapshot is not UTF-8") from error

    identity = manifest.get("identity")
    if not isinstance(identity, dict):
        raise EvidenceError("bundle manifest identity is invalid")
    identity = dict(identity)
    identity.update(
        {
            "baseline_profile": profiles["baseline"],
            "candidate_profile": profiles["candidate"],
            "baseline_profile_raw_json": profile_raw["baseline"],
            "candidate_profile_raw_json": profile_raw["candidate"],
        }
    )
    fixed = identity.get("fixed")
    if not isinstance(fixed, dict) or fixed.get("corpus_index_raw_json") != corpus_raw:
        raise EvidenceError("manifest identity does not bind the corpus snapshot bytes")

    warmups = [
        read_ref(bundle, calibration.get("warmup"), "calibration warmup"),
        read_ref(bundle, baseline_arm.get("warmup"), "baseline warmup"),
        read_ref(bundle, candidate_arm.get("warmup"), "candidate warmup"),
    ]
    calibration_pairs: list[dict[str, Any]] = []
    raw_calibration_pairs = calibration.get("pairs")
    if not isinstance(raw_calibration_pairs, list):
        raise EvidenceError("calibration pair references are invalid")
    for row in raw_calibration_pairs:
        if not isinstance(row, dict):
            raise EvidenceError("calibration pair reference is invalid")
        calibration_pairs.append(
            {
                "pair_index": row.get("pair_index"),
                "baseline_a": read_ref(bundle, row.get("baseline_a"), "calibration baseline-a"),
                "baseline_b": read_ref(bundle, row.get("baseline_b"), "calibration baseline-b"),
            }
        )
    comparison_pairs: list[dict[str, Any]] = []
    raw_comparison_pairs = pairs.get("pairs")
    if not isinstance(raw_comparison_pairs, list):
        raise EvidenceError("comparison pair references are invalid")
    for row in raw_comparison_pairs:
        if not isinstance(row, dict):
            raise EvidenceError("comparison pair reference is invalid")
        comparison_pairs.append(
            {
                "pair_index": row.get("pair_index"),
                "baseline": read_ref(bundle, row.get("baseline"), "comparison baseline"),
                "candidate": read_ref(bundle, row.get("candidate"), "comparison candidate"),
            }
        )
    document = {
        "schema_version": manifest.get("observation_schema_version"),
        "mode": manifest.get("mode"),
        "comparison_id": manifest.get("comparison_id"),
        "identity": identity,
        "environment": manifest.get("environment"),
        "protocol": manifest.get("protocol"),
        "correctness": {
            "baseline_raw_json": correctness_raw["baseline"],
            "candidate_raw_json": correctness_raw["candidate"],
            "baseline_sha256": correctness_snapshots["baseline"]["sha256"],
            "candidate_sha256": correctness_snapshots["candidate"]["sha256"],
        },
        "warmups": warmups,
        "calibration": calibration_pairs,
        "comparison": comparison_pairs,
        "absolute_budgets": manifest.get("absolute_budgets"),
        "operations": manifest.get("operations"),
    }
    return document, evaluation, manifest


def validate_bundle(
    path: Path | str,
    *,
    requirement: str,
    expected_commit: str,
    expected_profile_sha256: str,
    require_current_aa: bool = False,
) -> list[Path]:
    bundle = Path(path)
    if not bundle.is_absolute():
        raise EvidenceError("bundle path must be absolute")
    try:
        resolved_bundle = bundle.resolve(strict=True)
    except OSError as error:
        raise EvidenceError(f"could not resolve evidence bundle: {error}") from error
    if resolved_bundle != Path(os.path.abspath(bundle)):
        raise EvidenceError("bundle path must not traverse a symlinked ancestor")
    directory(bundle, "evidence bundle")
    inventory = _bundle_inventory(bundle)
    index, _ = read_json(bundle / "index.json", "bundle complete index")
    expected_index_fields = {
        "schema_version",
        "state",
        "comparison_id",
        "mode",
        "performance_claim_eligible",
        "performance_status",
        "operations_status",
        "gate_status",
        "next_stage_blocked",
        "files",
        "files_index_sha256",
    }
    if set(index) != expected_index_fields:
        raise EvidenceError("bundle complete index fields mismatch")
    if index["schema_version"] != baseline.INDEX_VERSION or index["state"] != "complete":
        raise EvidenceError("bundle index is not complete")
    if index["mode"] != "real":
        raise EvidenceError("selftest bundle cannot be used as real qualification evidence")
    files = index.get("files")
    if not isinstance(files, dict) or not files:
        raise EvidenceError("bundle complete index file inventory is empty")
    expected_files: set[str] = set()
    for relative, expected_hash in files.items():
        relative = safe_relative(relative, "bundle index file")
        if relative in expected_files or not isinstance(expected_hash, str):
            raise EvidenceError("bundle complete index file inventory is invalid")
        expected_files.add(relative)
        payload = regular_bytes(bundle / relative, f"indexed bundle member {relative}")
        if sha256_bytes(payload) != expected_hash:
            raise EvidenceError(f"bundle member hash mismatch: {relative}")
    if inventory != expected_files | {"index.json"}:
        raise EvidenceError(
            "bundle inventory does not exactly match complete index: "
            f"missing={sorted(expected_files - inventory)} extra={sorted(inventory - expected_files - {'index.json'})}"
        )
    if sha256_bytes(canonical(dict(sorted(files.items())))) != index["files_index_sha256"]:
        raise EvidenceError("bundle files_index_sha256 mismatch")

    document, recorded_evaluation, manifest = reconstruct_observation(bundle)
    try:
        fresh_evaluation = baseline.evaluate_document(document)
    except baseline.ContractError as error:
        raise EvidenceError(f"bundle observation revalidation failed: {error}") from error
    if fresh_evaluation != recorded_evaluation:
        raise EvidenceError("bundle evaluation does not match a fresh full revalidation")
    for key in (
        "comparison_id",
        "mode",
        "performance_claim_eligible",
        "performance_status",
        "operations_status",
        "gate_status",
        "next_stage_blocked",
    ):
        if index[key] != fresh_evaluation[key]:
            raise EvidenceError(f"bundle index {key} does not match fresh evaluation")
    identity = document["identity"]
    if identity["baseline_tool_commit"] != expected_commit or identity["candidate_tool_commit"] != expected_commit:
        raise EvidenceError("bundle tool_commit does not match the qualification commit")
    if identity["baseline_profile_sha256"] != expected_profile_sha256 or identity["candidate_profile_sha256"] != expected_profile_sha256:
        raise EvidenceError("bundle profile_sha256 does not match the qualification profile")
    if identity["baseline_source_state"] != "clean" or identity["candidate_source_state"] != "clean":
        raise EvidenceError("bundle source identity is dirty")
    if identity["baseline_dirty_diff_sha256"] is not None or identity["candidate_dirty_diff_sha256"] is not None:
        raise EvidenceError("bundle dirty diff identity is non-null")
    if require_current_aa:
        if identity["allowed_profile_differences"] or identity["allowed_tool_changes"]:
            raise EvidenceError("current-build A/A bundle must have empty difference allowlists")
        if identity["baseline_command"] != identity["candidate_command"]:
            raise EvidenceError("current-build A/A bundle commands differ")
        if identity["baseline_profile_raw_json"] != identity["candidate_profile_raw_json"]:
            raise EvidenceError("current-build A/A bundle profiles differ")
        if identity["baseline_source_artifacts"] != identity["candidate_source_artifacts"]:
            raise EvidenceError("current-build A/A bundle source artifacts differ")
        replay_binaries = [
            binary
            for binary in identity["candidate_profile"]["binaries"]
            if isinstance(binary, dict) and binary.get("role") == "replay"
        ]
        if len(replay_binaries) != 1 or (
            identity["candidate_command"]["argv"][0] != replay_binaries[0].get("path")
            or identity["candidate_command"]["executable_sha256"]
            != replay_binaries[0].get("sha256")
        ):
            raise EvidenceError("current-build A/A command is not the pinned replay binary")
    if fresh_evaluation["performance_status"] != "pass":
        raise EvidenceError("bundle performance evidence is not pass")
    operations = fresh_evaluation["operations"]
    if operations["actual_parser_performance"]["status"] != "pass":
        raise EvidenceError("Q10 bundle lacks strict actual-parser performance evidence")
    if requirement == "Q10":
        pass
    elif requirement == "Q11":
        if any(operations[name]["status"] != "pass" for name in OPERATION_NAMES):
            raise EvidenceError("Q11 bundle does not contain all strict V7 operation passes")
        if fresh_evaluation["operations_status"] != "pass" or fresh_evaluation["gate_status"] != "pass":
            raise EvidenceError("Q11 bundle aggregate gate is not pass")
    else:
        raise EvidenceError(f"unsupported evidence requirement: {requirement}")
    for name, row in operations.items():
        if row["raw_json"] is not None:
            operation_path = f"operations/{name}.json"
            if files.get(operation_path) != row["evidence_sha256"]:
                raise EvidenceError(f"operation raw file is absent or mismatched: {name}")
    return [bundle / relative for relative in sorted(inventory)]


def git_output(project_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=project_root,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise EvidenceError(f"git {' '.join(arguments)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def git_identity(project_root: Path) -> tuple[str, str | None]:
    commit = git_output(project_root, "rev-parse", "HEAD")
    worktree = subprocess.run(["git", "diff", "--quiet", "--"], cwd=project_root, check=False)
    index = subprocess.run(["git", "diff", "--cached", "--quiet", "--"], cwd=project_root, check=False)
    if worktree.returncode not in {0, 1} or index.returncode not in {0, 1}:
        raise EvidenceError("could not determine tracked source cleanliness")
    if worktree.returncode == 0 and index.returncode == 0:
        return commit, None
    diff = subprocess.run(
        ["git", "diff", "--binary", "HEAD", "--"],
        cwd=project_root,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    return commit, sha256_bytes(diff)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def active_workloads() -> list[str]:
    active: list[str] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        arguments = [
            item.decode("utf-8", "replace")
            for item in raw.split(b"\0")
            if item
        ]
        if not arguments:
            continue
        executable = Path(arguments[0]).name
        basenames = [Path(argument).name for argument in arguments[1:] if argument]
        is_active = (
            executable == "afl-fuzz"
            or (executable == "cargo" and len(arguments) > 1 and arguments[1] == "fuzz")
            or ACTIVE_SCRIPT.fullmatch(executable) is not None
            or any(ACTIVE_SCRIPT.fullmatch(name) for name in basenames)
            or executable.endswith(("_fuzzer", "_replay"))
            or (
                executable == "tool"
                and len(arguments) > 1
                and arguments[1] in {"run", "campaign", "harness"}
            )
        )
        if is_active:
            command = " ".join(arguments)
            active.append(f"pid={entry.name} command={command}")
    return sorted(active)


def audit_corpus(corpus_index: Path) -> tuple[str, list[dict[str, str]]]:
    value, _ = read_json(corpus_index, "performance corpus index")
    if value.get("schema_version") != "format-performance-corpus-v1":
        raise EvidenceError("performance corpus index schema is unsupported")
    rows = value.get("inputs")
    if not isinstance(rows, list) or not rows:
        raise EvidenceError("performance corpus index inputs must be non-empty")
    identities: list[dict[str, str]] = []
    observed: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise EvidenceError(f"performance corpus input {index} is not an object")
        relative = safe_relative(row.get("path"), f"performance corpus input {index} path")
        if relative in observed:
            raise EvidenceError(f"performance corpus input path is duplicated: {relative}")
        observed.add(relative)
        expected = row.get("sha256")
        try:
            expected = baseline._sha256(expected, f"performance corpus input {index} sha256")
        except baseline.ContractError as error:
            raise EvidenceError(str(error)) from error
        path = corpus_index.parent / relative
        actual = sha256_bytes(regular_bytes(path, f"performance corpus input {relative}"))
        if actual != expected:
            raise EvidenceError(f"performance corpus input hash mismatch: {relative}")
        identities.append({"relative_path": relative, "path": str(path), "sha256": actual})
    aggregate = sha256_bytes(
        canonical({row["relative_path"]: row["sha256"] for row in identities})
    )
    return aggregate, identities


def _system_memory() -> tuple[int, int, int, int]:
    memory = 0
    available = 0
    swap = 0
    swap_free = 0
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            key, value = line.split(":", 1)
            amount = int(value.strip().split()[0]) * 1024
            if key == "MemTotal":
                memory = amount
            elif key == "MemAvailable":
                available = amount
            elif key == "SwapTotal":
                swap = amount
            elif key == "SwapFree":
                swap_free = amount
    except (OSError, ValueError, IndexError) as error:
        raise EvidenceError(f"could not read WSL memory allocation: {error}") from error
    if memory <= 0 or available <= 0:
        raise EvidenceError("WSL memory totals are unavailable")
    return memory, available, swap, swap_free


def audit_profile_files(profile: dict[str, Any]) -> None:
    identities: list[tuple[str, dict[str, Any]]] = []
    for index, row in enumerate(profile["patches"]):
        identities.append((f"profile patch {index}", row))
    for name in ("compiler", "linker", "engine", "python", "rust"):
        row = profile["toolchain"].get(name)
        if row is not None:
            identities.append((f"profile toolchain {name}", row))
    for binary in profile["binaries"]:
        identities.append((f"profile binary {binary['role']}", binary))
        for index, library in enumerate(binary.get("linked_libraries", [])):
            identities.append((f"profile binary {binary['role']} library {index}", library))
    for label, identity in identities:
        path = Path(identity["path"]).resolve(strict=True)
        require_wsl_ext4(path, label)
        payload = regular_bytes(path, label, 1024 * 1024 * 1024)
        if sha256_bytes(payload) != identity["sha256"]:
            raise EvidenceError(f"{label} bytes do not match the profile hash")


def prepare(args: argparse.Namespace) -> int:
    project_root = Path(__file__).resolve().parent.parent
    commit, dirty = git_identity(project_root)
    if commit != args.expected_commit:
        raise EvidenceError(f"HEAD {commit} does not match expected commit {args.expected_commit}")
    if args.mode == "real" and dirty is not None:
        raise EvidenceError("real evidence preparation requires a clean tracked worktree and index")
    if args.mode == "real":
        active = active_workloads()
        if active:
            raise EvidenceError(f"concurrent fuzz/build workload is active: {active[0]}")
    profile = args.profile.resolve(strict=True)
    replay = args.replay.resolve(strict=True)
    corpus_index = args.corpus_index.resolve(strict=True)
    for path, label in (
        (project_root, "project root"),
        (profile, "profile"),
        (replay, "replay"),
        (corpus_index, "corpus index"),
    ):
        require_wsl_ext4(path, label)
    for path, label in ((profile, "profile"), (replay, "replay"), (corpus_index, "corpus index")):
        regular_bytes(path, label)
    profile_value, profile_payload = read_json(profile, "TFLite profile", 4 * 1024 * 1024)
    try:
        baseline._validate_target_profile_shape(profile_value, "TFLite profile")
    except baseline.ContractError as error:
        raise EvidenceError(f"TFLite profile is invalid: {error}") from error
    audit_profile_files(profile_value)
    if profile_value.get("target_id") != "tflite":
        raise EvidenceError("profile target_id must be tflite")
    limits = profile_value.get("limits")
    if not isinstance(limits, dict) or limits.get("workers") != 1 or limits.get("threads") != 1:
        raise EvidenceError("TFLite evidence profile must pin one worker and one thread")
    if limits.get("memory_bytes") != args.peak_rss_bytes:
        raise EvidenceError("peak RSS budget must equal the pinned profile memory limit")
    replay_sha = sha256_bytes(regular_bytes(replay, "replay", 1024 * 1024 * 1024))
    matching_replays = [
        row
        for row in profile_value.get("binaries", [])
        if isinstance(row, dict)
        and row.get("role") == "replay"
        and row.get("path") == str(replay)
        and row.get("sha256") == replay_sha
    ]
    if len(matching_replays) != 1:
        raise EvidenceError("replay path/hash must match exactly one pinned profile binary")
    fuzzers = [
        row
        for row in profile_value.get("binaries", [])
        if isinstance(row, dict) and row.get("role") == "fuzzer"
    ]
    if len(fuzzers) != 1:
        raise EvidenceError("TFLite evidence profile must pin exactly one fuzzer binary")
    fuzzer = Path(fuzzers[0].get("path", "")).resolve(strict=True)
    require_wsl_ext4(fuzzer, "fuzzer")
    fuzzer_sha = sha256_bytes(regular_bytes(fuzzer, "fuzzer", 1024 * 1024 * 1024))
    if fuzzers[0].get("sha256") != fuzzer_sha:
        raise EvidenceError("fuzzer path/hash does not match the pinned profile binary")
    corpus_sha, corpus_files = audit_corpus(corpus_index)
    try:
        requested_corpus_sha = baseline._sha256(args.corpus_sha256, "--corpus-sha256")
        baseline._commit(args.expected_commit, "--expected-commit")
    except baseline.ContractError as error:
        raise EvidenceError(str(error)) from error
    if corpus_sha != requested_corpus_sha:
        raise EvidenceError("--corpus-sha256 does not match the audited corpus files")
    if baseline.SAFE_ID.fullmatch(args.comparison_id) is None:
        raise EvidenceError("comparison ID is unsafe")
    if any(value <= 0 for value in (args.peak_rss_bytes, args.log_bytes, args.disk_bytes)):
        raise EvidenceError("all precommitted budgets must be positive")
    evidence_root = args.evidence_root.resolve(strict=True)
    require_wsl_ext4(evidence_root, "evidence output root")
    directory(evidence_root, "evidence output root")
    run_root = args.run_root.absolute()
    require_wsl_ext4(run_root, "run root")
    require_wsl_ext4(run_root.parent.resolve(strict=True), "run root parent")
    mkdir_new(run_root, "run root")
    memory, available, swap, swap_free = _system_memory()
    disk = os.statvfs(run_root)
    cpu_count = os.cpu_count()
    if not isinstance(cpu_count, int) or cpu_count < 1:
        raise EvidenceError("could not determine the WSL CPU allocation")
    value = {
        "schema_version": "tflite-evidence-run-v1",
        "state": "prepared",
        "mode": args.mode,
        "comparison_id": args.comparison_id,
        "project_root": str(project_root),
        "tool_commit": commit,
        "dirty_diff_sha256": dirty,
        "profile": str(profile),
        "profile_sha256": sha256_bytes(profile_payload),
        "replay": str(replay),
        "replay_sha256": replay_sha,
        "fuzzer": str(fuzzer),
        "fuzzer_sha256": fuzzer_sha,
        "corpus_index": str(corpus_index),
        "corpus_index_sha256": sha256_bytes(regular_bytes(corpus_index, "corpus index")),
        "corpus_sha256": corpus_sha,
        "corpus_files": corpus_files,
        "evidence_root": str(evidence_root),
        "prepared_utc": utc_now(),
        "resources": {
            "cpu_count": cpu_count,
            "memory_bytes": memory,
            "memory_available_bytes": available,
            "swap_bytes": swap,
            "swap_free_bytes": swap_free,
            "disk_free_bytes": disk.f_bavail * disk.f_frsize,
        },
        "budgets": {
            "peak_rss_bytes": args.peak_rss_bytes,
            "log_bytes": args.log_bytes,
            "disk_bytes": args.disk_bytes,
        },
        "parallel_capacity": {
            "required_memory_and_swap_bytes": args.peak_rss_bytes * 2 + args.peak_rss_bytes // 2,
            "required_disk_free_bytes": args.disk_bytes * 2,
            "worker_processes": 2,
            "workers_per_process": 1,
        },
    }
    exclusive_write(run_root / "prepare.json", canonical(value))
    print(f"TFLITE_EVIDENCE_PREPARED=yes run_root={run_root} commit={commit} mode={args.mode}")
    return 0


def read_prepare(run_root: Path, *, recheck: bool) -> dict[str, Any]:
    run_root = run_root.absolute()
    directory(run_root, "run root")
    value, _ = read_json(run_root / "prepare.json", "prepared run manifest")
    if value.get("schema_version") != "tflite-evidence-run-v1" or value.get("state") != "prepared":
        raise EvidenceError("prepared run manifest state mismatch")
    if recheck:
        project_root = Path(value["project_root"])
        commit, dirty = git_identity(project_root)
        if commit != value["tool_commit"] or dirty != value["dirty_diff_sha256"]:
            raise EvidenceError("tool commit or tracked dirty identity changed after prepare")
        for path_key, hash_key, label in (
            ("profile", "profile_sha256", "profile"),
            ("replay", "replay_sha256", "replay"),
            ("fuzzer", "fuzzer_sha256", "fuzzer"),
            ("corpus_index", "corpus_index_sha256", "corpus index"),
        ):
            if sha256_bytes(regular_bytes(Path(value[path_key]), label)) != value[hash_key]:
                raise EvidenceError(f"{label} changed after prepare")
        observed_corpus_sha, observed_files = audit_corpus(Path(value["corpus_index"]))
        if observed_corpus_sha != value["corpus_sha256"] or observed_files != value["corpus_files"]:
            raise EvidenceError("performance corpus changed after prepare")
    return value


def _require_current_aa(document: dict[str, Any], prepared: dict[str, Any]) -> None:
    identity = document.get("identity")
    if not isinstance(identity, dict):
        raise EvidenceError("performance observations identity is invalid")
    expected_profile = prepared["profile_sha256"]
    expected_commit = prepared["tool_commit"]
    for arm in ("baseline", "candidate"):
        if identity.get(f"{arm}_profile_sha256") != expected_profile:
            raise EvidenceError(f"{arm} profile does not match prepared profile")
        if identity.get(f"{arm}_tool_commit") != expected_commit:
            raise EvidenceError(f"{arm} commit does not match prepared commit")
        if identity.get(f"{arm}_source_state") != "clean" or identity.get(f"{arm}_dirty_diff_sha256") is not None:
            raise EvidenceError(f"{arm} source is not the prepared clean build")
    if identity.get("baseline_profile_raw_json") != identity.get("candidate_profile_raw_json"):
        raise EvidenceError("first Q10 must use the same profile bytes in both arms")
    if identity.get("baseline_command") != identity.get("candidate_command"):
        raise EvidenceError("first Q10 must use the same replay command in both arms")
    command = identity.get("candidate_command")
    if not isinstance(command, dict) or command.get("argv", [None])[0] != prepared["replay"]:
        raise EvidenceError("first Q10 command does not use the prepared replay path")
    if command.get("executable_sha256") != prepared["replay_sha256"]:
        raise EvidenceError("first Q10 command does not use the prepared replay bytes")
    if identity.get("baseline_source_artifacts") != identity.get("candidate_source_artifacts"):
        raise EvidenceError("first Q10 must use the same source artifacts in both arms")
    if identity.get("allowed_profile_differences") != [] or identity.get("allowed_tool_changes") != []:
        raise EvidenceError("first Q10 difference allowlists must be empty")
    fixed = identity.get("fixed")
    if not isinstance(fixed, dict) or fixed.get("corpus_sha256") != prepared["corpus_sha256"]:
        raise EvidenceError("performance corpus does not match prepared corpus")


def _metric(value: Any, unit: str, **extra: Any) -> dict[str, Any]:
    return {"value": value, "unit": unit, "reason": None, **extra}


def _pending(reason: str) -> dict[str, Any]:
    return {
        "status": "pending",
        "reason": reason,
        "evidence_sha256": None,
        "raw_json": None,
    }


def _current_cgroup_parent() -> Path:
    try:
        rows = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except OSError as error:
        raise EvidenceError(f"could not read the collector cgroup: {error}") from error
    unified = [row.split(":", 2)[2] for row in rows if row.startswith("0::")]
    if len(unified) != 1:
        raise EvidenceError("performance collection requires a unified cgroup-v2 hierarchy")
    relative = unified[0].lstrip("/")
    parent = Path("/sys/fs/cgroup") / relative
    directory(parent, "delegated cgroup parent")
    if not (parent / "cgroup.controllers").is_file():
        raise EvidenceError("performance collection requires cgroup v2")
    return parent


class SampleCgroup:
    def __init__(self, parent: Path, sample_id: str, memory_limit: int) -> None:
        if baseline.SAFE_ID.fullmatch(sample_id) is None:
            raise EvidenceError(f"unsafe cgroup sample ID: {sample_id}")
        self.path = parent / sample_id
        try:
            self.path.mkdir(mode=0o700)
        except OSError as error:
            raise EvidenceError(
                "could not create a private sample cgroup; run performance inside a "
                f"delegated cgroup-v2 scope: {self.path}: {error}"
            ) from error
        try:
            (self.path / "memory.max").write_text(f"{memory_limit}\n", encoding="ascii")
            (self.path / "memory.peak").read_text(encoding="ascii")
        except OSError as error:
            try:
                self.path.rmdir()
            except OSError:
                pass
            raise EvidenceError(f"sample cgroup lacks a writable memory controller: {error}") from error

    def child_setup(self) -> None:
        os.setsid()
        with (self.path / "cgroup.procs").open("w", encoding="ascii") as stream:
            stream.write(f"{os.getpid()}\n")

    def pids(self) -> list[int]:
        try:
            text = (self.path / "cgroup.procs").read_text(encoding="ascii")
        except OSError as error:
            raise EvidenceError(f"could not audit sample cgroup processes: {error}") from error
        return [int(row) for row in text.splitlines() if row]

    def kill(self) -> None:
        kill_path = self.path / "cgroup.kill"
        if kill_path.is_file():
            try:
                kill_path.write_text("1\n", encoding="ascii")
                return
            except OSError:
                pass
        for pid in self.pids():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def finish(self) -> tuple[int, str]:
        residual = len(self.pids())
        if residual:
            self.kill()
            deadline = time.monotonic() + 2.0
            while self.pids() and time.monotonic() < deadline:
                time.sleep(0.01)
        raw_peak = (self.path / "memory.peak").read_text(encoding="ascii")
        if re.fullmatch(r"(?:0|[1-9][0-9]*)\n", raw_peak) is None:
            raise EvidenceError("sample cgroup memory.peak is not an unsigned byte count")
        try:
            self.path.rmdir()
        except OSError as error:
            raise EvidenceError(f"could not remove completed sample cgroup: {error}") from error
        return residual, raw_peak


def _command_environment(command: dict[str, Any]) -> dict[str, str]:
    environment = dict(command["allowed_env"])
    environment.setdefault("PATH", "/usr/bin:/bin")
    environment.setdefault("LC_ALL", "C")
    return environment


def _expand_replay_argv(command: dict[str, Any], input_path: Path) -> list[str]:
    result: list[str] = []
    replaced = 0
    for item in command["argv"]:
        if item == "{input}":
            result.append(str(input_path))
            replaced += 1
        elif "{" in item or "}" in item:
            raise EvidenceError(f"unsupported replay command placeholder: {item!r}")
        else:
            result.append(item)
    if replaced != 1:
        raise EvidenceError("replay command must contain exactly one {input} placeholder")
    return result


def _run_replay_once(
    command: dict[str, Any],
    input_path: Path,
    cgroup: SampleCgroup,
    timeout_seconds: float,
) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        _expand_replay_argv(command, input_path),
        cwd=command["cwd"],
        env=_command_environment(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=cgroup.child_setup,
        close_fds=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
    elapsed = time.monotonic() - started
    combined = stdout + stderr
    calls = len(LOAD_MARKER.findall(combined))
    return {
        "exit_code": 124 if timed_out else process.returncode,
        "elapsed_seconds": elapsed,
        "output_bytes": len(combined),
        "target_api_calls": calls,
        "load_ok": len(LOAD_OK_MARKER.findall(combined)),
        "load_reject": len(LOAD_REJECT_MARKER.findall(combined)),
        "access_ok": len(ACCESS_OK_MARKER.findall(combined)),
    }


def _corpus_document(prepared: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    document, payload = read_json(Path(prepared["corpus_index"]), "performance corpus index")
    if set(document) != {"schema_version", "inputs"} or document.get(
        "schema_version"
    ) != "format-performance-corpus-v1":
        raise EvidenceError("performance corpus index fields or schema are invalid")
    rows = document.get("inputs")
    if not isinstance(rows, list) or not rows:
        raise EvidenceError("performance corpus index inputs must be non-empty")
    expected_fields = {
        "path",
        "sha256",
        "expected_outcome",
        "expected_exit_code",
        "target_api_stage",
        "minimum_target_api_calls",
        "required_api_events",
        "zero_call_reason",
        "throughput_order_index",
        "throughput_exclusion_reason",
        "latency_probe_order_index",
        "latency_exclusion_reason",
    }
    throughput_orders: list[int] = []
    latency_orders: list[int] = []
    for index, row in enumerate(rows):
        label = f"performance corpus inputs[{index}]"
        if not isinstance(row, dict) or set(row) != expected_fields:
            raise EvidenceError(f"{label} fields mismatch")
        safe_relative(row["path"], f"{label}.path")
        try:
            baseline._sha256(row["sha256"], f"{label}.sha256")
        except baseline.ContractError as error:
            raise EvidenceError(str(error)) from error
        outcome = row["expected_outcome"]
        expected_exit = 0 if outcome == "accepted" else 9 if outcome == "rejected" else None
        if row["expected_exit_code"] != expected_exit:
            raise EvidenceError(f"{label} outcome and expected exit code disagree")
        events = row["required_api_events"]
        if not isinstance(events, list) or any(event != LOAD_EVENT for event in events):
            raise EvidenceError(f"{label} required API events must name {LOAD_EVENT}")
        stage = row["target_api_stage"]
        if stage == "target-parser":
            if row["minimum_target_api_calls"] != 1 or events != [LOAD_EVENT] or row["zero_call_reason"] is not None:
                raise EvidenceError(f"{label} target-parser expectations are invalid")
        elif stage == "pre-parser-reject":
            if row["minimum_target_api_calls"] != 0 or events or not isinstance(
                row["zero_call_reason"], str
            ):
                raise EvidenceError(f"{label} pre-parser expectations are invalid")
        else:
            raise EvidenceError(f"{label} target API stage is invalid")
        for prefix, orders in (
            ("throughput", throughput_orders),
            ("latency", latency_orders),
        ):
            order_key = (
                "throughput_order_index"
                if prefix == "throughput"
                else "latency_probe_order_index"
            )
            order = row[order_key]
            reason = row[f"{prefix}_exclusion_reason"]
            if order is None:
                if not isinstance(reason, str) or not reason:
                    raise EvidenceError(f"{label} {prefix} exclusion reason is missing")
            else:
                if (
                    not isinstance(order, int)
                    or isinstance(order, bool)
                    or order < 1
                    or reason is not None
                    or stage != "target-parser"
                ):
                    raise EvidenceError(f"{label} {prefix} inclusion is invalid")
                orders.append(order)
    for label, orders in (
        ("throughput", throughput_orders),
        ("latency", latency_orders),
    ):
        if sorted(orders) != list(range(1, len(orders) + 1)) or not orders:
            raise EvidenceError(f"performance corpus {label} order is not contiguous")
    return document, payload


def _profile_replay_command(
    prepared: dict[str, Any], profile: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    rows = [
        row
        for row in profile["binaries"]
        if row.get("role") == "replay"
        and row.get("path") == prepared["replay"]
        and row.get("sha256") == prepared["replay_sha256"]
    ]
    if len(rows) != 1:
        raise EvidenceError("prepared replay is not the unique replay binary in the profile")
    environment: dict[str, str] = {}
    for source in (
        profile["toolchain"].get("environment", {}),
        profile["sanitizer_policy"]["runtime_env"],
    ):
        for key, value in source.items():
            if key in environment and environment[key] != value:
                raise EvidenceError(f"profile environment conflicts for {key}")
            environment[key] = value
    environment.setdefault("PATH", "/usr/bin:/bin")
    command = {
        "argv": [prepared["replay"], *rows[0]["argv"]],
        "allowed_env": environment,
        "cwd": prepared["project_root"],
        "executable_sha256": prepared["replay_sha256"],
    }
    _expand_replay_argv(command, Path("/tmp/input.tflite"))
    return command, rows[0]


def _correctness_snapshot(
    *,
    arm: str,
    rows: list[dict[str, Any]],
    prepared: dict[str, Any],
    command: dict[str, Any],
    conditions_sha256: str,
    cgroup_parent: Path,
    memory_limit: int,
    timeout_seconds: float,
) -> str:
    records: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        sample_id = f"correctness-{arm}-{index}"
        group = SampleCgroup(cgroup_parent, sample_id, memory_limit)
        result = _run_replay_once(
            command,
            Path(prepared["corpus_index"]).parent / row["path"],
            group,
            timeout_seconds,
        )
        residual, _raw_peak = group.finish()
        expected_outcome = row["expected_outcome"]
        if result["load_ok"] == 1 and result["access_ok"] == 1 and result["load_reject"] == 0:
            outcome = "accepted"
            detail = "load-allocate-access-complete"
        elif result["load_reject"] == 1 and result["load_ok"] == 0:
            outcome = "rejected"
            detail = "load-allocate-rejected"
        elif result["target_api_calls"] == 0 and result["exit_code"] == 9:
            outcome = "rejected"
            detail = "pre-parser-rejected"
        else:
            outcome = "accepted" if result["exit_code"] == 0 else "rejected"
            detail = "unrecognized-replay-transcript"
        calls = result["target_api_calls"]
        records.append(
            {
                "path": row["path"],
                "sha256": row["sha256"],
                "outcome_class": outcome,
                "outcome_detail": detail,
                "target_api_calls": calls,
                "api_events": [LOAD_EVENT] * calls,
                "exit_code": result["exit_code"],
                "residual_processes": residual,
            }
        )
        if outcome != expected_outcome:
            raise EvidenceError(
                f"correctness replay outcome for {row['path']} is {outcome}, expected {expected_outcome}"
            )
    command_sha = sha256_bytes(canonical(command))
    snapshot = {
        "schema_version": "format-correctness-replay-v1",
        "arm": arm,
        "profile_sha256": prepared["profile_sha256"],
        "tool_commit": prepared["tool_commit"],
        "dirty_diff_sha256": None,
        "command_sha256": command_sha,
        "corpus_sha256": prepared["corpus_sha256"],
        "corpus_index_sha256": prepared["corpus_index_sha256"],
        "conditions_sha256": conditions_sha256,
        "records": records,
    }
    return canonical(snapshot).decode("utf-8")


def _collect_sample(
    *,
    sample_id: str,
    phase: str,
    arm: str,
    pair_index: int,
    order_index: int,
    minimum_seconds: float,
    context_sha256: str,
    rows: list[dict[str, Any]],
    prepared: dict[str, Any],
    command: dict[str, Any],
    protocol: dict[str, Any],
    cgroup_parent: Path,
    memory_limit: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    throughput = sorted(
        (row for row in rows if row["throughput_order_index"] is not None),
        key=lambda row: row["throughput_order_index"],
    )
    latency = sorted(
        (row for row in rows if row["latency_probe_order_index"] is not None),
        key=lambda row: row["latency_probe_order_index"],
    )
    rotation = 0 if pair_index == 0 else (pair_index - 1) % len(latency)
    latency = latency[rotation:] + latency[:rotation]
    preparation_started = time.monotonic()
    group = SampleCgroup(cgroup_parent, sample_id, memory_limit)
    preparation_time = time.monotonic() - preparation_started
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    wall_started = time.monotonic()
    complete_passes = 0
    input_count = 0
    target_calls = 0
    output_bytes = 0
    aggregate_exit = 0
    while complete_passes == 0 or time.monotonic() - wall_started < minimum_seconds:
        for row in throughput:
            result = _run_replay_once(
                command,
                Path(prepared["corpus_index"]).parent / row["path"],
                group,
                timeout_seconds,
            )
            input_count += 1
            target_calls += result["target_api_calls"]
            output_bytes += result["output_bytes"]
            if result["exit_code"] != row["expected_exit_code"] and aggregate_exit == 0:
                aggregate_exit = max(1, result["exit_code"])
        complete_passes += 1
    wall_time = time.monotonic() - wall_started
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_time = (usage_after.ru_utime + usage_after.ru_stime) - (
        usage_before.ru_utime + usage_before.ru_stime
    )

    latency_rows: list[dict[str, Any]] = []
    batch_iterations = protocol["latency_batch_iterations"]
    for probe_index, row in enumerate(latency, start=1):
        probe_started = time.monotonic()
        probe_calls = 0
        probe_residual = 0
        observed_exit = 0
        for _iteration in range(batch_iterations):
            result = _run_replay_once(
                command,
                Path(prepared["corpus_index"]).parent / row["path"],
                group,
                timeout_seconds,
            )
            probe_calls += result["target_api_calls"]
            if result["exit_code"] != row["expected_exit_code"] and observed_exit == 0:
                observed_exit = max(1, result["exit_code"])
        probe_elapsed = time.monotonic() - probe_started
        probe_residual = len(group.pids())
        if observed_exit == 0:
            observed_exit = row["expected_exit_code"]
        latency_rows.append(
            {
                "path": row["path"],
                "sha256": row["sha256"],
                "probe_order_index": probe_index,
                "batch_iterations": batch_iterations,
                "target_api_calls": probe_calls,
                "expected_exit_code": row["expected_exit_code"],
                "observed_exit_code": observed_exit,
                "outcome_class": row["expected_outcome"],
                "residual_processes": probe_residual,
                "process_elapsed_seconds": probe_elapsed,
                "normalized_seconds_per_call": (
                    probe_elapsed / probe_calls if probe_calls else 0.0
                ),
            }
        )
    residual, raw_peak = group.finish()
    peak = int(raw_peak.strip())

    command_sha = sha256_bytes(canonical(command))
    config_sha = sha256_bytes(canonical(protocol["memory_collector_config"]))
    return {
        "sample_id": sample_id,
        "phase": phase,
        "arm": arm,
        "pair_index": pair_index,
        "order_index": order_index,
        "profile_sha256": prepared["profile_sha256"],
        "tool_commit": prepared["tool_commit"],
        "dirty_diff_sha256": None,
        "command_sha256": command_sha,
        "corpus_sha256": prepared["corpus_sha256"],
        "corpus_index_sha256": prepared["corpus_index_sha256"],
        "measurement_context_sha256": context_sha256,
        "throughput_workload": {
            "scope": "workload_only",
            "input_order": "corpus_index_rounds",
            "complete_corpus_passes": complete_passes,
        },
        "preparation_time": _metric(preparation_time, "seconds"),
        "wall_time": _metric(wall_time, "seconds"),
        "input_count": _metric(input_count, "inputs"),
        "target_api_calls": _metric(target_calls, "calls"),
        "peak_rss": _metric(
            peak,
            "bytes",
            scope="process_tree_peak",
            collector="cgroup-v2-memory.peak",
            collector_implementation_sha256=protocol[
                "memory_collector_implementation_sha256"
            ],
            collector_config_sha256=config_sha,
            raw_observation={
                "schema_version": "cgroup-v2-memory-peak-v1",
                "sample_id": sample_id,
                "cgroup_path": str(cgroup_parent / sample_id),
                "memory_peak_raw_text": raw_peak,
            },
        ),
        "cpu_time": _metric(cpu_time, "seconds"),
        "output_bytes": _metric(output_bytes, "bytes"),
        "exit_code": _metric(aggregate_exit, "exit_code"),
        "residual_processes": _metric(residual, "processes"),
        "per_input_latency": _metric(
            latency_rows,
            "seconds",
            scope="fixed_corpus_latency_probe",
            order="pair_index_rotation",
        ),
    }


def _performance_document(
    prepared: dict[str, Any],
    cgroup_parent: Path,
    *,
    mode: str = "real",
    sample_seconds: float = 60.0,
    latency_batch_iterations: int = 10,
) -> dict[str, Any]:
    if mode not in {"real", "selftest"}:
        raise EvidenceError(f"unsupported performance collection mode: {mode}")
    if mode == "real" and (
        sample_seconds != 60.0 or latency_batch_iterations != 10
    ):
        raise EvidenceError("real performance collection protocol cannot be shortened")
    profile, profile_payload = read_json(Path(prepared["profile"]), "prepared TFLite profile")
    corpus, corpus_payload = _corpus_document(prepared)
    rows = corpus["inputs"]
    command, replay_row = _profile_replay_command(prepared, profile)
    memory_limit = profile["limits"]["memory_bytes"]
    timeout_seconds = profile["limits"]["input_timeout_ms"] / 1000.0
    implementation_raw = regular_bytes(Path(__file__).resolve(), "collector implementation").decode(
        "utf-8", "strict"
    )
    protocol = {
        "preparation_excluded": True,
        "elapsed_scope": "workload_only",
        "minimum_sample_seconds": 60.0,
        "alternation": "baseline_then_candidate",
        "memory_scope": "process_tree_peak",
        "memory_collector": "cgroup-v2-memory.peak",
        "memory_collector_implementation_raw_text": implementation_raw,
        "memory_collector_implementation_sha256": sha256_bytes(
            implementation_raw.encode("utf-8")
        ),
        "memory_collector_config": dict(baseline.MEMORY_COLLECTOR_CONFIG),
        "clock_resolution_seconds": time.get_clock_info("perf_counter").resolution,
        "rss_resolution_bytes": 1,
        "api_call_resolution_calls": 1,
        "bootstrap_seed": baseline.BOOTSTRAP_SEED,
        "bootstrap_resamples": baseline.BOOTSTRAP_RESAMPLES,
        "quantile_method": "nearest-rank",
        "latency_probe_order": "pair_index_rotation",
        "latency_batch_iterations": latency_batch_iterations,
    }
    budgets = {
        "peak_rss_bytes": memory_limit,
        "latency_p95_seconds": 5.0,
    }
    fixed = {
        "target_id": profile["target_id"],
        "depth": profile["depth"],
        "parser_pin": {
            "loader_id": profile["loader_id"],
            "loader_version": profile["loader_version"],
            "source_artifacts": profile["source_artifacts"],
        },
        "toolchain_pin": profile["toolchain"],
        "target_patch_sha256": sha256_bytes(canonical(profile["patches"])),
        "engine_flags": list(replay_row["argv"]),
        "corpus_sha256": prepared["corpus_sha256"],
        "corpus_index_raw_json": corpus_payload.decode("utf-8", "strict"),
        "corpus_index_sha256": prepared["corpus_index_sha256"],
        "corpus_input_count": len(rows),
        "workers": profile["limits"]["workers"],
        "threads": profile["limits"]["threads"],
        "input_timeout_ms": profile["limits"]["input_timeout_ms"],
        "memory_limit_bytes": memory_limit,
        "filesystem_path_type": "wsl-ext4",
        "log_level": "error",
        "cache_policy": "warm",
    }
    environment = {
        "wsl_cpu_count": prepared["resources"]["cpu_count"],
        "wsl_memory_bytes": prepared["resources"]["memory_bytes"],
        "wsl_swap_bytes": prepared["resources"]["swap_bytes"],
        "disk_free_bytes": prepared["resources"]["disk_free_bytes"],
        "concurrent_workload": "none",
        "cache_policy": "warm",
    }
    conditions_sha = baseline._measurement_conditions_sha256(
        mode, fixed, environment, protocol, budgets
    )
    baseline_correctness = _correctness_snapshot(
        arm="baseline",
        rows=rows,
        prepared=prepared,
        command=command,
        conditions_sha256=conditions_sha,
        cgroup_parent=cgroup_parent,
        memory_limit=memory_limit,
        timeout_seconds=timeout_seconds,
    )
    candidate_correctness = _correctness_snapshot(
        arm="candidate",
        rows=rows,
        prepared=prepared,
        command=command,
        conditions_sha256=conditions_sha,
        cgroup_parent=cgroup_parent,
        memory_limit=memory_limit,
        timeout_seconds=timeout_seconds,
    )
    operation_started = datetime.now(timezone.utc)
    correctness_hashes = {
        "baseline": sha256_bytes(baseline_correctness.encode("utf-8")),
        "candidate": sha256_bytes(candidate_correctness.encode("utf-8")),
    }
    calibration_context = baseline._measurement_context_sha256(
        conditions_sha, correctness_hashes
    )
    common_sample = {
        "rows": rows,
        "prepared": prepared,
        "command": command,
        "protocol": protocol,
        "cgroup_parent": cgroup_parent,
        "memory_limit": memory_limit,
        "timeout_seconds": timeout_seconds,
    }
    warmups = [
        _collect_sample(
            sample_id=f"q10-warmup-{arm}",
            phase="warmup",
            arm=arm,
            pair_index=0,
            order_index=index,
            minimum_seconds=0.0,
            context_sha256=calibration_context,
            **common_sample,
        )
        for index, arm in enumerate(("calibration", "baseline", "candidate"), start=1)
    ]
    calibration: list[dict[str, Any]] = []
    for index in range(1, 6):
        calibration.append(
            {
                "pair_index": index,
                "baseline_a": _collect_sample(
                    sample_id=f"q10-cal-{index}-a",
                    phase="calibration",
                    arm="baseline_a",
                    pair_index=index,
                    order_index=index * 2 - 1,
                    minimum_seconds=sample_seconds,
                    context_sha256=calibration_context,
                    **common_sample,
                ),
                "baseline_b": _collect_sample(
                    sample_id=f"q10-cal-{index}-b",
                    phase="calibration",
                    arm="baseline_b",
                    pair_index=index,
                    order_index=index * 2,
                    minimum_seconds=sample_seconds,
                    context_sha256=calibration_context,
                    **common_sample,
                ),
            }
        )
    comparison_context = baseline._comparison_measurement_context_sha256(
        calibration_context, sha256_bytes(canonical(calibration))
    )
    comparison: list[dict[str, Any]] = []
    for index in range(1, 6):
        comparison.append(
            {
                "pair_index": index,
                "baseline": _collect_sample(
                    sample_id=f"q10-pair-{index}-base",
                    phase="comparison",
                    arm="baseline",
                    pair_index=index,
                    order_index=index * 2 - 1,
                    minimum_seconds=sample_seconds,
                    context_sha256=comparison_context,
                    **common_sample,
                ),
                "candidate": _collect_sample(
                    sample_id=f"q10-pair-{index}-candidate",
                    phase="comparison",
                    arm="candidate",
                    pair_index=index,
                    order_index=index * 2,
                    minimum_seconds=sample_seconds,
                    context_sha256=comparison_context,
                    **common_sample,
                ),
            }
        )
    source_artifacts = {
        path: sha256_bytes(regular_bytes(Path(prepared["project_root"]) / path, path))
        for path in PERFORMANCE_SOURCE_PATHS
    }
    profile_raw = profile_payload.decode("utf-8", "strict")
    command_sha = sha256_bytes(canonical(command))
    document = {
        "schema_version": baseline.SCHEMA_VERSION,
        "mode": mode,
        "comparison_id": prepared["comparison_id"],
        "identity": {
            "fixed": fixed,
            "baseline_profile": profile,
            "candidate_profile": profile,
            "baseline_profile_raw_json": profile_raw,
            "candidate_profile_raw_json": profile_raw,
            "baseline_profile_sha256": prepared["profile_sha256"],
            "candidate_profile_sha256": prepared["profile_sha256"],
            "baseline_profile_canonical_sha256": baseline._canonical_profile_sha256(profile),
            "candidate_profile_canonical_sha256": baseline._canonical_profile_sha256(profile),
            "allowed_profile_differences": [],
            "baseline_tool_commit": prepared["tool_commit"],
            "candidate_tool_commit": prepared["tool_commit"],
            "baseline_source_state": "clean",
            "candidate_source_state": "clean",
            "baseline_dirty_diff_raw_text": None,
            "candidate_dirty_diff_raw_text": None,
            "baseline_dirty_diff_sha256": None,
            "candidate_dirty_diff_sha256": None,
            "baseline_command": command,
            "candidate_command": command,
            "baseline_command_sha256": command_sha,
            "candidate_command_sha256": command_sha,
            "baseline_source_artifacts": source_artifacts,
            "candidate_source_artifacts": source_artifacts,
            "allowed_tool_changes": [],
        },
        "environment": environment,
        "protocol": protocol,
        "correctness": {
            "baseline_raw_json": baseline_correctness,
            "candidate_raw_json": candidate_correctness,
            "baseline_sha256": correctness_hashes["baseline"],
            "candidate_sha256": correctness_hashes["candidate"],
        },
        "warmups": warmups,
        "calibration": calibration,
        "comparison": comparison,
        "absolute_budgets": budgets,
        "operations": {
            name: _pending("fuzz-PC operation has not completed")
            for name in OPERATION_NAMES
        },
    }
    all_samples = warmups + [
        sample
        for pair in [*calibration, *comparison]
        for key, sample in pair.items()
        if key != "pair_index"
    ]
    performance_ended = datetime.now(timezone.utc)
    operation_duration = (performance_ended - operation_started).total_seconds()
    observed_peak = max(sample["peak_rss"]["value"] for sample in all_samples)
    observed_output = sum(sample["output_bytes"]["value"] for sample in all_samples)
    observed_calls = sum(sample["target_api_calls"]["value"] for sample in all_samples)
    raw_operation = {
        "schema_version": "tflite-v7-operation-v1",
        "operation": "actual_parser_performance",
        "mode": "real",
        "target_id": profile["target_id"],
        "tool_commit": prepared["tool_commit"],
        "dirty_diff_sha256": None,
        "profile_sha256": prepared["profile_sha256"],
        "command": command,
        "command_sha256": command_sha,
        "corpus_before_sha256": prepared["corpus_sha256"],
        "corpus_after_sha256": audit_corpus(Path(prepared["corpus_index"]))[0],
        "started_utc": operation_started.isoformat().replace("+00:00", "Z"),
        "ended_utc": performance_ended.isoformat().replace("+00:00", "Z"),
        "duration_seconds": operation_duration,
        "target_api_calls": observed_calls,
        "worker_count": 1,
        "expected_outcome": "completed",
        "observed_outcome": "completed",
        "exit_code": 0,
        "signal": None,
        "residual_processes": sum(
            sample["residual_processes"]["value"] for sample in all_samples
        ),
        "resource_samples": [
            {
                "elapsed_seconds": 0.0,
                "peak_rss_bytes": 0,
                "log_bytes": 0,
                "disk_bytes": 0,
                "owned_processes": 0,
            },
            {
                "elapsed_seconds": operation_duration,
                "peak_rss_bytes": observed_peak,
                "log_bytes": observed_output,
                "disk_bytes": 0,
                "owned_processes": 0,
            },
        ],
        "budgets": dict(prepared["budgets"]),
        "artifacts": [
            {
                "path": "corpus-index.json",
                "sha256": prepared["corpus_index_sha256"],
                "size_bytes": len(corpus_payload),
            }
        ],
    }
    raw_text = canonical(raw_operation).decode("utf-8")
    if mode == "real":
        document["operations"]["actual_parser_performance"] = {
            "status": "pass",
            "reason": None,
            "evidence_sha256": sha256_bytes(raw_text.encode("utf-8")),
            "raw_json": raw_text,
        }
    return document


def performance(args: argparse.Namespace) -> int:
    run_root = args.run_root.absolute()
    prepared = read_prepare(run_root, recheck=True)
    if prepared["mode"] != "real":
        raise EvidenceError("selftest run roots cannot publish actual Q10 evidence")
    if (run_root / "performance.json").exists() or (run_root / "performance.json").is_symlink():
        raise EvidenceError("Q10 performance collection was already completed")
    if (run_root / "observations.json").exists() or (run_root / "observations.json").is_symlink():
        raise EvidenceError("Q10 observations destination already exists")
    active = active_workloads()
    if active:
        raise EvidenceError(f"concurrent fuzz/build workload is active: {active[0]}")
    _memory_total, memory_available, _swap_total, swap_free = _system_memory()
    disk = os.statvfs(run_root)
    if memory_available + swap_free < (
        prepared["budgets"]["peak_rss_bytes"]
        + prepared["budgets"]["peak_rss_bytes"] // 2
    ):
        raise EvidenceError("current WSL memory/swap cannot safely collect Q10")
    if disk.f_bavail * disk.f_frsize < prepared["budgets"]["disk_bytes"]:
        raise EvidenceError("current disk space cannot safely collect Q10")
    cgroup_parent = (
        args.cgroup_parent.resolve(strict=True)
        if args.cgroup_parent is not None
        else _current_cgroup_parent()
    )
    if str(cgroup_parent) == "/sys/fs/cgroup" or not str(cgroup_parent).startswith(
        "/sys/fs/cgroup/"
    ):
        raise EvidenceError("cgroup parent must be a delegated child below /sys/fs/cgroup")
    document = _performance_document(prepared, cgroup_parent)
    if read_prepare(run_root, recheck=True) != prepared:
        raise EvidenceError("prepared identity changed during Q10 collection")
    _require_current_aa(document, prepared)
    try:
        evaluation = baseline.evaluate_document(document)
    except baseline.ContractError as error:
        raise EvidenceError(f"collected performance observations are invalid: {error}") from error
    if evaluation["performance_status"] != "pass" or evaluation["operations"]["actual_parser_performance"]["status"] != "pass":
        raise EvidenceError("collected performance observations do not pass Q10 and actual-parser validation")
    observations_payload = canonical(document)
    exclusive_write(run_root / "observations.json", observations_payload)
    output_root = Path(prepared["evidence_root"])
    try:
        destination = baseline.publish_evidence(document, evaluation, output_root)
    except baseline.EvidenceError as error:
        raise EvidenceError(str(error)) from error
    validate_bundle(
        destination,
        requirement="Q10",
        expected_commit=prepared["tool_commit"],
        expected_profile_sha256=prepared["profile_sha256"],
        require_current_aa=True,
    )
    exclusive_write(
        run_root / "performance.json",
        canonical(
            {
                "schema_version": "tflite-evidence-performance-v1",
                "state": "complete",
                "bundle": str(destination),
                "bundle_index_sha256": sha256_bytes(regular_bytes(destination / "index.json", "bundle index")),
            }
        ),
    )
    print(f"TFLITE_EVIDENCE_Q10_OK=yes bundle={destination}")
    return 0


def process_start_ticks(pid: int) -> str | None:
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError:
        return None
    closing = value.rfind(")")
    fields = value[closing + 2 :].split()
    return fields[19] if closing >= 0 and len(fields) > 19 else None


def _wait_for_supervisor_ready(
    supervisor: subprocess.Popen[bytes],
    ready_fd: int,
    *,
    timeout: float = SUPERVISOR_READY_TIMEOUT_SECONDS,
) -> None:
    deadline = time.monotonic() + timeout
    received = bytearray()
    while bytes(received) != SUPERVISOR_READY:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EvidenceError("supervisor did not become ready before timeout")
        readable, _writable, _exceptional = select.select(
            [ready_fd], [], [], min(remaining, 0.1)
        )
        if not readable:
            if supervisor.poll() is not None:
                raise EvidenceError("supervisor exited before becoming ready")
            continue
        chunk = os.read(ready_fd, len(SUPERVISOR_READY) - len(received))
        if not chunk:
            raise EvidenceError("supervisor closed its readiness channel before becoming ready")
        received.extend(chunk)
        if not SUPERVISOR_READY.startswith(received):
            raise EvidenceError("supervisor returned an invalid readiness marker")


def process_group_sample(group: int) -> tuple[int, int]:
    count = 0
    rss = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat_text = (entry / "stat").read_text(encoding="ascii")
            closing = stat_text.rfind(")")
            fields = stat_text[closing + 2 :].split()
            if int(fields[2]) != group:
                continue
            count += 1
            for line in (entry / "status").read_text(encoding="ascii").splitlines():
                if line.startswith("VmRSS:"):
                    rss += int(line.split()[1]) * 1024
                    break
        except (OSError, ValueError, IndexError):
            continue
    return count, rss


def command_document(path: Path) -> tuple[dict[str, Any], bytes]:
    value, payload = read_json(path, "operation command")
    if set(value) != {"argv", "cwd", "allowed_env"}:
        raise EvidenceError("operation command fields mismatch")
    argv = value["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        raise EvidenceError("operation argv must be a non-empty string array")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise EvidenceError("operation argv[0] must be absolute")
    regular_bytes(executable, "operation executable", 1024 * 1024 * 1024)
    cwd = Path(value["cwd"])
    if not cwd.is_absolute():
        raise EvidenceError("operation cwd must be absolute")
    directory(cwd, "operation cwd")
    environment = value["allowed_env"]
    if not isinstance(environment, dict) or not all(
        isinstance(key, str) and key and isinstance(item, str) for key, item in environment.items()
    ):
        raise EvidenceError("operation allowed_env must be a string map")
    return value, payload


def operation_disk_bytes(operation_root: Path) -> int:
    total = 0
    for current, directories, files in os.walk(operation_root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            metadata = (current_path / name).lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise EvidenceError(f"operation tree contains a linked directory: {current_path / name}")
        for name in files:
            path = current_path / name
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise EvidenceError(f"operation tree contains a non-regular file: {path}")
            total += metadata.st_size
    return total


def _copy_worker_corpus(prepared: dict[str, Any], destination: Path) -> None:
    mkdir_new(destination, "worker corpus")
    source_root = Path(prepared["corpus_index"]).parent
    for row in prepared["corpus_files"]:
        relative = PurePosixPath(row["relative_path"])
        output = destination.joinpath(*relative.parts)
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if output.exists() or output.is_symlink():
            raise EvidenceError(f"worker corpus destination already exists: {output}")
        source = source_root.joinpath(*relative.parts)
        source_payload = regular_bytes(source, f"worker corpus source {relative}")
        exclusive_write(output, source_payload)
        if sha256_bytes(source_payload) != row["sha256"]:
            raise EvidenceError(f"worker corpus source changed while copying: {relative}")


def _operation_argv(
    command: dict[str, Any],
    prepared: dict[str, Any],
    operation_root: Path,
    operation: str,
    worker_index: int,
) -> list[str]:
    worker_root = operation_root / f"worker-{worker_index}"
    mkdir_new(worker_root, "operation worker root")
    corpus_dir = worker_root / "corpus"
    input_path: Path | None = None
    if operation in {"single_worker_soak", "parallel_soak"}:
        _copy_worker_corpus(prepared, corpus_dir)
    else:
        corpus, _ = _corpus_document(prepared)
        expected_outcome = "accepted" if operation == "engine_smoke" else "rejected"
        candidates = [
            row
            for row in corpus["inputs"]
            if row["expected_outcome"] == expected_outcome
            and row["target_api_stage"] == "target-parser"
        ]
        if not candidates:
            raise EvidenceError(
                f"{operation} needs a target-parser {expected_outcome} corpus fixture"
            )
        input_path = Path(prepared["corpus_index"]).parent / candidates[0]["path"]
    result: list[str] = []
    for item in command["argv"]:
        if item == "{corpus_dir}":
            result.append(str(corpus_dir))
        elif item == "{run_dir}":
            result.append(str(worker_root))
        elif item == "{worker_id}":
            result.append(str(worker_index))
        elif item == "{input}":
            if input_path is None:
                raise EvidenceError("fuzzer operation command cannot use {input}")
            result.append(str(input_path))
        elif "{" in item or "}" in item:
            raise EvidenceError(f"unsupported operation command placeholder: {item!r}")
        else:
            result.append(item)
    return result


def validate_operation_file(
    run_root: Path,
    operation: str,
    prepared: dict[str, Any],
) -> None:
    document, _ = read_json(run_root / "observations.json", "preserved performance observations")
    raw = regular_bytes(
        run_root / "operations" / operation / "operation.json",
        f"{operation} raw evidence",
    )
    try:
        raw_text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{operation} raw evidence is not UTF-8") from error
    document["operations"][operation] = {
        "status": "pass",
        "reason": None,
        "evidence_sha256": sha256_bytes(raw),
        "raw_json": raw_text,
    }
    try:
        baseline.evaluate_document(document)
    except baseline.ContractError as error:
        raise EvidenceError(f"{operation} raw evidence is invalid: {error}") from error
    if document["identity"]["candidate_tool_commit"] != prepared["tool_commit"]:
        raise EvidenceError(f"{operation} observation commit does not match prepare")
    raw_document, _ = read_json(
        run_root / "operations" / operation / "operation.json",
        f"{operation} raw evidence",
    )
    artifacts = raw_document.get("artifacts")
    if not isinstance(artifacts, list):
        raise EvidenceError(f"{operation} raw artifact inventory is invalid")
    operation_root = run_root / "operations" / operation
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise EvidenceError(f"{operation} artifact {index} is invalid")
        relative = safe_relative(artifact.get("path"), f"{operation} artifact {index} path")
        payload = regular_bytes(
            operation_root / relative,
            f"{operation} artifact {relative}",
            prepared["budgets"]["log_bytes"],
        )
        if len(payload) != artifact.get("size_bytes") or sha256_bytes(payload) != artifact.get(
            "sha256"
        ):
            raise EvidenceError(f"{operation} artifact changed after collection: {relative}")


def soak_start(args: argparse.Namespace) -> int:
    run_root = args.run_root.absolute()
    prepared = read_prepare(run_root, recheck=True)
    if prepared["mode"] != "real":
        raise EvidenceError("selftest run roots cannot start qualifying operations")
    active = active_workloads()
    if active:
        raise EvidenceError(f"concurrent fuzz/build workload is active: {active[0]}")
    if not (run_root / "performance.json").is_file():
        raise EvidenceError("Q10 performance evidence must complete before V7 operations start")
    command, command_payload = command_document(args.command.resolve(strict=True))
    profile, _ = read_json(Path(prepared["profile"]), "prepared TFLite profile", 4 * 1024 * 1024)
    try:
        baseline._validate_command_environment(command, profile, "operation command")
    except baseline.ContractError as error:
        raise EvidenceError(str(error)) from error
    if "PATH" not in command["allowed_env"]:
        raise EvidenceError("operation command must pin PATH explicitly")
    executable = Path(command["argv"][0])
    executable_sha = sha256_bytes(
        regular_bytes(executable, "operation executable", 1024 * 1024 * 1024)
    )
    matching_binaries = [
        row
        for row in profile.get("binaries", [])
        if isinstance(row, dict)
        and row.get("path") == str(executable)
        and row.get("sha256") == executable_sha
    ]
    if len(matching_binaries) != 1:
        raise EvidenceError("operation executable is not a pinned profile binary")
    expected_role = (
        "replay"
        if args.operation in {"engine_smoke", "fault_injection"}
        else "fuzzer"
    )
    if matching_binaries[0].get("role") != expected_role:
        raise EvidenceError(
            f"{args.operation} requires the profile-pinned {expected_role} binary"
        )
    if expected_role == "fuzzer":
        required_flags = {"-print_final_stats=1", "-max_total_time=21600"}
        missing_flags = sorted(required_flags - set(command["argv"]))
        if missing_flags:
            raise EvidenceError(
                f"soak command misses required libFuzzer flags: {missing_flags}"
            )
    required_placeholder = "{corpus_dir}" if expected_role == "fuzzer" else "{input}"
    if command["argv"].count(required_placeholder) != 1:
        raise EvidenceError(
            f"{args.operation} command must contain exactly one {required_placeholder} placeholder"
        )
    operations_root = run_root / "operations"
    if not operations_root.exists():
        mkdir_new(operations_root, "operations root")
    else:
        directory(operations_root, "operations root")
    for other in BACKGROUND_OPERATIONS:
        controller_path = operations_root / other / "controller.json"
        if not controller_path.is_file():
            continue
        controller, _ = read_json(controller_path, f"{other} operation controller")
        other_pid = controller.get("supervisor_pid")
        if isinstance(other_pid, int) and process_start_ticks(other_pid) == controller.get(
            "supervisor_start_ticks"
        ):
            raise EvidenceError(f"another evidence operation is still active: {other}")
    predecessor = {
        "engine_smoke": None,
        "fault_injection": "engine_smoke",
        "single_worker_soak": "fault_injection",
        "parallel_soak": "single_worker_soak",
    }[args.operation]
    if predecessor is not None:
        if not (operations_root / predecessor / "operation.json").is_file():
            raise EvidenceError(f"{args.operation} requires completed {predecessor} evidence first")
        validate_operation_file(run_root, predecessor, prepared)
    operation_workers = 2 if args.operation == "parallel_soak" else 1
    _memory_total, memory_available, _swap_total, swap_free = _system_memory()
    disk = os.statvfs(run_root)
    disk_free = disk.f_bavail * disk.f_frsize
    required_memory = (
        prepared["budgets"]["peak_rss_bytes"] * operation_workers
        + prepared["budgets"]["peak_rss_bytes"] // 2
    )
    required_disk = prepared["budgets"]["disk_bytes"] * operation_workers
    if memory_available + swap_free < required_memory:
        raise EvidenceError(
            f"current WSL memory/swap cannot safely run {operation_workers} isolated worker(s)"
        )
    if disk_free < required_disk:
        raise EvidenceError(
            f"current disk space cannot safely run {operation_workers} isolated worker(s)"
        )
    operation_root = operations_root / args.operation
    mkdir_new(operation_root, "operation run root")
    exclusive_write(operation_root / "command.json", command_payload)
    ready_read_fd, ready_write_fd = os.pipe()
    supervisor: subprocess.Popen[bytes] | None = None
    try:
        try:
            supervisor = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(Path(__file__).resolve()),
                    "_supervise",
                    "--run-root",
                    str(run_root),
                    "--operation",
                    args.operation,
                    "--sample-seconds",
                    str(args.sample_seconds),
                    "--ready-fd",
                    str(ready_write_fd),
                ],
                cwd="/",
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                pass_fds=(ready_write_fd,),
            )
        finally:
            os.close(ready_write_fd)
        _wait_for_supervisor_ready(supervisor, ready_read_fd)
    except Exception:
        if supervisor is not None and supervisor.poll() is None:
            supervisor.terminate()
            try:
                supervisor.wait(timeout=12.0)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.wait()
        raise
    finally:
        os.close(ready_read_fd)
    assert supervisor is not None
    ticks = process_start_ticks(supervisor.pid)
    if ticks is None:
        if supervisor.poll() is None:
            supervisor.terminate()
            try:
                supervisor.wait(timeout=12.0)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.wait()
        else:
            supervisor.wait()
        raise EvidenceError("supervisor exited before its identity could be captured")
    controller = {
        "schema_version": "tflite-operation-controller-v1",
        "state": "running",
        "operation": args.operation,
        "supervisor_pid": supervisor.pid,
        "supervisor_start_ticks": ticks,
        "operation_root": str(operation_root),
        "command_sha256": sha256_bytes(command_payload),
        "started_utc": utc_now(),
    }
    exclusive_write(operation_root / "controller.json", canonical(controller))
    print(
        "TFLITE_EVIDENCE_SOAK_STARTED=yes "
        f"operation={args.operation} supervisor_pid={supervisor.pid} start_ticks={ticks} "
        f"run_root={run_root}"
    )
    print(f"status: {Path(__file__).resolve()} status --run-root {run_root} --operation {args.operation}")
    print(f"stop: {Path(__file__).resolve()} stop --run-root {run_root} --operation {args.operation}")
    print(f"finalize: {Path(__file__).resolve()} finalize --run-root {run_root} --requirement Q11 --comparison-id ID")
    return 0


def _operation_paths(run_root: Path, operation: str) -> tuple[Path, dict[str, Any]]:
    operation_root = run_root / "operations" / operation
    directory(operation_root, "operation run root")
    controller, _ = read_json(operation_root / "controller.json", "operation controller")
    return operation_root, controller


def status(args: argparse.Namespace) -> int:
    run_root = args.run_root.absolute()
    read_prepare(run_root, recheck=False)
    operation_root, controller = _operation_paths(run_root, args.operation)
    pid = controller.get("supervisor_pid")
    expected_ticks = controller.get("supervisor_start_ticks")
    running = isinstance(pid, int) and process_start_ticks(pid) == expected_ticks
    raw_path = operation_root / "operation.json"
    failure_path = operation_root / "failure.json"
    state = "running" if running else "complete" if raw_path.is_file() else "failed" if failure_path.is_file() else "unknown"
    print(
        json.dumps(
            {
                "operation": args.operation,
                "state": state,
                "supervisor_pid": pid,
                "supervisor_identity_matches": running,
                "operation_root": str(operation_root),
            },
            sort_keys=True,
        )
    )
    return 0 if state in {"running", "complete"} else 1


def stop(args: argparse.Namespace) -> int:
    run_root = args.run_root.absolute()
    read_prepare(run_root, recheck=False)
    _operation_root, controller = _operation_paths(run_root, args.operation)
    pid = controller.get("supervisor_pid")
    ticks = controller.get("supervisor_start_ticks")
    if not isinstance(pid, int) or process_start_ticks(pid) != ticks:
        raise EvidenceError("supervisor identity is absent or changed; refusing to signal")
    os.kill(pid, signal.SIGTERM)
    print(f"TFLITE_EVIDENCE_STOP_REQUESTED=yes operation={args.operation} supervisor_pid={pid}")
    return 0


def _supervise_operation(args: argparse.Namespace) -> int:
    run_root = args.run_root.absolute()
    prepared = read_prepare(run_root, recheck=True)
    operation_root = run_root / "operations" / args.operation
    command, command_payload = command_document(operation_root / "command.json")
    executable_path = Path(command["argv"][0])
    executable_sha = sha256_bytes(
        regular_bytes(executable_path, "operation executable", 1024 * 1024 * 1024)
    )
    worker_count = 2 if args.operation == "parallel_soak" else 1
    started_wall = time.monotonic()
    started_datetime = datetime.now(timezone.utc)
    children: list[subprocess.Popen[bytes]] = []
    descriptors: list[int] = []
    artifact_names: list[str] = []
    stop_requested = False
    stop_requested_at: float | None = None
    resource_failure: str | None = None
    operation_budgets = dict(prepared["budgets"])
    if worker_count == 2:
        operation_budgets = {key: value * 2 for key, value in operation_budgets.items()}

    def handle_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested, stop_requested_at
        stop_requested = True
        if stop_requested_at is None:
            stop_requested_at = time.monotonic()
        for child in children:
            if child.poll() is not None:
                continue
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)
    samples: list[dict[str, Any]] = []
    peak_rss = 0

    def enforce_budgets(sample: dict[str, Any]) -> None:
        nonlocal resource_failure, stop_requested_at
        for sample_key, budget_key in (
            ("peak_rss_bytes", "peak_rss_bytes"),
            ("log_bytes", "log_bytes"),
            ("disk_bytes", "disk_bytes"),
        ):
            if sample[sample_key] <= operation_budgets[budget_key]:
                continue
            resource_failure = f"{sample_key}_budget_exceeded"
            if stop_requested_at is None:
                stop_requested_at = time.monotonic()
            for child in children:
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
            break

    try:
        for worker_index in range(1, worker_count + 1):
            suffix = f"-{worker_index}" if worker_count > 1 else ""
            stdout_path = operation_root / f"stdout{suffix}.log"
            stderr_path = operation_root / f"stderr{suffix}.log"
            stdout_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            stderr_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            descriptors.extend((stdout_fd, stderr_fd))
            artifact_names.extend((stdout_path.name, stderr_path.name))
            environment = dict(command["allowed_env"])
            children.append(
                subprocess.Popen(
                    _operation_argv(
                        command,
                        prepared,
                        operation_root,
                        args.operation,
                        worker_index,
                    ),
                    cwd=command["cwd"],
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_fd,
                    stderr=stderr_fd,
                    start_new_session=True,
                    close_fds=True,
                )
            )
        ready_fd = getattr(args, "ready_fd", None)
        if ready_fd is not None:
            try:
                view = memoryview(SUPERVISOR_READY)
                while view:
                    view = view[os.write(ready_fd, view) :]
            finally:
                os.close(ready_fd)
        initial_groups = [process_group_sample(child.pid) for child in children]
        samples.append(
            {
                "elapsed_seconds": time.monotonic() - started_wall,
                "peak_rss_bytes": sum(row[1] for row in initial_groups),
                "log_bytes": sum(os.fstat(descriptor).st_size for descriptor in descriptors),
                "disk_bytes": operation_disk_bytes(operation_root),
                "owned_processes": sum(row[0] for row in initial_groups),
            }
        )
        peak_rss = samples[0]["peak_rss_bytes"]
        enforce_budgets(samples[-1])
        while any(child.poll() is None for child in children):
            elapsed = time.monotonic() - started_wall
            group_samples = [process_group_sample(child.pid) for child in children]
            owned = sum(row[0] for row in group_samples)
            rss = sum(row[1] for row in group_samples)
            peak_rss = max(peak_rss, rss)
            samples.append(
                {
                    "elapsed_seconds": elapsed,
                    "peak_rss_bytes": peak_rss,
                    "log_bytes": sum(os.fstat(descriptor).st_size for descriptor in descriptors),
                    "disk_bytes": operation_disk_bytes(operation_root),
                    "owned_processes": owned,
                }
            )
            enforce_budgets(samples[-1])
            if stop_requested_at is not None and time.monotonic() - stop_requested_at >= 10.0:
                for child in children:
                    if child.poll() is None:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
            time.sleep(min(args.sample_seconds, 1.0 if stop_requested else args.sample_seconds))
        exit_codes = [child.wait() for child in children]
        duration = time.monotonic() - started_wall
        group_samples = [process_group_sample(child.pid) for child in children]
        owned = sum(row[0] for row in group_samples)
        rss = sum(row[1] for row in group_samples)
        peak_rss = max(peak_rss, rss)
        samples.append(
            {
                "elapsed_seconds": duration,
                "peak_rss_bytes": peak_rss,
                "log_bytes": sum(os.fstat(descriptor).st_size for descriptor in descriptors),
                "disk_bytes": operation_disk_bytes(operation_root),
                "owned_processes": owned,
            }
        )
        enforce_budgets(samples[-1])
    finally:
        if sys.exc_info()[0] is not None:
            for child in children:
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            for child in children:
                try:
                    child.wait(timeout=2.0)
                except (subprocess.TimeoutExpired, ChildProcessError):
                    pass
        for descriptor in descriptors:
            os.close(descriptor)
    if not children:
        raise EvidenceError("operation child did not start")
    residual_processes = samples[-1]["owned_processes"]
    if residual_processes:
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        time.sleep(0.2)
        for child in children:
            if process_group_sample(child.pid)[0]:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    if stop_requested:
        failure = {
            "schema_version": "tflite-operation-failure-v1",
            "reason": "user_stop",
            "exit_codes": exit_codes,
            "residual_processes_before_cleanup": residual_processes,
        }
        exclusive_write(operation_root / "failure.json", canonical(failure))
        return 1
    if resource_failure is not None:
        failure = {
            "schema_version": "tflite-operation-failure-v1",
            "reason": resource_failure,
            "exit_codes": exit_codes,
            "residual_processes_before_cleanup": residual_processes,
        }
        exclusive_write(operation_root / "failure.json", canonical(failure))
        return 1
    if sha256_bytes(
        regular_bytes(executable_path, "operation executable", 1024 * 1024 * 1024)
    ) != executable_sha:
        raise EvidenceError("operation executable changed during the run")
    profile, _ = read_json(Path(prepared["profile"]), "prepared TFLite profile")
    expected_outcome = "worker_failure" if args.operation == "fault_injection" else "completed"
    corpus_after_sha, _ = audit_corpus(Path(prepared["corpus_index"]))
    target_calls: list[int] = []
    for worker_index in range(worker_count):
        suffix = f"-{worker_index + 1}" if worker_count > 1 else ""
        stdout = regular_bytes(operation_root / f"stdout{suffix}.log", "operation stdout")
        stderr = regular_bytes(operation_root / f"stderr{suffix}.log", "operation stderr")
        if args.operation in {"engine_smoke", "fault_injection"}:
            calls = len(LOAD_MARKER.findall(stdout + stderr))
            if args.operation == "engine_smoke" and not (
                LOAD_OK_MARKER.search(stdout + stderr)
                and ACCESS_OK_MARKER.search(stdout + stderr)
            ):
                raise EvidenceError("engine smoke did not reach load/allocate/access markers")
            if args.operation == "fault_injection" and not LOAD_REJECT_MARKER.search(
                stdout + stderr
            ):
                raise EvidenceError("fault injection did not preserve a loader rejection marker")
        else:
            counts = [int(value) for value in LIBFUZZER_EXECUTED_UNITS.findall(stderr)]
            if not counts:
                raise EvidenceError(
                    "libFuzzer soak log lacks stat::number_of_executed_units final evidence"
                )
            calls = counts[-1]
        if calls <= 0:
            raise EvidenceError("operation transcript proves zero target API calls")
        target_calls.append(calls)
    if args.operation == "fault_injection":
        qualifying_exit = exit_codes[0]
    else:
        qualifying_exit = 0 if all(value == 0 for value in exit_codes) else next(
            value for value in exit_codes if value != 0
        )
    observed_signal = None
    if qualifying_exit < 0:
        observed_signal = signal.Signals(-qualifying_exit).name
        qualifying_exit = 128 - qualifying_exit
    observed_outcome = (
        "completed" if all(value == 0 for value in exit_codes) else "worker_failure"
    )
    ended_datetime = started_datetime + timedelta(seconds=duration)
    operation_value = {
        "schema_version": "tflite-v7-operation-v1",
        "operation": args.operation,
        "mode": "real",
        "target_id": profile["target_id"],
        "tool_commit": prepared["tool_commit"],
        "dirty_diff_sha256": prepared["dirty_diff_sha256"],
        "profile_sha256": prepared["profile_sha256"],
        "command": {
            **command,
            "executable_sha256": executable_sha,
        },
        "command_sha256": "",
        "corpus_before_sha256": prepared["corpus_sha256"],
        "corpus_after_sha256": corpus_after_sha,
        "started_utc": started_datetime.isoformat().replace("+00:00", "Z"),
        "ended_utc": ended_datetime.isoformat().replace("+00:00", "Z"),
        "duration_seconds": duration,
        "target_api_calls": sum(target_calls),
        "worker_count": worker_count,
        "expected_outcome": expected_outcome,
        "observed_outcome": observed_outcome,
        "exit_code": qualifying_exit,
        "signal": observed_signal,
        "residual_processes": residual_processes,
        "resource_samples": samples,
        "budgets": operation_budgets,
        "artifacts": [
            {
                "path": name,
                "sha256": sha256_bytes(regular_bytes(operation_root / name, name)),
                "size_bytes": (operation_root / name).stat().st_size,
            }
            for name in artifact_names
        ],
    }
    operation_value["command_sha256"] = sha256_bytes(canonical(operation_value["command"]))
    exclusive_write(operation_root / "operation.json", canonical(operation_value))
    return 0


def _supervise(args: argparse.Namespace) -> int:
    try:
        return _supervise_operation(args)
    except (
        EvidenceError,
        OSError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
        baseline.ContractError,
    ) as error:
        failure_path = (
            args.run_root.absolute()
            / "operations"
            / args.operation
            / "failure.json"
        )
        if not failure_path.exists() and not failure_path.is_symlink():
            try:
                exclusive_write(
                    failure_path,
                    canonical(
                        {
                            "schema_version": "tflite-operation-failure-v1",
                            "reason": "supervisor_error",
                            "error": str(error),
                        }
                    ),
                )
            except (EvidenceError, OSError):
                pass
        print(f"[tflite-evidence-supervisor] fail: {error}", file=sys.stderr)
        return 1


def finalize(args: argparse.Namespace) -> int:
    run_root = args.run_root.absolute()
    prepared = read_prepare(run_root, recheck=True)
    finalize_path = run_root / f"finalize-{args.requirement.lower()}.json"
    if finalize_path.exists() or finalize_path.is_symlink():
        raise EvidenceError(f"run root was already finalized for {args.requirement}")
    performance_record, _ = read_json(run_root / "performance.json", "performance completion")
    if args.requirement == "Q10":
        destination = Path(performance_record["bundle"])
    else:
        if baseline.SAFE_ID.fullmatch(args.comparison_id) is None:
            raise EvidenceError("final Q11 comparison ID is unsafe")
        if args.comparison_id == prepared["comparison_id"]:
            raise EvidenceError("final Q11 bundle needs a distinct comparison ID")
        document, _ = read_json(run_root / "observations.json", "preserved performance observations")
        document["comparison_id"] = args.comparison_id
        for name in BACKGROUND_OPERATIONS:
            validate_operation_file(run_root, name, prepared)
            raw = regular_bytes(run_root / "operations" / name / "operation.json", f"{name} raw evidence")
            try:
                raw_text = raw.decode("utf-8", "strict")
            except UnicodeDecodeError as error:
                raise EvidenceError(f"{name} raw evidence is not UTF-8") from error
            document["operations"][name] = {
                "status": "pass",
                "reason": None,
                "evidence_sha256": sha256_bytes(raw),
                "raw_json": raw_text,
            }
        destination = Path(prepared["evidence_root"]) / args.comparison_id
        if destination.exists() or destination.is_symlink():
            validate_bundle(
                destination,
                requirement="Q11",
                expected_commit=prepared["tool_commit"],
                expected_profile_sha256=prepared["profile_sha256"],
                require_current_aa=True,
            )
        else:
            try:
                evaluation = baseline.evaluate_document(document)
                destination = baseline.publish_evidence(
                    document, evaluation, Path(prepared["evidence_root"])
                )
            except (baseline.ContractError, baseline.EvidenceError) as error:
                raise EvidenceError(f"final Q11 bundle publication failed: {error}") from error
    validate_bundle(
        destination,
        requirement=args.requirement,
        expected_commit=prepared["tool_commit"],
        expected_profile_sha256=prepared["profile_sha256"],
        require_current_aa=True,
    )
    exclusive_write(
        finalize_path,
        canonical(
            {
                "schema_version": "tflite-evidence-finalize-v1",
                "state": "complete",
                "requirement": args.requirement,
                "bundle": str(destination),
                "finalized_utc": utc_now(),
            }
        ),
    )
    print(f"TFLITE_EVIDENCE_FINALIZED=yes requirement={args.requirement} bundle={destination}")
    return 0


def validate_command(args: argparse.Namespace) -> int:
    identities = validate_bundle(
        args.bundle.absolute(),
        requirement=args.requirement,
        expected_commit=args.expected_commit,
        expected_profile_sha256=args.expected_profile_sha256,
        require_current_aa=args.require_current_aa,
    )
    print(f"TFLITE_EVIDENCE_BUNDLE_OK=yes requirement={args.requirement} files={len(identities)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--run-root", required=True, type=Path)
    prepare_parser.add_argument("--profile", required=True, type=Path)
    prepare_parser.add_argument("--replay", required=True, type=Path)
    prepare_parser.add_argument("--corpus-index", required=True, type=Path)
    prepare_parser.add_argument("--corpus-sha256", required=True)
    prepare_parser.add_argument("--evidence-root", required=True, type=Path)
    prepare_parser.add_argument("--comparison-id", required=True)
    prepare_parser.add_argument("--expected-commit", required=True)
    prepare_parser.add_argument("--mode", choices=("real", "selftest"), default="real")
    prepare_parser.add_argument("--peak-rss-bytes", type=int, default=1_073_741_824)
    prepare_parser.add_argument("--log-bytes", type=int, required=True)
    prepare_parser.add_argument("--disk-bytes", type=int, required=True)
    prepare_parser.set_defaults(function=prepare)

    performance_parser = subparsers.add_parser("performance")
    performance_parser.add_argument("--run-root", required=True, type=Path)
    performance_parser.add_argument("--cgroup-parent", type=Path)
    performance_parser.set_defaults(function=performance)

    start_parser = subparsers.add_parser("soak-start")
    start_parser.add_argument("--run-root", required=True, type=Path)
    start_parser.add_argument("--operation", required=True, choices=BACKGROUND_OPERATIONS)
    start_parser.add_argument("--command", required=True, type=Path)
    start_parser.add_argument("--sample-seconds", type=float, default=10.0)
    start_parser.set_defaults(function=soak_start)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--run-root", required=True, type=Path)
    status_parser.add_argument("--operation", required=True, choices=BACKGROUND_OPERATIONS)
    status_parser.set_defaults(function=status)

    stop_parser = subparsers.add_parser("stop")
    stop_parser.add_argument("--run-root", required=True, type=Path)
    stop_parser.add_argument("--operation", required=True, choices=BACKGROUND_OPERATIONS)
    stop_parser.set_defaults(function=stop)

    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--run-root", required=True, type=Path)
    finalize_parser.add_argument("--requirement", required=True, choices=("Q10", "Q11"))
    finalize_parser.add_argument("--comparison-id")
    finalize_parser.set_defaults(function=finalize)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--bundle", required=True, type=Path)
    validate_parser.add_argument("--requirement", required=True, choices=("Q10", "Q11"))
    validate_parser.add_argument("--expected-commit", required=True)
    validate_parser.add_argument("--expected-profile-sha256", required=True)
    validate_parser.add_argument("--require-current-aa", action="store_true")
    validate_parser.set_defaults(function=validate_command)

    supervise_parser = subparsers.add_parser("_supervise", help=argparse.SUPPRESS)
    supervise_parser.add_argument("--run-root", required=True, type=Path)
    supervise_parser.add_argument("--operation", required=True, choices=BACKGROUND_OPERATIONS)
    supervise_parser.add_argument("--sample-seconds", required=True, type=float)
    supervise_parser.add_argument("--ready-fd", required=True, type=int)
    supervise_parser.set_defaults(function=_supervise)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "sample_seconds", 1.0) <= 0:
        parser.error("--sample-seconds must be > 0")
    if getattr(args, "requirement", None) == "Q11" and not getattr(args, "comparison_id", None):
        parser.error("Q11 finalize requires --comparison-id")
    try:
        return int(args.function(args))
    except (
        EvidenceError,
        OSError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
        baseline.ContractError,
    ) as error:
        if args.command == "_supervise":
            failure_path = (
                args.run_root.absolute()
                / "operations"
                / args.operation
                / "failure.json"
            )
            if not failure_path.exists() and not failure_path.is_symlink():
                try:
                    exclusive_write(
                        failure_path,
                        canonical(
                            {
                                "schema_version": "tflite-operation-failure-v1",
                                "reason": "supervisor_error",
                                "error": str(error),
                            }
                        ),
                    )
                except (EvidenceError, OSError):
                    pass
        print(f"[tflite-evidence] fail: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
