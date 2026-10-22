#!/usr/bin/env python3
"""Audit FND-03 evidence and issue a TFLite qualification sidecar.

This is intentionally TFLite-specific.  A verified sidecar is emitted only when
all Q01..Q12 suites pass for one immutable profile and one clean tool commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Iterable


SUITE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "unit": ("Q01", "Q05"),
    "oracle": ("Q02", "Q03", "Q04"),
    "engine": ("Q06",),
    "coverage": ("Q07",),
    "integration": ("Q08", "Q09"),
    "performance": ("Q10",),
    "soak": ("Q11",),
    "install": ("Q12",),
}
ALL_REQUIREMENTS = tuple(f"Q{number:02}" for number in range(1, 13))
STATUS_NAMES = {"pass", "fail", "blocked", "not_run", "inconclusive"}
HASH_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PROFILE_BYTES = 4 * 1024 * 1024
RECORD_FIELDS = {
    "schema_version",
    "requirement_id",
    "task_id",
    "status",
    "reason",
    "expected",
    "observed",
    "command_argv",
    "command_executable",
    "identity_files",
    "cwd",
    "allowed_env",
    "tool_commit",
    "dirty_diff_sha256",
    "validation_run_id",
    "profile_sha256",
    "corpus_index_sha256",
    "start_utc",
    "end_utc",
    "elapsed_ms",
    "exit_code",
    "signal",
    "stdout",
    "stderr",
    "result",
    "artifacts",
}


class QualificationError(Exception):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise QualificationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


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
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise QualificationError(f"could not serialize qualification: {error}") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def regular_metadata(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationError(f"could not inspect {label} '{path}': {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise QualificationError(f"{label} must be a private regular file: {path}")
    return metadata


def directory_metadata(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationError(f"could not inspect {label} '{path}': {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise QualificationError(f"{label} must be a directory, not a symlink: {path}")
    return metadata


def read_regular(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    metadata = regular_metadata(path, label)
    if metadata.st_size > maximum:
        raise QualificationError(f"{label} exceeds {maximum} bytes: {path}")
    try:
        value = path.read_bytes()
    except OSError as error:
        raise QualificationError(f"could not read {label} '{path}': {error}") from error
    if len(value) != metadata.st_size:
        raise QualificationError(f"{label} changed while being read: {path}")
    return value


def read_external_identity(path: Path, label: str, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise QualificationError(f"could not inspect {label} '{path}': {error}") from error
    require(stat.S_ISREG(before.st_mode), f"{label} must be a regular file: {path}")
    require(before.st_size <= maximum, f"{label} exceeds {maximum} bytes: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise QualificationError(f"could not open {label} '{path}': {error}") from error
    try:
        opened = os.fstat(descriptor)
        require(
            stat.S_ISREG(opened.st_mode)
            and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
            f"{label} changed while being opened: {path}",
        )
        chunks: list[bytes] = []
        observed_size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed_size))
            if not chunk:
                break
            chunks.append(chunk)
            observed_size += len(chunk)
            require(observed_size <= maximum, f"{label} exceeds {maximum} bytes: {path}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    require(
        (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        == (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ),
        f"{label} changed while being read: {path}",
    )
    value = b"".join(chunks)
    require(len(value) == after.st_size, f"{label} size changed while being read: {path}")
    return value


def read_json(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    payload = read_regular(path, label, maximum)
    try:
        value = json.loads(payload, object_pairs_hook=unique_object)
    except QualificationError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise QualificationError(f"invalid {label} JSON '{path}': {error}") from error
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be a JSON object: {path}")
    return value, payload


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def require_hash(value: Any, label: str) -> str:
    require(isinstance(value, str) and HASH_RE.fullmatch(value) is not None, f"{label} is not sha256")
    return value


def require_commit(value: Any, label: str) -> str:
    require(isinstance(value, str) and COMMIT_RE.fullmatch(value) is not None, f"{label} is not a commit")
    return value


def require_string_list(value: Any, label: str) -> list[str]:
    require(isinstance(value, list) and all(isinstance(item, str) and item for item in value), f"{label} must be a nonempty string array")
    require(len(value) == len(set(value)), f"{label} contains duplicates")
    return value


def exact_inventory(path: Path, files: Iterable[str], directories: Iterable[str], label: str) -> None:
    expected_files = set(files)
    expected_directories = set(directories)
    try:
        entries = {entry.name: entry for entry in os.scandir(path)}
    except OSError as error:
        raise QualificationError(f"could not inspect {label}: {error}") from error
    observed = set(entries)
    expected = expected_files | expected_directories
    require(
        observed == expected,
        f"{label} inventory mismatch: missing={sorted(expected - observed)}, unexpected={sorted(observed - expected)}",
    )
    for name in expected_files:
        metadata = entries[name].stat(follow_symlinks=False)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, f"{label} file is not private regular: {name}")
    for name in expected_directories:
        metadata = entries[name].stat(follow_symlinks=False)
        require(stat.S_ISDIR(metadata.st_mode), f"{label} directory is invalid: {name}")


def safe_relative(value: Any, prefix: str, label: str) -> str:
    require(isinstance(value, str) and value.startswith(prefix), f"{label} has invalid path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts), f"{label} path escapes evidence")
    return value


def verify_file_metadata(root: Path, metadata: Any, expected_path: str, label: str) -> None:
    require(isinstance(metadata, dict), f"{label} metadata must be an object")
    require(metadata.get("path") == expected_path, f"{label} path mismatch")
    missing = metadata.get("missing")
    require(missing is False, f"{label} is missing")
    require(metadata.get("error") is None, f"{label} records an error")
    expected_hash = require_hash(metadata.get("sha256"), f"{label}.sha256")
    size = metadata.get("size_bytes")
    require(isinstance(size, int) and size >= 0, f"{label}.size_bytes is invalid")
    payload = read_regular(root / expected_path, label)
    require(len(payload) == size, f"{label} size mismatch")
    require(sha256_bytes(payload) == expected_hash, f"{label} hash mismatch")


def verify_stream(root: Path, metadata: Any, expected_path: str, label: str) -> None:
    require(isinstance(metadata, dict), f"{label} metadata must be an object")
    require(metadata.get("path") == expected_path, f"{label} path mismatch")
    require(isinstance(metadata.get("truncated"), bool), f"{label}.truncated is invalid")
    expected_hash = require_hash(metadata.get("sha256"), f"{label}.sha256")
    size = metadata.get("size_bytes")
    require(isinstance(size, int) and size >= 0, f"{label}.size_bytes is invalid")
    payload = read_regular(root / expected_path, label)
    require(len(payload) == size, f"{label} size mismatch")
    require(sha256_bytes(payload) == expected_hash, f"{label} hash mismatch")


def verify_identity_file(path_value: Any, hash_value: Any, label: str) -> tuple[Path, str]:
    require(isinstance(path_value, str), f"{label}.path must be a string")
    path = Path(path_value)
    require(path.is_absolute(), f"{label}.path must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise QualificationError(f"could not resolve {label} '{path}': {error}") from error
    require(resolved == path, f"{label}.path must be canonical")
    expected_hash = require_hash(hash_value, f"{label}.sha256")
    payload = read_external_identity(path, label, 1024 * 1024 * 1024)
    require(sha256_bytes(payload) == expected_hash, f"{label} hash mismatch")
    return path, expected_hash


def verify_record_identity(metadata: Any, label: str) -> tuple[Path, str]:
    require(isinstance(metadata, dict), f"{label} must be an object")
    path, expected_hash = verify_identity_file(
        metadata.get("path"), metadata.get("sha256"), label
    )
    size = metadata.get("size_bytes")
    require(isinstance(size, int) and size >= 0, f"{label}.size_bytes is invalid")
    require(path.stat().st_size == size, f"{label} size mismatch")
    return path, expected_hash


def audit_profile(path: Path) -> tuple[str, bytes, list[tuple[Path, str]]]:
    require(path.is_absolute(), "profile path must be absolute")
    profile, payload = read_json(path, "TFLite profile", MAX_PROFILE_BYTES)
    require(profile.get("schema_version") == "1", "profile schema_version must be 1")
    require(profile.get("target_id") == "tflite", "profile target_id must be tflite")
    require(profile.get("depth") == "load-allocate-access", "profile depth mismatch")
    artifacts = profile.get("source_artifacts")
    require(isinstance(artifacts, list) and artifacts, "profile source_artifacts must not be empty")
    for index, artifact in enumerate(artifacts):
        require(isinstance(artifact, dict), f"source_artifacts[{index}] must be an object")
        url = artifact.get("url")
        require(isinstance(url, str) and url.startswith("https://"), f"source_artifacts[{index}].url must use https")
        require(isinstance(artifact.get("tag"), str) and artifact["tag"], f"source_artifacts[{index}].tag is empty")
        require(isinstance(artifact.get("resolved_commit"), str) and artifact["resolved_commit"], f"source_artifacts[{index}].resolved_commit is empty")
        require_hash(artifact.get("sha256"), f"source_artifacts[{index}].sha256")
        require(isinstance(artifact.get("size_bytes"), int) and artifact["size_bytes"] > 0, f"source_artifacts[{index}].size_bytes is invalid")

    engine_capabilities = profile.get("engine_capabilities")
    require(isinstance(engine_capabilities, list) and len(engine_capabilities) == 1, "profile must declare exactly one TFLite backend")
    capability = engine_capabilities[0]
    require(
        capability == {
            "backend": "local-harness",
            "binary_role": "replay",
            "required_mode": "native",
            "instrumentation_scope": "tensorflow/lite",
        },
        "profile backend/depth scope mismatch",
    )

    identities: list[tuple[Path, str]] = []
    for index, patch in enumerate(profile.get("patches", [])):
        require(isinstance(patch, dict), f"patches[{index}] must be an object")
        identities.append(verify_identity_file(patch.get("path"), patch.get("sha256"), f"profile patch {index}"))
    toolchain = profile.get("toolchain")
    require(isinstance(toolchain, dict), "profile toolchain must be an object")
    for name in ("compiler", "linker", "engine"):
        item = toolchain.get(name)
        require(isinstance(item, dict), f"profile toolchain.{name} must be an object")
        identities.append(verify_identity_file(item.get("path"), item.get("sha256"), f"profile toolchain.{name}"))
    for name in ("python", "rust"):
        item = toolchain.get(name)
        if item is not None:
            require(isinstance(item, dict), f"profile toolchain.{name} must be null or object")
            identities.append(verify_identity_file(item.get("path"), item.get("sha256"), f"profile toolchain.{name}"))

    binaries = profile.get("binaries")
    require(isinstance(binaries, list) and binaries, "profile binaries must not be empty")
    roles: set[str] = set()
    for index, binary in enumerate(binaries):
        require(isinstance(binary, dict), f"binaries[{index}] must be an object")
        role = binary.get("role")
        require(isinstance(role, str) and role and role not in roles, f"binaries[{index}].role is invalid")
        roles.add(role)
        identities.append(verify_identity_file(binary.get("path"), binary.get("sha256"), f"profile binary {role}"))
        linked = binary.get("linked_libraries")
        require(isinstance(linked, list), f"profile binary {role} linked_libraries must be an array")
        for library_index, library in enumerate(linked):
            require(isinstance(library, dict), f"linked library {library_index} must be an object")
            identities.append(
                verify_identity_file(
                    library.get("path"),
                    library.get("sha256"),
                    f"profile binary {role} linked library {library_index}",
                )
            )
    require("replay" in roles, "profile has no replay binary")
    return sha256_bytes(payload), payload, identities


def audit_record_tree(
    suite_root: Path,
    task_id: str,
    record: dict[str, Any],
    profile_hash: str,
    tool_commit: str,
    dirty_diff: str | None,
) -> list[tuple[Path, str]]:
    missing_fields = sorted(RECORD_FIELDS - set(record))
    require(not missing_fields, f"record {task_id} misses fields: {missing_fields}")
    require(record.get("schema_version") == "1", f"record {task_id} schema mismatch")
    require(record.get("task_id") == task_id, f"record {task_id} task ID mismatch")
    require(record.get("status") in STATUS_NAMES, f"record {task_id} status is invalid")
    require(record.get("profile_sha256") == profile_hash, f"record {task_id} profile mismatch")
    require(record.get("tool_commit") == tool_commit, f"record {task_id} tool commit mismatch")
    require(record.get("dirty_diff_sha256") == dirty_diff, f"record {task_id} dirty identity mismatch")
    command_argv = require_string_list(record.get("command_argv"), f"record {task_id} command argv")
    command_path, command_hash = verify_record_identity(
        record.get("command_executable"), f"record {task_id} command executable"
    )
    try:
        argv_executable = Path(command_argv[0]).resolve(strict=True)
    except OSError as error:
        raise QualificationError(
            f"record {task_id} command executable cannot be resolved: {error}"
        ) from error
    require(
        argv_executable == command_path,
        f"record {task_id} command executable does not match argv[0]",
    )
    raw_identities = record.get("identity_files")
    require(isinstance(raw_identities, list), f"record {task_id} identity_files must be an array")
    require(len(raw_identities) <= 64, f"record {task_id} has too many identity files")
    execution_identities = [(command_path, command_hash)]
    identity_paths: set[Path] = set()
    for index, metadata in enumerate(raw_identities):
        identity_path, identity_hash = verify_record_identity(
            metadata, f"record {task_id} identity_files[{index}]"
        )
        require(
            identity_path not in identity_paths,
            f"record {task_id} identity_files contains a duplicate path",
        )
        identity_paths.add(identity_path)
        execution_identities.append((identity_path, identity_hash))
    verify_stream(suite_root, record.get("stdout"), f"logs/{task_id}.stdout", f"record {task_id} stdout")
    verify_stream(suite_root, record.get("stderr"), f"logs/{task_id}.stderr", f"record {task_id} stderr")

    expected_task_files: set[str] = set()
    result = record.get("result")
    require(isinstance(result, dict), f"record {task_id} result metadata is invalid")
    result_path = f"tasks/{task_id}/result.json"
    require(result.get("path") == result_path, f"record {task_id} result path mismatch")
    if result.get("missing") is False:
        verify_file_metadata(suite_root, result, result_path, f"record {task_id} result")
        expected_task_files.add("result.json")
    else:
        require(result.get("missing") is True, f"record {task_id} result missing flag is invalid")
        require(record.get("status") != "pass", f"passing record {task_id} has no child result")

    artifacts = record.get("artifacts")
    require(isinstance(artifacts, list), f"record {task_id} artifacts must be an array")
    for index, artifact in enumerate(artifacts):
        require(isinstance(artifact, dict), f"record {task_id} artifact {index} is invalid")
        prefix = f"tasks/{task_id}/"
        relative = safe_relative(artifact.get("path"), prefix, f"record {task_id} artifact {index}")
        if artifact.get("missing") is False:
            verify_file_metadata(suite_root, artifact, relative, f"record {task_id} artifact {index}")
            expected_task_files.add(relative[len(prefix) :])
        else:
            require(artifact.get("missing") is True, f"record {task_id} artifact missing flag is invalid")

    task_root = suite_root / "tasks" / task_id
    actual_files: set[str] = set()
    for current, directories, files in os.walk(task_root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            metadata = (current_path / name).lstat()
            require(stat.S_ISDIR(metadata.st_mode), f"task {task_id} contains a linked directory")
        for name in files:
            path = current_path / name
            regular_metadata(path, f"task {task_id} evidence")
            actual_files.add(path.relative_to(task_root).as_posix())
    require(actual_files == expected_task_files, f"task {task_id} evidence inventory mismatch")
    return execution_identities


def audit_suite(
    root: Path,
    suite: str,
    profile_hash: str,
) -> tuple[
    dict[str, str],
    dict[str, str],
    str,
    str | None,
    list[tuple[Path, str]],
]:
    suite_root = root / suite
    directory_metadata(suite_root, f"{suite} evidence")
    run, run_bytes = read_json(suite_root / "run.json", f"{suite} run manifest")
    summary, _summary_bytes = read_json(suite_root / "summary.json", f"{suite} summary")
    expected_requirements = list(SUITE_REQUIREMENTS[suite])

    require(run.get("schema_version") == "1" and run.get("state") == "incomplete", f"{suite} run manifest state mismatch")
    require(run.get("target_id") == "tflite" and run.get("suite") == suite, f"{suite} run target/suite mismatch")
    require(run.get("profile_sha256") == profile_hash, f"{suite} run profile mismatch")
    require(run.get("required_requirement_ids") == expected_requirements, f"{suite} run requirement coverage mismatch")
    task_ids = require_string_list(run.get("required_task_ids"), f"{suite} run task IDs")
    tool_commit = require_commit(run.get("tool_commit"), f"{suite} run tool_commit")
    dirty_diff = run.get("dirty_diff_sha256")
    if dirty_diff is not None:
        require_hash(dirty_diff, f"{suite} run dirty_diff_sha256")
    run_hash = sha256_bytes(run_bytes)

    require(summary.get("schema_version") == "1" and summary.get("state") == "complete", f"{suite} summary state mismatch")
    require(summary.get("target_id") == "tflite" and summary.get("suite") == suite, f"{suite} summary target/suite mismatch")
    require(summary.get("profile_sha256") == profile_hash, f"{suite} summary profile mismatch")
    require(summary.get("run_manifest_sha256") == run_hash, f"{suite} run manifest hash mismatch")
    require(summary.get("required_requirement_ids") == expected_requirements, f"{suite} summary requirement coverage mismatch")
    require(summary.get("required_task_ids") == task_ids, f"{suite} summary task coverage mismatch")
    require(summary.get("qualification_candidate") is None, f"{suite} forged a qualification candidate")
    require(summary.get("requirements_sha256") == run.get("requirements_sha256"), f"{suite} requirements identity mismatch")
    require(summary.get("validation_run_id") == run.get("validation_run_id"), f"{suite} validation run mismatch")
    require(summary.get("validator") == run.get("validator"), f"{suite} validator mismatch")

    record_hashes = summary.get("record_sha256")
    requirement_hashes = summary.get("requirement_evidence_sha256")
    require(isinstance(record_hashes, dict) and set(record_hashes) == set(task_ids), f"{suite} record hash inventory mismatch")
    require(isinstance(requirement_hashes, dict) and list(requirement_hashes) == expected_requirements, f"{suite} requirement hash inventory mismatch")
    exact_inventory(
        suite_root,
        {"run.json", "summary.json"},
        {"records", "logs", "tasks", "requirements"},
        f"{suite} evidence root",
    )
    exact_inventory(
        suite_root / "records",
        {f"{task_id}.json" for task_id in task_ids},
        set(),
        f"{suite} records",
    )
    exact_inventory(
        suite_root / "logs",
        {f"{task_id}.{stream}" for task_id in task_ids for stream in ("stdout", "stderr")},
        set(),
        f"{suite} logs",
    )
    exact_inventory(
        suite_root / "tasks",
        set(),
        set(task_ids),
        f"{suite} tasks",
    )
    exact_inventory(
        suite_root / "requirements",
        {f"{requirement}.json" for requirement in expected_requirements},
        set(),
        f"{suite} requirements",
    )

    records: dict[str, dict[str, Any]] = {}
    execution_identities: list[tuple[Path, str]] = []
    counts = {name: 0 for name in STATUS_NAMES}
    for task_id in task_ids:
        record, record_bytes = read_json(suite_root / "records" / f"{task_id}.json", f"{suite} record {task_id}")
        require(sha256_bytes(record_bytes) == require_hash(record_hashes[task_id], f"{suite} record hash {task_id}"), f"{suite} record {task_id} hash mismatch")
        execution_identities.extend(
            audit_record_tree(
                suite_root, task_id, record, profile_hash, tool_commit, dirty_diff
            )
        )
        requirement_id = record.get("requirement_id")
        require(requirement_id in expected_requirements, f"{suite} record {task_id} requirement mismatch")
        records[task_id] = record
        counts[record["status"]] += 1

    expected_overall = "fail" if counts["fail"] else "pass" if counts["pass"] == len(task_ids) and summary.get("identity_error") is None else "incomplete"
    require(summary.get("counts") == counts, f"{suite} summary counts mismatch")
    require(summary.get("overall_status") == expected_overall, f"{suite} summary overall status mismatch")

    requirement_statuses: dict[str, str] = {}
    audited_hashes: dict[str, str] = {}
    for requirement_id in expected_requirements:
        aggregate, aggregate_bytes = read_json(
            suite_root / "requirements" / f"{requirement_id}.json",
            f"{suite} requirement {requirement_id}",
        )
        aggregate_hash = sha256_bytes(aggregate_bytes)
        require(aggregate_hash == require_hash(requirement_hashes[requirement_id], f"{suite} requirement hash {requirement_id}"), f"{suite} requirement {requirement_id} hash mismatch")
        require(aggregate.get("schema_version") == "1", f"{suite} requirement {requirement_id} schema mismatch")
        require(aggregate.get("requirement_id") == requirement_id, f"{suite} requirement ID mismatch")
        require(aggregate.get("profile_sha256") == profile_hash, f"{suite} requirement {requirement_id} profile mismatch")
        require(aggregate.get("requirements_sha256") == run.get("requirements_sha256"), f"{suite} requirement {requirement_id} specification mismatch")
        require(aggregate.get("run_manifest_sha256") == run_hash, f"{suite} requirement {requirement_id} run hash mismatch")
        require(aggregate.get("validation_run_id") == run.get("validation_run_id"), f"{suite} requirement {requirement_id} run ID mismatch")
        require(aggregate.get("suite") == suite and aggregate.get("validator") == run.get("validator"), f"{suite} requirement {requirement_id} suite/validator mismatch")
        rows = aggregate.get("records")
        require(isinstance(rows, list) and rows, f"{suite} requirement {requirement_id} has no records")
        observed_tasks: list[str] = []
        statuses: list[str] = []
        for row in rows:
            require(isinstance(row, dict) and set(row) == {"task_id", "record_sha256"}, f"{suite} requirement {requirement_id} record reference is invalid")
            task_id = row.get("task_id")
            require(isinstance(task_id, str) and task_id in records, f"{suite} requirement {requirement_id} names an unknown task")
            require(records[task_id].get("requirement_id") == requirement_id, f"{suite} requirement {requirement_id} names another requirement's task")
            require(row.get("record_sha256") == record_hashes[task_id], f"{suite} requirement {requirement_id} record hash mismatch")
            observed_tasks.append(task_id)
            statuses.append(records[task_id]["status"])
        require(len(observed_tasks) == len(set(observed_tasks)), f"{suite} requirement {requirement_id} duplicates a task")
        expected_status = "fail" if "fail" in statuses else "pass" if all(status == "pass" for status in statuses) and summary.get("identity_error") is None else "incomplete"
        require(aggregate.get("status") == expected_status, f"{suite} requirement {requirement_id} aggregate status mismatch")
        requirement_statuses[requirement_id] = expected_status
        audited_hashes[requirement_id] = aggregate_hash

    require(
        set(task_ids) == {task for requirement in expected_requirements for task in [task_id for task_id, record in records.items() if record.get("requirement_id") == requirement]},
        f"{suite} contains an unowned task",
    )
    return requirement_statuses, audited_hashes, tool_commit, dirty_diff, execution_identities


def recheck_profile(path: Path, payload: bytes, identities: list[tuple[Path, str]]) -> None:
    require(read_regular(path, "TFLite profile", MAX_PROFILE_BYTES) == payload, "profile changed during qualification")
    for identity_path, expected_hash in identities:
        current = read_external_identity(
            identity_path, "profile identity", 1024 * 1024 * 1024
        )
        require(sha256_bytes(current) == expected_hash, f"profile identity changed during qualification: {identity_path}")


def publish(path: Path, value: dict[str, Any]) -> None:
    require(path.is_absolute(), "output path must be absolute")
    directory_metadata(path.parent, "qualification output parent")
    if path.exists() or path.is_symlink():
        raise QualificationError(f"qualification output already exists: {path}")
    payload = canonical(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        raise QualificationError(f"could not create qualification output '{path}': {error}") from error
    try:
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:])
        os.fsync(fd)
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def qualify(profile: Path, evidence_root: Path, output: Path, status: str) -> None:
    profile_hash, profile_payload, identities = audit_profile(profile)
    directory_metadata(evidence_root, "TFLite evidence root")
    try:
        observed_suites = {entry.name for entry in os.scandir(evidence_root)}
    except OSError as error:
        raise QualificationError(f"could not inspect TFLite evidence root: {error}") from error
    missing_suites = set(SUITE_REQUIREMENTS) - observed_suites
    if missing_suites:
        raise QualificationError(f"missing suite evidence: {','.join(sorted(missing_suites))}")
    exact_inventory(evidence_root, set(), set(SUITE_REQUIREMENTS), "TFLite evidence root")

    statuses: dict[str, str] = {}
    hashes: dict[str, str] = {}
    tool_commit: str | None = None
    dirty_suites: list[str] = []
    execution_identities: dict[Path, str] = {}
    for suite in SUITE_REQUIREMENTS:
        suite_statuses, suite_hashes, suite_commit, suite_dirty, suite_identities = audit_suite(
            evidence_root, suite, profile_hash
        )
        if tool_commit is None:
            tool_commit = suite_commit
        require(suite_commit == tool_commit, f"{suite} tool commit mismatch")
        if suite_dirty is not None:
            dirty_suites.append(suite)
        statuses.update(suite_statuses)
        hashes.update(suite_hashes)
        for identity_path, identity_hash in suite_identities:
            previous_hash = execution_identities.setdefault(identity_path, identity_hash)
            require(
                previous_hash == identity_hash,
                f"execution identity has conflicting hashes: {identity_path}",
            )

    require(set(statuses) == set(ALL_REQUIREMENTS), "qualification requirement inventory mismatch")
    passed = [requirement for requirement in ALL_REQUIREMENTS if statuses[requirement] == "pass"]
    pending = [requirement for requirement in ALL_REQUIREMENTS if statuses[requirement] != "pass"]
    if status == "verified":
        require(not pending, f"verified qualification has non-pass requirements: {','.join(pending)}")
        require(not dirty_suites, f"verified qualification has dirty source evidence: {','.join(dirty_suites)}")
    else:
        require(bool(passed), "smoke qualification has no passing requirement evidence")

    recheck_profile(profile, profile_payload, identities)
    for identity_path, expected_hash in execution_identities.items():
        current = read_external_identity(
            identity_path, "execution identity", 1024 * 1024 * 1024
        )
        require(
            sha256_bytes(current) == expected_hash,
            f"execution identity changed during qualification: {identity_path}",
        )
    qualification = {
        "schema_version": "1",
        "profile_sha256": profile_hash,
        "status": status,
        "gate_evidence": [
            {"requirement_id": requirement, "evidence_sha256": hashes[requirement]}
            for requirement in passed
        ],
    }
    publish(output, qualification)
    pending_text = ",".join(pending) if pending else "none"
    assert tool_commit is not None
    print(
        "TFL07_QUALIFICATION_OK=yes "
        f"status={status} passed={len(passed)} pending={pending_text} "
        f"profile_sha256={profile_hash} tool_commit={tool_commit}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--status", required=True, choices=("verified", "smoke_passed"))
    args = parser.parse_args()
    try:
        qualify(
            args.profile.resolve(strict=True),
            args.evidence_root.resolve(strict=True),
            args.output.absolute(),
            args.status,
        )
    except (QualificationError, OSError) as error:
        print(f"[tflite-qualification] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
