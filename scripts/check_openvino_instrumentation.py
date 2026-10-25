#!/usr/bin/env python3
"""Fail-closed OVI-05 target-object instrumentation and source-coverage gate."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Any, NoReturn


EXPECTED_VERSION = "2026.4.1"
EXPECTED_SOURCE_SHA256 = "1ee85264556025486a4745a2d452ea823c578b3d162768bfef590366d2e6c539"
MANIFEST_SCHEMA = "openvino-ir-instrumentation-v1"
COVERAGE_SCHEMA = "openvino-ir-source-coverage-v1"
REQUIRED_OBJECTS = {
    "ir_reader_frontend": "src/frontends/ir/src/frontend.cpp",
    "ir_reader_model_conversion": "src/frontends/ir/src/input_model.cpp",
    "validation_type_inference": "src/core/src/model.cpp",
    "constant_access": "src/core/src/op/constant.cpp",
}
REQUIRED_PATHS = {
    "ir_reader_load": "src/frontends/ir/src/frontend.cpp",
    "ir_reader_convert": "src/frontends/ir/src/input_model.cpp",
    "validation_type_inference": "src/core/src/model.cpp",
    "constant_access": "src/core/src/op/constant.cpp",
}
REQUIRED_RANGES = {
    "ir_reader_load": (160, 263),
    "ir_reader_convert": (258, 280),
    "validation_type_inference": (238, 280),
    "constant_access": (421, 431),
}


class ContractError(RuntimeError):
    """Existing evidence violates the OVI-05 contract."""


class BlockedError(RuntimeError):
    """An external build/tool prerequisite is unavailable."""


def fail(message: str) -> NoReturn:
    raise ContractError(message)


def blocked(message: str) -> NoReturn:
    raise BlockedError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_unique_json(path: Path, *, prerequisite: bool = False) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        if prerequisite:
            blocked(f"required evidence is unavailable: {path}")
        fail(f"evidence is missing or not a regular file: {path}")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def require_regular(path: Path, label: str, *, prerequisite: bool = False) -> None:
    if not path.is_file() or path.is_symlink():
        if prerequisite:
            blocked(f"{label} is unavailable: {path}")
        fail(f"{label} is missing or not a regular file: {path}")


def require_executable(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
        blocked(f"{label} is unavailable: {path}")


def require_under(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} escapes the target root: {resolved}")
    return resolved


def file_identity(record: Any, root: Path, label: str) -> Path:
    if not isinstance(record, dict):
        fail(f"{label} identity is not an object")
    path_value = record.get("path")
    expected_sha = record.get("sha256")
    if not isinstance(path_value, str) or not isinstance(expected_sha, str):
        fail(f"{label} identity is incomplete")
    path = require_under(Path(path_value), root, label)
    require_regular(path, label)
    if sha256_file(path) != expected_sha:
        fail(f"{label} sha256 mismatch")
    return path


def run_tool(command: list[str], label: str) -> str:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(
            f"{label} failed rc={completed.returncode}: {command!r}; "
            f"stderr={completed.stderr[-2000:]!r}"
        )
    return completed.stdout


def symbol_count(nm: Path, path: Path, marker: str, *, undefined_only: bool) -> int:
    command = [str(nm), "-A"]
    if undefined_only:
        command.append("--undefined-only")
    command.append(str(path))
    output = run_tool(command, f"llvm-nm {path.name}")
    return sum(marker in line for line in output.splitlines())


def section_count(objdump: Path, path: Path, marker: str) -> int:
    output = run_tool([str(objdump), "-h", str(path)], f"llvm-objdump {path.name}")
    return sum(marker in line for line in output.splitlines())


def expect_rejected(label: str, callback: Any) -> None:
    try:
        callback()
    except ContractError:
        return
    fail(f"negative control was accepted: {label}")


def validate_guided_claim(claim: dict[str, Any]) -> None:
    normal = claim.get("normal_component_hooks")
    target = claim.get("target_component_hooks")
    objects = claim.get("object_hooks")
    if normal != {"core": 0, "ir_frontend": 0}:
        fail(f"normal build is not a clean negative control: {normal!r}")
    if not isinstance(target, dict) or set(target) != {"core", "ir_frontend"}:
        fail("guided target component hook set is incomplete")
    if any(not isinstance(target[role], int) or target[role] <= 0 for role in target):
        fail(f"guided target component has no sanitizer coverage: {target!r}")
    if not isinstance(objects, dict) or set(objects) != set(REQUIRED_OBJECTS):
        fail("guided compile evidence omits a required IR/Core target object")
    if any(not isinstance(objects[role], int) or objects[role] <= 0 for role in objects):
        fail(f"guided target object has no sanitizer coverage: {objects!r}")
    normal_counters = claim.get("normal_control_counters")
    guided_counters = claim.get("guided_counters")
    if not isinstance(normal_counters, int) or normal_counters <= 0:
        fail("wrapper-only control counter count is absent")
    if not isinstance(guided_counters, int) or guided_counters <= normal_counters:
        fail("guided run does not exceed the wrapper-only counter control")


def validate_coverage_claim(claim: dict[str, Any]) -> None:
    normal = claim.get("normal_component_counters")
    target = claim.get("target_component_counters")
    objects = claim.get("object_counters")
    mappings = claim.get("object_covmap_sections")
    if normal != {"core": 0, "ir_frontend": 0}:
        fail(f"normal build unexpectedly has source-profile counters: {normal!r}")
    if not isinstance(target, dict) or set(target) != {"core", "ir_frontend"}:
        fail("coverage target component counter set is incomplete")
    if any(not isinstance(target[role], int) or target[role] <= 0 for role in target):
        fail(f"coverage target component has no source-profile counters: {target!r}")
    if not isinstance(objects, dict) or set(objects) != set(REQUIRED_OBJECTS):
        fail("coverage compile evidence omits a required IR/Core target object")
    if any(not isinstance(objects[role], int) or objects[role] <= 0 for role in objects):
        fail(f"coverage target object has no source-profile counters: {objects!r}")
    if not isinstance(mappings, dict) or set(mappings) != set(REQUIRED_OBJECTS):
        fail("coverage mapping evidence omits a required IR/Core target object")
    if any(not isinstance(mappings[role], int) or mappings[role] <= 0 for role in mappings):
        fail(f"coverage target object has no coverage mapping: {mappings!r}")


def validate_profile_set(evidence: dict[str, Any], evidence_root: Path) -> None:
    run_id = evidence.get("profile_run_id")
    started = evidence.get("run_started_ns")
    profiles = evidence.get("profile_files")
    if evidence.get("fresh_output_created") is not True:
        fail("coverage runner did not attest a fresh output directory")
    if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        fail("coverage run id is invalid")
    if not isinstance(started, int) or started <= 0:
        fail("coverage run start time is invalid")
    if not isinstance(profiles, list) or not profiles:
        fail("coverage profile set is empty")
    observed: set[str] = set()
    for record in profiles:
        if not isinstance(record, dict):
            fail("coverage profile identity is not an object")
        relative = record.get("path")
        if not isinstance(relative, str):
            fail("coverage profile path is absent")
        relative_path = Path(relative)
        if relative_path.is_absolute() or len(relative_path.parts) != 2 or relative_path.parts[0] != "raw":
            fail(f"coverage profile path is not canonical: {relative}")
        if not relative_path.name.startswith(run_id + "-"):
            fail(f"coverage profile belongs to a reused run: {relative}")
        if relative in observed:
            fail(f"duplicate coverage profile identity: {relative}")
        observed.add(relative)
        path = evidence_root / relative_path
        require_regular(path, "raw coverage profile")
        metadata = path.stat()
        if metadata.st_size <= 0:
            fail(f"raw coverage profile is empty: {relative}")
        if metadata.st_size != record.get("size_bytes"):
            fail(f"raw coverage profile size mismatch: {relative}")
        if metadata.st_mtime_ns != record.get("mtime_ns") or metadata.st_mtime_ns < started:
            fail(f"raw coverage profile is stale or has changed: {relative}")
        if sha256_file(path) != record.get("sha256"):
            fail(f"raw coverage profile hash mismatch: {relative}")


def validate_profile_ownership(evidence: dict[str, Any]) -> None:
    profiles = evidence.get("profile_files")
    ownership = evidence.get("profile_components")
    if not isinstance(profiles, list) or not isinstance(ownership, dict):
        fail("component-specific raw profile ownership is absent")
    expected = {
        record.get("path")
        for record in profiles
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }
    if len(expected) != len(profiles):
        fail("raw profile identities are incomplete")
    if set(ownership) != {"driver", "core", "ir_frontend"}:
        fail("raw profile component set is incomplete")
    flattened: list[str] = []
    for role in ("driver", "core", "ir_frontend"):
        paths = ownership[role]
        if not isinstance(paths, list) or not paths or any(not isinstance(path, str) for path in paths):
            fail(f"raw profile ownership is empty for {role}")
        flattened.extend(paths)
    if len(flattened) != len(set(flattened)):
        fail("one raw profile was reused across multiple components")
    if set(flattened) != expected:
        fail("raw profile ownership does not cover the exact fresh profile set")


def validate_runner_identity(evidence: dict[str, Any], expected_runner: Path) -> None:
    record = evidence.get("runner")
    if not isinstance(record, dict):
        fail("coverage runner identity is absent")
    if Path(str(record.get("path", ""))).resolve() != expected_runner.resolve():
        fail("coverage evidence records the wrong runner")
    if record.get("sha256") != sha256_file(expected_runner):
        fail("coverage runner changed after evidence generation")


def validate_source_path_claim(evidence: dict[str, Any]) -> None:
    expected_sources = sorted(set(REQUIRED_PATHS.values()))
    hits = evidence.get("required_path_hits")
    if hits != {name: True for name in REQUIRED_PATHS}:
        fail(f"required source path hit set is incomplete: {hits!r}")
    details = evidence.get("required_path_evidence")
    if not isinstance(details, dict) or set(details) != set(REQUIRED_PATHS):
        fail("required source path evidence set is incomplete")
    for role, suffix in REQUIRED_PATHS.items():
        row = details[role]
        if not isinstance(row, dict) or row.get("source") != suffix:
            fail(f"required source identity mismatch for {role}")
        line = row.get("line")
        count = row.get("count")
        start, end = REQUIRED_RANGES[role]
        if not isinstance(line, int) or not start <= line <= end:
            fail(f"required source line is outside the measured range for {role}")
        if not isinstance(count, int) or count <= 0:
            fail(f"required source path has no executed counter for {role}")
    for field in ("source_scope", "measured_sources"):
        measured = evidence.get(field)
        if measured != expected_sources:
            fail(f"{field} does not equal the required OpenVINO target-source range")


def validate_source_inputs(evidence: dict[str, Any], fixture_root: Path) -> None:
    inputs = evidence.get("source_inputs")
    if not isinstance(inputs, list) or len(inputs) != 2:
        fail("source coverage did not record the exact FZB1 Constant pair")
    expected_names = ("constant-one.fzb", "constant-two.fzb")
    if tuple(row.get("name") for row in inputs if isinstance(row, dict)) != expected_names:
        fail("source coverage did not use the exact FZB1 Constant pair")
    for record, name in zip(inputs, expected_names, strict=True):
        path = fixture_root / name
        require_regular(path, f"FZB1 source input {name}")
        if record.get("sha256") != sha256_file(path):
            fail(f"FZB1 source input hash mismatch: {name}")
        if record.get("size_bytes") != path.stat().st_size:
            fail(f"FZB1 source input size mismatch: {name}")


def validate_manifest_header(manifest: dict[str, Any], mode: str) -> None:
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        fail(f"{mode} manifest schema mismatch")
    if manifest.get("target") != "openvino-ir" or manifest.get("target_version") != EXPECTED_VERSION:
        fail(f"{mode} manifest target identity mismatch")
    if manifest.get("mode") != mode:
        fail(f"{mode} manifest mode mismatch")
    if manifest.get("source_archive_sha256") != EXPECTED_SOURCE_SHA256:
        fail(f"{mode} manifest source identity mismatch")


def validate_compile_evidence(
    manifest: dict[str, Any], target_root: Path, source_root: Path, flag: str
) -> dict[str, Path]:
    commands_record = manifest.get("compile_commands")
    commands_path = file_identity(commands_record, target_root, "compile commands")
    try:
        rows = json.loads(commands_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid compile commands: {error}")
    if not isinstance(rows, list):
        fail("compile commands root is not an array")
    records = manifest.get("required_objects")
    if not isinstance(records, list):
        fail("required target object records are absent")
    by_role: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("role"), str):
            fail("target object record is invalid")
        role = record["role"]
        if role in by_role:
            fail(f"duplicate target object role: {role}")
        by_role[role] = record
    if set(by_role) != set(REQUIRED_OBJECTS):
        fail("required target object record set is incomplete")

    object_paths: dict[str, Path] = {}
    for role, suffix in REQUIRED_OBJECTS.items():
        source = (source_root / suffix).resolve()
        matching = [row for row in rows if Path(str(row.get("file", ""))).resolve() == source]
        if len(matching) != 1:
            fail(f"compile commands contain {len(matching)} rows for {suffix}")
        row = matching[0]
        command = row.get("command")
        output = row.get("output")
        directory = row.get("directory")
        if not all(isinstance(value, str) for value in (command, output, directory)):
            fail(f"compile command is incomplete for {suffix}")
        if flag not in command.split():
            fail(f"compile command omits {flag} for {suffix}")
        command_words = shlex.split(command)
        if not command_words or Path(command_words[0]).name != "clang++":
            fail(f"compile command lost the clang++ driver for {suffix}")
        output_path = (Path(directory) / output).resolve()
        record = by_role[role]
        if record.get("source") != suffix:
            fail(f"source identity mismatch for {role}")
        object_path = file_identity(record.get("object"), target_root, f"{role} object")
        if object_path != output_path:
            fail(f"compile output and recorded object differ for {role}")
        if record.get("compile_command_sha256") != sha256_text(command):
            fail(f"compile command hash mismatch for {role}")
        object_paths[role] = object_path
    return object_paths


def normal_components(profile: dict[str, Any], target_root: Path) -> dict[str, Path]:
    if profile.get("schema_version") != "openvino-ir-build-profile-v1":
        fail("normal build profile schema mismatch")
    if profile.get("target_version") != EXPECTED_VERSION:
        fail("normal build profile version mismatch")
    components = profile.get("components")
    if not isinstance(components, dict):
        fail("normal build profile has no component identities")
    return {
        role: file_identity(components.get(role), target_root, f"normal {role}")
        for role in ("core", "ir_frontend")
    }


def validate_runtime_record(record: Any, target_root: Path, label: str) -> int:
    if not isinstance(record, dict):
        fail(f"{label} runtime evidence is absent")
    file_identity(record.get("binary"), target_root, f"{label} binary")
    file_identity(record.get("log"), target_root, f"{label} log")
    file_identity(record.get("fixture"), target_root, f"{label} fixture")
    counters = record.get("loaded_inline_counters")
    if not isinstance(counters, int) or counters <= 0:
        fail(f"{label} runtime counter count is invalid")
    return counters


def validate_coverage_evidence(
    evidence: dict[str, Any], evidence_path: Path, coverage: dict[str, Path], manifest_sha: str,
    target_root: Path, expected_runner: Path,
) -> None:
    if evidence.get("schema_version") != COVERAGE_SCHEMA:
        fail("source coverage schema mismatch")
    if evidence.get("target") != "openvino-ir" or evidence.get("target_version") != EXPECTED_VERSION:
        fail("source coverage target identity mismatch")
    if evidence.get("instrumentation") != "llvm-source-cov":
        fail("source coverage instrumentation kind mismatch")
    if evidence.get("coverage_manifest_sha256") != manifest_sha:
        fail("source coverage is not bound to the coverage build manifest")
    validate_runner_identity(evidence, expected_runner)
    components = evidence.get("measured_components")
    if not isinstance(components, dict):
        fail("source coverage measured component identities are absent")
    for role in ("core", "ir_frontend", "driver"):
        record = components.get(role)
        if not isinstance(record, dict):
            fail(f"source coverage omits measured {role}")
        if Path(str(record.get("path", ""))).resolve() != coverage[role]:
            fail(f"source coverage measured the wrong {role}")
        if record.get("sha256") != sha256_file(coverage[role]):
            fail(f"source coverage {role} hash mismatch")

    validate_source_path_claim(evidence)
    for field in ("covered_lines", "total_lines", "covered_functions", "total_functions"):
        if not isinstance(evidence.get(field), int) or evidence[field] <= 0:
            fail(f"source coverage total is empty: {field}")
    if evidence.get("driver_only_evidence_accepted") is not False:
        fail("source coverage permits driver-only evidence")
    validate_source_inputs(evidence, target_root / "instrumentation-fixtures")
    if evidence.get("accepted_models") != 2 or evidence.get("rejected_models") != 0:
        fail("source coverage replay did not accept both FZB1 pair inputs")
    validate_profile_set(evidence, evidence_path.parent)
    validate_profile_ownership(evidence)
    component_profiles = evidence.get("component_profdata")
    exports = evidence.get("coverage_exports")
    if not isinstance(component_profiles, dict) or set(component_profiles) != {"core", "ir_frontend"}:
        fail("component-specific merged profiles are absent")
    if not isinstance(exports, dict) or set(exports) != {"core", "ir_frontend"}:
        fail("component-specific coverage exports are absent")
    for role in ("core", "ir_frontend"):
        for record_name, record in (
            ("profdata", component_profiles[role]),
            ("coverage export", exports[role].get("output") if isinstance(exports[role], dict) else None),
            ("coverage diagnostics", exports[role].get("diagnostics") if isinstance(exports[role], dict) else None),
        ):
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                fail(f"{role} {record_name} identity is absent")
            relative = Path(record["path"])
            if relative.is_absolute() or ".." in relative.parts:
                fail(f"{role} {record_name} path is not canonical")
            path = evidence_path.parent / relative
            require_regular(path, f"{role} {record_name}")
            if sha256_file(path) != record.get("sha256"):
                fail(f"{role} {record_name} hash mismatch")
        diagnostics_path = evidence_path.parent / exports[role]["diagnostics"]["path"]
        if diagnostics_path.stat().st_size != 0 or exports[role]["diagnostics"].get("size_bytes") != 0:
            fail(f"{role} llvm-cov emitted diagnostics")


def selftest() -> int:
    passed = 0
    failed = 0

    good_guided = {
        "normal_component_hooks": {"core": 0, "ir_frontend": 0},
        "target_component_hooks": {"core": 17, "ir_frontend": 5},
        "object_hooks": {role: 1 for role in REQUIRED_OBJECTS},
        "normal_control_counters": 7,
        "guided_counters": 29,
    }

    controls = []
    wrapper_only = copy.deepcopy(good_guided)
    wrapper_only["target_component_hooks"] = {"core": 0, "ir_frontend": 0}
    controls.append(("wrapper-only guided evidence", lambda: validate_guided_claim(wrapper_only)))
    missing_ir = copy.deepcopy(good_guided)
    del missing_ir["object_hooks"]["ir_reader_frontend"]
    controls.append(("missing IR frontend object", lambda: validate_guided_claim(missing_ir)))

    try:
        with tempfile.TemporaryDirectory(prefix="openvino-instrumentation-selftest-") as temporary:
            root = Path(temporary)
            raw = root / "raw"
            raw.mkdir()
            run_id = "0123456789abcdef0123456789abcdef"
            started = 1
            empty = raw / f"{run_id}-empty.profraw"
            empty.write_bytes(b"")
            empty_evidence = {
                "fresh_output_created": True,
                "profile_run_id": run_id,
                "run_started_ns": started,
                "profile_files": [{
                    "path": f"raw/{empty.name}",
                    "size_bytes": 0,
                    "mtime_ns": empty.stat().st_mtime_ns,
                    "sha256": sha256_file(empty),
                }],
            }
            controls.append(("empty raw profile", lambda: validate_profile_set(empty_evidence, root)))

            reused = raw / "prior-run.profraw"
            reused.write_bytes(b"profile")
            reused_evidence = {
                "fresh_output_created": True,
                "profile_run_id": run_id,
                "run_started_ns": started,
                "profile_files": [{
                    "path": f"raw/{reused.name}",
                    "size_bytes": reused.stat().st_size,
                    "mtime_ns": reused.stat().st_mtime_ns,
                    "sha256": sha256_file(reused),
                }],
            }
            controls.append(("reused raw profile", lambda: validate_profile_set(reused_evidence, root)))

            for label, callback in controls:
                try:
                    expect_rejected(label, callback)
                    passed += 1
                except ContractError as error:
                    failed += 1
                    print(f"[openvino-instrumentation-selftest] fail: {error}", file=sys.stderr)

            valid = raw / f"{run_id}-fresh.profraw"
            valid.write_bytes(b"fresh-profile")
            valid_core = raw / f"{run_id}-core.profraw"
            valid_core.write_bytes(b"core-profile")
            valid_ir = raw / f"{run_id}-ir.profraw"
            valid_ir.write_bytes(b"ir-profile")
            valid_paths = (valid, valid_core, valid_ir)
            valid_evidence = {
                "fresh_output_created": True,
                "profile_run_id": run_id,
                "run_started_ns": started,
                "profile_files": [
                    {
                        "path": f"raw/{path.name}",
                        "size_bytes": path.stat().st_size,
                        "mtime_ns": path.stat().st_mtime_ns,
                        "sha256": sha256_file(path),
                    }
                    for path in valid_paths
                ],
                "profile_components": {
                    "driver": [f"raw/{valid.name}"],
                    "core": [f"raw/{valid_core.name}"],
                    "ir_frontend": [f"raw/{valid_ir.name}"],
                },
            }
            overlapping = copy.deepcopy(valid_evidence)
            overlapping["profile_components"]["ir_frontend"] = [f"raw/{valid_core.name}"]
            try:
                expect_rejected(
                    "raw profile reused across target components",
                    lambda: validate_profile_ownership(overlapping),
                )
                passed += 1
            except ContractError as error:
                failed += 1
                print(f"[openvino-instrumentation-selftest] fail: {error}", file=sys.stderr)

            runner = root / "run_coverage_openvino.sh"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            stale_runner = {"runner": {"path": str(runner), "sha256": "0" * 64}}
            path_claim = {
                "source_scope": sorted(set(REQUIRED_PATHS.values())),
                "measured_sources": sorted(set(REQUIRED_PATHS.values())),
                "required_path_hits": {role: True for role in REQUIRED_PATHS},
                "required_path_evidence": {
                    role: {"source": source, "line": REQUIRED_RANGES[role][0], "count": 1}
                    for role, source in REQUIRED_PATHS.items()
                },
            }
            bad_path_claim = copy.deepcopy(path_claim)
            bad_path_claim["required_path_evidence"]["constant_access"]["line"] = \
                REQUIRED_RANGES["constant_access"][1] + 1
            fixture_root = root / "fixtures"
            fixture_root.mkdir()
            for name, payload in (("constant-one.fzb", b"one"), ("constant-two.fzb", b"two")):
                (fixture_root / name).write_bytes(payload)
            input_claim = {
                "source_inputs": [
                    {
                        "name": name,
                        "sha256": sha256_file(fixture_root / name),
                        "size_bytes": (fixture_root / name).stat().st_size,
                    }
                    for name in ("constant-one.fzb", "constant-two.fzb")
                ]
            }
            bad_input_claim = copy.deepcopy(input_claim)
            bad_input_claim["source_inputs"][1]["sha256"] = "0" * 64
            for label, callback in (
                ("stale coverage runner", lambda: validate_runner_identity(stale_runner, runner)),
                ("out-of-range source hit", lambda: validate_source_path_claim(bad_path_claim)),
                ("wrong FZB1 source input", lambda: validate_source_inputs(bad_input_claim, fixture_root)),
            ):
                try:
                    expect_rejected(label, callback)
                    passed += 1
                except ContractError as error:
                    failed += 1
                    print(f"[openvino-instrumentation-selftest] fail: {error}", file=sys.stderr)
            try:
                validate_guided_claim(good_guided)
                validate_profile_set(valid_evidence, root)
                validate_profile_ownership(valid_evidence)
                validate_runner_identity(
                    {"runner": {"path": str(runner), "sha256": sha256_file(runner)}},
                    runner,
                )
                validate_source_path_claim(path_claim)
                validate_source_inputs(input_claim, fixture_root)
                passed += 1
            except ContractError as error:
                failed += 1
                print(f"[openvino-instrumentation-selftest] fail: valid evidence rejected: {error}", file=sys.stderr)
    except OSError as error:
        failed += 1
        print(f"[openvino-instrumentation-selftest] fail: {error}", file=sys.stderr)

    print(f"[openvino-instrumentation-selftest] pass={passed} fail={failed}")
    return 0 if failed == 0 else 1


def check_actual(target_root: Path, coverage_evidence: Path) -> int:
    target_root = target_root.resolve()
    profile_path = target_root / "build-profile.json"
    guided_path = target_root / "guided-instrumentation.json"
    coverage_path = target_root / "coverage-instrumentation.json"
    profile = load_unique_json(profile_path, prerequisite=True)
    guided_manifest = load_unique_json(guided_path, prerequisite=True)
    coverage_manifest = load_unique_json(coverage_path, prerequisite=True)
    evidence = load_unique_json(coverage_evidence, prerequisite=True)

    toolchain = profile.get("toolchain")
    if not isinstance(toolchain, dict):
        fail("normal build profile has no toolchain")
    compiler_record = toolchain.get("compiler")
    if not isinstance(compiler_record, dict) or not isinstance(compiler_record.get("path"), str):
        fail("normal build profile has no compiler path")
    tool_bin = Path(compiler_record["path"]).resolve().parent
    nm = tool_bin / "llvm-nm"
    objdump = tool_bin / "llvm-objdump"
    require_executable(nm, "pinned llvm-nm")
    require_executable(objdump, "pinned llvm-objdump")

    normal = normal_components(profile, target_root)
    normal_hooks = {role: symbol_count(nm, path, "__sanitizer_cov_", undefined_only=True) for role, path in normal.items()}
    normal_counters = {role: symbol_count(nm, path, "__profc_", undefined_only=False) for role, path in normal.items()}

    manifests = {"guided": guided_manifest, "coverage": coverage_manifest}
    components: dict[str, dict[str, Path]] = {}
    objects: dict[str, dict[str, Path]] = {}
    for mode, manifest in manifests.items():
        validate_manifest_header(manifest, mode)
        compiler = manifest.get("compiler")
        if not isinstance(compiler, dict) or Path(str(compiler.get("invocation_path", ""))).name != "clang++":
            fail(f"{mode} manifest did not preserve the clang++ driver invocation")
        normal_profile = manifest.get("normal_build_profile")
        if not isinstance(normal_profile, dict) or normal_profile.get("sha256") != sha256_file(profile_path):
            fail(f"{mode} manifest is not bound to the normal build profile")
        if Path(str(normal_profile.get("path", ""))).resolve() != profile_path.resolve():
            fail(f"{mode} manifest records the wrong normal build profile")
        component_records = manifest.get("components")
        if not isinstance(component_records, dict):
            fail(f"{mode} component identities are absent")
        components[mode] = {
            role: file_identity(component_records.get(role), target_root, f"{mode} {role}")
            for role in ("core", "ir_frontend", "driver")
        }
        for role in ("core", "ir_frontend"):
            if sha256_file(components[mode][role]) == sha256_file(normal[role]):
                fail(f"{mode} {role} reuses the normal uninstrumented component")
        flag = "-fsanitize=fuzzer-no-link" if mode == "guided" else "-fcoverage-mapping"
        objects[mode] = validate_compile_evidence(
            manifest,
            target_root,
            target_root / "build/source",
            flag,
        )

    guided_component_hooks = {
        role: symbol_count(nm, components["guided"][role], "__sanitizer_cov_", undefined_only=True)
        for role in ("core", "ir_frontend")
    }
    guided_object_hooks = {
        role: symbol_count(nm, path, "__sanitizer_cov_", undefined_only=True)
        for role, path in objects["guided"].items()
    }
    guided_counts = guided_manifest.get("instrumentation")
    if not isinstance(guided_counts, dict):
        fail("guided instrumentation counts are absent")
    if guided_counts.get("component_symbol_counts") != guided_component_hooks:
        fail("guided component hook counts changed")
    if guided_counts.get("object_symbol_counts") != guided_object_hooks:
        fail("guided object hook counts changed")
    runtime = guided_manifest.get("runtime")
    if not isinstance(runtime, dict):
        fail("guided runtime evidence is absent")
    normal_runtime_counters = validate_runtime_record(runtime.get("normal_control"), target_root, "normal control")
    guided_runtime_counters = validate_runtime_record(runtime.get("guided"), target_root, "guided")
    guided_claim = {
        "normal_component_hooks": normal_hooks,
        "target_component_hooks": guided_component_hooks,
        "object_hooks": guided_object_hooks,
        "normal_control_counters": normal_runtime_counters,
        "guided_counters": guided_runtime_counters,
    }
    validate_guided_claim(guided_claim)

    coverage_component_counters = {
        role: symbol_count(nm, components["coverage"][role], "__profc_", undefined_only=False)
        for role in ("core", "ir_frontend")
    }
    coverage_object_counters = {
        role: symbol_count(nm, path, "__profc_", undefined_only=False)
        for role, path in objects["coverage"].items()
    }
    coverage_object_mappings = {
        role: section_count(objdump, path, "__llvm_covmap")
        for role, path in objects["coverage"].items()
    }
    coverage_counts = coverage_manifest.get("instrumentation")
    if not isinstance(coverage_counts, dict):
        fail("coverage instrumentation counts are absent")
    if coverage_counts.get("component_symbol_counts") != coverage_component_counters:
        fail("coverage component counter counts changed")
    if coverage_counts.get("object_symbol_counts") != coverage_object_counters:
        fail("coverage object counter counts changed")
    if coverage_counts.get("object_covmap_sections") != coverage_object_mappings:
        fail("coverage object mapping counts changed")
    validate_coverage_claim({
        "normal_component_counters": normal_counters,
        "target_component_counters": coverage_component_counters,
        "object_counters": coverage_object_counters,
        "object_covmap_sections": coverage_object_mappings,
    })

    validate_coverage_evidence(
        evidence,
        coverage_evidence,
        components["coverage"],
        sha256_file(coverage_path),
        target_root,
        Path(__file__).resolve().with_name("run_coverage_openvino.sh"),
    )
    wrapper_only = copy.deepcopy(guided_claim)
    wrapper_only["target_component_hooks"] = dict(normal_hooks)
    expect_rejected(
        "actual wrapper-only component set",
        lambda: validate_guided_claim(wrapper_only),
    )
    missing_ir_object = copy.deepcopy(guided_claim)
    del missing_ir_object["object_hooks"]["ir_reader_frontend"]
    expect_rejected(
        "actual guided evidence missing the IR frontend object",
        lambda: validate_guided_claim(missing_ir_object),
    )
    empty_profiles = copy.deepcopy(evidence)
    empty_profiles["profile_files"] = []
    expect_rejected(
        "actual evidence with an empty profile set",
        lambda: validate_profile_set(empty_profiles, coverage_evidence.parent),
    )
    reused_profiles = copy.deepcopy(evidence)
    reused_profiles["profile_components"]["ir_frontend"] = list(
        reused_profiles["profile_components"]["core"]
    )
    expect_rejected(
        "actual evidence reusing the Core profile as IR frontend evidence",
        lambda: validate_profile_ownership(reused_profiles),
    )
    print(
        "[openvino-instrumentation] "
        f"guided_hooks=core:{guided_component_hooks['core']},ir:{guided_component_hooks['ir_frontend']} "
        f"coverage_counters=core:{coverage_component_counters['core']},ir:{coverage_component_counters['ir_frontend']}"
    )
    print(
        "[openvino-instrumentation] "
        f"source_lines={evidence['covered_lines']}/{evidence['total_lines']} "
        f"source_functions={evidence['covered_functions']}/{evidence['total_functions']}"
    )
    print("[openvino-instrumentation] negative_controls=4/0")
    print("[openvino-instrumentation] pass=1 fail=0 blocked=0")
    return 0


def parse_args() -> argparse.Namespace:
    project = Path(__file__).resolve().parent.parent
    default_target = project / "data/targets/openvino-ir/2026.4.1"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--target-root", type=Path, default=default_target)
    parser.add_argument("--coverage-evidence", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.selftest:
        return selftest()
    target = args.target_root.resolve()
    evidence = args.coverage_evidence
    if evidence is None:
        evidence = target / "instrumentation-evidence/coverage/coverage.json"
    try:
        return check_actual(target, evidence.resolve())
    except BlockedError as error:
        print(f"[openvino-instrumentation] blocked: {error}", file=sys.stderr)
        print("[openvino-instrumentation] pass=0 fail=0 blocked=1")
        return 2
    except (ContractError, OSError, UnicodeError, ValueError) as error:
        print(f"[openvino-instrumentation] fail: {error}", file=sys.stderr)
        print("[openvino-instrumentation] pass=0 fail=1 blocked=0")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
