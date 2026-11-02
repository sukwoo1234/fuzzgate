#!/usr/bin/env python3
"""Fail-closed HDF-05 target-object instrumentation and source-coverage gate."""

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
from typing import Any, NoReturn


EXPECTED_ARCHIVE_SHA = "1a1ab8209b35586fbc1aa279ba76d102130b95badcb20ca329587219112d8c16"
MANIFEST_SCHEMA = "hdf5-weights-instrumentation-v1"
COVERAGE_SCHEMA = "hdf5-weights-source-coverage-v1"
REQUIRED_OBJECTS = {
    "reader_io": "src/H5Fio.c",
    "dataset_read": "src/H5Dio.c",
    "chunk_decode": "src/H5Dchunk.c",
    "filter_pipeline": "src/H5Z.c",
    "shuffle_filter": "src/H5Zshuffle.c",
    "fletcher32_filter": "src/H5Zfletcher32.c",
}
REQUIRED_SOURCE_SHA256 = {
    "reader_io": "d58491a293695f84cfedebb3f414d6ad0c5cfd15a15e0a08f8800d040d272ba5",
    "dataset_read": "34cc21c84e88b0c6e066a78548c7a686e9ccce5d77869023fae5825d804a5b04",
    "chunk_decode": "6895faf7913775040d51e69e46cdfda0fe209cfac2d612bad356476a9cff34f1",
    "filter_pipeline": "e4958b2a98a62c5942f9b97bd3f26250b7306e7c5c802529b613372030202a65",
    "shuffle_filter": "900d1c2588adbe1e53dfe2499462f534c168495ef656c2f6736dd0266fec4471",
    "fletcher32_filter": "a1a7e28c3c601db8615b95de8f5c0b82e6e00b187982928511f8a53413eb45a6",
}
REQUIRED_PATHS = {
    "reader_block_read": ("src/H5Fio.c", 77, 102),
    "dataset_read": ("src/H5Dio.c", 77, 491),
    "chunk_unfilter": ("src/H5Dchunk.c", 4825, 4885),
    "filter_pipeline": ("src/H5Z.c", 1372, 1515),
    "shuffle_decode": ("src/H5Zshuffle.c", 108, 214),
    "fletcher32_decode": ("src/H5Zfletcher32.c", 49, 108),
}


class ContractError(RuntimeError):
    """Existing evidence violates the HDF-05 contract."""


class BlockedError(RuntimeError):
    """A required build or tool prerequisite is unavailable."""


def fail(message: str) -> NoReturn:
    raise ContractError(message)


def blocked(message: str) -> NoReturn:
    raise BlockedError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, *, prerequisite: bool = False) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        if prerequisite:
            blocked(f"required evidence unavailable: {path}")
        fail(f"evidence is missing or unsafe: {path}")

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


def require_under(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} escapes its owning root: {resolved}")
    return resolved


def identity(record: Any, root: Path, label: str, *, relative: bool = False) -> Path:
    if not isinstance(record, dict):
        fail(f"{label} identity is not an object")
    raw = record.get("path")
    expected = record.get("sha256")
    if not isinstance(raw, str) or not isinstance(expected, str):
        fail(f"{label} identity is incomplete")
    candidate = root / raw if relative else Path(raw)
    path = require_under(candidate, root, label)
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is missing or unsafe: {path}")
    if sha256(path) != expected:
        fail(f"{label} sha256 mismatch")
    size = record.get("size_bytes")
    if size is not None and size != path.stat().st_size:
        fail(f"{label} size mismatch")
    return path


def external_identity(record: Any, label: str) -> Path:
    if not isinstance(record, dict):
        fail(f"{label} identity is not an object")
    raw = record.get("path")
    expected = record.get("sha256")
    if not isinstance(raw, str) or not isinstance(expected, str):
        fail(f"{label} identity is incomplete")
    path = Path(raw).resolve()
    if not path.is_file() or path.is_symlink() or sha256(path) != expected:
        fail(f"{label} identity mismatch")
    return path


def run(command: list[str], label: str) -> str:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"{label} failed rc={completed.returncode}: {completed.stderr[-1000:]!r}")
    return completed.stdout


def symbol_count(tool: Path, path: Path, marker: str, *, undefined: bool) -> int:
    command = [str(tool), "-A"]
    if undefined:
        command.append("--undefined-only")
    command.append(str(path))
    return sum(marker in line for line in run(command, f"llvm-nm {path.name}").splitlines())


def section_count(tool: Path, path: Path, marker: str) -> int:
    return sum(marker in line for line in run([str(tool), "-h", str(path)], f"llvm-objdump {path.name}").splitlines())


def validate_guided_claim(claim: dict[str, Any]) -> None:
    required = set(REQUIRED_OBJECTS)
    if claim.get("normal_component_hooks") != {"core": 0, "high_level": 0}:
        fail("normal HDF5 is not a clean wrapper-only negative control")
    target = claim.get("target_component_hooks")
    if not isinstance(target, dict) or set(target) != {"core", "high_level"} or any(
        not isinstance(value, int) or value <= 0 for value in target.values()
    ):
        fail("guided HDF5 components have no target instrumentation")
    objects = claim.get("object_hooks")
    if not isinstance(objects, dict) or set(objects) != required or any(
        not isinstance(value, int) or value <= 0 for value in objects.values()
    ):
        fail("guided evidence omits an instrumented reader/dataset/filter object")
    normal = claim.get("normal_control_counters")
    guided = claim.get("guided_counters")
    if not isinstance(normal, int) or normal <= 0:
        fail("wrapper-only runtime control is absent")
    if not isinstance(guided, int) or guided <= normal:
        fail("guided runtime does not exceed the wrapper-only control")


def validate_coverage_claim(claim: dict[str, Any]) -> None:
    required = set(REQUIRED_OBJECTS)
    if claim.get("normal_component_counters") != {"core": 0, "high_level": 0}:
        fail("normal HDF5 unexpectedly has source-profile counters")
    target = claim.get("target_component_counters")
    if not isinstance(target, dict) or set(target) != {"core", "high_level"} or any(
        not isinstance(value, int) or value <= 0 for value in target.values()
    ):
        fail("coverage HDF5 components have no source-profile counters")
    for field in ("object_counters", "object_covmap_sections"):
        values = claim.get(field)
        if not isinstance(values, dict) or set(values) != required or any(
            not isinstance(value, int) or value <= 0 for value in values.values()
        ):
            fail(f"coverage evidence has incomplete {field}")


def validate_source_claim(claim: dict[str, Any]) -> None:
    if set(claim) != set(REQUIRED_SOURCE_SHA256):
        fail("official HDF5 source identity set is incomplete")
    for role, expected in REQUIRED_SOURCE_SHA256.items():
        if claim.get(role) != expected:
            fail(f"official HDF5 source sha256 mismatch for {role}")


def validate_path_claim(claim: dict[str, Any]) -> None:
    if claim.get("driver_only_evidence_accepted") is not False:
        fail("driver-only coverage was accepted")
    hits = claim.get("required_path_hits")
    evidence = claim.get("required_path_evidence")
    if not isinstance(hits, dict) or set(hits) != set(REQUIRED_PATHS) or not all(hits.values()):
        fail("coverage omits a required reader/dataset/filter hit")
    if not isinstance(evidence, dict) or set(evidence) != set(REQUIRED_PATHS):
        fail("coverage path evidence is incomplete")
    for label, (source, start, end) in REQUIRED_PATHS.items():
        row = evidence[label]
        if not isinstance(row, dict) or row.get("source") != source:
            fail(f"coverage source mismatch for {label}")
        line = row.get("line")
        count = row.get("count")
        if not isinstance(line, int) or not start <= line <= end or not isinstance(count, int) or count <= 0:
            fail(f"coverage line/count is invalid for {label}")


def validate_profile_claim(claim: dict[str, Any]) -> None:
    if claim.get("fresh_output_created") is not True:
        fail("coverage output was not fresh")
    run_id = claim.get("profile_run_id")
    started = claim.get("run_started_ns")
    profiles = claim.get("profile_files")
    if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        fail("coverage run id is invalid")
    if not isinstance(started, int) or started <= 0 or not isinstance(profiles, list) or not profiles:
        fail("coverage raw profile set is absent")
    if any(not isinstance(row, dict) or int(row.get("size_bytes", 0)) <= 0 for row in profiles):
        fail("coverage raw profile set contains an empty profile")


def expect_rejected(label: str, callback: Any) -> None:
    try:
        callback()
    except ContractError:
        return
    fail(f"negative control was accepted: {label}")


def selftest() -> None:
    guided = {
        "normal_component_hooks": {"core": 0, "high_level": 0},
        "target_component_hooks": {"core": 3, "high_level": 2},
        "object_hooks": {role: 1 for role in REQUIRED_OBJECTS},
        "normal_control_counters": 10,
        "guided_counters": 100,
    }
    coverage = {
        "normal_component_counters": {"core": 0, "high_level": 0},
        "target_component_counters": {"core": 3, "high_level": 2},
        "object_counters": {role: 1 for role in REQUIRED_OBJECTS},
        "object_covmap_sections": {role: 1 for role in REQUIRED_OBJECTS},
    }
    paths = {
        "driver_only_evidence_accepted": False,
        "required_path_hits": {label: True for label in REQUIRED_PATHS},
        "required_path_evidence": {
            label: {"source": source, "line": start, "count": 1}
            for label, (source, start, _end) in REQUIRED_PATHS.items()
        },
    }
    profiles = {
        "fresh_output_created": True,
        "profile_run_id": "a" * 32,
        "run_started_ns": 1,
        "profile_files": [{"path": "raw/a.profraw", "size_bytes": 1}],
    }
    cases: list[tuple[str, Any]] = []
    altered = copy.deepcopy(guided)
    altered["target_component_hooks"]["core"] = 0
    cases.append(("wrapper-only guided", lambda value=altered: validate_guided_claim(value)))
    altered = copy.deepcopy(guided)
    del altered["object_hooks"]["fletcher32_filter"]
    cases.append(("missing filter object", lambda value=altered: validate_guided_claim(value)))
    altered = copy.deepcopy(guided)
    altered["guided_counters"] = altered["normal_control_counters"]
    cases.append(("no runtime target delta", lambda value=altered: validate_guided_claim(value)))
    altered = copy.deepcopy(coverage)
    del altered["object_counters"]["reader_io"]
    cases.append(("missing reader object", lambda value=altered: validate_coverage_claim(value)))
    altered = copy.deepcopy(coverage)
    altered["object_covmap_sections"]["shuffle_filter"] = 0
    cases.append(("missing filter covmap", lambda value=altered: validate_coverage_claim(value)))
    altered = copy.deepcopy(paths)
    altered["driver_only_evidence_accepted"] = True
    cases.append(("driver-only coverage", lambda value=altered: validate_path_claim(value)))
    altered = copy.deepcopy(paths)
    altered["required_path_hits"]["chunk_unfilter"] = False
    cases.append(("missing target hit", lambda value=altered: validate_path_claim(value)))
    altered = copy.deepcopy(profiles)
    altered["profile_files"][0]["size_bytes"] = 0
    cases.append(("empty raw profile", lambda value=altered: validate_profile_claim(value)))
    sources = dict(REQUIRED_SOURCE_SHA256)
    sources["filter_pipeline"] = "0" * 64
    cases.append(("modified HDF5 source", lambda value=sources: validate_source_claim(value)))
    for label, callback in cases:
        expect_rejected(label, callback)
    print(f"[hdf5-instrumentation-selftest] pass={len(cases)} fail=0")


def validate_manifest(path: Path, target: Path, mode: str) -> tuple[dict[str, Any], dict[str, Path]]:
    document = load_json(path, prerequisite=True)
    if document.get("schema_version") != MANIFEST_SCHEMA or document.get("mode") != mode:
        fail(f"{mode} manifest schema/mode mismatch")
    if document.get("target") != "hdf5-weights" or document.get("target_version") != "2.2.0":
        fail(f"{mode} manifest target mismatch")
    if document.get("source_archive_sha256") != EXPECTED_ARCHIVE_SHA:
        fail(f"{mode} source archive mismatch")
    archive = target / "source/2.2.0.tar.gz"
    if not archive.is_file() or archive.is_symlink() or sha256(archive) != EXPECTED_ARCHIVE_SHA:
        blocked("pinned HDF5 source archive is unavailable")
    profile_path = identity(document.get("normal_build_profile"), target, f"{mode} normal profile")
    commands_path = identity(document.get("compile_commands"), target, f"{mode} compile commands")
    fixture = identity(document.get("fixture"), target, f"{mode} filtered fixture")
    if fixture.name != "shuffle-fletcher32.h5":
        fail(f"{mode} fixture name mismatch")
    external_identity(document.get("compiler"), f"{mode} compiler")
    flags = document.get("compile_flags")
    expected_flags = (
        {"-O1", "-g", "-DNDEBUG", "-fsanitize=fuzzer-no-link"}
        if mode == "guided"
        else {"-O1", "-g", "-DNDEBUG", "-fprofile-instr-generate", "-fcoverage-mapping"}
    )
    if not isinstance(flags, list) or set(flags) != expected_flags:
        fail(f"{mode} compile flags mismatch")

    components = document.get("components")
    if not isinstance(components, dict) or set(components) != {"core", "high_level", "driver"}:
        fail(f"{mode} component set mismatch")
    component_paths = {
        role: identity(record, target, f"{mode} {role}") for role, record in components.items()
    }
    normal = document.get("normal_components")
    if not isinstance(normal, dict) or set(normal) != {"core", "high_level"}:
        fail(f"{mode} normal component set mismatch")
    normal_paths = {
        role: identity(record, target, f"{mode} normal {role}") for role, record in normal.items()
    }
    profile = load_json(profile_path)
    profile_components = profile.get("components")
    if not isinstance(profile_components, dict):
        fail(f"{mode} normal profile has no component inventory")
    for role, path_value in normal_paths.items():
        if role not in profile_components or identity(
            profile_components[role], target, f"{mode} profile {role}"
        ) != path_value:
            fail(f"{mode} normal control is not bound to the HDF-01 {role} component")

    objects = document.get("required_objects")
    if not isinstance(objects, list) or len(objects) != len(REQUIRED_OBJECTS):
        fail(f"{mode} required object inventory is incomplete")
    object_paths: dict[str, Path] = {}
    source_claim: dict[str, Any] = {}
    for row in objects:
        if not isinstance(row, dict):
            fail(f"{mode} object record is invalid")
        role = row.get("role")
        if role not in REQUIRED_OBJECTS or row.get("source") != REQUIRED_OBJECTS[role] or role in object_paths:
            fail(f"{mode} object role/source mismatch")
        source_path = target / "build/source" / REQUIRED_OBJECTS[role]
        source_claim[role] = row.get("source_sha256")
        if (
            row.get("source_sha256") != REQUIRED_SOURCE_SHA256[role]
            or not source_path.is_file()
            or source_path.is_symlink()
            or sha256(source_path) != REQUIRED_SOURCE_SHA256[role]
        ):
            fail(f"{mode} official source identity mismatch for {role}")
        object_paths[role] = identity(row.get("object"), target, f"{mode} object {role}")
        command_sha = row.get("compile_command_sha256")
        if not isinstance(command_sha, str) or re.fullmatch(r"[0-9a-f]{64}", command_sha) is None:
            fail(f"{mode} compile command identity missing for {role}")
    if set(object_paths) != set(REQUIRED_OBJECTS):
        fail(f"{mode} object role set mismatch")
    validate_source_claim(source_claim)

    try:
        compile_rows = json.loads(commands_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{mode} compile commands are invalid: {error}")
    if not isinstance(compile_rows, list):
        fail(f"{mode} compile commands root is not a list")
    source_root = (target / "build/source").resolve()
    for role, suffix in REQUIRED_OBJECTS.items():
        source = (source_root / suffix).resolve()
        matches = [
            row
            for row in compile_rows
            if isinstance(row, dict)
            and isinstance(row.get("file"), str)
            and Path(row["file"]).resolve() == source
        ]
        if len(matches) != 1:
            fail(f"{mode} compile evidence has {len(matches)} records for {suffix}")
        row = matches[0]
        directory = row.get("directory")
        output = row.get("output")
        command = row.get("command")
        if not all(isinstance(value, str) for value in (directory, output, command)):
            fail(f"{mode} compile record is incomplete for {role}")
        compiled_object = (Path(directory) / output).resolve()
        if compiled_object != object_paths[role]:
            fail(f"{mode} compile output differs from the bound object for {role}")
        record = next(item for item in objects if item["role"] == role)
        command_sha = hashlib.sha256(command.encode("utf-8")).hexdigest()
        if record.get("compile_command_sha256") != command_sha:
            fail(f"{mode} compile command sha256 mismatch for {role}")
        command_tokens = set(shlex.split(command))
        if not expected_flags.issubset(command_tokens):
            fail(f"{mode} compile command omits required flags for {role}")

    compiler = Path(str(document["compiler"]["path"])).resolve()
    tool_dir = compiler.parent
    nm = tool_dir / "llvm-nm"
    objdump = tool_dir / "llvm-objdump"
    if not nm.is_file() or not os.access(nm, os.X_OK) or not objdump.is_file() or not os.access(objdump, os.X_OK):
        blocked("LLVM object inspection tools are unavailable")
    instrumentation = document.get("instrumentation")
    if not isinstance(instrumentation, dict):
        fail(f"{mode} instrumentation claim is absent")
    if mode == "guided":
        runtime = document.get("runtime")
        if not isinstance(runtime, dict) or set(runtime) != {"normal_control", "guided"}:
            fail("guided runtime claim is incomplete")
        normal_runtime = runtime["normal_control"]
        guided_runtime = runtime["guided"]
        identity(normal_runtime.get("binary"), target, "normal-control driver")
        identity(normal_runtime.get("log"), target, "normal-control log")
        identity(guided_runtime.get("binary"), target, "guided driver")
        identity(guided_runtime.get("log"), target, "guided log")
        claim = dict(instrumentation)
        claim["normal_control_counters"] = normal_runtime.get("loaded_inline_counters")
        claim["guided_counters"] = guided_runtime.get("loaded_inline_counters")
        validate_guided_claim(claim)
        actual_normal = {role: symbol_count(nm, path, "__sanitizer_cov_", undefined=True) for role, path in normal_paths.items()}
        actual_target = {role: symbol_count(nm, component_paths[role], "__sanitizer_cov_", undefined=True) for role in ("core", "high_level")}
        actual_objects = {role: symbol_count(nm, path, "__sanitizer_cov_", undefined=True) for role, path in object_paths.items()}
        if instrumentation.get("normal_component_hooks") != actual_normal or instrumentation.get("target_component_hooks") != actual_target or instrumentation.get("object_hooks") != actual_objects:
            fail("guided symbol counts do not match current artifacts")
    else:
        validate_coverage_claim(instrumentation)
        actual_normal = {role: symbol_count(nm, path, "__profc_", undefined=False) for role, path in normal_paths.items()}
        actual_target = {role: symbol_count(nm, component_paths[role], "__profc_", undefined=False) for role in ("core", "high_level")}
        actual_objects = {role: symbol_count(nm, path, "__profc_", undefined=False) for role, path in object_paths.items()}
        actual_maps = {role: section_count(objdump, path, "__llvm_covmap") for role, path in object_paths.items()}
        if instrumentation.get("normal_component_counters") != actual_normal or instrumentation.get("target_component_counters") != actual_target or instrumentation.get("object_counters") != actual_objects or instrumentation.get("object_covmap_sections") != actual_maps:
            fail("coverage symbol/section counts do not match current artifacts")
    return document, component_paths


def validate_coverage_evidence(
    path: Path,
    target: Path,
    coverage_manifest_path: Path,
    coverage_manifest: dict[str, Any],
    components: dict[str, Path],
) -> dict[str, Any]:
    evidence = load_json(path, prerequisite=True)
    root = path.parent.resolve()
    if evidence.get("schema_version") != COVERAGE_SCHEMA:
        fail("coverage evidence schema mismatch")
    if evidence.get("target") != "hdf5-weights" or evidence.get("target_version") != "2.2.0":
        fail("coverage evidence target mismatch")
    if evidence.get("coverage_manifest_sha256") != sha256(coverage_manifest_path):
        fail("coverage manifest binding mismatch")
    validate_profile_claim(evidence)
    validate_path_claim(evidence)

    runner = external_identity(evidence.get("runner"), "coverage runner")
    expected_runner = Path(__file__).resolve().with_name("run_coverage_hdf5.sh")
    if runner != expected_runner:
        fail("coverage runner identity mismatch")
    profiles = evidence["profile_files"]
    observed_profiles: set[str] = set()
    profile_paths: dict[str, Path] = {}
    started = evidence["run_started_ns"]
    for index, record in enumerate(profiles):
        profile = identity(record, root, f"raw profile {index}", relative=True)
        relative = profile.relative_to(root).as_posix()
        if not relative.startswith("raw/") or relative in observed_profiles:
            fail("raw profile path is invalid or duplicated")
        observed_profiles.add(relative)
        profile_paths[relative] = profile
        mtime = record.get("mtime_ns")
        if not isinstance(mtime, int) or mtime < started:
            fail("raw profile predates the coverage run")
    mapping = evidence.get("profile_components")
    if not isinstance(mapping, dict) or set(mapping) != {"driver", "core", "high_level"}:
        fail("profile component ownership is incomplete")
    owned = [item for items in mapping.values() if isinstance(items, list) for item in items]
    if len(owned) != len(observed_profiles) or set(owned) != observed_profiles or any(not mapping[role] for role in mapping):
        fail("raw profiles are not owned exactly once by all components")

    compiler = external_identity(coverage_manifest.get("compiler"), "coverage compiler")
    llvm_profdata = compiler.parent / "llvm-profdata"
    llvm_cov = compiler.parent / "llvm-cov"
    for tool in (llvm_profdata, llvm_cov):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            blocked(f"LLVM coverage tool is unavailable: {tool}")
    markers = {
        "driver": ("_ZN4tool11hdf5_loader9LoadImage",),
        "high_level": ("H5LTopen_file_image",),
        "core": ("H5D__read", "H5F_shared_block_read", "H5Z_pipeline"),
    }
    actual_mapping = {role: [] for role in markers}
    for relative, profile in profile_paths.items():
        shown = run(
            [str(llvm_profdata), "show", "--all-functions", str(profile)],
            f"classify raw profile {relative}",
        )
        matches = [
            role for role, required in markers.items() if all(marker in shown for marker in required)
        ]
        if len(matches) != 1:
            fail(f"raw profile ownership is ambiguous for {relative}: {matches!r}")
        actual_mapping[matches[0]].append(relative)
    for paths in actual_mapping.values():
        paths.sort()
    normalized_mapping = {
        role: sorted(paths) if isinstance(paths, list) else paths for role, paths in mapping.items()
    }
    if actual_mapping != normalized_mapping:
        fail("raw profile component ownership does not match llvm-profdata")

    measured = evidence.get("measured_components")
    if not isinstance(measured, dict) or set(measured) != set(components):
        fail("measured component set mismatch")
    for role, component in components.items():
        if identity(measured[role], target, f"measured {role}") != component:
            fail(f"measured {role} differs from the coverage manifest")
    expected_scope = sorted(set(REQUIRED_OBJECTS.values()))
    if evidence.get("source_scope") != expected_scope or evidence.get("measured_sources") != expected_scope:
        fail("coverage source scope is not the exact HDF5 reader/dataset/filter set")
    fixture = identity(coverage_manifest.get("fixture"), target, "coverage fixture")
    inputs = evidence.get("source_inputs")
    if not isinstance(inputs, list) or len(inputs) != 1:
        fail("coverage source input inventory mismatch")
    source_input = inputs[0]
    if source_input.get("name") != fixture.name or source_input.get("sha256") != sha256(fixture) or source_input.get("size_bytes") != fixture.stat().st_size:
        fail("coverage source input identity mismatch")
    if evidence.get("accepted_inputs") != 1 or evidence.get("rejected_inputs") != 0:
        fail("coverage replay result counts mismatch")
    for field in ("covered_lines", "total_lines", "covered_functions", "total_functions"):
        if not isinstance(evidence.get(field), int) or evidence[field] <= 0:
            fail(f"coverage total is empty: {field}")
    profdata = evidence.get("component_profdata")
    if not isinstance(profdata, dict) or set(profdata) != {"core", "high_level"}:
        fail("component profdata inventory mismatch")
    profdata_paths = {
        role: identity(record, root, f"{role} profdata", relative=True)
        for role, record in profdata.items()
    }
    export = evidence.get("coverage_export")
    if not isinstance(export, dict) or set(export) != {"output", "diagnostics"}:
        fail("coverage export inventory mismatch")
    output = identity(export["output"], root, "coverage export", relative=True)
    diagnostics = identity(export["diagnostics"], root, "coverage diagnostics", relative=True)
    if output.stat().st_size <= 0 or diagnostics.stat().st_size != 0:
        fail("coverage export is empty or has mismatch diagnostics")

    source_root = (target / "build/source").resolve()
    evidence_rows = evidence["required_path_evidence"]
    for label, (source, _start, _end) in REQUIRED_PATHS.items():
        row = evidence_rows[label]
        shown = run(
            [
                str(llvm_cov),
                "show",
                str(components["core"]),
                f"-instr-profile={profdata_paths['core']}",
                str(source_root / source),
            ],
            f"llvm-cov show {source}",
        )
        counts: dict[int, str] = {}
        for line_text in shown.splitlines():
            match = re.match(r"^\s*(\d+)\|\s*([^|]*)\|", line_text)
            if match is not None:
                counts[int(match.group(1))] = match.group(2).strip().replace(",", "")
        observed_count = counts.get(row["line"], "")
        if not observed_count.isdigit() or int(observed_count) != row["count"]:
            fail(f"live source coverage differs from recorded evidence for {label}")

    scope_paths = [str(source_root / source) for source in sorted(set(REQUIRED_OBJECTS.values()))]
    report = run(
        [
            str(llvm_cov),
            "report",
            str(components["core"]),
            f"-instr-profile={profdata_paths['core']}",
            *scope_paths,
        ],
        "llvm-cov report HDF-05 scope",
    )
    total_line = next((line for line in report.splitlines() if line.startswith("TOTAL")), None)
    if total_line is None:
        fail("llvm-cov report omitted the TOTAL row")
    fields = total_line.split()
    if len(fields) < 10:
        fail("llvm-cov TOTAL row is malformed")
    try:
        total_functions = int(fields[4])
        missed_functions = int(fields[5])
        total_lines = int(fields[7])
        missed_lines = int(fields[8])
    except ValueError:
        fail("llvm-cov TOTAL counts are invalid")
    live_totals = {
        "covered_lines": total_lines - missed_lines,
        "total_lines": total_lines,
        "covered_functions": total_functions - missed_functions,
        "total_functions": total_functions,
    }
    if any(evidence.get(field) != value for field, value in live_totals.items()):
        fail("live llvm-cov totals differ from recorded evidence")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--target-root", type=Path)
    parser.add_argument("--coverage-evidence", type=Path)
    args = parser.parse_args()
    try:
        if args.selftest:
            selftest()
            return 0
        if args.target_root is None or args.coverage_evidence is None:
            parser.error("--target-root and --coverage-evidence are required")
        target = args.target_root.resolve()
        guided_path = target / "guided-instrumentation.json"
        coverage_path = target / "coverage-instrumentation.json"
        guided, _guided_components = validate_manifest(guided_path, target, "guided")
        coverage, coverage_components = validate_manifest(coverage_path, target, "coverage")
        if guided.get("fixture") != coverage.get("fixture"):
            fail("guided and coverage builds did not use the same filtered fixture")
        evidence = validate_coverage_evidence(
            args.coverage_evidence.resolve(),
            target,
            coverage_path,
            coverage,
            coverage_components,
        )
    except BlockedError as error:
        print(f"[hdf5-instrumentation] BLOCKED: {error}", file=sys.stderr)
        return 2
    except ContractError as error:
        print(f"[hdf5-instrumentation] fail: {error}", file=sys.stderr)
        return 1
    print(
        "[hdf5-instrumentation] pass=9 fail=0 "
        f"guided_counters={guided['runtime']['guided']['loaded_inline_counters']} "
        f"wrapper_only_counters={guided['runtime']['normal_control']['loaded_inline_counters']} "
        f"covered_lines={evidence['covered_lines']}/{evidence['total_lines']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
