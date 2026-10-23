#!/usr/bin/env python3
"""Validate the pinned OVI-01 Core + IR frontend build evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
from typing import Any


VERSION = "2026.4.1"
TARGET_ID = "openvino-ir"
EXPECTED_MARKER = "OPENVINO_IR_FRONTEND_OK nodes=2 parameters=1 results=1"
EXPECTED_SOURCES = [
    {
        "name": "openvino",
        "url": "https://github.com/openvinotoolkit/openvino/archive/refs/tags/2026.4.1.tar.gz",
        "tag": VERSION,
        "resolved_commit": "e213a14725769a6a2bf86fc86650aa78a9c05d3e",
        "sha256": "1ee85264556025486a4745a2d452ea823c578b3d162768bfef590366d2e6c539",
        "size_bytes": 71349787,
    },
    {
        "name": "pugixml",
        "url": "https://github.com/zeux/pugixml/archive/ee86beb30e4973f5feffe3ce63bfa4fbadf72f38.tar.gz",
        "tag": "ee86beb30e4973f5feffe3ce63bfa4fbadf72f38",
        "resolved_commit": "ee86beb30e4973f5feffe3ce63bfa4fbadf72f38",
        "sha256": "51c102d4187fac99daa38af281b0772c5e6c586f65004cdc63f8f2e011a21492",
        "size_bytes": 583144,
    },
    {
        "name": "xbyak",
        "url": "https://github.com/herumi/xbyak/archive/431abd865e70a46d56f5aa0e1f87572decb60169.tar.gz",
        "tag": "431abd865e70a46d56f5aa0e1f87572decb60169",
        "resolved_commit": "431abd865e70a46d56f5aa0e1f87572decb60169",
        "sha256": "3d80df7150abaa2103a0c50bbc3e2a100fd7866b3c90e9608783c0a5c785bbe8",
        "size_bytes": 563317,
    },
    {
        "name": "nlohmann-json",
        "url": "https://github.com/nlohmann/json/archive/9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03.tar.gz",
        "tag": "9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03",
        "resolved_commit": "9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03",
        "sha256": "0dbc5e40a01ff142e7e68c03e85247a4dcede2f592d12d3677dee3664d17975a",
        "size_bytes": 8054631,
    },
]
EXPECTED_OPTIONS = {
    "BUILD_SHARED_LIBS": "ON",
    "CMAKE_BUILD_TYPE": "RelWithDebInfo",
    "ENABLE_AUTO": "OFF",
    "ENABLE_AUTO_BATCH": "OFF",
    "ENABLE_DOCS": "OFF",
    "ENABLE_HETERO": "OFF",
    "ENABLE_INTEL_CPU": "OFF",
    "ENABLE_INTEL_GPU": "OFF",
    "ENABLE_INTEL_NPU": "OFF",
    "ENABLE_IO_URING": "OFF",
    "ENABLE_JS": "OFF",
    "ENABLE_LTO": "OFF",
    "ENABLE_MULTI": "OFF",
    "ENABLE_OV_GGUF_FRONTEND": "OFF",
    "ENABLE_OV_IR_FRONTEND": "ON",
    "ENABLE_OV_JAX_FRONTEND": "OFF",
    "ENABLE_OV_ONNX_FRONTEND": "OFF",
    "ENABLE_OV_PADDLE_FRONTEND": "OFF",
    "ENABLE_OV_PYTORCH_FRONTEND": "OFF",
    "ENABLE_OV_TF_FRONTEND": "OFF",
    "ENABLE_OV_TF_LITE_FRONTEND": "OFF",
    "ENABLE_PKGCONFIG_GEN": "OFF",
    "ENABLE_PLUGINS_XML": "OFF",
    "ENABLE_PROFILING_ITT": "OFF",
    "ENABLE_PROXY": "OFF",
    "ENABLE_PYTHON": "OFF",
    "ENABLE_SAMPLES": "OFF",
    "ENABLE_SYSTEM_PUGIXML": "OFF",
    "ENABLE_TEMPLATE": "OFF",
    "ENABLE_TESTS": "OFF",
    "THREADING": "SEQ",
}
EXPECTED_COMPILE_FLAGS = ["-O1", "-g", "-DNDEBUG"]
FORBIDDEN_INSTALL_TOKENS = (
    "openvino_auto_",
    "openvino_hetero_",
    "openvino_intel_cpu",
    "openvino_intel_gpu",
    "openvino_intel_npu",
    "openvino_onnx_frontend",
    "openvino_paddle_frontend",
    "openvino_pytorch_frontend",
    "openvino_tensorflow_frontend",
    "openvino_tensorflow_lite_frontend",
    "openvino_gguf_frontend",
)


class CheckError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise CheckError(message)


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: pathlib.Path) -> dict[str, Any]:
    require_regular(path, path.name)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def require_regular(path: pathlib.Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is not a regular non-symlink file: {path}")


def require_exact_file(path: pathlib.Path, source: dict[str, Any]) -> None:
    require_regular(path, source["name"] + " archive")
    observed_size = path.stat().st_size
    if observed_size != source["size_bytes"]:
        fail(
            f"{source['name']} archive size mismatch: "
            f"expected {source['size_bytes']} observed {observed_size}"
        )
    observed_sha = file_sha256(path)
    if observed_sha != source["sha256"]:
        fail(
            f"{source['name']} archive sha256 mismatch: "
            f"expected {source['sha256']} observed {observed_sha}"
        )


def require_identity(row: Any, label: str, *, executable: bool = False) -> pathlib.Path:
    if not isinstance(row, dict) or set(row) != {"path", "sha256", "version"}:
        fail(f"{label} identity fields are invalid")
    path = pathlib.Path(row["path"])
    if not path.is_absolute():
        fail(f"{label} path is not absolute: {path}")
    require_regular(path, label)
    if executable and not os.access(path, os.X_OK):
        fail(f"{label} is not executable: {path}")
    if file_sha256(path) != row["sha256"]:
        fail(f"{label} sha256 mismatch: {path}")
    if not isinstance(row["version"], str) or not row["version"]:
        fail(f"{label} version is empty")
    return path


def require_component(row: Any, label: str, *, executable: bool = False) -> pathlib.Path:
    if not isinstance(row, dict) or set(row) != {"path", "sha256"}:
        fail(f"{label} component fields are invalid")
    path = pathlib.Path(row["path"])
    if not path.is_absolute():
        fail(f"{label} component path is not absolute: {path}")
    require_regular(path, label)
    if executable and not os.access(path, os.X_OK):
        fail(f"{label} component is not executable: {path}")
    if file_sha256(path) != row["sha256"]:
        fail(f"{label} component sha256 mismatch: {path}")
    return path


def validate_linkage_roles(manifest: dict[str, Any]) -> None:
    libraries = manifest.get("libraries")
    if not isinstance(libraries, list):
        fail("linkage manifest libraries must be a list")
    roles: dict[str, dict[str, Any]] = {}
    for row in libraries:
        if not isinstance(row, dict) or set(row) != {"role", "path", "sha256"}:
            fail("linkage manifest library fields are invalid")
        role = row["role"]
        if role in roles:
            fail(f"duplicate linkage role: {role}")
        roles[role] = row
    expected = {"core", "ir_frontend"}
    if set(roles) != expected:
        fail(f"linkage roles must be exactly {sorted(expected)}; observed {sorted(roles)}")


def validate(root: pathlib.Path) -> tuple[pathlib.Path, dict[str, Any]]:
    root = root.resolve()
    archive_dir = root / "source"
    archives = [
        archive_dir / f"{VERSION}.tar.gz",
        archive_dir / "dependencies" / "pugixml-ee86beb30e4973f5feffe3ce63bfa4fbadf72f38.tar.gz",
        archive_dir / "dependencies" / "xbyak-431abd865e70a46d56f5aa0e1f87572decb60169.tar.gz",
        archive_dir / "dependencies" / "nlohmann-json-9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03.tar.gz",
    ]
    for path, source in zip(archives, EXPECTED_SOURCES, strict=True):
        require_exact_file(path, source)

    meta = load_json(root / "meta.json")
    expected_meta = {
        "schema_version": "1.0",
        "target": TARGET_ID,
        "version": VERSION,
        "source_kind": "official_release",
        "source_artifacts": EXPECTED_SOURCES,
    }
    if meta != expected_meta:
        fail("meta.json does not exactly bind the official release and dependency archives")

    profile_path = root / "build-profile.json"
    profile = load_json(profile_path)
    required_top = {
        "schema_version",
        "target_id",
        "target_version",
        "status",
        "source_artifacts",
        "patches",
        "toolchain",
        "cmake_options",
        "compile_flags",
        "components",
        "evidence_files",
        "linkage_manifest",
        "probe_contract",
        "execution_profile_ready",
        "next_card",
    }
    if set(profile) != required_top:
        fail(f"build profile fields mismatch: {sorted(set(profile) ^ required_top)}")
    if profile["schema_version"] != "openvino-ir-build-profile-v1":
        fail("build profile schema mismatch")
    if profile["target_id"] != TARGET_ID or profile["target_version"] != VERSION:
        fail("build profile target/version mismatch")
    if profile["status"] != "provisioned":
        fail("build profile is not provisioned")
    if profile["source_artifacts"] != EXPECTED_SOURCES or profile["patches"] != []:
        fail("build profile source pins or patch declaration mismatch")
    if profile["cmake_options"] != EXPECTED_OPTIONS:
        fail("build profile CMake option set mismatch")
    if profile["compile_flags"] != EXPECTED_COMPILE_FLAGS:
        fail("build profile compile flags mismatch")
    if profile["execution_profile_ready"] is not False or profile["next_card"] != "OVI-02":
        fail("OVI-01 must not claim an execution-ready target profile or skip OVI-02")

    toolchain = profile["toolchain"]
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "cmake",
        "compiler",
        "linker",
        "ninja",
        "readelf",
    }:
        fail("build profile toolchain fields mismatch")
    require_identity(toolchain["cmake"], "cmake", executable=True)
    compiler_path = require_identity(toolchain["compiler"], "compiler", executable=True)
    require_identity(toolchain["linker"], "linker", executable=True)
    require_identity(toolchain["ninja"], "ninja", executable=True)
    readelf_path = require_identity(toolchain["readelf"], "readelf", executable=True)

    components = profile["components"]
    if not isinstance(components, dict) or set(components) != {"core", "ir_frontend", "probe"}:
        fail("build profile components must be exactly core, ir_frontend, and probe")
    core_path = require_component(components["core"], "core")
    frontend_path = require_component(components["ir_frontend"], "ir_frontend")
    probe_path = require_component(components["probe"], "probe", executable=True)
    if "openvino" not in core_path.name or "ir_frontend" in core_path.name:
        fail("core component filename is not an OpenVINO Core library")
    if "openvino_ir_frontend" not in frontend_path.name:
        fail("IR frontend component filename is not libopenvino_ir_frontend")

    evidence = profile["evidence_files"]
    expected_evidence = {
        "cmake_cache",
        "compile_commands",
        "install_manifest",
        "link_commands",
        "probe_compile_commands",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected_evidence:
        fail("build profile evidence file set mismatch")
    evidence_paths = {
        name: require_component(row, f"evidence_files.{name}")
        for name, row in evidence.items()
    }
    cache_text = evidence_paths["cmake_cache"].read_text(encoding="utf-8")
    for key, expected in EXPECTED_OPTIONS.items():
        match = re.search(rf"^{re.escape(key)}:[^=]+=(.*)$", cache_text, re.MULTILINE)
        if match is None or match.group(1) != expected:
            observed = None if match is None else match.group(1)
            fail(f"CMake cache option {key} mismatch: expected {expected}, observed {observed}")
    for key in ("CMAKE_C_FLAGS_RELWITHDEBINFO", "CMAKE_CXX_FLAGS_RELWITHDEBINFO"):
        match = re.search(rf"^{key}:[^=]+=([^\n]*)$", cache_text, re.MULTILINE)
        if match is None or match.group(1) != "-O1 -g -DNDEBUG":
            observed = None if match is None else match.group(1)
            fail(f"CMake cache flags {key} mismatch: {observed}")
    commands = json.loads(evidence_paths["compile_commands"].read_text(encoding="utf-8"))
    if not isinstance(commands, list) or not commands:
        fail("OpenVINO compile_commands.json is empty")
    sources = [str(row.get("file", "")).replace("\\", "/") for row in commands if isinstance(row, dict)]
    if not any("/src/frontends/ir/" in source for source in sources):
        fail("OpenVINO compile commands do not include the IR frontend")
    if not any("/src/core/" in source for source in sources):
        fail("OpenVINO compile commands do not include Core")
    forbidden_source_tokens = (
        "/src/frontends/onnx/",
        "/src/frontends/paddle/",
        "/src/frontends/pytorch/",
        "/src/frontends/tensorflow/",
        "/src/frontends/tensorflow_lite/",
        "/src/frontends/gguf/",
        "/src/plugins/intel_cpu/",
        "/src/plugins/intel_gpu/",
        "/src/plugins/intel_npu/",
    )
    if any(token in source for token in forbidden_source_tokens for source in sources):
        fail("OpenVINO compile commands contain a disabled frontend or inference plugin")
    relevant_commands = [
        row
        for row in commands
        if isinstance(row, dict)
        and any(token in str(row.get("file", "")).replace("\\", "/") for token in ("/src/core/", "/src/frontends/ir/"))
    ]
    for row in relevant_commands:
        argv = row.get("arguments")
        if not isinstance(argv, list):
            command = row.get("command")
            if not isinstance(command, str):
                fail("compile command has neither arguments nor command")
            argv = shlex.split(command)
        if not argv or pathlib.Path(argv[0]).resolve() != compiler_path:
            fail("Core/IR compile command does not use the pinned compiler")
        if not all(flag in argv for flag in EXPECTED_COMPILE_FLAGS):
            fail("Core/IR compile command omits a pinned compile flag")
    probe_commands = json.loads(evidence_paths["probe_compile_commands"].read_text(encoding="utf-8"))
    if not isinstance(probe_commands, list) or len(probe_commands) != 1:
        fail("probe compile_commands.json must contain exactly one translation unit")
    if not str(probe_commands[0].get("file", "")).endswith("/harnesses/openvino/profile_probe.cc"):
        fail("probe compile command does not compile profile_probe.cc")

    linkage_path = pathlib.Path(profile["linkage_manifest"])
    if not linkage_path.is_absolute():
        fail("linkage manifest path is not absolute")
    linkage = load_json(linkage_path)
    if linkage.get("schema_version") != "openvino-ir-linkage-v1":
        fail("linkage manifest schema mismatch")
    validate_linkage_roles(linkage)
    manifest_rows = {row["role"]: row for row in linkage["libraries"]}
    for role, component_path in (("core", core_path), ("ir_frontend", frontend_path)):
        row = manifest_rows[role]
        if pathlib.Path(row["path"]) != component_path or row["sha256"] != file_sha256(component_path):
            fail(f"linkage manifest {role} identity mismatch")
    installed = linkage.get("installed_shared_libraries")
    if not isinstance(installed, list) or not all(isinstance(item, str) for item in installed):
        fail("installed_shared_libraries must be a string list")
    if any(token in item for token in FORBIDDEN_INSTALL_TOKENS for item in installed):
        fail("linkage manifest contains a disabled frontend or inference plugin")
    if not any("openvino_ir_frontend" in item for item in installed):
        fail("linkage manifest does not contain the IR frontend library")
    needed = linkage.get("probe_dynamic_dependencies")
    if not isinstance(needed, list) or not any("libopenvino.so" in item for item in needed):
        fail("probe does not have a dynamic dependency on OpenVINO Core")
    dynamic = subprocess.check_output([str(readelf_path), "-d", str(probe_path)], text=True)
    observed_needed = re.findall(r"Shared library: \[([^]]+)\]", dynamic)
    if needed != observed_needed:
        fail("probe dynamic dependencies changed after linkage evidence was written")

    contract = profile["probe_contract"]
    if contract != {
        "api": "ov::Core::read_model(model_text, weights)",
        "input": "embedded-memory-ir-v11",
        "expected_marker": EXPECTED_MARKER,
    }:
        fail("probe contract mismatch")

    completed = subprocess.run(
        [str(probe_path)],
        cwd=root,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0 or completed.stdout.strip() != EXPECTED_MARKER:
        fail(
            f"IR frontend probe failed rc={completed.returncode}: "
            f"{completed.stdout.strip()!r}"
        )
    return profile_path, profile


def selftest() -> None:
    complete = {
        "libraries": [
            {"role": "core", "path": "/tmp/libopenvino.so", "sha256": "a" * 64},
            {
                "role": "ir_frontend",
                "path": "/tmp/libopenvino_ir_frontend.so",
                "sha256": "b" * 64,
            },
        ]
    }
    validate_linkage_roles(complete)
    core_only = {"libraries": [complete["libraries"][0]]}
    try:
        validate_linkage_roles(core_only)
    except CheckError as error:
        if "ir_frontend" not in str(error):
            fail(f"Core-only rejection had the wrong reason: {error}")
    else:
        fail("Core-only linkage manifest was accepted")
    duplicate = {"libraries": [complete["libraries"][0], complete["libraries"][0]]}
    try:
        validate_linkage_roles(duplicate)
    except CheckError as error:
        if "duplicate linkage role" not in str(error):
            fail(f"duplicate-role rejection had the wrong reason: {error}")
    else:
        fail("duplicate linkage role was accepted")
    print("[openvino-profile-selftest] pass=3 fail=0")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-root", type=pathlib.Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest == (args.target_root is not None):
        parser.error("choose exactly one of --selftest or --target-root")
    return args


def main() -> int:
    args = parse_args()
    try:
        if args.selftest:
            selftest()
        else:
            profile_path, profile = validate(args.target_root)
            print(
                "[openvino-profile] pass=1 fail=0 "
                f"profile={profile_path} version={profile['target_version']}"
            )
    except (CheckError, OSError, subprocess.SubprocessError) as error:
        print(f"[openvino-profile] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
