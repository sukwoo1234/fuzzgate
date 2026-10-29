#!/usr/bin/env python3
"""Validate the pinned HDF-01 core + high-level file-image build evidence."""

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
import tempfile
from typing import Any


VERSION = "2.2.0"
TARGET_ID = "hdf5-weights"
EXPECTED_MARKER = (
    "HDF5_FILE_IMAGE_OK calls=3 readonly=1 group=1 "
    "deflate=0 szip=0 shuffle=1 fletcher32=1 nbit=1 scaleoffset=1 "
    "version=2.2.0"
)
EXPECTED_SOURCE = {
    "name": "hdf5",
    "url": "https://github.com/HDFGroup/hdf5/releases/download/2.2.0/hdf5-2.2.0.tar.gz",
    "tag": VERSION,
    "resolved_commit": "49df1b4e5ca4108d56e80f06321a749da1535268",
    "sha256": "1a1ab8209b35586fbc1aa279ba76d102130b95badcb20ca329587219112d8c16",
    "size_bytes": 42131403,
}
EXPECTED_OPTIONS = {
    "BUILD_SHARED_LIBS": "ON",
    "BUILD_STATIC_LIBS": "OFF",
    "BUILD_TESTING": "OFF",
    "CMAKE_BUILD_TYPE": "RelWithDebInfo",
    "CMAKE_EXE_LINKER_FLAGS": "-fuse-ld=lld",
    "CMAKE_SHARED_LINKER_FLAGS": "-fuse-ld=lld",
    "HDF5_ALLOW_EXTERNAL_SUPPORT": "NO",
    "HDF5_BUILD_CPP_LIB": "OFF",
    "HDF5_BUILD_DOC": "OFF",
    "HDF5_BUILD_EXAMPLES": "OFF",
    "HDF5_BUILD_FORTRAN": "OFF",
    "HDF5_BUILD_HL_LIB": "ON",
    "HDF5_BUILD_JAVA": "OFF",
    "HDF5_BUILD_TOOLS": "OFF",
    "HDF5_ENABLE_CONCURRENCY": "OFF",
    "HDF5_ENABLE_HDFS": "OFF",
    "HDF5_ENABLE_PARALLEL": "OFF",
    "HDF5_ENABLE_PLUGIN_SUPPORT": "OFF",
    "HDF5_ENABLE_SZIP_SUPPORT": "OFF",
    "HDF5_ENABLE_THREADSAFE": "OFF",
    "HDF5_ENABLE_ZLIB_SUPPORT": "OFF",
}
EXPECTED_COMPILE_FLAGS = ["-O1", "-g", "-DNDEBUG"]
EXPECTED_FILTER_CONTRACT = {
    "built_in_filters": ["shuffle", "fletcher32", "nbit", "scaleoffset"],
    "deflate": "unsupported-build-disabled",
    "dynamic_plugin_loading": False,
    "external_support": "NO",
    "szip": "unsupported-build-disabled",
}


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


def require_regular(path: pathlib.Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is not a regular non-symlink file: {path}")


def load_json(path: pathlib.Path) -> dict[str, Any]:
    require_regular(path, path.name)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def validate_release_artifact(source: Any) -> None:
    if source != EXPECTED_SOURCE:
        observed = source.get("tag") if isinstance(source, dict) else None
        fail(f"HDF5 release pin mismatch: expected {VERSION}, observed {observed}")


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
    expected = {"core", "high_level"}
    if set(roles) != expected:
        fail(
            "linkage roles must include the HDF5 high-level library; "
            f"expected {sorted(expected)}, observed {sorted(roles)}"
        )


def validate_probe_call_evidence(linkage: dict[str, Any], marker: Any) -> None:
    symbols = linkage.get("probe_undefined_symbols")
    if not isinstance(symbols, list) or not all(isinstance(item, str) for item in symbols):
        fail("probe undefined-symbol evidence must be a string list")
    if not any(item.split("@", 1)[0] == "H5LTopen_file_image" for item in symbols):
        fail("probe does not link a call to H5LTopen_file_image")
    if marker != EXPECTED_MARKER:
        fail("probe did not execute the required H5LTopen_file_image success/rejection calls")


def validate_fresh_build_logs(build_log: str, probe_build_log: str) -> None:
    for label, text in (("HDF5", build_log), ("probe", probe_build_log)):
        if "ninja: no work to do." in text:
            fail(f"{label} build reused stale objects instead of rebuilding from clean source")
    for token in ("H5F.c.o", "H5LT.c.o"):
        if token not in build_log:
            fail(f"fresh HDF5 build log omits {token}")
    if "profile_probe.cc.o" not in probe_build_log:
        fail("fresh probe build log omits profile_probe.cc.o")


def cache_path(cache_text: str, key: str) -> pathlib.Path:
    match = re.search(rf"^{re.escape(key)}:[^=]+=([^\n]+)$", cache_text, re.MULTILINE)
    if match is None:
        fail(f"CMake cache omits {key}")
    return pathlib.Path(match.group(1)).resolve()


def validate_linker_evidence(
    main_commands: str,
    probe_commands: str,
    driver_trace: str,
    linker: pathlib.Path,
) -> None:
    core_lines = [
        line
        for line in main_commands.splitlines()
        if " -shared " in f" {line} " and "-o bin/libhdf5.so." in line
    ]
    high_level_lines = [
        line
        for line in main_commands.splitlines()
        if " -shared " in f" {line} " and "-o bin/libhdf5_hl.so." in line
    ]
    probe_lines = [
        line
        for line in probe_commands.splitlines()
        if "-o hdf5_file_image_probe " in line
        and "profile_probe.cc.o" in line
    ]
    for label, lines in (
        ("HDF5 core", core_lines),
        ("HDF5 high-level", high_level_lines),
        ("file-image probe", probe_lines),
    ):
        if len(lines) != 1 or "-fuse-ld=lld" not in lines[0]:
            fail(f"{label} link command does not uniquely force the recorded LLD linker")
    traced = re.findall(r'"([^"\n]*/ld\.lld)"', driver_trace)
    if len(traced) != 2:
        fail(f"linker driver trace must contain two ld.lld invocations, observed {len(traced)}")
    for path in traced:
        if pathlib.Path(path).resolve() != linker:
            fail("compiler driver trace resolves to a linker other than the recorded identity")


def validate_runtime_library_bindings(
    linkage: dict[str, Any], components: dict[str, pathlib.Path], needed: list[str]
) -> None:
    bindings = linkage.get("runtime_library_bindings")
    if not isinstance(bindings, list):
        fail("runtime_library_bindings must be a list")
    by_role: dict[str, dict[str, Any]] = {}
    expected_fields = {"role", "needed", "loader_path", "resolved_path", "sha256"}
    for row in bindings:
        if not isinstance(row, dict) or set(row) != expected_fields:
            fail("runtime library binding fields are invalid")
        role = row["role"]
        if role in by_role:
            fail(f"duplicate runtime library binding role: {role}")
        by_role[role] = row
    if set(by_role) != {"core", "high_level"}:
        fail("runtime library bindings must contain exactly core and high_level")
    prefixes = {"core": "libhdf5.so.", "high_level": "libhdf5_hl.so."}
    for role, component in components.items():
        row = by_role[role]
        needed_name = row["needed"]
        if not isinstance(needed_name, str) or not needed_name.startswith(prefixes[role]):
            fail(f"runtime binding has an invalid DT_NEEDED name for {role}")
        if needed.count(needed_name) != 1:
            fail(f"runtime binding is not uniquely present in DT_NEEDED for {role}")
        loader_path = pathlib.Path(row["loader_path"])
        if not loader_path.is_absolute() or not loader_path.is_symlink():
            fail(f"runtime loader path is not an absolute symlink for {role}")
        if loader_path.parent != component.parent or loader_path.name != needed_name:
            fail(f"runtime loader path is outside the hashed component directory for {role}")
        try:
            resolved = loader_path.resolve(strict=True)
        except OSError as error:
            fail(f"runtime loader symlink is broken for {role}: {error}")
        if resolved != component or pathlib.Path(row["resolved_path"]) != component:
            fail(f"runtime loader symlink does not resolve to the hashed {role} component")
        if row["sha256"] != file_sha256(component):
            fail(f"runtime loader binding hash mismatch for {role}")


def require_exact_archive(path: pathlib.Path) -> None:
    require_regular(path, "HDF5 archive")
    if path.stat().st_size != EXPECTED_SOURCE["size_bytes"]:
        fail(
            "HDF5 archive size mismatch: "
            f"expected {EXPECTED_SOURCE['size_bytes']} observed {path.stat().st_size}"
        )
    observed_sha = file_sha256(path)
    if observed_sha != EXPECTED_SOURCE["sha256"]:
        fail(
            "HDF5 archive sha256 mismatch: "
            f"expected {EXPECTED_SOURCE['sha256']} observed {observed_sha}"
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


def dynamic_symbols(readelf: pathlib.Path, probe: pathlib.Path) -> list[str]:
    output = subprocess.check_output(
        [
            str(readelf),
            "--elf-output-style=GNU",
            "--dyn-symbols",
            "--wide",
            str(probe),
        ],
        text=True,
    )
    symbols: list[str] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[6] == "UND":
            symbols.append(fields[7])
    return symbols


def dynamic_dependencies(readelf: pathlib.Path, probe: pathlib.Path) -> list[str]:
    output = subprocess.check_output([str(readelf), "-d", str(probe)], text=True)
    return re.findall(r"Shared library: \[([^]]+)\]", output)


def validate(root: pathlib.Path) -> tuple[pathlib.Path, dict[str, Any]]:
    root = root.resolve()
    archive = root / "source" / f"{VERSION}.tar.gz"
    require_exact_archive(archive)

    meta = load_json(root / "meta.json")
    expected_meta = {
        "schema_version": "1.0",
        "target": TARGET_ID,
        "version": VERSION,
        "source_kind": "official_release",
        "source_artifacts": [EXPECTED_SOURCE],
    }
    if meta != expected_meta:
        fail("meta.json does not exactly bind the official HDF5 release archive")

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
        "filter_contract",
        "components",
        "evidence_files",
        "linkage_manifest",
        "probe_contract",
        "execution_profile_ready",
        "next_card",
    }
    if set(profile) != required_top:
        fail(f"build profile fields mismatch: {sorted(set(profile) ^ required_top)}")
    if profile["schema_version"] != "hdf5-weights-build-profile-v1":
        fail("build profile schema mismatch")
    if profile["target_id"] != TARGET_ID or profile["target_version"] != VERSION:
        fail("build profile target/version mismatch")
    if profile["status"] != "provisioned":
        fail("build profile is not provisioned")
    if profile["source_artifacts"] != [EXPECTED_SOURCE] or profile["patches"] != []:
        fail("build profile source pin or patch declaration mismatch")
    validate_release_artifact(profile["source_artifacts"][0])
    if profile["cmake_options"] != EXPECTED_OPTIONS:
        fail("build profile CMake option set mismatch")
    if profile["compile_flags"] != EXPECTED_COMPILE_FLAGS:
        fail("build profile compile flags mismatch")
    if profile["filter_contract"] != EXPECTED_FILTER_CONTRACT:
        fail("build profile filter contract mismatch")
    if profile["execution_profile_ready"] is not False or profile["next_card"] != "HDF-02":
        fail("HDF-01 must not claim an execution-ready target profile or skip HDF-02")

    toolchain = profile["toolchain"]
    expected_tools = {"cmake", "c_compiler", "cxx_compiler", "linker", "ninja", "readelf"}
    if not isinstance(toolchain, dict) or set(toolchain) != expected_tools:
        fail("build profile toolchain fields mismatch")
    require_identity(toolchain["cmake"], "cmake", executable=True)
    c_compiler = require_identity(toolchain["c_compiler"], "C compiler", executable=True)
    cxx_compiler = require_identity(toolchain["cxx_compiler"], "C++ compiler", executable=True)
    linker = require_identity(toolchain["linker"], "linker", executable=True)
    require_identity(toolchain["ninja"], "ninja", executable=True)
    readelf = require_identity(toolchain["readelf"], "readelf", executable=True)

    components = profile["components"]
    if not isinstance(components, dict) or set(components) != {"core", "high_level", "probe"}:
        fail("build profile components must be exactly core, high_level, and probe")
    core = require_component(components["core"], "core")
    high_level = require_component(components["high_level"], "high_level")
    probe = require_component(components["probe"], "probe", executable=True)
    if "libhdf5.so" not in core.name:
        fail("core component filename is not libhdf5")
    if "libhdf5_hl.so" not in high_level.name:
        fail("high_level component filename is not libhdf5_hl")

    evidence = profile["evidence_files"]
    expected_evidence = {
        "cmake_cache",
        "compile_commands",
        "install_manifest",
        "link_commands",
        "probe_cmake_cache",
        "probe_compile_commands",
        "probe_link_commands",
        "linker_trace",
        "build_log",
        "probe_build_log",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected_evidence:
        fail("build profile evidence file set mismatch")
    evidence_paths = {
        name: require_component(row, f"evidence_files.{name}")
        for name, row in evidence.items()
    }
    cache_text = evidence_paths["cmake_cache"].read_text(encoding="utf-8")
    probe_cache_text = evidence_paths["probe_cmake_cache"].read_text(encoding="utf-8")
    if cache_path(cache_text, "CMAKE_C_COMPILER") != c_compiler:
        fail("HDF5 CMake cache C compiler differs from the recorded identity")
    if cache_path(cache_text, "CMAKE_CXX_COMPILER") != cxx_compiler:
        fail("HDF5 CMake cache C++ compiler differs from the recorded identity")
    if cache_path(cache_text, "CMAKE_LINKER") != linker:
        fail("HDF5 CMake cache linker differs from the recorded identity")
    if cache_path(probe_cache_text, "CMAKE_CXX_COMPILER") != cxx_compiler:
        fail("probe CMake cache C++ compiler differs from the recorded identity")
    if cache_path(probe_cache_text, "CMAKE_LINKER") != linker:
        fail("probe CMake cache linker differs from the recorded identity")
    probe_linker_flags = re.search(
        r"^CMAKE_EXE_LINKER_FLAGS:[^=]+=([^\n]*)$", probe_cache_text, re.MULTILINE
    )
    if probe_linker_flags is None or probe_linker_flags.group(1) != "-fuse-ld=lld":
        fail("probe CMake cache does not force the recorded LLD linker")
    for key, expected in EXPECTED_OPTIONS.items():
        match = re.search(rf"^{re.escape(key)}:[^=]+=(.*)$", cache_text, re.MULTILINE)
        observed = None if match is None else match.group(1)
        if observed != expected:
            fail(f"CMake cache option {key} mismatch: expected {expected}, observed {observed}")
    for key in ("CMAKE_C_FLAGS_RELWITHDEBINFO", "CMAKE_CXX_FLAGS_RELWITHDEBINFO"):
        match = re.search(rf"^{key}:[^=]+=([^\n]*)$", cache_text, re.MULTILINE)
        observed = None if match is None else match.group(1)
        if observed != "-O1 -g -DNDEBUG":
            fail(f"CMake cache flags {key} mismatch: {observed}")

    commands = json.loads(evidence_paths["compile_commands"].read_text(encoding="utf-8"))
    if not isinstance(commands, list) or not commands:
        fail("HDF5 compile_commands.json is empty")
    sources = [str(row.get("file", "")).replace("\\", "/") for row in commands if isinstance(row, dict)]
    if not any(source.endswith("/src/H5F.c") for source in sources):
        fail("HDF5 compile commands do not include the core file implementation")
    if not any(source.endswith("/hl/src/H5LT.c") for source in sources):
        fail("HDF5 compile commands do not include the high-level H5LT implementation")
    relevant = [
        row
        for row in commands
        if isinstance(row, dict)
        and any(token in str(row.get("file", "")).replace("\\", "/") for token in ("/src/", "/hl/src/"))
    ]
    for row in relevant:
        argv = row.get("arguments")
        if not isinstance(argv, list):
            command = row.get("command")
            if not isinstance(command, str):
                fail("compile command has neither arguments nor command")
            argv = shlex.split(command)
        if not argv or pathlib.Path(argv[0]).resolve() != c_compiler:
            fail("HDF5 compile command does not use the pinned compiler")
        if not all(flag in argv for flag in EXPECTED_COMPILE_FLAGS):
            fail("HDF5 compile command omits a pinned compile flag")

    probe_commands = json.loads(
        evidence_paths["probe_compile_commands"].read_text(encoding="utf-8")
    )
    if not isinstance(probe_commands, list) or len(probe_commands) != 1:
        fail("probe compile_commands.json must contain exactly one translation unit")
    if not str(probe_commands[0].get("file", "")).endswith("/harnesses/hdf5/profile_probe.cc"):
        fail("probe compile command does not compile the HDF5 profile probe")
    probe_argv = probe_commands[0].get("arguments")
    if not isinstance(probe_argv, list):
        probe_command = probe_commands[0].get("command")
        if not isinstance(probe_command, str):
            fail("probe compile command has neither arguments nor command")
        probe_argv = shlex.split(probe_command)
    if not probe_argv or pathlib.Path(probe_argv[0]).resolve() != cxx_compiler:
        fail("probe compile command does not use the pinned C++ compiler")
    validate_fresh_build_logs(
        evidence_paths["build_log"].read_text(encoding="utf-8"),
        evidence_paths["probe_build_log"].read_text(encoding="utf-8"),
    )
    validate_linker_evidence(
        evidence_paths["link_commands"].read_text(encoding="utf-8"),
        evidence_paths["probe_link_commands"].read_text(encoding="utf-8"),
        evidence_paths["linker_trace"].read_text(encoding="utf-8"),
        linker,
    )

    linkage_path = pathlib.Path(profile["linkage_manifest"])
    if not linkage_path.is_absolute():
        fail("linkage manifest path is not absolute")
    linkage = load_json(linkage_path)
    expected_linkage_fields = {
        "schema_version",
        "libraries",
        "installed_shared_libraries",
        "probe_dynamic_dependencies",
        "probe_undefined_symbols",
        "runtime_library_bindings",
    }
    if set(linkage) != expected_linkage_fields or linkage.get("schema_version") != "hdf5-weights-linkage-v1":
        fail("linkage manifest schema or fields mismatch")
    validate_linkage_roles(linkage)
    rows = {row["role"]: row for row in linkage["libraries"]}
    for role, component in (("core", core), ("high_level", high_level)):
        row = rows[role]
        if pathlib.Path(row["path"]) != component or row["sha256"] != file_sha256(component):
            fail(f"linkage manifest {role} identity mismatch")
    installed = linkage.get("installed_shared_libraries")
    if not isinstance(installed, list) or not all(isinstance(item, str) for item in installed):
        fail("installed_shared_libraries must be a string list")
    if not any("libhdf5.so" in item for item in installed):
        fail("installed libraries do not contain HDF5 core")
    if not any("libhdf5_hl.so" in item for item in installed):
        fail("installed libraries do not contain HDF5 high-level")
    needed = linkage.get("probe_dynamic_dependencies")
    if not isinstance(needed, list) or not all(isinstance(item, str) for item in needed):
        fail("probe dynamic dependencies must be a string list")
    if not any("libhdf5_hl.so" in item for item in needed):
        fail("probe has no dynamic dependency on HDF5 high-level")
    if not any(item.startswith("libhdf5.so") for item in needed):
        fail("probe has no dynamic dependency on HDF5 core")
    validate_runtime_library_bindings(
        linkage, {"core": core, "high_level": high_level}, needed
    )
    if dynamic_dependencies(readelf, probe) != needed:
        fail("probe dynamic dependencies changed after linkage evidence was written")
    if dynamic_symbols(readelf, probe) != linkage.get("probe_undefined_symbols"):
        fail("probe dynamic symbols changed after linkage evidence was written")

    contract = profile["probe_contract"]
    if contract != {
        "api": "H5LTopen_file_image(buffer, size, 0)",
        "input": "runtime-generated-core-driver-image",
        "expected_marker": EXPECTED_MARKER,
        "required_calls": 3,
    }:
        fail("probe contract mismatch")
    validate_probe_call_evidence(linkage, contract["expected_marker"])

    env = {
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "LD_LIBRARY_PATH": str(core.parent),
        "HDF5_PLUGIN_PATH": "",
    }
    completed = subprocess.run(
        [str(probe)],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )
    marker = completed.stdout.strip()
    if completed.returncode != 0 or marker != EXPECTED_MARKER:
        fail(f"file-image runtime probe failed rc={completed.returncode}: {marker!r}")
    validate_probe_call_evidence(linkage, marker)
    return profile_path, profile


def invalid_case(name: str) -> None:
    source = dict(EXPECTED_SOURCE)
    complete = {
        "libraries": [
            {"role": "core", "path": "/tmp/libhdf5.so", "sha256": "a" * 64},
            {"role": "high_level", "path": "/tmp/libhdf5_hl.so", "sha256": "b" * 64},
        ],
        "probe_undefined_symbols": ["H5LTopen_file_image"],
    }
    if name == "wrong-version":
        source["tag"] = "1.14.6"
        validate_release_artifact(source)
    elif name == "missing-high-level":
        validate_linkage_roles({"libraries": complete["libraries"][:1]})
    elif name == "missing-file-image-call":
        complete["probe_undefined_symbols"] = ["H5Fopen"]
        validate_probe_call_evidence(complete, EXPECTED_MARKER)
    elif name == "stale-build-log":
        validate_fresh_build_logs("ninja: no work to do.\n", "profile_probe.cc.o\n")
    elif name == "soname-symlink-mismatch":
        with tempfile.TemporaryDirectory(prefix="hdf5-binding-selftest-") as directory:
            root = pathlib.Path(directory)
            core = root / "libhdf5.so.320.2.0"
            high_level = root / "libhdf5_hl.so.320.0.3"
            decoy = root / "libhdf5-decoy.so"
            core.write_bytes(b"core")
            high_level.write_bytes(b"high-level")
            decoy.write_bytes(b"decoy")
            (root / "libhdf5.so.320").symlink_to(decoy.name)
            (root / "libhdf5_hl.so.320").symlink_to(high_level.name)
            validate_runtime_library_bindings(
                {
                    "runtime_library_bindings": [
                        {
                            "role": "core",
                            "needed": "libhdf5.so.320",
                            "loader_path": str(root / "libhdf5.so.320"),
                            "resolved_path": str(core),
                            "sha256": file_sha256(core),
                        },
                        {
                            "role": "high_level",
                            "needed": "libhdf5_hl.so.320",
                            "loader_path": str(root / "libhdf5_hl.so.320"),
                            "resolved_path": str(high_level),
                            "sha256": file_sha256(high_level),
                        },
                    ]
                },
                {"core": core, "high_level": high_level},
                ["libhdf5.so.320", "libhdf5_hl.so.320"],
            )
    elif name == "wrong-linker-driver":
        validate_linker_evidence(
            "clang -shared -o libhdf5.so.320 H5F.c.o",
            "clang++ -fuse-ld=lld -o hdf5_file_image_probe profile_probe.cc.o",
            '"/toolchain/bin/ld.lld"\n"/toolchain/bin/ld.lld"\n',
            pathlib.Path("/toolchain/bin/lld"),
        )
    else:
        fail(f"unknown self-test case: {name}")
    fail(f"negative self-test unexpectedly passed: {name}")


def selftest() -> None:
    cases = (
        "wrong-version",
        "missing-high-level",
        "missing-file-image-call",
        "stale-build-log",
        "soname-symlink-mismatch",
        "wrong-linker-driver",
    )
    for name in cases:
        try:
            invalid_case(name)
        except CheckError:
            continue
        fail(f"negative self-test unexpectedly passed: {name}")
    print("[hdf5-profile-selftest] pass=6 fail=0")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-root", type=pathlib.Path)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--selftest-case",
        choices=(
            "wrong-version",
            "missing-high-level",
            "missing-file-image-call",
            "stale-build-log",
            "soname-symlink-mismatch",
            "wrong-linker-driver",
        ),
    )
    args = parser.parse_args()
    selected = int(args.target_root is not None) + int(args.selftest) + int(args.selftest_case is not None)
    if selected != 1:
        parser.error("choose exactly one of --target-root, --selftest, or --selftest-case")
    return args


def main() -> int:
    args = parse_args()
    try:
        if args.selftest:
            selftest()
        elif args.selftest_case:
            invalid_case(args.selftest_case)
        else:
            profile_path, profile = validate(args.target_root)
            print(
                "[hdf5-profile] pass=1 fail=0 "
                f"profile={profile_path} version={profile['target_version']}"
            )
    except (CheckError, OSError, subprocess.SubprocessError) as error:
        print(f"[hdf5-profile] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
