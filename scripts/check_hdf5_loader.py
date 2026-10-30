#!/usr/bin/env python3
"""Verify the HDF-03 shared loader, replay, engine, and resource contract."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from typing import Any, NoReturn


class ContractError(RuntimeError):
    """The HDF-03 loader contract was not met."""


class Results:
    def __init__(self, prefix: str = "hdf5-loader") -> None:
        self.prefix = prefix
        self.passed = 0
        self.failed = 0

    def ok(self, message: str) -> None:
        self.passed += 1
        print(f"[{self.prefix}] ok: {message}")

    def bad(self, message: str) -> None:
        self.failed += 1
        print(f"[{self.prefix}] fail: {message}", file=sys.stderr)


def fail(message: str) -> NoReturn:
    raise ContractError(message)


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    expect: int = 0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != expect:
        fail(
            f"command returned {completed.returncode}, expected {expect}: {command!r}\n"
            f"stdout={completed.stdout[-4000:]!r}\nstderr={completed.stderr[-4000:]!r}"
        )
    return completed


def load_unique_json(path: Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                fail(f"duplicate JSON key {key!r} in {path}")
            value[key] = item
        return value

    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read unique JSON {path}: {error}")
    if not isinstance(document, dict):
        fail(f"JSON root is not an object: {path}")
    return document


def require_regular(path: Path, label: str, *, executable: bool = False) -> None:
    try:
        path.lstat()
    except OSError as error:
        fail(f"{label} is unavailable: {path}: {error}")
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")
    if executable and not os.access(path, os.X_OK):
        fail(f"{label} is not executable: {path}")


def validate_loader_linkage(readelf: Path, binary: Path, target: Path) -> None:
    dynamic = run([str(readelf), "-d", str(binary)]).stdout
    needed = re.findall(r"Shared library: \[([^]]+)\]", dynamic)
    if not any(name.startswith("libhdf5.so") for name in needed):
        fail(f"{binary.name} has no dynamic dependency on pinned HDF5 core")
    if not any(name.startswith("libhdf5_hl.so") for name in needed):
        fail(f"{binary.name} has no dynamic dependency on pinned HDF5 high-level")
    if str(target / "install/lib") not in dynamic:
        fail(f"{binary.name} has no runpath to the pinned HDF5 library directory")
    symbols = run(
        [
            str(readelf),
            "--elf-output-style=GNU",
            "--dyn-symbols",
            "--wide",
            str(binary),
        ]
    ).stdout
    for symbol in ("H5LTopen_file_image", "H5Dread", "H5Aread"):
        if symbol not in symbols:
            fail(f"{binary.name} does not call required HDF5 API: {symbol}")


def validate_source_contract(loader: str, replay: str, fuzzer: str, header: str) -> None:
    required_header = (
        "kMaxInputBytes = 32U * 1024U * 1024U",
        "kMaxDatasets = 4096U",
        "kMaxRank = 32U",
        "kMaxReadBytes = 1U * 1024U * 1024U",
        "LoadImage(",
    )
    for marker in required_header:
        if marker not in header:
            fail(f"common loader header omits required contract: {marker}")

    required_loader = (
        "H5LTopen_file_image",
        "H5Lget_info2",
        "H5Oget_info_by_name3",
        "H5Otoken_cmp",
        "H5Dget_type",
        "H5Dget_space",
        "H5Dget_create_plist",
        "H5Pget_external_count",
        "H5D_VIRTUAL",
        "H5T_REFERENCE",
        "H5T_VLEN",
        "H5Sselect_hyperslab",
        "H5Dread(",
        "H5Aread(",
    )
    for marker in required_loader:
        if marker not in loader:
            fail(f"common loader omits required HDF5 operation: {marker}")
    for marker in (
        "scalar-numeric",
        "empty-numeric",
        "tensor-contiguous",
        "tensor-chunked",
        "missing-dataset",
        "unsupported-filter",
        "unsupported-dtype",
        "external-link",
    ):
        if marker in loader:
            fail(f"common loader hard-codes an HDF-02 fixture identity: {marker}")
    for marker in ("catch (...)", "catch (const std::exception&", "H5Pset_elink_prefix"):
        if marker in loader:
            fail(f"common loader contains forbidden fault/external bypass: {marker}")
    if re.search(r"static\s+(?:std::vector|LoadSummary|Handle)", loader):
        fail("common loader retains per-input data or handles in static state")

    read_call = loader.find("H5Dread(")
    read_check = loader.find("if (read_status < 0)", read_call)
    publish = loader.find("observation.values = std::move(values)", read_call)
    if read_call < 0 or read_check < read_call or publish < read_check:
        fail("H5Dread result is not checked before the output buffer reaches the oracle")

    for label, wrapper in (("replay", replay), ("engine", fuzzer)):
        if wrapper.count("tool::hdf5_loader::LoadImage(") != 1:
            fail(f"{label} wrapper does not call the single common loader exactly once")
        for marker in ("<hdf5", "<hdf5_hl", "H5LT", "H5Dread", "H5Dopen", "H5Gopen"):
            if marker in wrapper:
                fail(f"{label} wrapper contains a separate HDF5 loader operation: {marker}")


def case_groups(output: str) -> list[list[str]]:
    groups: list[list[str]] = []
    current: list[str] | None = None
    for line in output.splitlines():
        if line.startswith("HDF5_CASE_BEGIN ordinal="):
            if current is not None:
                fail("nested HDF5 case marker")
            current = []
        elif line.startswith("HDF5_CASE_END ordinal="):
            if current is None:
                fail("orphan HDF5 case end")
            groups.append(current)
            current = None
        elif current is not None:
            current.append(line)
    if current is not None:
        fail("unterminated HDF5 case marker")
    return groups


def validate_aba(output: str) -> None:
    groups = case_groups(output)
    if len(groups) != 3:
        fail(f"expected three completed A-B-A cases, observed {len(groups)}")
    if groups[0] != groups[2]:
        fail("A observations differ after B")
    if groups[0] == groups[1]:
        fail("A and B observations are identical; value access or state reset is absent")
    if not any("values=7" in line for line in groups[0]):
        fail("A scalar value evidence is absent")
    if not any("values=-3,0,7,11,1024,-2048" in line for line in groups[1]):
        fail("B chunked value evidence is absent")


def validate_outcome(
    completed: subprocess.CompletedProcess[str],
    *,
    classification: str,
    stage: str,
) -> None:
    combined = completed.stdout + completed.stderr
    marker = f"HDF5_RESULT classification={classification} stage={stage} "
    if marker not in combined:
        fail(f"outcome marker is absent: {marker!r}\n{combined[-2000:]}")


def expect_contract_failure(label: str, callback: Any) -> None:
    try:
        callback()
    except ContractError:
        return
    fail(f"negative control was accepted: {label}")


def run_negative_controls() -> None:
    good_header = """
kMaxInputBytes = 32U * 1024U * 1024U
kMaxDatasets = 4096U
kMaxRank = 32U
kMaxReadBytes = 1U * 1024U * 1024U
LoadImage(
"""
    good_loader = """
H5LTopen_file_image H5Lget_info2 H5Oget_info_by_name3 H5Otoken_cmp
H5Dget_type H5Dget_space H5Dget_create_plist H5Pget_external_count
H5D_VIRTUAL H5T_REFERENCE H5T_VLEN H5Sselect_hyperslab
const herr_t read_status = H5Dread(dataset, type, mem, file, props, buffer);
if (read_status < 0) { return result; }
observation.values = std::move(values);
H5Aread(attribute, type, buffer)
"""
    good_replay = "tool::hdf5_loader::LoadImage(data, size, limits);"
    good_fuzzer = "tool::hdf5_loader::LoadImage(data, size, limits);"

    expect_contract_failure(
        "H5Dread omitted",
        lambda: validate_source_contract(
            good_loader.replace("H5Dread(", "PretendRead("),
            good_replay,
            good_fuzzer,
            good_header,
        ),
    )
    expect_contract_failure(
        "failed H5Dread buffer published",
        lambda: validate_source_contract(
            good_loader.replace(
                "if (read_status < 0) { return result; }\n"
                "observation.values = std::move(values);",
                "observation.values = std::move(values);\n"
                "if (read_status < 0) { return result; }",
            ),
            good_replay,
            good_fuzzer,
            good_header,
        ),
    )
    expect_contract_failure(
        "engine implements a split loader",
        lambda: validate_source_contract(
            good_loader,
            good_replay,
            good_fuzzer + "\nH5Dread(dataset, type, mem, file, props, buffer);",
            good_header,
        ),
    )
    expect_contract_failure(
        "external-link prefix enables outside resolution",
        lambda: validate_source_contract(
            good_loader + "\nH5Pset_elink_prefix(properties, cwd);",
            good_replay,
            good_fuzzer,
            good_header,
        ),
    )

    accepted_empty = subprocess.CompletedProcess(
        [], 0, "HDF5_RESULT classification=accepted stage=complete reason=loaded\n", ""
    )
    rejected_missing = subprocess.CompletedProcess(
        [], 9, "", "HDF5_RESULT classification=target_reject stage=dataset_lookup reason=required_dataset_absent\n"
    )
    validate_outcome(accepted_empty, classification="accepted", stage="complete")
    validate_outcome(rejected_missing, classification="target_reject", stage="dataset_lookup")
    expect_contract_failure(
        "empty and missing collapsed",
        lambda: validate_outcome(accepted_empty, classification="target_reject", stage="dataset_lookup"),
    )

    a = [
        "HDF5_RESULT classification=accepted stage=complete reason=loaded",
        "HDF5_DATASET values=7",
    ]
    b = [
        "HDF5_RESULT classification=accepted stage=complete reason=loaded",
        "HDF5_DATASET values=-3,0,7,11,1024,-2048",
    ]

    def transcript(groups: list[list[str]]) -> str:
        lines: list[str] = []
        for ordinal, group in enumerate(groups, 1):
            lines.append(f"HDF5_CASE_BEGIN ordinal={ordinal}")
            lines.extend(group)
            lines.append(f"HDF5_CASE_END ordinal={ordinal} status=accepted")
        return "\n".join(lines) + "\n"

    validate_aba(transcript([a, b, a]))
    expect_contract_failure("A-B-A sticky state", lambda: validate_aba(transcript([a, a, a])))


def selftest() -> int:
    results = Results("hdf5-loader-selftest")
    checks = (
        ("omitted H5Dread", run_negative_controls),
    )
    for label, callback in checks:
        try:
            callback()
            results.ok(f"RED controls reject {label}, failure-buffer, split-loader, external, empty/missing, and sticky-state defects")
        except (ContractError, OSError, ValueError) as error:
            results.bad(f"RED controls are ineffective: {error}")
    print(f"[{results.prefix}] pass={results.passed} fail={results.failed}")
    return 0 if results.failed == 0 else 1


def write_fault_probe(project: Path, work: Path) -> tuple[Path, Path, Path]:
    fake_loader = work / "fault_loader.cc"
    fake_loader.write_text(
        """#include "harnesses/hdf5/loader.h"
#include <csignal>
namespace tool::hdf5_loader {
LoadResult LoadImage(const std::uint8_t*, std::size_t, const Limits&) {
  std::raise(SIGABRT);
  return {};
}
}  // namespace tool::hdf5_loader
""",
        encoding="utf-8",
    )
    driver = work / "fault_driver.cc"
    driver.write_text(
        """#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t);
int main() {
  const std::uint8_t input[] = {0};
  return LLVMFuzzerTestOneInput(input, sizeof(input));
}
""",
        encoding="utf-8",
    )
    output = work / "fault-engine"
    return fake_loader, driver, output


def build_preload_shims(
    compiler: Path, include: Path, work: Path
) -> tuple[Path, Path, Path]:
    read_source = work / "fail_h5dread.c"
    read_source.write_text(
        """#include <hdf5.h>
herr_t H5Dread(hid_t dataset, hid_t memory_type, hid_t memory_space,
               hid_t file_space, hid_t properties, void *buffer) {
  (void)dataset; (void)memory_type; (void)memory_space; (void)file_space;
  (void)properties; (void)buffer;
  return -1;
}
""",
        encoding="utf-8",
    )
    read_shim = work / "fail_h5dread.so"
    run([str(compiler), "-shared", "-fPIC", f"-I{include}", str(read_source), "-o", str(read_shim)])

    open_source = work / "guard_outside_open.c"
    open_source.write_text(
        r'''#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>

static void guard(const char *path) {
  if (path && (strstr(path, "outside-payload.h5") ||
               strstr(path, "outside-raw.bin") ||
               strstr(path, "outside-vds.h5"))) {
    raise(SIGABRT);
  }
}

int open(const char *path, int flags, ...) {
  static int (*real_open)(const char *, int, ...) = 0;
  if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
  guard(path);
  if (flags & O_CREAT) {
    va_list args; va_start(args, flags); mode_t mode = va_arg(args, mode_t); va_end(args);
    return real_open(path, flags, mode);
  }
  return real_open(path, flags);
}

int open64(const char *path, int flags, ...) {
  static int (*real_open64)(const char *, int, ...) = 0;
  if (!real_open64) real_open64 = dlsym(RTLD_NEXT, "open64");
  guard(path);
  if (flags & O_CREAT) {
    va_list args; va_start(args, flags); mode_t mode = va_arg(args, mode_t); va_end(args);
    return real_open64(path, flags, mode);
  }
  return real_open64(path, flags);
}

int openat(int dirfd, const char *path, int flags, ...) {
  static int (*real_openat)(int, const char *, int, ...) = 0;
  if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
  guard(path);
  if (flags & O_CREAT) {
    va_list args; va_start(args, flags); mode_t mode = va_arg(args, mode_t); va_end(args);
    return real_openat(dirfd, path, flags, mode);
  }
  return real_openat(dirfd, path, flags);
}
''',
        encoding="utf-8",
    )
    open_shim = work / "guard_outside_open.so"
    run([str(compiler), "-shared", "-fPIC", str(open_source), "-ldl", "-o", str(open_shim)])

    version_source = work / "wrong_hdf5_version.c"
    version_source.write_text(
        """#include <hdf5.h>
herr_t H5get_libversion(unsigned *major, unsigned *minor, unsigned *release) {
  *major = 1; *minor = 14; *release = 0;
  return 0;
}
""",
        encoding="utf-8",
    )
    version_shim = work / "wrong_hdf5_version.so"
    run(
        [
            str(compiler),
            "-shared",
            "-fPIC",
            f"-I{include}",
            str(version_source),
            "-o",
            str(version_shim),
        ]
    )
    return read_shim, open_shim, version_shim


def validate_normal_outputs(replay: Path, fixtures: Path) -> None:
    cases = {
        "scalar-numeric.h5": ("dtype=int64-le shape=- elements=1 read_elements=1 values=7", None),
        "empty-numeric.h5": ("state=present_empty dtype=float32-le shape=0,3 elements=0 read_elements=0 values=-", None),
        "tensor-contiguous.h5": (
            "dtype=float32-le shape=2,3 elements=6 read_elements=6 values=1.25,-2,3.5,4.25,-5.75,6",
            ("name_hex=666978747572655f76657273696f6e", "name_hex=617869735f636f756e74"),
        ),
        "tensor-chunked.h5": ("dtype=int16-le shape=3,2 elements=6 read_elements=6 values=-3,0,7,11,1024,-2048", None),
    }
    for filename, (dataset_marker, attributes) in cases.items():
        completed = run([str(replay), str(fixtures / filename)])
        validate_outcome(completed, classification="accepted", stage="complete")
        if dataset_marker not in completed.stdout:
            fail(f"{filename} exact dataset oracle is absent: {dataset_marker}")
        if "HDF5_ACCESS_OK" not in completed.stdout or "h5dread_calls=1" not in completed.stdout:
            fail(f"{filename} did not prove H5Dread plus bounded value access")
        if attributes:
            for marker in attributes:
                if marker not in completed.stdout:
                    fail(f"{filename} attribute access marker is absent: {marker}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--target-root", type=Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.project_root is None or args.target_root is None:
        parser.error("--project-root and --target-root are required")

    project = args.project_root.resolve()
    target = args.target_root.resolve()
    results = Results()

    try:
        run_negative_controls()
        results.ok("RED controls reject omitted-read, failure-buffer, split-loader, external, empty/missing, and sticky-state defects")
    except (ContractError, OSError, ValueError) as error:
        results.bad(f"RED controls are ineffective: {error}")

    sources = {
        "common loader header": project / "harnesses/hdf5/loader.h",
        "common loader implementation": project / "harnesses/hdf5/loader.cc",
        "replay wrapper": project / "harnesses/hdf5/replay.cc",
        "engine wrapper": project / "harnesses/hdf5/fuzzer.cc",
        "loader test tool": project / "harnesses/hdf5/loader_test_tool.cc",
        "CMake source": project / "harnesses/hdf5/CMakeLists.txt",
        "HDF-02 fixture generator": project / "scripts/gen_hdf5_fixtures.py",
        "HDF-02 fixture source": project / "harnesses/hdf5/fixture_tool.cc",
        "pinned build profile": target / "build-profile.json",
    }
    missing = False
    for label, path in sources.items():
        if not path.is_file() or path.is_symlink():
            results.bad(f"{label} is missing or not a regular file: {path}")
            missing = True
    if missing:
        print(f"[{results.prefix}] pass={results.passed} fail={results.failed}")
        return 1

    try:
        header = sources["common loader header"].read_text(encoding="utf-8")
        loader = sources["common loader implementation"].read_text(encoding="utf-8")
        replay_source = sources["replay wrapper"].read_text(encoding="utf-8")
        fuzzer_source = sources["engine wrapper"].read_text(encoding="utf-8")
        validate_source_contract(loader, replay_source, fuzzer_source, header)
        results.ok("replay and engine use one common loader with read-before-oracle and no retained state")

        run(
            [
                sys.executable,
                "-B",
                str(project / "scripts/check_hdf5_profile.py"),
                "--target-root",
                str(target),
            ]
        )
        profile = load_unique_json(sources["pinned build profile"])
        toolchain = profile.get("toolchain")
        if not isinstance(toolchain, dict):
            fail("build profile has no toolchain object")
        cmake = Path(str(toolchain.get("cmake", {}).get("path", "")))
        c_compiler = Path(str(toolchain.get("c_compiler", {}).get("path", "")))
        recorded_cxx_compiler = Path(
            str(toolchain.get("cxx_compiler", {}).get("path", ""))
        )
        cxx_compiler = recorded_cxx_compiler.with_name("clang++")
        ninja = Path(str(toolchain.get("ninja", {}).get("path", "")))
        readelf = Path(str(toolchain.get("readelf", {}).get("path", "")))
        for label, path in (
            ("cmake", cmake),
            ("C compiler", c_compiler),
            ("recorded C++ compiler", recorded_cxx_compiler),
            ("ninja", ninja),
            ("readelf", readelf),
        ):
            require_regular(path, f"pinned {label}", executable=True)
        if (
            not cxx_compiler.is_symlink()
            or not cxx_compiler.resolve().is_file()
            or not os.access(cxx_compiler, os.X_OK)
            or cxx_compiler.resolve() != recorded_cxx_compiler.resolve()
        ):
            fail("clang++ driver does not resolve to the pinned compiler bytes")
        hdf5_dir = target / "install/lib/cmake/hdf5"
        include = target / "install/include"
        require_regular(hdf5_dir / "hdf5-config.cmake", "pinned HDF5 CMake package")
        results.ok("official HDF5 2.2.0 profile and toolchain identity are valid")

        with tempfile.TemporaryDirectory(prefix="hdf5-loader-check-") as temporary:
            work = Path(temporary)
            default_build = work / "default-build"
            run(
                [
                    str(cmake),
                    "-S",
                    str(project / "harnesses/hdf5"),
                    "-B",
                    str(default_build),
                    "-G",
                    "Ninja",
                    "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                    f"-DCMAKE_C_COMPILER={c_compiler}",
                    f"-DCMAKE_CXX_COMPILER={cxx_compiler}",
                    f"-DCMAKE_MAKE_PROGRAM={ninja}",
                    f"-DHDF5_DIR={hdf5_dir}",
                ]
            )
            default_targets = run(
                [str(cmake), "--build", str(default_build), "--target", "help"]
            ).stdout
            if "hdf5_loader_replay" in default_targets or "hdf5_loader_test_tool" in default_targets:
                fail("default HDF-01 configure unexpectedly includes HDF-03 targets")
            results.ok("default HDF-01 configure keeps every HDF-03 target disabled")

            build = work / "build"
            run(
                [
                    str(cmake),
                    "-S",
                    str(project / "harnesses/hdf5"),
                    "-B",
                    str(build),
                    "-G",
                    "Ninja",
                    "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                    f"-DCMAKE_C_COMPILER={c_compiler}",
                    f"-DCMAKE_CXX_COMPILER={cxx_compiler}",
                    f"-DCMAKE_MAKE_PROGRAM={ninja}",
                    f"-DHDF5_DIR={hdf5_dir}",
                    "-DHDF5_BUILD_FIXTURE_TOOL=ON",
                    "-DHDF5_BUILD_LOADER=ON",
                    "-DHDF5_BUILD_LOADER_TESTS=ON",
                ]
            )
            run(
                [
                    str(cmake),
                    "--build",
                    str(build),
                    "--target",
                    "hdf5_fixture_tool",
                    "hdf5_loader_replay",
                    "hdf5_loader_fuzzer",
                    "hdf5_loader_test_tool",
                ]
            )
            fixture_tool = build / "hdf5_fixture_tool"
            replay = build / "hdf5_loader_replay"
            fuzzer = build / "hdf5_loader_fuzzer"
            test_tool = build / "hdf5_loader_test_tool"
            for label, path in (
                ("fixture tool", fixture_tool),
                ("replay", replay),
                ("engine", fuzzer),
                ("loader test tool", test_tool),
            ):
                require_regular(path, f"built {label}", executable=True)
            validate_loader_linkage(readelf, replay, target)
            validate_loader_linkage(readelf, fuzzer, target)
            results.ok("pinned core/high-level libraries build both wrappers and the HDF-03 test tool")

            fixtures = work / "fixtures"
            run(
                [
                    sys.executable,
                    "-B",
                    str(sources["HDF-02 fixture generator"]),
                    "--build-profile",
                    str(sources["pinned build profile"]),
                    "--fixture-tool",
                    str(fixture_tool),
                    "generate",
                    "--output",
                    str(fixtures),
                ]
            )
            policies = work / "policies"
            policies.mkdir()
            run([str(test_tool), "generate", str(policies)])

            validate_normal_outputs(replay, fixtures)
            results.ok("scalar, empty, contiguous, chunked, group, attribute, shape, dtype, and values are observed")

            rejects = (
                ("missing-dataset.h5", "dataset_lookup"),
                ("truncated-image.h5", "file_image_open"),
                ("invalid-metadata.h5", "object_lookup"),
            )
            for filename, stage in rejects:
                completed = run([str(replay), str(fixtures / filename)], expect=9)
                validate_outcome(completed, classification="target_reject", stage=stage)
            unsupported = (
                ("unsupported-filter.h5", "filter_policy"),
                ("unsupported-dtype.h5", "dtype_policy"),
                ("external-link.h5", "link_policy"),
            )
            for filename, stage in unsupported:
                completed = run([str(replay), str(fixtures / filename)], expect=9)
                validate_outcome(completed, classification="unsupported_feature", stage=stage)
            results.ok("HDF-02 normal 4, reject 3, and unsupported 3 keep distinct stages and exit 0/9")

            aba = run(
                [
                    str(replay),
                    str(fixtures / "scalar-numeric.h5"),
                    str(fixtures / "tensor-chunked.h5"),
                    str(fixtures / "scalar-numeric.h5"),
                ]
            )
            validate_aba(aba.stdout)
            results.ok("same-process A-B-A reproduces A exactly without sticky values or handles")

            large = run([str(replay), str(policies / "large-bounded.h5")])
            if "read_elements=8192" not in large.stdout or "read_bytes=65536" not in large.stdout:
                fail("large dataset was not read through the bounded 64 KiB hyperslab")
            non_divisible = run(
                [str(replay), str(policies / "non-divisible-hyperslab.h5")]
            )
            if (
                "shape=3,5000 elements=15000 read_elements=5000" not in non_divisible.stdout
                or "read_bytes=40000" not in non_divisible.stdout
            ):
                fail(
                    "non-divisible multidimensional dataset did not use a valid bounded hyperslab: "
                    f"{non_divisible.stdout[-2000:]!r}"
                )
            alias_cycle = run(
                [str(replay), str(policies / "object-alias-cycle.h5")]
            )
            if (
                "HDF5_LOAD_OK groups=3 datasets=1 attributes=0 visited_objects=4"
                not in alias_cycle.stdout
                or "HDF5_ACCESS_OK datasets=1" not in alias_cycle.stdout
                or "h5dread_calls=1" not in alias_cycle.stdout
            ):
                fail(
                    "object-token visit set did not collapse hard-link aliases/cycles: "
                    f"{alias_cycle.stdout[-2000:]!r}"
                )
            for filename, stage in (
                ("too-many-datasets.h5", "dataset_count"),
                ("read-budget.h5", "read_budget"),
            ):
                completed = run([str(replay), str(policies / filename)], expect=9)
                validate_outcome(completed, classification="policy_limit", stage=stage)
            rank32 = run([str(replay), str(policies / "rank-32.h5")])
            validate_outcome(rank32, classification="accepted", stage="complete")
            limit_checks = run(
                [
                    str(test_tool),
                    "check-limits",
                    str(fixtures),
                    str(policies),
                ]
            )
            if "HDF5_TEST_LIMITS_OK" not in limit_checks.stdout:
                fail("lowered-limit negative controls did not reach every policy branch")
            oversized = work / "oversized.h5"
            with oversized.open("wb") as stream:
                stream.truncate(32 * 1024 * 1024 + 1)
            oversized_result = run([str(replay), str(oversized)], expect=9)
            validate_outcome(oversized_result, classification="policy_limit", stage="input_size")
            results.ok("object-token visits, 32 MiB, 4096 datasets, rank 32, 1 MiB total read, and divisible/non-divisible bounded hyperslab limits are live")

            for filename, stage in (
                ("object-reference.h5", "dtype_policy"),
                ("external-storage.h5", "storage_policy"),
                ("virtual-dataset.h5", "layout_policy"),
            ):
                completed = run([str(replay), str(policies / filename)], expect=9)
                validate_outcome(completed, classification="unsupported_feature", stage=stage)
            results.ok("reference dtype, external storage, and VDS are unsupported rather than successful")

            missing_input = run([str(replay), str(work / "absent.h5")], expect=10)
            validate_outcome(missing_input, classification="environment_error", stage="input_read")
            results.ok("unreadable input remains an environment error with exit 10")

            read_shim, open_shim, version_shim = build_preload_shims(
                c_compiler, include, work
            )
            read_env = dict(os.environ)
            read_env["LD_PRELOAD"] = str(read_shim)
            failed_read = run(
                [str(replay), str(fixtures / "scalar-numeric.h5")],
                env=read_env,
                expect=9,
            )
            validate_outcome(failed_read, classification="target_reject", stage="dataset_read")
            if "HDF5_DATASET " in failed_read.stdout or "HDF5_ACCESS_OK" in failed_read.stdout:
                fail("failed H5Dread buffer reached the success oracle")
            results.ok("forced H5Dread failure is rejected before its output buffer is consumed")

            version_env = dict(os.environ)
            version_env["LD_PRELOAD"] = str(version_shim)
            wrong_version = run(
                [str(replay), str(fixtures / "scalar-numeric.h5")],
                env=version_env,
                expect=10,
            )
            validate_outcome(
                wrong_version,
                classification="environment_error",
                stage="library_identity",
            )
            results.ok("wrong HDF5 runtime identity remains an environment error with exit 10")

            open_env = dict(os.environ)
            open_env["LD_PRELOAD"] = str(open_shim)
            for path, stage in (
                (fixtures / "external-link.h5", "link_policy"),
                (policies / "external-storage.h5", "storage_policy"),
                (policies / "virtual-dataset.h5", "layout_policy"),
            ):
                completed = run([str(replay), str(path)], env=open_env, expect=9)
                validate_outcome(completed, classification="unsupported_feature", stage=stage)
            results.ok("external link, storage, and VDS are classified before any outside-file open")

            handles = run(
                [str(test_tool), "check-handles", str(fixtures), str(policies)]
            )
            if "HDF5_TEST_HANDLES_OK" not in handles.stdout:
                fail("normal/error/repeated handle-count evidence is absent")
            failed_handles = run(
                [str(test_tool), "check-handles", str(fixtures), str(policies)],
                env=read_env,
            )
            if "HDF5_TEST_HANDLES_OK" not in failed_handles.stdout:
                fail("forced H5Dread failure leaks an HDF5 handle")
            results.ok("normal, reject, unsupported, repeated, and forced-read-failure paths return all handles")

            nm_name = "llvm-nm" if (cxx_compiler.parent / "llvm-nm").is_file() else "nm"
            nm = cxx_compiler.parent / nm_name if nm_name == "llvm-nm" else Path("/usr/bin/nm")
            require_regular(nm, "symbol inspection tool", executable=True)
            symbol = "tool::hdf5_loader::LoadImage("
            for label, path in (("replay", replay), ("engine", fuzzer)):
                symbols = run([str(nm), "-C", str(path)]).stdout
                if symbol not in symbols:
                    fail(f"{label} binary does not carry the common LoadImage symbol")
            results.ok("replay and engine binaries link the same common loader symbol")

            corpus = work / "corpus"
            corpus.mkdir()
            for path in sorted(fixtures.glob("*.h5")):
                (corpus / path.name).write_bytes(path.read_bytes())
            engine = run([str(fuzzer), "-runs=20", str(corpus)])
            combined = engine.stdout + engine.stderr
            if re.search(r"AddressSanitizer|UndefinedBehaviorSanitizer|deadly signal", combined, re.I):
                fail("engine smoke emitted a sanitizer/fault marker")
            results.ok("engine wrapper returns normally for accepted, rejected, and unsupported HDF5 inputs")

            fake_loader, fault_driver, fault_engine = write_fault_probe(project, work)
            run(
                [
                    str(cxx_compiler),
                    "-std=c++17",
                    f"-I{project}",
                    str(sources["engine wrapper"]),
                    str(fake_loader),
                    str(fault_driver),
                    "-o",
                    str(fault_engine),
                ]
            )
            fault = subprocess.run(
                [str(fault_engine)],
                cwd=work,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if fault.returncode != -signal.SIGABRT:
                fail(f"engine wrapper swallowed/remapped SIGABRT (rc={fault.returncode})")
            results.ok("engine wrapper preserves a common-loader fault as the original signal")

            ubsan_loader = work / "ubsan_loader.cc"
            ubsan_loader.write_text(
                """#include "harnesses/hdf5/loader.h"
namespace tool::hdf5_loader {
LoadResult LoadImage(const std::uint8_t*, std::size_t, const Limits&) {
  volatile int zero = 0;
  volatile int value = 1 / zero;
  (void)value;
  return {};
}
}  // namespace tool::hdf5_loader
""",
                encoding="utf-8",
            )
            ubsan_engine = work / "ubsan-engine"
            run(
                [
                    str(cxx_compiler),
                    "-std=c++17",
                    "-fsanitize=undefined",
                    "-fno-sanitize-recover=undefined",
                    f"-I{project}",
                    str(sources["engine wrapper"]),
                    str(ubsan_loader),
                    str(fault_driver),
                    "-o",
                    str(ubsan_engine),
                ]
            )
            ubsan = subprocess.run(
                [str(ubsan_engine)],
                cwd=work,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if ubsan.returncode == 0 or not re.search(
                r"UndefinedBehaviorSanitizer|runtime error:.*division by zero",
                ubsan.stderr,
            ):
                fail(
                    "engine wrapper swallowed/remapped UBSan fault "
                    f"(rc={ubsan.returncode}, stderr={ubsan.stderr[-1000:]!r})"
                )
            results.ok("engine wrapper preserves a UBSan fault and its diagnostic")

    except (ContractError, OSError, UnicodeError, ValueError) as error:
        results.bad(str(error))

    print(f"[{results.prefix}] pass={results.passed} fail={results.failed}")
    return 0 if results.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
