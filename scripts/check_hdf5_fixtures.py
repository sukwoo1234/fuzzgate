#!/usr/bin/env python3
"""Exercise the HDF-02 fixture, manifest, and official-HDF5 API contract."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, NoReturn


class ContractError(RuntimeError):
    """The HDF-02 fixture contract was not met."""


def fail(message: str) -> NoReturn:
    raise ContractError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reference_contract() -> dict[str, Any]:
    return {
        "fixtures": [
            {
                "fixture_id": "scalar-numeric",
                "classification": "normal",
                "expected_api_outcome": "accepted",
                "expected": {
                    "dataset": {
                        "path": "/weights/scalar",
                        "state": "present_nonempty",
                        "dtype": "int64-le",
                        "shape": [],
                        "element_count": 1,
                        "limited_values": [7],
                    },
                    "layout": "contiguous",
                    "attributes": [],
                },
            },
            {
                "fixture_id": "empty-numeric",
                "classification": "normal",
                "expected_api_outcome": "accepted",
                "expected": {
                    "dataset": {
                        "path": "/weights/empty",
                        "state": "present_empty",
                        "dtype": "float32-le",
                        "shape": [0, 3],
                        "element_count": 0,
                        "limited_values": [],
                    },
                    "layout": "contiguous",
                    "attributes": [],
                },
            },
            {
                "fixture_id": "tensor-contiguous",
                "classification": "normal",
                "expected_api_outcome": "accepted",
                "expected": {
                    "dataset": {
                        "path": "/weights/kernel",
                        "state": "present_nonempty",
                        "dtype": "float32-le",
                        "shape": [2, 3],
                        "element_count": 6,
                        "limited_values": [1.25, -2.0, 3.5, 4.25, -5.75, 6.0],
                    },
                    "layout": "contiguous",
                    "attributes": [
                        {"object": "/weights", "name": "fixture_version", "value": 1},
                        {"object": "/weights/kernel", "name": "axis_count", "value": 2},
                    ],
                },
            },
            {
                "fixture_id": "missing-dataset",
                "classification": "reject",
                "expected_api_outcome": "absent",
                "expected": {
                    "dataset": {
                        "path": "/weights/missing",
                        "state": "absent",
                        "dtype": None,
                        "shape": None,
                        "element_count": None,
                        "limited_values": None,
                    },
                    "layout": None,
                    "attributes": [],
                },
            },
        ]
    }


def validate_manifest_contract(actual: dict[str, Any], expected: dict[str, Any]) -> None:
    if actual != expected:
        actual_rows = actual.get("fixtures")
        expected_rows = expected.get("fixtures")
        if isinstance(actual_rows, list) and isinstance(expected_rows, list):
            for index, expected_row in enumerate(expected_rows):
                fixture_id = expected_row.get("fixture_id", f"position-{index}")
                if index >= len(actual_rows) or actual_rows[index] != expected_row:
                    fail(f"manifest contract mismatch for {fixture_id}")
        fail("manifest contract differs")
    fixtures = actual.get("fixtures")
    if not isinstance(fixtures, list):
        fail("manifest fixtures must be a list")
    rows = {
        row.get("fixture_id"): row
        for row in fixtures
        if isinstance(row, dict) and isinstance(row.get("fixture_id"), str)
    }
    empty = rows.get("empty-numeric")
    missing = rows.get("missing-dataset")
    if not isinstance(empty, dict) or not isinstance(missing, dict):
        fail("empty and missing fixture rows are both required")
    empty_dataset = empty.get("expected", {}).get("dataset")
    missing_dataset = missing.get("expected", {}).get("dataset")
    if (
        empty.get("classification") != "normal"
        or not isinstance(empty_dataset, dict)
        or empty_dataset.get("state") != "present_empty"
        or empty_dataset.get("element_count") != 0
        or empty_dataset.get("shape") != [0, 3]
    ):
        fail("empty dataset is not a present normal boundary")
    if (
        missing.get("classification") != "reject"
        or not isinstance(missing_dataset, dict)
        or missing_dataset.get("state") != "absent"
        or missing_dataset.get("element_count") is not None
        or missing_dataset.get("shape") is not None
    ):
        fail("missing dataset is not explicit absence")
    if empty_dataset == missing_dataset:
        fail("empty and missing datasets were normalized to one meaning")


def validate_fixture_identity(root: Path, manifest: dict[str, Any]) -> None:
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list):
        fail("manifest has no fixture identity list")
    for row in fixtures:
        if not isinstance(row, dict):
            fail("fixture identity row is not an object")
        fixture_id = row.get("fixture_id")
        filename = row.get("file")
        if not isinstance(fixture_id, str) or not isinstance(filename, str):
            fail("fixture identity row has invalid names")
        path = root / filename
        try:
            path.lstat()
        except OSError as error:
            fail(f"fixture identity path is unavailable for {fixture_id}: {error}")
        if not path.is_file() or path.is_symlink():
            fail(f"fixture identity path is not a regular file for {fixture_id}")
        if row.get("size_bytes") != path.stat().st_size:
            fail(f"fixture size mismatch for {fixture_id}")
        if row.get("sha256") != sha256_file(path):
            fail(f"fixture SHA-256 mismatch for {fixture_id}")


def validate_markers(output: str, manifest: dict[str, Any]) -> None:
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list):
        fail("manifest has no fixture marker list")
    expected = []
    counts = {"normal": 0, "reject": 0, "unsupported": 0}
    for row in fixtures:
        if not isinstance(row, dict):
            fail("fixture marker row is invalid")
        fixture_id = row.get("fixture_id")
        classification = row.get("classification")
        outcome = row.get("expected_api_outcome")
        if (
            not isinstance(fixture_id, str)
            or classification not in counts
            or not isinstance(outcome, str)
        ):
            fail("fixture marker fields are invalid")
        counts[classification] += 1
        expected.append(
            f"HDF5_FIXTURE id={fixture_id} class={classification} outcome={outcome}"
        )
    expected.append(
        "HDF5_FIXTURE_SET_OK "
        f"normal={counts['normal']} reject={counts['reject']} unsupported={counts['unsupported']}"
    )
    actual = output.strip().splitlines()
    if actual != expected:
        fail("official HDF5 API outcome markers differ from the manifest")


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def expect_rejected(self, label: str, action: Callable[[], None]) -> None:
        try:
            action()
        except ContractError as error:
            self.passed += 1
            print(f"[hdf5-fixtures-selftest] PASS {label}: {error}")
            return
        self.failed += 1
        print(f"[hdf5-fixtures-selftest] RED {label}: invalid input was accepted")

    def ok(self, message: str) -> None:
        self.passed += 1
        print(f"[hdf5-fixtures] ok: {message}")

    def bad(self, message: str) -> None:
        self.failed += 1
        print(f"[hdf5-fixtures] fail: {message}", file=sys.stderr)


def run_selftest() -> int:
    results = Results()
    expected = reference_contract()
    generator = import_generator(Path(__file__).with_name("gen_hdf5_fixtures.py"))

    merged = copy.deepcopy(expected)
    rows = {row["fixture_id"]: row for row in merged["fixtures"]}
    rows["missing-dataset"]["expected"]["dataset"] = copy.deepcopy(
        rows["empty-numeric"]["expected"]["dataset"]
    )
    results.expect_rejected(
        "empty-missing-merged",
        lambda: validate_manifest_contract(merged, expected),
    )

    for field, replacement in (
        ("dtype", "float64-le"),
        ("shape", [6]),
        ("limited_values", [0.0] * 6),
    ):
        tampered = copy.deepcopy(expected)
        tampered["fixtures"][2]["expected"]["dataset"][field] = replacement
        results.expect_rejected(
            f"manifest-{field}-tamper",
            lambda tampered=tampered: validate_manifest_contract(tampered, expected),
        )
    for field, replacement in (("layout", "chunked"), ("attributes", [])):
        tampered = copy.deepcopy(expected)
        tampered["fixtures"][2]["expected"][field] = replacement
        results.expect_rejected(
            f"manifest-{field}-tamper",
            lambda tampered=tampered: validate_manifest_contract(tampered, expected),
        )

    with tempfile.TemporaryDirectory(prefix="hdf5-fixture-red-") as directory:
        root = Path(directory)
        data = b"fixture-bytes"
        (root / "scalar-numeric.h5").write_bytes(data + b"-tampered")
        identity_manifest = {
            "fixtures": [
                {
                    "fixture_id": "scalar-numeric",
                    "file": "scalar-numeric.h5",
                    "sha256": sha256_bytes(data),
                    "size_bytes": len(data),
                }
            ]
        }
        results.expect_rejected(
            "fixture-byte-tamper",
            lambda: validate_fixture_identity(root, identity_manifest),
        )

    fake_lines = "\n".join(
        [
            "HDF5_FIXTURE id=scalar-numeric class=normal outcome=rejected",
            "HDF5_FIXTURE id=empty-numeric class=normal outcome=rejected",
            "HDF5_FIXTURE id=tensor-contiguous class=normal outcome=rejected",
            "HDF5_FIXTURE id=missing-dataset class=reject outcome=accepted",
            "HDF5_FIXTURE_SET_OK normal=3 reject=1 unsupported=0",
        ]
    )
    results.expect_rejected(
        "normal-reject-and-reject-accept",
        lambda: validate_markers(fake_lines, expected),
    )

    with tempfile.TemporaryDirectory(prefix="hdf5-profile-locality-red-") as directory:
        profile_root = Path(directory) / "copy-target"
        profile_root.mkdir()
        escaped_profile = {
            "components": {
                "core": {"path": str(Path(directory) / "source-target/libhdf5.so")},
                "high_level": {
                    "path": str(Path(directory) / "source-target/libhdf5_hl.so")
                },
            }
        }

        def reject_escaped_profile() -> None:
            try:
                generator.validate_component_paths(escaped_profile, profile_root)
            except generator.FixtureError as error:
                fail(str(error))

        results.expect_rejected(
            "profile-component-path-escape",
            reject_escaped_profile,
        )

    print(f"[hdf5-fixtures-selftest] pass={results.passed} fail={results.failed}")
    return 0 if results.failed == 0 else 1


def load_unique_json(path: Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                fail(f"duplicate JSON key {key!r} in {path}")
            value[key] = item
        return value

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def import_generator(path: Path) -> Any:
    specification = importlib.util.spec_from_file_location("gen_hdf5_fixtures", path)
    if specification is None or specification.loader is None:
        fail(f"cannot import HDF-02 generator: {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
    expect: int = 0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != expect:
        fail(
            f"command returned {completed.returncode}, expected {expect}: {command!r}\n"
            f"stdout={completed.stdout[-3000:]!r}\nstderr={completed.stderr[-3000:]!r}"
        )
    return completed


def expect_command_rejected(
    command: list[str],
    *,
    contains: str,
    environment: dict[str, str] | None = None,
) -> None:
    completed = subprocess.run(
        command,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode == 0:
        fail(f"negative command unexpectedly succeeded: {command!r}")
    if contains not in completed.stderr:
        fail(
            f"negative command failed for the wrong reason: {command!r}: "
            f"stderr={completed.stderr[-2000:]!r}"
        )


def tree_snapshot(root: Path) -> list[tuple[str, int, str]]:
    return [
        (str(path.relative_to(root)), path.stat().st_size, sha256_file(path))
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    ]


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generator_command(
    generator: Path, profile: Path, tool: Path, command: str, output: Path
) -> list[str]:
    return [
        sys.executable,
        "-B",
        str(generator),
        "--build-profile",
        str(profile),
        "--fixture-tool",
        str(tool),
        command,
        "--output",
        str(output),
    ]


def mutate_manifest_copy(
    source: Path,
    destination: Path,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    shutil.copytree(source, destination)
    manifest_path = destination / "manifest.json"
    manifest = load_unique_json(manifest_path)
    mutation(manifest)
    write_json(manifest_path, manifest)


def validate_tool_linkage(readelf: Path, tool: Path) -> None:
    dynamic = run([str(readelf), "-d", str(tool)]).stdout
    needed = re.findall(r"Shared library: \[([^]]+)\]", dynamic)
    if not any(name.startswith("libhdf5.so") for name in needed):
        fail("fixture tool has no dynamic dependency on HDF5 core")
    if not any(name.startswith("libhdf5_hl.so") for name in needed):
        fail("fixture tool has no dynamic dependency on HDF5 high-level")
    symbols = run(
        [
            str(readelf),
            "--elf-output-style=GNU",
            "--dyn-symbols",
            "--wide",
            str(tool),
        ]
    ).stdout
    for symbol in ("H5LTopen_file_image", "H5Dcreate2", "H5Dread", "H5Dread_chunk2"):
        if symbol not in symbols:
            fail(f"fixture tool does not call required HDF5 API: {symbol}")


def run_gate(project: Path, target: Path) -> int:
    generator_path = project / "scripts/gen_hdf5_fixtures.py"
    profile_checker = project / "scripts/check_hdf5_profile.py"
    fixture_source = project / "harnesses/hdf5/fixture_tool.cc"
    cmake_source = project / "harnesses/hdf5"
    profile_path = target / "build-profile.json"
    results = Results()

    required = {
        "HDF-02 generator": generator_path,
        "HDF-02 fixture source": fixture_source,
        "HDF-01 profile checker": profile_checker,
        "HDF-01 build profile": profile_path,
    }
    for label, path in required.items():
        if not path.is_file() or path.is_symlink():
            results.bad(f"{label} is missing or not a regular file: {path}")
    if results.failed:
        print(f"[hdf5-fixtures] pass={results.passed} fail={results.failed}")
        return 1

    try:
        generator = import_generator(generator_path)
        run([sys.executable, "-B", str(profile_checker), "--target-root", str(target)])
        profile = generator.validate_build_profile(profile_path)
        results.ok("pinned HDF-01 core/high-level build profile is valid")

        toolchain = profile.get("toolchain")
        if not isinstance(toolchain, dict):
            fail("build profile has no toolchain object")
        cmake = Path(str(toolchain.get("cmake", {}).get("path", "")))
        ninja = Path(str(toolchain.get("ninja", {}).get("path", "")))
        compiler = Path(str(toolchain.get("cxx_compiler", {}).get("path", "")))
        compiler_driver = compiler.parent / "clang++"
        if not compiler_driver.is_file():
            compiler_driver = compiler
        if compiler_driver.resolve() != compiler.resolve():
            fail(
                "C++ compiler driver does not resolve to the pinned HDF-01 compiler: "
                f"driver={compiler_driver} pinned={compiler}"
            )
        readelf = Path(str(toolchain.get("readelf", {}).get("path", "")))
        hdf5_dir = target / "install/lib/cmake/hdf5"
        for label, path in (
            ("cmake", cmake),
            ("ninja", ninja),
            ("C++ compiler", compiler_driver),
            ("readelf", readelf),
        ):
            if not path.is_file() or not os.access(path, os.X_OK):
                fail(f"pinned {label} is unavailable or non-executable: {path}")
        if not (hdf5_dir / "hdf5-config.cmake").is_file():
            fail(f"pinned HDF5 CMake package is unavailable: {hdf5_dir}")

        with tempfile.TemporaryDirectory(prefix="hdf5-fixtures-check-") as directory:
            work = Path(directory)
            configure_base = [
                str(cmake),
                "-S",
                str(cmake_source),
                "-G",
                "Ninja",
                "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                f"-DCMAKE_CXX_COMPILER={compiler_driver}",
                f"-DCMAKE_MAKE_PROGRAM={ninja}",
                "-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld",
                f"-DHDF5_DIR={hdf5_dir}",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            ]
            profile_build = work / "profile-build"
            run([*configure_base, "-B", str(profile_build)])
            profile_commands = json.loads(
                (profile_build / "compile_commands.json").read_text(encoding="utf-8")
            )
            profile_sources = [
                Path(str(row.get("file", ""))).name
                for row in profile_commands
                if isinstance(row, dict)
            ]
            if profile_sources != ["profile_probe.cc"]:
                fail(
                    "default HDF-01 configure leaked HDF-02 translation units: "
                    f"{profile_sources!r}"
                )
            results.ok("default HDF-01 configure excludes the HDF-02 fixture tool")

            fixture_build = work / "fixture-build"
            run(
                [
                    *configure_base,
                    "-B",
                    str(fixture_build),
                    "-DHDF5_BUILD_FIXTURE_TOOL=ON",
                    "-DHDF5_BUILD_FIXTURE_TEST_MUTANTS=ON",
                ]
            )
            run(
                [
                    str(cmake),
                    "--build",
                    str(fixture_build),
                    "--target",
                    "hdf5_fixture_tool",
                    "hdf5_fixture_chunk_mutant",
                    "hdf5_fixture_attribute_mutant",
                ]
            )
            fixture_tool = fixture_build / "hdf5_fixture_tool"
            if not fixture_tool.is_file() or not os.access(fixture_tool, os.X_OK):
                fail("HDF-02 fixture tool build produced no executable")
            validate_tool_linkage(readelf, fixture_tool)
            results.ok("fixture tool links and calls pinned HDF5 core plus high-level APIs")

            output_a = work / "fixtures-a"
            output_b = work / "fixtures-b"
            run(generator_command(generator_path, profile_path, fixture_tool, "generate", output_a))
            time.sleep(2)
            run(generator_command(generator_path, profile_path, fixture_tool, "generate", output_b))
            if tree_snapshot(output_a) != tree_snapshot(output_b):
                fail("two time-separated fixture generations differ")
            results.ok("two time-separated generations are byte-for-byte deterministic")

            run(generator_command(generator_path, profile_path, fixture_tool, "verify", output_a))
            manifest = load_unique_json(output_a / "manifest.json")
            expected_manifest = generator.build_manifest(output_a, profile_path)
            validate_manifest_contract(manifest, expected_manifest)
            validate_fixture_identity(output_a, manifest)
            results.ok("manifest fixes every fixture SHA, structure, value, and classification")

            extra_entry = output_a / "unexpected-entry"
            extra_entry.symlink_to("manifest.json")
            completed = subprocess.run(
                generator_command(
                    generator_path, profile_path, fixture_tool, "verify", output_a
                ),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if (
                completed.returncode == 0
                or "fixture output file set mismatch" not in completed.stderr
            ):
                fail(
                    "fixture verifier accepted an unexpected directory entry: "
                    f"rc={completed.returncode} stderr={completed.stderr[-2000:]!r}"
                )
            extra_entry.unlink()
            contaminated_environment = dict(os.environ)
            contaminated_environment["HDF5_VOL_CONNECTOR"] = (
                "definitely_not_a_connector"
            )
            run(
                generator_command(
                    generator_path, profile_path, fixture_tool, "verify", output_a
                ),
                environment=contaminated_environment,
            )
            results.ok("extra entries fail and inherited HDF5 environment cannot alter verification")

            tool_result = run(
                [str(fixture_tool), "verify", str(output_a)],
                environment=generator.tool_environment(profile),
            )
            validate_markers(tool_result.stdout, manifest)
            results.ok("official HDF5 APIs verify all normal, reject, and unsupported fixtures")

            for executable_name, fixture_id, reason in (
                (
                    "hdf5_fixture_chunk_mutant",
                    "tensor-chunked",
                    "dataset chunk shape differs",
                ),
                (
                    "hdf5_fixture_attribute_mutant",
                    "tensor-contiguous",
                    "attribute value differs",
                ),
            ):
                mutant_output = work / executable_name
                mutant_output.mkdir()
                mutant_tool = fixture_build / executable_name
                run(
                    [str(mutant_tool), "generate", str(mutant_output)],
                    environment=generator.tool_environment(profile),
                )
                completed = subprocess.run(
                    [str(fixture_tool), "verify", str(mutant_output)],
                    env=generator.tool_environment(profile),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if (
                    completed.returncode == 0
                    or f"id={fixture_id}" not in completed.stderr
                    or reason not in completed.stderr
                ):
                    fail(
                        f"canonical verifier accepted {executable_name}: "
                        f"rc={completed.returncode} stderr={completed.stderr[-2000:]!r}"
                    )
            results.ok("chunk-shape and attribute-dtype API mutants are rejected")

            rows = {row["fixture_id"]: row for row in manifest["fixtures"]}
            empty_dataset = rows["empty-numeric"]["expected"]["dataset"]
            missing_dataset = rows["missing-dataset"]["expected"]["dataset"]
            if empty_dataset["state"] != "present_empty" or missing_dataset["state"] != "absent":
                fail("empty and missing dataset meanings collapsed")
            results.ok("empty dataset presence remains distinct from missing dataset absence")

            manifest_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
                (
                    "dtype",
                    lambda value: value["fixtures"][2]["expected"]["dataset"].__setitem__(
                        "dtype", "float64-le"
                    ),
                ),
                (
                    "shape",
                    lambda value: value["fixtures"][2]["expected"]["dataset"].__setitem__(
                        "shape", [6]
                    ),
                ),
                (
                    "value",
                    lambda value: value["fixtures"][2]["expected"]["dataset"].__setitem__(
                        "limited_values", [0.0] * 6
                    ),
                ),
                (
                    "layout",
                    lambda value: value["fixtures"][2]["expected"]["layout"].__setitem__(
                        "class", "chunked"
                    ),
                ),
                (
                    "attribute",
                    lambda value: value["fixtures"][2]["expected"].__setitem__(
                        "attributes", []
                    ),
                ),
            ]
            for label, mutation in manifest_mutations:
                mutated = work / f"manifest-{label}"
                mutate_manifest_copy(output_a, mutated, mutation)
                expect_command_rejected(
                    generator_command(
                        generator_path, profile_path, fixture_tool, "verify", mutated
                    ),
                    contains="fixture manifest mismatch",
                )
            results.ok("dtype, shape, value, layout, and attribute manifest tampering is rejected")

            merged = work / "empty-missing-merged"
            def merge_empty_missing(value: dict[str, Any]) -> None:
                manifest_rows = {row["fixture_id"]: row for row in value["fixtures"]}
                manifest_rows["missing-dataset"]["expected"]["dataset"] = copy.deepcopy(
                    manifest_rows["empty-numeric"]["expected"]["dataset"]
                )

            mutate_manifest_copy(output_a, merged, merge_empty_missing)
            expect_command_rejected(
                generator_command(generator_path, profile_path, fixture_tool, "verify", merged),
                contains="fixture manifest mismatch",
            )
            results.ok("manifest cannot normalize empty dataset into missing dataset")

            byte_tamper = work / "byte-tamper"
            shutil.copytree(output_a, byte_tamper)
            with (byte_tamper / "scalar-numeric.h5").open("ab") as stream:
                stream.write(b"\x00")
            expect_command_rejected(
                generator_command(
                    generator_path, profile_path, fixture_tool, "verify", byte_tamper
                ),
                contains="fixture manifest mismatch",
            )
            results.ok("fixture byte tampering is rejected by SHA-256 identity")

            structure_tamper = work / "structure-tamper"
            shutil.copytree(output_a, structure_tamper)
            replacement = structure_tamper / "empty-numeric.h5"
            shutil.copyfile(structure_tamper / "missing-dataset.h5", replacement)
            structure_manifest_path = structure_tamper / "manifest.json"
            structure_manifest = load_unique_json(structure_manifest_path)
            structure_rows = {
                row["fixture_id"]: row for row in structure_manifest["fixtures"]
            }
            structure_rows["empty-numeric"]["sha256"] = sha256_file(replacement)
            structure_rows["empty-numeric"]["size_bytes"] = replacement.stat().st_size
            write_json(structure_manifest_path, structure_manifest)
            expect_command_rejected(
                generator_command(
                    generator_path, profile_path, fixture_tool, "verify", structure_tamper
                ),
                contains="fixture tool verify failed",
            )
            results.ok("official HDF5 structure checks reject empty-to-missing substitution")

            bad_markers = "\n".join(
                [
                    f"HDF5_FIXTURE id={row['fixture_id']} class={row['classification']} "
                    f"outcome={'rejected' if row['classification'] == 'normal' else 'accepted'}"
                    for row in manifest["fixtures"]
                ]
                + ["HDF5_FIXTURE_SET_OK normal=4 reject=3 unsupported=3"]
            )
            try:
                validate_markers(bad_markers, manifest)
            except ContractError:
                pass
            else:
                fail("classification gate accepted all-normal-reject/all-reject-accept output")
            results.ok("classification gate rejects all-normal-reject and reject-as-accept output")

            unsupported_filter = rows["unsupported-filter"]["expected"]["layout"]["filters"]
            external = rows["external-link"]["expected"]["external_reference"]
            if (
                unsupported_filter[0]["id"] != 32024
                or unsupported_filter[0]["stored_chunk_filter_mask"] != 0
                or unsupported_filter[0]["stored_chunk_encoding"]
                != "little-endian-int32"
                or unsupported_filter[0]["stored_chunk_values"] != [10, 20, 30, 40]
                or external["kind"] != "external_link"
                or external["outside_access_required"] is not True
            ):
                fail("unsupported filter or external reference evidence is incomplete")
            results.ok("unsupported filter and outside-file external link are explicit API facts")

    except (ContractError, RuntimeError, OSError, UnicodeError, ValueError) as error:
        results.bad(str(error))

    print(f"[hdf5-fixtures] pass={results.passed} fail={results.failed}")
    return 0 if results.failed == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--target-root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.selftest:
        return run_selftest()
    if args.project_root is None or args.target_root is None:
        print("[hdf5-fixtures] fail: --project-root and --target-root are required", file=sys.stderr)
        return 64
    return run_gate(args.project_root.resolve(), args.target_root.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
