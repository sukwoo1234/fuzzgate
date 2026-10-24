#!/usr/bin/env python3
"""Exercise the OVI-02 deterministic pair-fixture and pinned-frontend contract."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, NoReturn


EXPECTED_FIXTURES = [
    "constant-one.fzb",
    "constant-two.fzb",
    "empty-weights.fzb",
    "missing-bin.fzb",
    "truncated-weights.fzb",
    "malformed-xml.fzb",
]


class ContractError(RuntimeError):
    """The OVI-02 fixture contract was not met."""


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def ok(self, message: str) -> None:
        self.passed += 1
        print(f"[openvino-fixtures] ok: {message}")

    def bad(self, message: str) -> None:
        self.failed += 1
        print(f"[openvino-fixtures] fail: {message}", file=sys.stderr)


def fail(message: str) -> NoReturn:
    raise ContractError(message)


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    expect: int = 0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != expect:
        fail(
            f"command returned {completed.returncode}, expected {expect}: {command!r}\n"
            f"stdout={completed.stdout[-2000:]!r}\nstderr={completed.stderr[-2000:]!r}"
        )
    return completed


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_unique_json(path: Path) -> dict[str, Any]:
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
        fail(f"cannot read unique JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def import_bundle_codec(path: Path) -> Any:
    specification = importlib.util.spec_from_file_location("model_bundle", path)
    if specification is None or specification.loader is None:
        fail(f"cannot import FZB1 codec: {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def tree_snapshot(root: Path) -> list[tuple[str, int, str]]:
    return [
        (str(path.relative_to(root)), path.stat().st_size, sha256(path))
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    ]


def fixture_entries(codec: Any, path: Path) -> dict[str, bytes]:
    return dict(codec.decode_bundle(path.read_bytes()))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project = args.project_root.resolve()
    target = args.target_root.resolve()
    generator = project / "scripts/gen_openvino_fixtures.py"
    generator_check = project / "scripts/check_openvino_profile.py"
    probe_source = project / "harnesses/openvino/fixture_probe.cc"
    bundle_codec_path = project / "scripts/model_bundle.py"
    cmake_source = project / "harnesses/openvino"
    profile_path = target / "build-profile.json"
    results = Results()

    required = {
        "OVI-02 generator": generator,
        "OVI-02 fixture probe source": probe_source,
        "FZB1 codec": bundle_codec_path,
        "OVI-01 profile checker": generator_check,
        "pinned build profile": profile_path,
    }
    missing = False
    for label, path in required.items():
        if not path.is_file() or path.is_symlink():
            results.bad(f"{label} is missing or not a regular file: {path}")
            missing = True
    if missing:
        print(f"[openvino-fixtures] pass={results.passed} fail={results.failed}")
        return 1

    try:
        run([sys.executable, "-B", str(generator_check), "--target-root", str(target)])
        results.ok("pinned OVI-01 Core+IR frontend profile is valid")

        profile = load_unique_json(profile_path)
        toolchain = profile.get("toolchain")
        if not isinstance(toolchain, dict):
            fail("build profile has no toolchain object")
        cmake_row = toolchain.get("cmake")
        compiler_row = toolchain.get("compiler")
        if not isinstance(cmake_row, dict) or not isinstance(compiler_row, dict):
            fail("build profile has incomplete cmake/compiler identity")
        cmake = Path(str(cmake_row.get("path")))
        clang = Path(str(compiler_row.get("path")))
        clangxx = clang.with_name("clang++")
        ninja = Path(str(toolchain.get("ninja", {}).get("path")))
        for label, path in (("cmake", cmake), ("clang++", clangxx), ("ninja", ninja)):
            if not path.is_file() or not os.access(path, os.X_OK):
                fail(f"pinned {label} is unavailable or non-executable: {path}")

        codec = import_bundle_codec(bundle_codec_path)
        with tempfile.TemporaryDirectory(prefix="openvino-fixtures-check-") as temporary:
            work = Path(temporary)
            profile_probe_build = work / "profile-probe-build"
            run(
                [
                    str(cmake),
                    "-S",
                    str(cmake_source),
                    "-B",
                    str(profile_probe_build),
                    "-G",
                    "Ninja",
                    "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                    f"-DCMAKE_CXX_COMPILER={clangxx}",
                    f"-DCMAKE_MAKE_PROGRAM={ninja}",
                    f"-DOpenVINO_DIR={target / 'install/runtime/cmake'}",
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                ]
            )
            profile_commands = json.loads(
                (profile_probe_build / "compile_commands.json").read_text(encoding="utf-8")
            )
            if not isinstance(profile_commands, list):
                fail("profile-only compile_commands.json is not a list")
            profile_sources = [
                Path(str(row.get("file", ""))).name
                for row in profile_commands
                if isinstance(row, dict)
            ]
            if profile_sources != ["profile_probe.cc"]:
                fail(
                    "clean OVI-01 profile configure leaked other translation units: "
                    f"{profile_sources!r}"
                )
            results.ok("clean OVI-01 profile configure excludes the OVI-02 fixture probe")

            probe_build = work / "probe-build"
            run(
                [
                    str(cmake),
                    "-S",
                    str(cmake_source),
                    "-B",
                    str(probe_build),
                    "-G",
                    "Ninja",
                    "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                    f"-DCMAKE_CXX_COMPILER={clangxx}",
                    f"-DCMAKE_MAKE_PROGRAM={ninja}",
                    f"-DOpenVINO_DIR={target / 'install/runtime/cmake'}",
                    "-DOPENVINO_BUILD_FIXTURE_PROBE=ON",
                ]
            )
            run([str(cmake), "--build", str(probe_build), "--target", "openvino_ir_fixture_probe"])
            probe = probe_build / "openvino_ir_fixture_probe"
            if not probe.is_file() or not os.access(probe, os.X_OK):
                fail("fixture probe build produced no executable")
            results.ok("OVI-02 fixture probe builds against the pinned IR frontend")

            output_a = work / "fixtures-a"
            output_b = work / "fixtures-b"
            generate_base = [
                sys.executable,
                "-B",
                str(generator),
                "--build-profile",
                str(profile_path),
            ]
            run([*generate_base, "generate", "--output", str(output_a)])
            run([*generate_base, "generate", "--output", str(output_b)])
            run([*generate_base, "verify", "--output", str(output_a)])
            if tree_snapshot(output_a) != tree_snapshot(output_b):
                fail("two clean fixture generations differ")
            results.ok("two clean generations are byte-for-byte deterministic")

            index = load_unique_json(output_a / "index.json")
            fixtures = index.get("fixtures")
            if not isinstance(fixtures, list):
                fail("fixture index has no fixtures list")
            if [row.get("name") for row in fixtures if isinstance(row, dict)] != EXPECTED_FIXTURES:
                fail("fixture index names/order differ from the OVI-02 contract")
            rows = {str(row["name"]): row for row in fixtures if isinstance(row, dict)}
            results.ok("fixture index fixes generator, hash, license, pair, and outcome metadata")

            decoded = {
                name: fixture_entries(codec, output_a / name) for name in EXPECTED_FIXTURES
            }
            empty_entries = decoded["empty-weights.fzb"]
            if set(empty_entries) != {"model.bin", "model.xml"} or empty_entries["model.bin"] != b"":
                fail("empty model.bin entry was lost or confused with a missing entry")
            missing_entries = decoded["missing-bin.fzb"]
            if set(missing_entries) != {"model.xml"}:
                fail("missing-bin negative fixture does not actually omit model.bin")
            results.ok("empty model.bin remains present and distinct from missing model.bin")

            def probe_fixture(name: str, expected: int, cwd: Path | None = None) -> str:
                completed = run([str(probe), str(output_a / name)], cwd=cwd, expect=expected)
                return completed.stdout.strip()

            constant_one = probe_fixture("constant-one.fzb", 0)
            constant_two = probe_fixture("constant-two.fzb", 0)
            empty_result = probe_fixture("empty-weights.fzb", 0)
            for name, actual in (
                ("constant-one.fzb", constant_one),
                ("constant-two.fzb", constant_two),
                ("empty-weights.fzb", empty_result),
            ):
                if actual != rows[name].get("expected_marker"):
                    fail(f"{name} did not match its pinned frontend oracle: {actual!r}")
            results.ok("pinned IR frontend accepts every normal pair and matches its oracle")

            first = decoded["constant-one.fzb"]
            second = decoded["constant-two.fzb"]
            if first["model.xml"] != second["model.xml"]:
                fail("constant pair XML bytes differ")
            if first["model.bin"] == second["model.bin"] or constant_one == constant_two:
                fail("same-XML fixtures did not expose distinct BIN constant values")
            results.ok("same XML with different BIN bytes produces distinct Constant observations")

            decoy_dir = work / "decoy"
            decoy_dir.mkdir()
            missing_bundle = decoy_dir / "missing-bin.fzb"
            shutil.copyfile(output_a / "missing-bin.fzb", missing_bundle)
            (decoy_dir / "model.bin").write_bytes(first["model.bin"])
            cwd_dir = work / "cwd"
            cwd_dir.mkdir()
            (cwd_dir / "model.bin").write_bytes(second["model.bin"])
            missing = run([str(probe), str(missing_bundle)], cwd=cwd_dir, expect=9)
            if "FZB1 entries do not match target allowlist" not in missing.stderr:
                fail("missing model.bin rejection did not come from the exact FZB1 allowlist")
            results.ok("missing model.bin is rejected despite adjacent and CWD decoys")

            for name in ("truncated-weights.fzb", "malformed-xml.fzb"):
                completed = run([str(probe), str(output_a / name)], expect=9)
                if "OPENVINO_FIXTURE_REJECTED" not in completed.stderr:
                    fail(f"{name} did not produce a pinned frontend rejection marker")
            results.ok("pinned IR frontend rejects malformed XML/BIN pairs")

            empty_lost = work / "empty-entry-lost.fzb"
            empty_lost.write_bytes(codec.encode_bundle([("model.xml", empty_entries["model.xml"])]))
            lost = run([str(probe), str(empty_lost)], expect=9)
            if "FZB1 entries do not match target allowlist" not in lost.stderr:
                fail("empty-entry-loss mutation was not rejected by the exact allowlist")
            results.ok("empty BIN entry loss is detected rather than normalized to missing")

            malformed_index = work / "malformed-index"
            shutil.copytree(output_a, malformed_index)
            index_path = malformed_index / "index.json"
            text = index_path.read_text(encoding="utf-8")
            index_path.write_text('{"schema_version":"duplicate",' + text[1:], encoding="utf-8")
            malformed = run(
                [*generate_base, "verify", "--output", str(malformed_index)], expect=1
            )
            if "duplicate JSON key" not in malformed.stderr:
                fail("malformed duplicate-key index failed for an unrelated reason")
            results.ok("malformed fixture index is rejected with a specific reason")

            no_op_dir = work / "no-op"
            shutil.copytree(output_a, no_op_dir)
            shutil.copyfile(no_op_dir / "constant-one.fzb", no_op_dir / "constant-two.fzb")
            no_op_probe = run([str(probe), str(no_op_dir / "constant-two.fzb")]).stdout.strip()
            if no_op_probe != constant_one or no_op_probe == rows["constant-two.fzb"].get("expected_marker"):
                fail("no-op mutation did not collapse the second Constant observation as expected")
            no_op = run([*generate_base, "verify", "--output", str(no_op_dir)], expect=1)
            if "constant-two.fzb" not in no_op.stderr:
                fail("no-op fixture mutation failed without naming the changed fixture")
            results.ok("no-op fixture generation is detected by bytes and native oracle")

            nondeterministic = work / "nondeterministic"
            shutil.copytree(output_a, nondeterministic)
            with (nondeterministic / "constant-one.fzb").open("ab") as stream:
                stream.write(b"\x00")
            if tree_snapshot(output_a) == tree_snapshot(nondeterministic):
                fail("tree comparison did not detect a nondeterministic byte")
            results.ok("nondeterministic generated bytes are detected")

    except (ContractError, OSError, ValueError) as error:
        results.bad(str(error))

    print(f"[openvino-fixtures] pass={results.passed} fail={results.failed}")
    return 0 if results.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
