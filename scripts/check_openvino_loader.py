#!/usr/bin/env python3
"""Verify the OVI-03 shared loader, oracle, and same-process lifetime contract."""

from __future__ import annotations

import argparse
import hashlib
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
    """The OVI-03 loader contract was not met."""


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def ok(self, message: str) -> None:
        self.passed += 1
        print(f"[openvino-loader] ok: {message}")

    def bad(self, message: str) -> None:
        self.failed += 1
        print(f"[openvino-loader] fail: {message}", file=sys.stderr)


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
            f"stdout={completed.stdout[-3000:]!r}\nstderr={completed.stderr[-3000:]!r}"
        )
    return completed


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


def require_regular(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is missing or not a regular file: {path}")


def validate_source_contract(loader: str, replay: str, fuzzer: str) -> None:
    required_loader = (
        "DecodeWithAllowlist",
        "core.read_model(model_text, weights)",
        "validate_nodes_and_infer_types",
        "get_ordered_ops",
        "get_input_partial_shape",
        "get_output_partial_shape",
        "get_data_ptr",
        "catch (const ov::Exception&",
    )
    for marker in required_loader:
        if marker not in loader:
            fail(f"common loader omits required operation: {marker}")
    forbidden_loader = (
        "read_model(model_text, ov::Tensor{})",
        "compile_model(",
        "catch (const std::exception&",
        "catch (...)",
    )
    for marker in forbidden_loader:
        if marker in loader:
            fail(f"common loader contains forbidden bypass/catch: {marker}")
    if re.search(r"static\s+(?:std::vector|ov::Tensor|std::shared_ptr)", loader):
        fail("common loader retains model or weights in static state")

    for label, wrapper in (("replay", replay), ("engine", fuzzer)):
        if wrapper.count("tool::openvino_loader::LoadBundle(") != 1:
            fail(f"{label} wrapper does not call the single common loader exactly once")
        for marker in ("<openvino/", "DecodeWithAllowlist", "read_model(", "get_data_ptr"):
            if marker in wrapper:
                fail(f"{label} wrapper contains a separate loader operation: {marker}")


def case_groups(output: str) -> list[list[str]]:
    groups: list[list[str]] = []
    current: list[str] | None = None
    for line in output.splitlines():
        if line.startswith("OPENVINO_CASE_BEGIN ordinal="):
            if current is not None:
                fail("nested OpenVINO case marker")
            current = []
        elif line.startswith("OPENVINO_CASE_END ordinal="):
            if current is None:
                fail("orphan OpenVINO case end")
            groups.append(current)
            current = None
        elif current is not None:
            current.append(line)
    if current is not None:
        fail("unterminated OpenVINO case marker")
    return groups


def validate_aba(output: str) -> None:
    groups = case_groups(output)
    if len(groups) != 3:
        fail(f"expected three completed A-B-A cases, observed {len(groups)}")
    if groups[0] != groups[2]:
        fail("A observations differ after B")
    if groups[0] == groups[1]:
        fail("A and B observations are identical; weights or oracle did not change")
    if not any("payload_hex=0000c03f" in line for line in groups[0]):
        fail("A Constant payload evidence is absent")
    if not any("payload_hex=000010c0" in line for line in groups[1]):
        fail("B Constant payload evidence is absent")


def expect_contract_failure(label: str, callback: Any) -> None:
    try:
        callback()
    except ContractError:
        return
    fail(f"negative control was accepted: {label}")


def run_negative_controls() -> None:
    good_loader = """
DecodeWithAllowlist
core.read_model(model_text, weights)
validate_nodes_and_infer_types
get_ordered_ops
get_input_partial_shape
get_output_partial_shape
get_data_ptr
catch (const ov::Exception& exception)
"""
    good_replay = "tool::openvino_loader::LoadBundle(data, size, &summary, &error);"
    good_fuzzer = "tool::openvino_loader::LoadBundle(data, size, &summary, &error);"

    expect_contract_failure(
        "XML-only read_model bypass",
        lambda: validate_source_contract(
            good_loader.replace("core.read_model(model_text, weights)",
                                "read_model(model_text, ov::Tensor{})"),
            good_replay,
            good_fuzzer,
        ),
    )
    expect_contract_failure(
        "Constant payload access omitted",
        lambda: validate_source_contract(
            good_loader.replace("get_data_ptr", "get_byte_size"),
            good_replay,
            good_fuzzer,
        ),
    )
    expect_contract_failure(
        "engine implements a separate loader",
        lambda: validate_source_contract(
            good_loader,
            good_replay,
            good_fuzzer + "\ncore.read_model(model_text, weights);",
        ),
    )
    expect_contract_failure(
        "weights persist between inputs",
        lambda: validate_source_contract(
            good_loader + "\nstatic std::vector<unsigned char> sticky_weights;",
            good_replay,
            good_fuzzer,
        ),
    )

    a = [
        "OPENVINO_LOAD_OK nodes=4",
        "OPENVINO_CONSTANT index=1 payload_hex=0000c03f",
    ]
    b = [
        "OPENVINO_LOAD_OK nodes=4",
        "OPENVINO_CONSTANT index=1 payload_hex=000010c0",
    ]

    def transcript(groups: list[list[str]]) -> str:
        lines: list[str] = []
        for ordinal, group in enumerate(groups, 1):
            lines.append(f"OPENVINO_CASE_BEGIN ordinal={ordinal}")
            lines.extend(group)
            lines.append(f"OPENVINO_CASE_END ordinal={ordinal} status=ok")
        return "\n".join(lines) + "\n"

    expect_contract_failure(
        "XML-only transcript has no Constant data",
        lambda: validate_aba(transcript([["OPENVINO_LOAD_OK nodes=4"]] * 3)),
    )
    expect_contract_failure(
        "Constant access transcript is empty",
        lambda: validate_aba(transcript([a[:-1], b[:-1], a[:-1]])),
    )
    expect_contract_failure(
        "A-B-A transcript exposes sticky weights",
        lambda: validate_aba(transcript([a, a, a])),
    )


def build_fault_probe(
    project: Path, compiler: Path, work: Path, fuzzer_source: Path
) -> Path:
    fake_loader = work / "fault_loader.cc"
    fake_loader.write_text(
        """#include "harnesses/openvino/loader.h"
#include <csignal>
namespace tool::openvino_loader {
int LoadBundle(const std::uint8_t*, std::size_t, LoadSummary*, std::string*) {
  std::raise(SIGABRT);
  return 0;
}
}  // namespace tool::openvino_loader
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
    run(
        [
            str(compiler),
            "-std=c++17",
            f"-I{project}",
            str(fuzzer_source),
            str(fake_loader),
            str(driver),
            "-o",
            str(output),
        ]
    )
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project = args.project_root.resolve()
    target = args.target_root.resolve()
    results = Results()

    try:
        run_negative_controls()
        results.ok("RED controls reject XML-only, missing Constant, split-loader, and sticky-state defects")
    except ContractError as error:
        results.bad(f"RED controls are ineffective: {error}")

    sources = {
        "common loader header": project / "harnesses/openvino/loader.h",
        "common loader implementation": project / "harnesses/openvino/loader.cc",
        "replay wrapper": project / "harnesses/openvino/replay.cc",
        "engine wrapper": project / "harnesses/openvino/fuzzer.cc",
        "CMake source": project / "harnesses/openvino/CMakeLists.txt",
        "fixture generator": project / "scripts/gen_openvino_fixtures.py",
        "pinned build profile": target / "build-profile.json",
    }
    missing = False
    for label, path in sources.items():
        if not path.is_file() or path.is_symlink():
            results.bad(f"{label} is missing or not a regular file: {path}")
            missing = True
    if missing:
        print(f"[openvino-loader] pass={results.passed} fail={results.failed}")
        return 1

    try:
        loader_text = sources["common loader implementation"].read_text(encoding="utf-8")
        replay_text = sources["replay wrapper"].read_text(encoding="utf-8")
        fuzzer_text = sources["engine wrapper"].read_text(encoding="utf-8")
        validate_source_contract(loader_text, replay_text, fuzzer_text)
        results.ok("replay and engine wrappers contain no loader bypass or retained state")

        profile = load_unique_json(sources["pinned build profile"])
        toolchain = profile.get("toolchain")
        if not isinstance(toolchain, dict):
            fail("build profile has no toolchain object")
        cmake = Path(str(toolchain.get("cmake", {}).get("path", "")))
        compiler = Path(str(toolchain.get("compiler", {}).get("path", ""))).with_name("clang++")
        ninja = Path(str(toolchain.get("ninja", {}).get("path", "")))
        for label, path in (("cmake", cmake), ("clang++", compiler), ("ninja", ninja)):
            if not path.is_file() or not os.access(path, os.X_OK):
                fail(f"pinned {label} is not executable: {path}")

        with tempfile.TemporaryDirectory(prefix="openvino-loader-check-") as temporary:
            work = Path(temporary)
            build = work / "build"
            run(
                [
                    str(cmake),
                    "-S",
                    str(project / "harnesses/openvino"),
                    "-B",
                    str(build),
                    "-G",
                    "Ninja",
                    "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                    f"-DCMAKE_CXX_COMPILER={compiler}",
                    f"-DCMAKE_MAKE_PROGRAM={ninja}",
                    f"-DOpenVINO_DIR={target / 'install/runtime/cmake'}",
                    "-DOPENVINO_BUILD_LOADER=ON",
                ]
            )
            run(
                [
                    str(cmake),
                    "--build",
                    str(build),
                    "--target",
                    "openvino_ir_loader_replay",
                    "openvino_ir_loader_fuzzer",
                ]
            )
            replay = build / "openvino_ir_loader_replay"
            fuzzer = build / "openvino_ir_loader_fuzzer"
            for label, path in (("replay", replay), ("fuzzer", fuzzer)):
                require_regular(path, f"built {label}")
                if not os.access(path, os.X_OK):
                    fail(f"built {label} is not executable: {path}")
            results.ok("pinned Core+IR frontend builds both OVI-03 wrappers")

            fixtures = work / "fixtures"
            run(
                [
                    sys.executable,
                    "-B",
                    str(sources["fixture generator"]),
                    "--build-profile",
                    str(sources["pinned build profile"]),
                    "generate",
                    "--output",
                    str(fixtures),
                ]
            )

            normal = run([str(replay), str(fixtures / "constant-one.fzb")])
            if "payload_hex=0000c03f" not in normal.stdout:
                fail("normal replay did not expose the exact Constant payload")
            if "OPENVINO_ACCESS_OK nodes=4 constants=1 constant_bytes=4" not in normal.stdout:
                fail("normal replay did not finish validation/type/shape/Constant access")
            if "OPENVINO_OP index=0" not in normal.stdout or "outputs=f32:[1]" not in normal.stdout:
                fail("normal replay omitted ordered operation type/shape evidence")
            results.ok("normal FZB1 pair reaches validation, type/shape, and Constant data access")

            malformed = run([str(replay), str(fixtures / "malformed-xml.fzb")], expect=9)
            if "OPENVINO_LOAD_REJECT stage=frontend" not in malformed.stderr:
                fail("malformed XML was not classified as a frontend rejection")
            missing_pair = run([str(replay), str(fixtures / "missing-bin.fzb")], expect=9)
            if "OPENVINO_LOAD_REJECT stage=bundle" not in missing_pair.stderr:
                fail("missing model.bin was not classified as a pre-frontend bundle rejection")
            results.ok("bundle and pinned frontend rejections stay distinct and non-faulting")

            unavailable = run([str(replay), str(work / "absent.fzb")], expect=10)
            if "OPENVINO_INPUT_UNAVAILABLE" not in unavailable.stderr:
                fail("missing replay input did not retain the environment/unavailable boundary")
            results.ok("unreadable replay input is unavailable rather than an input finding")

            aba = run(
                [
                    str(replay),
                    str(fixtures / "constant-one.fzb"),
                    str(fixtures / "constant-two.fzb"),
                    str(fixtures / "constant-one.fzb"),
                ]
            )
            validate_aba(aba.stdout)
            results.ok("same-process A-B-A releases model/weights and reproduces A exactly")

            nm = Path(shutil_which("llvm-nm") or shutil_which("nm") or "")
            if not nm.is_file():
                fail("llvm-nm/nm is unavailable; shared loader symbol check cannot run")
            symbol = "tool::openvino_loader::LoadBundle("
            for label, path in (("replay", replay), ("engine", fuzzer)):
                symbols = run([str(nm), "-C", str(path)]).stdout
                if symbol not in symbols:
                    fail(f"{label} binary does not carry the common LoadBundle symbol")
            results.ok("replay and engine binaries both link the same common loader symbol")

            corpus = work / "corpus"
            corpus.mkdir()
            for name in (
                "constant-one.fzb",
                "constant-two.fzb",
                "empty-weights.fzb",
                "missing-bin.fzb",
                "truncated-weights.fzb",
                "malformed-xml.fzb",
            ):
                (corpus / name).write_bytes((fixtures / name).read_bytes())
            engine = run([str(fuzzer), "-runs=1", str(corpus)])
            combined = engine.stdout + engine.stderr
            if re.search(r"AddressSanitizer|UndefinedBehaviorSanitizer|deadly signal", combined):
                fail("engine smoke emitted a sanitizer/fault marker")
            results.ok("engine wrapper returns normally for accepted and rejected FZB1 inputs")

            fault_engine = build_fault_probe(
                project, compiler, work, sources["engine wrapper"]
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
            results.ok("engine wrapper preserves a loader fault as the original signal")

    except (ContractError, OSError, UnicodeError, ValueError) as error:
        results.bad(str(error))

    print(f"[openvino-loader] pass={results.passed} fail={results.failed}")
    return 0 if results.failed == 0 else 1


def shutil_which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


if __name__ == "__main__":
    raise SystemExit(main())
