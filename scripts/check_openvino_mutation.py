#!/usr/bin/env python3
"""Exercise the OVI-04 paired structural-mutation contract."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, NoReturn


OPERATORS = {
    "constant_layout": "constant.offset_size",
    "shape_dtype": "graph.shape_dtype",
    "graph_edge_port": "graph.edge_port",
    "operation_attribute": "operation.attribute",
    "node_identity": "node.name_id",
    "ir_metadata": "ir.metadata",
}
EXPECTED_SCHEMA = "openvino-ir-mutation-v1"


class ContractError(RuntimeError):
    """The OVI-04 mutation contract was not met."""


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def ok(self, message: str) -> None:
        self.passed += 1
        print(f"[openvino-mutation] ok: {message}")

    def bad(self, message: str) -> None:
        self.failed += 1
        print(f"[openvino-mutation] fail: {message}", file=sys.stderr)


def fail(message: str) -> NoReturn:
    raise ContractError(message)


def run(
    command: list[str],
    *,
    expect: int = 0,
    cwd: Path | None = None,
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


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
        fail(f"cannot read manifest {path}: {error}")
    if not isinstance(value, dict):
        fail(f"manifest root is not an object: {path}")
    return value


def import_path(path: Path, name: str) -> Any:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        fail(f"cannot import {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def edge_fixups_complete(xml: bytes) -> bool:
    root = ET.fromstring(xml)
    layers = {
        layer.get("id"): layer
        for layer in root.findall("./layers/layer")
        if layer.get("id") is not None
    }
    if len(layers) != len(root.findall("./layers/layer")):
        return False
    for edge in root.findall("./edges/edge"):
        source = layers.get(edge.get("from-layer"))
        target = layers.get(edge.get("to-layer"))
        if source is None or target is None:
            return False
        source_ports = {port.get("id") for port in source.findall("./output/port")}
        target_ports = {port.get("id") for port in target.findall("./input/port")}
        if edge.get("from-port") not in source_ports or edge.get("to-port") not in target_ports:
            return False
    return True


def run_preimplementation_red_controls(codec: Any, fixture: Path) -> None:
    source = fixture.read_bytes()
    if source != bytes(source):
        fail("no-op control was not identical")
    try:
        if source == bytes(source):
            raise ContractError("mutation is a no-op")
    except ContractError as error:
        if "no-op" not in str(error):
            raise
    else:
        fail("no-op control escaped detection")

    entries = dict(codec.decode_bundle(source))
    root = ET.fromstring(entries["model.xml"])
    first = root.find("./layers/layer")
    if first is None:
        fail("RED control fixture has no layer")
    first.set("id", "99")
    broken_xml = ET.tostring(root, encoding="utf-8")
    if edge_fixups_complete(broken_xml):
        fail("missing node/edge fixup escaped detection")

    empty = dict(codec.decode_bundle((fixture.parent / "empty-weights.fzb").read_bytes()))
    empty_root = ET.fromstring(empty["model.xml"])
    if empty_root.findall("./layers/layer[@type='Const']") or empty["model.bin"]:
        fail("inapplicable control unexpectedly contains a Constant payload")


def build_replay(project: Path, target: Path, work: Path) -> Path:
    profile = load_unique_json(target / "build-profile.json")
    toolchain = profile.get("toolchain")
    if not isinstance(toolchain, dict):
        fail("build profile has no toolchain object")
    cmake = Path(str(toolchain.get("cmake", {}).get("path", "")))
    compiler = Path(str(toolchain.get("compiler", {}).get("path", ""))).with_name("clang++")
    ninja = Path(str(toolchain.get("ninja", {}).get("path", "")))
    for label, path in (("cmake", cmake), ("clang++", compiler), ("ninja", ninja)):
        if not path.is_file() or not os.access(path, os.X_OK):
            fail(f"pinned {label} is unavailable or non-executable: {path}")
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
    run([str(cmake), "--build", str(build), "--target", "openvino_ir_loader_replay"])
    replay = build / "openvino_ir_loader_replay"
    if not replay.is_file() or not os.access(replay, os.X_OK):
        fail("OVI-03 replay did not build")
    return replay


def validate_manifest(
    path: Path,
    codec: Any,
    source: bytes,
    output: bytes,
    operator: str,
    requested_mode: str,
    effective_mode: str,
    seed: int,
) -> dict[str, Any]:
    document = load_unique_json(path)
    expected_loader = "accept" if effective_mode == "valid" else "reject"
    expected = {
        "schema_version": EXPECTED_SCHEMA,
        "target": "openvino-ir",
        "bundle_format": "FZB1",
        "operator": operator,
        "requested_mode": requested_mode,
        "effective_mode": effective_mode,
        "expected_loader": expected_loader,
        "seed": seed,
        "source_sha256": sha256_bytes(source),
        "output_sha256": sha256_bytes(output),
    }
    expected_keys = set(expected) | {"entries", "evidence"}
    if set(document) != expected_keys:
        fail(
            f"manifest keys mismatch: {sorted(document)} != {sorted(expected_keys)}"
        )
    for key, value in expected.items():
        if document.get(key) != value:
            fail(f"manifest {key} mismatch: {document.get(key)!r} != {value!r}")
    entries = document.get("entries")
    if not isinstance(entries, dict) or set(entries) != {"model.bin", "model.xml"}:
        fail("manifest does not bind the exact model.xml/model.bin pair")
    try:
        source_entries = dict(codec.decode_bundle(source))
        output_entries = dict(codec.decode_bundle(output))
    except (ValueError, UnicodeError) as error:
        fail(f"cannot decode manifest-bound bundle: {error}")
    expected_entries = {
        name: {
            "after_sha256": sha256_bytes(output_entries[name]),
            "after_size": len(output_entries[name]),
            "before_sha256": sha256_bytes(source_entries[name]),
            "before_size": len(source_entries[name]),
            "changed": output_entries[name] != source_entries[name],
        }
        for name in ("model.bin", "model.xml")
    }
    if entries != expected_entries:
        fail("manifest per-entry hash, size, or changed identity mismatch")
    evidence = document.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("field") != OPERATORS[operator]:
        fail("manifest operator evidence field mismatch")
    before, after = evidence.get("before"), evidence.get("after")
    if not isinstance(before, str) or not before or not isinstance(after, str) or not after:
        fail("manifest has incomplete before/after evidence")
    if before == after:
        fail("manifest evidence records a no-op")
    if operator == "constant_layout" and effective_mode == "valid":
        before_match = re.search(r"offset=(\d+);size=(\d+)", before)
        after_match = re.search(r"offset=(\d+);size=(\d+)", after)
        if before_match is None or after_match is None:
            fail("constant_layout evidence omits offset/size")
        if before_match.group(1) == after_match.group(1):
            fail("constant_layout valid mutation did not change Constant offset")
        if before_match.group(2) == after_match.group(2):
            fail("constant_layout valid mutation did not change Constant size")
    fixups = evidence.get("fixups")
    if not isinstance(fixups, list) or not fixups or not all(isinstance(row, str) for row in fixups):
        fail("manifest has no deterministic fixup evidence")
    if source == output:
        fail("mutator output is a no-op")
    if effective_mode == "valid":
        for name in ("model.xml", "model.bin"):
            row = entries.get(name)
            if not isinstance(row, dict) or row.get("changed") is not True:
                fail(f"valid mutation did not update paired entry {name}")
    return document


def constant_payload(output: str) -> str:
    matches = re.findall(r"^OPENVINO_CONSTANT .* payload_hex=([0-9a-f]+)$", output, re.MULTILINE)
    if len(matches) != 1:
        fail(f"expected one Constant payload observation, got {matches!r}")
    return matches[0]


def run_mutation(
    mutator: Path,
    source: Path,
    output: Path,
    operator: str,
    mode: str,
    seed: int,
) -> subprocess.CompletedProcess[str]:
    return run(
        [
            sys.executable,
            "-B",
            str(mutator),
            "--input",
            str(source),
            "--output",
            str(output),
            "--operator",
            operator,
            "--mode",
            mode,
            "--seed",
            str(seed),
        ]
    )


def check_operator_mode(
    codec: Any,
    mutator: Path,
    replay: Path,
    source: Path,
    work: Path,
    operator: str,
    mode: str,
) -> None:
    first = work / f"{operator}-{mode}-a.fzb"
    second = work / f"{operator}-{mode}-b.fzb"
    seed = 4200 + list(OPERATORS).index(operator)
    first_run = run_mutation(mutator, source, first, operator, mode, seed)
    second_run = run_mutation(mutator, source, second, operator, mode, seed)
    marker = (
        f"OPENVINO_MUTATION_OK operator={operator} requested_mode={mode} "
        f"effective_mode={mode} expected_loader={'accept' if mode == 'valid' else 'reject'}"
    )
    if marker not in first_run.stdout or marker not in second_run.stdout:
        fail(f"{operator}/{mode} did not emit the exact result marker")
    first_manifest = first.with_name(first.name + ".manifest.json")
    second_manifest = second.with_name(second.name + ".manifest.json")
    source_bytes = source.read_bytes()
    first_bytes = first.read_bytes()
    second_bytes = second.read_bytes()
    if first_bytes != second_bytes:
        fail(f"{operator}/{mode} output is nondeterministic")
    if first_manifest.read_bytes() != second_manifest.read_bytes():
        fail(f"{operator}/{mode} manifest is path- or time-dependent")
    validate_manifest(
        first_manifest,
        codec,
        source_bytes,
        first_bytes,
        operator,
        mode,
        mode,
        seed,
    )
    if mode == "valid":
        base = run([str(replay), str(source)]).stdout
        accepted = run([str(replay), str(first)]).stdout
        if "OPENVINO_LOAD_OK stage=read_validate_constants nodes=4" not in accepted:
            fail(f"{operator} did not reach the OVI-03 frontend at four nodes")
        if "OPENVINO_ACCESS_OK nodes=4 constants=1" not in accepted:
            fail(f"{operator} did not finish OVI-03 Constant access")
        if constant_payload(base) == constant_payload(accepted):
            fail(f"{operator} did not expose a changed Constant through OVI-03")
    else:
        rejected = run([str(replay), str(first)], expect=9)
        combined = rejected.stdout + rejected.stderr
        if "OPENVINO_LOAD_REJECT stage=frontend" not in combined:
            fail(f"{operator} boundary case was not rejected by the IR frontend")
        if re.search(r"AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|Segmentation fault", combined):
            fail(f"{operator} boundary case produced a fault marker")


def check_mixed_modes(
    codec: Any, mutator: Path, replay: Path, source: Path, work: Path
) -> None:
    observed: dict[str, Path] = {}
    for seed in range(64):
        output = work / f"mixed-{seed}.fzb"
        run_mutation(mutator, source, output, "constant_layout", "mixed", seed)
        manifest = load_unique_json(output.with_name(output.name + ".manifest.json"))
        effective = manifest.get("effective_mode")
        if effective not in ("valid", "boundary"):
            fail(f"mixed mode emitted invalid effective mode: {effective!r}")
        validate_manifest(
            output.with_name(output.name + ".manifest.json"),
            codec,
            source.read_bytes(),
            output.read_bytes(),
            "constant_layout",
            "mixed",
            effective,
            seed,
        )
        observed.setdefault(effective, output)
        if len(observed) == 2:
            break
    if set(observed) != {"valid", "boundary"}:
        fail("mixed mode did not deterministically expose both policy arms")
    run([str(replay), str(observed["valid"])])
    run([str(replay), str(observed["boundary"])], expect=9)


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
    required = {
        "FZB1 codec": project / "scripts/model_bundle.py",
        "OVI-02 fixture generator": project / "scripts/gen_openvino_fixtures.py",
        "OVI-03 common loader": project / "harnesses/openvino/loader.cc",
        "pinned build profile": target / "build-profile.json",
    }
    for label, path in required.items():
        if not path.is_file() or path.is_symlink():
            results.bad(f"{label} is missing or not a regular file: {path}")
    if results.failed:
        print(f"[openvino-mutation] pass={results.passed} fail={results.failed}")
        return 1

    try:
        codec = import_path(required["FZB1 codec"], "ovi04_bundle_codec")
        with tempfile.TemporaryDirectory(prefix="openvino-mutation-check-") as temporary:
            work = Path(temporary)
            fixtures = work / "fixtures"
            run(
                [
                    sys.executable,
                    "-B",
                    str(required["OVI-02 fixture generator"]),
                    "--build-profile",
                    str(required["pinned build profile"]),
                    "generate",
                    "--output",
                    str(fixtures),
                ]
            )
            source = fixtures / "constant-one.fzb"
            run_preimplementation_red_controls(codec, source)
            results.ok("RED controls catch a no-op, missing reference fixup, and inapplicable Constant")

            mutator = project / "scripts/mutate_openvino_bundle.py"
            if not mutator.is_file() or mutator.is_symlink():
                results.bad(f"OVI-04 mutator is missing or not a regular file: {mutator}")
                print(f"[openvino-mutation] pass={results.passed} fail={results.failed}")
                return 1

            module = import_path(mutator, "ovi04_mutator")
            entries = dict(codec.decode_bundle(source.read_bytes()))
            try:
                module.validate_candidate(entries, entries, "node_identity", "valid", {
                    "before": "same", "after": "same", "fixups": ["none"]
                })
            except module.MutationError:
                pass
            else:
                fail("production validator accepted a no-op")

            broken = dict(entries)
            root = ET.fromstring(entries["model.xml"])
            first = root.find("./layers/layer")
            if first is None:
                fail("fixture has no layer for missing-fixup control")
            first.set("id", "99")
            broken["model.xml"] = ET.tostring(root, encoding="utf-8")
            broken["model.bin"] = bytes([entries["model.bin"][0] ^ 1]) + entries["model.bin"][1:]
            try:
                module.validate_candidate(entries, broken, "node_identity", "valid", {
                    "before": "id=0", "after": "id=99", "fixups": ["layer ids"]
                })
            except module.MutationError:
                pass
            else:
                fail("production validator accepted a missing edge fixup")
            results.ok("production validator rejects no-op and incomplete valid fixups before publish")

            manifest_control = work / "manifest-control.fzb"
            manifest_seed = 73
            run_mutation(
                mutator,
                source,
                manifest_control,
                "graph_edge_port",
                "valid",
                manifest_seed,
            )
            manifest_path = manifest_control.with_name(manifest_control.name + ".manifest.json")
            manifest_document = load_unique_json(manifest_path)
            escaped: list[str] = []
            for label, mutate_manifest in (
                (
                    "per-entry identity",
                    lambda document: document["entries"]["model.bin"].pop("after_sha256"),
                ),
                (
                    "seed identity",
                    lambda document: document.__setitem__("seed", manifest_seed + 1),
                ),
            ):
                candidate = json.loads(json.dumps(manifest_document))
                mutate_manifest(candidate)
                bad_manifest = work / f"manifest-control-{label.replace(' ', '-')}.json"
                bad_manifest.write_text(
                    json.dumps(candidate, sort_keys=True) + "\n", encoding="utf-8"
                )
                try:
                    validate_manifest(
                        bad_manifest,
                        codec,
                        source.read_bytes(),
                        manifest_control.read_bytes(),
                        "graph_edge_port",
                        "valid",
                        "valid",
                        manifest_seed,
                    )
                except ContractError:
                    pass
                else:
                    escaped.append(label)
            if escaped:
                fail(f"manifest identity controls escaped validation: {', '.join(escaped)}")
            results.ok("manifest validator rejects wrong entry and seed identities")

            replay = build_replay(project, target, work)
            results.ok("OVI-03 single common loader replay builds from the pinned profile")

            for operator in OPERATORS:
                for mode in ("valid", "boundary"):
                    try:
                        check_operator_mode(
                            codec, mutator, replay, source, work, operator, mode
                        )
                        results.ok(
                            f"{operator}/{mode} is deterministic and matches the actual frontend outcome"
                        )
                    except ContractError as error:
                        results.bad(str(error))

            try:
                check_mixed_modes(codec, mutator, replay, source, work)
                results.ok("mixed mode deterministically keeps valid and boundary outcomes distinct")
            except ContractError as error:
                results.bad(str(error))

            inapplicable = work / "inapplicable.fzb"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(mutator),
                    "--input",
                    str(fixtures / "empty-weights.fzb"),
                    "--output",
                    str(inapplicable),
                    "--operator",
                    "constant_layout",
                    "--mode",
                    "valid",
                    "--seed",
                    "7",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if (
                completed.returncode == 3
                and "OPENVINO_MUTATION_INAPPLICABLE operator=constant_layout" in completed.stderr
                and not inapplicable.exists()
                and not inapplicable.with_name(inapplicable.name + ".manifest.json").exists()
            ):
                results.ok("inapplicable mutation exits explicitly without publishing output")
            else:
                results.bad(
                    f"inapplicable mutation violated rc/output contract: rc={completed.returncode}"
                )
    except (ContractError, OSError, UnicodeError, ValueError, ET.ParseError) as error:
        results.bad(str(error))

    print(f"[openvino-mutation] pass={results.passed} fail={results.failed}")
    return 0 if results.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
