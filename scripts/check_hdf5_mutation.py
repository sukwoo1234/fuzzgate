#!/usr/bin/env python3
"""Exercise the HDF-04 official-writer structural-mutation contract."""

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
from typing import Any, NoReturn


SCHEMA_VERSION = "hdf5-weights-mutation-v1"
GENERATOR_VERSION = "hdf5-weights-structural-mutator-v1"
TARGET_ID = "hdf5-weights"
STRUCTURAL_OPERATORS = {
    "object_names": "object.group_dataset_names",
    "shape_dtype": "dataset.shape_dtype",
    "payload": "dataset.payload",
    "chunk_layout": "dataset.chunk_layout",
    "attributes": "object.attributes",
}
OPERATORS = {**STRUCTURAL_OPERATORS, "raw_object_header": "dataset.object_header"}
STRUCTURAL_TARGET_API = "H5LTopen_file_image/H5Dread/H5Aread"
RAW_TARGET_API = "H5LTopen_file_image/H5Oget_info_by_name3"
EXPECTED_FIXUPS = {
    "object_names": [
        "official_writer_reserialize",
        "rewrite_group_path",
        "rewrite_dataset_path",
    ],
    "shape_dtype": [
        "official_writer_reserialize",
        "recreate_dataspace",
        "recreate_datatype",
        "rewrite_payload",
    ],
    "payload": ["official_writer_reserialize", "rewrite_numeric_payload"],
    "chunk_layout": [
        "official_writer_reserialize",
        "recreate_dcpl",
        "rewrite_chunk_index",
    ],
    "attributes": [
        "official_writer_reserialize",
        "recreate_group_attribute",
        "recreate_dataset_attribute",
    ],
    "raw_object_header": [
        "official_writer_reserialize",
        "intentional_raw_corruption",
    ],
}
PROBE_FIELDS = (
    "group_hex",
    "dataset_hex",
    "dtype",
    "shape",
    "layout",
    "chunks",
    "group_attr_name_hex",
    "group_attr_value",
    "dataset_attr_name_hex",
    "dataset_attr_value",
    "values",
)


class ContractError(RuntimeError):
    """The HDF-04 mutation contract was not met."""


class Results:
    def __init__(self, prefix: str = "hdf5-mutation") -> None:
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
    expect: int = 0,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    if completed.returncode != expect:
        fail(
            f"command returned {completed.returncode}, expected {expect}: {command!r}\n"
            f"stdout={completed.stdout[-3000:]!r}\nstderr={completed.stderr[-3000:]!r}"
        )
    return completed


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_regular(path: Path, label: str, *, executable: bool = False) -> None:
    try:
        path.lstat()
    except OSError as error:
        fail(f"{label} is unavailable: {path}: {error}")
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")
    if executable and not os.access(path, os.X_OK):
        fail(f"{label} is not executable: {path}")


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


def validate_identity(row: Any, blob: bytes, label: str) -> None:
    expected = {"sha256": sha256_bytes(blob), "size": len(blob)}
    if (
        not isinstance(row, dict)
        or set(row) != {"sha256", "size"}
        or type(row.get("sha256")) is not str
        or type(row.get("size")) is not int
        or row != expected
    ):
        fail(f"manifest {label} identity mismatch: {row!r} != {expected!r}")


def decode_probe_name(probe: dict[str, str], field: str) -> str:
    try:
        return bytes.fromhex(probe[field]).decode("utf-8")
    except (KeyError, ValueError, UnicodeError) as error:
        fail(f"cannot decode probe field {field!r}: {error}")


def expected_evidence(
    operator: str,
    seed: int,
    source_probe: dict[str, str] | None,
    output_probe: dict[str, str] | None,
) -> tuple[str, str]:
    if operator == "raw_object_header":
        return "signature:OHDR", "signature:XHDR"
    if source_probe is None or output_probe is None:
        fail(f"{operator} manifest evidence lacks independent source/output probes")
    validate_probe_change(operator, source_probe, output_probe)
    if operator == "object_names":
        before = (
            f"group:{decode_probe_name(source_probe, 'group_hex')};"
            f"dataset:{decode_probe_name(source_probe, 'dataset_hex')}"
        )
        after = (
            f"group:{decode_probe_name(output_probe, 'group_hex')};"
            f"dataset:{decode_probe_name(output_probe, 'dataset_hex')}"
        )
    elif operator == "shape_dtype":
        before = f"dtype:{source_probe['dtype']};shape:{source_probe['shape']}"
        after = f"dtype:{output_probe['dtype']};shape:{output_probe['shape']}"
    elif operator == "payload":
        source_values = source_probe["values"].split(",")
        output_values = output_probe["values"].split(",")
        if len(source_values) != len(output_values) or not source_values:
            fail("payload probe value counts differ")
        changed = [
            index
            for index, (before_value, after_value) in enumerate(
                zip(source_values, output_values, strict=True)
            )
            if before_value != after_value
        ]
        expected_index = seed % len(source_values)
        if changed != [expected_index]:
            fail(
                f"payload changed value indexes {changed!r}, "
                f"expected [{expected_index}]"
            )
        before = f"index:{expected_index};value:{source_values[expected_index]}"
        after = f"index:{expected_index};value:{output_values[expected_index]}"
    elif operator == "chunk_layout":
        before = f"layout:{source_probe['layout']};chunks:{source_probe['chunks']}"
        after = f"layout:{output_probe['layout']};chunks:{output_probe['chunks']}"
    elif operator == "attributes":
        before = (
            "group:"
            f"{decode_probe_name(source_probe, 'group_attr_name_hex')}:"
            f"{source_probe['group_attr_value']};dataset:"
            f"{decode_probe_name(source_probe, 'dataset_attr_name_hex')}:"
            f"{source_probe['dataset_attr_value']}"
        )
        after = (
            "group:"
            f"{decode_probe_name(output_probe, 'group_attr_name_hex')}:"
            f"{output_probe['group_attr_value']};dataset:"
            f"{decode_probe_name(output_probe, 'dataset_attr_name_hex')}:"
            f"{output_probe['dataset_attr_value']}"
        )
    else:
        fail(f"evidence validation does not support operator {operator!r}")
    return before, after


def validate_manifest(
    path: Path,
    source: bytes,
    output: bytes,
    native_tool: bytes,
    operator: str,
    seed: int,
    source_probe: dict[str, str] | None = None,
    output_probe: dict[str, str] | None = None,
) -> dict[str, Any]:
    document = load_unique_json(path)
    structural = operator in STRUCTURAL_OPERATORS
    expected_class = "structure_preserving" if structural else "raw_corruption"
    expected_loader = "accept" if structural else "reject"
    expected_scalars = {
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "target": TARGET_ID,
        "operator": operator,
        "mutation_class": expected_class,
        "field": OPERATORS[operator],
        "seed": seed,
        "expected_loader": expected_loader,
        "expected_stage": "complete" if structural else "object_lookup",
        "target_api": STRUCTURAL_TARGET_API if structural else RAW_TARGET_API,
        "writer": "official-hdf5-2.2.0" if structural else "raw-byte-corruption",
    }
    expected_keys = set(expected_scalars) | {
        "native_tool",
        "source",
        "output",
        "before",
        "after",
        "fixups",
    }
    if set(document) != expected_keys:
        fail(f"manifest keys mismatch: {sorted(document)} != {sorted(expected_keys)}")
    if type(document.get("seed")) is not int:
        fail("manifest seed must be a JSON integer, not a boolean or other type")
    for key, value in expected_scalars.items():
        if document.get(key) != value:
            fail(f"manifest {key} mismatch: {document.get(key)!r} != {value!r}")
    validate_identity(document.get("native_tool"), native_tool, "native_tool")
    validate_identity(document.get("source"), source, "source")
    validate_identity(document.get("output"), output, "output")
    if source == output:
        fail("mutation output is a no-op")
    before = document.get("before")
    after = document.get("after")
    if not isinstance(before, str) or not before:
        fail("manifest before evidence is missing")
    if not isinstance(after, str) or not after:
        fail("manifest after evidence is missing")
    if before == after:
        fail("manifest before/after evidence records a no-op")
    expected_before, expected_after = expected_evidence(
        operator, seed, source_probe, output_probe
    )
    if before != expected_before or after != expected_after:
        fail(
            "manifest before/after evidence mismatch: "
            f"{before!r}/{after!r} != {expected_before!r}/{expected_after!r}"
        )
    fixups = document.get("fixups")
    if not isinstance(fixups, list) or not fixups or not all(
        isinstance(item, str) and item for item in fixups
    ):
        fail("manifest fixup evidence is missing")
    if fixups != EXPECTED_FIXUPS[operator]:
        fail(
            f"manifest fixup evidence mismatch: {fixups!r} != "
            f"{EXPECTED_FIXUPS[operator]!r}"
        )
    return document


def validate_raw_reject(completed: subprocess.CompletedProcess[str]) -> None:
    result_lines = [
        line
        for line in (completed.stdout + completed.stderr).splitlines()
        if line.startswith("HDF5_RESULT ")
    ]
    if completed.returncode != 9 or len(result_lines) != 1:
        fail(
            "raw loader result must be one rc9 HDF5_RESULT line: "
            f"rc={completed.returncode} lines={result_lines!r}"
        )
    fields: dict[str, str] = {}
    for token in result_lines[0].split()[1:]:
        if token.count("=") != 1:
            fail(f"raw loader result token is malformed: {token!r}")
        key, value = token.split("=", 1)
        if key in fields or not key or not value:
            fail(f"raw loader result field is duplicated or empty: {token!r}")
        fields[key] = value
    if set(fields) != {"classification", "stage", "reason"}:
        fail(f"raw loader result fields are not exact: {fields!r}")
    if fields["classification"] != "target_reject" or fields["stage"] != "object_lookup":
        fail(
            "raw loader rejection does not bind the promised object_lookup stage: "
            f"{fields!r}"
        )


def validate_raw_byte_diff(source: bytes, output: bytes) -> None:
    if len(source) != len(output):
        fail(
            "raw corruption changed image size: "
            f"{len(source)} != {len(output)}"
        )
    changed_index: int | None = None
    for index, (before, after) in enumerate(zip(source, output, strict=True)):
        if before == after:
            continue
        if changed_index is not None:
            fail(
                "raw corruption changed more than the one object-header byte: "
                f"{changed_index}, {index}"
            )
        changed_index = index
    if changed_index is None:
        fail("raw corruption did not change an object-header byte")
    if (
        source[changed_index : changed_index + 4] != b"OHDR"
        or output[changed_index : changed_index + 4] != b"XHDR"
    ):
        fail(
            "raw corruption is not the exact dataset object-header O-to-X change: "
            f"offset={changed_index}"
        )


def validate_inapplicable_result(
    completed: subprocess.CompletedProcess[str],
    output: Path,
    operator: str,
) -> None:
    manifest = output.with_name(output.name + ".manifest.json")
    marker = f"HDF5_MUTATION_INAPPLICABLE operator={operator}"
    if completed.returncode != 3 or marker not in completed.stderr:
        fail(
            "inapplicable mutation did not use the explicit rc3/marker contract: "
            f"rc={completed.returncode} stderr={completed.stderr[-1000:]!r}"
        )
    if output.exists() or output.is_symlink() or manifest.exists() or manifest.is_symlink():
        fail("inapplicable mutation published an output or manifest")


def validate_failed_result(
    completed: subprocess.CompletedProcess[str],
    output: Path,
    reason_fragment: str,
) -> None:
    manifest = output.with_name(output.name + ".manifest.json")
    if (
        completed.returncode != 1
        or "HDF5_MUTATION_FAIL" not in completed.stderr
        or reason_fragment not in completed.stderr
    ):
        fail(
            "failed mutation did not use the explicit rc1/reason contract: "
            f"rc={completed.returncode} stderr={completed.stderr[-1000:]!r}"
        )
    if output.exists() or output.is_symlink() or manifest.exists() or manifest.is_symlink():
        fail("failed mutation published an output or manifest")


def expect_failure(label: str, callback: Any) -> None:
    try:
        callback()
    except ContractError:
        return
    fail(f"RED control escaped validation: {label}")


def parse_probe(output: str, error_output: str) -> dict[str, str]:
    if error_output:
        fail(f"mutation test tool inspect wrote stderr: {error_output[-1000:]!r}")
    lines = output.splitlines()
    if len(lines) != 1 or output not in {lines[0], lines[0] + "\n"}:
        fail("mutation test tool inspect must emit exactly one non-empty line")
    tokens = lines[0].split(" ")
    if not tokens or tokens[0] != "HDF5_MUTATION_INSPECT_OK":
        fail("mutation test tool inspect marker is missing")
    if len(tokens) != len(PROBE_FIELDS) + 1:
        fail("mutation test tool inspect field count mismatch")
    fields: dict[str, str] = {}
    observed_order: list[str] = []
    for token in tokens[1:]:
        if token.count("=") != 1:
            fail(f"mutation test tool inspect token is malformed: {token!r}")
        key, value = token.split("=", 1)
        if key in fields or not key or not value:
            fail(f"mutation test tool inspect field is duplicated or empty: {token!r}")
        fields[key] = value
        observed_order.append(key)
    if tuple(observed_order) != PROBE_FIELDS:
        fail(
            "mutation test tool inspect field order mismatch: "
            f"{tuple(observed_order)!r} != {PROBE_FIELDS!r}"
        )

    for field in (
        "group_hex",
        "dataset_hex",
        "group_attr_name_hex",
        "dataset_attr_name_hex",
    ):
        value = fields[field]
        if re.fullmatch(r"(?:[0-9a-f]{2})+", value) is None:
            fail(f"mutation test tool inspect {field} is not canonical lowercase hex")
        try:
            decoded = bytes.fromhex(value).decode("utf-8")
        except (ValueError, UnicodeError) as error:
            fail(f"mutation test tool inspect {field} is not UTF-8 text: {error}")
        if not decoded or any(
            character.isspace() or ord(character) < 0x21 or ord(character) == 0x7F
            for character in decoded
        ):
            fail(f"mutation test tool inspect {field} decodes to an invalid name")
        if field == "group_hex":
            if not decoded.startswith("/") or decoded == "/" or decoded.endswith("/"):
                fail("mutation test tool inspect group must be an absolute object path")
        elif "/" in decoded:
            fail(f"mutation test tool inspect {field} must be an object basename")
    if fields["dtype"] not in {"float32-le", "int32-le"}:
        fail("mutation test tool inspect dtype is unsupported")
    if re.fullmatch(r"[1-9][0-9]*x[1-9][0-9]*", fields["shape"]) is None:
        fail("mutation test tool inspect shape is not canonical")
    if fields["layout"] not in {"contiguous", "chunked"}:
        fail("mutation test tool inspect layout is unsupported")
    if fields["layout"] == "contiguous":
        if fields["chunks"] != "none":
            fail("contiguous inspect result must record chunks=none")
    elif re.fullmatch(r"[1-9][0-9]*x[1-9][0-9]*", fields["chunks"]) is None:
        fail("chunked inspect result must record canonical chunk dimensions")
    for field in ("group_attr_value", "dataset_attr_value"):
        if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", fields[field]) is None:
            fail(f"mutation test tool inspect {field} is not a canonical integer")
    number = r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:e-?[1-9][0-9]*)?"
    if re.fullmatch(rf"{number}(?:,{number})*", fields["values"]) is None:
        fail("mutation test tool inspect values are not a canonical numeric list")
    return fields


def expected_fixture_probe(
    group_attribute: str = "1", dataset_attribute: str = "2"
) -> dict[str, str]:
    return dict(
        zip(
            PROBE_FIELDS,
            (
                "/weights".encode().hex(),
                "kernel".encode().hex(),
                "float32-le",
                "2x3",
                "contiguous",
                "none",
                "fixture_version".encode().hex(),
                group_attribute,
                "axis_count".encode().hex(),
                dataset_attribute,
                "1.25,-2,3.5,4.25,-5.75,6",
            ),
            strict=True,
        )
    )


def validate_probe_change(
    operator: str, source: dict[str, str], mutated: dict[str, str]
) -> None:
    if tuple(source) != PROBE_FIELDS or tuple(mutated) != PROBE_FIELDS:
        fail("probe change validation received a non-canonical field set")
    changed = {
        field for field in PROBE_FIELDS if source[field] != mutated[field]
    }
    if operator == "object_names":
        expected = {"group_hex", "dataset_hex"}
    elif operator == "shape_dtype":
        expected = {"dtype", "shape", "values"}
        if source["dtype"] != "float32-le" or source["shape"] != "2x3":
            fail("shape_dtype source does not have the expected float32 2x3 contract")
        if mutated["dtype"] != "int32-le" or mutated["shape"] != "3x2":
            fail("shape_dtype output is not the expected int32 3x2 mutation")
    elif operator == "payload":
        expected = {"values"}
    elif operator == "chunk_layout":
        expected = {"layout", "chunks"}
        if source["layout"] != "contiguous" or source["chunks"] != "none":
            fail("chunk_layout source is not contiguous with no chunks")
        if mutated["layout"] != "chunked" or mutated["chunks"] != "1x3":
            fail("chunk_layout output is not chunked with 1x3 chunks")
    elif operator == "attributes":
        expected = {"group_attr_value", "dataset_attr_value"}
    else:
        fail(f"probe change validation does not support operator {operator!r}")
    if changed != expected:
        fail(
            f"{operator} changed semantic fields {sorted(changed)!r}, "
            f"expected exactly {sorted(expected)!r}"
        )


def inspect_image(tool: Path, image: Path) -> dict[str, str]:
    completed = run([str(tool), "inspect", str(image)])
    return parse_probe(completed.stdout, completed.stderr)


def require_inspect_reject(tool: Path, image: Path, reason: str) -> None:
    completed = run([str(tool), "inspect", str(image)], expect=1)
    marker = f"HDF5_MUTATION_TEST_TOOL_FAIL reason={reason}"
    if completed.stdout or marker not in completed.stderr:
        fail(
            f"mutation test tool did not reject {reason!r} exactly: "
            f"stdout={completed.stdout!r} stderr={completed.stderr[-1000:]!r}"
        )


def selftest() -> int:
    results = Results("hdf5-mutation-selftest")
    try:
        with tempfile.TemporaryDirectory(prefix="hdf5-mutation-selftest-") as temporary:
            root = Path(temporary)
            source = b"source-hdf-image"
            output = b"rewritten-hdf-image"
            native_tool = b"native-mutator-binary"
            seed = 17
            source_probe = expected_fixture_probe()
            object_probe = dict(source_probe)
            object_probe["group_hex"] = "/weights_m17".encode().hex()
            object_probe["dataset_hex"] = "kernel_m17".encode().hex()
            manifest = {
                "after": "group:/weights_m17;dataset:kernel_m17",
                "before": "group:/weights;dataset:kernel",
                "expected_loader": "accept",
                "expected_stage": "complete",
                "field": OPERATORS["object_names"],
                "fixups": EXPECTED_FIXUPS["object_names"],
                "generator_version": GENERATOR_VERSION,
                "mutation_class": "structure_preserving",
                "native_tool": {
                    "sha256": sha256_bytes(native_tool),
                    "size": len(native_tool),
                },
                "operator": "object_names",
                "output": {"sha256": sha256_bytes(output), "size": len(output)},
                "schema_version": SCHEMA_VERSION,
                "seed": seed,
                "source": {"sha256": sha256_bytes(source), "size": len(source)},
                "target": TARGET_ID,
                "target_api": STRUCTURAL_TARGET_API,
                "writer": "official-hdf5-2.2.0",
            }
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
            validate_manifest(
                path,
                source,
                output,
                native_tool,
                "object_names",
                seed,
                source_probe,
                object_probe,
            )
            results.ok(
                "valid structural manifest binds stage, API, tool, fixups, and identities"
            )

            raw_output = b"raw-corrupted-hdf-image"
            raw_manifest = dict(manifest)
            raw_manifest.update(
                {
                    "after": "signature:XHDR",
                    "before": "signature:OHDR",
                    "expected_loader": "reject",
                    "expected_stage": "object_lookup",
                    "field": OPERATORS["raw_object_header"],
                    "fixups": [
                        "official_writer_reserialize",
                        "intentional_raw_corruption",
                    ],
                    "mutation_class": "raw_corruption",
                    "operator": "raw_object_header",
                    "output": {
                        "sha256": sha256_bytes(raw_output),
                        "size": len(raw_output),
                    },
                    "target_api": RAW_TARGET_API,
                    "writer": "raw-byte-corruption",
                }
            )
            raw_path = root / "raw-manifest.json"
            raw_path.write_text(
                json.dumps(raw_manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            validate_manifest(
                raw_path,
                source,
                raw_output,
                native_tool,
                "raw_object_header",
                seed,
            )
            results.ok("raw manifest binds object_lookup to the object-info target API")

            expect_failure(
                "no-op output",
                lambda: validate_manifest(
                    path,
                    source,
                    source,
                    native_tool,
                    "object_names",
                    seed,
                    source_probe,
                    object_probe,
                ),
            )
            results.ok("RED control rejects a copied input reported as a mutation")

            missing_fixup = dict(manifest)
            missing_fixup["fixups"] = ["rewrite_dataset_path"]
            missing_path = root / "missing-fixup.json"
            missing_path.write_text(
                json.dumps(missing_fixup, sort_keys=True) + "\n", encoding="utf-8"
            )
            expect_failure(
                "missing official writer fixup",
                lambda: validate_manifest(
                    missing_path,
                    source,
                    output,
                    native_tool,
                    "object_names",
                    seed,
                    source_probe,
                    object_probe,
                ),
            )
            results.ok("RED control rejects structural output without writer/fixup evidence")

            wrong_identity = json.loads(json.dumps(manifest))
            wrong_identity["output"]["sha256"] = "0" * 64
            wrong_path = root / "wrong-identity.json"
            wrong_path.write_text(
                json.dumps(wrong_identity, sort_keys=True) + "\n", encoding="utf-8"
            )
            expect_failure(
                "manifest identity tamper",
                lambda: validate_manifest(
                    wrong_path,
                    source,
                    output,
                    native_tool,
                    "object_names",
                    seed,
                    source_probe,
                    object_probe,
                ),
            )
            results.ok("RED control rejects manifest/output identity tampering")

            wrong_tool = json.loads(json.dumps(manifest))
            wrong_tool["native_tool"]["size"] += 1
            wrong_tool_path = root / "wrong-tool.json"
            wrong_tool_path.write_text(
                json.dumps(wrong_tool, sort_keys=True) + "\n", encoding="utf-8"
            )
            expect_failure(
                "native tool identity tamper",
                lambda: validate_manifest(
                    wrong_tool_path,
                    source,
                    output,
                    native_tool,
                    "object_names",
                    seed,
                    source_probe,
                    object_probe,
                ),
            )
            results.ok("RED control rejects native tool identity tampering")

            false_evidence = json.loads(json.dumps(manifest))
            false_evidence["before"] = "group:/invented;dataset:not-real"
            false_evidence_path = root / "false-evidence.json"
            false_evidence_path.write_text(
                json.dumps(false_evidence, sort_keys=True) + "\n", encoding="utf-8"
            )
            duplicate_fixup = json.loads(json.dumps(manifest))
            duplicate_fixup["fixups"].append("rewrite_dataset_path")
            duplicate_fixup_path = root / "duplicate-fixup.json"
            duplicate_fixup_path.write_text(
                json.dumps(duplicate_fixup, sort_keys=True) + "\n", encoding="utf-8"
            )
            boolean_seed = json.loads(json.dumps(manifest))
            boolean_seed["seed"] = True
            boolean_seed_path = root / "boolean-seed.json"
            boolean_seed_path.write_text(
                json.dumps(boolean_seed, sort_keys=True) + "\n", encoding="utf-8"
            )
            for label, candidate, expected_seed in (
                ("invented before/after evidence", false_evidence_path, seed),
                ("duplicated fixup evidence", duplicate_fixup_path, seed),
                ("boolean seed", boolean_seed_path, 1),
            ):
                expect_failure(
                    label,
                    lambda candidate=candidate, expected_seed=expected_seed: validate_manifest(
                        candidate,
                        source,
                        output,
                        native_tool,
                        "object_names",
                        expected_seed,
                        source_probe,
                        object_probe,
                    ),
                )
            results.ok(
                "RED controls reject invented evidence, duplicate fixups, and boolean seeds"
            )

            exact_raw_reject = subprocess.CompletedProcess(
                args=["replay"],
                returncode=9,
                stdout="",
                stderr=(
                    "HDF5_RESULT classification=target_reject "
                    "stage=object_lookup reason=invalid_object\n"
                ),
            )
            wrong_stage_reject = subprocess.CompletedProcess(
                args=["replay"],
                returncode=9,
                stdout="",
                stderr=(
                    "HDF5_RESULT classification=target_reject "
                    "stage=file_image_open reason=invalid_image\n"
                ),
            )
            validate_raw_reject(exact_raw_reject)
            expect_failure(
                "raw corruption rejected at the wrong loader stage",
                lambda: validate_raw_reject(wrong_stage_reject),
            )
            results.ok("raw rejection is bound to the exact object_lookup stage")

            clean_raw_image = b"prefix-OHDR-object-suffix"
            exact_raw_image = b"prefix-XHDR-object-suffix"
            validate_raw_byte_diff(clean_raw_image, exact_raw_image)
            expect_failure(
                "raw corruption with an extra trailing byte",
                lambda: validate_raw_byte_diff(
                    clean_raw_image, exact_raw_image + b"Z"
                ),
            )
            results.ok("raw corruption permits exactly one OHDR O-to-X byte change")

            probe_line = "HDF5_MUTATION_INSPECT_OK " + " ".join(
                f"{key}={value}" for key, value in source_probe.items()
            )
            parsed_probe = parse_probe(probe_line + "\n", "")
            if parsed_probe != source_probe:
                fail("valid inspect line did not round-trip through the strict parser")

            valid_probes: dict[str, dict[str, str]] = {}
            valid_probes["object_names"] = object_probe
            valid_probes["shape_dtype"] = dict(source_probe)
            valid_probes["shape_dtype"]["dtype"] = "int32-le"
            valid_probes["shape_dtype"]["shape"] = "3x2"
            valid_probes["shape_dtype"]["values"] = "17,-18,19,-20,21,-22"
            valid_probes["payload"] = dict(source_probe)
            valid_probes["payload"]["values"] = "1.25,-2,3.5,4.25,-5.75,9"
            valid_probes["chunk_layout"] = dict(source_probe)
            valid_probes["chunk_layout"]["layout"] = "chunked"
            valid_probes["chunk_layout"]["chunks"] = "1x3"
            valid_probes["attributes"] = dict(source_probe)
            valid_probes["attributes"]["group_attr_value"] = "117"
            valid_probes["attributes"]["dataset_attr_value"] = "217"
            for operator, probe in valid_probes.items():
                validate_probe_change(operator, source_probe, probe)
            results.ok("strict probe accepts each operator's exact semantic mutation axis")

            group_only = dict(valid_probes["object_names"])
            group_only["dataset_hex"] = source_probe["dataset_hex"]
            one_attribute = dict(valid_probes["attributes"])
            one_attribute["dataset_attr_value"] = source_probe["dataset_attr_value"]
            unchanged_chunks = dict(source_probe)
            expect_failure(
                "object_names changed only the group",
                lambda: validate_probe_change("object_names", source_probe, group_only),
            )
            expect_failure(
                "attributes changed only one attribute",
                lambda: validate_probe_change(
                    "attributes", source_probe, one_attribute
                ),
            )
            expect_failure(
                "chunk_layout left layout and chunks unchanged",
                lambda: validate_probe_change(
                    "chunk_layout", source_probe, unchanged_chunks
                ),
            )
            results.ok(
                "RED controls reject group-only, one-attribute, and unchanged-chunk false positives"
            )

            inapplicable_output = root / "inapplicable.h5"
            copied = subprocess.CompletedProcess(
                args=["mutator"], returncode=0, stdout="HDF5_MUTATION_OK\n", stderr=""
            )
            expect_failure(
                "inapplicable copied as success",
                lambda: validate_inapplicable_result(
                    copied, inapplicable_output, "payload"
                ),
            )
            explicit = subprocess.CompletedProcess(
                args=["mutator"],
                returncode=3,
                stdout="",
                stderr="HDF5_MUTATION_INAPPLICABLE operator=payload reason=no_dataset\n",
            )
            validate_inapplicable_result(explicit, inapplicable_output, "payload")
            results.ok("RED control distinguishes explicit inapplicable from copied success")

            failed_output = root / "large-input.h5"
            oversized = subprocess.CompletedProcess(
                args=["mutator"],
                returncode=1,
                stdout="",
                stderr="HDF5_MUTATION_FAIL input exceeds 33554432 bytes\n",
            )
            validate_failed_result(oversized, failed_output, "exceeds 33554432 bytes")
            results.ok("RED control requires large-input failure without partial publication")
    except (ContractError, OSError, UnicodeError, ValueError) as error:
        results.bad(str(error))
    print(f"[{results.prefix}] pass={results.passed} fail={results.failed}")
    return 0 if results.failed == 0 else 1


def profile_tools(profile: dict[str, Any]) -> tuple[Path, Path, Path, Path]:
    toolchain = profile.get("toolchain")
    if not isinstance(toolchain, dict):
        fail("build profile has no toolchain object")
    cmake = Path(str(toolchain.get("cmake", {}).get("path", "")))
    c_compiler = Path(str(toolchain.get("c_compiler", {}).get("path", "")))
    recorded_cxx = Path(str(toolchain.get("cxx_compiler", {}).get("path", "")))
    cxx_compiler = recorded_cxx.with_name("clang++")
    ninja = Path(str(toolchain.get("ninja", {}).get("path", "")))
    for label, path in (
        ("cmake", cmake),
        ("C compiler", c_compiler),
        ("recorded C++ compiler", recorded_cxx),
        ("ninja", ninja),
    ):
        require_regular(path, f"pinned {label}", executable=True)
    if (
        not cxx_compiler.is_symlink()
        or not cxx_compiler.resolve().is_file()
        or not os.access(cxx_compiler, os.X_OK)
        or cxx_compiler.resolve() != recorded_cxx.resolve()
    ):
        fail("clang++ driver does not resolve to the pinned compiler bytes")
    return cmake, c_compiler, cxx_compiler, ninja


def run_mutation(
    wrapper: Path,
    tool: Path,
    source: Path,
    output: Path,
    operator: str,
    seed: int,
    *,
    expect: int = 0,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return run(
        [
            sys.executable,
            "-B",
            str(wrapper),
            "--tool",
            str(tool),
            "--input",
            str(source),
            "--output",
            str(output),
            "--operator",
            operator,
            "--seed",
            str(seed),
        ],
        expect=expect,
        env=env,
    )


def replay_lines(output: str, prefix: str) -> list[str]:
    return sorted(line for line in output.splitlines() if line.startswith(prefix))


def validate_replay_change(operator: str, source: str, mutated: str) -> None:
    source_datasets = replay_lines(source, "HDF5_DATASET ")
    output_datasets = replay_lines(mutated, "HDF5_DATASET ")
    source_attributes = replay_lines(source, "HDF5_ATTRIBUTE ")
    output_attributes = replay_lines(mutated, "HDF5_ATTRIBUTE ")
    if len(source_datasets) != 1 or len(output_datasets) != 1:
        fail(f"{operator} replay did not expose exactly one dataset")
    if "HDF5_ACCESS_OK datasets=1" not in mutated:
        fail(f"{operator} did not reach HDF-03 dataset access")
    if operator == "object_names":
        if source_datasets == output_datasets or source_attributes == output_attributes:
            fail("object_names did not expose changed group and dataset paths")
    elif operator == "shape_dtype":
        if source_datasets == output_datasets or not re.search(
            r" dtype=(?!float32-le)\S+ shape=(?!2,3)\S+", output_datasets[0]
        ):
            fail("shape_dtype did not expose changed dtype and shape")
    elif operator == "payload":
        before = re.sub(r" values=.*$", "", source_datasets[0])
        after = re.sub(r" values=.*$", "", output_datasets[0])
        if before != after or source_datasets == output_datasets:
            fail("payload changed structure or failed to change observed values")
    elif operator == "chunk_layout":
        if source_datasets != output_datasets:
            fail("chunk_layout unexpectedly changed HDF-03 semantic observations")
    elif operator == "attributes":
        if source_datasets != output_datasets or source_attributes == output_attributes:
            fail("attributes changed dataset semantics or left attributes unchanged")


def validate_source_contract(mutator: str, wrapper: str) -> None:
    for marker in (
        "H5Fcreate(",
        "H5Gcreate2(",
        "H5Dcreate2(",
        "H5Dwrite(",
        "H5Pset_obj_track_times(",
        "H5Pset_chunk(",
        "raw_object_header",
    ):
        if marker not in mutator:
            fail(f"native mutator omits required official-writer contract: {marker}")
    if "h5py" in wrapper:
        fail("wrapper must not replace the pinned native writer with h5py")
    for marker in ("subprocess.run", "manifest", "sha256"):
        if marker not in wrapper:
            fail(f"wrapper omits required orchestration contract: {marker}")
    if (
        "remove_owned" in wrapper
        or ".unlink(" in wrapper
        or "os.unlink(" in wrapper
        or "os.remove(" in wrapper
    ):
        fail("wrapper must not perform race-prone path-based rollback deletion")


def validate_publication_collision(wrapper_path: Path, work: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "hdf5_mutation_wrapper_collision_test", wrapper_path
    )
    if spec is None or spec.loader is None:
        fail("cannot load HDF-04 wrapper for publication-collision test")
    wrapper_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wrapper_module)

    staged_output = work / "collision-staged-output.h5"
    staged_manifest = work / "collision-staged-manifest.json"
    public_output = work / "collision-public-output.h5"
    public_manifest = work / "collision-public-output.h5.manifest.json"
    replacement = work / "collision-third-party-replacement"
    staged_output.write_bytes(b"owned-complete-output")
    staged_manifest.write_bytes(b"owned-complete-manifest")
    staged_output.chmod(0o600)
    staged_manifest.chmod(0o600)
    replacement_value = b"third-party-sentinel-must-survive"
    replacement.write_bytes(replacement_value)
    replacement.chmod(0o600)

    real_link = wrapper_module.os.link
    link_calls = 0

    def colliding_link(
        source: Path, destination: Path, *, follow_symlinks: bool
    ) -> None:
        nonlocal link_calls
        link_calls += 1
        if link_calls == 1:
            real_link(source, destination, follow_symlinks=follow_symlinks)
            os.replace(replacement, destination)
            return
        raise FileExistsError(17, "injected manifest-link collision", destination)

    wrapper_module.os.link = colliding_link
    try:
        try:
            wrapper_module.publish_pair(
                staged_output,
                public_output,
                staged_manifest,
                public_manifest,
            )
        except wrapper_module.MutationError:
            pass
        else:
            fail("publication collision unexpectedly succeeded")
    finally:
        wrapper_module.os.link = real_link

    if (
        link_calls != 2
        or not public_output.is_file()
        or public_output.is_symlink()
        or public_output.read_bytes() != replacement_value
        or public_manifest.exists()
        or public_manifest.is_symlink()
    ):
        fail("publication collision deleted or changed the third-party sentinel")


def actual(project: Path, target: Path) -> int:
    results = Results()
    required = {
        "HDF-04 native mutator": project / "harnesses/hdf5/structural_mutator.cc",
        "HDF-04 mutation test tool": project / "harnesses/hdf5/mutation_test_tool.cc",
        "HDF-04 wrapper": project / "scripts/mutate_hdf5_fixture.py",
        "HDF CMake source": project / "harnesses/hdf5/CMakeLists.txt",
        "HDF-02 fixture generator": project / "scripts/gen_hdf5_fixtures.py",
        "HDF-03 replay source": project / "harnesses/hdf5/replay.cc",
        "HDF-01 profile checker": project / "scripts/check_hdf5_profile.py",
        "pinned build profile": target / "build-profile.json",
    }
    missing = False
    for label, path in required.items():
        if not path.is_file() or path.is_symlink():
            results.bad(f"{label} is missing or not a regular file: {path}")
            missing = True
    if missing:
        print(f"[{results.prefix}] pass={results.passed} fail={results.failed}")
        return 1

    try:
        validate_source_contract(
            required["HDF-04 native mutator"].read_text(encoding="utf-8"),
            required["HDF-04 wrapper"].read_text(encoding="utf-8"),
        )
        results.ok("native source uses the official writer and keeps raw corruption separate")
        run(
            [
                sys.executable,
                "-B",
                str(required["HDF-01 profile checker"]),
                "--target-root",
                str(target),
            ]
        )
        profile = load_unique_json(required["pinned build profile"])
        cmake, c_compiler, cxx_compiler, ninja = profile_tools(profile)
        hdf5_dir = target / "install/lib/cmake/hdf5"
        require_regular(hdf5_dir / "hdf5-config.cmake", "pinned HDF5 CMake package")
        results.ok("official HDF5 2.2.0 profile and toolchain identity are valid")

        with tempfile.TemporaryDirectory(prefix="hdf5-mutation-check-") as temporary:
            work = Path(temporary)
            base = [
                str(cmake),
                "-S",
                str(project / "harnesses/hdf5"),
                "-G",
                "Ninja",
                "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                f"-DCMAKE_C_COMPILER={c_compiler}",
                f"-DCMAKE_CXX_COMPILER={cxx_compiler}",
                f"-DCMAKE_MAKE_PROGRAM={ninja}",
                f"-DHDF5_DIR={hdf5_dir}",
            ]
            default_build = work / "default-build"
            run([*base, "-B", str(default_build)])
            targets = run(
                [str(cmake), "--build", str(default_build), "--target", "help"]
            ).stdout
            for target_name in (
                "hdf5_structural_mutator",
                "hdf5_mutation_test_tool",
            ):
                if target_name in targets:
                    fail(
                        "default HDF-01 configure unexpectedly includes the "
                        f"HDF-04 target {target_name}"
                    )
            results.ok("default HDF-01 configure keeps HDF-04 targets disabled")

            build = work / "build"
            run(
                [
                    *base,
                    "-B",
                    str(build),
                    "-DHDF5_BUILD_FIXTURE_TOOL=ON",
                    "-DHDF5_BUILD_LOADER=ON",
                    "-DHDF5_BUILD_MUTATOR=ON",
                    "-DHDF5_BUILD_MUTATOR_TESTS=ON",
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
                    "hdf5_structural_mutator",
                    "hdf5_mutation_test_tool",
                ]
            )
            fixture_tool = build / "hdf5_fixture_tool"
            replay = build / "hdf5_loader_replay"
            mutator = build / "hdf5_structural_mutator"
            mutation_test_tool = build / "hdf5_mutation_test_tool"
            for label, path in (
                ("fixture tool", fixture_tool),
                ("HDF-03 replay", replay),
                ("HDF-04 mutator", mutator),
                ("HDF-04 mutation test tool", mutation_test_tool),
            ):
                require_regular(path, f"built {label}", executable=True)
            results.ok(
                "fixture, replay, opt-in mutator, and checker-only tool build together"
            )

            fixtures = work / "fixtures"
            run(
                [
                    sys.executable,
                    "-B",
                    str(required["HDF-02 fixture generator"]),
                    "--build-profile",
                    str(required["pinned build profile"]),
                    "--fixture-tool",
                    str(fixture_tool),
                    "generate",
                    "--output",
                    str(fixtures),
                ]
            )
            source = fixtures / "tensor-contiguous.h5"
            source_before = source.read_bytes()
            native_tool_before = mutator.read_bytes()
            source_replay = run([str(replay), str(source)]).stdout
            source_probe = inspect_image(mutation_test_tool, source)
            if source_probe != expected_fixture_probe():
                fail("mutation test tool did not expose the exact source fixture semantics")

            for index, operator in enumerate(OPERATORS):
                seed = 4200 + index
                first = work / f"{operator}-a.h5"
                second = work / f"{operator}-b.h5"
                first_run = run_mutation(
                    required["HDF-04 wrapper"], mutator, source, first, operator, seed
                )
                second_run = run_mutation(
                    required["HDF-04 wrapper"], mutator, source, second, operator, seed
                )
                mutation_class = (
                    "structure_preserving"
                    if operator in STRUCTURAL_OPERATORS
                    else "raw_corruption"
                )
                expected = "accept" if operator in STRUCTURAL_OPERATORS else "reject"
                marker = (
                    f"HDF5_MUTATION_OK operator={operator} mutation_class={mutation_class} "
                    f"expected_loader={expected}"
                )
                if marker not in first_run.stdout or marker not in second_run.stdout:
                    fail(f"{operator} omitted the exact result marker")
                first_manifest = first.with_name(first.name + ".manifest.json")
                second_manifest = second.with_name(second.name + ".manifest.json")
                if first.read_bytes() != second.read_bytes():
                    fail(f"{operator} output is nondeterministic")
                if first_manifest.read_bytes() != second_manifest.read_bytes():
                    fail(f"{operator} manifest is path- or time-dependent")
                output_probe = (
                    inspect_image(mutation_test_tool, first)
                    if operator in STRUCTURAL_OPERATORS
                    else None
                )
                validate_manifest(
                    first_manifest,
                    source_before,
                    first.read_bytes(),
                    native_tool_before,
                    operator,
                    seed,
                    source_probe if output_probe is not None else None,
                    output_probe,
                )
                if operator in STRUCTURAL_OPERATORS:
                    replayed = run([str(replay), str(first)]).stdout
                    validate_replay_change(operator, source_replay, replayed)
                else:
                    validate_raw_byte_diff(source_before, first.read_bytes())
                    rejected = run([str(replay), str(first)], expect=9)
                    combined = rejected.stdout + rejected.stderr
                    validate_raw_reject(rejected)
                    if re.search(
                        r"AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|Segmentation fault",
                        combined,
                    ):
                        fail("raw_object_header produced a fault marker")
                results.ok(
                    f"{operator} is deterministic, manifest-bound, and semantically exact"
                )

            default_driver_output = work / "driver-default-payload.h5"
            family_driver_output = work / "driver-family-payload.h5"
            driver_seed = 91
            run_mutation(
                required["HDF-04 wrapper"],
                mutator,
                source,
                default_driver_output,
                "payload",
                driver_seed,
            )
            family_environment = dict(os.environ)
            family_environment["HDF5_DRIVER"] = "family"
            run_mutation(
                required["HDF-04 wrapper"],
                mutator,
                source,
                family_driver_output,
                "payload",
                driver_seed,
                env=family_environment,
            )
            if (
                default_driver_output.read_bytes()
                != family_driver_output.read_bytes()
                or default_driver_output.with_name(
                    default_driver_output.name + ".manifest.json"
                ).read_bytes()
                != family_driver_output.with_name(
                    family_driver_output.name + ".manifest.json"
                ).read_bytes()
            ):
                fail("HDF5_DRIVER changed deterministic output or manifest bytes")
            results.ok("writer output is independent of inherited HDF5_DRIVER")

            extra_source = work / "source-with-extra-structure.h5"
            run(
                [
                    str(mutation_test_tool),
                    "add-extra",
                    str(source),
                    str(extra_source),
                ]
            )
            require_regular(extra_source, "extra-structure source")
            extra_output = work / "extra-structure-payload.h5"
            completed = run_mutation(
                required["HDF-04 wrapper"],
                mutator,
                extra_source,
                extra_output,
                "payload",
                7,
                expect=3,
            )
            validate_inapplicable_result(completed, extra_output, "payload")
            results.ok("source with extra structure is explicitly inapplicable")

            root_attribute_source = work / "source-with-root-attribute.h5"
            run(
                [
                    str(mutation_test_tool),
                    "add-root-attribute",
                    str(source),
                    str(root_attribute_source),
                ]
            )
            require_inspect_reject(
                mutation_test_tool,
                root_attribute_source,
                "root_attribute_contract_invalid",
            )
            results.ok("independent probe rejects unexpected root attributes")

            filtered_source = work / "source-with-fletcher32.h5"
            run([str(mutation_test_tool), "make-filtered", str(filtered_source)])
            require_inspect_reject(
                mutation_test_tool,
                filtered_source,
                "dataset_filters_unsupported",
            )
            results.ok("independent probe rejects unexpected dataset filters")

            external_storage_source = work / "source-with-external-storage.h5"
            external_storage_raw = work / "external-storage.raw"
            run(
                [
                    str(mutation_test_tool),
                    "make-external-storage",
                    str(external_storage_source),
                    str(external_storage_raw),
                ]
            )
            require_inspect_reject(
                mutation_test_tool,
                external_storage_source,
                "external_storage_unsupported",
            )
            for suffix in ("present", "absent"):
                if suffix == "absent":
                    external_storage_raw.rename(
                        external_storage_raw.with_name("external-storage-away.raw")
                    )
                external_output = work / f"external-storage-{suffix}-output.h5"
                external_completed = run_mutation(
                    required["HDF-04 wrapper"],
                    mutator,
                    external_storage_source,
                    external_output,
                    "payload",
                    9,
                    expect=3,
                )
                validate_inapplicable_result(
                    external_completed, external_output, "payload"
                )

            external_link_source = work / "source-with-external-link.h5"
            external_link_target = work / "external-link-target.h5"
            run(
                [
                    str(mutation_test_tool),
                    "make-external-link",
                    str(source),
                    str(external_link_source),
                    str(external_link_target),
                ]
            )
            require_inspect_reject(
                mutation_test_tool,
                external_link_source,
                "object_link_not_hard",
            )
            for suffix in ("present", "absent"):
                if suffix == "absent":
                    external_link_target.rename(
                        external_link_target.with_name("external-link-target-away.h5")
                    )
                external_output = work / f"external-link-{suffix}-output.h5"
                external_completed = run_mutation(
                    required["HDF-04 wrapper"],
                    mutator,
                    external_link_source,
                    external_output,
                    "payload",
                    9,
                    expect=3,
                )
                validate_inapplicable_result(
                    external_completed, external_output, "payload"
                )

            external_group_source = work / "source-with-external-group.h5"
            external_group_target = work / "external-group-target.h5"
            run(
                [
                    str(mutation_test_tool),
                    "make-external-group",
                    str(source),
                    str(external_group_source),
                    str(external_group_target),
                ]
            )
            require_inspect_reject(
                mutation_test_tool,
                external_group_source,
                "object_link_not_hard",
            )
            for suffix in ("present", "absent"):
                if suffix == "absent":
                    external_group_target.rename(
                        external_group_target.with_name("external-group-target-away.h5")
                    )
                external_output = work / f"external-group-{suffix}-output.h5"
                external_completed = run_mutation(
                    required["HDF-04 wrapper"],
                    mutator,
                    external_group_source,
                    external_output,
                    "payload",
                    9,
                    expect=3,
                )
                validate_inapplicable_result(
                    external_completed, external_output, "payload"
                )
            results.ok(
                "external storage, dataset links, and group links are inapplicable "
                "without outside-file reads"
            )

            array_attribute_source = work / "source-with-array-attribute.h5"
            run(
                [
                    str(mutation_test_tool),
                    "set-array-attribute",
                    str(source),
                    str(array_attribute_source),
                ]
            )
            require_inspect_reject(
                mutation_test_tool,
                array_attribute_source,
                "attribute_contract_invalid",
            )
            array_output = work / "array-attribute-output.h5"
            array_completed = run_mutation(
                required["HDF-04 wrapper"],
                mutator,
                array_attribute_source,
                array_output,
                "payload",
                9,
                expect=3,
            )
            validate_inapplicable_result(array_completed, array_output, "payload")
            results.ok("array attributes are rejected before scalar reads")

            nonfinite_source = work / "source-with-nonfinite-payload.h5"
            run(
                [
                    str(mutation_test_tool),
                    "set-nonfinite-payload",
                    str(source),
                    str(nonfinite_source),
                ]
            )
            nonfinite_output = work / "nonfinite-payload-output.h5"
            nonfinite_completed = run_mutation(
                required["HDF-04 wrapper"],
                mutator,
                nonfinite_source,
                nonfinite_output,
                "payload",
                0,
                expect=3,
            )
            validate_inapplicable_result(
                nonfinite_completed, nonfinite_output, "payload"
            )
            results.ok("non-finite payloads are explicitly inapplicable")

            large_payload_source = work / "source-with-large-payload.h5"
            run(
                [
                    str(mutation_test_tool),
                    "set-large-payload",
                    str(source),
                    str(large_payload_source),
                ]
            )
            large_payload_probe = inspect_image(
                mutation_test_tool, large_payload_source
            )
            large_payload_output = work / "large-payload-output.h5"
            run_mutation(
                required["HDF-04 wrapper"],
                mutator,
                large_payload_source,
                large_payload_output,
                "payload",
                0,
            )
            large_payload_output_probe = inspect_image(
                mutation_test_tool, large_payload_output
            )
            validate_manifest(
                large_payload_output.with_name(
                    large_payload_output.name + ".manifest.json"
                ),
                large_payload_source.read_bytes(),
                large_payload_output.read_bytes(),
                native_tool_before,
                "payload",
                0,
                large_payload_probe,
                large_payload_output_probe,
            )
            results.ok("large finite float payload changes by an observable value")

            custom_attributes = work / "source-attributes-41-73.h5"
            run(
                [
                    str(mutation_test_tool),
                    "set-attributes",
                    str(source),
                    str(custom_attributes),
                    "41",
                    "73",
                ]
            )
            require_regular(custom_attributes, "custom-attribute source")
            custom_probe = inspect_image(mutation_test_tool, custom_attributes)
            expected_custom_probe = expected_fixture_probe("41", "73")
            if custom_probe != expected_custom_probe:
                fail("set-attributes changed fields beyond the two requested values")
            custom_output = work / "attributes-from-41-73.h5"
            custom_seed = 73
            run_mutation(
                required["HDF-04 wrapper"],
                mutator,
                custom_attributes,
                custom_output,
                "attributes",
                custom_seed,
            )
            custom_manifest_path = custom_output.with_name(
                custom_output.name + ".manifest.json"
            )
            custom_output_probe = inspect_image(mutation_test_tool, custom_output)
            custom_document = validate_manifest(
                custom_manifest_path,
                custom_attributes.read_bytes(),
                custom_output.read_bytes(),
                native_tool_before,
                "attributes",
                custom_seed,
                custom_probe,
                custom_output_probe,
            )
            if (
                custom_document["before"]
                != "group:fixture_version:41;dataset:axis_count:73"
            ):
                fail("attributes manifest before evidence does not bind actual 41/73 values")
            validate_replay_change(
                "attributes",
                run([str(replay), str(custom_attributes)]).stdout,
                run([str(replay), str(custom_output)]).stdout,
            )
            validate_probe_change(
                "attributes",
                custom_probe,
                custom_output_probe,
            )
            results.ok(
                "attribute mutation derives evidence and both value changes from 41/73"
            )

            for group_value, dataset_value in ((173, 0), (173, 273)):
                collision_source = work / (
                    f"source-attributes-{group_value}-{dataset_value}.h5"
                )
                run(
                    [
                        str(mutation_test_tool),
                        "set-attributes",
                        str(source),
                        str(collision_source),
                        str(group_value),
                        str(dataset_value),
                    ]
                )
                collision_probe = inspect_image(
                    mutation_test_tool, collision_source
                )
                collision_output = work / (
                    f"attributes-from-{group_value}-{dataset_value}.h5"
                )
                run_mutation(
                    required["HDF-04 wrapper"],
                    mutator,
                    collision_source,
                    collision_output,
                    "attributes",
                    73,
                )
                collision_output_probe = inspect_image(
                    mutation_test_tool, collision_output
                )
                validate_manifest(
                    collision_output.with_name(
                        collision_output.name + ".manifest.json"
                    ),
                    collision_source.read_bytes(),
                    collision_output.read_bytes(),
                    native_tool_before,
                    "attributes",
                    73,
                    collision_probe,
                    collision_output_probe,
                )
            results.ok("attribute seed collisions still change both values")

            negative_seed_output = work / "native-negative-seed.h5"
            negative_seed = subprocess.run(
                [
                    str(mutator),
                    "--input",
                    str(source),
                    "--output",
                    str(negative_seed_output),
                    "--operator",
                    "payload",
                    "--seed",
                    "-1",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if (
                negative_seed.returncode != 1
                or negative_seed.stdout
                or "HDF5_NATIVE_MUTATION_FAIL" not in negative_seed.stderr
            ):
                fail(
                    "native negative seed did not use rc1/failure-marker contract: "
                    f"rc={negative_seed.returncode} stdout={negative_seed.stdout!r} "
                    f"stderr={negative_seed.stderr[-1000:]!r}"
                )
            if negative_seed_output.exists() or negative_seed_output.is_symlink():
                fail("native negative seed published an output")

            sentinel = b"preexisting-output-must-survive"
            preexisting_output = work / "native-preexisting.h5"
            preexisting_output.write_bytes(sentinel)
            preexisting = subprocess.run(
                [
                    str(mutator),
                    "--input",
                    str(source),
                    "--output",
                    str(preexisting_output),
                    "--operator",
                    "payload",
                    "--seed",
                    "7",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if (
                preexisting.returncode != 1
                or preexisting.stdout
                or "HDF5_NATIVE_MUTATION_FAIL" not in preexisting.stderr
            ):
                fail("native preexisting-output refusal did not use rc1")
            if preexisting_output.read_bytes() != sentinel:
                fail("native preexisting-output refusal changed the sentinel")
            results.ok("native rejects negative seeds and preserves preexisting output")

            wrapper_preexisting = work / "wrapper-preexisting.h5"
            wrapper_preexisting.write_bytes(sentinel)
            wrapper_refusal = run_mutation(
                required["HDF-04 wrapper"],
                mutator,
                source,
                wrapper_preexisting,
                "payload",
                7,
                expect=1,
            )
            if (
                "HDF5_MUTATION_FAIL" not in wrapper_refusal.stderr
                or wrapper_preexisting.read_bytes() != sentinel
                or wrapper_preexisting.with_name(
                    wrapper_preexisting.name + ".manifest.json"
                ).exists()
            ):
                fail("wrapper preexisting-output refusal damaged the sentinel")
            results.ok("wrapper preserves a preexisting output it does not own")

            validate_publication_collision(required["HDF-04 wrapper"], work)
            results.ok(
                "publication-link collision preserves a replacement third-party sentinel"
            )

            fake_native = work / "fake-partial-native.py"
            fake_native.write_text(
                "#!/usr/bin/env python3\n"
                "import hashlib\n"
                "import json\n"
                "import os\n"
                "from pathlib import Path\n"
                "import stat\n"
                "import sys\n"
                "tool = Path(sys.argv[0])\n"
                "input_path = Path(sys.argv[sys.argv.index('--input') + 1])\n"
                "output = Path(sys.argv[sys.argv.index('--output') + 1])\n"
                "record = {\n"
                "    'tool': str(tool), 'input': str(input_path), 'output': str(output),\n"
                "    'tool_sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),\n"
                "    'input_sha256': hashlib.sha256(input_path.read_bytes()).hexdigest(),\n"
                "    'tool_mode': stat.S_IMODE(tool.stat().st_mode),\n"
                "    'input_mode': stat.S_IMODE(input_path.stat().st_mode),\n"
                "}\n"
                "Path(os.environ['HDF5_FAKE_OUTPUT_LOG']).write_text(json.dumps(record), encoding='utf-8')\n"
                "output.write_bytes(b'partial-native-output')\n"
                "print('HDF5_NATIVE_MUTATION_FAIL reason=forced_failure', file=sys.stderr)\n"
                "raise SystemExit(1)\n",
                encoding="utf-8",
            )
            fake_native.chmod(0o700)
            fake_native_bytes = fake_native.read_bytes()
            fake_log = work / "fake-native-paths.json"
            requested_output = work / "fake-native-requested.h5"
            fake_environment = dict(os.environ)
            fake_environment["HDF5_FAKE_OUTPUT_LOG"] = str(fake_log)
            fake_completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(required["HDF-04 wrapper"]),
                    "--tool",
                    str(fake_native),
                    "--input",
                    str(source),
                    "--output",
                    str(requested_output),
                    "--operator",
                    "payload",
                    "--seed",
                    "7",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=fake_environment,
            )
            if (
                fake_completed.returncode != 1
                or "HDF5_MUTATION_FAIL" not in fake_completed.stderr
            ):
                fail("forced native failure did not propagate as wrapper rc1")
            require_regular(fake_log, "fake native output-path log")
            fake_record = json.loads(fake_log.read_text(encoding="utf-8"))
            if set(fake_record) != {
                "tool",
                "input",
                "output",
                "tool_sha256",
                "input_sha256",
                "tool_mode",
                "input_mode",
            }:
                fail("fake native path record fields are not exact")
            native_tool_path = Path(fake_record["tool"])
            native_input_path = Path(fake_record["input"])
            native_output_path = Path(fake_record["output"])
            if (
                native_tool_path == fake_native
                or native_input_path == source
                or native_output_path == requested_output
                or len(
                    {
                        native_tool_path.parent,
                        native_input_path.parent,
                        native_output_path.parent,
                    }
                )
                != 1
                or fake_record["tool_sha256"] != sha256_bytes(fake_native_bytes)
                or fake_record["input_sha256"] != sha256_bytes(source_before)
                or fake_record["tool_mode"] != 0o700
                or fake_record["input_mode"] != 0o600
            ):
                fail(
                    "wrapper did not execute immutable private copies of tool/input: "
                    f"{fake_record!r}"
                )
            requested_manifest = requested_output.with_name(
                requested_output.name + ".manifest.json"
            )
            if (
                requested_output.exists()
                or requested_output.is_symlink()
                or requested_manifest.exists()
                or requested_manifest.is_symlink()
                or native_tool_path.exists()
                or native_tool_path.is_symlink()
                or native_input_path.exists()
                or native_input_path.is_symlink()
                or native_output_path.exists()
                or native_output_path.is_symlink()
            ):
                fail("forced native failure left staged or published partial output")
            results.ok(
                "wrapper executes private tool/input copies and leaves no partial failure output"
            )

            for operator in OPERATORS:
                label = f"missing dataset for {operator}"
                inapplicable_output = work / f"inapplicable-missing-{operator}.h5"
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(required["HDF-04 wrapper"]),
                        "--tool",
                        str(mutator),
                        "--input",
                        str(fixtures / "missing-dataset.h5"),
                        "--output",
                        str(inapplicable_output),
                        "--operator",
                        operator,
                        "--seed",
                        "7",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                validate_inapplicable_result(completed, inapplicable_output, operator)
                results.ok(f"{label} exits explicitly without publishing output")

            for label, fixture, operator in (
                ("empty payload", "empty-numeric.h5", "payload"),
                ("absent attributes", "scalar-numeric.h5", "attributes"),
            ):
                inapplicable_output = work / (
                    f"inapplicable-{label.replace(' ', '-')}.h5"
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(required["HDF-04 wrapper"]),
                        "--tool",
                        str(mutator),
                        "--input",
                        str(fixtures / fixture),
                        "--output",
                        str(inapplicable_output),
                        "--operator",
                        operator,
                        "--seed",
                        "7",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                validate_inapplicable_result(completed, inapplicable_output, operator)
                results.ok(f"{label} exits explicitly without publishing output")

            oversized = work / "oversized-input.h5"
            with oversized.open("wb") as stream:
                stream.seek(32 * 1024 * 1024)
                stream.write(b"x")
            large_output = work / "oversized-output.h5"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(required["HDF-04 wrapper"]),
                    "--tool",
                    str(mutator),
                    "--input",
                    str(oversized),
                    "--output",
                    str(large_output),
                    "--operator",
                    "payload",
                    "--seed",
                    "7",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            validate_failed_result(completed, large_output, "exceeds 33554432 bytes")
            results.ok("oversized input fails before native mutation or partial publication")
            if source.read_bytes() != source_before:
                fail("HDF-04 mutated the source fixture in place")
            results.ok("source fixture remains byte-for-byte unchanged")
    except (ContractError, OSError, UnicodeError, ValueError) as error:
        results.bad(str(error))
    print(f"[{results.prefix}] pass={results.passed} fail={results.failed}")
    return 0 if results.failed == 0 else 1


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
    return actual(args.project_root.resolve(), args.target_root.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
