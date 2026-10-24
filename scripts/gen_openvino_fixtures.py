#!/usr/bin/env python3
"""Generate and verify deterministic OVI-02 XML+BIN FZB1 fixtures."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from typing import Any, NoReturn


GENERATOR_VERSION = "openvino-ir-fixtures-v1"
INDEX_SCHEMA = "openvino-ir-fixture-index-v1"
EXPECTED_VERSION = "2026.4.1"
EXPECTED_COMMIT = "e213a14725769a6a2bf86fc86650aa78a9c05d3e"
EXPECTED_SOURCE_SHA256 = "1ee85264556025486a4745a2d452ea823c578b3d162768bfef590366d2e6c539"
EXPECTED_FILES = [
    "constant-one.fzb",
    "constant-two.fzb",
    "empty-weights.fzb",
    "missing-bin.fzb",
    "truncated-weights.fzb",
    "malformed-xml.fzb",
]


class FixtureError(RuntimeError):
    """The pinned identity or generated fixture set violates OVI-02."""


def fail(message: str) -> NoReturn:
    raise FixtureError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
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
        fail(f"invalid JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def require_regular(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"{label} is unavailable: {path}: {error}")
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")
    if metadata.st_size < 0:
        fail(f"{label} has an invalid size: {path}")


def import_bundle_codec() -> Any:
    path = Path(__file__).resolve().with_name("model_bundle.py")
    require_regular(path, "FZB1 codec")
    specification = importlib.util.spec_from_file_location("model_bundle", path)
    if specification is None or specification.loader is None:
        fail(f"cannot import FZB1 codec: {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def validate_build_profile(path: Path) -> None:
    require_regular(path, "OpenVINO build profile")
    profile = load_unique_json(path)
    if profile.get("schema_version") != "openvino-ir-build-profile-v1":
        fail("build profile schema mismatch")
    if profile.get("target_id") != "openvino-ir" or profile.get("target_version") != EXPECTED_VERSION:
        fail("build profile does not pin openvino-ir 2026.4.1")
    if profile.get("status") != "provisioned" or profile.get("execution_profile_ready") is not False:
        fail("build profile must be provisioned and explicitly not execution-ready")
    sources = profile.get("source_artifacts")
    if not isinstance(sources, list):
        fail("build profile has no source artifact list")
    source = next(
        (row for row in sources if isinstance(row, dict) and row.get("name") == "openvino"),
        None,
    )
    if source is None or source.get("tag") != EXPECTED_VERSION:
        fail("build profile has no pinned OpenVINO 2026.4.1 source")
    if source.get("resolved_commit") != EXPECTED_COMMIT or source.get("sha256") != EXPECTED_SOURCE_SHA256:
        fail("build profile OpenVINO source identity mismatch")
    components = profile.get("components")
    if not isinstance(components, dict):
        fail("build profile has no component identity")
    for role in ("core", "ir_frontend", "probe"):
        row = components.get(role)
        if not isinstance(row, dict):
            fail(f"build profile component is missing: {role}")
        component = Path(str(row.get("path", "")))
        require_regular(component, f"pinned {role} component")
        expected_sha = row.get("sha256")
        if not isinstance(expected_sha, str) or sha256_file(component) != expected_sha:
            fail(f"pinned {role} component hash mismatch")


def constant_xml() -> bytes:
    return b"""<net name="ovi02-add-constant" version="11">
    <layers>
        <layer name="input" type="Parameter" id="0" version="opset1">
            <data element_type="f32" shape="1"/>
            <output><port id="0" precision="FP32"><dim>1</dim></port></output>
        </layer>
        <layer name="weight" type="Const" id="1" version="opset1">
            <data element_type="f32" shape="1" offset="0" size="4"/>
            <output><port id="0" precision="FP32"><dim>1</dim></port></output>
        </layer>
        <layer name="add" type="Add" id="2" version="opset1">
            <data auto_broadcast="numpy"/>
            <input>
                <port id="0" precision="FP32"><dim>1</dim></port>
                <port id="1" precision="FP32"><dim>1</dim></port>
            </input>
            <output><port id="2" precision="FP32"><dim>1</dim></port></output>
        </layer>
        <layer name="output" type="Result" id="3" version="opset1">
            <input><port id="0" precision="FP32"><dim>1</dim></port></input>
        </layer>
    </layers>
    <edges>
        <edge from-layer="0" from-port="0" to-layer="2" to-port="0"/>
        <edge from-layer="1" from-port="0" to-layer="2" to-port="1"/>
        <edge from-layer="2" from-port="2" to-layer="3" to-port="0"/>
    </edges>
</net>
"""


def empty_weights_xml() -> bytes:
    return b"""<net name="ovi02-empty-weights" version="11">
    <layers>
        <layer name="input" type="Parameter" id="0" version="opset1">
            <data element_type="f32" shape="1"/>
            <output><port id="0" precision="FP32"><dim>1</dim></port></output>
        </layer>
        <layer name="output" type="Result" id="1" version="opset1">
            <input><port id="0" precision="FP32"><dim>1</dim></port></input>
        </layer>
    </layers>
    <edges><edge from-layer="0" from-port="0" to-layer="1" to-port="0"/></edges>
</net>
"""


def fixture_specs(codec: Any) -> list[dict[str, Any]]:
    xml = constant_xml()
    empty_xml = empty_weights_xml()
    malformed_xml = xml.removesuffix(b"</net>\n")
    definitions = [
        (
            "constant-one.fzb",
            [("model.xml", xml), ("model.bin", struct.pack("<f", 1.5))],
            "accept",
            "OPENVINO_FIXTURE_OK nodes=4 parameters=1 results=1 constants=1 "
            "constant_bytes=4 constant_hex=0000c03f",
            "same-xml-constant-pair",
        ),
        (
            "constant-two.fzb",
            [("model.xml", xml), ("model.bin", struct.pack("<f", -2.25))],
            "accept",
            "OPENVINO_FIXTURE_OK nodes=4 parameters=1 results=1 constants=1 "
            "constant_bytes=4 constant_hex=000010c0",
            "same-xml-constant-pair",
        ),
        (
            "empty-weights.fzb",
            [("model.xml", empty_xml), ("model.bin", b"")],
            "accept",
            "OPENVINO_FIXTURE_OK nodes=2 parameters=1 results=1 constants=0 "
            "constant_bytes=0 constant_hex=-",
            "empty-bin-present",
        ),
        (
            "missing-bin.fzb",
            [("model.xml", xml)],
            "wrapper_reject",
            None,
            "missing-bin-no-fallback",
        ),
        (
            "truncated-weights.fzb",
            [("model.xml", xml), ("model.bin", struct.pack("<f", 1.5)[:3])],
            "frontend_reject",
            None,
            "truncated-constant-bin",
        ),
        (
            "malformed-xml.fzb",
            [("model.xml", malformed_xml), ("model.bin", struct.pack("<f", 1.5))],
            "frontend_reject",
            None,
            "malformed-ir-xml",
        ),
    ]
    specs: list[dict[str, Any]] = []
    for name, entries, outcome, marker, purpose in definitions:
        bundle = codec.encode_bundle(entries)
        ordered = sorted(entries, key=lambda entry: entry[0].encode("ascii"))
        specs.append(
            {
                "name": name,
                "bytes": bundle,
                "index": {
                    "name": name,
                    "purpose": purpose,
                    "expected_outcome": outcome,
                    "expected_marker": marker,
                    "sha256": sha256_bytes(bundle),
                    "size_bytes": len(bundle),
                    "entries": [
                        {
                            "name": entry_name,
                            "sha256": sha256_bytes(data),
                            "size_bytes": len(data),
                        }
                        for entry_name, data in ordered
                    ],
                },
            }
        )
    return specs


def expected_index(codec: Any) -> dict[str, Any]:
    generator = Path(__file__).resolve()
    bundle_codec = generator.with_name("model_bundle.py")
    return {
        "schema_version": INDEX_SCHEMA,
        "generator_version": GENERATOR_VERSION,
        "generator_sha256": sha256_file(generator),
        "bundle_codec_sha256": sha256_file(bundle_codec),
        "bundle_format": "FZB1",
        "required_entries": ["model.bin", "model.xml"],
        "limits": {"bundle_bytes": 64 * 1024 * 1024, "xml_bytes": 8 * 1024 * 1024},
        "license": {
            "status": "project-authored-unlicensed-test-data",
            "provenance": "deterministic local templates; no upstream fixture bytes",
            "upstream_fixture_bytes": False,
        },
        "openvino_source": {
            "version": EXPECTED_VERSION,
            "resolved_commit": EXPECTED_COMMIT,
            "archive_sha256": EXPECTED_SOURCE_SHA256,
        },
        "seed": 0,
        "fixtures": [spec["index"] for spec in fixture_specs(codec)],
    }


def verify_output(output: Path, codec: Any) -> None:
    try:
        metadata = output.lstat()
    except OSError as error:
        fail(f"fixture output is unavailable: {output}: {error}")
    if not output.is_dir() or output.is_symlink() or metadata.st_mode == 0:
        fail(f"fixture output must be a non-symlink directory: {output}")
    index_path = output / "index.json"
    require_regular(index_path, "fixture index")
    actual_index = load_unique_json(index_path)
    expected = expected_index(codec)
    if actual_index != expected:
        actual_rows = actual_index.get("fixtures")
        expected_rows = expected["fixtures"]
        if isinstance(actual_rows, list):
            for position, expected_row in enumerate(expected_rows):
                if position >= len(actual_rows) or actual_rows[position] != expected_row:
                    fail(f"fixture index mismatch for {expected_row['name']}")
        fail("fixture index does not match the deterministic OVI-02 contract")
    actual_files = sorted(
        path.name
        for path in output.iterdir()
        if path.is_file() and not path.is_symlink()
    )
    expected_files = sorted(["index.json", *EXPECTED_FILES])
    if actual_files != expected_files:
        fail(f"fixture output file set mismatch: {actual_files!r}")
    for spec in fixture_specs(codec):
        path = output / spec["name"]
        require_regular(path, spec["name"])
        if path.read_bytes() != spec["bytes"]:
            fail(f"generated bytes differ for {spec['name']}")
        entries = codec.decode_bundle(path.read_bytes())
        if [name for name, _ in entries] != [row["name"] for row in spec["index"]["entries"]]:
            fail(f"decoded entry order differs for {spec['name']}")


def generate(output: Path, codec: Any) -> None:
    output = output.absolute()
    if output.exists() or output.is_symlink():
        fail(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.new.", dir=output.parent) as temporary:
        staging = Path(temporary)
        for spec in fixture_specs(codec):
            (staging / spec["name"]).write_bytes(spec["bytes"])
        (staging / "index.json").write_text(
            json.dumps(expected_index(codec), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        verify_output(staging, codec)
        os.rename(staging, output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-profile", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("generate", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        validate_build_profile(args.build_profile.resolve())
        codec = import_bundle_codec()
        if args.command == "generate":
            generate(args.output, codec)
            print(f"[gen-openvino-fixtures] output={args.output.absolute()} fixtures={len(EXPECTED_FILES)}")
        else:
            verify_output(args.output.resolve(), codec)
            print(f"[gen-openvino-fixtures] verified={args.output.resolve()} fixtures={len(EXPECTED_FILES)}")
    except (FixtureError, OSError, UnicodeError, ValueError) as error:
        print(f"[gen-openvino-fixtures] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
