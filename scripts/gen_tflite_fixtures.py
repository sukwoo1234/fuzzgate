#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


GENERATOR_VERSION = "tflite-fixtures-v1"
EXPECTED_TENSORFLOW_COMMIT = "72fbba3d20f4616d7312b5e2b7f79daf6e82f2fa"
EXPECTED_FLATBUFFERS_COMMIT = "e6463926479bd6b330cbcf673f7e917803fd5831"


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"[gen-tflite-fixtures] fail: {message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file(path: Path, label: str, executable: bool = False) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"{label} is not a readable regular file '{path}': {error}")
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular file, not a symlink: {path}")
    if executable and metadata.st_mode & 0o111 == 0:
        fail(f"{label} is not executable: {path}")


def load_unique_json(path: Path, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {label} '{path}': {error}")
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    return value


def flatbuffer_json(identity: bool) -> dict[str, object]:
    if identity:
        return {
            "version": 3,
            "operator_codes": [],
            "subgraphs": [{
                "tensors": [{
                    "shape": [1],
                    "type": "FLOAT32",
                    "buffer": 0,
                    "name": "identity",
                }],
                "inputs": [0],
                "outputs": [0],
                "operators": [],
                "name": "identity",
            }],
            "description": "tool deterministic identity fixture",
            "buffers": [{}],
        }
    return {
        "version": 3,
        "operator_codes": [{"builtin_code": "ADD", "version": 1}],
        "subgraphs": [{
            "tensors": [
                {"shape": [1], "type": "FLOAT32", "buffer": 0, "name": "input"},
                {"shape": [1], "type": "FLOAT32", "buffer": 1, "name": "weight"},
                {"shape": [1], "type": "FLOAT32", "buffer": 0, "name": "output"},
            ],
            "inputs": [0],
            "outputs": [2],
            "operators": [{
                "opcode_index": 0,
                "inputs": [0, 1],
                "outputs": [2],
                "builtin_options_type": "AddOptions",
                "builtin_options": {"fused_activation_function": "NONE"},
            }],
            "name": "add_constant",
        }],
        "description": "tool deterministic float32 constant ADD fixture",
        "buffers": [{}, {"data": [0, 0, 192, 63]}],
    }


def generate_flatbuffer(flatc: Path, schema: Path, staging: Path, name: str, document: dict[str, object]) -> None:
    json_path = staging / f"{name}.json"
    json_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    command = [
        str(flatc),
        "--binary",
        "--strict-json",
        "--filename-ext",
        "tflite",
        "-o",
        str(staging),
        str(schema),
        str(json_path),
    ]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        fail(f"flatc failed for {name}: {completed.stderr.strip()}")
    output = staging / f"{name}.tflite"
    regular_file(output, f"generated {name} fixture")
    json_path.unlink()


def expected_lines() -> dict[str, list[str]]:
    shape_192 = "1,8,8,3"
    return {
        "identity_float.tflite": [
            "TFLITE_TENSOR index=0 role=input_output name_hex=6964656e74697479 dtype=float32 shape=1 bytes=4 payload_hex=-",
            "TFLITE_ACCESS_OK tensors=1 constants=0 constant_bytes=0",
        ],
        "add_float.tflite": [
            f"TFLITE_TENSOR index=0 role=intermediate name_hex=616464 dtype=float32 shape={shape_192} bytes=768 payload_hex=-",
            f"TFLITE_TENSOR index=1 role=input name_hex=696e707574 dtype=float32 shape={shape_192} bytes=768 payload_hex=-",
            f"TFLITE_TENSOR index=2 role=output name_hex=6f7574707574 dtype=float32 shape={shape_192} bytes=768 payload_hex=-",
            "TFLITE_ACCESS_OK tensors=3 constants=0 constant_bytes=0",
        ],
        "add_int8.tflite": [
            f"TFLITE_TENSOR index=0 role=intermediate name_hex=616464 dtype=int8 shape={shape_192} bytes=192 payload_hex=-",
            f"TFLITE_TENSOR index=1 role=input name_hex=696e707574 dtype=int8 shape={shape_192} bytes=192 payload_hex=-",
            f"TFLITE_TENSOR index=2 role=output name_hex=6f7574707574 dtype=int8 shape={shape_192} bytes=192 payload_hex=-",
            "TFLITE_ACCESS_OK tensors=3 constants=0 constant_bytes=0",
        ],
        "add_constant_float.tflite": [
            "TFLITE_TENSOR index=0 role=input name_hex=696e707574 dtype=float32 shape=1 bytes=4 payload_hex=-",
            "TFLITE_TENSOR index=1 role=constant name_hex=776569676874 dtype=float32 shape=1 bytes=4 payload_hex=0000c03f",
            "TFLITE_TENSOR index=2 role=output name_hex=6f7574707574 dtype=float32 shape=1 bytes=4 payload_hex=-",
            "TFLITE_ACCESS_OK tensors=3 constants=1 constant_bytes=4",
        ],
        "multi_add_float.tflite": [
            *[
                f"TFLITE_TENSOR index={index} role=input name_hex={name.encode().hex()} dtype=float32 shape={shape_192} bytes=768 payload_hex=-"
                for index, name in enumerate(["a", "b", "c", "d"])
            ],
            f"TFLITE_TENSOR index=4 role=intermediate name_hex=69 dtype=float32 shape={shape_192} bytes=768 payload_hex=-",
            f"TFLITE_TENSOR index=5 role=output name_hex=78 dtype=float32 shape={shape_192} bytes=768 payload_hex=-",
            f"TFLITE_TENSOR index=6 role=output name_hex=79 dtype=float32 shape={shape_192} bytes=768 payload_hex=-",
            "TFLITE_ACCESS_OK tensors=7 constants=0 constant_bytes=0",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic pinned TFLite fixtures")
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--flatc", required=True, type=Path)
    parser.add_argument("--build-identity", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    flatc = args.flatc.resolve()
    identity_path = args.build_identity.resolve()
    output = args.output.absolute()
    regular_file(flatc, "flatc", executable=True)
    regular_file(identity_path, "build identity")
    identity = load_unique_json(identity_path, "build identity")
    source = identity.get("source")
    if not isinstance(source, dict) or source.get("resolved_commit") != EXPECTED_TENSORFLOW_COMMIT:
        fail("build identity does not pin TensorFlow v2.20.0")
    dependencies = identity.get("dependencies")
    if not isinstance(dependencies, list) or not any(
        isinstance(row, dict)
        and row.get("name") == "flatbuffers"
        and row.get("resolved_commit") == EXPECTED_FLATBUFFERS_COMMIT
        for row in dependencies
    ):
        fail("build identity does not pin the expected FlatBuffers commit")
    flatc_identity = identity.get("flatc")
    if not isinstance(flatc_identity, dict) or flatc_identity.get("path") != str(flatc):
        fail("flatc path does not match build identity")
    if flatc_identity.get("sha256") != sha256_file(flatc):
        fail("flatc sha256 does not match build identity")

    schema = source_root / "tensorflow/compiler/mlir/lite/schema/schema.fbs"
    regular_file(schema, "TFLite schema")
    official = source_root / "tensorflow/lite/testdata"
    copied = {
        "add_float.tflite": official / "add.bin",
        "add_int8.tflite": official / "add_quantized_int8.bin",
        "multi_add_float.tflite": official / "multi_add.bin",
    }
    for name, path in copied.items():
        regular_file(path, f"official fixture source for {name}")
    if output.exists():
        fail(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=f".{output.name}.new.", dir=output.parent) as temporary:
        staging = Path(temporary)
        generate_flatbuffer(flatc, schema, staging, "identity_float", flatbuffer_json(True))
        generate_flatbuffer(flatc, schema, staging, "add_constant_float", flatbuffer_json(False))
        for name, source_path in copied.items():
            shutil.copyfile(source_path, staging / name)

        oracles = expected_lines()
        order = [
            "identity_float.tflite",
            "add_float.tflite",
            "add_int8.tflite",
            "add_constant_float.tflite",
            "multi_add_float.tflite",
        ]
        fixtures = []
        for name in order:
            path = staging / name
            fixtures.append({
                "name": name,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
                "expected_lines": oracles[name],
                "constant_values": [{
                    "tensor_index": 1,
                    "dtype": "float32",
                    "shape": [1],
                    "values": [1.5],
                    "payload_hex": "0000c03f",
                }] if name == "add_constant_float.tflite" else [],
            })
        manifest = {
            "schema_version": "1",
            "generator_version": GENERATOR_VERSION,
            "generator_sha256": sha256_file(Path(__file__).resolve()),
            "seed": 0,
            "tensorflow_commit": EXPECTED_TENSORFLOW_COMMIT,
            "flatbuffers_commit": EXPECTED_FLATBUFFERS_COMMIT,
            "flatc_sha256": sha256_file(flatc),
            "schema_sha256": sha256_file(schema),
            "fixtures": fixtures,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.rename(staging, output)
    print(f"[gen-tflite-fixtures] output={output} fixtures=5")
    return 0


if __name__ == "__main__":
    sys.exit(main())
