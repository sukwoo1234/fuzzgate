#!/usr/bin/env python3
"""Generate and verify deterministic HDF-02 fixtures with official HDF5 APIs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, NoReturn


GENERATOR_VERSION = "hdf5-weights-fixtures-v1"
MANIFEST_SCHEMA = "hdf5-weights-fixture-manifest-v1"
TARGET_ID = "hdf5-weights"
TARGET_VERSION = "2.2.0"
SOURCE_COMMIT = "49df1b4e5ca4108d56e80f06321a749da1535268"
SOURCE_SHA256 = "1a1ab8209b35586fbc1aa279ba76d102130b95badcb20ca329587219112d8c16"
SOURCE_SIZE = 42131403


class FixtureError(RuntimeError):
    """The pinned identity or generated fixture set violates HDF-02."""


def fail(message: str) -> NoReturn:
    raise FixtureError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def require_regular(path: Path, label: str, *, executable: bool = False) -> None:
    try:
        path.lstat()
    except OSError as error:
        fail(f"{label} is unavailable: {path}: {error}")
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")
    if executable and not os.access(path, os.X_OK):
        fail(f"{label} is not executable: {path}")


def validate_component_paths(profile: dict[str, Any], profile_root: Path) -> None:
    root = profile_root.resolve()
    components = profile.get("components")
    if not isinstance(components, dict):
        fail("build profile component identity is missing")
    for role in ("core", "high_level"):
        row = components.get(role)
        if not isinstance(row, dict):
            fail(f"build profile component is missing: {role}")
        component = Path(str(row.get("path", ""))).resolve()
        try:
            component.relative_to(root)
        except ValueError:
            fail(f"pinned {role} library escapes the HDF5 target root: {component}")


def fixture_contracts() -> list[dict[str, Any]]:
    return [
        {
            "fixture_id": "scalar-numeric",
            "file": "scalar-numeric.h5",
            "classification": "normal",
            "expected_api_outcome": "accepted",
            "expected": {
                "group_paths": ["/weights"],
                "dataset": {
                    "path": "/weights/scalar",
                    "state": "present_nonempty",
                    "dtype": "int64-le",
                    "shape": [],
                    "element_count": 1,
                    "limited_values": [7],
                },
                "layout": {"class": "contiguous", "chunk_shape": None, "filters": []},
                "attributes": [],
                "external_reference": None,
                "rejection": None,
            },
        },
        {
            "fixture_id": "empty-numeric",
            "file": "empty-numeric.h5",
            "classification": "normal",
            "expected_api_outcome": "accepted",
            "expected": {
                "group_paths": ["/weights"],
                "dataset": {
                    "path": "/weights/empty",
                    "state": "present_empty",
                    "dtype": "float32-le",
                    "shape": [0, 3],
                    "element_count": 0,
                    "limited_values": [],
                },
                "layout": {"class": "contiguous", "chunk_shape": None, "filters": []},
                "attributes": [],
                "external_reference": None,
                "rejection": None,
            },
        },
        {
            "fixture_id": "tensor-contiguous",
            "file": "tensor-contiguous.h5",
            "classification": "normal",
            "expected_api_outcome": "accepted",
            "expected": {
                "group_paths": ["/weights"],
                "dataset": {
                    "path": "/weights/kernel",
                    "state": "present_nonempty",
                    "dtype": "float32-le",
                    "shape": [2, 3],
                    "element_count": 6,
                    "limited_values": [1.25, -2.0, 3.5, 4.25, -5.75, 6.0],
                },
                "layout": {"class": "contiguous", "chunk_shape": None, "filters": []},
                "attributes": [
                    {"object": "/weights", "name": "fixture_version", "dtype": "int32-le", "value": 1},
                    {"object": "/weights/kernel", "name": "axis_count", "dtype": "int32-le", "value": 2},
                ],
                "external_reference": None,
                "rejection": None,
            },
        },
        {
            "fixture_id": "tensor-chunked",
            "file": "tensor-chunked.h5",
            "classification": "normal",
            "expected_api_outcome": "accepted",
            "expected": {
                "group_paths": ["/weights"],
                "dataset": {
                    "path": "/weights/chunked",
                    "state": "present_nonempty",
                    "dtype": "int16-le",
                    "shape": [3, 2],
                    "element_count": 6,
                    "limited_values": [-3, 0, 7, 11, 1024, -2048],
                },
                "layout": {"class": "chunked", "chunk_shape": [2, 2], "filters": []},
                "attributes": [],
                "external_reference": None,
                "rejection": None,
            },
        },
        {
            "fixture_id": "missing-dataset",
            "file": "missing-dataset.h5",
            "classification": "reject",
            "expected_api_outcome": "absent",
            "expected": {
                "group_paths": ["/weights"],
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
                "external_reference": None,
                "rejection": {"stage": "dataset_lookup", "reason": "required_dataset_absent"},
            },
        },
        {
            "fixture_id": "truncated-image",
            "file": "truncated-image.h5",
            "classification": "reject",
            "expected_api_outcome": "file_rejected",
            "expected": {
                "group_paths": None,
                "dataset": {
                    "path": "/weights/kernel",
                    "state": "uninspectable",
                    "dtype": None,
                    "shape": None,
                    "element_count": None,
                    "limited_values": None,
                },
                "layout": None,
                "attributes": [],
                "external_reference": None,
                "rejection": {"stage": "H5LTopen_file_image", "reason": "truncated_to_64_bytes"},
            },
        },
        {
            "fixture_id": "invalid-metadata",
            "file": "invalid-metadata.h5",
            "classification": "reject",
            "expected_api_outcome": "metadata_rejected",
            "expected": {
                "group_paths": ["/weights"],
                "dataset": {
                    "path": "/weights/kernel",
                    "state": "corrupt_object_header",
                    "dtype": None,
                    "shape": None,
                    "element_count": None,
                    "limited_values": None,
                },
                "layout": None,
                "attributes": [],
                "external_reference": None,
                "rejection": {
                    "stage": "H5Dopen2",
                    "reason": "dataset_object_header_signature_corrupted",
                },
            },
        },
        {
            "fixture_id": "unsupported-filter",
            "file": "unsupported-filter.h5",
            "classification": "unsupported",
            "expected_api_outcome": "unsupported_filter",
            "expected": {
                "group_paths": ["/weights"],
                "dataset": {
                    "path": "/weights/filtered",
                    "state": "present_nonempty_unreadable",
                    "dtype": "int32-le",
                    "shape": [4],
                    "element_count": 4,
                    "limited_values": None,
                },
                "layout": {
                    "class": "chunked",
                    "chunk_shape": [4],
                    "filters": [
                        {
                            "id": 32024,
                            "availability": "unavailable",
                            "declaration_flags": ["optional"],
                            "stored_chunk_filter_mask": 0,
                            "stored_chunk_encoding": "little-endian-int32",
                            "stored_chunk_values": [10, 20, 30, 40],
                        }
                    ],
                },
                "attributes": [],
                "external_reference": None,
                "rejection": {"stage": "dataset_read", "reason": "filter_32024_unavailable"},
            },
        },
        {
            "fixture_id": "unsupported-dtype",
            "file": "unsupported-dtype.h5",
            "classification": "unsupported",
            "expected_api_outcome": "unsupported_dtype",
            "expected": {
                "group_paths": ["/weights"],
                "dataset": {
                    "path": "/weights/vlen_text",
                    "state": "present_unsupported_dtype",
                    "dtype": "variable-length-string",
                    "shape": [1],
                    "element_count": 1,
                    "limited_values": None,
                },
                "layout": {"class": "contiguous", "chunk_shape": None, "filters": []},
                "attributes": [],
                "external_reference": None,
                "rejection": {"stage": "dtype_policy", "reason": "variable_length_dtype"},
            },
        },
        {
            "fixture_id": "external-link",
            "file": "external-link.h5",
            "classification": "unsupported",
            "expected_api_outcome": "external_reference",
            "expected": {
                "group_paths": ["/weights"],
                "dataset": {
                    "path": "/weights/external",
                    "state": "external_link",
                    "dtype": None,
                    "shape": None,
                    "element_count": None,
                    "limited_values": None,
                },
                "layout": None,
                "attributes": [],
                "external_reference": {
                    "kind": "external_link",
                    "filename": "outside-payload.h5",
                    "object_path": "/payload",
                    "outside_access_required": True,
                    "outside_file_in_fixture_set": False,
                },
                "rejection": {"stage": "external_reference_policy", "reason": "outside_file_access"},
            },
        },
    ]


def validate_build_profile(path: Path) -> dict[str, Any]:
    require_regular(path, "HDF5 build profile")
    profile = load_unique_json(path)
    if profile.get("schema_version") != "hdf5-weights-build-profile-v1":
        fail("build profile schema mismatch")
    if profile.get("target_id") != TARGET_ID or profile.get("target_version") != TARGET_VERSION:
        fail("build profile does not pin hdf5-weights 2.2.0")
    if (
        profile.get("status") != "provisioned"
        or profile.get("execution_profile_ready") is not False
        or profile.get("next_card") != "HDF-02"
    ):
        fail("HDF-02 requires the provisioned, not execution-ready, HDF-01 profile")
    sources = profile.get("source_artifacts")
    if not isinstance(sources, list) or len(sources) != 1 or not isinstance(sources[0], dict):
        fail("build profile source identity is incomplete")
    source = sources[0]
    expected_source = {
        "name": "hdf5",
        "resolved_commit": SOURCE_COMMIT,
        "sha256": SOURCE_SHA256,
        "size_bytes": SOURCE_SIZE,
        "tag": TARGET_VERSION,
    }
    for key, value in expected_source.items():
        if source.get(key) != value:
            fail(f"build profile HDF5 source field differs: {key}")
    validate_component_paths(profile, path.parent)
    components = profile["components"]
    for role in ("core", "high_level"):
        row = components.get(role)
        if not isinstance(row, dict):
            fail(f"build profile component is missing: {role}")
        component = Path(str(row.get("path", "")))
        require_regular(component, f"pinned {role} library")
        if row.get("sha256") != sha256_file(component):
            fail(f"pinned {role} library hash mismatch")
    filters = profile.get("filter_contract")
    if not isinstance(filters, dict) or filters.get("dynamic_plugin_loading") is not False:
        fail("build profile must keep dynamic HDF5 plugin loading disabled")
    if filters.get("deflate") != "unsupported-build-disabled":
        fail("build profile no longer marks deflate unsupported")
    return profile


def tool_environment(profile: dict[str, Any]) -> dict[str, str]:
    components = profile["components"]
    library_dir = str(Path(components["core"]["path"]).parent)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("HDF5_") and key not in {"LD_AUDIT", "LD_PRELOAD"}
    }
    environment["LD_LIBRARY_PATH"] = library_dir
    environment["HDF5_PLUGIN_PATH"] = ""
    return environment


def expected_marker_lines() -> list[str]:
    return [
        f"HDF5_FIXTURE id={row['fixture_id']} class={row['classification']} "
        f"outcome={row['expected_api_outcome']}"
        for row in fixture_contracts()
    ] + ["HDF5_FIXTURE_SET_OK normal=4 reject=3 unsupported=3"]


def run_tool(tool: Path, command: str, output: Path, profile: dict[str, Any]) -> str:
    completed = subprocess.run(
        [str(tool), command, str(output)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=tool_environment(profile),
    )
    if completed.returncode != 0:
        fail(
            f"fixture tool {command} failed with rc={completed.returncode}: "
            f"stdout={completed.stdout[-2000:]!r} stderr={completed.stderr[-2000:]!r}"
        )
    lines = completed.stdout.strip().splitlines()
    if command == "generate":
        if lines != ["HDF5_FIXTURE_GENERATED count=10"]:
            fail(f"unexpected fixture generation marker: {lines!r}")
    elif lines != expected_marker_lines():
        fail(f"official HDF5 verification markers differ: {lines!r}")
    return completed.stdout


def build_manifest(output: Path, profile_path: Path) -> dict[str, Any]:
    generator = Path(__file__).resolve()
    tool_source = generator.parent.parent / "harnesses/hdf5/fixture_tool.cc"
    require_regular(tool_source, "HDF-02 fixture tool source")
    rows = []
    for contract in fixture_contracts():
        path = output / contract["file"]
        require_regular(path, f"fixture {contract['fixture_id']}")
        row = dict(contract)
        row["sha256"] = sha256_file(path)
        row["size_bytes"] = path.stat().st_size
        rows.append(row)
    return {
        "schema_version": MANIFEST_SCHEMA,
        "target_id": TARGET_ID,
        "target_version": TARGET_VERSION,
        "generator_version": GENERATOR_VERSION,
        "generator_sha256": sha256_file(generator),
        "fixture_tool_source_sha256": sha256_file(tool_source),
        "build_profile_sha256": sha256_file(profile_path),
        "hdf5_source": {
            "version": TARGET_VERSION,
            "resolved_commit": SOURCE_COMMIT,
            "archive_sha256": SOURCE_SHA256,
            "archive_size_bytes": SOURCE_SIZE,
        },
        "api_contract": {
            "writer": "official HDF5 2.2.0 C API",
            "verifier": "H5LTopen_file_image plus official HDF5 2.2.0 C API",
            "file_image_flags": 0,
            "dynamic_plugin_loading": False,
        },
        "reproducibility": {
            "identity": "byte-sha256",
            "object_track_times": False,
            "two_clean_generations_required": True,
            "normalized_fallback_used": False,
        },
        "license": {
            "status": "project-authored-unlicensed-test-data",
            "provenance": "deterministic local HDF5 API construction; no upstream fixture bytes",
            "upstream_fixture_bytes": False,
        },
        "fixtures": rows,
    }


def verify_output(output: Path, profile_path: Path, profile: dict[str, Any], tool: Path) -> None:
    try:
        status = output.lstat()
    except OSError as error:
        fail(f"fixture output is unavailable: {output}: {error}")
    if not output.is_dir() or output.is_symlink() or status.st_mode == 0:
        fail(f"fixture output must be a non-symlink directory: {output}")
    manifest_path = output / "manifest.json"
    require_regular(manifest_path, "fixture manifest")
    actual = load_unique_json(manifest_path)
    expected = build_manifest(output, profile_path)
    if actual != expected:
        actual_rows = actual.get("fixtures")
        if isinstance(actual_rows, list):
            expected_rows = expected["fixtures"]
            for index, expected_row in enumerate(expected_rows):
                if index >= len(actual_rows) or actual_rows[index] != expected_row:
                    fail(f"fixture manifest mismatch for {expected_row['fixture_id']}")
        fail("fixture manifest does not match the deterministic HDF-02 contract")
    actual_files = sorted(path.name for path in output.iterdir())
    expected_files = sorted(["manifest.json", *[row["file"] for row in fixture_contracts()]])
    if actual_files != expected_files:
        fail(f"fixture output file set mismatch: {actual_files!r}")
    run_tool(tool, "verify", output, profile)


def generate(output: Path, profile_path: Path, profile: dict[str, Any], tool: Path) -> None:
    output = output.absolute()
    if output.exists() or output.is_symlink():
        fail(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.new.", dir=output.parent) as temporary:
        staging = Path(temporary)
        run_tool(tool, "generate", staging, profile)
        manifest = build_manifest(staging, profile_path)
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        verify_output(staging, profile_path, profile, tool)
        os.rename(staging, output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-profile", required=True, type=Path)
    parser.add_argument("--fixture-tool", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("generate", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        profile_path = args.build_profile.resolve()
        tool = args.fixture_tool.resolve()
        profile = validate_build_profile(profile_path)
        require_regular(tool, "HDF-02 fixture tool", executable=True)
        if args.command == "generate":
            generate(args.output, profile_path, profile, tool)
            print("[gen-hdf5-fixtures] output=" f"{args.output.absolute()} fixtures=10")
        else:
            verify_output(args.output.resolve(), profile_path, profile, tool)
            print("[gen-hdf5-fixtures] verified=" f"{args.output.resolve()} fixtures=10")
    except (FixtureError, OSError, UnicodeError, ValueError) as error:
        print(f"[gen-hdf5-fixtures] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
