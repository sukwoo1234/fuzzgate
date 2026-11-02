#!/usr/bin/env python3
"""Validate the HDF-06 HDF5-only support boundary and its negative controls."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys
from typing import Any, Callable


EXPECTED_FILTER_CONTRACT = {
    "built_in_filters": ["shuffle", "fletcher32", "nbit", "scaleoffset"],
    "deflate": "unsupported-build-disabled",
    "dynamic_plugin_loading": False,
    "external_support": "NO",
    "szip": "unsupported-build-disabled",
}

EXPECTED_TARGET_SPEC = {
    "schema_version": "1",
    "target_id": "hdf5-weights",
    "seed_subdir": "hdf5-weights",
    "input_ext": "h5",
    "storage_name": "hdf5-weights",
    "coverage_env_key": "TOOL_COVERAGE_HDF5_CMD",
    "coverage_runner": "scripts/run_coverage_hdf5.sh",
    "external_harness_env": "TOOL_HDF5_WEIGHTS_HARNESS_CMD",
    "mutation_supported": False,
    "campaign_supported": False,
    "ui_supported": False,
    "support_scope": "profile-backend",
}

EXPECTED_EXECUTION_SCOPE = {
    "schema_version": "1",
    "target_id": "hdf5-weights",
    "format_revision": "hdf5-2.2.0-numeric-datasets-v1",
    "loader_id": "hdf5-file-image-numeric-dataset",
    "loader_version": "2.2.0",
    "input_kind": {
        "kind": "single",
        "extensions": ["h5"],
        "subformats": ["numeric-dataset"],
    },
    "depth": "read-numeric-datasets",
    "engine_capabilities": [
        {
            "backend": "local-harness",
            "binary_role": "replay",
            "required_mode": "native",
            "instrumentation_scope": "hdf5-core+high-level-file-image",
        }
    ],
    "coverage_scope": {
        "unit": "source-line",
        "include_sources": [
            "src/H5Fio.c",
            "src/H5Dio.c",
            "src/H5Dchunk.c",
            "src/H5Z.c",
            "src/H5Zshuffle.c",
            "src/H5Zfletcher32.c",
        ],
        "exclude_sources": [],
    },
}


class ScopeError(RuntimeError):
    """The HDF5-only integration boundary was widened or mislabeled."""


def fail(message: str) -> None:
    raise ScopeError(message)


def load_object(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root must be an object: {path}")
    return value


def assert_no_keras_claim(value: Any, label: str) -> None:
    rendered = json.dumps(value, sort_keys=True).lower()
    if "keras" in rendered:
        fail(f"{label} must not claim Keras support")


def validate_scope(
    target_spec: dict[str, Any],
    build_profile: dict[str, Any],
    execution_profile: dict[str, Any],
) -> None:
    if target_spec != EXPECTED_TARGET_SPEC:
        fail("target spec differs from the HDF5-only unqualified capability boundary")
    assert_no_keras_claim(target_spec, "target spec")

    if build_profile.get("target_id") != "hdf5-weights":
        fail("build profile target_id must remain hdf5-weights")
    if build_profile.get("status") != "provisioned":
        fail("HDF-06 must not promote the HDF-01 build profile status")
    if build_profile.get("execution_profile_ready") is not False:
        fail("the immutable HDF-01 build profile must remain non-execution-ready")
    if build_profile.get("filter_contract") != EXPECTED_FILTER_CONTRACT:
        fail("build-disabled or unverified filters were mislabeled as supported")
    assert_no_keras_claim(build_profile, "build profile")

    for key, expected in EXPECTED_EXECUTION_SCOPE.items():
        if execution_profile.get(key) != expected:
            fail(f"execution profile {key} exceeds or differs from the HDF-06 scope")
    assert_no_keras_claim(execution_profile, "execution profile")


def valid_documents() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    build = {
        "target_id": "hdf5-weights",
        "status": "provisioned",
        "execution_profile_ready": False,
        "filter_contract": copy.deepcopy(EXPECTED_FILTER_CONTRACT),
    }
    execution = copy.deepcopy(EXPECTED_EXECUTION_SCOPE)
    return copy.deepcopy(EXPECTED_TARGET_SPEC), build, execution


def run_selftest() -> int:
    passed = 0
    failed = 0

    def expect_reject(label: str, mutate: Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], None]) -> None:
        nonlocal passed, failed
        spec, build, execution = valid_documents()
        mutate(spec, build, execution)
        try:
            validate_scope(spec, build, execution)
        except ScopeError as error:
            passed += 1
            print(f"[hdf5-scope-selftest] PASS {label}: {error}")
        else:
            failed += 1
            print(f"[hdf5-scope-selftest] RED {label}: invalid claim was accepted", file=sys.stderr)

    spec, build, execution = valid_documents()
    try:
        validate_scope(spec, build, execution)
        passed += 1
        print("[hdf5-scope-selftest] PASS valid HDF5-only boundary")
    except ScopeError as error:
        failed += 1
        print(f"[hdf5-scope-selftest] RED valid boundary: {error}", file=sys.stderr)

    expect_reject(
        "Keras target alias",
        lambda spec, _build, _execution: spec.__setitem__("target_id", "keras-v3"),
    )
    expect_reject(
        "Keras loader claim",
        lambda _spec, _build, execution: execution.__setitem__("loader_id", "keras-load-model"),
    )
    expect_reject(
        "deflate support claim",
        lambda _spec, build, _execution: build["filter_contract"].__setitem__("deflate", "supported"),
    )
    expect_reject(
        "SZIP support claim",
        lambda _spec, build, _execution: build["filter_contract"].__setitem__("szip", "supported"),
    )
    expect_reject(
        "dynamic plugin support claim",
        lambda _spec, build, _execution: build["filter_contract"].__setitem__("dynamic_plugin_loading", True),
    )
    expect_reject(
        "campaign promotion",
        lambda spec, _build, _execution: spec.__setitem__("campaign_supported", True),
    )
    expect_reject(
        "UI launch promotion",
        lambda spec, _build, _execution: spec.__setitem__("ui_supported", True),
    )

    print(f"[hdf5-scope-selftest] pass={passed} fail={failed}")
    return 0 if failed == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--target-spec", type=pathlib.Path)
    parser.add_argument("--build-profile", type=pathlib.Path)
    parser.add_argument("--execution-profile", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.selftest:
        return run_selftest()
    if not all((args.target_spec, args.build_profile, args.execution_profile)):
        print("[hdf5-scope] fail: all three document paths are required", file=sys.stderr)
        return 2
    try:
        validate_scope(
            load_object(args.target_spec),
            load_object(args.build_profile),
            load_object(args.execution_profile),
        )
    except ScopeError as error:
        print(f"[hdf5-scope] fail: {error}", file=sys.stderr)
        return 1
    print("[hdf5-scope] pass=1 fail=0 target=hdf5-weights keras_supported=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
