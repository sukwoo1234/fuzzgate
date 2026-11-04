#!/usr/bin/env python3
"""Create the immutable HDF-07 Q10/Q11 corpus from HDF-02 fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


VERSION = "2.2.0"
RESOLVED_COMMIT = "49df1b4e5ca4108d56e80f06321a749da1535268"
ARCHIVE_SHA256 = "1a1ab8209b35586fbc1aa279ba76d102130b95badcb20ca329587219112d8c16"
ARCHIVE_SIZE = 42131403
FIXTURES: dict[str, tuple[str, str]] = {
    "scalar-numeric.h5": ("normal", "accepted"),
    "empty-numeric.h5": ("normal", "accepted"),
    "tensor-contiguous.h5": ("normal", "accepted"),
    "tensor-chunked.h5": ("normal", "accepted"),
    "missing-dataset.h5": ("reject", "absent"),
    "truncated-image.h5": ("reject", "file_rejected"),
    "invalid-metadata.h5": ("reject", "metadata_rejected"),
    "unsupported-filter.h5": ("unsupported", "unsupported_filter"),
    "unsupported-dtype.h5": ("unsupported", "unsupported_dtype"),
    "external-link.h5": ("unsupported", "external_reference"),
}


class CorpusError(RuntimeError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CorpusError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_private(path: Path, label: str, maximum: int = 128 * 1024 * 1024) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CorpusError(f"could not inspect {label}: {path}: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum
    ):
        raise CorpusError(f"{label} must be a bounded private regular file: {path}")
    value = path.read_bytes()
    if len(value) != metadata.st_size:
        raise CorpusError(f"{label} changed while being read: {path}")
    return value


def exclusive_write(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build(fixture_index: Path, output: Path) -> tuple[Path, str]:
    if not fixture_index.is_absolute() or not output.is_absolute():
        raise CorpusError("fixture index and output directory must be absolute")
    if output.exists() or output.is_symlink():
        raise CorpusError(f"output already exists: {output}")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as error:
        raise CorpusError(f"output parent is unavailable: {error}") from error
    if parent != output.parent:
        raise CorpusError("output parent must be canonical")
    source_root = fixture_index.parent
    if source_root.resolve(strict=True) != source_root:
        raise CorpusError("fixture directory must be canonical")
    payload = read_private(fixture_index, "HDF-02 fixture manifest", 16 * 1024 * 1024)
    try:
        document = json.loads(payload, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise CorpusError(f"invalid fixture manifest: {error}") from error
    if not isinstance(document, dict):
        raise CorpusError("fixture manifest must be a JSON object")
    if (
        document.get("schema_version") != "hdf5-weights-fixture-manifest-v1"
        or document.get("target_id") != "hdf5-weights"
        or document.get("target_version") != VERSION
        or document.get("hdf5_source")
        != {
            "version": VERSION,
            "resolved_commit": RESOLVED_COMMIT,
            "archive_sha256": ARCHIVE_SHA256,
            "archive_size_bytes": ARCHIVE_SIZE,
        }
    ):
        raise CorpusError("fixture manifest target/version identity mismatch")
    raw_rows = document.get("fixtures")
    if not isinstance(raw_rows, list):
        raise CorpusError("fixture rows are missing")
    rows_by_name: dict[str, dict[str, Any]] = {}
    for row in raw_rows:
        if not isinstance(row, dict) or not isinstance(row.get("file"), str):
            raise CorpusError("fixture row is invalid")
        name = row["file"]
        if name in rows_by_name:
            raise CorpusError(f"duplicate fixture row: {name}")
        rows_by_name[name] = row
    if set(rows_by_name) != set(FIXTURES):
        raise CorpusError("fixture inventory mismatch")

    output.mkdir(mode=0o700)
    performance_rows: list[dict[str, Any]] = []
    throughput_order = 0
    latency_order = 0
    for name, (classification, api_outcome) in FIXTURES.items():
        row = rows_by_name[name]
        if (
            row.get("classification") != classification
            or row.get("expected_api_outcome") != api_outcome
        ):
            raise CorpusError(f"fixture contract mismatch: {name}")
        fixture_payload = read_private(source_root / name, f"fixture {name}")
        observed = digest_bytes(fixture_payload)
        if row.get("sha256") != observed or row.get("size_bytes") != len(fixture_payload):
            raise CorpusError(f"fixture identity mismatch: {name}")
        exclusive_write(output / name, fixture_payload)
        accepted = classification == "normal"
        if accepted:
            throughput_order += 1
            latency_order += 1
        performance_rows.append(
            {
                "path": name,
                "sha256": observed,
                "expected_outcome": "accepted" if accepted else "rejected",
                "expected_exit_code": 0 if accepted else 9,
                "target_api_stage": "target-parser",
                "minimum_target_api_calls": 1,
                "required_api_events": ["ReadNumericDatasets"],
                "zero_call_reason": None,
                "throughput_order_index": throughput_order if accepted else None,
                "throughput_exclusion_reason": None
                if accepted
                else "rejection-only correctness case",
                "latency_probe_order_index": latency_order if accepted else None,
                "latency_exclusion_reason": None
                if accepted
                else "rejection-only correctness case",
            }
        )
    index = {"schema_version": "format-performance-corpus-v1", "inputs": performance_rows}
    index_payload = (
        json.dumps(index, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode()
    index_path = output / "index.json"
    exclusive_write(index_path, index_payload)
    aggregate = digest_bytes(
        (
            json.dumps(
                {row["path"]: row["sha256"] for row in performance_rows},
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
    )
    return index_path, aggregate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-index", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        index, aggregate = build(args.fixture_index.absolute(), args.output_dir.absolute())
        print(
            "HDF5_PERFORMANCE_CORPUS_OK=yes "
            f"index={index} corpus_sha256={aggregate} inputs={len(FIXTURES)}"
        )
    except (CorpusError, OSError, ValueError) as error:
        print(f"[hdf5-performance-corpus] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
