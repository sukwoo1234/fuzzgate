#!/usr/bin/env python3
"""Create the immutable OVI-07 Q10/Q11 corpus from OVI-02 fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


VERSION = "2026.4.1"
RESOLVED_COMMIT = "e213a14725769a6a2bf86fc86650aa78a9c05d3e"
ARCHIVE_SHA256 = "1ee85264556025486a4745a2d452ea823c578b3d162768bfef590366d2e6c539"
FIXTURES: dict[str, tuple[str, str]] = {
    "constant-one.fzb": ("accept", "same-xml-constant-pair"),
    "constant-two.fzb": ("accept", "same-xml-constant-pair"),
    "empty-weights.fzb": ("accept", "empty-bin-present"),
    "missing-bin.fzb": ("wrapper_reject", "missing-bin-no-fallback"),
    "truncated-weights.fzb": ("frontend_reject", "truncated-constant-bin"),
    "malformed-xml.fzb": ("frontend_reject", "malformed-ir-xml"),
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


def read_index(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = read_private(path, "OVI-02 fixture index", 16 * 1024 * 1024)
    try:
        value = json.loads(payload, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise CorpusError(f"invalid fixture index: {error}") from error
    if not isinstance(value, dict):
        raise CorpusError("fixture index must be a JSON object")
    return value, payload


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
    document, _payload = read_index(fixture_index)
    if (
        document.get("schema_version") != "openvino-ir-fixture-index-v1"
        or document.get("bundle_format") != "FZB1"
        or document.get("openvino_source")
        != {
            "version": VERSION,
            "resolved_commit": RESOLVED_COMMIT,
            "archive_sha256": ARCHIVE_SHA256,
        }
    ):
        raise CorpusError("fixture index target/version identity mismatch")
    raw_rows = document.get("fixtures")
    if not isinstance(raw_rows, list):
        raise CorpusError("fixture index rows are missing")
    rows_by_name: dict[str, dict[str, Any]] = {}
    for row in raw_rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise CorpusError("fixture index row is invalid")
        name = row["name"]
        if name in rows_by_name:
            raise CorpusError(f"duplicate fixture row: {name}")
        rows_by_name[name] = row
    if set(rows_by_name) != set(FIXTURES):
        raise CorpusError("fixture index inventory mismatch")

    output.mkdir(mode=0o700)
    performance_rows: list[dict[str, Any]] = []
    throughput_order = 0
    latency_order = 0
    try:
        for name in FIXTURES:
            expected_outcome, purpose = FIXTURES[name]
            row = rows_by_name[name]
            if row.get("expected_outcome") != expected_outcome or row.get("purpose") != purpose:
                raise CorpusError(f"fixture contract mismatch: {name}")
            source_path = source_root / name
            payload = read_private(source_path, f"fixture {name}")
            observed = digest_bytes(payload)
            if row.get("sha256") != observed or row.get("size_bytes") != len(payload):
                raise CorpusError(f"fixture identity mismatch: {name}")
            exclusive_write(output / name, payload)
            accepted = expected_outcome == "accept"
            if accepted:
                throughput_order += 1
                latency_order += 1
            pre_parser = expected_outcome == "wrapper_reject"
            performance_rows.append(
                {
                    "path": name,
                    "sha256": observed,
                    "expected_outcome": "accepted" if accepted else "rejected",
                    "expected_exit_code": 0 if accepted else 9,
                    "target_api_stage": "pre-parser-reject"
                    if pre_parser
                    else "target-parser",
                    "minimum_target_api_calls": 0 if pre_parser else 1,
                    "required_api_events": []
                    if pre_parser
                    else ["ReadValidateConstants"],
                    "zero_call_reason": "FZB1 required-entry rejection"
                    if pre_parser
                    else None,
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
        index = {
            "schema_version": "format-performance-corpus-v1",
            "inputs": performance_rows,
        }
        index_payload = (
            json.dumps(index, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
            + "\n"
        ).encode("utf-8")
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
            ).encode("utf-8")
        )
        return index_path, aggregate
    except Exception:
        # The new directory is never reused after a partial build. Leave it in
        # place as evidence and require a fresh destination on the next attempt.
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-index", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        index, aggregate = build(args.fixture_index.absolute(), args.output_dir.absolute())
        print(
            "OPENVINO_PERFORMANCE_CORPUS_OK=yes "
            f"index={index} corpus_sha256={aggregate} inputs={len(FIXTURES)}"
        )
    except (CorpusError, OSError, ValueError) as error:
        print(f"[openvino-performance-corpus] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
