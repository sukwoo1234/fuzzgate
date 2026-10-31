#!/usr/bin/env python3
"""Run the pinned HDF5 structural writer and publish deterministic evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from typing import Any, NoReturn


MAX_INPUT_BYTES = 32 * 1024 * 1024
SCHEMA_VERSION = "hdf5-weights-mutation-v1"
GENERATOR_VERSION = "hdf5-weights-structural-mutator-v1"
TARGET_ID = "hdf5-weights"
STRUCTURAL_TARGET_API = "H5LTopen_file_image/H5Dread/H5Aread"
RAW_TARGET_API = "H5LTopen_file_image/H5Oget_info_by_name3"
STRUCTURAL_OPERATORS = {
    "object_names": "object.group_dataset_names",
    "shape_dtype": "dataset.shape_dtype",
    "payload": "dataset.payload",
    "chunk_layout": "dataset.chunk_layout",
    "attributes": "object.attributes",
}
OPERATORS = {**STRUCTURAL_OPERATORS, "raw_object_header": "dataset.object_header"}
NATIVE_KEYS = {
    "operator",
    "mutation_class",
    "field",
    "before",
    "after",
    "fixups",
    "expected_loader",
    "writer",
}


class MutationError(RuntimeError):
    """The native result or publication violates the HDF-04 contract."""


def fail(message: str) -> NoReturn:
    raise MutationError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_regular_bytes(
    path: Path,
    label: str,
    *,
    executable: bool = False,
    maximum: int | None = None,
    nonempty: bool = False,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"{label} is unavailable: {path}: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"{label} must be a regular non-symlink file: {path}")
        if executable and stat.S_IMODE(before.st_mode) & 0o111 == 0:
            fail(f"{label} is not executable: {path}")
        if maximum is not None and before.st_size > maximum:
            fail(f"{label} exceeds {maximum} bytes")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            value = handle.read()
        after = os.fstat(descriptor)
        try:
            current = path.lstat()
        except OSError as error:
            fail(f"{label} changed while it was read: {path}: {error}")
        identity = (before.st_dev, before.st_ino)
        if (
            identity != (after.st_dev, after.st_ino)
            or identity != (current.st_dev, current.st_ino)
            or not stat.S_ISREG(current.st_mode)
            or before.st_size != after.st_size
            or len(value) != after.st_size
        ):
            fail(f"{label} changed while it was read: {path}")
        if nonempty and not value:
            fail(f"{label} is empty")
        return value
    finally:
        os.close(descriptor)


def read_input(path: Path) -> bytes:
    return read_regular_bytes(
        path,
        "input image",
        maximum=MAX_INPUT_BYTES,
        nonempty=True,
    )


def ensure_fresh(output: Path, manifest: Path) -> None:
    if output.exists() or output.is_symlink():
        fail(f"output image path must be fresh: {output}")
    if manifest.exists() or manifest.is_symlink():
        fail(f"output manifest path must be fresh: {manifest}")
    parent = output.parent
    try:
        parent_status = parent.lstat()
    except OSError as error:
        fail(f"output parent is unavailable: {parent}: {error}")
    if not stat.S_ISDIR(parent_status.st_mode):
        fail(f"output parent must be a non-symlink directory: {parent}")


def single_line(value: str, label: str) -> str:
    lines = [line for line in value.splitlines() if line]
    if len(lines) != 1:
        fail(f"native {label} must contain exactly one non-empty line")
    return lines[0]


def parse_native_success(output: str, error_output: str) -> dict[str, str]:
    if error_output:
        fail("native success wrote unexpected stderr")
    line = single_line(output, "stdout")
    tokens = line.split()
    if not tokens or tokens[0] != "HDF5_NATIVE_MUTATION_OK":
        fail("native success marker is missing")
    fields: dict[str, str] = {}
    for token in tokens[1:]:
        if token.count("=") != 1:
            fail(f"native success token is malformed: {token!r}")
        key, value = token.split("=", 1)
        if key in fields:
            fail(f"native success repeats field {key!r}")
        if not key or not value:
            fail(f"native success has an empty field: {token!r}")
        fields[key] = value
    if set(fields) != NATIVE_KEYS:
        fail(
            "native success fields mismatch: "
            f"{sorted(fields)} != {sorted(NATIVE_KEYS)}"
        )
    return fields


def expected_contract(operator: str) -> dict[str, str]:
    structural = operator in STRUCTURAL_OPERATORS
    return {
        "operator": operator,
        "mutation_class": (
            "structure_preserving" if structural else "raw_corruption"
        ),
        "field": OPERATORS[operator],
        "expected_loader": "accept" if structural else "reject",
        "expected_stage": "complete" if structural else "object_lookup",
        "target_api": STRUCTURAL_TARGET_API if structural else RAW_TARGET_API,
        "writer": (
            "official-hdf5-2.2.0" if structural else "raw-byte-corruption"
        ),
    }


def validate_native_fields(fields: dict[str, str], operator: str) -> list[str]:
    expected = expected_contract(operator)
    for key in (
        "operator",
        "mutation_class",
        "field",
        "expected_loader",
        "writer",
    ):
        expected_value = expected[key]
        if fields.get(key) != expected_value:
            fail(
                f"native {key} mismatch: {fields.get(key)!r} != {expected_value!r}"
            )
    if fields["before"] == fields["after"]:
        fail("native before/after evidence records a no-op")
    fixups = fields["fixups"].split(",")
    if not fixups or any(not item for item in fixups) or len(set(fixups)) != len(fixups):
        fail("native fixup evidence is empty or duplicated")
    if operator in STRUCTURAL_OPERATORS:
        if "official_writer_reserialize" not in fixups:
            fail("structural mutation omits official-writer reserialization")
    elif "intentional_raw_corruption" not in fixups:
        fail("raw mutation omits intentional-corruption evidence")
    return fixups


def parse_native_inapplicable(
    completed: subprocess.CompletedProcess[str], operator: str
) -> str:
    if completed.stdout:
        fail("native inapplicable result wrote unexpected stdout")
    line = single_line(completed.stderr, "inapplicable stderr")
    prefix = f"HDF5_NATIVE_MUTATION_INAPPLICABLE operator={operator} reason="
    if not line.startswith(prefix) or len(line) == len(prefix):
        fail("native inapplicable marker is malformed")
    reason = line[len(prefix) :]
    if any(character.isspace() for character in reason):
        fail("native inapplicable reason must be one token")
    return reason


def write_private(
    path: Path, value: bytes, label: str, *, mode: int = 0o600
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        fail(f"cannot create fresh {label} {path}: {error}")
    status = os.fstat(descriptor)
    try:
        if not stat.S_ISREG(status.st_mode):
            fail(f"fresh {label} is not a regular file: {path}")
        os.fchmod(descriptor, mode)
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail(f"short write to {label} {path}")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    try:
        os.close(descriptor)
    except OSError as close_error:
        fail(f"cannot close fresh {label} {path}: {close_error}")


def publish_pair(
    staged_output: Path,
    output: Path,
    staged_manifest: Path,
    manifest: Path,
) -> None:
    staged: list[tuple[Path, Path, str, tuple[int, int]]] = []
    for source, destination, label in (
        (staged_output, output, "output image"),
        (staged_manifest, manifest, "output manifest"),
    ):
        try:
            source_status = source.lstat()
        except OSError as error:
            fail(f"cannot inspect staged {label} {source}: {error}")
        if not stat.S_ISREG(source_status.st_mode):
            fail(f"staged {label} is not a regular file: {source}")
        staged.append(
            (
                source,
                destination,
                label,
                (source_status.st_dev, source_status.st_ino),
            )
        )

    published: list[tuple[Path, str, tuple[int, int]]] = []
    for source, destination, label, identity in staged:
        try:
            os.link(source, destination, follow_symlinks=False)
        except OSError as error:
            detail = ""
            if published:
                detail = (
                    "; a complete previously published artifact was retained "
                    "because path-based rollback is unsafe"
                )
            fail(f"cannot publish fresh {label} {destination}: {error}{detail}")
        published.append((destination, label, identity))

    for destination, label, identity in published:
        try:
            current = destination.lstat()
        except OSError as error:
            fail(f"published {label} changed before verification: {error}")
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != identity
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            fail(f"published {label} was replaced before verification")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_descriptor = os.open(output.parent, directory_flags)
    except OSError as error:
        fail(f"cannot open output directory for sync: {error}")
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def manifest_for(
    source: bytes,
    output: bytes,
    operator: str,
    seed: int,
    native_tool: bytes,
    fields: dict[str, str],
    fixups: list[str],
) -> dict[str, Any]:
    expected = expected_contract(operator)
    return {
        "after": fields["after"],
        "before": fields["before"],
        "expected_loader": expected["expected_loader"],
        "expected_stage": expected["expected_stage"],
        "field": expected["field"],
        "fixups": fixups,
        "generator_version": GENERATOR_VERSION,
        "mutation_class": expected["mutation_class"],
        "native_tool": {
            "sha256": sha256_bytes(native_tool),
            "size": len(native_tool),
        },
        "operator": operator,
        "output": {"sha256": sha256_bytes(output), "size": len(output)},
        "schema_version": SCHEMA_VERSION,
        "seed": seed,
        "source": {"sha256": sha256_bytes(source), "size": len(source)},
        "target": TARGET_ID,
        "target_api": expected["target_api"],
        "writer": expected["writer"],
    }


def serialize_manifest(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--operator", required=True, choices=OPERATORS)
    parser.add_argument("--seed", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = args.output.with_name(args.output.name + ".manifest.json")
    if args.seed < 0 or args.seed > (1 << 64) - 1:
        print("HDF5_MUTATION_FAIL seed must be in 0..=2^64-1", file=sys.stderr)
        return 1
    try:
        tool_path = args.tool.absolute()
        native_tool = read_regular_bytes(
            tool_path, "native mutator", executable=True, nonempty=True
        )
        source = read_input(args.input)
        ensure_fresh(args.output, manifest_path)
        inapplicable_reason: str | None = None
        with tempfile.TemporaryDirectory(
            prefix=".hdf5-mutation-", dir=args.output.parent
        ) as temporary:
            staging_root = Path(temporary)
            directory_flags = os.O_RDONLY | os.O_CLOEXEC
            directory_flags |= getattr(os, "O_DIRECTORY", 0)
            directory_flags |= getattr(os, "O_NOFOLLOW", 0)
            directory_descriptor = os.open(staging_root, directory_flags)
            try:
                os.fchmod(directory_descriptor, 0o700)
                directory_status = os.fstat(directory_descriptor)
                if (
                    not stat.S_ISDIR(directory_status.st_mode)
                    or stat.S_IMODE(directory_status.st_mode) != 0o700
                ):
                    fail("private staging directory is not mode 0700")
            finally:
                os.close(directory_descriptor)
            staged_tool = staging_root / "native-mutator"
            staged_input = staging_root / "input.h5"
            native_output = staging_root / "native-output.h5"
            write_private(
                staged_tool, native_tool, "staged native mutator", mode=0o700
            )
            write_private(staged_input, source, "staged input image")
            try:
                completed = subprocess.run(
                    [
                        str(staged_tool),
                        "--input",
                        str(staged_input),
                        "--output",
                        str(native_output),
                        "--operator",
                        args.operator,
                        "--seed",
                        str(args.seed),
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=120,
                )
            except subprocess.TimeoutExpired as error:
                if (
                    read_regular_bytes(
                        staged_tool,
                        "staged native mutator",
                        executable=True,
                        nonempty=True,
                    )
                    != native_tool
                ):
                    fail("native mutator bytes changed during execution")
                if read_input(staged_input) != source:
                    fail("staged input image changed during mutation")
                fail(f"native mutator timed out after {error.timeout} seconds")

            if (
                read_regular_bytes(
                    staged_tool,
                    "staged native mutator",
                    executable=True,
                    nonempty=True,
                )
                != native_tool
            ):
                fail("native mutator bytes changed during execution")
            if read_input(staged_input) != source:
                fail("staged input image changed during mutation")

            if completed.returncode == 3:
                inapplicable_reason = parse_native_inapplicable(
                    completed, args.operator
                )
            elif completed.returncode != 0:
                detail = completed.stderr.strip().replace("\n", " | ")
                if not detail:
                    detail = "no native diagnostic"
                fail(f"native mutator returned {completed.returncode}: {detail}")
            else:
                fields = parse_native_success(completed.stdout, completed.stderr)
                fixups = validate_native_fields(fields, args.operator)
                output = read_regular_bytes(
                    native_output, "native output image", nonempty=True
                )
                if output == source:
                    fail("native output image is a no-op")
                document = manifest_for(
                    source,
                    output,
                    args.operator,
                    args.seed,
                    native_tool,
                    fields,
                    fixups,
                )
                manifest_value = serialize_manifest(document)

                staged_output = staging_root / "publish-output.h5"
                staged_manifest = staging_root / "publish-manifest.json"
                write_private(staged_output, output, "publishable output image")
                write_private(
                    staged_manifest,
                    manifest_value,
                    "publishable output manifest",
                )
                publish_pair(
                    staged_output,
                    args.output,
                    staged_manifest,
                    manifest_path,
                )

        if inapplicable_reason is not None:
            print(
                f"HDF5_MUTATION_INAPPLICABLE operator={args.operator} "
                f"reason={inapplicable_reason}",
                file=sys.stderr,
            )
            return 3
    except (MutationError, OSError, UnicodeError, ValueError) as error:
        print(f"HDF5_MUTATION_FAIL {error}", file=sys.stderr)
        return 1

    print(
        f"HDF5_MUTATION_OK operator={args.operator} "
        f"mutation_class={document['mutation_class']} "
        f"expected_loader={document['expected_loader']} "
        f"output_sha256={document['output']['sha256']} manifest={manifest_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
