#!/usr/bin/env python3
"""Create, inspect, and safely stage deterministic FZB1 model bundles."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
from typing import Iterable, Sequence


MAGIC = b"FZBNDL1\0"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 64
MAX_NAME_BYTES = 240
MAX_NAME_DEPTH = 8
EXIT_INPUT_REJECTED = 9


class BundleError(ValueError):
    """An input violates the FZB1 framing or staging contract."""


def _validate_name_bytes(raw: bytes) -> str:
    if not 1 <= len(raw) <= MAX_NAME_BYTES:
        raise BundleError(f"FZB1 entry name length must be 1..={MAX_NAME_BYTES} bytes")
    if not raw.isascii():
        raise BundleError("FZB1 entry name must be ASCII")
    name = raw.decode("ascii")
    segments = name.split("/")
    if len(segments) > MAX_NAME_DEPTH:
        raise BundleError(f"FZB1 entry name depth must be <= {MAX_NAME_DEPTH}")
    for segment in segments:
        if not segment or segment in (".", ".."):
            raise BundleError("FZB1 entry name contains a non-canonical segment")
        if any(not (byte.isalnum() or byte in "_.-") for byte in segment):
            raise BundleError("FZB1 entry name contains a forbidden byte")
    return name


def _take(blob: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    end = offset + length
    if end > len(blob):
        raise BundleError(f"truncated FZB1 {label}")
    return blob[offset:end], end


def decode_bundle(blob: bytes) -> list[tuple[str, bytes]]:
    if len(blob) > MAX_BUNDLE_BYTES:
        raise BundleError(f"FZB1 input exceeds the {MAX_BUNDLE_BYTES}-byte limit")
    offset = 0
    magic, offset = _take(blob, offset, len(MAGIC), "magic")
    if magic != MAGIC:
        raise BundleError("invalid FZB1 magic")
    raw_count, offset = _take(blob, offset, 4, "entry count")
    count = struct.unpack("<I", raw_count)[0]
    if not 1 <= count <= MAX_ENTRIES:
        raise BundleError(f"FZB1 entry count must be 1..={MAX_ENTRIES}")

    entries: list[tuple[str, bytes]] = []
    previous: bytes | None = None
    seen: set[bytes] = set()
    for _ in range(count):
        raw_name_len, offset = _take(blob, offset, 2, "entry name length")
        raw_data_len, offset = _take(blob, offset, 8, "entry data length")
        name_len = struct.unpack("<H", raw_name_len)[0]
        data_len = struct.unpack("<Q", raw_data_len)[0]
        raw_name, offset = _take(blob, offset, name_len, "entry name")
        name = _validate_name_bytes(raw_name)
        if previous is not None:
            if raw_name == previous:
                raise BundleError(f"duplicate FZB1 entry name: {name}")
            if raw_name < previous:
                raise BundleError(f"FZB1 entries are not in canonical byte order: {name}")
        if any(raw_name[:index] in seen for index, byte in enumerate(raw_name) if byte == ord("/")):
            raise BundleError("FZB1 entry names conflict as file and directory")
        data, offset = _take(blob, offset, data_len, "entry data")
        entries.append((name, data))
        previous = raw_name
        seen.add(raw_name)
    if offset != len(blob):
        raise BundleError("trailing bytes after the final FZB1 entry")
    return entries


def require_allowlist(
    entries: Sequence[tuple[str, bytes]], allowlist: Iterable[str]
) -> None:
    allowed: set[str] = set()
    count = 0
    for name in allowlist:
        if count == MAX_ENTRIES:
            raise BundleError(f"FZB1 allowlist size must be 1..={MAX_ENTRIES}")
        _validate_name_bytes(name.encode("ascii", errors="strict"))
        count += 1
        if name in allowed:
            raise BundleError(f"duplicate FZB1 allowlist entry: {name}")
        allowed.add(name)
    if not 1 <= count <= MAX_ENTRIES:
        raise BundleError(f"FZB1 allowlist size must be 1..={MAX_ENTRIES}")
    actual = {name for name, _ in entries}
    if actual != allowed:
        missing = sorted(allowed - actual)
        unexpected = sorted(actual - allowed)
        raise BundleError(
            f"FZB1 entries do not match target allowlist "
            f"(missing: {missing!r}, unexpected: {unexpected!r})"
        )


def encode_bundle(entries: Iterable[tuple[str, bytes]]) -> bytes:
    ordered: list[tuple[str, bytes]] = []
    for entry in entries:
        if len(ordered) == MAX_ENTRIES:
            raise BundleError(f"FZB1 entry count must be 1..={MAX_ENTRIES}")
        ordered.append(entry)
    if not ordered:
        raise BundleError(f"FZB1 entry count must be 1..={MAX_ENTRIES}")
    for name, data in ordered:
        _validate_name_bytes(name.encode("ascii", errors="strict"))
        if not isinstance(data, bytes):
            raise BundleError(f"FZB1 content for {name!r} must be bytes")
    ordered.sort(key=lambda entry: entry[0].encode("ascii"))
    seen_names: set[str] = set()
    for name, _ in ordered:
        if name in seen_names:
            raise BundleError(f"duplicate FZB1 entry name: {name}")
        if any(name[:index] in seen_names for index, byte in enumerate(name) if byte == "/"):
            raise BundleError("FZB1 entry names conflict as file and directory")
        seen_names.add(name)

    total = len(MAGIC) + 4
    for name, data in ordered:
        total += 2 + 8 + len(name) + len(data)
        if total > MAX_BUNDLE_BYTES:
            raise BundleError(f"FZB1 output exceeds the {MAX_BUNDLE_BYTES}-byte limit")
    output = bytearray(MAGIC)
    output += struct.pack("<I", len(ordered))
    for name, data in ordered:
        raw_name = name.encode("ascii")
        output += struct.pack("<HQ", len(raw_name), len(data))
        output += raw_name
        output += data
    return bytes(output)


def _read_regular(path: Path, max_bytes: int = MAX_BUNDLE_BYTES) -> bytes:
    if max_bytes < 0:
        raise BundleError(f"no FZB1 capacity remains for input {str(path)!r}")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise BundleError(f"cannot open regular input {str(path)!r}: {error}") from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise BundleError(f"input is not a regular file: {str(path)!r}")
        if metadata.st_size > max_bytes:
            raise BundleError(f"input exceeds the remaining FZB1 capacity: {str(path)!r}")
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise BundleError(f"input exceeds the remaining FZB1 capacity: {str(path)!r}")
        return data
    finally:
        os.close(fd)


def _directory_flags() -> int:
    flags = os.O_CLOEXEC | getattr(os, "O_PATH", os.O_RDONLY)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _open_directory(path: Path) -> int:
    flags = _directory_flags()
    try:
        current = os.open("/" if path.is_absolute() else ".", flags)
        for component in path.parts:
            if component in ("", ".", os.sep):
                continue
            if component == "..":
                raise BundleError(f"directory path may not contain '..': {str(path)!r}")
            try:
                next_fd = os.open(component, flags, dir_fd=current)
            except OSError as error:
                raise BundleError(
                    f"cannot open directory component {component!r} in {str(path)!r}: {error}"
                ) from error
            os.close(current)
            current = next_fd
        return current
    except Exception:
        if "current" in locals():
            os.close(current)
        raise


def _identity(fd: int) -> tuple[int, int]:
    metadata = os.fstat(fd)
    return metadata.st_dev, metadata.st_ino


def _same_identity_at(parent_fd: int, name: str, identity: tuple[int, int]) -> bool:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return (metadata.st_dev, metadata.st_ino) == identity


def _write_new_file(path: Path, data: bytes) -> None:
    name = path.name
    if not name or name in (".", ".."):
        raise BundleError("output needs a final file component")
    parent = path.parent if str(path.parent) else Path(".")
    parent_fd = _open_directory(parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
        created_identity = _identity(fd)
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written == 0:
                raise BundleError(f"short write to {str(path)!r}")
            view = view[written:]
        os.fsync(fd)
        if not _same_identity_at(parent_fd, name, created_identity):
            raise BundleError("output path changed while the FZB1 file was being written")
    except Exception as error:
        if created_identity is not None and _same_identity_at(parent_fd, name, created_identity):
            try:
                os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass
        if isinstance(error, BundleError):
            raise
        if not isinstance(error, OSError):
            raise
        raise BundleError(f"cannot create output {str(path)!r}: {error}") from error
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def _cleanup_owned_stage(
    parent_fd: int,
    root_fd: int,
    name: str,
    identity: tuple[int, int],
) -> None:
    try:
        os.chmod(".", 0o700, dir_fd=root_fd, follow_symlinks=False)
    except OSError:
        pass
    descriptor_path = Path(f"/proc/self/fd/{root_fd}")
    try:
        for child in os.scandir(descriptor_path):
            try:
                if child.is_dir(follow_symlinks=False):
                    shutil.rmtree(child.path)
                else:
                    os.unlink(child.path)
            except OSError:
                pass
    except OSError:
        pass
    if _same_identity_at(parent_fd, name, identity):
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            pass


def _stage_entries(
    entries: Sequence[tuple[str, bytes]], destination: Path
) -> None:
    name = destination.name
    if not name or name in (".", ".."):
        raise BundleError("staging destination needs a new final directory component")
    parent = destination.parent if str(destination.parent) else Path(".")
    parent_fd = _open_directory(parent)
    root_fd: int | None = None
    root_identity: tuple[int, int] | None = None
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except OSError as error:
            raise BundleError(f"cannot create staging directory {name!r}: {error}") from error
        root_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
        root_identity = _identity(root_fd)
        os.chmod(name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_identity_at(parent_fd, name, root_identity):
            raise BundleError("staging root changed during creation")
        for entry_name, data in entries:
            segments = entry_name.split("/")
            directory_fd = os.dup(root_fd)
            try:
                for segment in segments[:-1]:
                    created = False
                    try:
                        os.mkdir(segment, 0o700, dir_fd=directory_fd)
                        created = True
                    except FileExistsError:
                        pass
                    next_fd = os.open(segment, _directory_flags(), dir_fd=directory_fd)
                    try:
                        if created:
                            os.chmod(
                                segment,
                                0o700,
                                dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                    except Exception:
                        os.close(next_fd)
                        raise
                    os.close(directory_fd)
                    directory_fd = next_fd
                file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    file_flags |= os.O_NOFOLLOW
                file_fd = os.open(segments[-1], file_flags, 0o600, dir_fd=directory_fd)
                try:
                    os.fchmod(file_fd, 0o600)
                    view = memoryview(data)
                    while view:
                        written = os.write(file_fd, view)
                        if written == 0:
                            raise BundleError(f"short write for FZB1 entry {entry_name!r}")
                        view = view[written:]
                    os.fsync(file_fd)
                finally:
                    os.close(file_fd)
            finally:
                os.close(directory_fd)
        if not _same_identity_at(parent_fd, name, root_identity):
            raise BundleError("staging root changed while entries were written")
    except BundleError:
        if root_fd is not None and root_identity is not None:
            _cleanup_owned_stage(parent_fd, root_fd, name, root_identity)
        raise
    except OSError as error:
        if root_fd is not None and root_identity is not None:
            _cleanup_owned_stage(parent_fd, root_fd, name, root_identity)
        raise BundleError(f"cannot stage bundle in {str(destination)!r}: {error}") from error
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)


def _cmd_pack(args: argparse.Namespace) -> None:
    if not 1 <= len(args.entry) <= MAX_ENTRIES:
        raise BundleError(f"FZB1 entry count must be 1..={MAX_ENTRIES}")
    sources: list[tuple[str, Path]] = []
    names: set[str] = set()
    framing_bytes = len(MAGIC) + 4
    for specification in args.entry:
        if "=" not in specification:
            raise BundleError(f"pack entry must be NAME=PATH: {specification!r}")
        name, raw_path = specification.split("=", 1)
        _validate_name_bytes(name.encode("ascii", errors="strict"))
        if name in names:
            raise BundleError(f"duplicate FZB1 entry name: {name}")
        names.add(name)
        framing_bytes += 2 + 8 + len(name)
        if framing_bytes > MAX_BUNDLE_BYTES:
            raise BundleError(f"FZB1 output exceeds the {MAX_BUNDLE_BYTES}-byte limit")
        sources.append((name, Path(raw_path)))

    entries: list[tuple[str, bytes]] = []
    remaining = MAX_BUNDLE_BYTES - framing_bytes
    for name, path in sources:
        data = _read_regular(path, remaining)
        entries.append((name, data))
        remaining -= len(data)
    _write_new_file(Path(args.output), encode_bundle(entries))


def _cmd_list(args: argparse.Namespace) -> None:
    entries = decode_bundle(_read_regular(Path(args.bundle)))
    if args.allow:
        require_allowlist(entries, args.allow)
    for name, data in entries:
        print(f"{name}\t{len(data)}")


def _cmd_unpack(args: argparse.Namespace) -> None:
    blob = _read_regular(Path(args.bundle))
    entries = decode_bundle(blob)
    require_allowlist(entries, args.allow)
    _stage_entries(entries, Path(args.output_dir))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    pack = subparsers.add_parser("pack", help="pack explicit NAME=PATH files")
    pack.add_argument("--output", required=True)
    pack.add_argument("--entry", action="append", required=True)
    pack.set_defaults(handler=_cmd_pack)

    listing = subparsers.add_parser("list", help="list validated entries")
    listing.add_argument("bundle")
    listing.add_argument("--allow", action="append", default=[])
    listing.set_defaults(handler=_cmd_list)

    unpack = subparsers.add_parser("unpack", help="stage allowlisted entries in a new directory")
    unpack.add_argument("bundle")
    unpack.add_argument("--output-dir", required=True)
    unpack.add_argument("--allow", action="append", required=True)
    unpack.set_defaults(handler=_cmd_unpack)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        args.handler(args)
    except (BundleError, UnicodeError, ValueError) as error:
        print(f"model-bundle: rejected: {error}", file=sys.stderr)
        return EXIT_INPUT_REJECTED
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
