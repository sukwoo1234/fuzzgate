"""Fail-closed execution and evidence helpers for format acceptance checks.

The command-line wrapper is intentionally thin.  This module owns the strict
requirements schema, bounded child supervision, immutable task records, and
requirement-evidence aggregation.  It uses only the Python standard
library so the same code can run on the development host and the fuzzing PC.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Iterable, Mapping, Sequence
import uuid


SUPPORTED_SUITES = frozenset(
    {"unit", "oracle", "engine", "coverage", "integration", "performance", "soak", "install"}
)
STATUS_NAMES = ("pass", "fail", "blocked", "not_run", "inconclusive")
REQUIREMENT_IDS = tuple(f"Q{number:02d}" for number in range(1, 13))

MAX_JSON_BYTES = 1024 * 1024
MAX_TASKS = 256
MAX_ARGV = 256
MAX_ENV_KEYS = 256
MAX_TIMEOUT_MS = 7 * 24 * 60 * 60 * 1000
MAX_TOTAL_TIMEOUT_MS = MAX_TIMEOUT_MS
MAX_STREAM_BYTES = 64 * 1024 * 1024
MAX_TOTAL_STREAM_BYTES = 1024 * 1024 * 1024
MAX_GIT_DIFF_BYTES = 64 * 1024 * 1024
MAX_GIT_PATH_LIST_BYTES = 8 * 1024 * 1024
MAX_GIT_UNTRACKED_FILES = 16384
MAX_GIT_UNTRACKED_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_ARTIFACTS = 256
MAX_IDENTITY_FILES = 64
MAX_TOTAL_IDENTITY_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_EXECUTION_IDENTITY_BYTES = 2 * 1024 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37

SOURCE_IDENTITY_PATHS = (
    "src",
    "scripts",
    "harnesses",
    "vendor",
    "fuzz",
    "tests",
    "benches",
    "examples",
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "rust-toolchain.toml",
    ".cargo/config.toml",
)

RESULT_PATH_ENV = "FORMAT_ACCEPTANCE_RESULT_PATH"
TASK_DIR_ENV = "FORMAT_ACCEPTANCE_TASK_DIR"
PROFILE_PATH_ENV = "FORMAT_ACCEPTANCE_PROFILE_PATH"
PROFILE_SHA256_ENV = "FORMAT_ACCEPTANCE_PROFILE_SHA256"
TARGET_ENV = "FORMAT_ACCEPTANCE_TARGET"
SUITE_ENV = "FORMAT_ACCEPTANCE_SUITE"
TASK_ID_ENV = "FORMAT_ACCEPTANCE_TASK_ID"
TEST_HOOK_ENV = "FORMAT_ACCEPTANCE_TEST_HOOK"
TOOL_TARGET_PROFILE_ENV = "TOOL_TARGET_PROFILE"
TOOL_PROFILE_SHA256_ENV = "TOOL_PROFILE_SHA256"
TOOL_VALIDATION_RUN_ENV = "TOOL_VALIDATION_RUN"

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REQUIREMENT_ID = re.compile(r"^Q(?:0[1-9]|1[0-2])$")
_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_FORBIDDEN_ENV = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "GCONV_PATH",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_PATH",
        "NODE_OPTIONS",
        "PATH",
        "PERL5LIB",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUBYLIB",
        "RUBYOPT",
    }
)
_RESERVED_ENV = frozenset(
    {
        RESULT_PATH_ENV,
        TASK_DIR_ENV,
        PROFILE_PATH_ENV,
        PROFILE_SHA256_ENV,
        TARGET_ENV,
        SUITE_ENV,
        TASK_ID_ENV,
        TEST_HOOK_ENV,
        TOOL_TARGET_PROFILE_ENV,
        TOOL_PROFILE_SHA256_ENV,
        TOOL_VALIDATION_RUN_ENV,
    }
)


class ConfigurationError(ValueError):
    """The invocation or requirements document is invalid (CLI rc 64)."""


class EvidenceError(RuntimeError):
    """Evidence could not be completed safely (runner rc 2)."""


class _RunInterrupted(EvidenceError):
    pass


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True)
class _Snapshot:
    path: Path
    data: bytes
    sha256: str
    device: int
    inode: int


@dataclass(frozen=True)
class _DirectoryIdentity:
    path: Path
    device: int
    inode: int
    mode: int


@dataclass(frozen=True)
class _FileIdentity:
    path: Path
    sha256: str
    size_bytes: int
    device: int
    inode: int
    mode: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _Requirement:
    requirement_id: str
    required_task_ids: tuple[str, ...]


@dataclass(frozen=True)
class _Task:
    task_id: str
    requirement_id: str
    command_argv: tuple[str, ...]
    executable: _FileIdentity
    cwd: Path
    cwd_device: int
    cwd_inode: int
    identity_files: tuple[_FileIdentity, ...]
    allowed_env: Mapping[str, str]
    timeout_ms: int
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    depends_on: tuple[str, ...]
    corpus_index_sha256: str | None
    artifacts: tuple[str, ...]


@dataclass(frozen=True)
class _Requirements:
    target_id: str
    suite: str
    profile_sha256: str
    requirements: tuple[_Requirement, ...]
    tasks: tuple[_Task, ...]


@dataclass(frozen=True)
class _Stream:
    data: bytes
    truncated: bool


@dataclass(frozen=True)
class _Observation:
    stdout: _Stream
    stderr: _Stream
    start_utc: str
    end_utc: str
    elapsed_ms: int
    exit_code: int | None
    signal_number: int | None
    timed_out: bool
    launch_error: str | None


@dataclass
class _ArtifactBudget:
    remaining_bytes: int

    def maximum_for_file(self) -> int:
        return min(MAX_ARTIFACT_BYTES, max(0, self.remaining_bytes))

    def consume(self, size_bytes: int) -> None:
        if size_bytes < 0 or size_bytes > self.remaining_bytes:
            raise ConfigurationError("artifacts exceed the run-wide byte limit")
        self.remaining_bytes -= size_bytes


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return text.encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError) as error:
        raise EvidenceError(f"could not serialize evidence JSON: {error}") from error


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey(f"duplicate key '{key}'")
        value[key] = item
    return value


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number '{value}'")


def _parse_json(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise ConfigurationError(f"invalid {label} JSON: {error}") from error


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    observed = set(value)
    missing = sorted(expected - observed)
    unknown = sorted(observed - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {missing}")
        if unknown:
            details.append(f"unknown {unknown}")
        raise ConfigurationError(f"{label} fields are invalid: {', '.join(details)}")


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{label} must be a JSON object")
    return value


def _require_string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ConfigurationError(f"{label} must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise ConfigurationError(f"{label} must contain valid Unicode scalar values") from error
    if (not allow_empty and not value) or len(encoded) > MAX_TEXT_BYTES:
        raise ConfigurationError(f"{label} is empty or too long")
    if "\0" in value:
        raise ConfigurationError(f"{label} contains NUL")
    return value


def _require_positive_int(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or value < 1 or value > maximum:
        raise ConfigurationError(f"{label} must be an integer in 1..{maximum}")
    return value


def _validate_sha256(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ConfigurationError(f"{label} must be a 64-digit sha256")
    if set(value.lower()) == {"0"}:
        raise ConfigurationError(f"{label} must not be an all-zero placeholder")
    return value.lower()


def _read_regular(
    path: Path,
    label: str,
    maximum: int = MAX_JSON_BYTES,
    *,
    allow_empty: bool = False,
) -> _Snapshot:
    if not path.is_absolute():
        raise ConfigurationError(f"{label} path must be absolute: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ConfigurationError("this runner requires O_NOFOLLOW support")
    flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ConfigurationError(f"could not open {label} '{path}': {error}") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ConfigurationError(f"{label} must be a regular file: {path}")
        minimum = 0 if allow_empty else 1
        if before.st_size < minimum or before.st_size > maximum:
            raise ConfigurationError(f"{label} size must be in {minimum}..{maximum} bytes: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        if (
            len(data) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ConfigurationError(f"{label} changed while being read: {path}")
        if len(data) > maximum:
            raise ConfigurationError(f"{label} exceeds {maximum} bytes: {path}")
        return _Snapshot(path, data, _sha256(data), before.st_dev, before.st_ino)
    finally:
        os.close(fd)


def _canonicalize_parent(path: Path, label: str) -> Path:
    """Pin an absolute path to its resolved parent without following its leaf."""

    if not path.is_absolute():
        raise ConfigurationError(f"{label} path must be absolute: {path}")
    if path.name in ("", ".", ".."):
        raise ConfigurationError(f"{label} path has an unsafe final component: {path}")
    try:
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ConfigurationError(f"could not resolve {label} parent '{path.parent}': {error}") from error
    if not parent.is_dir():
        raise ConfigurationError(f"{label} parent is not a directory: {parent}")
    return parent / path.name


def _measure_open_regular(
    fd: int,
    path: Path,
    label: str,
    maximum: int,
    *,
    allow_empty: bool,
    require_single_link: bool = False,
) -> _FileIdentity:
    before = os.fstat(fd)
    minimum = 0 if allow_empty else 1
    if not stat.S_ISREG(before.st_mode):
        raise ConfigurationError(f"{label} must be a regular file: {path}")
    if require_single_link and before.st_nlink != 1:
        raise ConfigurationError(f"{label} must have exactly one hard link: {path}")
    if before.st_size < minimum or before.st_size > maximum:
        raise ConfigurationError(f"{label} size must be in {minimum}..{maximum} bytes: {path}")
    digest = hashlib.sha256()
    measured = 0
    while True:
        chunk = os.read(fd, min(1024 * 1024, maximum + 1 - measured))
        if not chunk:
            break
        digest.update(chunk)
        measured += len(chunk)
        if measured > maximum:
            raise ConfigurationError(f"{label} exceeds {maximum} bytes: {path}")
    after = os.fstat(fd)
    if require_single_link and after.st_nlink != 1:
        raise ConfigurationError(f"{label} hard-link count changed while being hashed: {path}")
    if (
        measured != before.st_size
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_mode != after.st_mode
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        raise ConfigurationError(f"{label} changed while being hashed: {path}")
    return _FileIdentity(
        path=path,
        sha256=digest.hexdigest(),
        size_bytes=measured,
        device=after.st_dev,
        inode=after.st_ino,
        mode=after.st_mode,
        mtime_ns=after.st_mtime_ns,
        ctime_ns=after.st_ctime_ns,
    )


def _measure_regular_identity(
    path: Path,
    label: str,
    maximum: int,
    *,
    allow_empty: bool = True,
) -> _FileIdentity:
    """Hash a bounded regular file and retain metadata from the same open FD."""

    if not path.is_absolute():
        raise ConfigurationError(f"{label} path must be absolute: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ConfigurationError("this runner requires O_NOFOLLOW support")
    flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ConfigurationError(f"could not open {label} '{path}': {error}") from error
    try:
        return _measure_open_regular(
            fd,
            path,
            label,
            maximum,
            allow_empty=allow_empty,
        )
    finally:
        os.close(fd)


def _measure_regular(
    path: Path,
    label: str,
    maximum: int,
    *,
    allow_empty: bool = True,
) -> tuple[str, int]:
    """Hash a bounded regular file without retaining its contents in memory."""

    measured = _measure_regular_identity(
        path,
        label,
        maximum,
        allow_empty=allow_empty,
    )
    return measured.sha256, measured.size_bytes


def _measure_beneath_regular(
    root: Path,
    relative: str,
    label: str,
    maximum: int,
    *,
    allow_empty: bool = True,
) -> tuple[str, int]:
    """Hash a relative regular file without following any component symlink."""

    safe_relative = _safe_relative_artifact(relative, label)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | os.O_NOFOLLOW
    )
    directory_fd: int | None = None
    file_fd: int | None = None
    display_path = root / safe_relative
    try:
        directory_fd = os.open(root, directory_flags)
        parts = Path(safe_relative).parts
        for component in parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        measured = _measure_open_regular(
            file_fd,
            display_path,
            label,
            maximum,
            allow_empty=allow_empty,
            require_single_link=True,
        )
        return measured.sha256, measured.size_bytes
    except OSError as error:
        raise ConfigurationError(f"could not open {label} '{display_path}': {error}") from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _identity_matches_metadata(
    identity: _FileIdentity,
    metadata: os.stat_result,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_dev == identity.device
        and metadata.st_ino == identity.inode
        and metadata.st_mode == identity.mode
        and metadata.st_size == identity.size_bytes
        and metadata.st_mtime_ns == identity.mtime_ns
        and metadata.st_ctime_ns == identity.ctime_ns
    )


def _identity_at_path(identity: _FileIdentity, path: Path) -> _FileIdentity:
    return _FileIdentity(
        path=path,
        sha256=identity.sha256,
        size_bytes=identity.size_bytes,
        device=identity.device,
        inode=identity.inode,
        mode=identity.mode,
        mtime_ns=identity.mtime_ns,
        ctime_ns=identity.ctime_ns,
    )


def _read_identity_prefix(identity: _FileIdentity, length: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ConfigurationError("this runner requires O_NOFOLLOW support")
    try:
        fd = os.open(identity.path, flags | os.O_NOFOLLOW)
    except OSError as error:
        raise ConfigurationError(
            f"could not reopen execution identity '{identity.path}': {error}"
        ) from error
    try:
        before = os.fstat(fd)
        if not _identity_matches_metadata(identity, before):
            raise ConfigurationError(
                f"execution identity changed after hashing: {identity.path}"
            )
        prefix = os.read(fd, length)
        after = os.fstat(fd)
        if not _identity_matches_metadata(identity, after):
            raise ConfigurationError(
                f"execution identity changed while inspecting: {identity.path}"
            )
        return prefix
    finally:
        os.close(fd)


def _snapshot_unchanged(snapshot: _Snapshot) -> tuple[bool, str | None]:
    try:
        current = _read_regular(snapshot.path, "identity file", max(len(snapshot.data), 1))
    except ConfigurationError as error:
        return False, str(error)
    if (
        current.device != snapshot.device
        or current.inode != snapshot.inode
        or current.data != snapshot.data
        or current.sha256 != snapshot.sha256
    ):
        return False, f"identity changed: {snapshot.path}"
    return True, None


def _validate_profile(snapshot: _Snapshot, target: str) -> None:
    value = _require_object(_parse_json(snapshot.data, "target profile"), "target profile")
    if value.get("schema_version") != "1":
        raise ConfigurationError("target profile schema_version must be '1'")
    observed = _require_string(value.get("target_id"), "target profile target_id")
    if observed != target:
        raise ConfigurationError(f"target profile mismatch: requested '{target}', observed '{observed}'")


def _safe_relative_artifact(value: Any, label: str) -> str:
    text = _require_string(value, label)
    candidate = Path(text)
    if candidate.is_absolute() or not candidate.parts or any(part in ("", ".", "..") for part in candidate.parts):
        raise ConfigurationError(f"{label} must be a safe relative path")
    if "\\" in text:
        raise ConfigurationError(f"{label} must use '/' separators")
    return candidate.as_posix()


def _interpreter_script_index(executable: Path, argv: Sequence[str]) -> int | None:
    """Return the script argument for common interpreters, if one is required."""

    name = executable.name.lower()
    if re.fullmatch(r"python(?:[0-9]+(?:\.[0-9]+)*)?", name):
        index = 1
        while index < len(argv):
            argument = argv[index]
            if argument == "-c":
                return None
            if argument == "-m":
                raise ConfigurationError(
                    "Python -m tasks are unsupported because their module files cannot be pinned"
                )
            if argument in ("-W", "-X"):
                index += 2
                continue
            if argument == "--":
                return index + 1 if index + 1 < len(argv) else None
            if argument.startswith("-"):
                index += 1
                continue
            return index
        return None
    if name in {"sh", "bash", "dash", "zsh", "ksh", "perl", "ruby", "node"}:
        for index, argument in enumerate(argv[1:], start=1):
            if argument in ("-c", "-e"):
                return None
            if argument == "--":
                return index + 1 if index + 1 < len(argv) else None
            if not argument.startswith("-"):
                return index
    return None


def _argument_path_forms(argument: str) -> list[tuple[str, str]]:
    """Return (prefix, path text) forms that can directly name a local file."""

    if argument.startswith("@") and len(argument) > 1:
        return [("@", argument[1:])]
    if argument.startswith("-") and "=" in argument:
        prefix, value = argument.split("=", 1)
        if value:
            return [(prefix + "=", value)]
    if argument.startswith("-"):
        return []
    return [("", argument)]


def _parse_requirements(snapshot: _Snapshot) -> _Requirements:
    root = _require_object(_parse_json(snapshot.data, "requirements"), "requirements")
    _require_exact_keys(
        root,
        {"schema_version", "target_id", "suite", "profile_sha256", "requirements", "tasks"},
        "requirements",
    )
    if root["schema_version"] != "1":
        raise ConfigurationError("requirements schema_version must be '1'")
    target_id = _require_string(root["target_id"], "requirements.target_id")
    if not _SAFE_ID.fullmatch(target_id):
        raise ConfigurationError("requirements.target_id is not a safe identifier")
    suite = _require_string(root["suite"], "requirements.suite")
    if suite not in SUPPORTED_SUITES:
        raise ConfigurationError(f"unsupported requirements suite '{suite}'")
    profile_sha256 = _validate_sha256(root["profile_sha256"], "requirements.profile_sha256")
    assert profile_sha256 is not None

    raw_requirements = root["requirements"]
    raw_tasks = root["tasks"]
    if not isinstance(raw_requirements, list) or not isinstance(raw_tasks, list):
        raise ConfigurationError("requirements.requirements and requirements.tasks must be arrays")
    if not raw_requirements or not raw_tasks:
        raise ConfigurationError("requirements must contain at least one requirement and one task")
    if len(raw_tasks) > MAX_TASKS or len(raw_requirements) > len(REQUIREMENT_IDS):
        raise ConfigurationError("requirements contains too many tasks or requirement IDs")

    requirements: list[_Requirement] = []
    seen_requirements: set[str] = set()
    required_owners: dict[str, str] = {}
    for index, raw in enumerate(raw_requirements):
        item = _require_object(raw, f"requirements.requirements[{index}]")
        _require_exact_keys(item, {"requirement_id", "required_task_ids"}, f"requirements.requirements[{index}]")
        requirement_id = _require_string(item["requirement_id"], f"requirements.requirements[{index}].requirement_id")
        if not _REQUIREMENT_ID.fullmatch(requirement_id):
            raise ConfigurationError(f"invalid requirement_id '{requirement_id}'")
        if requirement_id in seen_requirements:
            raise ConfigurationError(f"duplicate requirement_id '{requirement_id}'")
        seen_requirements.add(requirement_id)
        raw_ids = item["required_task_ids"]
        if not isinstance(raw_ids, list) or not raw_ids:
            raise ConfigurationError(f"{requirement_id}.required_task_ids must be a non-empty array")
        if len(raw_ids) > MAX_TASKS:
            raise ConfigurationError(
                f"{requirement_id}.required_task_ids contains more than {MAX_TASKS} entries"
            )
        task_ids: list[str] = []
        for task_index, raw_id in enumerate(raw_ids):
            task_id = _require_string(raw_id, f"{requirement_id}.required_task_ids[{task_index}]")
            if not _SAFE_ID.fullmatch(task_id):
                raise ConfigurationError(f"invalid task_id '{task_id}'")
            if task_id in required_owners:
                raise ConfigurationError(f"required task_id '{task_id}' is listed more than once")
            required_owners[task_id] = requirement_id
            task_ids.append(task_id)
        requirements.append(_Requirement(requirement_id, tuple(task_ids)))

    execution_identity_cache: dict[tuple[int, int], _FileIdentity] = {}
    execution_identity_total = 0

    def measure_execution_identity(
        path: Path,
        metadata: os.stat_result,
        label: str,
    ) -> _FileIdentity:
        nonlocal execution_identity_total
        key = (metadata.st_dev, metadata.st_ino)
        cached = execution_identity_cache.get(key)
        if cached is not None:
            if not _identity_matches_metadata(cached, metadata):
                raise ConfigurationError(
                    f"execution identity changed while parsing: {path}"
                )
            return _identity_at_path(cached, path)
        remaining = MAX_TOTAL_EXECUTION_IDENTITY_BYTES - execution_identity_total
        if metadata.st_size < 1 or metadata.st_size > remaining:
            raise ConfigurationError(
                "execution identity files exceed the run-wide byte limit"
            )
        measured = _measure_regular_identity(
            path,
            label,
            min(MAX_ARTIFACT_BYTES, remaining),
            allow_empty=False,
        )
        measured_key = (measured.device, measured.inode)
        prior = execution_identity_cache.get(measured_key)
        if prior is not None:
            if prior != _identity_at_path(measured, prior.path):
                raise ConfigurationError(
                    f"execution identity changed while parsing: {path}"
                )
            return _identity_at_path(prior, path)
        execution_identity_total += measured.size_bytes
        execution_identity_cache[measured_key] = measured
        return measured

    tasks: list[_Task] = []
    seen_tasks: set[str] = set()
    total_timeout_ms = 0
    total_stream_bytes = 0
    task_fields = {
        "task_id",
        "requirement_id",
        "command_argv",
        "cwd",
        "identity_files",
        "allowed_env",
        "timeout_ms",
        "stdout_limit_bytes",
        "stderr_limit_bytes",
        "depends_on",
        "corpus_index_sha256",
        "artifacts",
    }
    for index, raw in enumerate(raw_tasks):
        item = _require_object(raw, f"requirements.tasks[{index}]")
        _require_exact_keys(item, task_fields, f"requirements.tasks[{index}]")
        task_id = _require_string(item["task_id"], f"requirements.tasks[{index}].task_id")
        requirement_id = _require_string(item["requirement_id"], f"requirements.tasks[{index}].requirement_id")
        if not _SAFE_ID.fullmatch(task_id):
            raise ConfigurationError(f"invalid task_id '{task_id}'")
        if not _REQUIREMENT_ID.fullmatch(requirement_id):
            raise ConfigurationError(f"invalid requirement_id '{requirement_id}'")
        if task_id in seen_tasks:
            raise ConfigurationError(f"duplicate task_id '{task_id}'")
        seen_tasks.add(task_id)

        timeout_ms = _require_positive_int(
            item["timeout_ms"], f"task '{task_id}' timeout_ms", MAX_TIMEOUT_MS
        )
        stdout_limit_bytes = _require_positive_int(
            item["stdout_limit_bytes"],
            f"task '{task_id}' stdout_limit_bytes",
            MAX_STREAM_BYTES,
        )
        stderr_limit_bytes = _require_positive_int(
            item["stderr_limit_bytes"],
            f"task '{task_id}' stderr_limit_bytes",
            MAX_STREAM_BYTES,
        )
        total_timeout_ms += timeout_ms
        total_stream_bytes += stdout_limit_bytes + stderr_limit_bytes
        if total_timeout_ms > MAX_TOTAL_TIMEOUT_MS:
            raise ConfigurationError("task timeouts exceed the run-wide limit")
        if total_stream_bytes > MAX_TOTAL_STREAM_BYTES:
            raise ConfigurationError("task output limits exceed the run-wide byte limit")

        raw_argv = item["command_argv"]
        if not isinstance(raw_argv, list) or not raw_argv:
            raise ConfigurationError(f"task '{task_id}' command_argv must be non-empty")
        if len(raw_argv) > MAX_ARGV:
            raise ConfigurationError(
                f"task '{task_id}' command_argv contains more than {MAX_ARGV} entries"
            )
        argv = [_require_string(arg, f"task '{task_id}' command_argv") for arg in raw_argv]
        requested_executable = Path(argv[0])
        if not requested_executable.is_absolute():
            raise ConfigurationError(f"task '{task_id}' executable must be absolute")
        try:
            executable = requested_executable.resolve(strict=True)
            executable_metadata = os.lstat(executable)
        except (OSError, RuntimeError) as error:
            raise ConfigurationError(
                f"task '{task_id}' executable is not available: {requested_executable}: {error}"
            ) from error
        if Path(os.path.abspath(requested_executable)) != executable:
            raise ConfigurationError(
                f"task '{task_id}' executable path must not traverse symlinks: "
                f"{requested_executable}"
            )
        if not stat.S_ISREG(executable_metadata.st_mode) or not os.access(executable, os.X_OK):
            raise ConfigurationError(f"task '{task_id}' executable is not available: {executable}")
        executable_identity = measure_execution_identity(
            executable,
            executable_metadata,
            f"task '{task_id}' executable",
        )
        if _read_identity_prefix(executable_identity, 2) == b"#!":
            raise ConfigurationError(
                f"task '{task_id}' must invoke scripts through a pinned interpreter"
            )
        if executable.name == "env":
            raise ConfigurationError(
                f"task '{task_id}' must not use an environment-dispatch executable"
            )

        requested_cwd = Path(_require_string(item["cwd"], f"task '{task_id}' cwd"))
        if not requested_cwd.is_absolute():
            raise ConfigurationError(f"task '{task_id}' cwd must be an existing absolute directory")
        try:
            cwd = requested_cwd.resolve(strict=True)
            cwd_metadata = os.lstat(cwd)
        except OSError as error:
            raise ConfigurationError(
                f"task '{task_id}' cwd must be an existing absolute directory: {error}"
            ) from error
        if not stat.S_ISDIR(cwd_metadata.st_mode):
            raise ConfigurationError(f"task '{task_id}' cwd must be an existing absolute directory")

        raw_identity_files = item["identity_files"]
        if not isinstance(raw_identity_files, list):
            raise ConfigurationError(f"task '{task_id}' identity_files must be an array")
        if len(raw_identity_files) > MAX_IDENTITY_FILES:
            raise ConfigurationError(
                f"task '{task_id}' contains more than {MAX_IDENTITY_FILES} identity files"
            )
        identity_files: list[_FileIdentity] = []
        identity_by_path: dict[Path, _FileIdentity] = {}
        seen_identity_inodes: set[tuple[int, int]] = set()
        total_identity_size = 0
        for identity_index, raw_identity in enumerate(raw_identity_files):
            identity = _require_object(
                raw_identity, f"task '{task_id}' identity_files[{identity_index}]"
            )
            _require_exact_keys(
                identity,
                {"path", "sha256"},
                f"task '{task_id}' identity_files[{identity_index}]",
            )
            raw_path = Path(
                _require_string(
                    identity["path"],
                    f"task '{task_id}' identity_files[{identity_index}].path",
                )
            )
            requested_path = raw_path if raw_path.is_absolute() else cwd / raw_path
            try:
                identity_path = requested_path.resolve(strict=True)
                identity_metadata = os.lstat(identity_path)
            except (OSError, RuntimeError) as error:
                raise ConfigurationError(
                    f"task '{task_id}' identity file is unavailable: {requested_path}: {error}"
                ) from error
            lexical_identity_path = Path(os.path.abspath(requested_path))
            if lexical_identity_path != identity_path:
                raise ConfigurationError(
                    f"task '{task_id}' identity file path must not traverse symlinks: "
                    f"{requested_path}"
                )
            if not stat.S_ISREG(identity_metadata.st_mode):
                raise ConfigurationError(
                    f"task '{task_id}' identity file must be regular: {identity_path}"
                )
            expected_sha256 = _validate_sha256(
                identity["sha256"],
                f"task '{task_id}' identity_files[{identity_index}].sha256",
            )
            assert expected_sha256 is not None
            if total_identity_size + identity_metadata.st_size > MAX_TOTAL_IDENTITY_BYTES:
                raise ConfigurationError(
                    f"task '{task_id}' identity files exceed the aggregate byte limit"
                )
            measured_identity = measure_execution_identity(
                identity_path,
                identity_metadata,
                f"task '{task_id}' identity file",
            )
            if measured_identity.sha256 != expected_sha256:
                raise ConfigurationError(
                    f"task '{task_id}' identity file hash mismatch: {identity_path}"
                )
            inode_key = (identity_metadata.st_dev, identity_metadata.st_ino)
            if identity_path in identity_by_path or inode_key in seen_identity_inodes:
                raise ConfigurationError(
                    f"task '{task_id}' contains duplicate identity file: {identity_path}"
                )
            file_identity = measured_identity
            identity_files.append(file_identity)
            identity_by_path[identity_path] = file_identity
            seen_identity_inodes.add(inode_key)
            total_identity_size += measured_identity.size_bytes

        for argument_index, argument in enumerate(argv[1:], start=1):
            for _argument_prefix, path_text in _argument_path_forms(argument):
                candidate = Path(path_text)
                requested_argument = candidate if candidate.is_absolute() else cwd / candidate
                if not os.path.lexists(requested_argument):
                    continue
                try:
                    resolved_argument = requested_argument.resolve(strict=True)
                    argument_metadata = os.lstat(resolved_argument)
                except (OSError, RuntimeError) as error:
                    raise ConfigurationError(
                        f"task '{task_id}' file argument is unavailable: "
                        f"{requested_argument}: {error}"
                    ) from error
                if stat.S_ISDIR(argument_metadata.st_mode):
                    break
                if not stat.S_ISREG(argument_metadata.st_mode):
                    raise ConfigurationError(
                        f"task '{task_id}' file argument must be regular: "
                        f"{requested_argument}"
                    )
                if Path(os.path.abspath(requested_argument)) != resolved_argument:
                    raise ConfigurationError(
                        f"task '{task_id}' file argument path must not traverse symlinks: "
                        f"{requested_argument}"
                    )
                if resolved_argument not in identity_by_path:
                    raise ConfigurationError(
                        f"task '{task_id}' file argument is not listed in identity_files: "
                        f"{requested_argument}"
                    )
                break

        script_index = _interpreter_script_index(executable, argv)
        if script_index is not None:
            script_argument = Path(argv[script_index])
            requested_script = script_argument if script_argument.is_absolute() else cwd / script_argument
            try:
                resolved_script = requested_script.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ConfigurationError(
                    f"task '{task_id}' interpreter script is unavailable: {requested_script}: {error}"
                ) from error
            if Path(os.path.abspath(requested_script)) != resolved_script:
                raise ConfigurationError(
                    f"task '{task_id}' interpreter script path must not traverse symlinks: "
                    f"{requested_script}"
                )
            if resolved_script not in identity_by_path:
                raise ConfigurationError(
                    f"task '{task_id}' interpreter script is not listed in identity_files: "
                    f"{requested_script}"
                )

        raw_env = _require_object(item["allowed_env"], f"task '{task_id}' allowed_env")
        if len(raw_env) > MAX_ENV_KEYS:
            raise ConfigurationError(
                f"task '{task_id}' allowed_env contains more than {MAX_ENV_KEYS} entries"
            )
        allowed_env: dict[str, str] = {}
        for key, raw_value in raw_env.items():
            safe_key = _require_string(key, f"task '{task_id}' environment key")
            if (
                not _ENV_KEY.fullmatch(safe_key)
                or safe_key in _RESERVED_ENV
                or safe_key in _FORBIDDEN_ENV
            ):
                raise ConfigurationError(
                    f"task '{task_id}' has an invalid or reserved environment key"
                )
            allowed_env[safe_key] = _require_string(
                raw_value,
                f"task '{task_id}' environment {safe_key}",
                allow_empty=True,
            )

        raw_dependencies = item["depends_on"]
        if not isinstance(raw_dependencies, list):
            raise ConfigurationError(f"task '{task_id}' depends_on must be an array")
        if len(raw_dependencies) > MAX_TASKS:
            raise ConfigurationError(
                f"task '{task_id}' depends_on contains more than {MAX_TASKS} entries"
            )
        dependencies: list[str] = []
        for raw_dependency in raw_dependencies:
            dependency = _require_string(raw_dependency, f"task '{task_id}' dependency")
            if not _SAFE_ID.fullmatch(dependency) or dependency == task_id or dependency in dependencies:
                raise ConfigurationError(f"task '{task_id}' has an invalid dependency '{dependency}'")
            dependencies.append(dependency)

        raw_artifacts = item["artifacts"]
        if not isinstance(raw_artifacts, list):
            raise ConfigurationError(f"task '{task_id}' artifacts must be an array")
        if len(raw_artifacts) > MAX_ARTIFACTS:
            raise ConfigurationError(
                f"task '{task_id}' contains more than {MAX_ARTIFACTS} artifacts"
            )
        artifacts = tuple(
            _safe_relative_artifact(raw_artifact, f"task '{task_id}' artifacts[{artifact_index}]")
            for artifact_index, raw_artifact in enumerate(raw_artifacts)
        )
        if len(set(artifacts)) != len(artifacts):
            raise ConfigurationError(f"task '{task_id}' contains duplicate artifact paths")
        if any(
            artifact == "result.json" or artifact.startswith("result.json/")
            for artifact in artifacts
        ) or any(
            right.startswith(left + "/")
            for left in artifacts
            for right in artifacts
            if left != right
        ):
            raise ConfigurationError(
                f"task '{task_id}' artifact paths contain a file/directory prefix collision"
            )

        tasks.append(
            _Task(
                task_id=task_id,
                requirement_id=requirement_id,
                command_argv=tuple(argv),
                executable=executable_identity,
                cwd=cwd,
                cwd_device=cwd_metadata.st_dev,
                cwd_inode=cwd_metadata.st_ino,
                identity_files=tuple(identity_files),
                allowed_env=allowed_env,
                timeout_ms=timeout_ms,
                stdout_limit_bytes=stdout_limit_bytes,
                stderr_limit_bytes=stderr_limit_bytes,
                depends_on=tuple(dependencies),
                corpus_index_sha256=_validate_sha256(
                    item["corpus_index_sha256"], f"task '{task_id}' corpus_index_sha256", nullable=True
                ),
                artifacts=artifacts,
            )
        )

    if seen_tasks != set(required_owners):
        missing = sorted(set(required_owners) - seen_tasks)
        extra = sorted(seen_tasks - set(required_owners))
        raise ConfigurationError(f"required task inventory mismatch: missing={missing}, extra={extra}")
    by_task = {task.task_id: task for task in tasks}
    for task in tasks:
        owner = required_owners.get(task.task_id)
        if owner != task.requirement_id:
            raise ConfigurationError(
                f"task '{task.task_id}' requirement mismatch: list={owner}, task={task.requirement_id}"
            )
        unknown_dependencies = sorted(set(task.depends_on) - set(by_task))
        if unknown_dependencies:
            raise ConfigurationError(f"task '{task.task_id}' has unknown dependencies {unknown_dependencies}")

    # Stable Kahn pass proves the dependency graph is acyclic before any task starts.
    completed: set[str] = set()
    while len(completed) != len(tasks):
        ready = [task.task_id for task in tasks if task.task_id not in completed and set(task.depends_on) <= completed]
        if not ready:
            raise ConfigurationError("task dependency graph contains a cycle")
        completed.update(ready)

    return _Requirements(target_id, suite, profile_sha256, tuple(requirements), tuple(tasks))


def _mkdir_private(path: Path) -> None:
    previous = os.umask(0o077)
    try:
        os.mkdir(path, 0o700)
    finally:
        os.umask(previous)
    os.chmod(path, 0o700, follow_symlinks=False)
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise EvidenceError(f"private evidence directory has unsafe mode: {path}")


def _directory_identity(path: Path) -> _DirectoryIdentity:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise EvidenceError(f"could not inspect evidence directory '{path}': {error}") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode) or mode != 0o700:
        raise EvidenceError(f"private evidence directory has unsafe identity or mode: {path}")
    return _DirectoryIdentity(path, metadata.st_dev, metadata.st_ino, mode)


def _verify_directory_identities(identities: Iterable[_DirectoryIdentity]) -> None:
    for expected in identities:
        observed = _directory_identity(expected.path)
        if (
            observed.device != expected.device
            or observed.inode != expected.inode
            or observed.mode != expected.mode
        ):
            raise EvidenceError(f"evidence directory identity changed: {expected.path}")


def _open_directory(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise EvidenceError("this runner requires O_NOFOLLOW support")
    try:
        return os.open(path, flags | os.O_NOFOLLOW)
    except OSError as error:
        raise EvidenceError(f"could not open evidence directory '{path}': {error}") from error


def _clean_terminal_files_on_fd(directory_fd: int) -> list[str]:
    errors: list[str] = []
    try:
        os.fchmod(directory_fd, 0o700)
    except OSError as error:
        errors.append(f"could not restore evidence directory mode: {error}")
    for name in ("summary.json", "qualification.candidate.json"):
        try:
            os.unlink(name, dir_fd=directory_fd)
        except IsADirectoryError:
            quarantine = f".untrusted-{name}-{uuid.uuid4().hex}"
            try:
                os.rename(
                    name,
                    quarantine,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
            except OSError as error:
                errors.append(f"could not quarantine untrusted {name}: {error}")
        except FileNotFoundError:
            pass
        except OSError as error:
            errors.append(f"could not remove untrusted {name}: {error}")
    try:
        os.fsync(directory_fd)
    except OSError as error:
        errors.append(f"could not sync evidence directory cleanup: {error}")
    return errors


def _remove_untrusted_terminal_files(
    evidence_dir: Path,
    evidence_fd: int | None,
    evidence_parent_fd: int | None,
) -> None:
    errors: list[str] = []
    cleaned_identities: set[tuple[int, int]] = set()
    if evidence_fd is not None:
        try:
            metadata = os.fstat(evidence_fd)
            cleaned_identities.add((metadata.st_dev, metadata.st_ino))
        except OSError as error:
            errors.append(f"could not inspect held evidence directory: {error}")
        errors.extend(_clean_terminal_files_on_fd(evidence_fd))
    current_fd: int | None = None
    try:
        if evidence_parent_fd is None:
            raise EvidenceError("held evidence-parent directory is unavailable")
        current_metadata = os.stat(
            evidence_dir.name,
            dir_fd=evidence_parent_fd,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(current_metadata.st_mode):
            os.unlink(evidence_dir.name, dir_fd=evidence_parent_fd)
            os.fsync(evidence_parent_fd)
        else:
            os.chmod(
                evidence_dir.name,
                0o700,
                dir_fd=evidence_parent_fd,
                follow_symlinks=False,
            )
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | os.O_NOFOLLOW
            )
            current_fd = os.open(evidence_dir.name, flags, dir_fd=evidence_parent_fd)
            current_metadata = os.fstat(current_fd)
            current_identity = (current_metadata.st_dev, current_metadata.st_ino)
            if current_identity not in cleaned_identities:
                errors.extend(_clean_terminal_files_on_fd(current_fd))
                cleaned_identities.add(current_identity)
    except FileNotFoundError:
        pass
    except (EvidenceError, OSError) as error:
        errors.append(str(error))
    finally:
        if current_fd is not None:
            os.close(current_fd)
    for error in errors:
        print(f"[format-acceptance] terminal evidence cleanup failed: {error}", file=sys.stderr)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(directory: Path, name: str, data: bytes, *, inject_failure: bool = False) -> Path:
    if Path(name).name != name or name in ("", ".", ".."):
        raise EvidenceError(f"unsafe evidence filename '{name}'")
    final = directory / name
    temporary = directory / f".{name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        fd = os.open(temporary, flags, 0o600)
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short evidence write")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        if inject_failure:
            raise EvidenceError(f"injected record publication failure for '{name}'")
        # link() is an atomic no-replace publication.  It cannot silently overwrite
        # a record created by another process between validation and commit.
        os.link(temporary, final, follow_symlinks=False)
        os.unlink(temporary)
        _fsync_directory(directory)
        return final
    except Exception as error:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError(f"could not atomically publish '{final}': {error}") from error


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        # Descendants can still hold the group after the leader exits.
        pass
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        pass
    deadline = time.monotonic() + 0.15
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass


def _child_subreaper_state() -> bool:
    """Read the Linux subreaper flag for this dedicated runner process."""

    if not sys.platform.startswith("linux"):
        raise ConfigurationError("this runner requires Linux child-subreaper support")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.restype = ctypes.c_int
        state = ctypes.c_int()
        result = prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(state), 0, 0, 0)
    except (AttributeError, OSError) as error:
        raise ConfigurationError(f"could not inspect child subreaper: {error}") from error
    if result != 0:
        error_number = ctypes.get_errno()
        raise ConfigurationError(
            f"could not inspect child subreaper: {os.strerror(error_number)}"
        )
    return state.value != 0


def _set_child_subreaper(enabled: bool) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.restype = ctypes.c_int
        result = prctl(PR_SET_CHILD_SUBREAPER, int(enabled), 0, 0, 0)
    except (AttributeError, OSError) as error:
        raise ConfigurationError(f"could not configure child subreaper: {error}") from error
    if result != 0:
        error_number = ctypes.get_errno()
        raise ConfigurationError(
            f"could not configure child subreaper: {os.strerror(error_number)}"
        )


def _direct_child_pids() -> set[int]:
    children_path = Path(f"/proc/self/task/{os.getpid()}/children")
    try:
        text = children_path.read_text(encoding="ascii")
        return {int(value) for value in text.split()}
    except (OSError, ValueError) as error:
        raise EvidenceError(f"could not enumerate owned child processes: {error}") from error


def _require_dedicated_process() -> None:
    if threading.current_thread() is not threading.main_thread():
        raise ConfigurationError("acceptance runner must execute on the main thread")
    try:
        with os.scandir("/proc/self/task") as iterator:
            thread_count = sum(1 for _entry in iterator)
    except OSError as error:
        raise ConfigurationError(f"could not inspect runner threads: {error}") from error
    if thread_count != 1:
        raise ConfigurationError(
            "acceptance runner requires a dedicated single-threaded process"
        )
    try:
        child_pids = _direct_child_pids()
    except EvidenceError as error:
        raise ConfigurationError(str(error)) from error
    if child_pids:
        raise ConfigurationError(
            f"acceptance runner started with unrelated child processes: {sorted(child_pids)}"
        )


def _wait_reaped(pid: int) -> bool:
    try:
        waited, _status = os.waitpid(pid, os.WNOHANG)
        return waited == pid
    except ChildProcessError:
        return True


def _terminate_adopted_children(baseline: set[int]) -> None:
    """Terminate descendants that escaped the task's original process group."""

    def remaining() -> set[int]:
        candidates = _direct_child_pids() - baseline
        for pid in tuple(candidates):
            if _wait_reaped(pid):
                candidates.discard(pid)
        return candidates

    candidates = remaining()
    for pid in candidates:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 0.2
    while time.monotonic() < deadline:
        candidates = remaining()
        if not candidates:
            return
        for pid in candidates:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        time.sleep(0.01)

    deadline = time.monotonic() + 1.0
    while True:
        candidates = remaining()
        if not candidates:
            return
        for pid in candidates:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if time.monotonic() >= deadline:
            raise EvidenceError(f"could not reap task descendants: {sorted(candidates)}")
        time.sleep(0.01)


class _SignalScope:
    def __init__(self) -> None:
        self.active: subprocess.Popen[bytes] | None = None
        self.active_baseline: set[int] | None = None
        self.defer_interrupt = False
        self.pending_signum: int | None = None
        self.previous_subreaper: bool | None = None
        self.previous_mask: set[signal.Signals] | None = None
        self.previous: dict[int, Any] = {}

    def _handler(self, signum: int, _frame: Any) -> None:
        if self.defer_interrupt:
            if self.pending_signum is None:
                self.pending_signum = signum
            return
        raise _RunInterrupted(f"acceptance runner interrupted by signal {signum}")

    def begin_spawn(self, baseline: set[int]) -> None:
        self.active_baseline = baseline
        self.pending_signum = None
        self.defer_interrupt = True

    def finish_spawn(self) -> None:
        self.defer_interrupt = False
        pending = self.pending_signum
        self.pending_signum = None
        if pending is not None:
            raise _RunInterrupted(f"acceptance runner interrupted by signal {pending}")

    def clear_active(self) -> None:
        self.active = None
        self.active_baseline = None

    def cleanup_active(self) -> None:
        self.defer_interrupt = True
        self.pending_signum = None
        try:
            if self.active is not None:
                _terminate_process_group(self.active)
            if self.active_baseline is not None:
                _terminate_adopted_children(self.active_baseline)
        finally:
            self.clear_active()
            self.defer_interrupt = False
        pending = self.pending_signum
        self.pending_signum = None
        if pending is not None:
            raise _RunInterrupted(f"acceptance runner interrupted by signal {pending}")

    def __enter__(self) -> "_SignalScope":
        control_signals = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
        try:
            for signum in control_signals:
                previous = signal.getsignal(signum)
                signal.signal(signum, self._handler)
                self.previous[signum] = previous
            self.previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            signal.pthread_sigmask(signal.SIG_UNBLOCK, control_signals)
            self.previous_subreaper = _child_subreaper_state()
            if not self.previous_subreaper:
                _set_child_subreaper(True)
            return self
        except Exception:
            if self.previous_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, self.previous_mask)
                self.previous_mask = None
            for signum, handler in self.previous.items():
                signal.signal(signum, handler)
            self.previous.clear()
            if self.previous_subreaper is not None and not self.previous_subreaper:
                _set_child_subreaper(False)
            self.previous_subreaper = None
            raise

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        try:
            self.cleanup_active()
        finally:
            self.defer_interrupt = False
            self.pending_signum = None
            if self.previous_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, self.previous_mask)
                self.previous_mask = None
            for signum, handler in self.previous.items():
                signal.signal(signum, handler)
            self.previous.clear()
            if self.previous_subreaper is not None and not self.previous_subreaper:
                _set_child_subreaper(False)
            self.previous_subreaper = None


def _run_child(task: _Task, environment: Mapping[str, str], scope: _SignalScope) -> _Observation:
    started_utc = _utc_now()
    started = time.monotonic_ns()
    stdout = bytearray()
    stderr = bytearray()
    stdout_truncated = False
    stderr_truncated = False
    timed_out = False
    process: subprocess.Popen[bytes] | None = None
    child_baseline = _direct_child_pids()
    launch_error: OSError | None = None
    scope.begin_spawn(child_baseline)
    try:
        try:
            process = subprocess.Popen(
                task.command_argv,
                cwd=task.cwd,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
            )
            scope.active = process
        except OSError as error:
            launch_error = error
    finally:
        scope.finish_spawn()
    if launch_error is not None:
        scope.clear_active()
        elapsed_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
        return _Observation(
            _Stream(b"", False),
            _Stream(b"", False),
            started_utc,
            _utc_now(),
            elapsed_ms,
            None,
            None,
            False,
            str(launch_error),
        )

    assert process is not None
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): ("stdout", stdout, task.stdout_limit_bytes),
        process.stderr.fileno(): ("stderr", stderr, task.stderr_limit_bytes),
    }
    try:
        for file_object in (process.stdout, process.stderr):
            os.set_blocking(file_object.fileno(), False)
            selector.register(file_object, selectors.EVENT_READ)
        deadline = time.monotonic() + task.timeout_ms / 1000.0
        killed_for_output = False
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process_group(process)
                break
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                # Pipes can become readable for EOF just after the leader exits.
                continue
            for key, _mask in events:
                fd = key.fileobj.fileno()
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                name, buffer, limit = streams[fd]
                available = max(0, limit - len(buffer))
                if available:
                    buffer.extend(chunk[:available])
                if len(chunk) > available:
                    if name == "stdout":
                        stdout_truncated = True
                    else:
                        stderr_truncated = True
                    killed_for_output = True
            if killed_for_output:
                _terminate_process_group(process)
                break
        if process.poll() is None:
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                _terminate_process_group(process)
        return_code = process.poll()
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        # The leader may exit cleanly after leaving a descendant behind with its
        # standard streams closed.  Reap the whole owned process group even on
        # the successful path so a late writer cannot outlive its task record.
        scope.cleanup_active()

    elapsed_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
    exit_code = return_code if return_code is not None and return_code >= 0 else None
    signal_number = -return_code if return_code is not None and return_code < 0 else None
    return _Observation(
        _Stream(bytes(stdout), stdout_truncated),
        _Stream(bytes(stderr), stderr_truncated),
        started_utc,
        _utc_now(),
        elapsed_ms,
        exit_code,
        signal_number,
        timed_out,
        None,
    )


def _read_result(
    path: Path, expected_validation_run_id: str
) -> tuple[dict[str, Any] | None, str | None, dict[str, Any]]:
    snapshot: _Snapshot | None = None
    relative_path = f"tasks/{path.parent.name}/result.json"
    try:
        snapshot = _read_regular(
            path, "task result", MAX_JSON_BYTES, allow_empty=True
        )
        value = _require_object(_parse_json(snapshot.data, "task result"), "task result")
        _require_exact_keys(
            value,
            {
                "schema_version",
                "status",
                "reason",
                "expected",
                "observed",
                "validation_run_id",
                "corpus_index_sha256",
                "artifacts",
            },
            "task result",
        )
        if value["schema_version"] != "1":
            raise ConfigurationError("task result schema_version must be '1'")
        status_name = _require_string(value["status"], "task result status")
        if status_name not in STATUS_NAMES:
            raise ConfigurationError(f"unsupported task result status '{status_name}'")
        _require_string(value["reason"], "task result reason")
        validation_run_id = _require_string(
            value["validation_run_id"], "task result validation_run_id"
        )
        if validation_run_id != expected_validation_run_id:
            raise ConfigurationError("task result validation_run_id does not match this run")
        value["corpus_index_sha256"] = _validate_sha256(
            value["corpus_index_sha256"], "task result corpus_index_sha256", nullable=True
        )
        if not isinstance(value["artifacts"], list):
            raise ConfigurationError("task result artifacts must be an array")
        if len(value["artifacts"]) > MAX_ARTIFACTS:
            raise ConfigurationError(f"task result contains more than {MAX_ARTIFACTS} artifacts")
        value["artifacts"] = [
            _safe_relative_artifact(item, f"task result artifacts[{index}]")
            for index, item in enumerate(value["artifacts"])
        ]
        if len(set(value["artifacts"])) != len(value["artifacts"]):
            raise ConfigurationError("task result contains duplicate artifacts")
        return (
            value,
            None,
            {
                "path": relative_path,
                "sha256": snapshot.sha256,
                "size_bytes": len(snapshot.data),
                "missing": False,
                "error": None,
            },
        )
    except ConfigurationError as error:
        if snapshot is None:
            metadata = {
                "path": relative_path,
                "sha256": None,
                "size_bytes": None,
                "missing": True,
                "error": str(error),
            }
        else:
            metadata = {
                "path": relative_path,
                "sha256": snapshot.sha256,
                "size_bytes": len(snapshot.data),
                "missing": False,
                "error": str(error),
            }
        return None, str(error), metadata


def _artifact_records(
    task_dir: Path,
    expected: Sequence[str],
    observed: Sequence[str],
    budget: _ArtifactBudget,
) -> tuple[list[dict[str, Any]], str | None]:
    records: list[dict[str, Any]] = []
    error: str | None = None
    if set(expected) != set(observed):
        error = f"artifact inventory mismatch: expected={sorted(expected)}, observed={sorted(observed)}"
    for relative in sorted(set(expected) | set(observed)):
        row: dict[str, Any] = {"path": f"tasks/{task_dir.name}/{relative}"}
        try:
            artifact_sha256, artifact_size = _measure_beneath_regular(
                task_dir,
                relative,
                "task artifact",
                budget.maximum_for_file(),
                allow_empty=True,
            )
            budget.consume(artifact_size)
        except ConfigurationError as artifact_error:
            row.update({"sha256": None, "size_bytes": None, "missing": True, "error": str(artifact_error)})
            error = error or str(artifact_error)
        else:
            row.update(
                {
                    "sha256": artifact_sha256,
                    "size_bytes": artifact_size,
                    "missing": False,
                    "error": None,
                }
            )
        records.append(row)
    return records, error


def _stream_metadata(relative: str, stream: _Stream) -> dict[str, Any]:
    return {
        "path": relative,
        "sha256": _sha256(stream.data),
        "size_bytes": len(stream.data),
        "truncated": stream.truncated,
    }


def _capture_bounded_stdout(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    maximum: int,
    timeout_seconds: float,
) -> tuple[bool, bytes]:
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    output = bytearray()
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(process)
                return False, b""
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                continue
            for key, _mask in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), min(1024 * 1024, maximum + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > maximum:
                    _terminate_process_group(process)
                    return False, b""
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_group(process)
            return False, b""
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            return False, b""
        if return_code != 0:
            return False, b""
        return True, bytes(output)
    except (OSError, subprocess.SubprocessError):
        if process is not None:
            _terminate_process_group(process)
        return False, b""
    finally:
        selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _git_untracked_source_identity(
    root: Path,
    environment: Mapping[str, str],
) -> tuple[bool, str | None]:
    command = [
        "git",
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        *SOURCE_IDENTITY_PATHS,
    ]
    available, listing = _capture_bounded_stdout(
        command,
        cwd=root,
        environment=environment,
        maximum=MAX_GIT_PATH_LIST_BYTES,
        timeout_seconds=10.0,
    )
    if not available or (listing and not listing.endswith(b"\0")):
        return False, None
    raw_paths = listing[:-1].split(b"\0") if listing else []
    if len(raw_paths) > MAX_GIT_UNTRACKED_FILES or len(set(raw_paths)) != len(raw_paths):
        return False, None

    digest = hashlib.sha256()
    total_size = 0
    for raw_path in raw_paths:
        if not raw_path or raw_path.startswith(b"/") or b"\0" in raw_path:
            return False, None
        relative = Path(os.fsdecode(raw_path))
        if any(part in ("", ".", "..") for part in relative.parts):
            return False, None
        requested = root / relative
        try:
            resolved = requested.resolve(strict=True)
            metadata = os.lstat(resolved)
        except (OSError, RuntimeError):
            return False, None
        if Path(os.path.abspath(requested)) != resolved or not stat.S_ISREG(metadata.st_mode):
            return False, None
        remaining = MAX_GIT_UNTRACKED_BYTES - total_size
        if metadata.st_size > remaining:
            return False, None
        try:
            file_hash, file_size = _measure_regular(
                resolved,
                "untracked source file",
                remaining,
                allow_empty=True,
            )
        except ConfigurationError:
            return False, None
        total_size += file_size
        digest.update(len(raw_path).to_bytes(8, "big"))
        digest.update(raw_path)
        digest.update(file_size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(file_hash))

    relisted, final_listing = _capture_bounded_stdout(
        command,
        cwd=root,
        environment=environment,
        maximum=MAX_GIT_PATH_LIST_BYTES,
        timeout_seconds=10.0,
    )
    if not relisted or final_listing != listing:
        return False, None
    return True, digest.hexdigest() if raw_paths else None


def _git_diff_identity(root: Path, environment: Mapping[str, str]) -> tuple[bool, str | None]:
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(
            [
                "git",
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                "HEAD",
                "--",
            ],
            cwd=root,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        digest = hashlib.sha256()
        measured = 0
        deadline = time.monotonic() + 10.0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(process)
                return False, None
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                continue
            for key, _mask in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 1024 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                measured += len(chunk)
                if measured > MAX_GIT_DIFF_BYTES:
                    _terminate_process_group(process)
                    return False, None
                digest.update(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_group(process)
            return False, None
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            return False, None
        if return_code != 0:
            return False, None
        return True, digest.hexdigest() if measured else None
    except (OSError, subprocess.SubprocessError):
        if process is not None:
            _terminate_process_group(process)
        return False, None
    finally:
        selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _git_identity(root: Path) -> tuple[str, str | None]:
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    try:
        commit_run = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        commit = commit_run.stdout.decode("ascii", "strict").strip()
        if commit_run.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", commit):
            return "unavailable", None
        dirty_run = subprocess.run(
            [
                "git",
                "diff",
                "--quiet",
                "--no-ext-diff",
                "--no-textconv",
                "HEAD",
                "--",
            ],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        tracked_hash: str | None
        if dirty_run.returncode == 0:
            tracked_hash = None
        elif dirty_run.returncode != 1:
            return "unavailable", None
        else:
            diff_available, tracked_hash = _git_diff_identity(root, environment)
            if not diff_available or tracked_hash is None:
                return "unavailable", None
        untracked_available, untracked_hash = _git_untracked_source_identity(
            root,
            environment,
        )
        if not untracked_available:
            return "unavailable", None
        if tracked_hash is None and untracked_hash is None:
            return commit, None
        combined = hashlib.sha256()
        for label, value in (
            (b"tracked", tracked_hash),
            (b"untracked-source", untracked_hash),
        ):
            combined.update(label + b"\0")
            combined.update(bytes.fromhex(value) if value is not None else b"-")
            combined.update(b"\0")
        return commit, combined.hexdigest()
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return "unavailable", None


def _validator_identity(entrypoint: _Snapshot, library: _Snapshot) -> dict[str, Any]:
    combined_payload = {
        "protocol_version": "1",
        "files": [
            {"name": "entrypoint", "sha256": entrypoint.sha256},
            {"name": "library", "sha256": library.sha256},
        ],
    }
    combined = _sha256(
        json.dumps(combined_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return {
        "protocol_version": "1",
        "entrypoint": {"sha256": entrypoint.sha256},
        "library": {"sha256": library.sha256},
        "combined_sha256": combined,
        "python_version": sys.version.split()[0],
    }


def _topological_tasks(specification: _Requirements) -> list[_Task]:
    ordered: list[_Task] = []
    completed: set[str] = set()
    while len(ordered) != len(specification.tasks):
        ready = [
            task
            for task in specification.tasks
            if task.task_id not in completed and set(task.depends_on) <= completed
        ]
        if not ready:
            raise ConfigurationError("task dependency graph contains a cycle")
        for task in ready:
            ordered.append(task)
            completed.add(task.task_id)
    return ordered


def _command_identity(task: _Task) -> dict[str, Any]:
    return {
        "path": str(task.executable.path),
        "sha256": task.executable.sha256,
        "size_bytes": task.executable.size_bytes,
    }


def _identity_file_records(task: _Task) -> list[dict[str, Any]]:
    return [
        {
            "path": str(identity.path),
            "sha256": identity.sha256,
            "size_bytes": identity.size_bytes,
        }
        for identity in task.identity_files
    ]


def _task_identity_error(task: _Task) -> str | None:
    try:
        executable_metadata = os.lstat(task.executable.path)
        if not _identity_matches_metadata(task.executable, executable_metadata):
            return f"task executable identity changed: {task.executable.path}"
        for identity in task.identity_files:
            identity_metadata = os.lstat(identity.path)
            if not _identity_matches_metadata(identity, identity_metadata):
                return f"task identity file changed: {identity.path}"
        cwd_metadata = os.lstat(task.cwd)
        if (
            not stat.S_ISDIR(cwd_metadata.st_mode)
            or cwd_metadata.st_dev != task.cwd_device
            or cwd_metadata.st_ino != task.cwd_inode
        ):
            return f"task cwd identity changed: {task.cwd}"
    except (OSError, ConfigurationError) as error:
        return f"task execution identity unavailable: {error}"
    return None


def _terminal_task_identity_error(tasks: Sequence[_Task]) -> str | None:
    """Cryptographically recheck each unique execution-identity inode once."""

    verified: dict[tuple[int, int], tuple[str, int]] = {}
    total_size = 0
    for task in tasks:
        metadata_error = _task_identity_error(task)
        if metadata_error is not None:
            return metadata_error
        for label, identity in (
            (f"task '{task.task_id}' executable", task.executable),
            *(
                (f"task '{task.task_id}' identity file", item)
                for item in task.identity_files
            ),
        ):
            key = (identity.device, identity.inode)
            expected = (identity.sha256, identity.size_bytes)
            if key in verified:
                if verified[key] != expected:
                    return f"conflicting execution identity: {identity.path}"
                continue
            remaining = MAX_TOTAL_EXECUTION_IDENTITY_BYTES - total_size
            if identity.size_bytes > remaining:
                return "execution identity files exceed the terminal audit byte limit"
            try:
                measured = _measure_regular_identity(
                    identity.path,
                    label,
                    min(MAX_ARTIFACT_BYTES, remaining),
                    allow_empty=False,
                )
            except ConfigurationError as error:
                return f"task execution identity unavailable: {error}"
            if measured != identity:
                return f"task execution identity changed: {identity.path}"
            verified[key] = expected
            total_size += measured.size_bytes
    return None


def _record_for_not_run(
    task: _Task,
    statuses: Mapping[str, str],
    profile_sha256: str,
    tool_commit: str,
    dirty_diff_sha256: str | None,
    validation_run_id: str,
    stdout_meta: Mapping[str, Any],
    stderr_meta: Mapping[str, Any],
) -> dict[str, Any]:
    now = _utc_now()
    dependencies = {dependency: statuses.get(dependency, "missing") for dependency in task.depends_on}
    return {
        "schema_version": "1",
        "requirement_id": task.requirement_id,
        "task_id": task.task_id,
        "status": "not_run",
        "reason": f"dependency did not pass: {dependencies}",
        "expected": {"dependencies": "pass"},
        "observed": {"dependencies": dependencies},
        "command_argv": list(task.command_argv),
        "command_executable": _command_identity(task),
        "identity_files": _identity_file_records(task),
        "cwd": str(task.cwd),
        "allowed_env": dict(sorted(task.allowed_env.items())),
        "tool_commit": tool_commit,
        "dirty_diff_sha256": dirty_diff_sha256,
        "validation_run_id": validation_run_id,
        "profile_sha256": profile_sha256,
        "corpus_index_sha256": task.corpus_index_sha256,
        "start_utc": now,
        "end_utc": now,
        "elapsed_ms": 0,
        "exit_code": None,
        "signal": None,
        "stdout": dict(stdout_meta),
        "stderr": dict(stderr_meta),
        "result": {
            "path": f"tasks/{task.task_id}/result.json",
            "sha256": None,
            "size_bytes": None,
            "missing": True,
            "error": "task was not run",
        },
        "artifacts": [],
    }


def _classify_task(
    task: _Task,
    observation: _Observation,
    result: dict[str, Any] | None,
    result_error: str | None,
    identity_error: str | None,
    artifact_error: str | None,
) -> tuple[str, str, Any, Any, str | None]:
    if result is not None and result["status"] == "fail":
        return "fail", result["reason"], result["expected"], result["observed"], result["corpus_index_sha256"]
    if observation.launch_error:
        return "blocked", f"task could not start: {observation.launch_error}", None, None, task.corpus_index_sha256
    if observation.timed_out:
        return "inconclusive", f"task timeout after {task.timeout_ms}ms", None, None, task.corpus_index_sha256
    if observation.stdout.truncated or observation.stderr.truncated:
        streams = []
        if observation.stdout.truncated:
            streams.append("stdout")
        if observation.stderr.truncated:
            streams.append("stderr")
        return "inconclusive", f"task output limit exceeded: {','.join(streams)}", None, None, task.corpus_index_sha256
    if observation.signal_number is not None:
        return "inconclusive", f"task terminated by signal {observation.signal_number}", None, None, task.corpus_index_sha256
    if result is None:
        detail = result_error or "task result is missing"
        return "inconclusive", detail, None, None, task.corpus_index_sha256
    status_name = result["status"]
    if identity_error:
        return "inconclusive", identity_error, result["expected"], result["observed"], result["corpus_index_sha256"]
    if result["corpus_index_sha256"] != task.corpus_index_sha256:
        return (
            "inconclusive",
            "task result corpus_index_sha256 does not match requirements",
            result["expected"],
            result["observed"],
            result["corpus_index_sha256"],
        )
    if artifact_error:
        return "inconclusive", artifact_error, result["expected"], result["observed"], result["corpus_index_sha256"]
    if status_name == "pass" and (result["expected"] is None or result["observed"] is None):
        return (
            "inconclusive",
            "task reported pass without an expected and observed measurement",
            result["expected"],
            result["observed"],
            result["corpus_index_sha256"],
        )
    if status_name == "pass" and _has_skip_evidence(observation.stdout.data, observation.stderr.data):
        return (
            "inconclusive",
            "task reported pass while its raw output reported a skip",
            result["expected"],
            result["observed"],
            result["corpus_index_sha256"],
        )
    if status_name == "pass" and observation.exit_code != 0:
        return (
            "inconclusive",
            f"task reported pass but exited with {observation.exit_code}",
            result["expected"],
            result["observed"],
            result["corpus_index_sha256"],
        )
    return status_name, result["reason"], result["expected"], result["observed"], result["corpus_index_sha256"]


def _has_skip_evidence(stdout: bytes, stderr: bytes) -> bool:
    """Recognize an explicit, line-oriented SKIP verdict without parsing 'last ok'."""

    for raw_line in (stdout + b"\n" + stderr).splitlines():
        line = raw_line.decode("utf-8", "replace").strip()
        if re.match(
            r"^(?:\[[^]]+\]\s+)?SKIP(?:PED)?(?:\s*:|\s|$)",
            line,
            re.IGNORECASE,
        ):
            return True
        for match in re.finditer(r"\bskip(?:ped)?\s*[:=]\s*([0-9]+)\b", line, re.IGNORECASE):
            if match.group(1).strip("0"):
                return True
        for match in re.finditer(r"\b([0-9]+)\s+skip(?:ped)?\b", line, re.IGNORECASE):
            if match.group(1).strip("0"):
                return True
    return False


def _exact_directory_inventory(
    path: Path,
    *,
    expected_files: set[str],
    expected_directories: set[str],
    label: str,
) -> None:
    expected_names = expected_files | expected_directories
    entries: dict[str, os.DirEntry[str]] = {}
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                entries[entry.name] = entry
                if len(entries) > len(expected_names):
                    raise EvidenceError(f"{label} contains unexpected evidence entries")
    except OSError as error:
        raise EvidenceError(f"could not inspect {label}: {error}") from error
    observed_names = set(entries)
    if observed_names != expected_names:
        raise EvidenceError(
            f"{label} inventory mismatch: missing={sorted(expected_names - observed_names)}, "
            f"unexpected={sorted(observed_names - expected_names)}"
        )
    for name in expected_files:
        try:
            metadata = entries[name].stat(follow_symlinks=False)
        except OSError as error:
            raise EvidenceError(f"could not inspect {label} file '{name}': {error}") from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise EvidenceError(f"{label} file is not a private regular file: {name}")
    for name in expected_directories:
        try:
            metadata = entries[name].stat(follow_symlinks=False)
        except OSError as error:
            raise EvidenceError(f"could not inspect {label} directory '{name}': {error}") from error
        if not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceError(f"{label} entry is not a directory: {name}")


def _audit_task_tree(task_dir: Path, task_id: str, record: Mapping[str, Any]) -> None:
    expected_files: set[str] = set()
    result_value = record.get("result")
    if not isinstance(result_value, dict):
        raise EvidenceError(f"task record {task_id} has invalid result metadata")
    result_prefix = f"tasks/{task_id}/"
    result_path = result_value.get("path")
    if result_path != result_prefix + "result.json":
        raise EvidenceError(f"task record {task_id} has invalid result path")
    if result_value.get("missing") is False:
        expected_files.add("result.json")
    elif result_value.get("missing") is not True:
        raise EvidenceError(f"task record {task_id} has invalid result missing flag")

    artifact_values = record.get("artifacts")
    if not isinstance(artifact_values, list):
        raise EvidenceError(f"task record {task_id} has invalid artifacts metadata")
    for artifact in artifact_values:
        if not isinstance(artifact, dict):
            raise EvidenceError(f"task record {task_id} has invalid artifact metadata")
        artifact_path = artifact.get("path")
        if not isinstance(artifact_path, str) or not artifact_path.startswith(result_prefix):
            raise EvidenceError(f"task record {task_id} has invalid artifact path")
        if artifact.get("missing") is False:
            expected_files.add(artifact_path[len(result_prefix) :])
        elif artifact.get("missing") is not True:
            raise EvidenceError(f"task record {task_id} has invalid artifact missing flag")

    expected_directories: set[str] = set()
    for relative in expected_files:
        parts = Path(relative).parts
        for depth in range(1, len(parts)):
            expected_directories.add(Path(*parts[:depth]).as_posix())
    if expected_files & expected_directories:
        raise EvidenceError(f"task {task_id} evidence contains a file/directory collision")

    directories = {"": task_dir}
    for relative in sorted(expected_directories, key=lambda value: (value.count("/"), value)):
        directories[relative] = task_dir / relative
    for relative, directory in directories.items():
        prefix = f"{relative}/" if relative else ""
        direct_files = {
            value[len(prefix) :]
            for value in expected_files
            if value.startswith(prefix) and "/" not in value[len(prefix) :]
        }
        direct_directories = {
            value[len(prefix) :]
            for value in expected_directories
            if value.startswith(prefix) and "/" not in value[len(prefix) :]
        }
        _exact_directory_inventory(
            directory,
            expected_files=direct_files,
            expected_directories=direct_directories,
            label=f"task {task_id} evidence directory '{relative or '.'}'",
        )


def _audit_evidence_tree(
    evidence_dir: Path,
    specification: _Requirements,
    records: Mapping[str, Mapping[str, Any]],
    requirement_ids: Iterable[str],
    *,
    include_summary: bool,
) -> None:
    root_files = {"run.json"}
    if include_summary:
        root_files.add("summary.json")
    _exact_directory_inventory(
        evidence_dir,
        expected_files=root_files,
        expected_directories={"records", "logs", "tasks", "requirements"},
        label="evidence root",
    )
    task_ids = {task.task_id for task in specification.tasks}
    _exact_directory_inventory(
        evidence_dir / "records",
        expected_files={f"{task_id}.json" for task_id in task_ids},
        expected_directories=set(),
        label="record directory",
    )
    _exact_directory_inventory(
        evidence_dir / "logs",
        expected_files={
            f"{task_id}.{stream_name}"
            for task_id in task_ids
            for stream_name in ("stdout", "stderr")
        },
        expected_directories=set(),
        label="log directory",
    )
    _exact_directory_inventory(
        evidence_dir / "tasks",
        expected_files=set(),
        expected_directories=task_ids,
        label="task directory",
    )
    for task_id in sorted(task_ids):
        _audit_task_tree(evidence_dir / "tasks" / task_id, task_id, records[task_id])
    _exact_directory_inventory(
        evidence_dir / "requirements",
        expected_files={f"{requirement_id}.json" for requirement_id in requirement_ids},
        expected_directories=set(),
        label="requirement directory",
    )


def _audit_requirement_evidence(
    requirements_dir: Path,
    expected_hashes: Mapping[str, str],
) -> None:
    for requirement_id, expected_hash in sorted(expected_hashes.items()):
        snapshot = _read_regular(
            requirements_dir / f"{requirement_id}.json",
            f"{requirement_id} requirement evidence",
            MAX_JSON_BYTES,
        )
        if snapshot.sha256 != expected_hash:
            raise EvidenceError(
                f"requirement evidence changed after publication: {requirement_id}"
            )


def _audit_records(
    records_dir: Path,
    specification: _Requirements,
    expected_hashes: Mapping[str, str],
    evidence_dir: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    expected_ids = {task.task_id for task in specification.tasks}
    expected_names = {f"{task_id}.json" for task_id in expected_ids}
    _exact_directory_inventory(
        records_dir,
        expected_files=expected_names,
        expected_directories=set(),
        label="record directory",
    )
    records: dict[str, dict[str, Any]] = {}
    hashes: dict[str, str] = {}
    seen_content_ids: set[str] = set()
    by_task = {task.task_id: task for task in specification.tasks}
    artifact_budget = _ArtifactBudget(MAX_TOTAL_ARTIFACT_BYTES)
    for task_id in sorted(expected_ids):
        snapshot = _read_regular(records_dir / f"{task_id}.json", "task record", MAX_JSON_BYTES)
        if snapshot.sha256 != expected_hashes.get(task_id):
            raise EvidenceError(f"task record changed after publication: {task_id}")
        value = _require_object(_parse_json(snapshot.data, "task record"), "task record")
        if value.get("task_id") != task_id or value.get("requirement_id") != by_task[task_id].requirement_id:
            raise EvidenceError(f"task record identity mismatch: {task_id}")
        if task_id in seen_content_ids:
            raise EvidenceError(f"duplicate task record identity: {task_id}")
        seen_content_ids.add(task_id)
        if value.get("status") not in STATUS_NAMES:
            raise EvidenceError(f"task record has invalid status: {task_id}")
        for stream_name in ("stdout", "stderr"):
            stream_value = value.get(stream_name)
            if not isinstance(stream_value, dict):
                raise EvidenceError(f"task record {task_id} has invalid {stream_name} metadata")
            relative = stream_value.get("path")
            if not isinstance(relative, str):
                raise EvidenceError(f"task record {task_id} has no {stream_name} path")
            log_sha256, log_size = _measure_regular(
                evidence_dir / relative,
                f"{task_id} {stream_name} log",
                MAX_STREAM_BYTES,
                allow_empty=True,
            )
            if (
                log_sha256 != stream_value.get("sha256")
                or log_size != stream_value.get("size_bytes")
            ):
                raise EvidenceError(f"task record {task_id} {stream_name} log changed")
        result_value = value.get("result")
        if not isinstance(result_value, dict):
            raise EvidenceError(f"task record {task_id} has invalid result metadata")
        expected_result_path = f"tasks/{task_id}/result.json"
        if result_value.get("path") != expected_result_path:
            raise EvidenceError(f"task record {task_id} has invalid result path")
        if result_value.get("missing") is True:
            if os.path.lexists(evidence_dir / expected_result_path):
                raise EvidenceError(f"task record {task_id} hides a result entry")
        elif result_value.get("missing") is False:
            try:
                result_sha256, result_size = _measure_beneath_regular(
                    evidence_dir / "tasks" / task_id,
                    "result.json",
                    f"{task_id} result evidence",
                    MAX_JSON_BYTES,
                    allow_empty=True,
                )
            except ConfigurationError as error:
                raise EvidenceError(str(error)) from error
            if (
                result_sha256 != result_value.get("sha256")
                or result_size != result_value.get("size_bytes")
            ):
                raise EvidenceError(f"task record {task_id} result evidence changed")
        else:
            raise EvidenceError(f"task record {task_id} has invalid result missing flag")
        artifact_values = value.get("artifacts")
        if not isinstance(artifact_values, list):
            raise EvidenceError(f"task record {task_id} has invalid artifacts metadata")
        artifact_prefix = f"tasks/{task_id}/"
        seen_artifact_paths: set[str] = set()
        for artifact_value in artifact_values:
            if not isinstance(artifact_value, dict):
                raise EvidenceError(f"task record {task_id} has invalid artifact metadata")
            artifact_path = artifact_value.get("path")
            if not isinstance(artifact_path, str) or not artifact_path.startswith(artifact_prefix):
                raise EvidenceError(f"task record {task_id} has invalid artifact path")
            relative = artifact_path[len(artifact_prefix) :]
            try:
                relative = _safe_relative_artifact(relative, f"{task_id} artifact path")
            except ConfigurationError as error:
                raise EvidenceError(str(error)) from error
            if relative in seen_artifact_paths:
                raise EvidenceError(f"task record {task_id} has duplicate artifact path: {relative}")
            seen_artifact_paths.add(relative)
            if artifact_value.get("missing") is True:
                continue
            if artifact_value.get("missing") is not False:
                raise EvidenceError(f"task record {task_id} has invalid artifact missing flag: {relative}")
            try:
                artifact_sha256, artifact_size = _measure_beneath_regular(
                    evidence_dir / "tasks" / task_id,
                    relative,
                    f"{task_id} artifact",
                    artifact_budget.maximum_for_file(),
                    allow_empty=True,
                )
                artifact_budget.consume(artifact_size)
            except ConfigurationError as error:
                raise EvidenceError(str(error)) from error
            if (
                artifact_sha256 != artifact_value.get("sha256")
                or artifact_size != artifact_value.get("size_bytes")
            ):
                raise EvidenceError(f"task record {task_id} artifact changed: {relative}")
        records[task_id] = value
        hashes[task_id] = snapshot.sha256
    return records, hashes


def _identity_error(snapshots: Iterable[_Snapshot]) -> str | None:
    for snapshot in snapshots:
        unchanged, error = _snapshot_unchanged(snapshot)
        if not unchanged:
            return error or f"identity changed: {snapshot.path}"
    return None


def run_acceptance(
    *,
    target: str,
    profile_path: Path,
    suite: str,
    evidence_dir: Path,
    requirements_path: Path,
    entrypoint_path: Path,
) -> int:
    """Run one explicitly selected acceptance suite and return 0, 1, or 2.

    ConfigurationError is raised before task execution for malformed arguments,
    profiles, requirements, or test hooks.  The CLI maps it to EX_USAGE (64).
    Once the initial run manifest exists, operational failures return 2 and leave
    that manifest incomplete; a completed normal run publishes summary.json last.
    """

    target = _require_string(target, "target")
    if not _SAFE_ID.fullmatch(target):
        raise ConfigurationError("target is not a safe identifier")
    if suite not in SUPPORTED_SUITES:
        raise ConfigurationError(f"unsupported suite '{suite}'")
    profile_path = _canonicalize_parent(Path(profile_path), "target profile")
    requirements_path = _canonicalize_parent(Path(requirements_path), "requirements")
    evidence_dir = _canonicalize_parent(Path(evidence_dir), "evidence directory")
    entrypoint_path = Path(entrypoint_path)
    if os.path.lexists(evidence_dir):
        raise ConfigurationError(f"evidence directory already exists: {evidence_dir}")

    profile_snapshot = _read_regular(profile_path, "target profile")
    _validate_profile(profile_snapshot, target)
    requirements_snapshot = _read_regular(requirements_path, "requirements")
    specification = _parse_requirements(requirements_snapshot)
    if specification.target_id != target:
        raise ConfigurationError(
            f"requirements target mismatch: requested '{target}', observed '{specification.target_id}'"
        )
    if specification.suite != suite:
        raise ConfigurationError(
            f"requirements suite mismatch: requested '{suite}', observed '{specification.suite}'"
        )
    if specification.profile_sha256 != profile_snapshot.sha256:
        raise ConfigurationError(
            "requirements profile_sha256 mismatch: "
            f"expected {profile_snapshot.sha256}, observed {specification.profile_sha256}"
        )

    entrypoint_snapshot = _read_regular(entrypoint_path, "validator entrypoint")
    library_snapshot = _read_regular(Path(__file__).resolve(), "validator library", 8 * MAX_JSON_BYTES)
    validator = _validator_identity(entrypoint_snapshot, library_snapshot)
    ordered_tasks = _topological_tasks(specification)
    _require_dedicated_process()

    hook = os.environ.get(TEST_HOOK_ENV)
    fail_record_task: str | None = None
    if hook:
        prefix = "fail-record-replace:"
        if not hook.startswith(prefix) or not hook[len(prefix) :]:
            raise ConfigurationError(f"unsupported {TEST_HOOK_ENV} value")
        fail_record_task = hook[len(prefix) :]
        if fail_record_task not in {task.task_id for task in specification.tasks}:
            raise ConfigurationError(f"test hook names unknown task '{fail_record_task}'")

    project_root = Path(__file__).resolve().parents[2]
    tool_commit, dirty_diff_sha256 = _git_identity(project_root)
    started_utc = _utc_now()
    validation_run_id = f"FND03-{suite}-{uuid.uuid4().hex}"
    required_task_ids = [task_id for req in specification.requirements for task_id in req.required_task_ids]
    required_requirement_ids = [req.requirement_id for req in specification.requirements]

    evidence_parent_fd: int | None = None
    evidence_fd: int | None = None
    try:
        evidence_parent_fd = _open_directory(evidence_dir.parent)
        _mkdir_private(evidence_dir)
        _fsync_directory(evidence_dir.parent)
        evidence_fd = _open_directory(evidence_dir)
        directory_identities = [_directory_identity(evidence_dir)]
        for child_name in ("records", "logs", "tasks", "requirements"):
            _mkdir_private(evidence_dir / child_name)
            directory_identities.append(_directory_identity(evidence_dir / child_name))
        _fsync_directory(evidence_dir)
        run_manifest = {
            "schema_version": "1",
            "state": "incomplete",
            "target_id": target,
            "suite": suite,
            "profile_path": str(profile_path),
            "profile_sha256": profile_snapshot.sha256,
            "requirements_path": str(requirements_path),
            "requirements_sha256": requirements_snapshot.sha256,
            "required_requirement_ids": required_requirement_ids,
            "required_task_ids": required_task_ids,
            "validator": validator,
            "tool_commit": tool_commit,
            "dirty_diff_sha256": dirty_diff_sha256,
            "validation_run_id": validation_run_id,
            "start_utc": started_utc,
        }
        run_manifest_bytes = _canonical_json(run_manifest)
        run_manifest_sha256 = _sha256(run_manifest_bytes)
        _atomic_write(evidence_dir, "run.json", run_manifest_bytes)
    except (EvidenceError, OSError) as error:
        if evidence_fd is not None or evidence_parent_fd is not None:
            _remove_untrusted_terminal_files(
                evidence_dir,
                evidence_fd,
                evidence_parent_fd,
            )
        if evidence_fd is not None:
            os.close(evidence_fd)
        if evidence_parent_fd is not None:
            os.close(evidence_parent_fd)
        print(f"[format-acceptance] evidence setup failed: {error}", file=sys.stderr)
        return 2

    records_dir = evidence_dir / "records"
    logs_dir = evidence_dir / "logs"
    tasks_dir = evidence_dir / "tasks"
    requirements_dir = evidence_dir / "requirements"
    statuses: dict[str, str] = {}
    expected_record_hashes: dict[str, str] = {}
    artifact_budget = _ArtifactBudget(MAX_TOTAL_ARTIFACT_BYTES)
    identity_snapshots = (profile_snapshot, requirements_snapshot, entrypoint_snapshot, library_snapshot)

    try:
        with _SignalScope() as signal_scope:
            for task in ordered_tasks:
                pre_spawn_identity_error = _task_identity_error(task)
                if pre_spawn_identity_error is not None:
                    raise EvidenceError(pre_spawn_identity_error)
                task_dir = tasks_dir / task.task_id
                _mkdir_private(task_dir)
                directory_identities.append(_directory_identity(task_dir))
                stdout_relative = f"logs/{task.task_id}.stdout"
                stderr_relative = f"logs/{task.task_id}.stderr"
                child_validation_run_id = (
                    f"{validation_run_id}-{_sha256(task.task_id.encode('utf-8'))[:16]}"
                )

                if any(statuses.get(dependency) != "pass" for dependency in task.depends_on):
                    stdout_stream = _Stream(b"", False)
                    stderr_stream = _Stream(b"", False)
                    _atomic_write(logs_dir, f"{task.task_id}.stdout", b"")
                    _atomic_write(logs_dir, f"{task.task_id}.stderr", b"")
                    record = _record_for_not_run(
                        task,
                        statuses,
                        profile_snapshot.sha256,
                        tool_commit,
                        dirty_diff_sha256,
                        child_validation_run_id,
                        _stream_metadata(stdout_relative, stdout_stream),
                        _stream_metadata(stderr_relative, stderr_stream),
                    )
                else:
                    result_path = task_dir / "result.json"
                    child_env = dict(task.allowed_env)
                    child_env.update(
                        {
                            RESULT_PATH_ENV: str(result_path),
                            TASK_DIR_ENV: str(task_dir),
                            PROFILE_PATH_ENV: str(profile_path),
                            PROFILE_SHA256_ENV: profile_snapshot.sha256,
                            TARGET_ENV: target,
                            SUITE_ENV: suite,
                            TASK_ID_ENV: task.task_id,
                            TOOL_TARGET_PROFILE_ENV: str(profile_path.resolve(strict=True)),
                            TOOL_PROFILE_SHA256_ENV: profile_snapshot.sha256,
                            TOOL_VALIDATION_RUN_ENV: child_validation_run_id,
                        }
                    )
                    observation = _run_child(task, child_env, signal_scope)
                    _atomic_write(logs_dir, f"{task.task_id}.stdout", observation.stdout.data)
                    _atomic_write(logs_dir, f"{task.task_id}.stderr", observation.stderr.data)
                    result, result_error, result_metadata = _read_result(
                        result_path, child_validation_run_id
                    )
                    observed_artifacts: Sequence[str] = result["artifacts"] if result is not None else ()
                    artifacts, artifact_error = _artifact_records(
                        task_dir,
                        task.artifacts,
                        observed_artifacts,
                        artifact_budget,
                    )
                    current_identity_error = _identity_error(identity_snapshots)
                    current_identity_error = current_identity_error or _task_identity_error(task)
                    status_name, reason, expected, observed, corpus_hash = _classify_task(
                        task,
                        observation,
                        result,
                        result_error,
                        current_identity_error,
                        artifact_error,
                    )
                    record = {
                        "schema_version": "1",
                        "requirement_id": task.requirement_id,
                        "task_id": task.task_id,
                        "status": status_name,
                        "reason": reason,
                        "expected": expected,
                        "observed": observed,
                        "command_argv": list(task.command_argv),
                        "command_executable": _command_identity(task),
                        "identity_files": _identity_file_records(task),
                        "cwd": str(task.cwd),
                        "allowed_env": dict(sorted(task.allowed_env.items())),
                        "tool_commit": tool_commit,
                        "dirty_diff_sha256": dirty_diff_sha256,
                        "validation_run_id": child_validation_run_id,
                        "profile_sha256": profile_snapshot.sha256,
                        "corpus_index_sha256": corpus_hash,
                        "start_utc": observation.start_utc,
                        "end_utc": observation.end_utc,
                        "elapsed_ms": observation.elapsed_ms,
                        "exit_code": observation.exit_code,
                        "signal": observation.signal_number,
                        "stdout": _stream_metadata(stdout_relative, observation.stdout),
                        "stderr": _stream_metadata(stderr_relative, observation.stderr),
                        "result": result_metadata,
                        "artifacts": artifacts,
                    }
                record_bytes = _canonical_json(record)
                _atomic_write(
                    records_dir,
                    f"{task.task_id}.json",
                    record_bytes,
                    inject_failure=fail_record_task == task.task_id,
                )
                statuses[task.task_id] = record["status"]
                expected_record_hashes[task.task_id] = _sha256(record_bytes)

            _verify_directory_identities(directory_identities)
            run_snapshot = _read_regular(evidence_dir / "run.json", "run manifest", MAX_JSON_BYTES)
            if run_snapshot.sha256 != run_manifest_sha256:
                raise EvidenceError("run manifest changed after publication")
            records, record_hashes = _audit_records(
                records_dir, specification, expected_record_hashes, evidence_dir
            )
            _audit_evidence_tree(
                evidence_dir,
                specification,
                records,
                (),
                include_summary=False,
            )
            final_identity_error = _identity_error(identity_snapshots)
            final_identity_error = final_identity_error or _terminal_task_identity_error(
                specification.tasks
            )
            if tool_commit == "unavailable":
                final_identity_error = final_identity_error or "tool commit identity unavailable"
            end_commit, end_dirty_diff = _git_identity(project_root)
            if (end_commit, end_dirty_diff) != (tool_commit, dirty_diff_sha256):
                final_identity_error = final_identity_error or "tool source identity changed during acceptance run"

            counts = {status_name: 0 for status_name in STATUS_NAMES}
            for task_id in required_task_ids:
                counts[records[task_id]["status"]] += 1
            if counts["fail"]:
                overall_status = "fail"
                result_code = 1
            elif counts["pass"] == len(required_task_ids) and final_identity_error is None:
                overall_status = "pass"
                result_code = 0
            else:
                overall_status = "incomplete"
                result_code = 2

            requirement_hashes: dict[str, str] = {}
            for requirement in specification.requirements:
                requirement_statuses = [records[task_id]["status"] for task_id in requirement.required_task_ids]
                if "fail" in requirement_statuses:
                    requirement_status = "fail"
                elif (
                    final_identity_error is None
                    and all(status_name == "pass" for status_name in requirement_statuses)
                ):
                    requirement_status = "pass"
                else:
                    requirement_status = "incomplete"
                aggregate = {
                    "schema_version": "1",
                    "requirement_id": requirement.requirement_id,
                    "status": requirement_status,
                    "profile_sha256": profile_snapshot.sha256,
                    "requirements_sha256": requirements_snapshot.sha256,
                    "run_manifest_sha256": run_manifest_sha256,
                    "validation_run_id": validation_run_id,
                    "suite": suite,
                    "validator": validator,
                    "records": [
                        {"task_id": task_id, "record_sha256": record_hashes[task_id]}
                        for task_id in requirement.required_task_ids
                    ],
                }
                aggregate_bytes = _canonical_json(aggregate)
                _atomic_write(requirements_dir, f"{requirement.requirement_id}.json", aggregate_bytes)
                requirement_hashes[requirement.requirement_id] = _sha256(aggregate_bytes)

            _verify_directory_identities(directory_identities)
            _audit_evidence_tree(
                evidence_dir,
                specification,
                records,
                required_requirement_ids,
                include_summary=False,
            )
            _audit_requirement_evidence(requirements_dir, requirement_hashes)
            summary = {
                "schema_version": "1",
                "state": "complete",
                "overall_status": overall_status,
                "counts": counts,
                "target_id": target,
                "suite": suite,
                "profile_sha256": profile_snapshot.sha256,
                "requirements_sha256": requirements_snapshot.sha256,
                "run_manifest_sha256": run_manifest_sha256,
                "validation_run_id": validation_run_id,
                "required_requirement_ids": required_requirement_ids,
                "required_task_ids": required_task_ids,
                "record_sha256": record_hashes,
                "requirement_evidence_sha256": requirement_hashes,
                "validator": validator,
                "identity_error": final_identity_error,
                # A single explicitly selected suite cannot authorize a target.
                # Format-07 assembles reviewed, multi-suite Q01-Q12 evidence.
                "qualification_candidate": None,
                "start_utc": started_utc,
                "end_utc": _utc_now(),
            }
            summary_bytes = _canonical_json(summary)
            summary_sha256 = _sha256(summary_bytes)
            _atomic_write(evidence_dir, "summary.json", summary_bytes)
            published_summary = _read_regular(
                evidence_dir / "summary.json", "summary", MAX_JSON_BYTES
            )
            if published_summary.sha256 != summary_sha256:
                raise EvidenceError("summary changed after publication")
            _verify_directory_identities(directory_identities)
            _audit_evidence_tree(
                evidence_dir,
                specification,
                records,
                required_requirement_ids,
                include_summary=True,
            )
            _audit_requirement_evidence(requirements_dir, requirement_hashes)
            return result_code
    except (_RunInterrupted, KeyboardInterrupt) as error:
        _remove_untrusted_terminal_files(evidence_dir, evidence_fd, evidence_parent_fd)
        print(f"[format-acceptance] interrupted: {error}", file=sys.stderr)
        return 2
    except (EvidenceError, ConfigurationError, OSError) as error:
        _remove_untrusted_terminal_files(evidence_dir, evidence_fd, evidence_parent_fd)
        print(f"[format-acceptance] evidence incomplete: {error}", file=sys.stderr)
        return 2
    finally:
        if evidence_fd is not None:
            os.close(evidence_fd)
        if evidence_parent_fd is not None:
            os.close(evidence_parent_fd)


__all__ = ["ConfigurationError", "EvidenceError", "SUPPORTED_SUITES", "run_acceptance"]
