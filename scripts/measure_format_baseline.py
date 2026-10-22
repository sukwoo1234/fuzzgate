#!/usr/bin/env python3
"""Validate, evaluate, and preserve paired format-performance observations.

The real mode consumes observations produced by a separately pinned workload
driver.  It never treats this script's synthetic self-test as performance
evidence.  Evidence is published into a new comparison directory only; an
existing path is never replaced.
"""

from __future__ import annotations

import argparse
import copy
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import random
import re
import stat
import statistics
import sys
import tempfile
from typing import Any, Callable, Iterable, Sequence
import uuid


SCHEMA_VERSION = "format-performance-observation-v1"
EVALUATION_VERSION = "format-performance-evaluation-v1"
INDEX_VERSION = "format-performance-evidence-v1"
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SHA256_RE = re.compile(r"[0-9A-Fa-f]{64}")
BOOTSTRAP_SEED = 0
BOOTSTRAP_RESAMPLES = 10_000
MIN_PAIRS = 5
MAX_PAIRS = 10
MIN_REAL_SAMPLE_SECONDS = 60.0
MAX_LATENCY_BATCH_ITERATIONS = 1_000_000
MAX_U64 = (1 << 64) - 1
SUPPORTED_MEMORY_COLLECTORS = {"cgroup-v2-memory.peak"}
MEMORY_COLLECTOR_CONFIG = {
    "cgroup_version": 2,
    "membership_scope": "private_leaf_process_tree",
    "peak_file": "memory.peak",
    "sample_lifecycle": "new_cgroup_per_sample",
}
SELFTEST_MEMORY_COLLECTOR_RAW = (
    "selftest collector identity only; real observations must embed the exact collector implementation\n"
)


class ContractError(ValueError):
    """The observation does not satisfy the FND-05/V6 contract."""


class EvidenceError(RuntimeError):
    """Evidence could not be published without replacement."""


def _canonical_json(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ContractError("JSON contains a string that is not valid UTF-8") from error
    except (OverflowError, TypeError, ValueError) as error:
        raise ContractError(f"JSON cannot be represented canonically: {error}") from error


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_profile_sha256(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value))


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json_text(text: str, label: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ContractError(f"{label} is not strict JSON: {error}") from error
    _validate_json_values(value, label)
    return value


def _validate_json_values(value: Any, label: str) -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise ContractError(f"{label} contains a string that is not valid UTF-8") from error
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractError(f"{label} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_values(item, f"{label}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"{label} has a non-string key")
            try:
                key.encode("utf-8", "strict")
            except UnicodeEncodeError as error:
                raise ContractError(f"{label} has an object key that is not valid UTF-8") from error
            _validate_json_values(item, f"{label}.{key}")
        return
    raise ContractError(f"{label} contains unsupported value type {type(value).__name__}")


def _object(value: Any, label: str, expected_keys: Iterable[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    expected = set(expected_keys)
    observed = set(value)
    if observed != expected:
        missing = sorted(expected - observed)
        unknown = sorted(observed - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unknown:
            details.append(f"unknown={','.join(unknown)}")
        raise ContractError(f"{label} fields mismatch ({'; '.join(details)})")
    return value


def _object_with_optional(
    value: Any,
    label: str,
    required_keys: Iterable[str],
    optional_keys: Iterable[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    required = set(required_keys)
    allowed = required | set(optional_keys)
    observed = set(value)
    missing = sorted(required - observed)
    unknown = sorted(observed - allowed)
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unknown:
            details.append(f"unknown={','.join(unknown)}")
        raise ContractError(f"{label} fields mismatch ({'; '.join(details)})")
    return value


def _string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise ContractError(f"{label} must be {'a non-empty ' if nonempty else ''}string")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ContractError(f"{label} must be valid UTF-8") from error
    return value


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        raise ContractError(f"{label} must be >= {minimum}")
    if maximum is not None and value > maximum:
        message = (
            f"{label} must fit unsigned 64-bit range"
            if maximum == MAX_U64
            else f"{label} must be <= {maximum}"
        )
        raise ContractError(message)
    return value


def _checked_add_u64(left: int, right: int, label: str) -> int:
    result = left + right
    if left < 0 or right < 0 or result > MAX_U64:
        raise ContractError(f"{label} must fit unsigned 64-bit range")
    return result


def _checked_product_u64(left: int, right: int, label: str) -> int:
    result = left * right
    if left < 0 or right < 0 or result > MAX_U64:
        raise ContractError(f"{label} must fit unsigned 64-bit range")
    return result


def _checked_sum_u64(values: Iterable[int], label: str) -> int:
    result = 0
    for value in values:
        result = _checked_add_u64(result, value, label)
    return result


def _unsigned(value: Any, label: str, *, bits: int, minimum: int = 0) -> int:
    result = _integer(value, label, minimum=minimum)
    if result > (1 << bits) - 1:
        raise ContractError(f"{label} exceeds unsigned {bits}-bit range")
    return result


def _number(value: Any, label: str, *, minimum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{label} must be a number")
    try:
        result = float(value)
    except (OverflowError, ValueError) as error:
        raise ContractError(f"{label} must be a finite representable number") from error
    if not math.isfinite(result):
        raise ContractError(f"{label} must be finite")
    if minimum is not None and result < minimum:
        raise ContractError(f"{label} must be >= {minimum}")
    return result


def _finite_derived(value: float, label: str) -> float:
    if not math.isfinite(value):
        raise ContractError(f"{label} must be a finite derived number")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if not SHA256_RE.fullmatch(text):
        raise ContractError(f"{label} must be a 64-digit hexadecimal SHA-256")
    if text.lower() == "0" * 64:
        raise ContractError(f"{label} must not be an all-zero placeholder")
    return text.lower()


def _commit(value: Any, label: str) -> str:
    text = _string(value, label)
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", text) is None:
        raise ContractError(f"{label} must be an exact lowercase commit id")
    return text


def _json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _json_differences(left: Any, right: Any, pointer: str = "") -> set[str]:
    if type(left) is not type(right):
        return {pointer or "/"}
    if isinstance(left, dict):
        result: set[str] = set()
        for key in sorted(set(left) | set(right)):
            child = f"{pointer}/{_json_pointer_escape(key)}"
            if key not in left or key not in right:
                result.add(child)
            else:
                result.update(_json_differences(left[key], right[key], child))
        return result
    if isinstance(left, list):
        result = set()
        maximum = max(len(left), len(right))
        for index in range(maximum):
            child = f"{pointer}/{index}"
            if index >= len(left) or index >= len(right):
                result.add(child)
            else:
                result.update(_json_differences(left[index], right[index], child))
        return result
    return set() if left == right else {pointer or "/"}


def _nearest_rank(values: Sequence[float], percentile: float) -> float:
    if not values:
        raise ContractError("nearest-rank requires at least one value")
    ordered = sorted(_finite_derived(float(value), "nearest-rank input") for value in values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def _median(values: Sequence[float]) -> float:
    if not values:
        raise ContractError("median requires at least one value")
    checked = [_finite_derived(float(value), "median input") for value in values]
    return _finite_derived(float(statistics.median(checked)), "median result")


def bootstrap_median_ci(ratios: Sequence[float]) -> tuple[float, float]:
    """Return a Random(0), 10,000-resample nearest-rank 95% interval.

    Each element is already a ratio from one paired baseline/candidate index.
    Resampling these indexes preserves the pairing; the two arms are never
    resampled independently.
    """

    if not ratios:
        raise ContractError("bootstrap requires at least one paired ratio")
    checked = [
        _finite_derived(_number(value, "bootstrap ratio", minimum=0.0), "bootstrap ratio")
        for value in ratios
    ]
    generator = random.Random(BOOTSTRAP_SEED)
    count = len(checked)
    medians: list[float] = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        medians.append(_median([checked[generator.randrange(count)] for _ in range(count)]))
    return _nearest_rank(medians, 0.025), _nearest_rank(medians, 0.975)


FIXED_IDENTITY_FIELDS = {
    "target_id",
    "depth",
    "parser_pin",
    "toolchain_pin",
    "target_patch_sha256",
    "engine_flags",
    "corpus_sha256",
    "corpus_index_raw_json",
    "corpus_index_sha256",
    "corpus_input_count",
    "workers",
    "threads",
    "input_timeout_ms",
    "memory_limit_bytes",
    "filesystem_path_type",
    "log_level",
    "cache_policy",
}

IDENTITY_FIELDS = {
    "fixed",
    "baseline_profile",
    "candidate_profile",
    "baseline_profile_raw_json",
    "candidate_profile_raw_json",
    "baseline_profile_sha256",
    "candidate_profile_sha256",
    "baseline_profile_canonical_sha256",
    "candidate_profile_canonical_sha256",
    "allowed_profile_differences",
    "baseline_tool_commit",
    "candidate_tool_commit",
    "baseline_source_state",
    "candidate_source_state",
    "baseline_dirty_diff_raw_text",
    "candidate_dirty_diff_raw_text",
    "baseline_dirty_diff_sha256",
    "candidate_dirty_diff_sha256",
    "baseline_command",
    "candidate_command",
    "baseline_command_sha256",
    "candidate_command_sha256",
    "baseline_source_artifacts",
    "candidate_source_artifacts",
    "allowed_tool_changes",
}

PROFILE_REQUIRED_FIELDS = {
    "schema_version",
    "target_id",
    "format_revision",
    "loader_id",
    "loader_version",
    "source_artifacts",
    "patches",
    "toolchain",
    "sanitizer_policy",
    "binaries",
    "input_kind",
    "depth",
    "engine_capabilities",
    "limits",
    "coverage_scope",
}

FORBIDDEN_PROFILE_DIFF_PREFIXES = (
    "/schema_version",
    "/target_id",
    "/format_revision",
    "/loader_id",
    "/loader_version",
    "/source_artifacts",
    "/patches",
    "/toolchain",
    "/sanitizer_policy",
    "/input_kind",
    "/depth",
    "/engine_capabilities",
    "/limits",
    "/coverage_scope",
)

COMMAND_FIELDS = {"argv", "allowed_env", "cwd", "executable_sha256"}
COMMAND_OS_ENV_ALLOWLIST = {
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TZ",
    "WINDIR",
}

PROFILE_ALLOWED_ENV = {
    "ASAN_OPTIONS",
    "GGUF_FUZZ_DEPTH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LSAN_OPTIONS",
    "MKL_NUM_THREADS",
    "MSAN_OPTIONS",
    "NUMEXPR_NUM_THREADS",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "PATH",
    "RUST_BACKTRACE",
    "RUST_MIN_STACK",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TSAN_OPTIONS",
    "TZ",
    "UBSAN_OPTIONS",
    "VECLIB_MAXIMUM_THREADS",
}


def _profile_text(value: Any, label: str) -> str:
    text = _string(value, label)
    if len(text.encode("utf-8")) > 4096 or "\0" in text or "\r" in text or "\n" in text or not text.strip():
        raise ContractError(f"{label} contains invalid characters or is too long")
    return text


def _profile_id(value: Any, label: str) -> str:
    text = _profile_text(value, label)
    if len(text) > 128 or re.fullmatch(r"[A-Za-z0-9._-]+", text) is None:
        raise ContractError(f"{label} is not a safe identifier")
    return text


def _profile_absolute_path(value: Any, label: str) -> str:
    path = _profile_text(value, label)
    if not os.path.isabs(path):
        raise ContractError(f"{label} must be absolute")
    return path


def _profile_environment(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    for key, item in value.items():
        if key not in PROFILE_ALLOWED_ENV:
            raise ContractError(f"{label} contains disallowed key {key!r}")
        _profile_text(item, f"{label}.{key}")


def _profile_tool(value: Any, label: str) -> None:
    tool = _object(value, label, {"version", "path", "sha256"})
    _profile_text(tool["version"], f"{label}.version")
    _profile_absolute_path(tool["path"], f"{label}.path")
    _sha256(tool["sha256"], f"{label}.sha256")


def _profile_string_list(
    value: Any,
    label: str,
    *,
    nonempty: bool,
    identifiers: bool = False,
    extensions: bool = False,
    unique: bool = False,
) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ContractError(f"{label} must be {'a non-empty ' if nonempty else 'a '}list")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        text = _profile_id(item, f"{label}[{index}]") if identifiers else _profile_text(item, f"{label}[{index}]")
        if extensions and (
            text.startswith(".")
            or "/" in text
            or "\\" in text
            or re.fullmatch(r"[A-Za-z0-9_-]+", text) is None
        ):
            raise ContractError(f"{label}[{index}] is not a plain extension")
        if unique and text in seen:
            raise ContractError(f"{label} contains duplicate {text!r}")
        seen.add(text)
        result.append(text)
    return result


def _validate_target_profile_shape(profile: dict[str, Any], label: str) -> None:
    _object(profile, label, PROFILE_REQUIRED_FIELDS)
    if profile["schema_version"] != "1":
        raise ContractError(f"{label}.schema_version must be '1'")
    _profile_id(profile["target_id"], f"{label}.target_id")
    _profile_text(profile["format_revision"], f"{label}.format_revision")
    _profile_id(profile["loader_id"], f"{label}.loader_id")
    _profile_text(profile["loader_version"], f"{label}.loader_version")

    sources = profile["source_artifacts"]
    if not isinstance(sources, list) or not sources:
        raise ContractError(f"{label}.source_artifacts must be a non-empty list")
    for index, value in enumerate(sources):
        row_label = f"{label}.source_artifacts[{index}]"
        row = _object(value, row_label, {"url", "tag", "resolved_commit", "sha256", "size_bytes"})
        if not _profile_text(row["url"], f"{row_label}.url").startswith("https://"):
            raise ContractError(f"{row_label}.url must use https")
        _profile_text(row["tag"], f"{row_label}.tag")
        _profile_text(row["resolved_commit"], f"{row_label}.resolved_commit")
        _sha256(row["sha256"], f"{row_label}.sha256")
        _unsigned(row["size_bytes"], f"{row_label}.size_bytes", bits=64, minimum=1)

    patches = profile["patches"]
    if not isinstance(patches, list):
        raise ContractError(f"{label}.patches must be a list")
    for index, value in enumerate(patches):
        row_label = f"{label}.patches[{index}]"
        row = _object(value, row_label, {"order", "path", "sha256"})
        if _unsigned(row["order"], f"{row_label}.order", bits=32, minimum=1) != index + 1:
            raise ContractError(f"{row_label}.order must be {index + 1}")
        _profile_absolute_path(row["path"], f"{row_label}.path")
        _sha256(row["sha256"], f"{row_label}.sha256")

    toolchain = _object_with_optional(
        profile["toolchain"],
        f"{label}.toolchain",
        {"compiler", "linker", "engine"},
        {"python", "rust", "environment"},
    )
    for name in ("compiler", "linker", "engine"):
        _profile_tool(toolchain[name], f"{label}.toolchain.{name}")
    for name in ("python", "rust"):
        if toolchain.get(name) is not None:
            _profile_tool(toolchain[name], f"{label}.toolchain.{name}")
    _profile_environment(toolchain.get("environment", {}), f"{label}.toolchain.environment")

    sanitizer = _object(
        profile["sanitizer_policy"],
        f"{label}.sanitizer_policy",
        {"compile_flags", "recovery", "runtime_env", "rust_panic"},
    )
    _profile_string_list(
        sanitizer["compile_flags"], f"{label}.sanitizer_policy.compile_flags", nonempty=True
    )
    if sanitizer["recovery"] not in {"abort", "recover", "trap"}:
        raise ContractError(f"{label}.sanitizer_policy.recovery is unsupported")
    if sanitizer["rust_panic"] not in {"abort", "unwind"}:
        raise ContractError(f"{label}.sanitizer_policy.rust_panic is unsupported")
    if not isinstance(sanitizer["runtime_env"], dict) or not sanitizer["runtime_env"]:
        raise ContractError(f"{label}.sanitizer_policy.runtime_env must be non-empty")
    _profile_environment(sanitizer["runtime_env"], f"{label}.sanitizer_policy.runtime_env")

    binaries = profile["binaries"]
    if not isinstance(binaries, list) or not binaries:
        raise ContractError(f"{label}.binaries must be a non-empty list")
    roles: set[str] = set()
    supported_placeholders = {
        "{artifact_dir}",
        "{corpus_dir}",
        "{input}",
        "{restart_limit}",
        "{run_dir}",
        "{timeout_sec}",
        "{worker_id}",
        "{workers}",
    }
    for index, value in enumerate(binaries):
        row_label = f"{label}.binaries[{index}]"
        row = _object_with_optional(
            value,
            row_label,
            {"role", "path", "sha256", "argv"},
            {"linked_libraries"},
        )
        role = _profile_id(row["role"], f"{row_label}.role")
        if role in roles:
            raise ContractError(f"{label}.binaries contains duplicate role {role!r}")
        roles.add(role)
        _profile_absolute_path(row["path"], f"{row_label}.path")
        _sha256(row["sha256"], f"{row_label}.sha256")
        argv = _profile_string_list(row["argv"], f"{row_label}.argv", nonempty=True)
        for argument in argv:
            if ("{" in argument or "}" in argument) and argument not in supported_placeholders:
                raise ContractError(f"{row_label}.argv contains unsupported placeholder {argument!r}")
        libraries = row.get("linked_libraries", [])
        if not isinstance(libraries, list):
            raise ContractError(f"{row_label}.linked_libraries must be a list")
        for library_index, library_value in enumerate(libraries):
            library_label = f"{row_label}.linked_libraries[{library_index}]"
            library = _object(library_value, library_label, {"path", "sha256"})
            _profile_absolute_path(library["path"], f"{library_label}.path")
            _sha256(library["sha256"], f"{library_label}.sha256")
    if "replay" not in roles:
        raise ContractError(f"{label}.binaries must contain replay role")
    replay = next(row for row in binaries if row["role"] == "replay")
    if replay["argv"].count("{input}") != 1:
        raise ContractError(f"{label} replay argv must contain {{input}} exactly once")

    input_kind = _object_with_optional(
        profile["input_kind"],
        f"{label}.input_kind",
        {"kind", "extensions"},
        {"subformats"},
    )
    if input_kind["kind"] not in {"single", "fzb1"}:
        raise ContractError(f"{label}.input_kind.kind must be single or fzb1")
    _profile_string_list(
        input_kind["extensions"],
        f"{label}.input_kind.extensions",
        nonempty=True,
        extensions=True,
        unique=True,
    )
    _profile_string_list(
        input_kind.get("subformats", []), f"{label}.input_kind.subformats", nonempty=False, unique=True
    )
    depth = _profile_text(profile["depth"], f"{label}.depth")
    allowed_depths = {
        "onnx": {"session"},
        "gguf": {"metadata", "tensor-info", "full"},
        "safetensors": {"deserialize"},
        "tflite": {"load-allocate-access"},
    }
    target_id = profile["target_id"]
    if target_id not in allowed_depths or depth not in allowed_depths[target_id]:
        raise ContractError(f"{label}.depth {depth!r} is unsupported for target {target_id!r}")

    capabilities = profile["engine_capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        raise ContractError(f"{label}.engine_capabilities must be a non-empty list")
    backends: set[str] = set()
    for index, value in enumerate(capabilities):
        row_label = f"{label}.engine_capabilities[{index}]"
        row = _object(
            value,
            row_label,
            {"backend", "binary_role", "required_mode", "instrumentation_scope"},
        )
        backend = row["backend"]
        if backend not in {"local-harness", "aflpp", "libfuzzer", "coverage"}:
            raise ContractError(f"{row_label}.backend is unsupported")
        if backend in backends:
            raise ContractError(f"{label}.engine_capabilities duplicates backend {backend!r}")
        backends.add(backend)
        if row["binary_role"] not in roles:
            raise ContractError(f"{row_label}.binary_role does not name a profile binary")
        _profile_text(row["required_mode"], f"{row_label}.required_mode")
        _profile_text(row["instrumentation_scope"], f"{row_label}.instrumentation_scope")
    if "local-harness" not in backends:
        raise ContractError(f"{label}.engine_capabilities must include local-harness")

    limits = _object(
        profile["limits"],
        f"{label}.limits",
        {"max_input_bytes", "memory_bytes", "input_timeout_ms", "block_timeout_ms", "threads", "workers"},
    )
    for name in ("max_input_bytes", "memory_bytes", "input_timeout_ms", "block_timeout_ms", "threads", "workers"):
        _unsigned(
            limits[name],
            f"{label}.limits.{name}",
            bits=32 if name in {"threads", "workers"} else 64,
            minimum=1,
        )
    if limits["input_timeout_ms"] > limits["block_timeout_ms"]:
        raise ContractError(f"{label}.limits.input_timeout_ms exceeds block_timeout_ms")

    coverage = _object_with_optional(
        profile["coverage_scope"],
        f"{label}.coverage_scope",
        {"unit", "include_sources"},
        {"exclude_sources"},
    )
    _profile_id(coverage["unit"], f"{label}.coverage_scope.unit")
    _profile_string_list(
        coverage["include_sources"],
        f"{label}.coverage_scope.include_sources",
        nonempty=True,
        unique=True,
    )
    _profile_string_list(
        coverage.get("exclude_sources", []),
        f"{label}.coverage_scope.exclude_sources",
        nonempty=False,
        unique=True,
    )


def _normalize_target_profile_defaults(profile: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(profile)
    toolchain = normalized["toolchain"]
    toolchain.setdefault("python", None)
    toolchain.setdefault("rust", None)
    toolchain.setdefault("environment", {})
    for binary in normalized["binaries"]:
        binary.setdefault("linked_libraries", [])
    normalized["input_kind"].setdefault("subformats", [])
    normalized["coverage_scope"].setdefault("exclude_sources", [])
    return normalized


def _validate_command(value: Any, label: str) -> dict[str, Any]:
    command = _object(value, label, COMMAND_FIELDS)
    argv = command["argv"]
    if not isinstance(argv, list) or not argv:
        raise ContractError(f"{label}.argv must be a non-empty list")
    for index, item in enumerate(argv):
        _string(item, f"{label}.argv[{index}]")
    if not os.path.isabs(argv[0]):
        raise ContractError(f"{label}.argv[0] must be absolute")
    allowed_env = command["allowed_env"]
    if not isinstance(allowed_env, dict):
        raise ContractError(f"{label}.allowed_env must be an object")
    for key, item in allowed_env.items():
        _string(key, f"{label}.allowed_env key")
        _string(item, f"{label}.allowed_env.{key}", nonempty=False)
        if key not in PROFILE_ALLOWED_ENV | COMMAND_OS_ENV_ALLOWLIST:
            raise ContractError(f"{label}.allowed_env contains disallowed key {key!r}")
    cwd = _string(command["cwd"], f"{label}.cwd")
    if not os.path.isabs(cwd):
        raise ContractError(f"{label}.cwd must be absolute")
    _sha256(command["executable_sha256"], f"{label}.executable_sha256")
    return command


def _validate_command_environment(
    command: dict[str, Any],
    profile: dict[str, Any],
    label: str,
) -> None:
    required: dict[str, str] = {}
    for source_name, source in (
        ("toolchain.environment", profile["toolchain"]["environment"]),
        ("sanitizer_policy.runtime_env", profile["sanitizer_policy"]["runtime_env"]),
    ):
        for key, value in source.items():
            existing = required.get(key)
            if existing is not None and existing != value:
                raise ContractError(
                    f"{label} profile environment key {key!r} conflicts between pinned sources"
                )
            required[key] = value
    allowed_env = command["allowed_env"]
    for key, expected in required.items():
        if allowed_env.get(key) != expected:
            raise ContractError(
                f"{label}.allowed_env must include exact pinned profile environment value for {key!r}"
            )
    unexpected = sorted(set(allowed_env) - set(required) - COMMAND_OS_ENV_ALLOWLIST)
    if unexpected:
        raise ContractError(f"{label}.allowed_env has non-profile, non-OS keys: {unexpected}")


def _validate_profile_snapshot(identity: dict[str, Any], arm: str) -> dict[str, Any]:
    raw_key = f"{arm}_profile_raw_json"
    parsed_key = f"{arm}_profile"
    raw_sha_key = f"{arm}_profile_sha256"
    canonical_sha_key = f"{arm}_profile_canonical_sha256"
    raw = _string(identity[raw_key], f"identity.{raw_key}", nonempty=True)
    try:
        raw_bytes = raw.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ContractError(f"identity.{raw_key} is not UTF-8 encodable") from error
    if len(raw_bytes) > 1024 * 1024:
        raise ContractError(f"identity.{raw_key} exceeds the 1 MiB TargetProfile limit")
    parsed = _parse_json_text(raw, f"identity.{raw_key}")
    if not isinstance(parsed, dict):
        raise ContractError(f"identity.{raw_key} root must be an object")
    _validate_target_profile_shape(parsed, f"identity.{parsed_key}")
    if parsed != identity[parsed_key]:
        raise ContractError(f"identity.{parsed_key} does not match embedded raw profile bytes")
    observed_raw_sha = _sha256_bytes(raw_bytes)
    if _sha256(identity[raw_sha_key], f"identity.{raw_sha_key}") != observed_raw_sha:
        raise ContractError(f"identity.{raw_sha_key} does not match embedded raw profile bytes")
    observed_canonical_sha = _canonical_profile_sha256(parsed)
    if _sha256(identity[canonical_sha_key], f"identity.{canonical_sha_key}") != observed_canonical_sha:
        raise ContractError(f"identity.{canonical_sha_key} does not match parsed profile")
    parsed = _normalize_target_profile_defaults(parsed)
    missing_profile_fields = PROFILE_REQUIRED_FIELDS - set(parsed)
    unknown_profile_fields = set(parsed) - PROFILE_REQUIRED_FIELDS
    if missing_profile_fields or unknown_profile_fields:
        raise ContractError(
            f"identity.{parsed_key} TargetProfile fields mismatch: "
            f"missing={sorted(missing_profile_fields)} unknown={sorted(unknown_profile_fields)}"
        )
    fixed = identity["fixed"]
    if parsed["schema_version"] != "1":
        raise ContractError(f"identity.{parsed_key}.schema_version must be '1'")
    if parsed["target_id"] != fixed["target_id"]:
        raise ContractError(f"identity.{parsed_key}.target_id contradicts identity.fixed.target_id")
    if parsed["depth"] != fixed["depth"]:
        raise ContractError(f"identity.{parsed_key}.depth contradicts identity.fixed.depth")
    derived_parser_pin = {
        "loader_id": parsed["loader_id"],
        "loader_version": parsed["loader_version"],
        "source_artifacts": parsed["source_artifacts"],
    }
    if derived_parser_pin != fixed["parser_pin"]:
        raise ContractError(f"identity.{parsed_key} parser/source pin contradicts identity.fixed.parser_pin")
    if parsed["toolchain"] != fixed["toolchain_pin"]:
        raise ContractError(f"identity.{parsed_key}.toolchain contradicts identity.fixed.toolchain_pin")
    if _sha256_bytes(_canonical_json(parsed["patches"])) != fixed["target_patch_sha256"]:
        raise ContractError(f"identity.{parsed_key}.patches contradict identity.fixed.target_patch_sha256")
    limits = parsed["limits"]
    if not isinstance(limits, dict):
        raise ContractError(f"identity.{parsed_key}.limits must be an object")
    limit_mapping = {
        "workers": "workers",
        "threads": "threads",
        "input_timeout_ms": "input_timeout_ms",
        "memory_bytes": "memory_limit_bytes",
    }
    for profile_key, fixed_key in limit_mapping.items():
        if limits.get(profile_key) != fixed[fixed_key]:
            raise ContractError(
                f"identity.{parsed_key}.limits.{profile_key} contradicts identity.fixed.{fixed_key}"
            )
    return parsed


def _validate_source_artifacts(identity: dict[str, Any]) -> str:
    maps: dict[str, dict[str, str]] = {}
    for arm in ("baseline", "candidate"):
        key = f"{arm}_source_artifacts"
        value = identity[key]
        if not isinstance(value, dict) or not value:
            raise ContractError(f"identity.{key} must be a non-empty object")
        checked: dict[str, str] = {}
        for path, digest in value.items():
            if (
                not isinstance(path, str)
                or not path
                or os.path.isabs(path)
                or ".." in Path(path).parts
                or any(character in path for character in "*?[]")
            ):
                raise ContractError(f"identity.{key} has unsafe source path {path!r}")
            checked[path] = _sha256(digest, f"identity.{key}.{path}")
        maps[arm] = checked
    if set(maps["baseline"]) != set(maps["candidate"]):
        raise ContractError("baseline/candidate source artifact sets differ")
    observed = {
        path
        for path in maps["baseline"]
        if maps["baseline"][path] != maps["candidate"][path]
    }
    allowed_value = identity["allowed_tool_changes"]
    if not isinstance(allowed_value, list):
        raise ContractError("identity.allowed_tool_changes must be a list")
    allowed: set[str] = set()
    allowed_diff_parts: list[str] = []
    for index, value in enumerate(allowed_value):
        label = f"identity.allowed_tool_changes[{index}]"
        change = _object(
            value,
            label,
            {"path", "baseline_sha256", "candidate_sha256", "diff_raw_text", "diff_sha256"},
        )
        path = _string(change["path"], f"{label}.path")
        if (
            os.path.isabs(path)
            or ".." in Path(path).parts
            or any(character in path for character in "*?[]")
            or path in allowed
        ):
            raise ContractError(f"{label}.path is unsafe, wildcarded, or duplicated")
        if path not in observed:
            raise ContractError(f"{label}.path is not an observed source artifact change")
        if _sha256(change["baseline_sha256"], f"{label}.baseline_sha256") != maps["baseline"][path]:
            raise ContractError(f"{label}.baseline_sha256 does not match source artifacts")
        if _sha256(change["candidate_sha256"], f"{label}.candidate_sha256") != maps["candidate"][path]:
            raise ContractError(f"{label}.candidate_sha256 does not match source artifacts")
        diff_raw = _string(change["diff_raw_text"], f"{label}.diff_raw_text")
        if _sha256_bytes(diff_raw.encode("utf-8")) != _sha256(
            change["diff_sha256"], f"{label}.diff_sha256"
        ):
            raise ContractError(f"{label}.diff_sha256 does not match embedded diff bytes")
        allowed.add(path)
        allowed_diff_parts.append(diff_raw)
    if observed != allowed:
        raise ContractError(
            "source artifact changes differ from allowlist: "
            f"observed={sorted(observed)} allowed={sorted(allowed)}"
        )
    return "".join(allowed_diff_parts)


def _validate_identity(
    value: Any,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    identity = _object(value, "identity", IDENTITY_FIELDS)
    fixed = _object(identity["fixed"], "identity.fixed", FIXED_IDENTITY_FIELDS)
    for key in ("target_id", "depth", "filesystem_path_type", "log_level", "cache_policy"):
        _string(fixed[key], f"identity.fixed.{key}")
    if fixed["filesystem_path_type"] != "wsl-ext4":
        raise ContractError("identity.fixed.filesystem_path_type must be wsl-ext4 for this protocol")
    if not isinstance(fixed["parser_pin"], dict) or not fixed["parser_pin"]:
        raise ContractError("identity.fixed.parser_pin must be a non-empty object")
    if not isinstance(fixed["toolchain_pin"], dict) or not fixed["toolchain_pin"]:
        raise ContractError("identity.fixed.toolchain_pin must be a non-empty object")
    _validate_json_values(fixed["parser_pin"], "identity.fixed.parser_pin")
    _validate_json_values(fixed["toolchain_pin"], "identity.fixed.toolchain_pin")
    _sha256(fixed["target_patch_sha256"], "identity.fixed.target_patch_sha256")
    flags = fixed["engine_flags"]
    if not isinstance(flags, list):
        raise ContractError("identity.fixed.engine_flags must be a list")
    for index, flag in enumerate(flags):
        _string(flag, f"identity.fixed.engine_flags[{index}]")
    _sha256(fixed["corpus_sha256"], "identity.fixed.corpus_sha256")
    raw_index = _string(fixed["corpus_index_raw_json"], "identity.fixed.corpus_index_raw_json")
    if _sha256_bytes(raw_index.encode("utf-8")) != _sha256(
        fixed["corpus_index_sha256"], "identity.fixed.corpus_index_sha256"
    ):
        raise ContractError("identity.fixed.corpus_index_sha256 does not match embedded corpus index bytes")
    corpus_index = _parse_json_text(raw_index, "identity.fixed.corpus_index_raw_json")
    corpus_index = _object(corpus_index, "embedded corpus index", {"schema_version", "inputs"})
    if corpus_index["schema_version"] != "format-performance-corpus-v1":
        raise ContractError("embedded corpus index schema_version is unsupported")
    inputs = corpus_index["inputs"]
    if not isinstance(inputs, list) or not inputs:
        raise ContractError("embedded corpus index inputs must be non-empty")
    observed_paths: set[str] = set()
    throughput_orders: list[int] = []
    latency_orders: list[int] = []
    for index, item in enumerate(inputs):
        label = f"embedded corpus index inputs[{index}]"
        row = _object(
            item,
            label,
            {
                "path",
                "sha256",
                "expected_outcome",
                "expected_exit_code",
                "target_api_stage",
                "minimum_target_api_calls",
                "required_api_events",
                "zero_call_reason",
                "throughput_order_index",
                "throughput_exclusion_reason",
                "latency_probe_order_index",
                "latency_exclusion_reason",
            },
        )
        path = _string(row["path"], f"{label}.path")
        if os.path.isabs(path) or ".." in Path(path).parts or path in observed_paths:
            raise ContractError(f"embedded corpus index input path is unsafe or duplicated: {path}")
        observed_paths.add(path)
        _sha256(row["sha256"], f"{label}.sha256")
        expected_outcome = row["expected_outcome"]
        if expected_outcome not in {"accepted", "rejected"}:
            raise ContractError(f"{label}.expected_outcome must be accepted or rejected")
        expected_exit_code = _integer(row["expected_exit_code"], f"{label}.expected_exit_code", minimum=0)
        required_exit_code = 0 if expected_outcome == "accepted" else 9
        if expected_exit_code != required_exit_code:
            raise ContractError(
                f"{label}.expected_exit_code must be {required_exit_code} for {expected_outcome}; "
                "exit 10 means unavailable and is not a normal/rejected fixed-corpus result"
            )
        minimum_calls = _integer(
            row["minimum_target_api_calls"],
            f"{label}.minimum_target_api_calls",
            minimum=0,
            maximum=MAX_U64,
        )
        required_events = row["required_api_events"]
        if not isinstance(required_events, list):
            raise ContractError(f"{label}.required_api_events must be a list")
        for event_index, event in enumerate(required_events):
            _string(event, f"{label}.required_api_events[{event_index}]")
        if len(set(required_events)) != len(required_events):
            raise ContractError(f"{label}.required_api_events must be unique")
        if minimum_calls < len(required_events):
            raise ContractError(
                f"{label}.minimum_target_api_calls cannot be smaller than required_api_events"
            )
        stage = row["target_api_stage"]
        zero_reason = row["zero_call_reason"]
        if stage == "target-parser":
            if minimum_calls < 1 or not required_events or zero_reason is not None:
                raise ContractError(
                    f"{label} target-parser entries require calls/events and null zero_call_reason"
                )
        elif stage == "pre-parser-reject":
            if expected_outcome != "rejected" or minimum_calls != 0 or required_events:
                raise ContractError(f"{label} pre-parser-reject entry has inconsistent API expectations")
            _string(zero_reason, f"{label}.zero_call_reason")
        else:
            raise ContractError(f"{label}.target_api_stage is unsupported")

        for prefix, orders in (
            ("throughput", throughput_orders),
            ("latency", latency_orders),
        ):
            order_key = "throughput_order_index" if prefix == "throughput" else "latency_probe_order_index"
            reason_key = "throughput_exclusion_reason" if prefix == "throughput" else "latency_exclusion_reason"
            order = row[order_key]
            reason = row[reason_key]
            if order is None:
                _string(reason, f"{label}.{reason_key}")
            else:
                checked_order = _integer(order, f"{label}.{order_key}", minimum=1)
                orders.append(checked_order)
                if reason is not None:
                    raise ContractError(f"{label}.{reason_key} must be null when included")
                if minimum_calls < 1 or not required_events or stage != "target-parser":
                    raise ContractError(f"{label} {prefix} entries must reach the target parser")
    for label, orders in (
        ("throughput_order_index", throughput_orders),
        ("latency_probe_order_index", latency_orders),
    ):
        if not orders or sorted(orders) != list(range(1, len(orders) + 1)):
            raise ContractError(f"embedded corpus index {label} values must be unique and contiguous")
    if _integer(fixed["corpus_input_count"], "identity.fixed.corpus_input_count", minimum=1) != len(inputs):
        raise ContractError("identity.fixed.corpus_input_count does not match embedded corpus index")
    for key in ("workers", "threads", "input_timeout_ms", "memory_limit_bytes"):
        _integer(fixed[key], f"identity.fixed.{key}", minimum=1)

    baseline_profile = _validate_profile_snapshot(identity, "baseline")
    candidate_profile = _validate_profile_snapshot(identity, "candidate")
    allowed_value = identity["allowed_profile_differences"]
    if not isinstance(allowed_value, list):
        raise ContractError("identity.allowed_profile_differences must be a list")
    allowed: set[str] = set()
    for index, pointer in enumerate(allowed_value):
        pointer = _string(pointer, f"identity.allowed_profile_differences[{index}]")
        if (
            pointer == "/"
            or not pointer.startswith("/")
            or "*" in pointer
            or pointer in allowed
            or any(pointer == prefix or pointer.startswith(prefix + "/") for prefix in FORBIDDEN_PROFILE_DIFF_PREFIXES)
        ):
            raise ContractError(f"unsafe or forbidden profile difference allowlist entry: {pointer}")
        allowed.add(pointer)
    differences = _json_differences(baseline_profile, candidate_profile)
    if differences != allowed:
        raise ContractError(
            "profile difference set does not match allowlist: "
            f"observed={sorted(differences)} allowed={sorted(allowed)}"
        )

    baseline_command = _validate_command(identity["baseline_command"], "identity.baseline_command")
    candidate_command = _validate_command(identity["candidate_command"], "identity.candidate_command")
    if baseline_command["argv"][1:] != candidate_command["argv"][1:]:
        raise ContractError("baseline/candidate workload argv differ outside executable identity")
    if baseline_command["allowed_env"] != candidate_command["allowed_env"]:
        raise ContractError("baseline/candidate allowed_env differ")
    if baseline_command["cwd"] != candidate_command["cwd"]:
        raise ContractError("baseline/candidate cwd differ")
    if baseline_command["cwd"] == "/mnt" or baseline_command["cwd"].startswith("/mnt/"):
        raise ContractError("command cwd contradicts fixed wsl-ext4 filesystem path type")
    for arm, command, profile in (
        ("baseline", baseline_command, baseline_profile),
        ("candidate", candidate_command, candidate_profile),
    ):
        _validate_command_environment(command, profile, f"identity.{arm}_command")
        expected = _sha256_bytes(_canonical_json(command))
        if _sha256(identity[f"{arm}_command_sha256"], f"identity.{arm}_command_sha256") != expected:
            raise ContractError(f"identity.{arm}_command_sha256 does not match embedded command")
        _commit(identity[f"{arm}_tool_commit"], f"identity.{arm}_tool_commit")
        state = identity[f"{arm}_source_state"]
        dirty_raw = identity[f"{arm}_dirty_diff_raw_text"]
        dirty_sha = identity[f"{arm}_dirty_diff_sha256"]
        if state == "clean":
            if dirty_raw is not None or dirty_sha is not None:
                raise ContractError(
                    f"identity.{arm} dirty diff raw bytes/hash must be null for clean source"
                )
        elif state == "dirty":
            checked_raw = _string(dirty_raw, f"identity.{arm}_dirty_diff_raw_text")
            digest = _sha256(dirty_sha, f"identity.{arm}_dirty_diff_sha256")
            if _sha256_bytes(checked_raw.encode("utf-8")) != digest:
                raise ContractError(f"identity.{arm} dirty diff SHA does not match embedded raw bytes")
        else:
            raise ContractError(f"identity.{arm}_source_state must be clean or dirty")
        matching_binaries = [
            binary
            for binary in profile["binaries"]
            if isinstance(binary, dict)
            and binary.get("path") == command["argv"][0]
            and _sha256(binary.get("sha256"), f"identity.{arm}_profile binary sha256")
            == _sha256(command["executable_sha256"], f"identity.{arm}_command executable_sha256")
        ]
        if len(matching_binaries) != 1:
            raise ContractError(
                f"identity.{arm}_command executable path/hash does not match exactly one profile binary"
            )
        missing_flags = [flag for flag in fixed["engine_flags"] if flag not in command["argv"]]
        if missing_flags:
            raise ContractError(f"identity.{arm}_command is missing fixed engine flags: {missing_flags}")
    allowed_tool_diff = _validate_source_artifacts(identity)
    if (
        identity["candidate_source_state"] == "dirty"
        and identity["candidate_dirty_diff_raw_text"] != allowed_tool_diff
    ):
        raise ContractError(
            "identity candidate dirty diff raw bytes do not equal the complete allowed tool diff"
        )
    bindings = {
        "baseline": {
            "profile_sha256": identity["baseline_profile_sha256"],
            "tool_commit": identity["baseline_tool_commit"],
            "dirty_diff_sha256": identity["baseline_dirty_diff_sha256"],
            "command_sha256": identity["baseline_command_sha256"],
        },
        "candidate": {
            "profile_sha256": identity["candidate_profile_sha256"],
            "tool_commit": identity["candidate_tool_commit"],
            "dirty_diff_sha256": identity["candidate_dirty_diff_sha256"],
            "command_sha256": identity["candidate_command_sha256"],
        },
    }
    return identity, bindings, inputs


ENVIRONMENT_FIELDS = {
    "wsl_cpu_count",
    "wsl_memory_bytes",
    "wsl_swap_bytes",
    "disk_free_bytes",
    "concurrent_workload",
    "cache_policy",
}

PROTOCOL_FIELDS = {
    "preparation_excluded",
    "elapsed_scope",
    "minimum_sample_seconds",
    "alternation",
    "memory_scope",
    "memory_collector",
    "memory_collector_implementation_raw_text",
    "memory_collector_implementation_sha256",
    "memory_collector_config",
    "clock_resolution_seconds",
    "rss_resolution_bytes",
    "api_call_resolution_calls",
    "bootstrap_seed",
    "bootstrap_resamples",
    "quantile_method",
    "latency_probe_order",
    "latency_batch_iterations",
}


def _validate_environment(value: Any, fixed: dict[str, Any]) -> None:
    environment = _object(value, "environment", ENVIRONMENT_FIELDS)
    _integer(
        environment["wsl_cpu_count"],
        "environment.wsl_cpu_count",
        minimum=1,
        maximum=MAX_U64,
    )
    for key in ("wsl_memory_bytes", "disk_free_bytes"):
        _integer(environment[key], f"environment.{key}", minimum=1, maximum=MAX_U64)
    _integer(
        environment["wsl_swap_bytes"],
        "environment.wsl_swap_bytes",
        minimum=0,
        maximum=MAX_U64,
    )
    _string(environment["concurrent_workload"], "environment.concurrent_workload")
    cache_policy = _string(environment["cache_policy"], "environment.cache_policy")
    if cache_policy != fixed["cache_policy"]:
        raise ContractError("environment.cache_policy contradicts identity.fixed.cache_policy")


def _validate_protocol(value: Any) -> dict[str, Any]:
    protocol = _object(value, "protocol", PROTOCOL_FIELDS)
    if protocol["preparation_excluded"] is not True:
        raise ContractError("protocol.preparation_excluded must be true")
    if protocol["elapsed_scope"] != "workload_only":
        raise ContractError("protocol.elapsed_scope must be workload_only")
    minimum = _number(protocol["minimum_sample_seconds"], "protocol.minimum_sample_seconds", minimum=MIN_REAL_SAMPLE_SECONDS)
    if protocol["alternation"] != "baseline_then_candidate":
        raise ContractError("protocol.alternation must be baseline_then_candidate")
    if protocol["memory_scope"] != "process_tree_peak":
        raise ContractError("protocol.memory_scope must be process_tree_peak")
    collector = _string(protocol["memory_collector"], "protocol.memory_collector")
    if collector not in SUPPORTED_MEMORY_COLLECTORS:
        raise ContractError(
            "protocol.memory_collector must be a supported process-tree collector: "
            + ", ".join(sorted(SUPPORTED_MEMORY_COLLECTORS))
        )
    collector_raw = _string(
        protocol["memory_collector_implementation_raw_text"],
        "protocol.memory_collector_implementation_raw_text",
    )
    if len(collector_raw.encode("utf-8")) > 1024 * 1024:
        raise ContractError("protocol memory collector implementation exceeds 1 MiB")
    collector_sha = _sha256(
        protocol["memory_collector_implementation_sha256"],
        "protocol.memory_collector_implementation_sha256",
    )
    if _sha256_bytes(collector_raw.encode("utf-8")) != collector_sha:
        raise ContractError(
            "protocol.memory_collector_implementation_sha256 does not match embedded bytes"
        )
    collector_config = _object(
        protocol["memory_collector_config"],
        "protocol.memory_collector_config",
        MEMORY_COLLECTOR_CONFIG,
    )
    if (
        isinstance(collector_config["cgroup_version"], bool)
        or collector_config["cgroup_version"] != 2
        or _string(
            collector_config["membership_scope"],
            "protocol.memory_collector_config.membership_scope",
        )
        != MEMORY_COLLECTOR_CONFIG["membership_scope"]
        or _string(
            collector_config["peak_file"],
            "protocol.memory_collector_config.peak_file",
        )
        != MEMORY_COLLECTOR_CONFIG["peak_file"]
        or _string(
            collector_config["sample_lifecycle"],
            "protocol.memory_collector_config.sample_lifecycle",
        )
        != MEMORY_COLLECTOR_CONFIG["sample_lifecycle"]
    ):
        raise ContractError(
            "protocol.memory_collector_config must describe a new private cgroup-v2 leaf per sample"
        )
    _number(protocol["clock_resolution_seconds"], "protocol.clock_resolution_seconds", minimum=0.0)
    if protocol["clock_resolution_seconds"] <= 0:
        raise ContractError("protocol.clock_resolution_seconds must be > 0")
    _integer(
        protocol["rss_resolution_bytes"],
        "protocol.rss_resolution_bytes",
        minimum=1,
        maximum=MAX_U64,
    )
    if (
        _integer(
            protocol["api_call_resolution_calls"],
            "protocol.api_call_resolution_calls",
            minimum=1,
            maximum=MAX_U64,
        )
        != 1
    ):
        raise ContractError("protocol.api_call_resolution_calls must be exactly 1")
    if protocol["bootstrap_seed"] != BOOTSTRAP_SEED or isinstance(protocol["bootstrap_seed"], bool):
        raise ContractError(f"protocol.bootstrap_seed must be {BOOTSTRAP_SEED}")
    if protocol["bootstrap_resamples"] != BOOTSTRAP_RESAMPLES or isinstance(protocol["bootstrap_resamples"], bool):
        raise ContractError(f"protocol.bootstrap_resamples must be {BOOTSTRAP_RESAMPLES}")
    if protocol["quantile_method"] != "nearest-rank":
        raise ContractError("protocol.quantile_method must be nearest-rank")
    if protocol["latency_probe_order"] != "pair_index_rotation":
        raise ContractError("protocol.latency_probe_order must be pair_index_rotation")
    latency_batch = _integer(
        protocol["latency_batch_iterations"],
        "protocol.latency_batch_iterations",
        minimum=1,
    )
    if latency_batch > MAX_LATENCY_BATCH_ITERATIONS:
        raise ContractError(
            f"protocol.latency_batch_iterations must be <= {MAX_LATENCY_BATCH_ITERATIONS}"
        )
    return protocol


CORRECTNESS_CONTAINER_FIELDS = {
    "baseline_raw_json",
    "candidate_raw_json",
    "baseline_sha256",
    "candidate_sha256",
}
CORRECTNESS_SNAPSHOT_FIELDS = {
    "schema_version",
    "arm",
    "profile_sha256",
    "tool_commit",
    "dirty_diff_sha256",
    "command_sha256",
    "corpus_sha256",
    "corpus_index_sha256",
    "conditions_sha256",
    "records",
}
CORRECTNESS_RECORD_FIELDS = {
    "path",
    "sha256",
    "outcome_class",
    "outcome_detail",
    "target_api_calls",
    "api_events",
    "exit_code",
    "residual_processes",
}


def _measurement_conditions_sha256(
    mode: str,
    fixed: dict[str, Any],
    environment: dict[str, Any],
    protocol: dict[str, Any],
    budgets: dict[str, Any],
) -> str:
    """Bind pre-observation conditions without creating a correctness hash cycle."""

    return _sha256_bytes(
        _canonical_json(
            {
                "mode": mode,
                "fixed": fixed,
                "environment": environment,
                "protocol": protocol,
                "absolute_budgets": budgets,
            }
        )
    )


def _measurement_context_sha256(
    conditions_sha256: str,
    correctness_snapshot_sha256: dict[str, str],
) -> str:
    return _sha256_bytes(
        _canonical_json(
            {
                "conditions_sha256": conditions_sha256,
                "correctness_snapshot_sha256": correctness_snapshot_sha256,
            }
        )
    )


def _comparison_measurement_context_sha256(
    calibration_context_sha256: str,
    calibration_raw_sha256: str,
) -> str:
    return _sha256_bytes(
        _canonical_json(
            {
                "calibration_context_sha256": calibration_context_sha256,
                "calibration_raw_sha256": calibration_raw_sha256,
            }
        )
    )


def _correctness_digest(records: list[dict[str, Any]], outcome_class: str) -> str:
    selected = [
        {
            "path": row["path"],
            "sha256": row["sha256"],
            "outcome_class": row["outcome_class"],
            "outcome_detail": row["outcome_detail"],
        }
        for row in records
        if row["outcome_class"] == outcome_class
    ]
    return _sha256_bytes(_canonical_json(selected))


def _api_reach_digest(records: list[dict[str, Any]]) -> str:
    return _sha256_bytes(
        _canonical_json(
            [
                {
                    "path": row["path"],
                    "sha256": row["sha256"],
                    "target_api_calls": row["target_api_calls"],
                    "api_events": row["api_events"],
                }
                for row in records
            ]
        )
    )


def _validate_correctness(
    value: Any,
    *,
    fixed: dict[str, Any],
    bindings: dict[str, dict[str, Any]],
    corpus_inputs: list[dict[str, str]],
    conditions_sha256: str,
) -> tuple[dict[str, Any], list[str]]:
    """Validate embedded replay records and derive every correctness aggregate."""

    correctness = _object(value, "correctness", CORRECTNESS_CONTAINER_FIELDS)
    failures: list[str] = []
    snapshots: dict[str, dict[str, Any]] = {}
    summaries: dict[str, dict[str, Any]] = {}
    snapshot_hashes: dict[str, str] = {}
    for arm in ("baseline", "candidate"):
        raw_key = f"{arm}_raw_json"
        sha_key = f"{arm}_sha256"
        raw = _string(correctness[raw_key], f"correctness.{raw_key}")
        raw_bytes = raw.encode("utf-8", "strict")
        if len(raw_bytes) > 16 * 1024 * 1024:
            raise ContractError(f"correctness.{raw_key} exceeds 16 MiB")
        observed_sha = _sha256_bytes(raw_bytes)
        if _sha256(correctness[sha_key], f"correctness.{sha_key}") != observed_sha:
            raise ContractError(f"correctness.{sha_key} does not match embedded raw correctness bytes")
        snapshot_hashes[arm] = observed_sha
        snapshot = _parse_json_text(raw, f"correctness.{raw_key}")
        snapshot = _object(snapshot, f"correctness.{arm} snapshot", CORRECTNESS_SNAPSHOT_FIELDS)
        if snapshot["schema_version"] != "format-correctness-replay-v1":
            raise ContractError(f"correctness.{arm} snapshot schema_version is unsupported")
        if snapshot["arm"] != arm:
            raise ContractError(f"correctness.{arm} snapshot arm must be {arm!r}")
        for key, expected in bindings[arm].items():
            if snapshot[key] != expected:
                raise ContractError(f"correctness.{arm} snapshot {key} does not match identity")
        if snapshot["corpus_sha256"] != fixed["corpus_sha256"]:
            raise ContractError(f"correctness.{arm} snapshot corpus_sha256 does not match fixed corpus")
        if snapshot["corpus_index_sha256"] != fixed["corpus_index_sha256"]:
            raise ContractError(
                f"correctness.{arm} snapshot corpus_index_sha256 does not match fixed corpus index"
            )
        if snapshot["conditions_sha256"] != conditions_sha256:
            raise ContractError(f"correctness.{arm} snapshot conditions_sha256 does not match fixed conditions")
        records_value = snapshot["records"]
        if not isinstance(records_value, list) or len(records_value) != len(corpus_inputs):
            raise ContractError(
                f"correctness.{arm} snapshot records must exactly cover the fixed corpus"
            )
        records: list[dict[str, Any]] = []
        for index, (record_value, expected_input) in enumerate(zip(records_value, corpus_inputs)):
            label = f"correctness.{arm} snapshot records[{index}]"
            record = _object(record_value, label, CORRECTNESS_RECORD_FIELDS)
            path = _string(record["path"], f"{label}.path")
            digest = _sha256(record["sha256"], f"{label}.sha256")
            if path != expected_input["path"] or digest != _sha256(
                expected_input["sha256"], f"embedded corpus index inputs[{index}].sha256"
            ):
                raise ContractError(f"{label} does not match corpus index path/hash order")
            outcome_class = record["outcome_class"]
            if outcome_class not in {"accepted", "rejected"}:
                raise ContractError(f"{label}.outcome_class is unsupported")
            _string(record["outcome_detail"], f"{label}.outcome_detail")
            calls = _integer(
                record["target_api_calls"],
                f"{label}.target_api_calls",
                minimum=0,
                maximum=MAX_U64,
            )
            events = record["api_events"]
            if not isinstance(events, list):
                raise ContractError(f"{label}.api_events must be a list")
            for event_index, event in enumerate(events):
                _string(event, f"{label}.api_events[{event_index}]")
            if len(events) != calls:
                raise ContractError(f"{label}.api_events must contain one raw event per target API call")
            exit_code = _integer(
                record["exit_code"], f"{label}.exit_code", minimum=0, maximum=MAX_U64
            )
            residual = _integer(
                record["residual_processes"],
                f"{label}.residual_processes",
                minimum=0,
                maximum=MAX_U64,
            )
            if outcome_class != expected_input["expected_outcome"]:
                failures.append(f"{arm} fixed-corpus input {path} outcome_class contradicts corpus index")
            if exit_code != expected_input["expected_exit_code"]:
                failures.append(
                    f"{arm} fixed-corpus input {path} exit_code contradicts corpus index"
                )
            if expected_input["target_api_stage"] == "pre-parser-reject":
                if calls != 0 or events:
                    failures.append(
                        f"{arm} fixed-corpus input {path} pre-parser rejection must have zero "
                        "target API calls and no API events"
                    )
            else:
                if calls < expected_input["minimum_target_api_calls"]:
                    failures.append(
                        f"{arm} fixed-corpus input {path} target API calls are below corpus minimum"
                    )
                missing_events = [
                    event for event in expected_input["required_api_events"] if event not in events
                ]
                if missing_events:
                    failures.append(
                        f"{arm} fixed-corpus input {path} misses required API events {missing_events}"
                    )
            if residual != 0:
                failures.append(f"{arm} fixed-corpus input {path} residual_processes is {residual}")
            records.append(record)
        summaries[arm] = {
            "snapshot_sha256": observed_sha,
            "input_count": len(records),
            "target_api_calls": _checked_sum_u64(
                (row["target_api_calls"] for row in records),
                f"correctness.{arm} target API call total",
            ),
            "normal_outcomes_sha256": _correctness_digest(records, "accepted"),
            "rejected_outcomes_sha256": _correctness_digest(records, "rejected"),
            "required_api_reach_sha256": _api_reach_digest(records),
            "target_api_calls_by_path": {
                row["path"]: row["target_api_calls"] for row in records
            },
            "maximum_exit_code": max(row["exit_code"] for row in records),
            "residual_processes": _checked_sum_u64(
                (row["residual_processes"] for row in records),
                f"correctness.{arm} residual process total",
            ),
        }
        if summaries[arm]["target_api_calls"] == 0:
            failures.append(f"{arm} fixed-corpus actual target API calls are zero")
        snapshots[arm] = snapshot

    semantic_fields = (
        "path",
        "sha256",
        "outcome_class",
        "outcome_detail",
        "target_api_calls",
        "api_events",
        "exit_code",
        "residual_processes",
    )
    for index, (baseline, candidate) in enumerate(
        zip(snapshots["baseline"]["records"], snapshots["candidate"]["records"])
    ):
        for key in semantic_fields:
            if baseline[key] != candidate[key]:
                failures.append(f"fixed-corpus records[{index}].{key} differs")
    for key in (
        "input_count",
        "target_api_calls",
        "normal_outcomes_sha256",
        "rejected_outcomes_sha256",
        "required_api_reach_sha256",
    ):
        if summaries["baseline"][key] != summaries["candidate"][key]:
            failures.append(f"fixed-corpus derived {key} differs")
    return {
        "conditions_sha256": conditions_sha256,
        "snapshot_sha256": snapshot_hashes,
        "baseline": summaries["baseline"],
        "candidate": summaries["candidate"],
    }, failures


METRIC_SPECS = {
    "preparation_time": ("seconds", "number"),
    "wall_time": ("seconds", "number"),
    "input_count": ("inputs", "integer"),
    "target_api_calls": ("calls", "integer"),
    "peak_rss": ("bytes", "integer"),
    "cpu_time": ("seconds", "number"),
    "output_bytes": ("bytes", "integer"),
    "exit_code": ("exit_code", "integer"),
    "residual_processes": ("processes", "integer"),
    "per_input_latency": ("seconds", "latencies"),
}

SAMPLE_FIELDS = {
    "sample_id",
    "phase",
    "arm",
    "pair_index",
    "order_index",
    "profile_sha256",
    "tool_commit",
    "dirty_diff_sha256",
    "command_sha256",
    "corpus_sha256",
    "corpus_index_sha256",
    "measurement_context_sha256",
    "throughput_workload",
    *METRIC_SPECS,
}


def _validate_metric(
    value: Any,
    label: str,
    sample_id: str,
    unit: str,
    kind: str,
    protocol: dict[str, Any],
    corpus_inputs: list[dict[str, Any]],
    latency_target_api_calls: list[int],
) -> Any:
    expected = {"value", "unit", "reason"}
    if label.endswith(".peak_rss"):
        expected.update(
            {
                "scope",
                "collector",
                "collector_implementation_sha256",
                "collector_config_sha256",
                "raw_observation",
            }
        )
    if label.endswith(".per_input_latency"):
        expected.update({"scope", "order"})
    metric = _object(value, label, expected)
    if metric["unit"] != unit:
        raise ContractError(f"{label} unit must be {unit}, observed {metric['unit']!r}")
    observed = metric["value"]
    reason = metric["reason"]
    if observed is None:
        _string(reason, f"{label}.reason")
    else:
        if reason is not None:
            raise ContractError(f"{label}.reason must be null when value is present")
        if kind == "integer":
            observed = _integer(observed, f"{label}.value", minimum=0, maximum=MAX_U64)
        elif kind == "number":
            observed = _number(observed, f"{label}.value", minimum=0.0)
        elif kind == "latencies":
            if not isinstance(observed, list) or len(observed) != len(corpus_inputs):
                raise ContractError(
                    f"{label}.value must contain exactly one row for each latency-probe corpus input"
                )
            latencies: list[dict[str, Any]] = []
            for index, (item, expected_input) in enumerate(zip(observed, corpus_inputs)):
                row_label = f"{label}.value[{index}]"
                row = _object(
                    item,
                    row_label,
                    {
                        "path",
                        "sha256",
                        "probe_order_index",
                        "batch_iterations",
                        "target_api_calls",
                        "expected_exit_code",
                        "observed_exit_code",
                        "outcome_class",
                        "residual_processes",
                        "process_elapsed_seconds",
                        "normalized_seconds_per_call",
                    },
                )
                if row["path"] != expected_input["path"] or row["sha256"] != expected_input["sha256"]:
                    raise ContractError(
                        f"{label}.value[{index}] does not match corpus index path/hash order"
                    )
                if row["probe_order_index"] != index + 1 or isinstance(row["probe_order_index"], bool):
                    raise ContractError(f"{row_label}.probe_order_index must be {index + 1}")
                batch_iterations = _integer(
                    row["batch_iterations"], f"{row_label}.batch_iterations", minimum=1
                )
                if batch_iterations != protocol["latency_batch_iterations"]:
                    raise ContractError(f"{row_label}.batch_iterations does not match protocol")
                calls = _integer(
                    row["target_api_calls"],
                    f"{row_label}.target_api_calls",
                    minimum=1,
                    maximum=MAX_U64,
                )
                expected_calls = _checked_product_u64(
                    batch_iterations,
                    latency_target_api_calls[index],
                    f"{row_label}.target_api_calls",
                )
                if calls != expected_calls:
                    raise ContractError(f"{row_label}.target_api_calls does not match correctness replay")
                expected_exit = _integer(
                    row["expected_exit_code"],
                    f"{row_label}.expected_exit_code",
                    minimum=0,
                    maximum=MAX_U64,
                )
                if expected_exit != expected_input["expected_exit_code"]:
                    raise ContractError(f"{row_label}.expected_exit_code contradicts corpus index")
                observed_exit = _integer(
                    row["observed_exit_code"],
                    f"{row_label}.observed_exit_code",
                    minimum=0,
                    maximum=MAX_U64,
                )
                if observed_exit != expected_exit:
                    raise ContractError(f"{row_label}.observed_exit_code is not the expected probe result")
                outcome_class = row["outcome_class"]
                if outcome_class != expected_input["expected_outcome"]:
                    raise ContractError(f"{row_label}.outcome_class contradicts corpus index")
                residual_processes = _integer(
                    row["residual_processes"],
                    f"{row_label}.residual_processes",
                    minimum=0,
                    maximum=MAX_U64,
                )
                if residual_processes != 0:
                    raise ContractError(f"{row_label}.residual_processes must be zero")
                elapsed = _number(
                    row["process_elapsed_seconds"],
                    f"{row_label}.process_elapsed_seconds",
                    minimum=0.0,
                )
                normalized = _number(
                    row["normalized_seconds_per_call"],
                    f"{row_label}.normalized_seconds_per_call",
                    minimum=0.0,
                )
                if elapsed <= 0 or normalized <= 0:
                    raise ContractError(f"{row_label} latency values must be > 0")
                derived = elapsed / calls
                if not math.isclose(normalized, derived, rel_tol=1e-12, abs_tol=0.0):
                    raise ContractError(
                        f"{row_label}.normalized_seconds_per_call does not match elapsed/target_api_calls"
                    )
                latencies.append(
                    {
                        "path": row["path"],
                        "sha256": row["sha256"],
                        "probe_order_index": index + 1,
                        "batch_iterations": batch_iterations,
                        "target_api_calls": calls,
                        "expected_exit_code": expected_exit,
                        "observed_exit_code": observed_exit,
                        "outcome_class": outcome_class,
                        "residual_processes": residual_processes,
                        "process_elapsed_seconds": elapsed,
                        "normalized_seconds_per_call": normalized,
                    }
                )
            observed = latencies
    if label.endswith(".per_input_latency"):
        if metric["scope"] != "fixed_corpus_latency_probe":
            raise ContractError(f"{label}.scope must be fixed_corpus_latency_probe")
        if metric["order"] != protocol["latency_probe_order"]:
            raise ContractError(f"{label}.order does not match protocol latency probe order")
    if label.endswith(".peak_rss"):
        if metric["scope"] != protocol["memory_scope"]:
            raise ContractError(f"{label}.scope does not match protocol memory scope")
        if metric["collector"] != protocol["memory_collector"]:
            raise ContractError(f"{label}.collector does not match protocol collector")
        if metric["collector"] not in SUPPORTED_MEMORY_COLLECTORS:
            raise ContractError(f"{label}.collector is not a supported process-tree collector")
        implementation_sha = _sha256(
            metric["collector_implementation_sha256"],
            f"{label}.collector_implementation_sha256",
        )
        protocol_implementation_sha = _sha256(
            protocol["memory_collector_implementation_sha256"],
            "protocol.memory_collector_implementation_sha256",
        )
        if implementation_sha != protocol_implementation_sha:
            raise ContractError(f"{label}.collector_implementation_sha256 does not match protocol")
        config_sha = _sha256(
            metric["collector_config_sha256"], f"{label}.collector_config_sha256"
        )
        expected_config_sha = _sha256_bytes(_canonical_json(protocol["memory_collector_config"]))
        if config_sha != expected_config_sha:
            raise ContractError(f"{label}.collector_config_sha256 does not match protocol")
        raw_observation = metric["raw_observation"]
        if observed is None:
            if raw_observation is not None:
                raise ContractError(f"{label}.raw_observation must be null when value is unavailable")
        else:
            raw = _object(
                raw_observation,
                f"{label}.raw_observation",
                {"schema_version", "sample_id", "cgroup_path", "memory_peak_raw_text"},
            )
            if raw["schema_version"] != "cgroup-v2-memory-peak-v1":
                raise ContractError(f"{label}.raw_observation schema_version is unsupported")
            if raw["sample_id"] != sample_id:
                raise ContractError(f"{label}.raw_observation sample_id does not match sample")
            cgroup_path = _string(raw["cgroup_path"], f"{label}.raw_observation.cgroup_path")
            if not cgroup_path.startswith("/sys/fs/cgroup/") or ".." in Path(cgroup_path).parts:
                raise ContractError(f"{label}.raw_observation.cgroup_path is not a cgroup-v2 path")
            if Path(cgroup_path).name != sample_id:
                raise ContractError(
                    f"{label}.raw_observation.cgroup_path leaf must equal the unique sample_id"
                )
            raw_text = _string(
                raw["memory_peak_raw_text"],
                f"{label}.raw_observation.memory_peak_raw_text",
            )
            if re.fullmatch(r"(?:0|[1-9][0-9]*)\n", raw_text) is None:
                raise ContractError(f"{label}.raw_observation.memory_peak_raw_text is not raw bytes")
            raw_digits = raw_text[:-1]
            if len(raw_digits) > 20:
                raise ContractError(
                    f"{label}.raw_observation.memory_peak_raw_text exceeds unsigned 64-bit range"
                )
            raw_peak = _integer(
                int(raw_digits),
                f"{label}.raw_observation.memory_peak_raw_text",
                minimum=0,
                maximum=MAX_U64,
            )
            if raw_peak != observed:
                raise ContractError(f"{label}.raw_observation does not match peak_rss value")
        if observed is not None and observed <= 0:
            raise ContractError(f"{label}.value must be > 0; use null with a reason when unavailable")
    return observed


def _validate_sample(
    value: Any,
    label: str,
    *,
    phase: str,
    arm: str,
    pair_index: int,
    order_index: int,
    binding: dict[str, str],
    fixed: dict[str, Any],
    protocol: dict[str, Any],
    corpus_inputs: list[dict[str, Any]],
    measurement_context_sha256: str,
    input_count_per_corpus_pass: int,
    target_api_calls_per_corpus_pass: int,
    latency_target_api_calls: list[int],
    mode: str,
) -> dict[str, Any]:
    sample = _object(value, label, SAMPLE_FIELDS)
    sample_id = _string(sample["sample_id"], f"{label}.sample_id")
    if SAFE_ID.fullmatch(sample_id) is None:
        raise ContractError(f"{label}.sample_id is unsafe")
    for key, expected in (("phase", phase), ("arm", arm), ("pair_index", pair_index), ("order_index", order_index)):
        if sample[key] != expected or (key in {"pair_index", "order_index"} and isinstance(sample[key], bool)):
            raise ContractError(f"{label}.{key} must be {expected!r}, observed {sample[key]!r}")
    for key, expected in binding.items():
        if sample[key] != expected:
            raise ContractError(f"{label}.{key} does not match {arm} identity")
    if sample["corpus_sha256"] != fixed["corpus_sha256"]:
        raise ContractError(f"{label}.corpus_sha256 does not match fixed corpus")
    if sample["corpus_index_sha256"] != fixed["corpus_index_sha256"]:
        raise ContractError(f"{label}.corpus_index_sha256 does not match fixed corpus index")
    if sample["measurement_context_sha256"] != measurement_context_sha256:
        raise ContractError(
            f"{label}.measurement_context_sha256 does not match its fixed conditions/calibration"
        )
    workload = _object(
        sample["throughput_workload"],
        f"{label}.throughput_workload",
        {"scope", "input_order", "complete_corpus_passes"},
    )
    if workload["scope"] != "workload_only":
        raise ContractError(f"{label}.throughput_workload.scope must be workload_only")
    if workload["input_order"] != "corpus_index_rounds":
        raise ContractError(f"{label}.throughput_workload.input_order must be corpus_index_rounds")
    complete_passes = _integer(
        workload["complete_corpus_passes"],
        f"{label}.throughput_workload.complete_corpus_passes",
        minimum=1,
        maximum=MAX_U64,
    )
    observed: dict[str, Any] = {}
    for key, (unit, kind) in METRIC_SPECS.items():
        observed[key] = _validate_metric(
            sample[key],
            f"{label}.{key}",
            sample_id,
            unit,
            kind,
            protocol,
            corpus_inputs,
            latency_target_api_calls,
        )
    input_count = observed["input_count"]
    if input_count is not None:
        expected_inputs = _checked_product_u64(
            complete_passes,
            input_count_per_corpus_pass,
            f"{label}.input_count",
        )
        if input_count != expected_inputs:
            raise ContractError(
                f"{label}.input_count must equal {expected_inputs} derived from complete corpus passes"
            )
    actual_calls = observed["target_api_calls"]
    if actual_calls is not None:
        expected_calls = _checked_product_u64(
            complete_passes,
            target_api_calls_per_corpus_pass,
            f"{label}.target_api_calls",
        )
        if actual_calls != expected_calls:
            raise ContractError(
                f"{label}.target_api_calls must equal {expected_calls} derived from complete corpus passes"
            )
    if mode == "real" and phase != "warmup":
        wall = observed["wall_time"]
        if wall is None or wall < protocol["minimum_sample_seconds"]:
            raise ContractError(
                f"{label}.wall_time must cover at least {protocol['minimum_sample_seconds']:g} seconds in real mode"
            )
    return observed


OPERATION_FIELDS = {
    "schema_version",
    "operation",
    "mode",
    "target_id",
    "tool_commit",
    "dirty_diff_sha256",
    "profile_sha256",
    "command",
    "command_sha256",
    "corpus_before_sha256",
    "corpus_after_sha256",
    "started_utc",
    "ended_utc",
    "duration_seconds",
    "target_api_calls",
    "worker_count",
    "expected_outcome",
    "observed_outcome",
    "exit_code",
    "signal",
    "residual_processes",
    "resource_samples",
    "budgets",
    "artifacts",
}


def _utc_timestamp(value: Any, label: str) -> datetime:
    text = _string(value, label)
    if not text.endswith("Z"):
        raise ContractError(f"{label} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise ContractError(f"{label} must be an RFC3339 UTC timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise ContractError(f"{label} must use UTC")
    return parsed


def _validate_operation_raw(
    value: Any,
    *,
    name: str,
    identity: dict[str, Any],
) -> dict[str, Any]:
    label = f"operations.{name}.raw_json"
    raw = _object(value, label, OPERATION_FIELDS)
    if raw["schema_version"] != "tflite-v7-operation-v1":
        raise ContractError(f"{label}.schema_version is unsupported")
    if raw["operation"] != name:
        raise ContractError(f"{label}.operation does not match its operation slot")
    if raw["mode"] != "real":
        raise ContractError(f"{label}.mode must be real")
    fixed = identity["fixed"]
    if raw["target_id"] != fixed["target_id"]:
        raise ContractError(f"{label}.target_id does not match the fixed identity")
    if _commit(raw["tool_commit"], f"{label}.tool_commit") != identity["candidate_tool_commit"]:
        raise ContractError(f"{label}.tool_commit does not match the candidate identity")
    dirty = raw["dirty_diff_sha256"]
    if dirty is not None:
        dirty = _sha256(dirty, f"{label}.dirty_diff_sha256")
    if dirty != identity["candidate_dirty_diff_sha256"]:
        raise ContractError(f"{label}.dirty_diff_sha256 does not match the candidate identity")
    if _sha256(raw["profile_sha256"], f"{label}.profile_sha256") != identity["candidate_profile_sha256"]:
        raise ContractError(f"{label}.profile_sha256 does not match the candidate identity")
    command = _object(
        raw["command"],
        f"{label}.command",
        {"argv", "allowed_env", "cwd", "executable_sha256"},
    )
    argv = command["argv"]
    if not isinstance(argv, list) or not argv:
        raise ContractError(f"{label}.command.argv must be a non-empty list")
    for index, item in enumerate(argv):
        _string(item, f"{label}.command.argv[{index}]")
    if not os.path.isabs(argv[0]):
        raise ContractError(f"{label}.command.argv[0] must be absolute")
    allowed_env = command["allowed_env"]
    if not isinstance(allowed_env, dict):
        raise ContractError(f"{label}.command.allowed_env must be an object")
    for key, item in allowed_env.items():
        _string(key, f"{label}.command.allowed_env key")
        _string(item, f"{label}.command.allowed_env.{key}", nonempty=False)
    _validate_command_environment(
        command,
        identity["candidate_profile"],
        f"{label}.command",
    )
    if "PATH" not in allowed_env:
        raise ContractError(f"{label}.command.allowed_env must pin PATH")
    cwd = _string(command["cwd"], f"{label}.command.cwd")
    if not os.path.isabs(cwd) or cwd == "/mnt" or cwd.startswith("/mnt/"):
        raise ContractError(f"{label}.command.cwd must be an absolute WSL ext4 path")
    executable_sha = _sha256(
        command["executable_sha256"], f"{label}.command.executable_sha256"
    )
    command_sha = _sha256(raw["command_sha256"], f"{label}.command_sha256")
    if _sha256_bytes(_canonical_json(command)) != command_sha:
        raise ContractError(f"{label}.command_sha256 does not match the embedded command")
    if name == "actual_parser_performance" and (
        command != identity["candidate_command"]
        or command_sha != identity["candidate_command_sha256"]
    ):
        raise ContractError(f"{label}.command does not match the candidate replay identity")
    matching_binaries = [
        binary
        for binary in identity["candidate_profile"]["binaries"]
        if isinstance(binary, dict)
        and binary.get("path") == argv[0]
        and binary.get("sha256") == executable_sha
    ]
    if len(matching_binaries) != 1:
        raise ContractError(
            f"{label}.command executable does not match exactly one candidate profile binary"
        )
    expected_binary_role = (
        "fuzzer" if name in {"single_worker_soak", "parallel_soak"} else "replay"
    )
    if matching_binaries[0].get("role") != expected_binary_role:
        raise ContractError(
            f"{label}.command must use the profile-pinned {expected_binary_role} binary"
        )
    if expected_binary_role == "fuzzer":
        required_flags = {"-print_final_stats=1", "-max_total_time=21600"}
        missing_flags = sorted(required_flags - set(argv))
        if missing_flags:
            raise ContractError(
                f"{label}.command misses required libFuzzer flags: {missing_flags}"
            )
    if expected_binary_role == "fuzzer" and argv.count("{corpus_dir}") != 1:
        raise ContractError(
            f"{label}.command must contain exactly one {{corpus_dir}} placeholder"
        )
    before = _sha256(raw["corpus_before_sha256"], f"{label}.corpus_before_sha256")
    after = _sha256(raw["corpus_after_sha256"], f"{label}.corpus_after_sha256")
    if before != fixed["corpus_sha256"] or after != before:
        raise ContractError(f"{label} corpus identity changed")

    started = _utc_timestamp(raw["started_utc"], f"{label}.started_utc")
    ended = _utc_timestamp(raw["ended_utc"], f"{label}.ended_utc")
    duration = _number(raw["duration_seconds"], f"{label}.duration_seconds", minimum=0.0)
    if duration <= 0:
        raise ContractError(f"{label}.duration_seconds must be > 0")
    elapsed = (ended - started).total_seconds()
    if elapsed <= 0 or abs(elapsed - duration) > max(0.001, duration * 0.000001):
        raise ContractError(f"{label} timestamps do not match duration_seconds")
    minimum_duration = 21_600.0 if name in {"single_worker_soak", "parallel_soak"} else 60.0
    if name in {"engine_smoke", "fault_injection"}:
        minimum_duration = 0.001
    if duration < minimum_duration:
        raise ContractError(
            f"{label}.duration_seconds must be at least {minimum_duration:g} for {name}"
        )
    target_calls = _integer(
        raw["target_api_calls"], f"{label}.target_api_calls", minimum=1, maximum=MAX_U64
    )
    if target_calls == 0:
        raise ContractError(f"{label}.target_api_calls must be > 0")
    expected_workers = 2 if name == "parallel_soak" else 1
    if _integer(raw["worker_count"], f"{label}.worker_count", minimum=1) != expected_workers:
        raise ContractError(f"{label}.worker_count must be {expected_workers}")
    expected_outcome = "worker_failure" if name == "fault_injection" else "completed"
    if raw["expected_outcome"] != expected_outcome or raw["observed_outcome"] != expected_outcome:
        raise ContractError(f"{label} outcome does not match the required {expected_outcome!r}")
    exit_code = _integer(raw["exit_code"], f"{label}.exit_code", minimum=0)
    if (name == "fault_injection" and exit_code == 0) or (
        name != "fault_injection" and exit_code != 0
    ):
        raise ContractError(f"{label}.exit_code contradicts the required outcome")
    if raw["signal"] is not None:
        _string(raw["signal"], f"{label}.signal")
        raise ContractError(f"{label}.signal must be null for a qualifying operation")
    if _integer(raw["residual_processes"], f"{label}.residual_processes", minimum=0) != 0:
        raise ContractError(f"{label}.residual_processes must be zero")

    budgets = _object(raw["budgets"], f"{label}.budgets", {"peak_rss_bytes", "log_bytes", "disk_bytes"})
    checked_budgets = {
        key: _integer(budgets[key], f"{label}.budgets.{key}", minimum=1, maximum=MAX_U64)
        for key in budgets
    }
    expected_peak_budget = fixed["memory_limit_bytes"] * expected_workers
    if checked_budgets["peak_rss_bytes"] != expected_peak_budget:
        raise ContractError(
            f"{label}.budgets.peak_rss_bytes must equal the pinned per-worker limit times workers"
        )
    samples = raw["resource_samples"]
    if not isinstance(samples, list) or len(samples) < 2:
        raise ContractError(f"{label}.resource_samples must contain start and final samples")
    previous_elapsed = -1.0
    previous_peak = -1
    previous_log = -1
    for index, sample_value in enumerate(samples):
        sample_label = f"{label}.resource_samples[{index}]"
        sample = _object(
            sample_value,
            sample_label,
            {"elapsed_seconds", "peak_rss_bytes", "log_bytes", "disk_bytes", "owned_processes"},
        )
        sample_elapsed = _number(sample["elapsed_seconds"], f"{sample_label}.elapsed_seconds", minimum=0.0)
        if sample_elapsed <= previous_elapsed or sample_elapsed > duration:
            raise ContractError(f"{sample_label}.elapsed_seconds must increase within the operation")
        previous_elapsed = sample_elapsed
        for key in ("peak_rss_bytes", "log_bytes", "disk_bytes"):
            observed = _integer(sample[key], f"{sample_label}.{key}", minimum=0, maximum=MAX_U64)
            if observed > checked_budgets[key]:
                raise ContractError(f"{sample_label}.{key} exceeds its precommitted budget")
            if key == "peak_rss_bytes":
                if observed < previous_peak:
                    raise ContractError(f"{sample_label}.{key} is not a cumulative peak")
                previous_peak = observed
            elif key == "log_bytes":
                if observed < previous_log:
                    raise ContractError(f"{sample_label}.{key} decreased")
                previous_log = observed
        _integer(sample["owned_processes"], f"{sample_label}.owned_processes", minimum=0)
    if abs(previous_elapsed - duration) > max(0.001, duration * 0.000001):
        raise ContractError(f"{label}.resource_samples do not reach the operation end")
    if samples[-1]["owned_processes"] != 0:
        raise ContractError(f"{label}.resource_samples final owned_processes must be zero")

    artifacts = raw["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ContractError(f"{label}.artifacts must be a non-empty list")
    artifact_paths: set[str] = set()
    for index, artifact_value in enumerate(artifacts):
        artifact_label = f"{label}.artifacts[{index}]"
        artifact = _object(artifact_value, artifact_label, {"path", "sha256", "size_bytes"})
        path = _string(artifact["path"], f"{artifact_label}.path")
        if os.path.isabs(path) or ".." in Path(path).parts or path in artifact_paths:
            raise ContractError(f"{artifact_label}.path is unsafe or duplicated")
        artifact_paths.add(path)
        _sha256(artifact["sha256"], f"{artifact_label}.sha256")
        _integer(artifact["size_bytes"], f"{artifact_label}.size_bytes", minimum=0)
    return raw


def _validate_operations(
    value: Any,
    *,
    identity: dict[str, Any],
    mode: str,
) -> tuple[dict[str, Any], str]:
    names = {
        "actual_parser_performance",
        "engine_smoke",
        "single_worker_soak",
        "parallel_soak",
        "fault_injection",
    }
    operations = _object(value, "operations", names)
    statuses: list[str] = []
    for name in sorted(names):
        row = _object(
            operations[name],
            f"operations.{name}",
            {"status", "reason", "evidence_sha256", "raw_json"},
        )
        status = row["status"]
        if status == "pass":
            if row["raw_json"] is None or row["evidence_sha256"] is None:
                raise ContractError(
                    f"operations.{name}.status pass requires strict raw V7 evidence"
                )
            if mode != "real":
                raise ContractError(f"operations.{name}.status pass requires real mode")
            if row["reason"] is not None:
                raise ContractError(f"operations.{name}.reason must be null for pass")
            raw_text = _string(row["raw_json"], f"operations.{name}.raw_json")
            raw_sha = _sha256(row["evidence_sha256"], f"operations.{name}.evidence_sha256")
            if _sha256_bytes(raw_text.encode("utf-8")) != raw_sha:
                raise ContractError(f"operations.{name}.evidence_sha256 does not match raw_json")
            raw = _parse_json_text(raw_text, f"operations.{name}.raw_json")
            _validate_operation_raw(raw, name=name, identity=identity)
        if status not in {"fail", "pending"}:
            if status != "pass":
                raise ContractError(f"operations.{name}.status is unsupported")
        if status != "pass":
            _string(row["reason"], f"operations.{name}.reason")
            if status == "pending" and (
                row["evidence_sha256"] is not None or row["raw_json"] is not None
            ):
                raise ContractError(
                    f"operations.{name} evidence_sha256/raw_json must be null while pending"
                )
            if status == "fail":
                if (row["evidence_sha256"] is None) != (row["raw_json"] is None):
                    raise ContractError(
                        f"operations.{name} failed raw_json and evidence_sha256 must appear together"
                    )
                if row["raw_json"] is not None:
                    raw_text = _string(row["raw_json"], f"operations.{name}.raw_json")
                    if _sha256_bytes(raw_text.encode("utf-8")) != _sha256(
                        row["evidence_sha256"], f"operations.{name}.evidence_sha256"
                    ):
                        raise ContractError(
                            f"operations.{name}.evidence_sha256 does not match raw_json"
                        )
        statuses.append(status)
    overall = "fail" if "fail" in statuses else "pending" if "pending" in statuses else "pass"
    return operations, overall


def _sample_values(sample: dict[str, Any]) -> dict[str, Any]:
    return {key: sample[key]["value"] for key in METRIC_SPECS}


def _latency_distribution(values: Sequence[dict[str, Any]]) -> dict[str, float]:
    """Summarize the fixed probe subset's normalized per-call values."""

    normalized = [float(row["normalized_seconds_per_call"]) for row in values]
    if not normalized:
        raise ContractError("latency distribution requires fixed-corpus observations")
    return {
        "median_seconds": _median(normalized),
        "p95_seconds": _nearest_rank(normalized, 0.95),
    }


def _latency_p95(values: Sequence[dict[str, Any]]) -> float:
    return _latency_distribution(values)["p95_seconds"]


def _derived_metrics(values: dict[str, Any]) -> dict[str, float | None]:
    wall = values["wall_time"]
    calls = values["target_api_calls"]
    throughput = None
    if wall is not None and calls is not None and wall > 0 and calls > 0:
        throughput = _finite_derived(
            float(calls) / float(wall),
            "throughput",
        )
    latency = values["per_input_latency"]
    latency_distribution = None if latency is None else _latency_distribution(latency)
    return {
        "throughput": throughput,
        "peak_rss": None if values["peak_rss"] is None else float(values["peak_rss"]),
        "latency_median": None if latency_distribution is None else latency_distribution["median_seconds"],
        "latency_p95": None if latency_distribution is None else latency_distribution["p95_seconds"],
    }


def _latency_statistics(values: dict[str, Any]) -> dict[str, Any] | None:
    rows = values["per_input_latency"]
    if rows is None:
        return None
    corpus = _latency_distribution(rows)
    return {
        "corpus_median_seconds": corpus["median_seconds"],
        "corpus_p95_seconds": corpus["p95_seconds"],
        "per_input": [
            {
                "path": row["path"],
                "sha256": row["sha256"],
                "probe_order_index": row["probe_order_index"],
                "batch_iterations": row["batch_iterations"],
                "target_api_calls": row["target_api_calls"],
                "process_elapsed_seconds": row["process_elapsed_seconds"],
                "normalized_seconds_per_call": row["normalized_seconds_per_call"],
            }
            for row in rows
        ],
    }


def _sample_failure_reasons(label: str, values: dict[str, Any]) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    incomplete: list[str] = []
    for key in METRIC_SPECS:
        if values[key] is None:
            incomplete.append(f"{label}.{key} is unavailable")
    if values["input_count"] == 0:
        failures.append(f"{label}.input_count is zero")
    if values["target_api_calls"] == 0:
        failures.append(f"{label}.target_api_calls is zero")
    if values["exit_code"] not in (None, 0):
        failures.append(f"{label}.exit_code is {values['exit_code']}")
    if values["residual_processes"] not in (None, 0):
        failures.append(f"{label}.residual_processes is {values['residual_processes']}")
    return failures, incomplete


def _calibration_summary(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    protocol: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for metric in ("throughput", "peak_rss", "latency_p95"):
        ratios: list[float] = []
        resolutions: list[float] = []
        unavailable = False
        for baseline_values, repeat_values in pairs:
            baseline = _derived_metrics(baseline_values)[metric]
            repeat = _derived_metrics(repeat_values)[metric]
            if baseline is None or repeat is None or baseline <= 0:
                unavailable = True
                continue
            ratios.append(_finite_derived(repeat / baseline, f"calibration {metric} ratio"))
            if metric == "throughput":
                wall = baseline_values["wall_time"]
                calls = baseline_values["target_api_calls"]
                if wall is None or calls is None or wall <= 0 or calls <= 0:
                    unavailable = True
                    continue
                resolution = max(
                    _finite_derived(
                        float(protocol["clock_resolution_seconds"]) / float(wall),
                        "throughput clock resolution",
                    ),
                    _finite_derived(
                        float(protocol["api_call_resolution_calls"]) / float(calls),
                        "throughput API-call resolution",
                    ),
                )
            elif metric == "peak_rss":
                resolution = _finite_derived(
                    float(protocol["rss_resolution_bytes"]) / baseline,
                    "peak RSS resolution",
                )
            else:
                resolution = _finite_derived(
                    float(protocol["clock_resolution_seconds"]) / baseline,
                    "latency clock resolution",
                )
            resolutions.append(resolution)
        sample_statistics = None
        if metric == "latency_p95":
            sample_statistics = [
                {
                    "pair_index": index,
                    "baseline_a": _latency_statistics(baseline_values),
                    "baseline_b": _latency_statistics(repeat_values),
                }
                for index, (baseline_values, repeat_values) in enumerate(pairs, start=1)
            ]
        if unavailable or len(ratios) != len(pairs) or len(resolutions) != len(pairs):
            result[metric] = {
                "status": "inconclusive",
                "paired_ratios": ratios,
                "noise_p95": None,
                "resolution": None,
                "delta": None,
                "aggregation": (
                    "corpus_nearest_rank_p95_of_normalized_per_call_rows"
                    if metric == "latency_p95"
                    else "sample_scalar"
                ),
                "sample_statistics": sample_statistics,
                "reason": "calibration metric unavailable or denominator is zero",
            }
            continue
        noise = _finite_derived(
            _nearest_rank([abs(item - 1.0) for item in ratios], 0.95),
            f"calibration {metric} noise",
        )
        resolution = _finite_derived(max(resolutions), f"calibration {metric} resolution")
        delta = _finite_derived(max(noise, resolution), f"calibration {metric} delta")
        status = "pass" if delta < 1.0 else "inconclusive"
        result[metric] = {
            "status": status,
            "paired_ratios": ratios,
            "noise_p95": noise,
            "resolution": resolution,
            "delta": delta,
            "aggregation": (
                "corpus_nearest_rank_p95_of_normalized_per_call_rows"
                if metric == "latency_p95"
                else "sample_scalar"
            ),
            "sample_statistics": sample_statistics,
            "reason": None if status == "pass" else "calibration delta must be < 1",
        }
    return result


def _comparison_summary(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    calibration: dict[str, dict[str, Any]],
    budgets: dict[str, float],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for metric in ("throughput", "peak_rss", "latency_p95"):
        ratios: list[float] = []
        candidate_values: list[float] = []
        unavailable = False
        for baseline_values, candidate in pairs:
            baseline_metric = _derived_metrics(baseline_values)[metric]
            candidate_metric = _derived_metrics(candidate)[metric]
            if candidate_metric is not None:
                candidate_values.append(candidate_metric)
            if baseline_metric is None or candidate_metric is None or baseline_metric <= 0:
                unavailable = True
                continue
            ratios.append(
                _finite_derived(
                    candidate_metric / baseline_metric,
                    f"comparison {metric} ratio",
                )
            )
        base: dict[str, Any] = {
            "paired_ratios": ratios,
            "median_ratio": None,
            "range": None,
            "bootstrap_95": None,
            "allowed_boundary": None,
            "absolute_budget": None,
            "aggregation": (
                "corpus_nearest_rank_p95_of_normalized_per_call_rows"
                if metric == "latency_p95"
                else "sample_scalar"
            ),
            "sample_statistics": (
                [
                    {
                        "pair_index": index,
                        "baseline": _latency_statistics(baseline_values),
                        "candidate": _latency_statistics(candidate_values),
                    }
                    for index, (baseline_values, candidate_values) in enumerate(pairs, start=1)
                ]
                if metric == "latency_p95"
                else None
            ),
            "status": "inconclusive",
            "reason": None,
        }
        calibration_row = calibration[metric]
        delta = calibration_row["delta"]
        if metric != "throughput" and candidate_values:
            budget_key = "peak_rss_bytes" if metric == "peak_rss" else "latency_p95_seconds"
            budget = budgets[budget_key]
            maximum_observed = max(candidate_values)
            base["absolute_budget"] = {
                "limit": budget,
                "maximum_observed": maximum_observed,
            }
            if maximum_observed > budget:
                base["status"] = "fail"
                base["reason"] = f"candidate exceeds absolute {budget_key} budget"
                result[metric] = base
                continue
        if unavailable or len(ratios) != len(pairs):
            base["reason"] = "comparison metric unavailable or denominator is zero"
            result[metric] = base
            continue
        base["median_ratio"] = _median(ratios)
        base["range"] = {"minimum": min(ratios), "maximum": max(ratios)}
        lower, upper = bootstrap_median_ci(ratios)
        base["bootstrap_95"] = {"lower": lower, "upper": upper}
        if delta is None or calibration_row["status"] != "pass":
            base["reason"] = "A/A calibration is unavailable or delta >= 1"
            result[metric] = base
            continue
        if metric == "throughput":
            boundary = 1.0 - delta
            base["allowed_boundary"] = {"kind": "minimum", "ratio": boundary}
            if lower >= boundary:
                base["status"] = "pass"
            elif upper < boundary:
                base["status"] = "fail"
                base["reason"] = "entire throughput interval is below the allowed boundary"
            else:
                base["reason"] = "throughput interval crosses the allowed boundary"
        else:
            boundary = 1.0 + delta
            base["allowed_boundary"] = {"kind": "maximum", "ratio": boundary}
            if upper <= boundary:
                base["status"] = "pass"
            elif lower > boundary:
                base["status"] = "fail"
                base["reason"] = f"entire {metric} interval is above the allowed boundary"
            else:
                base["reason"] = f"{metric} interval crosses the allowed boundary"
        result[metric] = base
    return result


def evaluate_document(document: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one complete paired observation document."""

    _validate_json_values(document, "observations")
    document = _object(
        document,
        "observations",
        {
            "schema_version",
            "mode",
            "comparison_id",
            "identity",
            "environment",
            "protocol",
            "correctness",
            "warmups",
            "calibration",
            "comparison",
            "absolute_budgets",
            "operations",
        },
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise ContractError(f"unsupported schema_version {document['schema_version']!r}")
    mode = document["mode"]
    if mode not in {"real", "selftest"}:
        raise ContractError("mode must be real or selftest")
    comparison_id = _string(document["comparison_id"], "comparison_id")
    if SAFE_ID.fullmatch(comparison_id) is None:
        raise ContractError("comparison_id is unsafe")
    identity, bindings, corpus_inputs = _validate_identity(document["identity"])
    fixed = identity["fixed"]
    _validate_environment(document["environment"], fixed)
    protocol = _validate_protocol(document["protocol"])
    budgets = _object(document["absolute_budgets"], "absolute_budgets", {"peak_rss_bytes", "latency_p95_seconds"})
    checked_budgets = {
        "peak_rss_bytes": _number(budgets["peak_rss_bytes"], "absolute_budgets.peak_rss_bytes", minimum=0.0),
        "latency_p95_seconds": _number(
            budgets["latency_p95_seconds"], "absolute_budgets.latency_p95_seconds", minimum=0.0
        ),
    }
    if any(value <= 0 for value in checked_budgets.values()):
        raise ContractError("absolute budgets must be > 0")
    conditions_sha256 = _measurement_conditions_sha256(
        mode,
        fixed,
        document["environment"],
        protocol,
        budgets,
    )
    correctness, functional_failures = _validate_correctness(
        document["correctness"],
        fixed=fixed,
        bindings=bindings,
        corpus_inputs=corpus_inputs,
        conditions_sha256=conditions_sha256,
    )
    calibration_context_sha256 = _measurement_context_sha256(
        conditions_sha256,
        correctness["snapshot_sha256"],
    )
    calibration_raw_sha256 = _sha256_bytes(_canonical_json(document["calibration"]))
    comparison_context_sha256 = _comparison_measurement_context_sha256(
        calibration_context_sha256,
        calibration_raw_sha256,
    )
    operations, operations_status = _validate_operations(
        document["operations"], identity=identity, mode=mode
    )

    throughput_inputs = sorted(
        (row for row in corpus_inputs if row["throughput_order_index"] is not None),
        key=lambda row: row["throughput_order_index"],
    )
    latency_inputs = sorted(
        (row for row in corpus_inputs if row["latency_probe_order_index"] is not None),
        key=lambda row: row["latency_probe_order_index"],
    )

    def sample_contract(arm: str, pair_index: int) -> tuple[int, int, list[dict[str, Any]], list[int]]:
        calls_by_path = correctness[arm]["target_api_calls_by_path"]
        calls_per_pass = sum(calls_by_path[row["path"]] for row in throughput_inputs)
        rotation = 0 if pair_index == 0 else (pair_index - 1) % len(latency_inputs)
        rotated = latency_inputs[rotation:] + latency_inputs[:rotation]
        return (
            len(throughput_inputs),
            calls_per_pass,
            rotated,
            [calls_by_path[row["path"]] for row in rotated],
        )

    warmups = document["warmups"]
    if not isinstance(warmups, list) or len(warmups) != 3:
        raise ContractError("warmups must contain separate calibration, baseline, and candidate records")
    warmup_specs = (
        ("calibration", "baseline", bindings["baseline"]),
        ("baseline", "baseline", bindings["baseline"]),
        ("candidate", "candidate", bindings["candidate"]),
    )
    all_sample_ids: set[str] = set()
    measurement_failures: list[str] = []
    incomplete: list[str] = []
    for offset, ((arm, identity_arm, binding), sample) in enumerate(zip(warmup_specs, warmups), start=1):
        input_count_per_pass, calls_per_pass, latency_rows, latency_calls = sample_contract(
            identity_arm, 0
        )
        observed = _validate_sample(
            sample,
            f"warmups[{offset - 1}]",
            phase="warmup",
            arm=arm,
            pair_index=0,
            order_index=offset,
            binding=binding,
            fixed=fixed,
            protocol=protocol,
            corpus_inputs=latency_rows,
            measurement_context_sha256=calibration_context_sha256,
            input_count_per_corpus_pass=input_count_per_pass,
            target_api_calls_per_corpus_pass=calls_per_pass,
            latency_target_api_calls=latency_calls,
            mode=mode,
        )
        sample_id = sample["sample_id"]
        if sample_id in all_sample_ids:
            raise ContractError(f"duplicate sample_id {sample_id}")
        all_sample_ids.add(sample_id)
        failures, missing = _sample_failure_reasons(f"warmups[{offset - 1}]", observed)
        measurement_failures.extend(failures)
        incomplete.extend(missing)

    calibration_value = document["calibration"]
    comparison_value = document["comparison"]
    if not isinstance(calibration_value, list) or not MIN_PAIRS <= len(calibration_value) <= MAX_PAIRS:
        raise ContractError(f"calibration must contain {MIN_PAIRS} to {MAX_PAIRS} complete pairs")
    if not isinstance(comparison_value, list) or not MIN_PAIRS <= len(comparison_value) <= MAX_PAIRS:
        raise ContractError(f"comparison must contain {MIN_PAIRS} to {MAX_PAIRS} complete pairs")
    if len(calibration_value) != len(comparison_value):
        raise ContractError("calibration and comparison pair counts must match")

    calibration_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    comparison_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    pair_specs = (
        (
            "calibration",
            calibration_value,
            "baseline_a",
            "baseline_b",
            bindings["baseline"],
            bindings["baseline"],
            "baseline",
            "baseline",
        ),
        (
            "comparison",
            comparison_value,
            "baseline",
            "candidate",
            bindings["baseline"],
            bindings["candidate"],
            "baseline",
            "candidate",
        ),
    )
    for (
        phase,
        raw_pairs,
        left_arm,
        right_arm,
        left_binding,
        right_binding,
        left_identity_arm,
        right_identity_arm,
    ) in pair_specs:
        destination = calibration_pairs if phase == "calibration" else comparison_pairs
        expected_pair_keys = {"pair_index", left_arm, right_arm}
        for offset, raw_pair in enumerate(raw_pairs, start=1):
            pair = _object(raw_pair, f"{phase}[{offset - 1}]", expected_pair_keys)
            if pair["pair_index"] != offset or isinstance(pair["pair_index"], bool):
                raise ContractError(f"{phase}[{offset - 1}].pair_index must be contiguous value {offset}")
            observed_arms: list[dict[str, Any]] = []
            for arm_offset, (arm, binding, identity_arm) in enumerate(
                (
                    (left_arm, left_binding, left_identity_arm),
                    (right_arm, right_binding, right_identity_arm),
                )
            ):
                sample = pair[arm]
                label = f"{phase}[{offset - 1}].{arm}"
                input_count_per_pass, calls_per_pass, latency_rows, latency_calls = sample_contract(
                    identity_arm, offset
                )
                observed = _validate_sample(
                    sample,
                    label,
                    phase=phase,
                    arm=arm,
                    pair_index=offset,
                    order_index=2 * (offset - 1) + arm_offset + 1,
                    binding=binding,
                    fixed=fixed,
                    protocol=protocol,
                    corpus_inputs=latency_rows,
                    measurement_context_sha256=(
                        calibration_context_sha256
                        if phase == "calibration"
                        else comparison_context_sha256
                    ),
                    input_count_per_corpus_pass=input_count_per_pass,
                    target_api_calls_per_corpus_pass=calls_per_pass,
                    latency_target_api_calls=latency_calls,
                    mode=mode,
                )
                sample_id = sample["sample_id"]
                if sample_id in all_sample_ids:
                    raise ContractError(f"duplicate sample_id {sample_id}")
                all_sample_ids.add(sample_id)
                failures, missing = _sample_failure_reasons(label, observed)
                measurement_failures.extend(failures)
                incomplete.extend(missing)
                observed_arms.append(observed)
            destination.append((observed_arms[0], observed_arms[1]))

    calibration = _calibration_summary(calibration_pairs, protocol)
    metrics = _comparison_summary(comparison_pairs, calibration, checked_budgets)
    metric_statuses = [row["status"] for row in metrics.values()]
    calibration_statuses = [row["status"] for row in calibration.values()]
    reasons: list[str] = []
    if functional_failures:
        reasons.extend(functional_failures)
    if measurement_failures:
        reasons.extend(measurement_failures)
    if functional_failures or measurement_failures:
        performance_status = "fail"
    elif "fail" in metric_statuses:
        performance_status = "fail"
        reasons.extend(row["reason"] for row in metrics.values() if row["status"] == "fail" and row["reason"])
    elif incomplete or "inconclusive" in calibration_statuses or "inconclusive" in metric_statuses:
        performance_status = "inconclusive"
        reasons.extend(incomplete)
        reasons.extend(
            row["reason"]
            for row in list(calibration.values()) + list(metrics.values())
            if row["status"] == "inconclusive" and row["reason"]
        )
    else:
        performance_status = "pass"
        reasons.append("no regression detected at the calibrated per-metric delta")

    if performance_status == "fail" or operations_status == "fail":
        gate_status = "fail"
    elif performance_status == "inconclusive":
        gate_status = "inconclusive"
    elif operations_status == "pending":
        gate_status = "pending"
    else:
        gate_status = "pass"
    # Self-tests and pending/failed V7 operations never authorize the next card.
    next_stage_blocked = gate_status != "pass" or mode != "real"
    return {
        "schema_version": EVALUATION_VERSION,
        "comparison_id": comparison_id,
        "mode": mode,
        "performance_claim_eligible": (
            mode == "real"
            and performance_status == "pass"
            and operations_status == "pass"
            and not next_stage_blocked
        ),
        "status": performance_status,
        "performance_status": performance_status,
        "gate_status": gate_status,
        "status_name": (
            "측정 분해능 δ에서 회귀 검출 없음"
            if performance_status == "pass"
            else performance_status
        ),
        "reasons": sorted(set(reasons)),
        "correctness_status": "fail" if functional_failures else "pass",
        "correctness": correctness,
        "measurement_contexts": {
            "conditions_sha256": conditions_sha256,
            "calibration_context_sha256": calibration_context_sha256,
            "calibration_raw_sha256": calibration_raw_sha256,
            "comparison_context_sha256": comparison_context_sha256,
        },
        "sample_integrity_status": "fail" if measurement_failures else "inconclusive" if incomplete else "pass",
        "calibration": calibration,
        "metrics": metrics,
        "operations_status": operations_status,
        "operations": operations,
        "bootstrap": {
            "python_version": sys.version.split()[0],
            "seed": BOOTSTRAP_SEED,
            "resamples": BOOTSTRAP_RESAMPLES,
            "quantile_method": "nearest-rank",
            "resampling_unit": "paired_index",
        },
        "pair_counts": {"calibration": len(calibration_pairs), "comparison": len(comparison_pairs)},
        "next_stage_blocked": next_stage_blocked,
    }


def _source_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _capture_evaluator_source(path: Path) -> tuple[bytes, tuple[int, int, int, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(f"could not open evaluator source without following symlinks: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError("evaluator source must be a regular file")
        if before.st_size <= 0 or before.st_size > 16 * 1024 * 1024:
            raise EvidenceError("evaluator source size must be between 1 byte and 16 MiB")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise EvidenceError("evaluator source changed or ended while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise EvidenceError("evaluator source grew while being read")
        after = os.fstat(descriptor)
        if _source_metadata(before) != _source_metadata(after):
            raise EvidenceError("evaluator source changed while being read")
    finally:
        os.close(descriptor)
    try:
        path_metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise EvidenceError(f"evaluator source path became unreadable: {error}") from error
    if not stat.S_ISREG(path_metadata.st_mode) or _source_metadata(path_metadata) != _source_metadata(after):
        raise EvidenceError("evaluator source path identity changed while being read")
    return b"".join(chunks), _source_metadata(after)


_EVALUATOR_SOURCE_PATH = Path(__file__).resolve()
_EVALUATOR_SOURCE_BYTES, _EVALUATOR_SOURCE_METADATA = _capture_evaluator_source(
    _EVALUATOR_SOURCE_PATH
)
_EVALUATOR_SOURCE_SHA256 = _sha256_bytes(_EVALUATOR_SOURCE_BYTES)


def _verify_evaluator_source_unchanged() -> None:
    current_bytes, current_metadata = _capture_evaluator_source(_EVALUATOR_SOURCE_PATH)
    if (
        current_metadata != _EVALUATOR_SOURCE_METADATA
        or current_bytes != _EVALUATOR_SOURCE_BYTES
        or _sha256_bytes(current_bytes) != _EVALUATOR_SOURCE_SHA256
    ):
        raise EvidenceError("evaluator source identity changed after module initialization")


def publish_evidence(
    document: dict[str, Any],
    evaluation: dict[str, Any],
    output_root: Path,
    *,
    test_hook: Callable[[str, Path, str], None] | None = None,
) -> Path:
    """Publish immutable, indexed evidence beneath an existing safe root.

    The destination directory and every record are created with no-replace
    primitives.  ``index.json`` is linked last and is the only completion
    marker; a crash or injected race therefore cannot turn a partial bundle
    into complete evidence.
    """

    if not isinstance(output_root, Path):
        output_root = Path(output_root)
    if not output_root.is_absolute():
        raise EvidenceError("output root must be an absolute path")
    comparison_id = evaluation.get("comparison_id")
    if comparison_id != document.get("comparison_id") or not isinstance(comparison_id, str):
        raise EvidenceError("evaluation comparison_id does not match observations")
    if SAFE_ID.fullmatch(comparison_id) is None:
        raise EvidenceError("comparison_id is unsafe")
    _verify_evaluator_source_unchanged()
    # Re-evaluate so callers cannot publish a forged verdict for these samples.
    expected_evaluation = evaluate_document(document)
    if expected_evaluation != evaluation:
        raise EvidenceError("evaluation does not match a fresh observation evaluation")

    destination = output_root / comparison_id
    root_fd: int | None = None
    destination_fd: int | None = None
    samples_fd: int | None = None
    profiles_fd: int | None = None
    operations_fd: int | None = None
    try:
        root_metadata = os.stat(output_root, follow_symlinks=False)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise EvidenceError("output root must be an existing non-symlink directory")
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        root_fd = os.open(output_root, directory_flags)
        opened_root = os.fstat(root_fd)
        root_identity = (opened_root.st_dev, opened_root.st_ino)
        if root_identity != (root_metadata.st_dev, root_metadata.st_ino):
            raise EvidenceError("output root changed while it was opened")
        try:
            os.mkdir(comparison_id, 0o700, dir_fd=root_fd)
        except FileExistsError as error:
            raise EvidenceError(f"evidence destination already exists: {destination}") from error
        os.fsync(root_fd)
        destination_fd = os.open(comparison_id, directory_flags, dir_fd=root_fd)
        destination_metadata = os.fstat(destination_fd)
        destination_identity = (destination_metadata.st_dev, destination_metadata.st_ino)
        for name in ("samples", "profiles", "operations"):
            os.mkdir(name, 0o700, dir_fd=destination_fd)
        os.fsync(destination_fd)
        samples_fd = os.open("samples", directory_flags, dir_fd=destination_fd)
        profiles_fd = os.open("profiles", directory_flags, dir_fd=destination_fd)
        operations_fd = os.open("operations", directory_flags, dir_fd=destination_fd)
        samples_identity = _fd_identity(samples_fd)
        profiles_identity = _fd_identity(profiles_fd)
        operations_identity = _fd_identity(operations_fd)

        if test_hook is not None:
            test_hook("directory_ready", destination, comparison_id)

        _verify_evaluator_source_unchanged()
        payloads = _evidence_payloads(document, evaluation)
        published_hashes: dict[str, str] = {}
        for relative, data in payloads:
            parent_fd = destination_fd
            name = relative
            if "/" in relative:
                prefix, name = relative.split("/", 1)
                if "/" in name:
                    raise EvidenceError(f"unsupported nested evidence path: {relative}")
                if prefix == "samples":
                    parent_fd = samples_fd
                elif prefix == "profiles":
                    parent_fd = profiles_fd
                elif prefix == "operations":
                    parent_fd = operations_fd
                else:
                    raise EvidenceError(f"unsafe evidence path: {relative}")
            _atomic_write_at(parent_fd, name, data)
            published_hashes[relative] = _sha256_bytes(data)

        if test_hook is not None:
            test_hook("before_index", destination, comparison_id)
        _verify_evaluator_source_unchanged()
        _verify_directory_identity(output_root, root_identity, "output root")
        _verify_child_identity(root_fd, comparison_id, destination_identity, "evidence directory")
        _verify_child_identity(destination_fd, "samples", samples_identity, "samples directory")
        _verify_child_identity(destination_fd, "profiles", profiles_identity, "profiles directory")
        _verify_child_identity(
            destination_fd, "operations", operations_identity, "operations directory"
        )
        index = {
            "schema_version": INDEX_VERSION,
            "state": "complete",
            "comparison_id": comparison_id,
            "mode": document["mode"],
            "performance_claim_eligible": evaluation["performance_claim_eligible"],
            "performance_status": evaluation["performance_status"],
            "operations_status": evaluation["operations_status"],
            "gate_status": evaluation["gate_status"],
            "next_stage_blocked": evaluation["next_stage_blocked"],
            "files": dict(sorted(published_hashes.items())),
            "files_index_sha256": _sha256_bytes(_canonical_json(dict(sorted(published_hashes.items())))),
        }
        _atomic_write_at(destination_fd, "index.json", _canonical_json(index))
        _verify_evaluator_source_unchanged()
        _verify_directory_identity(output_root, root_identity, "output root")
        _verify_child_identity(root_fd, comparison_id, destination_identity, "evidence directory")
        _verify_child_identity(destination_fd, "samples", samples_identity, "samples directory")
        _verify_child_identity(destination_fd, "profiles", profiles_identity, "profiles directory")
        _verify_child_identity(
            destination_fd, "operations", operations_identity, "operations directory"
        )
        os.fsync(destination_fd)
        os.fsync(root_fd)
        return destination
    except EvidenceError:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise EvidenceError(f"could not publish evidence without replacement: {error}") from error
    finally:
        for descriptor in (
            operations_fd,
            profiles_fd,
            samples_fd,
            destination_fd,
            root_fd,
        ):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _fd_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError("opened evidence object is not a directory")
    return metadata.st_dev, metadata.st_ino


def _verify_directory_identity(path: Path, identity: tuple[int, int], label: str) -> None:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise EvidenceError(f"{label} disappeared or became unreadable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != identity:
        raise EvidenceError(f"{label} identity changed during publication")


def _verify_child_identity(
    parent_fd: int,
    name: str,
    identity: tuple[int, int],
    label: str,
) -> None:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise EvidenceError(f"{label} disappeared or became unreadable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != identity:
        raise EvidenceError(f"{label} identity changed during publication")


def _atomic_write_at(directory_fd: int, name: str, data: bytes) -> None:
    if Path(name).name != name or name in {"", ".", ".."}:
        raise EvidenceError(f"unsafe evidence filename {name!r}")
    temporary = f".{name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short evidence write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError(f"could not atomically publish {name!r}: {error}") from error


def _evidence_payloads(
    document: dict[str, Any], evaluation: dict[str, Any]
) -> list[tuple[str, bytes]]:
    identity = document["identity"]
    script_path = _EVALUATOR_SOURCE_PATH
    script_sha = _EVALUATOR_SOURCE_SHA256
    profile_paths = {
        "baseline": "profiles/baseline-profile.json",
        "candidate": "profiles/candidate-profile.json",
    }
    correctness_paths = {
        "baseline": "profiles/baseline-correctness.json",
        "candidate": "profiles/candidate-correctness.json",
    }
    corpus_path = "profiles/corpus-index.json"
    manifest_identity = {
        key: value
        for key, value in identity.items()
        if key
        not in {
            "baseline_profile",
            "candidate_profile",
            "baseline_profile_raw_json",
            "candidate_profile_raw_json",
        }
    }
    manifest = {
        "schema_version": INDEX_VERSION,
        "state": "incomplete",
        "comparison_id": document["comparison_id"],
        "mode": document["mode"],
        "observation_schema_version": document["schema_version"],
        "canonical_observation_sha256": _sha256_bytes(_canonical_json(document)),
        "identity": manifest_identity,
        "profile_snapshots": {
            arm: {"path": path, "sha256": identity[f"{arm}_profile_sha256"]}
            for arm, path in profile_paths.items()
        },
        "correctness_snapshots": {
            arm: {
                "path": correctness_paths[arm],
                "sha256": document["correctness"][f"{arm}_sha256"],
            }
            for arm in ("baseline", "candidate")
        },
        "corpus_index_snapshot": {
            "path": corpus_path,
            "sha256": identity["fixed"]["corpus_index_sha256"],
        },
        "environment": document["environment"],
        "protocol": document["protocol"],
        "absolute_budgets": document["absolute_budgets"],
        "operations": document["operations"],
        "evaluator": {
            "path": str(script_path),
            "sha256": script_sha,
            "snapshot_path": "profiles/evaluator-source.py",
            "identity_scope": "module_initialization_source_snapshot",
            "python_version": sys.version.split()[0],
        },
    }
    payload_by_path: dict[str, bytes] = {
        "manifest.json": _canonical_json(manifest),
        profile_paths["baseline"]: identity["baseline_profile_raw_json"].encode("utf-8"),
        profile_paths["candidate"]: identity["candidate_profile_raw_json"].encode("utf-8"),
        correctness_paths["baseline"]: document["correctness"]["baseline_raw_json"].encode("utf-8"),
        correctness_paths["candidate"]: document["correctness"]["candidate_raw_json"].encode("utf-8"),
        corpus_path: identity["fixed"]["corpus_index_raw_json"].encode("utf-8"),
        "profiles/evaluator-source.py": _EVALUATOR_SOURCE_BYTES,
    }
    for name, row in sorted(document["operations"].items()):
        if row["raw_json"] is not None:
            payload_by_path[f"operations/{name}.json"] = row["raw_json"].encode("utf-8")
    refs: dict[str, list[dict[str, Any]]] = {
        "warmups": [],
        "calibration": [],
        "baseline": [],
        "candidate": [],
    }

    def add_sample(path: str, sample: dict[str, Any], bucket: str) -> dict[str, str]:
        data = _canonical_json(sample)
        payload_by_path[path] = data
        reference = {"path": path, "sha256": _sha256_bytes(data)}
        refs[bucket].append(reference)
        return reference

    for index, sample in enumerate(document["warmups"], start=1):
        add_sample(f"samples/warmup-{index:03d}-{sample['arm']}.json", sample, "warmups")
    calibration_pair_refs: list[dict[str, Any]] = []
    for pair in document["calibration"]:
        pair_index = pair["pair_index"]
        left = add_sample(
            f"samples/calibration-{pair_index:03d}-baseline-a.json",
            pair["baseline_a"],
            "calibration",
        )
        right = add_sample(
            f"samples/calibration-{pair_index:03d}-baseline-b.json",
            pair["baseline_b"],
            "calibration",
        )
        calibration_pair_refs.append({"pair_index": pair_index, "baseline_a": left, "baseline_b": right})
    comparison_pair_refs: list[dict[str, Any]] = []
    for pair in document["comparison"]:
        pair_index = pair["pair_index"]
        baseline = add_sample(
            f"samples/comparison-{pair_index:03d}-baseline.json",
            pair["baseline"],
            "baseline",
        )
        candidate = add_sample(
            f"samples/comparison-{pair_index:03d}-candidate.json",
            pair["candidate"],
            "candidate",
        )
        comparison_pair_refs.append(
            {"pair_index": pair_index, "baseline": baseline, "candidate": candidate}
        )
    payload_by_path["baseline.json"] = _canonical_json(
        {
            "schema_version": INDEX_VERSION,
            "arm": "baseline",
            "profile": {
                "path": profile_paths["baseline"],
                "sha256": identity["baseline_profile_sha256"],
            },
            "source_state": identity["baseline_source_state"],
            "tool_commit": identity["baseline_tool_commit"],
            "dirty_diff_sha256": identity["baseline_dirty_diff_sha256"],
            "command": identity["baseline_command"],
            "command_sha256": identity["baseline_command_sha256"],
            "correctness": {
                "path": correctness_paths["baseline"],
                "sha256": document["correctness"]["baseline_sha256"],
                "derived": evaluation["correctness"]["baseline"],
            },
            "warmup": refs["warmups"][1],
            "samples": refs["baseline"],
        }
    )
    payload_by_path["candidate.json"] = _canonical_json(
        {
            "schema_version": INDEX_VERSION,
            "arm": "candidate",
            "profile": {
                "path": profile_paths["candidate"],
                "sha256": identity["candidate_profile_sha256"],
            },
            "source_state": identity["candidate_source_state"],
            "tool_commit": identity["candidate_tool_commit"],
            "dirty_diff_sha256": identity["candidate_dirty_diff_sha256"],
            "command": identity["candidate_command"],
            "command_sha256": identity["candidate_command_sha256"],
            "correctness": {
                "path": correctness_paths["candidate"],
                "sha256": document["correctness"]["candidate_sha256"],
                "derived": evaluation["correctness"]["candidate"],
            },
            "warmup": refs["warmups"][2],
            "samples": refs["candidate"],
        }
    )
    payload_by_path["calibration.json"] = _canonical_json(
        {
            "schema_version": INDEX_VERSION,
            "arm": "baseline-a-a",
            "profile_sha256": identity["baseline_profile_sha256"],
            "warmup": refs["warmups"][0],
            "pairs": calibration_pair_refs,
        }
    )
    payload_by_path["pairs.json"] = _canonical_json(
        {"schema_version": INDEX_VERSION, "pairs": comparison_pair_refs}
    )
    payload_by_path["evaluation.json"] = _canonical_json(evaluation)

    preferred = [
        "manifest.json",
        profile_paths["baseline"],
        profile_paths["candidate"],
        correctness_paths["baseline"],
        correctness_paths["candidate"],
        corpus_path,
        "profiles/evaluator-source.py",
    ]
    remainder = sorted(path for path in payload_by_path if path not in preferred)
    return [(path, payload_by_path[path]) for path in preferred + remainder]


class SelftestFailure(AssertionError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SelftestFailure(message)


def _metric(value: Any, unit: str, *, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    result = {"value": value, "unit": unit, "reason": reason}
    result.update(extra)
    return result


def _peak_metric(value: int | None, sample_id: str, *, reason: str | None = None) -> dict[str, Any]:
    raw_observation = None
    if value is not None:
        raw_observation = {
            "schema_version": "cgroup-v2-memory-peak-v1",
            "sample_id": sample_id,
            "cgroup_path": f"/sys/fs/cgroup/fnd05/{sample_id}",
            "memory_peak_raw_text": f"{value}\n",
        }
    return _metric(
        value,
        "bytes",
        reason=reason,
        scope="process_tree_peak",
        collector="cgroup-v2-memory.peak",
        collector_implementation_sha256=_sha256_bytes(
            SELFTEST_MEMORY_COLLECTOR_RAW.encode("utf-8")
        ),
        collector_config_sha256=_sha256_bytes(_canonical_json(MEMORY_COLLECTOR_CONFIG)),
        raw_observation=raw_observation,
    )


def _set_peak_metric_value(metric: dict[str, Any], value: int) -> None:
    metric["value"] = value
    raw = metric.get("raw_observation")
    if not isinstance(raw, dict):
        raise SelftestFailure("synthetic peak RSS metric has no raw observation")
    raw["memory_peak_raw_text"] = f"{value}\n"


def _pending(reason: str) -> dict[str, Any]:
    return {
        "status": "pending",
        "reason": reason,
        "evidence_sha256": None,
        "raw_json": None,
    }


def _sample(
    *,
    phase: str,
    arm: str,
    pair_index: int,
    order_index: int,
    profile_sha256: str,
    tool_commit: str,
    dirty_diff_sha256: str | None,
    command_sha256: str,
    corpus_sha256: str,
    corpus_index_sha256: str,
    calls: int = 600,
    inputs: int = 600,
    wall: float = 61.2,
    rss: int = 1_000_000,
    latency_scale: float = 1.0,
) -> dict[str, Any]:
    sample_id = f"{phase}-{pair_index:02d}-{arm}"
    latency_bases = (0.010, 0.012, 0.014, 0.016, 0.020)
    if inputs <= 0 or inputs % len(latency_bases) != 0:
        raise SelftestFailure("synthetic input_count must be a positive multiple of corpus size")
    complete_passes = inputs // len(latency_bases)
    latency_probe_indexes = [0, 1, 2]
    rotation = 0 if pair_index == 0 else (pair_index - 1) % len(latency_probe_indexes)
    latency_probe_indexes = latency_probe_indexes[rotation:] + latency_probe_indexes[:rotation]
    latency_rows: list[dict[str, Any]] = []
    for probe_order_index, input_index in enumerate(latency_probe_indexes, start=1):
        normalized = latency_scale * latency_bases[input_index]
        batch_iterations = 10
        target_calls = batch_iterations
        latency_rows.append(
            {
                "path": f"input-{input_index}.onnx",
                "sha256": f"{input_index + 1:x}" * 64,
                "probe_order_index": probe_order_index,
                "batch_iterations": batch_iterations,
                "target_api_calls": target_calls,
                "expected_exit_code": 0,
                "observed_exit_code": 0,
                "outcome_class": "accepted",
                "residual_processes": 0,
                "process_elapsed_seconds": normalized * target_calls,
                "normalized_seconds_per_call": normalized,
            }
        )
    return {
        "sample_id": sample_id,
        "phase": phase,
        "arm": arm,
        "pair_index": pair_index,
        "order_index": order_index,
        "profile_sha256": profile_sha256,
        "tool_commit": tool_commit,
        "dirty_diff_sha256": dirty_diff_sha256,
        "command_sha256": command_sha256,
        "corpus_sha256": corpus_sha256,
        "corpus_index_sha256": corpus_index_sha256,
        "measurement_context_sha256": "",
        "throughput_workload": {
            "scope": "workload_only",
            "input_order": "corpus_index_rounds",
            "complete_corpus_passes": complete_passes,
        },
        "preparation_time": _metric(7.0, "seconds"),
        "wall_time": _metric(wall, "seconds"),
        "input_count": _metric(inputs, "inputs"),
        "target_api_calls": _metric(calls, "calls"),
        "peak_rss": _peak_metric(rss, sample_id),
        "cpu_time": _metric(50.0, "seconds"),
        "output_bytes": _metric(100, "bytes"),
        "exit_code": _metric(0, "exit_code"),
        "residual_processes": _metric(0, "processes"),
        "per_input_latency": _metric(
            latency_rows,
            "seconds",
            scope="fixed_corpus_latency_probe",
            order="pair_index_rotation",
        ),
    }


def _valid_document() -> dict[str, Any]:
    source_artifacts = [
        {
            "url": "https://github.com/microsoft/onnxruntime/archive/refs/tags/v1.20.1.tar.gz",
            "tag": "v1.20.1",
            "resolved_commit": "6" * 40,
            "sha256": "6" * 64,
            "size_bytes": 123456,
        }
    ]
    toolchain_pin = {
        "compiler": {"version": "clang-17", "path": "/opt/llvm/bin/clang++", "sha256": "a" * 64},
        "linker": {"version": "lld-17", "path": "/opt/llvm/bin/ld.lld", "sha256": "b" * 64},
        "engine": {"version": "libFuzzer-17", "path": "/opt/llvm/bin/clang++", "sha256": "a" * 64},
        "python": None,
        "rust": None,
        "environment": {"PATH": "/opt/llvm/bin:/usr/bin"},
    }
    patches: list[dict[str, Any]] = []
    patch_set_sha = _sha256_bytes(_canonical_json(patches))
    parser_pin = {
        "loader_id": "onnxruntime",
        "loader_version": "v1.20.1",
        "source_artifacts": source_artifacts,
    }
    baseline_profile = {
        "schema_version": "1",
        "target_id": "onnx",
        "format_revision": "onnx-opset-current",
        "loader_id": parser_pin["loader_id"],
        "loader_version": parser_pin["loader_version"],
        "source_artifacts": source_artifacts,
        "patches": patches,
        "toolchain": toolchain_pin,
        "sanitizer_policy": {
            "compile_flags": ["-fsanitize=address,undefined"],
            "recovery": "abort",
            "runtime_env": {"ASAN_OPTIONS": "abort_on_error=1"},
            "rust_panic": "abort",
        },
        "binaries": [
            {
                "role": "replay",
                "path": "/opt/onnx/replay",
                "sha256": "1" * 64,
                "argv": ["{input}"],
                "linked_libraries": [],
            }
        ],
        "input_kind": {"kind": "single", "extensions": ["onnx"], "subformats": []},
        "depth": "session",
        "engine_capabilities": [
            {
                "backend": "local-harness",
                "binary_role": "replay",
                "required_mode": "one-shot",
                "instrumentation_scope": "loader",
            },
            {
                "backend": "libfuzzer",
                "binary_role": "replay",
                "required_mode": "persistent-corpus",
                "instrumentation_scope": "loader",
            }
        ],
        "limits": {
            "max_input_bytes": 16_777_216,
            "memory_bytes": 536_870_912,
            "input_timeout_ms": 1000,
            "block_timeout_ms": 3000,
            "threads": 1,
            "workers": 1,
        },
        "coverage_scope": {
            "unit": "line",
            "include_sources": ["onnxruntime/core"],
            "exclude_sources": [],
        },
    }
    candidate_profile = copy.deepcopy(baseline_profile)
    candidate_profile["binaries"][0]["sha256"] = "2" * 64
    baseline_profile_raw = json.dumps(baseline_profile, indent=2, sort_keys=True) + "\n"
    candidate_profile_raw = json.dumps(candidate_profile, indent=2, sort_keys=True) + "\n"
    baseline_profile_sha = _sha256_bytes(baseline_profile_raw.encode("utf-8"))
    candidate_profile_sha = _sha256_bytes(candidate_profile_raw.encode("utf-8"))
    baseline_profile_canonical_sha = _canonical_profile_sha256(baseline_profile)
    candidate_profile_canonical_sha = _canonical_profile_sha256(candidate_profile)
    baseline_commit = "a" * 40
    candidate_commit = "b" * 40
    baseline_command_record = {
        "argv": ["/opt/onnx/replay", "--corpus", "corpus/index.json", "-runs=0"],
        "allowed_env": {
            "ASAN_OPTIONS": "abort_on_error=1",
            "PATH": "/opt/llvm/bin:/usr/bin",
        },
        "cwd": "/home/fuzz/bugbounty",
        "executable_sha256": "1" * 64,
    }
    candidate_command_record = {
        "argv": ["/opt/onnx/replay", "--corpus", "corpus/index.json", "-runs=0"],
        "allowed_env": {
            "ASAN_OPTIONS": "abort_on_error=1",
            "PATH": "/opt/llvm/bin:/usr/bin",
        },
        "cwd": "/home/fuzz/bugbounty",
        "executable_sha256": "2" * 64,
    }
    baseline_command = _sha256_bytes(_canonical_json(baseline_command_record))
    candidate_command = _sha256_bytes(_canonical_json(candidate_command_record))
    corpus_sha = "5" * 64
    corpus_index = {
        "schema_version": "format-performance-corpus-v1",
        "inputs": [
            {
                "path": f"input-{index}.onnx",
                "sha256": f"{index + 1:x}" * 64,
                "expected_outcome": "accepted" if index < 3 else "rejected",
                "expected_exit_code": 0 if index < 3 else 9,
                "target_api_stage": "target-parser",
                "minimum_target_api_calls": 1,
                "required_api_events": ["OrtCreateSession"],
                "zero_call_reason": None,
                "throughput_order_index": index + 1,
                "throughput_exclusion_reason": None,
                "latency_probe_order_index": index + 1 if index < 3 else None,
                "latency_exclusion_reason": (
                    None if index < 3 else "rejected input is correctness-only"
                ),
            }
            for index in range(5)
        ],
    }
    corpus_index_raw = json.dumps(corpus_index, indent=2, sort_keys=True) + "\n"
    corpus_index_sha = _sha256_bytes(corpus_index_raw.encode("utf-8"))
    allowed_tool_diff = (
        "--- a/harnesses/onnx/loader.cpp\n"
        "+++ b/harnesses/onnx/loader.cpp\n"
        "@@ -1 +1 @@\n-baseline loader\n+candidate loader\n"
    )
    candidate_dirty_sha = _sha256_bytes(allowed_tool_diff.encode("utf-8"))

    def correctness_snapshot(
        arm: str,
        profile_sha256: str,
        tool_commit: str,
        dirty_diff_sha256: str | None,
        command_sha256: str,
    ) -> str:
        records = []
        for index, corpus_row in enumerate(corpus_index["inputs"]):
            accepted = index < 3
            records.append(
                {
                    "path": corpus_row["path"],
                    "sha256": corpus_row["sha256"],
                    "outcome_class": "accepted" if accepted else "rejected",
                    "outcome_detail": "session-created" if accepted else "invalid-model-rejected",
                    "target_api_calls": 1,
                    "api_events": ["OrtCreateSession"],
                    "exit_code": 0 if accepted else 9,
                    "residual_processes": 0,
                }
            )
        snapshot = {
            "schema_version": "format-correctness-replay-v1",
            "arm": arm,
            "profile_sha256": profile_sha256,
            "tool_commit": tool_commit,
            "dirty_diff_sha256": dirty_diff_sha256,
            "command_sha256": command_sha256,
            "corpus_sha256": corpus_sha,
            "corpus_index_sha256": corpus_index_sha,
            "conditions_sha256": "",
            "records": records,
        }
        return json.dumps(snapshot, indent=2, sort_keys=True) + "\n"

    baseline_correctness_raw = correctness_snapshot(
        "baseline", baseline_profile_sha, baseline_commit, None, baseline_command
    )
    candidate_correctness_raw = correctness_snapshot(
        "candidate", candidate_profile_sha, candidate_commit, candidate_dirty_sha, candidate_command
    )

    calibration: list[dict[str, Any]] = []
    comparison: list[dict[str, Any]] = []
    aa_throughput_ratios = (1.0, 1.01, 0.99, 1.005, 0.995)
    aa_rss = (1_000_000, 1_005_000, 995_000, 1_003_000, 997_000)
    aa_latency = (1.0, 1.005, 0.995, 1.003, 0.997)
    for offset in range(5):
        pair_index = offset + 1
        calibration.append(
            {
                "pair_index": pair_index,
                "baseline_a": _sample(
                    phase="calibration",
                    arm="baseline_a",
                    pair_index=pair_index,
                    order_index=2 * offset + 1,
                    profile_sha256=baseline_profile_sha,
                    tool_commit=baseline_commit,
                    dirty_diff_sha256=None,
                    command_sha256=baseline_command,
                    corpus_sha256=corpus_sha,
                    corpus_index_sha256=corpus_index_sha,
                ),
                "baseline_b": _sample(
                    phase="calibration",
                    arm="baseline_b",
                    pair_index=pair_index,
                    order_index=2 * offset + 2,
                    profile_sha256=baseline_profile_sha,
                    tool_commit=baseline_commit,
                    dirty_diff_sha256=None,
                    command_sha256=baseline_command,
                    corpus_sha256=corpus_sha,
                    corpus_index_sha256=corpus_index_sha,
                    wall=61.2 / aa_throughput_ratios[offset],
                    rss=aa_rss[offset],
                    latency_scale=aa_latency[offset],
                ),
            }
        )
        comparison.append(
            {
                "pair_index": pair_index,
                "baseline": _sample(
                    phase="comparison",
                    arm="baseline",
                    pair_index=pair_index,
                    order_index=2 * offset + 1,
                    profile_sha256=baseline_profile_sha,
                    tool_commit=baseline_commit,
                    dirty_diff_sha256=None,
                    command_sha256=baseline_command,
                    corpus_sha256=corpus_sha,
                    corpus_index_sha256=corpus_index_sha,
                ),
                "candidate": _sample(
                    phase="comparison",
                    arm="candidate",
                    pair_index=pair_index,
                    order_index=2 * offset + 2,
                    profile_sha256=candidate_profile_sha,
                    tool_commit=candidate_commit,
                    dirty_diff_sha256=candidate_dirty_sha,
                    command_sha256=candidate_command,
                    corpus_sha256=corpus_sha,
                    corpus_index_sha256=corpus_index_sha,
                    wall=60.0,
                    rss=990_000,
                    latency_scale=0.99,
                ),
            }
        )

    def warmup(
        arm: str,
        profile: str,
        commit: str,
        dirty_diff: str | None,
        command: str,
        index: int,
    ) -> dict[str, Any]:
        return _sample(
            phase="warmup",
            arm=arm,
            pair_index=0,
            order_index=index,
            profile_sha256=profile,
            tool_commit=commit,
            dirty_diff_sha256=dirty_diff,
            command_sha256=command,
            corpus_sha256=corpus_sha,
            corpus_index_sha256=corpus_index_sha,
            wall=1.0,
            calls=10,
            inputs=10,
        )

    document = {
        "schema_version": SCHEMA_VERSION,
        "mode": "selftest",
        "comparison_id": "fnd05-selftest",
        "identity": {
            "fixed": {
                "target_id": "onnx",
                "depth": "session",
                "parser_pin": copy.deepcopy(parser_pin),
                "toolchain_pin": copy.deepcopy(toolchain_pin),
                "target_patch_sha256": patch_set_sha,
                "engine_flags": ["-runs=0"],
                "corpus_sha256": corpus_sha,
                "corpus_index_raw_json": corpus_index_raw,
                "corpus_index_sha256": corpus_index_sha,
                "corpus_input_count": 5,
                "workers": 1,
                "threads": 1,
                "input_timeout_ms": 1000,
                "memory_limit_bytes": 536_870_912,
                "filesystem_path_type": "wsl-ext4",
                "log_level": "error",
                "cache_policy": "warm",
            },
            "baseline_profile": baseline_profile,
            "candidate_profile": candidate_profile,
            "baseline_profile_raw_json": baseline_profile_raw,
            "candidate_profile_raw_json": candidate_profile_raw,
            "baseline_profile_sha256": baseline_profile_sha,
            "candidate_profile_sha256": candidate_profile_sha,
            "baseline_profile_canonical_sha256": baseline_profile_canonical_sha,
            "candidate_profile_canonical_sha256": candidate_profile_canonical_sha,
            "allowed_profile_differences": ["/binaries/0/sha256"],
            "baseline_tool_commit": baseline_commit,
            "candidate_tool_commit": candidate_commit,
            "baseline_source_state": "clean",
            "candidate_source_state": "dirty",
            "baseline_dirty_diff_sha256": None,
            "baseline_dirty_diff_raw_text": None,
            "candidate_dirty_diff_raw_text": allowed_tool_diff,
            "candidate_dirty_diff_sha256": candidate_dirty_sha,
            "baseline_command": baseline_command_record,
            "candidate_command": candidate_command_record,
            "baseline_command_sha256": baseline_command,
            "candidate_command_sha256": candidate_command,
            "baseline_source_artifacts": {
                "harnesses/onnx/loader.cpp": "8" * 64,
                "src/common.rs": "a" * 64,
            },
            "candidate_source_artifacts": {
                "harnesses/onnx/loader.cpp": "9" * 64,
                "src/common.rs": "a" * 64,
            },
            "allowed_tool_changes": [
                {
                    "path": "harnesses/onnx/loader.cpp",
                    "baseline_sha256": "8" * 64,
                    "candidate_sha256": "9" * 64,
                    "diff_raw_text": allowed_tool_diff,
                    "diff_sha256": _sha256_bytes(allowed_tool_diff.encode("utf-8")),
                }
            ],
        },
        "environment": {
            "wsl_cpu_count": 12,
            "wsl_memory_bytes": 16_000_000_000,
            "wsl_swap_bytes": 4_000_000_000,
            "disk_free_bytes": 300_000_000_000,
            "concurrent_workload": "none",
            "cache_policy": "warm",
        },
        "protocol": {
            "preparation_excluded": True,
            "elapsed_scope": "workload_only",
            "minimum_sample_seconds": 60.0,
            "alternation": "baseline_then_candidate",
            "memory_scope": "process_tree_peak",
            "memory_collector": "cgroup-v2-memory.peak",
            "memory_collector_implementation_raw_text": SELFTEST_MEMORY_COLLECTOR_RAW,
            "memory_collector_implementation_sha256": _sha256_bytes(
                SELFTEST_MEMORY_COLLECTOR_RAW.encode("utf-8")
            ),
            "memory_collector_config": copy.deepcopy(MEMORY_COLLECTOR_CONFIG),
            "clock_resolution_seconds": 0.000001,
            "rss_resolution_bytes": 4096,
            "api_call_resolution_calls": 1,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
            "quantile_method": "nearest-rank",
            "latency_probe_order": "pair_index_rotation",
            "latency_batch_iterations": 10,
        },
        "correctness": {
            "baseline_raw_json": baseline_correctness_raw,
            "candidate_raw_json": candidate_correctness_raw,
            "baseline_sha256": _sha256_bytes(baseline_correctness_raw.encode("utf-8")),
            "candidate_sha256": _sha256_bytes(candidate_correctness_raw.encode("utf-8")),
        },
        "warmups": [
            warmup("calibration", baseline_profile_sha, baseline_commit, None, baseline_command, 1),
            warmup("baseline", baseline_profile_sha, baseline_commit, None, baseline_command, 2),
            warmup(
                "candidate",
                candidate_profile_sha,
                candidate_commit,
                candidate_dirty_sha,
                candidate_command,
                3,
            ),
        ],
        "calibration": calibration,
        "comparison": comparison,
        "absolute_budgets": {
            "peak_rss_bytes": 2_000_000,
            "latency_p95_seconds": 0.1,
        },
        "operations": {
            "actual_parser_performance": _pending("synthetic selftest; real parser measurement pending"),
            "engine_smoke": _pending("fuzz-PC execution pending"),
            "single_worker_soak": _pending("fuzz-PC six-hour execution pending"),
            "parallel_soak": _pending("fuzz-PC execution pending"),
            "fault_injection": _pending("fuzz-PC execution pending"),
        },
    }
    _refresh_measurement_context(document)
    return document


def _all_samples(document: dict[str, Any]) -> list[dict[str, Any]]:
    samples = list(document["warmups"])
    for pair in document["calibration"]:
        samples.extend((pair["baseline_a"], pair["baseline_b"]))
    for pair in document["comparison"]:
        samples.extend((pair["baseline"], pair["candidate"]))
    return samples


def _correctness_snapshot_object(document: dict[str, Any], arm: str) -> dict[str, Any]:
    value = _parse_json_text(
        document["correctness"][f"{arm}_raw_json"],
        f"correctness.{arm}_raw_json",
    )
    if not isinstance(value, dict):
        raise SelftestFailure(f"correctness {arm} fixture root is not an object")
    return value


def _store_correctness_snapshot(
    document: dict[str, Any], arm: str, snapshot: dict[str, Any]
) -> None:
    raw = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    document["correctness"][f"{arm}_raw_json"] = raw
    document["correctness"][f"{arm}_sha256"] = _sha256_bytes(raw.encode("utf-8"))


def _store_corpus_index(document: dict[str, Any], corpus_index: dict[str, Any]) -> None:
    raw = json.dumps(corpus_index, indent=2, sort_keys=True) + "\n"
    digest = _sha256_bytes(raw.encode("utf-8"))
    fixed = document["identity"]["fixed"]
    fixed["corpus_index_raw_json"] = raw
    fixed["corpus_index_sha256"] = digest
    for sample in _all_samples(document):
        sample["corpus_index_sha256"] = digest
    for arm in ("baseline", "candidate"):
        snapshot = _correctness_snapshot_object(document, arm)
        snapshot["corpus_index_sha256"] = digest
        _store_correctness_snapshot(document, arm, snapshot)


def _refresh_measurement_context(document: dict[str, Any]) -> None:
    conditions_sha256 = _measurement_conditions_sha256(
        document["mode"],
        document["identity"]["fixed"],
        document["environment"],
        document["protocol"],
        document["absolute_budgets"],
    )
    snapshot_hashes: dict[str, str] = {}
    for arm in ("baseline", "candidate"):
        snapshot = _correctness_snapshot_object(document, arm)
        snapshot["conditions_sha256"] = conditions_sha256
        _store_correctness_snapshot(document, arm, snapshot)
        snapshot_hashes[arm] = document["correctness"][f"{arm}_sha256"]
    calibration_context_sha256 = _measurement_context_sha256(conditions_sha256, snapshot_hashes)
    for sample in document["warmups"]:
        sample["measurement_context_sha256"] = calibration_context_sha256
    for pair in document["calibration"]:
        pair["baseline_a"]["measurement_context_sha256"] = calibration_context_sha256
        pair["baseline_b"]["measurement_context_sha256"] = calibration_context_sha256
    calibration_raw_sha256 = _sha256_bytes(_canonical_json(document["calibration"]))
    comparison_context_sha256 = _comparison_measurement_context_sha256(
        calibration_context_sha256,
        calibration_raw_sha256,
    )
    for pair in document["comparison"]:
        pair["baseline"]["measurement_context_sha256"] = comparison_context_sha256
        pair["candidate"]["measurement_context_sha256"] = comparison_context_sha256


def _refresh_profile_snapshot(document: dict[str, Any], arm: str) -> None:
    identity = document["identity"]
    profile = identity[f"{arm}_profile"]
    raw = json.dumps(profile, indent=2, sort_keys=True) + "\n"
    identity[f"{arm}_profile_raw_json"] = raw
    raw_sha = _sha256_bytes(raw.encode("utf-8"))
    identity[f"{arm}_profile_sha256"] = raw_sha
    identity[f"{arm}_profile_canonical_sha256"] = _canonical_profile_sha256(profile)
    if arm == "baseline":
        for sample in document["warmups"][:2]:
            sample["profile_sha256"] = raw_sha
        for pair in document["calibration"]:
            pair["baseline_a"]["profile_sha256"] = raw_sha
            pair["baseline_b"]["profile_sha256"] = raw_sha
        for pair in document["comparison"]:
            pair["baseline"]["profile_sha256"] = raw_sha
    else:
        document["warmups"][2]["profile_sha256"] = raw_sha
        for pair in document["comparison"]:
            pair["candidate"]["profile_sha256"] = raw_sha
    if "correctness" in document:
        snapshot = _correctness_snapshot_object(document, arm)
        snapshot["profile_sha256"] = raw_sha
        _store_correctness_snapshot(document, arm, snapshot)


def _refresh_command_snapshot(document: dict[str, Any], arm: str) -> None:
    identity = document["identity"]
    command_sha = _sha256_bytes(_canonical_json(identity[f"{arm}_command"]))
    identity[f"{arm}_command_sha256"] = command_sha
    if arm == "baseline":
        samples = list(document["warmups"][:2])
        for pair in document["calibration"]:
            samples.extend((pair["baseline_a"], pair["baseline_b"]))
        samples.extend(pair["baseline"] for pair in document["comparison"])
    else:
        samples = [document["warmups"][2]]
        samples.extend(pair["candidate"] for pair in document["comparison"])
    for sample in samples:
        sample["command_sha256"] = command_sha
    if "correctness" in document:
        snapshot = _correctness_snapshot_object(document, arm)
        snapshot["command_sha256"] = command_sha
        _store_correctness_snapshot(document, arm, snapshot)


def _expect_contract_error(document: dict[str, Any], needle: str) -> None:
    try:
        evaluate_document(document)
    except ContractError as error:
        _require(needle in str(error), f"wrong contract error: {error}")
    else:
        raise SelftestFailure(f"expected ContractError containing {needle!r}")


class BaselineSelftest:
    def zero_input_does_not_pass(self) -> None:
        document = _valid_document()
        snapshot = _correctness_snapshot_object(document, "candidate")
        snapshot["records"] = []
        _store_correctness_snapshot(document, "candidate", snapshot)
        _refresh_measurement_context(document)
        _expect_contract_error(document, "exactly cover")

    def zero_api_calls_does_not_pass(self) -> None:
        document = _valid_document()
        snapshot = _correctness_snapshot_object(document, "candidate")
        for record in snapshot["records"]:
            record["target_api_calls"] = 0
            record["api_events"] = []
        _store_correctness_snapshot(document, "candidate", snapshot)
        _refresh_measurement_context(document)
        _expect_contract_error(document, "correctness replay")

    def unit_mismatch_is_rejected(self) -> None:
        document = _valid_document()
        document["comparison"][0]["candidate"]["wall_time"]["unit"] = "milliseconds"
        _expect_contract_error(document, "unit")

    def unallowed_profile_difference_is_rejected(self) -> None:
        document = _valid_document()
        identity = document["identity"]
        identity["candidate_profile"]["binaries"][0]["path"] = "/opt/onnx/unallowed-replay"
        raw = json.dumps(identity["candidate_profile"], indent=2, sort_keys=True) + "\n"
        identity["candidate_profile_raw_json"] = raw
        identity["candidate_profile_sha256"] = _sha256_bytes(raw.encode("utf-8"))
        identity["candidate_profile_canonical_sha256"] = _canonical_profile_sha256(identity["candidate_profile"])
        for pair in document["comparison"]:
            pair["candidate"]["profile_sha256"] = identity["candidate_profile_sha256"]
        document["warmups"][2]["profile_sha256"] = identity["candidate_profile_sha256"]
        _expect_contract_error(document, "profile difference")

    def actual_target_profile_shape_is_accepted(self) -> None:
        document = _valid_document()
        result = evaluate_document(document)
        _require(document["identity"]["baseline_profile"]["target_id"] == "onnx", "fixture is not current ONNX")
        _require(result["status"] == "pass", f"valid TargetProfile-shaped fixture status={result['status']}")

    def target_profile_serde_defaults_are_accepted(self) -> None:
        document = _valid_document()
        document["identity"]["fixed"]["toolchain_pin"]["environment"] = {}
        for arm in ("baseline", "candidate"):
            profile = document["identity"][f"{arm}_profile"]
            for key in ("python", "rust", "environment"):
                profile["toolchain"].pop(key)
            profile["binaries"][0].pop("linked_libraries")
            profile["input_kind"].pop("subformats")
            profile["coverage_scope"].pop("exclude_sources")
            _refresh_profile_snapshot(document, arm)
        _refresh_measurement_context(document)
        result = evaluate_document(document)
        _require(result["status"] == "pass", f"serde defaults status={result['status']}")

    def target_specific_depth_is_enforced(self) -> None:
        document = _valid_document()
        document["identity"]["candidate_profile"]["depth"] = "bogus"
        _refresh_profile_snapshot(document, "candidate")
        _expect_contract_error(document, "unsupported for target")

    def uppercase_profile_hash_is_accepted(self) -> None:
        _require(_sha256("A" * 64, "uppercase fixture") == "a" * 64, "uppercase SHA was not normalized")

    def duplicate_profile_argv_and_flags_are_accepted(self) -> None:
        profile = copy.deepcopy(_valid_document()["identity"]["baseline_profile"])
        profile["sanitizer_policy"]["compile_flags"].append(
            profile["sanitizer_policy"]["compile_flags"][0]
        )
        profile["binaries"][0]["argv"].append("--same-flag")
        profile["binaries"][0]["argv"].append("--same-flag")
        _validate_target_profile_shape(profile, "duplicate-compatible-profile")

    def profile_id_matches_rust_contract(self) -> None:
        _require(_profile_id("_profile", "profile id") == "_profile", "leading underscore rejected")

    def nested_profile_unknown_field_is_rejected(self) -> None:
        document = _valid_document()
        document["identity"]["candidate_profile"]["binaries"][0]["unknown_binary_field"] = True
        _refresh_profile_snapshot(document, "candidate")
        _expect_contract_error(document, "unknown=unknown_binary_field")

    def profile_raw_bytes_identity_is_enforced(self) -> None:
        document = _valid_document()
        document["identity"]["candidate_profile_raw_json"] += " "
        _expect_contract_error(document, "raw profile bytes")

    def partial_sample_is_rejected(self) -> None:
        document = _valid_document()
        del document["comparison"][2]["candidate"]["cpu_time"]
        _expect_contract_error(document, "cpu_time")

    def missing_value_requires_reason(self) -> None:
        document = _valid_document()
        document["comparison"][0]["candidate"]["output_bytes"] = _metric(None, "bytes")
        _expect_contract_error(document, "reason")

    def missing_latency_input_is_rejected(self) -> None:
        document = _valid_document()
        document["comparison"][0]["candidate"]["per_input_latency"]["value"].pop()
        _expect_contract_error(document, "exactly one row")

    def duplicate_latency_input_is_rejected(self) -> None:
        document = _valid_document()
        rows = document["comparison"][0]["candidate"]["per_input_latency"]["value"]
        rows[1] = copy.deepcopy(rows[0])
        _expect_contract_error(document, "corpus index path/hash order")

    def scalar_latency_rows_are_rejected(self) -> None:
        document = _valid_document()
        document["comparison"][0]["candidate"]["per_input_latency"]["value"] = [
            {
                "path": f"input-{index}.onnx",
                "sha256": f"{index + 1:x}" * 64,
                "seconds": 0.01,
            }
            for index in range(5)
        ]
        _expect_contract_error(document, "exactly one row")

    def latency_summary_tampering_is_rejected(self) -> None:
        document = _valid_document()
        row = document["comparison"][0]["candidate"]["per_input_latency"]["value"][0]
        row["normalized_seconds_per_call"] *= 2
        _expect_contract_error(document, "does not match elapsed/target_api_calls")

    def latency_workload_order_is_enforced(self) -> None:
        document = _valid_document()
        row = document["comparison"][0]["candidate"]["per_input_latency"]["value"][0]
        row["probe_order_index"] = 2
        _expect_contract_error(document, "probe_order_index")

    def latency_pair_rotation_is_fixed(self) -> None:
        document = _valid_document()
        pair = document["comparison"][1]
        baseline_paths = [row["path"] for row in pair["baseline"]["per_input_latency"]["value"]]
        candidate_paths = [row["path"] for row in pair["candidate"]["per_input_latency"]["value"]]
        _require(
            baseline_paths == ["input-1.onnx", "input-2.onnx", "input-0.onnx"],
            f"unexpected deterministic rotation: {baseline_paths}",
        )
        _require(candidate_paths == baseline_paths, "pair arms use different latency order")
        _require(evaluate_document(document)["status"] == "pass", "rotated latency fixture failed")

    def latency_arm_order_mismatch_is_rejected(self) -> None:
        document = _valid_document()
        rows = document["comparison"][1]["candidate"]["per_input_latency"]["value"]
        rows[0], rows[1] = rows[1], rows[0]
        for index, row in enumerate(rows, start=1):
            row["probe_order_index"] = index
        _expect_contract_error(document, "corpus index path/hash order")

    def latency_zero_denominator_is_rejected(self) -> None:
        document = _valid_document()
        row = document["comparison"][0]["candidate"]["per_input_latency"]["value"][0]
        row["target_api_calls"] = 0
        _expect_contract_error(document, "must be >= 1")

    def latency_failed_probe_is_rejected(self) -> None:
        document = _valid_document()
        row = document["comparison"][0]["candidate"]["per_input_latency"]["value"][0]
        row["observed_exit_code"] = 1
        _expect_contract_error(document, "expected probe result")

    def latency_subset_cannot_be_changed_by_an_arm(self) -> None:
        document = _valid_document()
        document["comparison"][0]["candidate"]["per_input_latency"]["value"].pop()
        _expect_contract_error(document, "exactly one row")

    def posthoc_budget_change_is_rejected(self) -> None:
        document = _valid_document()
        document["absolute_budgets"]["peak_rss_bytes"] = 999_999_999
        _expect_contract_error(document, "conditions_sha256")

    def posthoc_calibration_change_is_rejected(self) -> None:
        document = _valid_document()
        document["calibration"][0]["baseline_b"]["wall_time"]["value"] += 1.0
        _expect_contract_error(document, "calibration")

    def mode_relabel_is_rejected(self) -> None:
        document = _valid_document()
        document["mode"] = "real"
        _expect_contract_error(document, "conditions_sha256")

    def zero_real_resource_values_are_rejected(self) -> None:
        document = _valid_document()
        document["environment"]["wsl_memory_bytes"] = 0
        _expect_contract_error(document, "wsl_memory_bytes")

    def huge_numeric_budget_is_rejected(self) -> None:
        document = _valid_document()
        document["absolute_budgets"]["peak_rss_bytes"] = 10**400
        _expect_contract_error(document, "finite")

    def unbounded_sample_counts_are_rejected(self) -> None:
        document = _valid_document()
        sample = document["comparison"][0]["candidate"]
        sample["throughput_workload"]["complete_corpus_passes"] = 10**400
        sample["input_count"]["value"] = 5 * 10**400
        sample["target_api_calls"]["value"] = 5 * 10**400
        _expect_contract_error(document, "64-bit")

    def api_call_resolution_is_exactly_one(self) -> None:
        document = _valid_document()
        document["protocol"]["api_call_resolution_calls"] = 599
        for pair in document["comparison"]:
            pair["candidate"]["wall_time"]["value"] = 6120.0
        _refresh_measurement_context(document)
        _expect_contract_error(document, "exactly 1")

    def workload_flag_difference_is_rejected(self) -> None:
        document = _valid_document()
        document["identity"]["candidate_command"]["argv"].append("-candidate-only")
        _refresh_command_snapshot(document, "candidate")
        _expect_contract_error(document, "workload argv differ")

    def workload_environment_difference_is_rejected(self) -> None:
        document = _valid_document()
        document["identity"]["candidate_command"]["allowed_env"]["HOME"] = "/home/fuzz"
        _refresh_command_snapshot(document, "candidate")
        _expect_contract_error(document, "allowed_env differ")

    def workload_cwd_difference_is_rejected(self) -> None:
        document = _valid_document()
        document["identity"]["candidate_command"]["cwd"] = "/home/fuzz/other-checkout"
        _refresh_command_snapshot(document, "candidate")
        _expect_contract_error(document, "cwd differ")

    def windows_mount_contradicts_wsl_ext4(self) -> None:
        document = _valid_document()
        for arm in ("baseline", "candidate"):
            document["identity"][f"{arm}_command"]["cwd"] = "/mnt/c/bugbounty"
            _refresh_command_snapshot(document, arm)
        _expect_contract_error(document, "contradicts fixed wsl-ext4")

    def loader_injection_environment_is_rejected(self) -> None:
        document = _valid_document()
        for arm in ("baseline", "candidate"):
            document["identity"][f"{arm}_command"]["allowed_env"]["LD_PRELOAD"] = "/tmp/evil.so"
            _refresh_command_snapshot(document, arm)
        _expect_contract_error(document, "disallowed key")

    def pinned_profile_environment_is_required(self) -> None:
        document = _valid_document()
        for arm in ("baseline", "candidate"):
            document["identity"][f"{arm}_command"]["allowed_env"].pop("ASAN_OPTIONS")
            _refresh_command_snapshot(document, arm)
        _expect_contract_error(document, "exact pinned profile environment")

    def conflicting_profile_environment_is_rejected(self) -> None:
        document = _valid_document()
        profile = _normalize_target_profile_defaults(
            copy.deepcopy(document["identity"]["baseline_profile"])
        )
        profile["sanitizer_policy"]["runtime_env"]["PATH"] = "/different"
        try:
            _validate_command_environment(
                document["identity"]["baseline_command"], profile, "conflict fixture"
            )
        except ContractError as error:
            _require("conflicts" in str(error), f"wrong conflict error: {error}")
        else:
            raise SelftestFailure("conflicting pinned profile environments were accepted")

    def unverified_operation_pass_is_rejected(self) -> None:
        document = _valid_document()
        for row in document["operations"].values():
            row.update({"status": "pass", "reason": None, "evidence_sha256": "1" * 64})
        _expect_contract_error(document, "raw V7 evidence")

    def preparation_is_excluded_from_throughput(self) -> None:
        document = _valid_document()
        for pair in document["comparison"]:
            pair["candidate"]["preparation_time"]["value"] = 60_000.0
        result = evaluate_document(document)
        ratios = result["metrics"]["throughput"]["paired_ratios"]
        _require(all(abs(item - 1.02) < 1e-12 for item in ratios), f"wrong throughput ratios: {ratios}")

    def input_count_is_not_throughput_denominator(self) -> None:
        document = _valid_document()
        values = _sample_values(document["comparison"][0]["candidate"])
        values["per_input_latency"] = None
        expected = _derived_metrics(values)["throughput"]
        values["input_count"] = 60_000_000
        observed = _derived_metrics(values)["throughput"]
        _require(observed == expected, f"input count changed throughput: {expected} -> {observed}")

    def target_call_inflation_is_rejected(self) -> None:
        document = _valid_document()
        document["comparison"][0]["candidate"]["target_api_calls"]["value"] += 1
        _expect_contract_error(document, "derived from complete corpus passes")

    def throughput_cycle_ledger_is_compact(self) -> None:
        document = _valid_document()
        sample = document["comparison"][0]["candidate"]
        sample["throughput_workload"]["complete_corpus_passes"] = 2_000_000
        sample["input_count"]["value"] = 10_000_000
        sample["target_api_calls"]["value"] = 10_000_000
        _require(
            len(_canonical_json(document)) < 2_000_000,
            "compact throughput ledger expanded into per-call evidence",
        )
        result = evaluate_document(document)
        _require(result["status"] == "pass", f"compact throughput fixture status={result['status']}")

    def throughput_cycle_ledger_mismatch_is_rejected(self) -> None:
        document = _valid_document()
        document["comparison"][0]["candidate"]["throughput_workload"][
            "complete_corpus_passes"
        ] += 1
        _expect_contract_error(document, "derived from complete corpus passes")

    def pair_gap_is_rejected(self) -> None:
        document = _valid_document()
        document["comparison"][2]["pair_index"] = 7
        document["comparison"][2]["baseline"]["pair_index"] = 7
        document["comparison"][2]["candidate"]["pair_index"] = 7
        _expect_contract_error(document, "pair_index")

    def alternation_is_rejected(self) -> None:
        document = _valid_document()
        document["comparison"][0]["candidate"]["order_index"] = 1
        _expect_contract_error(document, "order_index")

    def too_few_pairs_is_rejected(self) -> None:
        document = _valid_document()
        document["comparison"] = document["comparison"][:4]
        _expect_contract_error(document, "5")

    def short_real_sample_is_rejected(self) -> None:
        document = _valid_document()
        document["mode"] = "real"
        _refresh_measurement_context(document)
        document["comparison"][0]["candidate"]["wall_time"]["value"] = 59.999
        _expect_contract_error(document, "60")

    def forged_tree_rss_collector_is_rejected(self) -> None:
        document = _valid_document()
        document["comparison"][0]["candidate"]["peak_rss"]["collector"] = "/usr/bin/time-child-max"
        _expect_contract_error(document, "collector")

    def memory_collector_alias_is_rejected(self) -> None:
        document = _valid_document()
        document["protocol"]["memory_collector"] = "GNU time maxrss"
        for sample in _all_samples(document):
            sample["peak_rss"]["collector"] = "GNU time maxrss"
        _refresh_measurement_context(document)
        _expect_contract_error(document, "supported process-tree collector")

    def memory_collector_provenance_is_bound(self) -> None:
        document = _valid_document()
        peak = document["comparison"][0]["candidate"]["peak_rss"]
        peak["raw_observation"]["memory_peak_raw_text"] = "1\n"
        _expect_contract_error(document, "raw_observation")

    def memory_collector_config_types_are_strict(self) -> None:
        document = _valid_document()
        document["protocol"]["memory_collector_config"]["cgroup_version"] = True
        rebound = _sha256_bytes(_canonical_json(document["protocol"]["memory_collector_config"]))
        for sample in _all_samples(document):
            sample["peak_rss"]["collector_config_sha256"] = rebound
        _refresh_measurement_context(document)
        _expect_contract_error(document, "private cgroup-v2 leaf")

    def memory_cgroup_leaf_is_unique_per_sample(self) -> None:
        document = _valid_document()
        for sample in _all_samples(document):
            sample["peak_rss"]["raw_observation"]["cgroup_path"] = (
                "/sys/fs/cgroup/fnd05/reused-leaf"
            )
        _refresh_measurement_context(document)
        _expect_contract_error(document, "unique sample_id")

    def deltas_are_metric_specific(self) -> None:
        result = evaluate_document(_valid_document())
        calibration = result["calibration"]
        _require(set(calibration) == {"throughput", "peak_rss", "latency_p95"}, f"wrong metrics: {calibration}")
        _require(all(0.0 <= item["delta"] < 1.0 for item in calibration.values()), f"bad deltas: {calibration}")
        _require(calibration["throughput"]["resolution"] != calibration["peak_rss"]["resolution"], "shared resolution")

    def delta_one_blocks_evaluation(self) -> None:
        document = _valid_document()
        document["calibration"][4]["baseline_b"]["wall_time"]["value"] = 1.0
        _refresh_measurement_context(document)
        result = evaluate_document(document)
        _require(result["status"] == "inconclusive", f"delta >= 1 status={result['status']}")
        _require(result["next_stage_blocked"], "calibration failure did not block")

    def pass_direction_is_correct(self) -> None:
        result = evaluate_document(_valid_document())
        _require(result["status"] == "pass", f"stable candidate did not pass: {result['status']}")
        _require(result["metrics"]["throughput"]["status"] == "pass", "throughput direction reversed")
        _require(result["metrics"]["peak_rss"]["status"] == "pass", "RSS direction reversed")

    def real_pending_operations_cannot_claim_or_unblock(self) -> None:
        document = _valid_document()
        document["mode"] = "real"
        _refresh_measurement_context(document)
        result = evaluate_document(document)
        _require(result["status"] == "pass", f"performance comparison status={result['status']}")
        _require(not result["performance_claim_eligible"], "pending operations enabled a performance claim")
        _require(result["next_stage_blocked"], "pending operations unblocked the next stage")
        _require(result["gate_status"] == "pending", f"pending gate status={result['gate_status']}")
        _require(_gate_exit_code(result["gate_status"]) == 2, "pending gate rc is not two")

    def real_failure_cannot_claim(self) -> None:
        document = _valid_document()
        document["mode"] = "real"
        _refresh_measurement_context(document)
        document["comparison"][0]["candidate"]["exit_code"]["value"] = 1
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"expected failure, got {result['status']}")
        _require(not result["performance_claim_eligible"], "failed observations enabled a claim")

    def real_inconclusive_cannot_claim(self) -> None:
        document = _valid_document()
        document["mode"] = "real"
        _refresh_measurement_context(document)
        sample = document["comparison"][0]["candidate"]
        sample["peak_rss"] = _peak_metric(
            None, sample["sample_id"], reason="collector unavailable"
        )
        result = evaluate_document(document)
        _require(result["status"] == "inconclusive", f"expected inconclusive, got {result['status']}")
        _require(not result["performance_claim_eligible"], "inconclusive observations enabled a claim")
        _require(result["gate_status"] == "inconclusive", f"wrong gate={result['gate_status']}")
        _require(_gate_exit_code(result["gate_status"]) == 2, "inconclusive gate rc is not two")

    def throughput_regression_fails(self) -> None:
        document = _valid_document()
        for pair in document["comparison"]:
            pair["candidate"]["wall_time"]["value"] = 120.0
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"throughput regression status={result['status']}")

    def rss_regression_fails(self) -> None:
        document = _valid_document()
        for pair in document["comparison"]:
            _set_peak_metric_value(pair["candidate"]["peak_rss"], 1_200_000)
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"RSS regression status={result['status']}")

    def absolute_budget_failure_precedes_calibration(self) -> None:
        document = _valid_document()
        _set_peak_metric_value(
            document["calibration"][0]["baseline_b"]["peak_rss"], 2_000_000
        )
        for pair in document["comparison"]:
            _set_peak_metric_value(pair["candidate"]["peak_rss"], 3_000_000)
        _refresh_measurement_context(document)
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"absolute budget violation status={result['status']}")
        _require(
            result["metrics"]["peak_rss"]["status"] == "fail",
            "RSS budget was not a hard fail",
        )

    def observed_budget_failure_precedes_missing_pair(self) -> None:
        document = _valid_document()
        first = document["comparison"][0]["candidate"]
        first["peak_rss"] = _peak_metric(
            None, first["sample_id"], reason="collector unavailable"
        )
        for pair in document["comparison"][1:]:
            _set_peak_metric_value(pair["candidate"]["peak_rss"], 3_000_000)
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"partial budget violation status={result['status']}")
        _require(
            result["metrics"]["peak_rss"]["status"] == "fail",
            "observed absolute budget violation was hidden by a missing pair",
        )

    def candidate_budget_is_checked_when_baseline_is_missing(self) -> None:
        document = _valid_document()
        pair = document["comparison"][0]
        baseline = pair["baseline"]
        baseline["peak_rss"] = _peak_metric(
            None, baseline["sample_id"], reason="baseline collector unavailable"
        )
        _set_peak_metric_value(pair["candidate"]["peak_rss"], 3_000_000)
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"missing-baseline budget status={result['status']}")
        peak = result["metrics"]["peak_rss"]
        _require(peak["status"] == "fail", f"peak budget status={peak['status']}")
        _require(
            peak["absolute_budget"]["maximum_observed"] == 3_000_000,
            f"candidate peak was lost: {peak['absolute_budget']}",
        )

    def dirty_diff_sha_is_bound_to_raw_bytes(self) -> None:
        document = _valid_document()
        digest = "f" * 64
        document["identity"]["candidate_dirty_diff_sha256"] = digest
        snapshot = _correctness_snapshot_object(document, "candidate")
        snapshot["dirty_diff_sha256"] = digest
        _store_correctness_snapshot(document, "candidate", snapshot)
        for sample in [document["warmups"][2], *[pair["candidate"] for pair in document["comparison"]]]:
            sample["dirty_diff_sha256"] = digest
        _refresh_measurement_context(document)
        _expect_contract_error(document, "dirty diff")

    def latency_regression_fails(self) -> None:
        document = _valid_document()
        for pair in document["comparison"]:
            for row in pair["candidate"]["per_input_latency"]["value"]:
                row["normalized_seconds_per_call"] = 0.1
                row["process_elapsed_seconds"] = 0.1 * row["target_api_calls"]
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"latency regression status={result['status']}")

    def correctness_precedes_statistics(self) -> None:
        document = _valid_document()
        snapshot = _correctness_snapshot_object(document, "candidate")
        snapshot["records"][0]["api_events"] = ["WrongApi"]
        _store_correctness_snapshot(document, "candidate", snapshot)
        _refresh_measurement_context(document)
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"functional loss status={result['status']}")

    def lone_surrogate_json_string_is_rejected(self) -> None:
        document = _valid_document()
        snapshot = _correctness_snapshot_object(document, "candidate")
        snapshot["records"][0]["outcome_detail"] = "\ud800"
        _store_correctness_snapshot(document, "candidate", snapshot)
        _expect_contract_error(document, "UTF-8")

    def correctness_call_count_mismatch_fails(self) -> None:
        document = _valid_document()
        snapshot = _correctness_snapshot_object(document, "candidate")
        snapshot["records"][0]["target_api_calls"] = 2
        snapshot["records"][0]["api_events"] = ["OrtCreateSession", "OrtCreateSession"]
        _store_correctness_snapshot(document, "candidate", snapshot)
        _refresh_measurement_context(document)
        # Keep the repeated-workload ledger internally consistent so the
        # correctness mismatch, rather than a malformed sample, decides.
        calls_per_pass = sum(row["target_api_calls"] for row in snapshot["records"])
        for sample in [document["warmups"][2], *[pair["candidate"] for pair in document["comparison"]]]:
            complete_passes = sample["throughput_workload"]["complete_corpus_passes"]
            sample["target_api_calls"]["value"] = complete_passes * calls_per_pass
            for row in sample["per_input_latency"]["value"]:
                if row["path"] == snapshot["records"][0]["path"]:
                    row["target_api_calls"] = row["batch_iterations"] * 2
                    row["process_elapsed_seconds"] = (
                        row["normalized_seconds_per_call"] * row["target_api_calls"]
                    )
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"correctness call mismatch status={result['status']}")

    def fabricated_correctness_hash_is_rejected(self) -> None:
        document = _valid_document()
        document["correctness"]["candidate_sha256"] = "f" * 64
        _expect_contract_error(document, "raw correctness bytes")

    def candidate_correctness_is_bound_to_samples(self) -> None:
        document = _valid_document()
        snapshot = _correctness_snapshot_object(document, "candidate")
        snapshot["records"][0]["outcome_detail"] = "changed-after-measurement"
        _store_correctness_snapshot(document, "candidate", snapshot)
        _expect_contract_error(document, "measurement_context_sha256")

    def corpus_oracle_rejects_joint_wrong_results(self) -> None:
        document = _valid_document()
        for arm in ("baseline", "candidate"):
            snapshot = _correctness_snapshot_object(document, arm)
            rejected = snapshot["records"][3]
            rejected["outcome_class"] = "rejected"
            rejected["outcome_detail"] = "unavailable"
            rejected["exit_code"] = 10
            _store_correctness_snapshot(document, arm, snapshot)
        _refresh_measurement_context(document)
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"joint unavailable result status={result['status']}")

    def pre_parser_oracle_requires_exact_zero_calls(self) -> None:
        document = _valid_document()
        corpus_index = _parse_json_text(
            document["identity"]["fixed"]["corpus_index_raw_json"], "corpus fixture"
        )
        row = corpus_index["inputs"][4]
        row.update(
            {
                "target_api_stage": "pre-parser-reject",
                "minimum_target_api_calls": 0,
                "required_api_events": [],
                "zero_call_reason": "adapter rejected before target parser",
                "throughput_order_index": None,
                "throughput_exclusion_reason": "pre-parser rejection is correctness-only",
            }
        )
        _store_corpus_index(document, corpus_index)
        for sample in _all_samples(document):
            complete_passes = sample["throughput_workload"]["complete_corpus_passes"]
            sample["input_count"]["value"] = complete_passes * 4
            sample["target_api_calls"]["value"] = complete_passes * 4
        _refresh_measurement_context(document)
        result = evaluate_document(document)
        _require(result["status"] == "fail", f"pre-parser nonzero call status={result['status']}")
        _require(
            any("pre-parser rejection" in reason for reason in result["reasons"]),
            f"pre-parser failure reason missing: {result['reasons']}",
        )

    def null_metric_is_inconclusive(self) -> None:
        document = _valid_document()
        sample = document["comparison"][0]["candidate"]
        sample["peak_rss"] = _peak_metric(
            None, sample["sample_id"], reason="collector unavailable"
        )
        result = evaluate_document(document)
        _require(result["status"] == "inconclusive", f"null metric status={result['status']}")

    def zero_peak_rss_is_rejected(self) -> None:
        document = _valid_document()
        _set_peak_metric_value(document["comparison"][0]["candidate"]["peak_rss"], 0)
        _expect_contract_error(document, "must be > 0")

    def aggregate_gate_exit_codes_are_explicit(self) -> None:
        _require(_gate_exit_code("pass") == 0, "verified pass rc is not zero")
        _require(_gate_exit_code("fail") == 1, "fail rc is not one")
        _require(_gate_exit_code("pending") == 2, "pending rc is not two")
        _require(_gate_exit_code("inconclusive") == 2, "inconclusive rc is not two")

    def operations_failure_fails_aggregate_gate(self) -> None:
        document = _valid_document()
        document["mode"] = "real"
        _refresh_measurement_context(document)
        document["operations"]["engine_smoke"] = {
            "status": "fail",
            "reason": "fuzz-PC engine smoke failed",
            "evidence_sha256": None,
            "raw_json": None,
        }
        result = evaluate_document(document)
        _require(result["performance_status"] == "pass", "performance fixture unexpectedly failed")
        _require(result["operations_status"] == "fail", "operation failure was lost")
        _require(result["gate_status"] == "fail", "aggregate gate did not fail")
        _require(_gate_exit_code(result["gate_status"]) == 1, "aggregate failure rc is not one")

    def bootstrap_is_deterministic(self) -> None:
        first = bootstrap_median_ci([0.9, 1.0, 1.1, 1.2, 1.3])
        second = bootstrap_median_ci([0.9, 1.0, 1.1, 1.2, 1.3])
        _require(first == second, f"bootstrap changed: {first} vs {second}")
        _require(first == (0.9, 1.3), f"unexpected nearest-rank interval: {first}")

    def duplicate_json_key_is_rejected(self) -> None:
        try:
            _parse_json_text('{"value":1,"value":2}', "duplicate fixture")
        except ContractError as error:
            _require("duplicate JSON key" in str(error), f"wrong duplicate-key error: {error}")
        else:
            raise SelftestFailure("duplicate JSON key was accepted")

    def nonfinite_json_number_is_rejected(self) -> None:
        try:
            _parse_json_text('{"value":NaN}', "nonfinite fixture")
        except ContractError as error:
            _require("non-finite" in str(error), f"wrong nonfinite error: {error}")
        else:
            raise SelftestFailure("NaN was accepted")

    def nonfinite_derived_numbers_are_rejected(self) -> None:
        document = _valid_document()
        for sample in _all_samples(document):
            for row in sample["per_input_latency"]["value"]:
                row["normalized_seconds_per_call"] = 5e-324
                row["process_elapsed_seconds"] = 5e-323
        _refresh_measurement_context(document)
        _expect_contract_error(document, "finite derived")

    def external_real_cli_preserves_pending_evidence(self) -> None:
        document = _valid_document()
        document["mode"] = "real"
        document["comparison_id"] = "fnd05-real-cli-selftest"
        _refresh_measurement_context(document)
        with tempfile.TemporaryDirectory(prefix="fnd05-cli-") as raw:
            root = Path(raw)
            observations = root / "observations.json"
            observations.write_bytes(_canonical_json(document))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = main(
                    [
                        "--evaluate",
                        str(observations.resolve()),
                        "--output-dir",
                        str(root.resolve()),
                    ]
                )
            _require(rc == 2, f"real pending CLI rc={rc} stderr={stderr.getvalue()}")
            _require(
                "performance_status=pass operations_status=pending gate_status=pending" in stdout.getvalue(),
                f"wrong CLI output: {stdout.getvalue()}",
            )
            _require("next_stage_blocked=yes" in stdout.getvalue(), f"wrong CLI output: {stdout.getvalue()}")
            destination = root / document["comparison_id"]
            evaluation = json.loads((destination / "evaluation.json").read_text(encoding="utf-8"))
            _require(not evaluation["performance_claim_eligible"], "pending real evidence became claim eligible")
            _require((destination / "index.json").is_file(), "real CLI omitted final evidence index")

    def evidence_is_split_and_indexed(self) -> None:
        document = _valid_document()
        result = evaluate_document(document)
        with tempfile.TemporaryDirectory(prefix="fnd05-publish-") as raw:
            destination = publish_evidence(document, result, Path(raw))
            _require((destination / "baseline.json").is_file(), "baseline evidence missing")
            _require((destination / "candidate.json").is_file(), "candidate evidence missing")
            _require((destination / "calibration.json").is_file(), "calibration evidence missing")
            _require(
                (destination / "profiles" / "baseline-correctness.json").is_file(),
                "baseline correctness raw evidence missing",
            )
            _require(
                (destination / "profiles" / "candidate-correctness.json").is_file(),
                "candidate correctness raw evidence missing",
            )
            index = json.loads((destination / "index.json").read_text(encoding="utf-8"))
            _require(index["state"] == "complete", f"bad index state: {index}")
            _require(any(name.startswith("samples/comparison-") for name in index["files"]), "raw samples not indexed")

    def existing_destination_is_never_overwritten(self) -> None:
        document = _valid_document()
        result = evaluate_document(document)
        with tempfile.TemporaryDirectory(prefix="fnd05-overwrite-") as raw:
            root = Path(raw)
            destination = publish_evidence(document, result, root)
            before = (destination / "baseline.json").read_bytes()
            try:
                publish_evidence(document, result, root)
            except EvidenceError:
                pass
            else:
                raise SelftestFailure("second publication unexpectedly succeeded")
            _require((destination / "baseline.json").read_bytes() == before, "baseline was overwritten")

    def preexisting_symlink_is_never_followed(self) -> None:
        document = _valid_document()
        result = evaluate_document(document)
        with tempfile.TemporaryDirectory(prefix="fnd05-symlink-") as raw:
            root = Path(raw)
            external = root / "external"
            external.mkdir()
            sentinel = external / "sentinel"
            sentinel.write_text("preserve", encoding="utf-8")
            (root / document["comparison_id"]).symlink_to(external, target_is_directory=True)
            try:
                publish_evidence(document, result, root)
            except EvidenceError:
                pass
            else:
                raise SelftestFailure("symlink destination unexpectedly accepted")
            _require(sentinel.read_text(encoding="utf-8") == "preserve", "external target changed")
            _require(sorted(item.name for item in external.iterdir()) == ["sentinel"], "external files created")

    def record_symlink_is_never_overwritten(self) -> None:
        document = _valid_document()
        result = evaluate_document(document)
        with tempfile.TemporaryDirectory(prefix="fnd05-record-link-") as raw:
            root = Path(raw)
            external = root / "sentinel"
            external.write_text("preserve", encoding="utf-8")

            def hook(phase: str, destination: Path, name: str) -> None:
                if phase == "directory_ready":
                    (destination / "baseline.json").symlink_to(external)

            try:
                publish_evidence(document, result, root, test_hook=hook)
            except EvidenceError:
                pass
            else:
                raise SelftestFailure("record symlink unexpectedly replaced")
            _require(external.read_text(encoding="utf-8") == "preserve", "record symlink target changed")

    def directory_swap_is_detected(self) -> None:
        document = _valid_document()
        result = evaluate_document(document)
        with tempfile.TemporaryDirectory(prefix="fnd05-dir-race-") as raw:
            root = Path(raw)
            external = root / "external"
            external.mkdir()
            sentinel = external / "sentinel"
            sentinel.write_text("preserve", encoding="utf-8")

            def hook(phase: str, destination: Path, name: str) -> None:
                if phase == "directory_ready":
                    destination.rename(root / "moved-evidence")
                    destination.symlink_to(external, target_is_directory=True)

            try:
                publish_evidence(document, result, root, test_hook=hook)
            except EvidenceError:
                pass
            else:
                raise SelftestFailure("directory replacement race unexpectedly succeeded")
            _require(sentinel.read_text(encoding="utf-8") == "preserve", "race target changed")
            _require(sorted(item.name for item in external.iterdir()) == ["sentinel"], "race wrote outside evidence")

    def evaluator_source_swap_is_detected(self) -> None:
        global _EVALUATOR_SOURCE_BYTES
        global _EVALUATOR_SOURCE_METADATA
        global _EVALUATOR_SOURCE_PATH
        global _EVALUATOR_SOURCE_SHA256

        saved = (
            _EVALUATOR_SOURCE_PATH,
            _EVALUATOR_SOURCE_BYTES,
            _EVALUATOR_SOURCE_METADATA,
            _EVALUATOR_SOURCE_SHA256,
        )
        with tempfile.TemporaryDirectory(prefix="fnd05-evaluator-race-") as raw:
            root = Path(raw)
            source = root / "evaluator.py"
            source.write_text("startup evaluator bytes\n", encoding="utf-8")
            source_bytes, source_metadata = _capture_evaluator_source(source)
            _EVALUATOR_SOURCE_PATH = source
            _EVALUATOR_SOURCE_BYTES = source_bytes
            _EVALUATOR_SOURCE_METADATA = source_metadata
            _EVALUATOR_SOURCE_SHA256 = _sha256_bytes(source_bytes)
            document = _valid_document()
            result = evaluate_document(document)

            def hook(phase: str, destination: Path, name: str) -> None:
                if phase == "directory_ready":
                    source.write_text("replacement evaluator bytes\n", encoding="utf-8")

            try:
                publish_evidence(document, result, root, test_hook=hook)
            except EvidenceError as error:
                _require("evaluator source" in str(error), f"wrong evaluator race error: {error}")
            else:
                raise SelftestFailure("evaluator source replacement race unexpectedly succeeded")
            finally:
                (
                    _EVALUATOR_SOURCE_PATH,
                    _EVALUATOR_SOURCE_BYTES,
                    _EVALUATOR_SOURCE_METADATA,
                    _EVALUATOR_SOURCE_SHA256,
                ) = saved
            destination = root / document["comparison_id"]
            _require(not (destination / "index.json").exists(), "raced evaluator published complete index")


SELFTEST_CASES = [
    ("zero input cannot pass", "zero_input_does_not_pass"),
    ("zero target calls cannot pass", "zero_api_calls_does_not_pass"),
    ("unit mismatch is rejected", "unit_mismatch_is_rejected"),
    ("unallowed profile difference is rejected", "unallowed_profile_difference_is_rejected"),
    ("current TargetProfile shape is accepted", "actual_target_profile_shape_is_accepted"),
    ("TargetProfile serde defaults are accepted", "target_profile_serde_defaults_are_accepted"),
    ("target-specific depth is enforced", "target_specific_depth_is_enforced"),
    ("uppercase profile SHA is accepted", "uppercase_profile_hash_is_accepted"),
    ("profile argv and flags may repeat", "duplicate_profile_argv_and_flags_are_accepted"),
    ("profile IDs match the Rust contract", "profile_id_matches_rust_contract"),
    ("nested profile unknown field is rejected", "nested_profile_unknown_field_is_rejected"),
    ("raw profile bytes identity is enforced", "profile_raw_bytes_identity_is_enforced"),
    ("partial sample is rejected", "partial_sample_is_rejected"),
    ("missing value has a reason", "missing_value_requires_reason"),
    ("latency covers every corpus input", "missing_latency_input_is_rejected"),
    ("latency input identity is unique", "duplicate_latency_input_is_rejected"),
    ("scalar latency cannot stand in for repetitions", "scalar_latency_rows_are_rejected"),
    ("latency summaries derive from raw", "latency_summary_tampering_is_rejected"),
    ("latency workload order is fixed", "latency_workload_order_is_enforced"),
    ("latency pair rotation is fixed", "latency_pair_rotation_is_fixed"),
    ("latency arm order mismatch is rejected", "latency_arm_order_mismatch_is_rejected"),
    ("latency zero denominator is rejected", "latency_zero_denominator_is_rejected"),
    ("latency failed probe is rejected", "latency_failed_probe_is_rejected"),
    ("latency subset is fixed across arms", "latency_subset_cannot_be_changed_by_an_arm"),
    ("budgets are fixed before samples", "posthoc_budget_change_is_rejected"),
    ("calibration is fixed before comparison", "posthoc_calibration_change_is_rejected"),
    ("measurement mode is context-bound", "mode_relabel_is_rejected"),
    ("real resource values are nonzero", "zero_real_resource_values_are_rejected"),
    ("huge numeric budgets are rejected", "huge_numeric_budget_is_rejected"),
    ("sample counts fit unsigned 64-bit", "unbounded_sample_counts_are_rejected"),
    ("API call resolution is exactly one", "api_call_resolution_is_exactly_one"),
    ("workload flags are equal", "workload_flag_difference_is_rejected"),
    ("workload environments are equal", "workload_environment_difference_is_rejected"),
    ("workload cwd is equal", "workload_cwd_difference_is_rejected"),
    ("WSL ext4 path type is enforced", "windows_mount_contradicts_wsl_ext4"),
    ("loader injection environment is rejected", "loader_injection_environment_is_rejected"),
    ("pinned profile environment is required", "pinned_profile_environment_is_required"),
    ("conflicting profile environments are rejected", "conflicting_profile_environment_is_rejected"),
    ("unverified operations cannot pass", "unverified_operation_pass_is_rejected"),
    ("preparation is excluded", "preparation_is_excluded_from_throughput"),
    ("actual calls are throughput numerator", "input_count_is_not_throughput_denominator"),
    ("target call inflation is rejected", "target_call_inflation_is_rejected"),
    ("throughput cycle ledger stays compact", "throughput_cycle_ledger_is_compact"),
    ("throughput cycle ledger is verified", "throughput_cycle_ledger_mismatch_is_rejected"),
    ("pair indexes are contiguous", "pair_gap_is_rejected"),
    ("arms alternate", "alternation_is_rejected"),
    ("at least five pairs are required", "too_few_pairs_is_rejected"),
    ("real samples last sixty seconds", "short_real_sample_is_rejected"),
    ("tree RSS collector is truthful", "forged_tree_rss_collector_is_rejected"),
    ("memory collector aliases are rejected", "memory_collector_alias_is_rejected"),
    ("memory collector provenance is bound", "memory_collector_provenance_is_bound"),
    ("memory collector config types are strict", "memory_collector_config_types_are_strict"),
    ("memory cgroup leaf is unique per sample", "memory_cgroup_leaf_is_unique_per_sample"),
    ("A/A deltas are metric-specific", "deltas_are_metric_specific"),
    ("delta one blocks evaluation", "delta_one_blocks_evaluation"),
    ("metric directions pass", "pass_direction_is_correct"),
    ("pending real operations block claims", "real_pending_operations_cannot_claim_or_unblock"),
    ("real failure cannot claim", "real_failure_cannot_claim"),
    ("real inconclusive cannot claim", "real_inconclusive_cannot_claim"),
    ("throughput regression fails", "throughput_regression_fails"),
    ("RSS regression fails", "rss_regression_fails"),
    ("absolute budget failure is hard", "absolute_budget_failure_precedes_calibration"),
    ("observed budget failure beats missing pair", "observed_budget_failure_precedes_missing_pair"),
    (
        "candidate budget survives missing baseline",
        "candidate_budget_is_checked_when_baseline_is_missing",
    ),
    ("dirty diff SHA binds raw bytes", "dirty_diff_sha_is_bound_to_raw_bytes"),
    ("latency regression fails", "latency_regression_fails"),
    ("correctness precedes statistics", "correctness_precedes_statistics"),
    ("lone surrogate JSON strings are rejected", "lone_surrogate_json_string_is_rejected"),
    ("correctness call counts must match", "correctness_call_count_mismatch_fails"),
    ("correctness raw hashes are verified", "fabricated_correctness_hash_is_rejected"),
    ("candidate correctness binds samples", "candidate_correctness_is_bound_to_samples"),
    ("corpus oracle rejects joint wrong results", "corpus_oracle_rejects_joint_wrong_results"),
    ("pre-parser oracle requires exact zero", "pre_parser_oracle_requires_exact_zero_calls"),
    ("null metric is inconclusive", "null_metric_is_inconclusive"),
    ("zero peak RSS is rejected", "zero_peak_rss_is_rejected"),
    ("aggregate gate exit codes are explicit", "aggregate_gate_exit_codes_are_explicit"),
    ("operation failure fails aggregate gate", "operations_failure_fails_aggregate_gate"),
    ("bootstrap is deterministic", "bootstrap_is_deterministic"),
    ("duplicate JSON key is rejected", "duplicate_json_key_is_rejected"),
    ("non-finite JSON is rejected", "nonfinite_json_number_is_rejected"),
    ("non-finite derived numbers are rejected", "nonfinite_derived_numbers_are_rejected"),
    ("external real CLI preserves pending evidence", "external_real_cli_preserves_pending_evidence"),
    ("evidence is split and indexed", "evidence_is_split_and_indexed"),
    ("existing evidence is immutable", "existing_destination_is_never_overwritten"),
    ("destination symlink is refused", "preexisting_symlink_is_never_followed"),
    ("record symlink is refused", "record_symlink_is_never_overwritten"),
    ("directory swap is detected", "directory_swap_is_detected"),
    ("evaluator source swap is detected", "evaluator_source_swap_is_detected"),
]


def run_selftest() -> int:
    passed = 0
    failed = 0
    tests = BaselineSelftest()
    for label, method_name in SELFTEST_CASES:
        try:
            method = getattr(tests, method_name)
            method()
        except Exception as error:
            failed += 1
            print(f"  FAIL {label}: {error}")
        else:
            passed += 1
            print(f"  ok   {label}")
    print(f"[format-baseline-selftest] pass={passed} fail={failed}")
    return 0 if failed == 0 else 1


class ContractArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = ContractArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--evaluate", type=Path, metavar="OBSERVATIONS_JSON")
    parser.add_argument("--output-dir", type=Path, help="existing non-symlink evidence root")
    return parser


def _read_observation_file(path: Path) -> dict[str, Any]:
    if not path.is_absolute():
        raise ContractError("observations path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ContractError(f"could not open observations without following symlinks: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError("observations must be a regular file")
        if before.st_size <= 0 or before.st_size > 64 * 1024 * 1024:
            raise ContractError("observations size must be between 1 byte and 64 MiB")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ContractError("observations changed or ended while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ContractError("observations grew while being read")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ContractError("observations changed while being read")
    finally:
        os.close(descriptor)
    try:
        text = b"".join(chunks).decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ContractError("observations are not valid UTF-8") from error
    document = _parse_json_text(text, "observations")
    if not isinstance(document, dict):
        raise ContractError("observations JSON root must be an object")
    return document


def _safe_error_text(error: BaseException) -> str:
    return str(error).encode("utf-8", "backslashreplace").decode("utf-8")


def _gate_exit_code(gate_status: str) -> int:
    try:
        return {"pass": 0, "fail": 1, "pending": 2, "inconclusive": 2}[gate_status]
    except KeyError as error:
        raise ContractError(f"unsupported aggregate gate status {gate_status!r}") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.selftest:
        if args.output_dir is not None:
            parser.error("--output-dir is not valid with --selftest")
        return run_selftest()
    if args.output_dir is None:
        parser.error("--output-dir is required with --evaluate")
    try:
        document = _read_observation_file(args.evaluate)
        if document.get("mode") != "real":
            raise ContractError("--evaluate accepts real observations only; selftest is never performance evidence")
        evaluation = evaluate_document(document)
        destination = publish_evidence(document, evaluation, args.output_dir)
    except ContractError as error:
        print(f"format-baseline: invalid observations: {_safe_error_text(error)}", file=sys.stderr)
        return 64
    except EvidenceError as error:
        print(f"format-baseline: evidence publication failed: {_safe_error_text(error)}", file=sys.stderr)
        return 73
    except Exception as error:
        print(f"format-baseline: internal error: {_safe_error_text(error)}", file=sys.stderr)
        return 2
    print(
        f"[format-baseline] performance_status={evaluation['performance_status']} "
        f"operations_status={evaluation['operations_status']} "
        f"gate_status={evaluation['gate_status']} "
        f"next_stage_blocked={'yes' if evaluation['next_stage_blocked'] else 'no'} "
        f"evidence={destination}"
    )
    return _gate_exit_code(evaluation["gate_status"])


if __name__ == "__main__":
    raise SystemExit(main())
