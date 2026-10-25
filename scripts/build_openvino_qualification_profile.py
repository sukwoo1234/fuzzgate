#!/usr/bin/env python3
"""Bind the OVI-06 replay and OVI-05 guided fuzzer into one OVI-07 profile."""

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
TARGET_ID = "openvino-ir"
INPUT_KIND = {
    "kind": "fzb1",
    "extensions": ["fzb"],
    "subformats": ["model.bin", "model.xml"],
}
CAPABILITY = {
    "backend": "local-harness",
    "binary_role": "replay",
    "required_mode": "native",
    "instrumentation_scope": "openvino-core+ir-frontend",
}
PRIMARY_SOURCE = {
    "url": "https://github.com/openvinotoolkit/openvino/archive/refs/tags/2026.4.1.tar.gz",
    "tag": "2026.4.1",
    "resolved_commit": "e213a14725769a6a2bf86fc86650aa78a9c05d3e",
    "sha256": "1ee85264556025486a4745a2d452ea823c578b3d162768bfef590366d2e6c539",
    "size_bytes": 71349787,
}


class ProfileError(RuntimeError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProfileError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProfileError(f"could not inspect {label}: {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ProfileError(f"{label} must be a private regular file: {path}")
    if metadata.st_size > 16 * 1024 * 1024:
        raise ProfileError(f"{label} is too large: {path}")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as error:
        raise ProfileError(f"could not parse {label}: {path}: {error}") from error
    if not isinstance(value, dict):
        raise ProfileError(f"{label} must be a JSON object")
    return value


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def identity(path: Path, label: str) -> dict[str, str]:
    if not path.is_absolute():
        raise ProfileError(f"{label} path must be absolute: {path}")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise ProfileError(f"could not resolve {label}: {path}: {error}") from error
    if resolved != path or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ProfileError(f"{label} must be a canonical private regular file: {path}")
    return {"path": str(path), "sha256": digest(path)}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileError(message)


def build_profile(execution_path: Path, guided_path: Path) -> dict[str, Any]:
    execution = read_json(execution_path, "OVI-06 execution profile")
    guided = read_json(guided_path, "OVI-05 guided manifest")
    require(execution.get("schema_version") == "1", "execution profile schema mismatch")
    require(execution.get("target_id") == TARGET_ID, "execution profile target mismatch")
    require(execution.get("loader_version") == VERSION, "execution profile version mismatch")
    source_artifacts = execution.get("source_artifacts")
    require(
        isinstance(source_artifacts, list)
        and source_artifacts
        and source_artifacts[0] == PRIMARY_SOURCE,
        "execution profile primary source pin mismatch",
    )
    require(execution.get("patches") == [], "OpenVINO qualification forbids target patches")
    require(execution.get("input_kind") == INPUT_KIND, "execution profile FZB1 contract mismatch")
    require(
        execution.get("depth") == "read-validate-constants",
        "execution profile depth mismatch",
    )
    require(
        execution.get("engine_capabilities") == [CAPABILITY],
        "execution profile backend/scope mismatch",
    )
    binaries = execution.get("binaries")
    require(
        isinstance(binaries, list)
        and len(binaries) == 1
        and isinstance(binaries[0], dict)
        and binaries[0].get("role") == "replay",
        "OVI-06 profile must contain exactly the replay role",
    )
    replay = binaries[0]
    replay_path = Path(replay.get("path", ""))
    require(identity(replay_path, "replay")["sha256"] == replay.get("sha256"), "replay hash mismatch")

    require(
        guided.get("schema_version") == "openvino-ir-instrumentation-v1"
        and guided.get("target") == TARGET_ID
        and guided.get("target_version") == VERSION
        and guided.get("mode") == "guided",
        "guided manifest identity mismatch",
    )
    components = guided.get("components")
    require(isinstance(components, dict), "guided manifest components are missing")
    component_identities: dict[str, dict[str, str]] = {}
    for role in ("core", "ir_frontend", "driver"):
        row = components.get(role)
        require(isinstance(row, dict), f"guided component is missing: {role}")
        observed = identity(Path(row.get("path", "")), f"guided {role}")
        require(observed == row, f"guided {role} identity mismatch")
        component_identities[role] = observed
    fuzzer_path = Path(component_identities["driver"]["path"])
    loader_library = fuzzer_path.parent / "libtool_openvino_loader.a"
    loader_identity = identity(loader_library, "guided common-loader library")

    profile = json.loads(json.dumps(execution))
    profile["binaries"].append(
        {
            "role": "fuzzer",
            "path": str(fuzzer_path),
            "sha256": component_identities["driver"]["sha256"],
            "argv": ["{corpus_dir}"],
            "linked_libraries": [
                component_identities["core"],
                component_identities["ir_frontend"],
                loader_identity,
            ],
        }
    )
    return profile


def publish(path: Path, value: dict[str, Any]) -> None:
    if not path.is_absolute():
        raise ProfileError("output path must be absolute")
    if path.exists() or path.is_symlink():
        raise ProfileError(f"output already exists: {path}")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise ProfileError(f"output parent is unavailable: {error}") from error
    if parent != path.parent or not path.parent.is_dir():
        raise ProfileError("output parent must be a canonical directory")
    payload = (
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-profile", required=True, type=Path)
    parser.add_argument("--guided-manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        execution = args.execution_profile.resolve(strict=True)
        guided = args.guided_manifest.resolve(strict=True)
        output = args.output.absolute()
        publish(output, build_profile(execution, guided))
        print(
            "OPENVINO_QUALIFICATION_PROFILE_OK=yes "
            f"profile={output} sha256={digest(output)}"
        )
    except (ProfileError, OSError, ValueError) as error:
        print(f"[openvino-qualification-profile] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
