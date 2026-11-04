#!/usr/bin/env python3
"""Audit HDF-07 evidence and issue an HDF5-only qualification sidecar."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import check_hdf5_scope as scope
import qualify_tflite as qualification


BUILD_IDENTITY = {
    "schema_version": "hdf5-weights-build-profile-v1",
    "target_id": "hdf5-weights",
    "target_version": "2.2.0",
    "status": "provisioned",
    "execution_profile_ready": False,
    "source_artifacts": [
        {
            "name": "hdf5",
            "url": "https://github.com/HDFGroup/hdf5/releases/download/2.2.0/hdf5-2.2.0.tar.gz",
            "tag": "2.2.0",
            "resolved_commit": "49df1b4e5ca4108d56e80f06321a749da1535268",
            "sha256": "1a1ab8209b35586fbc1aa279ba76d102130b95badcb20ca329587219112d8c16",
            "size_bytes": 42131403,
        }
    ],
    "patches": [],
}


def validate_support_scope(
    target_spec: dict[str, Any],
    build_profile: dict[str, Any],
    execution_profile: dict[str, Any],
) -> None:
    scope.validate_scope(target_spec, build_profile, execution_profile)
    for key, expected in BUILD_IDENTITY.items():
        if build_profile.get(key) != expected:
            raise scope.ScopeError(
                f"build profile {key} differs from the immutable HDF-01 identity"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--build-profile", required=True, type=Path)
    parser.add_argument("--target-spec", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--status", required=True, choices=("verified", "smoke_passed")
    )
    args = parser.parse_args()
    try:
        profile = args.profile.resolve(strict=True)
        build_profile = args.build_profile.resolve(strict=True)
        target_spec = args.target_spec.resolve(strict=True)
        target_document, _target_payload = qualification.read_json(
            target_spec, "HDF5 target spec"
        )
        build_document, _build_payload = qualification.read_json(
            build_profile, "HDF-01 build profile"
        )
        profile_document, _profile_payload = qualification.read_json(
            profile, "HDF-07 profile", qualification.MAX_PROFILE_BYTES
        )
        validate_support_scope(
            target_document,
            build_document,
            profile_document,
        )
        qualification.qualify(
            profile,
            args.evidence_root.resolve(strict=True),
            args.output.absolute(),
            args.status,
            qualification.HDF5_CONTRACT,
        )
    except (
        qualification.QualificationError,
        scope.ScopeError,
        OSError,
    ) as error:
        print(f"[hdf5-qualification] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
