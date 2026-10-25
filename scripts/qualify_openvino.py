#!/usr/bin/env python3
"""Audit OVI-07 FND-03 evidence and issue an OpenVINO sidecar."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import qualify_tflite as qualification


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--status", required=True, choices=("verified", "smoke_passed")
    )
    args = parser.parse_args()
    try:
        qualification.qualify(
            args.profile.resolve(strict=True),
            args.evidence_root.resolve(strict=True),
            args.output.absolute(),
            args.status,
            qualification.OPENVINO_CONTRACT,
        )
    except (qualification.QualificationError, OSError) as error:
        print(f"[openvino-qualification] fail: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
