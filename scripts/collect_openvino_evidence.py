#!/usr/bin/env python3
"""OpenVINO OVI-07 entrypoint for the shared strict Q10/Q11 collector."""

from __future__ import annotations

import sys

import collect_tflite_evidence as collector


EvidenceError = collector.EvidenceError
validate_bundle = collector.validate_bundle


def main() -> int:
    arguments = list(sys.argv[1:])
    if arguments and arguments[0] == "prepare" and "--target-id" not in arguments:
        arguments[1:1] = ["--target-id", "openvino-ir"]
    return collector.main(arguments, default_target_id="openvino-ir")


if __name__ == "__main__":
    raise SystemExit(main())
