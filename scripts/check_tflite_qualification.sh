#!/usr/bin/env bash
# TFL-07 qualification assembler contract. The Python self-test owns only a private
# temporary tree and proves that partial or mutable evidence cannot become verified.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
SELFTEST="$PROJECT_ROOT/scripts/check_tflite_qualification_selftest.py"
ASSEMBLER="$PROJECT_ROOT/scripts/qualify_tflite.py"

if [[ ! -f "$SELFTEST" ]]; then
  printf '[tflite-qualification] fail: self-test is missing: %s\n' "$SELFTEST" >&2
  exit 1
fi

exec python3 -B "$SELFTEST" --assembler "$ASSEMBLER"
