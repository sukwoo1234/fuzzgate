#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SELFTEST="$PROJECT_ROOT/scripts/check_tflite_evidence_selftest.py"

if [[ ! -f "$SELFTEST" || -L "$SELFTEST" ]]; then
  printf '[tflite-evidence] fail: self-test is missing or linked: %s\n' "$SELFTEST" >&2
  exit 1
fi

exec python3 -B "$SELFTEST"
