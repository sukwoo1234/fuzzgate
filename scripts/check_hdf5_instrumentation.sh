#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd -P)}"
TARGET_ROOT="${HDF5_TARGET_ROOT:-$PROJECT_ROOT/data/targets/hdf5-weights/2.2.0}"
COVERAGE_EVIDENCE="${HDF5_COVERAGE_EVIDENCE:-$TARGET_ROOT/instrumentation-evidence/coverage/coverage.json}"

python3 -B "$SCRIPT_DIR/check_hdf5_instrumentation.py" --selftest
exec python3 -B "$SCRIPT_DIR/check_hdf5_instrumentation.py" \
  --target-root "$TARGET_ROOT" \
  --coverage-evidence "$COVERAGE_EVIDENCE"
