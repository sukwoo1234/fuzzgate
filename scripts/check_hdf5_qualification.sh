#!/usr/bin/env bash
# HDF-07 qualification negative controls. Real Q10/Q11 work is never started
# by this self-test; run_hdf5_qualification.py consumes explicit bundles.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
SELFTEST="$PROJECT_ROOT/scripts/check_hdf5_qualification_selftest.py"

if [[ ! -f "$SELFTEST" ]]; then
  printf '[hdf5-qualification] fail: self-test is missing: %s\n' "$SELFTEST" >&2
  exit 1
fi

exec python3 -B "$SELFTEST"
