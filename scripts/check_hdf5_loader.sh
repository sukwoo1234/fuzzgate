#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TARGET_ROOT="${HDF5_TARGET_ROOT:-$PROJECT_ROOT/data/targets/hdf5-weights/2.2.0}"

exec python3 -B "$PROJECT_ROOT/scripts/check_hdf5_loader.py" \
  --project-root "$PROJECT_ROOT" --target-root "$TARGET_ROOT" "$@"
