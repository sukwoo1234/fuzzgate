#!/usr/bin/env bash
# Q01: revalidate the exact HDF-07 profile, HDF-01 build state, and scope.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
PROFILE="${HDF5_PROFILE:?HDF5_PROFILE is required}"
TARGET_ROOT="${HDF5_TARGET_ROOT:?HDF5_TARGET_ROOT is required}"
TARGET_SPEC="${HDF5_TARGET_SPEC:?HDF5_TARGET_SPEC is required}"

python3 -B - "$PROJECT_ROOT" "$PROFILE" <<'PY'
import pathlib
import sys

project = pathlib.Path(sys.argv[1])
profile = pathlib.Path(sys.argv[2]).resolve(strict=True)
sys.path.insert(0, str(project / "scripts"))
import qualify_tflite

qualify_tflite.audit_profile(profile, qualify_tflite.HDF5_CONTRACT)
PY

python3 -B "$PROJECT_ROOT/scripts/check_hdf5_profile.py" \
  --target-root "$TARGET_ROOT"
python3 -B "$PROJECT_ROOT/scripts/check_hdf5_scope.py" \
  --target-spec "$TARGET_SPEC" \
  --build-profile "$TARGET_ROOT/build-profile.json" \
  --execution-profile "$PROFILE"
printf '[hdf5-qualification-profile] pass=3 fail=0\n'
