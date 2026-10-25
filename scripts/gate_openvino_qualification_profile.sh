#!/usr/bin/env bash
# Q01: revalidate the exact OVI-07 profile and its reproducible-build guard.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
PROFILE="${OPENVINO_PROFILE:?OPENVINO_PROFILE is required}"

python3 -B - "$PROJECT_ROOT" "$PROFILE" <<'PY'
import pathlib
import sys

project = pathlib.Path(sys.argv[1])
profile = pathlib.Path(sys.argv[2]).resolve(strict=True)
sys.path.insert(0, str(project / "scripts"))
import qualify_tflite

qualify_tflite.audit_profile(profile, qualify_tflite.OPENVINO_CONTRACT)
PY

bash "$PROJECT_ROOT/scripts/test_build_openvino_profiles.sh"
printf '[openvino-qualification-profile] pass=2 fail=0\n'
