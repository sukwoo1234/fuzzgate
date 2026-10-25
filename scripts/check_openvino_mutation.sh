#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
OPENVINO_TARGET_ROOT="${OPENVINO_TARGET_ROOT:-$PROJECT_ROOT/data/targets/openvino-ir/2026.4.1}"

exec python3 -B "$PROJECT_ROOT/scripts/check_openvino_mutation.py" \
  --project-root "$PROJECT_ROOT" \
  --target-root "$OPENVINO_TARGET_ROOT"
