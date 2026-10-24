#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd -P)}"
TARGET_ROOT="${OPENVINO_TARGET_ROOT:-$PROJECT_ROOT/data/targets/openvino-ir/2026.4.1}"

exec python3 -B "$SCRIPT_DIR/check_openvino_fixtures.py" \
  --project-root "$PROJECT_ROOT" \
  --target-root "$TARGET_ROOT"
