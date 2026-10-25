#!/usr/bin/env bash
# OVI-07 qualification contract. The Python self-test owns only private
# temporary state and must not start real performance or long-running work.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
SELFTEST="$PROJECT_ROOT/scripts/check_openvino_qualification_selftest.py"

if [[ ! -f "$SELFTEST" ]]; then
  printf '[openvino-qualification] fail: self-test is missing: %s\n' "$SELFTEST" >&2
  exit 1
fi

exec python3 -B "$SELFTEST"
