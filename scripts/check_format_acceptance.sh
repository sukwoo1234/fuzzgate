#!/usr/bin/env bash
# FND-03 fail-closed acceptance-runner regression gate.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"

if ! command -v python3 >/dev/null 2>&1; then
  printf '[format-acceptance] fail: python3 is required\n' >&2
  exit 1
fi

exec python3 -B "$PROJECT_ROOT/scripts/check_format_acceptance_selftest.py"
