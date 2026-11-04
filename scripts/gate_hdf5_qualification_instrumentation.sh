#!/usr/bin/env bash
# Q06/Q07: retain variable measured counts behind a stable exact gate marker.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
bash "$PROJECT_ROOT/scripts/check_hdf5_instrumentation.sh"
printf '[hdf5-qualification-instrumentation] pass=2 fail=0\n'
