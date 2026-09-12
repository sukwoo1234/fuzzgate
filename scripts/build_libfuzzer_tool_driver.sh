#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORKDIR="${WORKDIR:-$PWD}"
SRC="${SRC:-$WORKDIR/harnesses/libfuzzer/tool_harness_driver.cc}"
OUT="${OUT:-$WORKDIR/harnesses/libfuzzer/tool_harness_driver}"

if ! command -v clang++ >/dev/null 2>&1; then
  echo "[build-libfuzzer-driver] clang++ not found"
  exit 1
fi

# R55: this driver is tracked, so git could restore it - but the pattern is the same and
# a truncated binary in the working tree is still a broken campaign.
# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT || exit 1
trap staged_cleanup EXIT
staged_new "$OUT" STAGED || exit 1

echo "[build-libfuzzer-driver] compiling"
clang++ -O1 -g -std=c++17 -fsanitize=fuzzer "$SRC" -o "$STAGED"
staged_commit "$STAGED" "$OUT" || exit 1
trap - EXIT

echo "[build-libfuzzer-driver] done"
echo "src: $SRC"
echo "out: $OUT"
