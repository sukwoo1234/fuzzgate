#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
BUILDER="$PROJECT_ROOT/scripts/build_openvino_profiles.sh"
WORK="$(mktemp -d /tmp/openvino-build-safety-XXXXXX)"
trap 'rm -rf -- "$WORK"' EXIT

pass=0
fail=0

expect_rejection() {
  local label="$1"
  local target_root="$2"
  local marker="$3"
  local log="$WORK/$label.log"
  local rc=0

  OPENVINO_TARGET_ROOT="$target_root" bash "$BUILDER" >"$log" 2>&1 || rc=$?
  if [[ "$rc" -ne 0 ]] && grep -Fq -- "$marker" "$log"; then
    printf '[openvino-build-safety] PASS %s\n' "$label"
    pass=$((pass + 1))
  else
    printf '[openvino-build-safety] FAIL %s rc=%d marker=%q\n' \
      "$label" "$rc" "$marker" >&2
    tail -n 20 "$log" >&2 || true
    fail=$((fail + 1))
  fi
}

mkdir "$WORK/real-target"
ln -s -- "$WORK/real-target" "$WORK/linked-target"

expect_rejection relative-target relative-target \
  'OPENVINO_TARGET_ROOT must be absolute'
expect_rejection symlink-target "$WORK/linked-target" \
  'OPENVINO_TARGET_ROOT must not be a symlink'
expect_rejection symlink-target-trailing-slash "$WORK/linked-target/" \
  'OPENVINO_TARGET_ROOT must not be a symlink'

printf '[openvino-build-safety] pass=%d fail=%d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
