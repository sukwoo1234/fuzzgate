#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
BUILDER="$PROJECT_ROOT/scripts/build_hdf5_profiles.sh"
WORK="$(mktemp -d /tmp/hdf5-build-safety-XXXXXX)"
trap 'rm -rf -- "$WORK"' EXIT

pass=0
fail=0

expect_rejection() {
  local label="$1"
  local target_root="$2"
  local marker="$3"
  local log="$WORK/$label.log"
  local rc=0

  HDF5_TARGET_ROOT="$target_root" bash "$BUILDER" >"$log" 2>&1 || rc=$?
  if [[ "$rc" -ne 0 ]] && grep -Fq -- "$marker" "$log"; then
    printf '[hdf5-build-safety] PASS %s\n' "$label"
    pass=$((pass + 1))
  else
    printf '[hdf5-build-safety] FAIL %s rc=%d marker=%q\n' \
      "$label" "$rc" "$marker" >&2
    tail -n 20 "$log" >&2 || true
    fail=$((fail + 1))
  fi
}

expect_project_root_override_rejection() {
  local log="$WORK/project-root-override.log"
  local rc=0
  PROJECT_ROOT=/dev/shm \
    HDF5_TARGET_ROOT=/dev/shm/data/targets/hdf5-weights/2.2.0 \
    bash "$BUILDER" >"$log" 2>&1 || rc=$?
  if [[ "$rc" -ne 0 ]] && \
    grep -Fq -- 'HDF5_TARGET_ROOT must equal the dedicated project target root' "$log"; then
    printf '[hdf5-build-safety] PASS project-root-override\n'
    pass=$((pass + 1))
  else
    printf '[hdf5-build-safety] FAIL project-root-override rc=%d\n' "$rc" >&2
    tail -n 20 "$log" >&2 || true
    fail=$((fail + 1))
  fi
}

mkdir "$WORK/real-target"
ln -s -- "$WORK/real-target" "$WORK/linked-target"
mkdir "$WORK/real-parent" "$WORK/child-path-target" "$WORK/external-build"
ln -s -- "$WORK/real-parent" "$WORK/linked-parent"
ln -s -- "$WORK/external-build" "$WORK/child-path-target/build"

expect_rejection relative-target relative-target \
  'HDF5_TARGET_ROOT must be absolute'
expect_rejection shallow-temp-root /tmp \
  'unsafe HDF5_TARGET_ROOT'
expect_rejection broad-dev-shm-root /dev/shm/hdf5-weights/2.2.0 \
  'HDF5_TARGET_ROOT must equal the dedicated project target root'
expect_rejection broad-mnt-root /mnt/c/hdf5-weights/2.2.0 \
  'HDF5_TARGET_ROOT must equal the dedicated project target root'
expect_project_root_override_rejection
expect_rejection symlink-target "$WORK/linked-target" \
  'HDF5_TARGET_ROOT must not be a symlink'
expect_rejection symlink-target-trailing-slash "$WORK/linked-target/" \
  'HDF5_TARGET_ROOT must not be a symlink'
expect_rejection intermediate-symlink "$WORK/linked-parent/target" \
  'HDF5_TARGET_ROOT must not traverse a symlink'
expect_rejection owned-build-symlink "$WORK/child-path-target" \
  'HDF5 target-owned path must not be a symlink'

printf '[hdf5-build-safety] pass=%d fail=%d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
