#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

check_refusal() {
  local name="$1" workdir="$2" data_dir="$3" log_dir="$4"
  local rc=0
  timeout 2 env WORKDIR="$workdir" DATA_DIR="$data_dir" LOG_DIR="$log_dir" \
    TOOL_BIN=/bin/false PROJECT_ROOT="$PROJECT_ROOT" \
    bash "$PROJECT_ROOT/scripts/check_ui_routes.sh" \
    >"$WORK/$name.stdout" 2>"$WORK/$name.stderr" || rc=$?
  [[ "$rc" -eq 1 ]] || {
    echo "[ui-guard-test] $name did not refuse immediately (rc=$rc)" >&2
    exit 1
  }
  grep -Fq '[FAIL] the check must not' "$WORK/$name.stderr" || {
    echo "[ui-guard-test] $name did not name the unsafe path" >&2
    exit 1
  }
}

root="$WORK/nested"
mkdir -p "$root"
check_refusal nested "$root" "$root/data/new" "$WORK/log-nested"
[[ ! -e "$root/data" ]] || {
  echo '[ui-guard-test] nested data path was created before refusal' >&2
  exit 1
}

root="$WORK/alias"
mkdir -p "$root/data"
check_refusal alias "$root" "$root/./data" "$WORK/log-alias"
[[ -z "$(find "$root/data" -mindepth 1 -print -quit)" ]] || {
  echo '[ui-guard-test] path alias wrote to operator data' >&2
  exit 1
}

root="$WORK/log-symlink"
mkdir -p "$root/data"
ln -s data "$root/log-alias"
check_refusal log-symlink "$root" "$WORK/clean-data" "$root/log-alias"
[[ -z "$(find "$root/data" -mindepth 1 -print -quit)" ]] || {
  echo '[ui-guard-test] log symlink wrote to operator data' >&2
  exit 1
}

echo '[ui-guard-test] PASS: nested, aliased, and symlinked operator data paths refused before writes'
