#!/usr/bin/env bash
# Q09: keep the three pre-existing format consumers green before promotion.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"

run_gate() {
  local script="$1"
  local marker="$2"
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/openvino-q09.XXXXXX")"
  if bash "$PROJECT_ROOT/scripts/$script" >"$output" 2>&1 \
    && grep -Fqx "$marker" "$output"; then
    cat "$output"
    rm -f -- "$output"
    return 0
  fi
  cat "$output" >&2
  rm -f -- "$output"
  return 1
}

run_gate check_target_registry_consumers.sh \
  '[target-registry-consumers] pass=28 fail=0'
run_gate check_format_dispatch.sh '[format-dispatch] pass=92 fail=0'
printf '[openvino-qualification-regressions] pass=2 fail=0\n'
