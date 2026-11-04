#!/usr/bin/env bash
# Q09: keep existing registry and format dispatch consumers green.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"

run_gate() {
  local script="$1"
  local marker="$2"
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/hdf5-q09.XXXXXX")"
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
run_gate check_onnx_coverage_source_scope.sh \
  '[onnx-coverage-source-scope] pass=3 fail=0'
run_gate check_gguf_oracle_verdicts.sh \
  '[gguf-oracle-verdicts] pass=7 fail=0'
run_gate check_safetensors_engine_check.sh \
  '[st-engine-check] 13/13 passed'
printf '[hdf5-qualification-regressions] pass=5 fail=0\n'
