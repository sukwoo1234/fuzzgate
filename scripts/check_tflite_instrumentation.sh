#!/usr/bin/env bash
# TFL-05: reject driver-only libFuzzer evidence and require source coverage from
# the pinned TensorFlow Lite target objects across load, allocate, and access.
set -u

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TARGET_ROOT="${TFLITE_TARGET_ROOT:-$PROJECT_ROOT/data/targets/tflite/v2.20.0}"
GUIDED_BUILD="${TFLITE_GUIDED_BUILD_DIR:-$TARGET_ROOT/build/guided-cmake}"
COVERAGE_BUILD="${TFLITE_COVERAGE_BUILD_DIR:-$TARGET_ROOT/build/coverage-cmake}"
GUIDED_LIB="${TFLITE_GUIDED_LIBRARY:-$GUIDED_BUILD/tensorflow-lite/libtensorflow-lite.a}"
GUIDED_FUZZER="${TFLITE_GUIDED_FUZZER:-$GUIDED_BUILD/tflite_loader_fuzzer}"
COVERAGE_LIB="${TFLITE_COVERAGE_LIBRARY:-$COVERAGE_BUILD/tensorflow-lite/libtensorflow-lite.a}"
COVERAGE_REPLAY="${TFLITE_COVERAGE_REPLAY:-$COVERAGE_BUILD/tflite_loader_replay}"
NORMAL_LIB="${TFLITE_NORMAL_LIBRARY:-$TARGET_ROOT/build/cmake/tensorflow-lite/libtensorflow-lite.a}"
FIXTURE="${TFLITE_FIXTURE:-$TARGET_ROOT/fixtures/add.tflite}"
GUIDED_BUILD_SCRIPT="$PROJECT_ROOT/scripts/build_tflite_guided.sh"
COVERAGE_BUILD_SCRIPT="$PROJECT_ROOT/scripts/build_coverage_tflite.sh"
COVERAGE_RUNNER="$PROJECT_ROOT/scripts/run_coverage_tflite.sh"
NM="${NM:-$(command -v nm || true)}"

PASS=0
FAIL=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tool-tflite-instrumentation.XXXXXX")" || exit 2
trap 'rm -rf -- "$WORK"' EXIT

ok() { PASS=$((PASS + 1)); printf '[tflite-instrumentation] ok: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '[tflite-instrumentation] fail: %s\n' "$1" >&2; }

for pair in \
  "guided build:$GUIDED_BUILD_SCRIPT" \
  "coverage build:$COVERAGE_BUILD_SCRIPT" \
  "coverage runner:$COVERAGE_RUNNER"
do
  label="${pair%%:*}"
  path="${pair#*:}"
  if [[ -f "$path" ]]; then
    ok "$label script exists"
  else
    bad "$label script is missing: $path"
  fi
done

if [[ ! -x "$NM" ]]; then
  bad "nm is unavailable; target-object instrumentation cannot be verified"
elif [[ ! -f "$NORMAL_LIB" ]]; then
  bad "normal target library is missing: $NORMAL_LIB"
else
  normal_hooks=$("$NM" -A --undefined-only "$NORMAL_LIB" 2>/dev/null \
    | grep -c '__sanitizer_cov_' || true)
  if [[ "$normal_hooks" -eq 0 ]]; then
    ok "negative control confirms the normal target library is driver-only"
  else
    bad "negative control unexpectedly has target sanitizer-coverage hooks: $normal_hooks"
  fi
fi

if [[ ! -x "$NM" || ! -f "$GUIDED_LIB" ]]; then
  bad "guided target library is unavailable: $GUIDED_LIB"
else
  guided_hooks=$("$NM" -A --undefined-only "$GUIDED_LIB" 2>/dev/null \
    | grep -c '__sanitizer_cov_' || true)
  guided_objects=$("$NM" -A --undefined-only "$GUIDED_LIB" 2>/dev/null \
    | grep '__sanitizer_cov_' | sed -E 's/:[^:]+$//' | sort -u | wc -l)
  if [[ "$guided_hooks" -gt 0 && "$guided_objects" -gt 0 ]]; then
    ok "pinned TensorFlow Lite archive has guided hooks ($guided_hooks hooks, $guided_objects objects)"
  else
    bad "guided archive has no target-object sanitizer-coverage evidence"
  fi
fi

if [[ ! -x "$GUIDED_FUZZER" || ! -f "$FIXTURE" ]]; then
  bad "guided fuzzer or fixture is unavailable"
else
  "$GUIDED_FUZZER" -runs=1 -max_len=16777216 "$FIXTURE" >"$WORK/guided.log" 2>&1
  guided_rc=$?
  guided_counters=$(sed -n 's/.*(\([0-9][0-9]*\) inline 8-bit counters).*/\1/p' \
    "$WORK/guided.log" | head -1)
  if [[ "$guided_rc" -eq 0 && "${guided_counters:-0}" -gt 29 ]]; then
    ok "guided engine executes target code with more than the 29 driver-only counters"
  else
    bad "guided engine did not prove target-object guidance (rc=$guided_rc counters=${guided_counters:-missing})"
  fi
fi

if [[ ! -x "$NM" || ! -f "$COVERAGE_LIB" ]]; then
  bad "coverage target library is unavailable: $COVERAGE_LIB"
else
  profile_symbols=$("$NM" -A "$COVERAGE_LIB" 2>/dev/null | grep -c '__profc_' || true)
  if [[ "$profile_symbols" -gt 0 ]]; then
    ok "pinned TensorFlow Lite archive has source-profile counters"
  else
    bad "coverage archive has no target-object source-profile counters"
  fi
fi

if [[ ! -x "$COVERAGE_REPLAY" || ! -f "$COVERAGE_RUNNER" || ! -f "$FIXTURE" ]]; then
  bad "coverage replay, runner, or fixture is unavailable"
else
  mkdir -p "$WORK/corpus" "$WORK/coverage"
  cp -- "$FIXTURE" "$WORK/corpus/add.tflite"
  env PROJECT_ROOT="$PROJECT_ROOT" TFLITE_TARGET_ROOT="$TARGET_ROOT" \
    TFLITE_COVERAGE_BUILD_DIR="$COVERAGE_BUILD" \
    TFLITE_COVERAGE_REPLAY="$COVERAGE_REPLAY" \
    OUT_DIR="$WORK/coverage" CORPUS_DIR="$WORK/corpus" \
    SOURCE_CORPUS_DIR="$WORK/corpus" \
    bash "$COVERAGE_RUNNER" >"$WORK/coverage.log" 2>&1
  coverage_rc=$?
  if [[ "$coverage_rc" -eq 0 && -s "$WORK/coverage/coverage.json" ]] \
      && python3 -B - "$WORK/coverage/coverage.json" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("target") != "tflite":
    raise SystemExit("wrong target")
if document.get("instrumentation") != "llvm-source-cov":
    raise SystemExit("wrong instrumentation")
paths = document.get("required_path_hits")
if paths != {"model_loading": True, "allocation": True, "tensor_access": True}:
    raise SystemExit(f"required path hits missing: {paths!r}")
sources = document.get("measured_sources")
if not isinstance(sources, list) or not sources:
    raise SystemExit("measured target sources missing")
if any("harnesses/tflite/" in source for source in sources):
    raise SystemExit("driver-only source was accepted")
PY
  then
    ok "source coverage proves target loading, allocation, and tensor-access paths"
  else
    bad "source coverage did not prove all required target paths (rc=$coverage_rc)"
    sed -n '1,40p' "$WORK/coverage.log" >&2
  fi
fi

printf '[tflite-instrumentation] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
