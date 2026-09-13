#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
SEED="${SEED:-$PROJECT_ROOT/seeds/onnx/onnx_5_mul_1.onnx}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/data/native-engine-checks/onnx}"
REQUIRE_AFLPP=0

usage() {
  cat <<'EOF'
usage: check_onnx_native_engines.sh [--require-aflpp]

Checks native ONNX fuzz engine plumbing without committing PoCs:
  - builds native libFuzzer ONNX harness
  - builds native standalone replay
  - runs a known-good seed through both
  - when AFL++ tools exist, builds AFL++ native replay and verifies afl-showmap coverage
  - with --require-aflpp, missing AFL++ tools or zero coverage is a hard failure
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-aflpp) REQUIRE_AFLPP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[onnx-native-check] unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

log() {
  echo "[onnx-native-check] $*"
}

fail() {
  echo "[onnx-native-check] fail: $*" >&2
  exit 1
}

[[ -f "$SEED" ]] || fail "seed not found: $SEED"
mkdir -p "$OUT_DIR"

# Build only when the harness is missing, the shape check_safetensors_native_engines.sh
# already uses. Building unconditionally reinstalled harnesses/libfuzzer/onnxruntime_*
# on every run of the check suite: this script observes those binaries, so rewriting
# them is a side effect, and SO_DIR auto-detection can pick a differently instrumented
# build than the one that was originally installed.
LF_FUZZER="$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer"
LF_REPLAY="$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_replay"

if [[ ! -x "$LF_FUZZER" ]]; then
  log "libFuzzer harness missing; building"
  "$PROJECT_ROOT/scripts/build_libfuzzer_onnx_native.sh" >/tmp/onnx-native-libfuzzer-build.log
fi

if [[ ! -x "$LF_REPLAY" ]]; then
  log "standalone replay missing; building"
  BUILD_STANDALONE=1 "$PROJECT_ROOT/scripts/build_libfuzzer_onnx_native.sh" >/tmp/onnx-native-standalone-build.log
fi

log "run libFuzzer fixed-input smoke"
LLVM_PROFILE_FILE="$OUT_DIR/libfuzzer-%p.profraw" \
  "$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer" -runs=1 "$SEED" \
  >"$OUT_DIR/libfuzzer-smoke.log" 2>&1

log "run standalone replay smoke"
LLVM_PROFILE_FILE="$OUT_DIR/replay-%p.profraw" \
  "$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_replay" "$SEED" \
  >"$OUT_DIR/replay-smoke.log" 2>&1

if command -v afl-clang-fast++ >/dev/null 2>&1 && command -v afl-showmap >/dev/null 2>&1; then
  log "build AFL++ native replay"
  "$PROJECT_ROOT/scripts/build_aflpp_onnx_native.sh" >"$OUT_DIR/aflpp-build.log" 2>&1

  log "run afl-showmap coverage smoke"
  AFL_MAP="$OUT_DIR/afl-showmap.txt"
  afl-showmap -q -o "$AFL_MAP" -- "$PROJECT_ROOT/harnesses/aflpp/onnxruntime_loader_replay" "$SEED" \
    >"$OUT_DIR/afl-showmap.log" 2>&1
  tuples="$(wc -l < "$AFL_MAP" | tr -d ' ')"
  if [[ "$tuples" -le 0 ]]; then
    fail "afl-showmap produced zero tuples"
  fi
  log "afl-showmap tuples=$tuples"
else
  msg="AFL++ tools missing: afl-clang-fast++ and/or afl-showmap"
  if [[ "$REQUIRE_AFLPP" -eq 1 ]]; then
    fail "$msg"
  fi
  log "skip AFL++ proof: $msg"
fi

log "done: $OUT_DIR"
