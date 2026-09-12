#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORKDIR="${WORKDIR:-$PWD}"
PROJECT_ROOT="${PROJECT_ROOT:-$WORKDIR}"
ORT_VER="${ORT_VER:-v1.23.2}"
ORT_SRC="${ORT_SRC:-$PROJECT_ROOT/data/targets/onnxruntime/$ORT_VER/onnxruntime-1.23.2}"
CONFIG="${CONFIG:-RelWithDebInfo}"
SRC="${SRC:-$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer.cc}"
OUT="${OUT:-$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer}"
STANDALONE_OUT="${STANDALONE_OUT:-$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_replay}"
FUZZ_SANITIZERS="${FUZZ_SANITIZERS:-fuzzer}"
STANDALONE_SANITIZERS="${STANDALONE_SANITIZERS:-}"
COVERAGE_FLAGS="${COVERAGE_FLAGS:-}"
CLANG_BUNDLE="$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin/clang++"

if [[ -z "${CLANGXX:-}" ]]; then
  if [[ -x "$CLANG_BUNDLE" ]]; then
    CLANGXX="$CLANG_BUNDLE"
  else
    CLANGXX="clang++"
  fi
fi

if [[ -z "${SO_DIR:-}" ]]; then
  for candidate in \
    "$ORT_SRC/build/Linux/Release" \
    "$ORT_SRC/build/Linux/$CONFIG" \
    "$ORT_SRC/build/cov-o0/$CONFIG" \
    "$ORT_SRC/build/cov/$CONFIG"
  do
    if [[ -f "$candidate/libonnxruntime.so" ]]; then
      SO_DIR="$candidate"
      break
    fi
  done
fi

if [[ -z "${SO_DIR:-}" ]]; then
  echo "[build-libfuzzer-onnx-native] libonnxruntime.so not found under $ORT_SRC/build" >&2
  echo "[build-libfuzzer-onnx-native] set SO_DIR or build ONNX Runtime first" >&2
  exit 1
fi

SO="$SO_DIR/libonnxruntime.so"
INCLUDE_DIR="$ORT_SRC/include/onnxruntime/core/session"

if ! command -v "$CLANGXX" >/dev/null 2>&1 && [[ ! -x "$CLANGXX" ]]; then
  echo "[build-libfuzzer-onnx-native] clang++ not found: $CLANGXX" >&2
  exit 1
fi

[[ -f "$SRC" ]] || { echo "[build-libfuzzer-onnx-native] source not found: $SRC" >&2; exit 1; }
[[ -f "$SO" ]] || { echo "[build-libfuzzer-onnx-native] shared library not found: $SO" >&2; exit 1; }
[[ -f "$INCLUDE_DIR/onnxruntime_cxx_api.h" ]] || { echo "[build-libfuzzer-onnx-native] header not found: $INCLUDE_DIR/onnxruntime_cxx_api.h" >&2; exit 1; }

if [[ "$SO_DIR" == *"/build/cov/"* || "$SO_DIR" == *"/build/cov-o0/"* ]]; then
  COVERAGE_FLAGS="${COVERAGE_FLAGS:--fprofile-instr-generate -fcoverage-mapping}"
fi

# R55: both outputs go through the shared staging helper - a link failure used to
# unlink the operational binary, which .gitignore keeps untracked.
# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT || exit 1
trap staged_cleanup EXIT
staged_new "$OUT" STAGED || exit 1

echo "[build-libfuzzer-onnx-native] compiling"
"$CLANGXX" -std=c++17 -O1 -g \
  -fsanitize="$FUZZ_SANITIZERS" \
  $COVERAGE_FLAGS \
  -I"$INCLUDE_DIR" \
  "$SRC" \
  -L"$SO_DIR" -lonnxruntime -Wl,-rpath,"$SO_DIR" \
  -o "$STAGED"

if [[ "$SO_DIR" == *"/build/cov/"* || "$SO_DIR" == *"/build/cov-o0/"* ]]; then
  echo "note: this ORT build is source-coverage instrumented; native crash capture works, but ORT edge-guided libFuzzer coverage requires a sanitizer-coverage ORT build"
fi

if [[ "${BUILD_STANDALONE:-0}" == "1" ]]; then
  staged_target STANDALONE_OUT || exit 1
  staged_new "$STANDALONE_OUT" STAGED_STANDALONE || exit 1
  standalone_sanitize_args=()
  if [[ -n "$STANDALONE_SANITIZERS" ]]; then
    standalone_sanitize_args=(-fsanitize="$STANDALONE_SANITIZERS")
  fi
  echo "[build-libfuzzer-onnx-native] compiling standalone replay"
  "$CLANGXX" -std=c++17 -O1 -g \
    -DONNX_FUZZ_STANDALONE \
    "${standalone_sanitize_args[@]}" \
    $COVERAGE_FLAGS \
    -I"$INCLUDE_DIR" \
    "$SRC" \
    -L"$SO_DIR" -lonnxruntime -Wl,-rpath,"$SO_DIR" \
    -o "$STAGED_STANDALONE"
fi

# Both binaries exist before either is installed. The standalone replay is compiled with
# its own -fsanitize set, so it can fail on its own; installing the fuzzer first would
# leave a new fuzzer beside the previous replay, and the crash oracle would then be a
# different build from the fuzzer that found the crash. Not fully atomic either: a second
# staged_commit that fails still leaves the first installed.
staged_commit "$STAGED" "$OUT" || exit 1
if [[ "${BUILD_STANDALONE:-0}" == "1" ]]; then
  staged_commit "$STAGED_STANDALONE" "$STANDALONE_OUT" || exit 1
fi

# Reported after the install, not before it: the old code's `-o "$OUT"` made the banner
# true at that point, staging does not.
echo "[build-libfuzzer-onnx-native] done"
echo "src: $SRC"
echo "out: $OUT"
echo "so: $SO"
if [[ "${BUILD_STANDALONE:-0}" == "1" ]]; then
  echo "standalone_out: $STANDALONE_OUT"
fi

# Last: the conditional standalone block above stages a second binary, so clearing the
# trap before it would leak that staging file into harnesses/libfuzzer/ when its link fails.
trap - EXIT
