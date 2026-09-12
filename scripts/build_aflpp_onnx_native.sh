#!/usr/bin/env bash
# Builds the native AFL++ ONNX replay binary.
#
# G2: the committed binary was a plain-clang artifact with zero AFL++ instrumentation, so
# Arm C was never coverage-guided even though this script claims an afl-clang-fast++ build.
# The build now verifies its own output and fails if the result carries no instrumentation.
# Set ALLOW_UNINSTRUMENTED=1 only for a deliberate uninstrumented baseline build.
#
# On a host without afl-clang-fast++, build inside the same image the loop runs:
#   docker run --rm -v "$PWD":/work -w /work aflplusplus/aflplusplus \
#     bash -lc 'scripts/build_aflpp_onnx_native.sh'
# Then confirm the tuples AFL++ will actually see:
#   afl-showmap -o /tmp/map.txt -- harnesses/aflpp/onnxruntime_loader_replay seeds/onnx/min.onnx
#   wc -l /tmp/map.txt   # must be > 0
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORKDIR="${WORKDIR:-$PWD}"
PROJECT_ROOT="${PROJECT_ROOT:-$WORKDIR}"
ORT_VER="${ORT_VER:-v1.23.2}"
ORT_SRC="${ORT_SRC:-$PROJECT_ROOT/data/targets/onnxruntime/$ORT_VER/onnxruntime-1.23.2}"
CONFIG="${CONFIG:-RelWithDebInfo}"
SRC="${SRC:-$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer.cc}"
OUT="${OUT:-$PROJECT_ROOT/harnesses/aflpp/onnxruntime_loader_replay}"
AFL_CXX="${AFL_CXX:-afl-clang-fast++}"
COVERAGE_FLAGS="${COVERAGE_FLAGS:-}"
EXTRA_CXXFLAGS="${AFLPP_EXTRA_CXXFLAGS:-}"

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
  echo "[build-aflpp-onnx-native] libonnxruntime.so not found under $ORT_SRC/build" >&2
  echo "[build-aflpp-onnx-native] set SO_DIR or build ONNX Runtime first" >&2
  exit 1
fi

SO="$SO_DIR/libonnxruntime.so"
INCLUDE_DIR="$ORT_SRC/include/onnxruntime/core/session"

if ! command -v "$AFL_CXX" >/dev/null 2>&1 && [[ ! -x "$AFL_CXX" ]]; then
  echo "[build-aflpp-onnx-native] compiler not found: $AFL_CXX" >&2
  echo "[build-aflpp-onnx-native] run inside aflplusplus/aflplusplus or set AFL_CXX" >&2
  exit 1
fi

[[ -f "$SRC" ]] || { echo "[build-aflpp-onnx-native] source not found: $SRC" >&2; exit 1; }
[[ -f "$SO" ]] || { echo "[build-aflpp-onnx-native] shared library not found: $SO" >&2; exit 1; }
[[ -f "$INCLUDE_DIR/onnxruntime_cxx_api.h" ]] || { echo "[build-aflpp-onnx-native] header not found: $INCLUDE_DIR/onnxruntime_cxx_api.h" >&2; exit 1; }

# R49/R55: never compile straight onto the operational replay. See
# scripts/lib/staged_install.sh for the reasoning and the contract.
# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT || exit 1
trap staged_cleanup EXIT
staged_new "$OUT" STAGED || exit 1

echo "[build-aflpp-onnx-native] compiling"
"$AFL_CXX" -std=c++17 -O1 -g \
  -DONNX_FUZZ_STANDALONE \
  $COVERAGE_FLAGS \
  $EXTRA_CXXFLAGS \
  -I"$INCLUDE_DIR" \
  "$SRC" \
  -L"$SO_DIR" -lonnxruntime -Wl,-rpath,"$SO_DIR" \
  -o "$STAGED"

# shellcheck source=lib/engine_mode.sh
. "$SCRIPT_DIR/lib/engine_mode.sh"

if has_afl_instrumentation "$STAGED"; then
  INSTRUMENTATION=instrumented
elif [[ "${ALLOW_UNINSTRUMENTED:-0}" == "1" ]]; then
  INSTRUMENTATION=uninstrumented
  echo "[build-aflpp-onnx-native] WARN: the new replay has no AFL++/sancov instrumentation (ALLOW_UNINSTRUMENTED=1)" >&2
else
  echo "[build-aflpp-onnx-native] the new replay has no AFL++/sancov instrumentation; $OUT left unchanged" >&2
  echo "[build-aflpp-onnx-native] AFL_CXX=$AFL_CXX did not instrument; build inside aflplusplus/aflplusplus" >&2
  echo "[build-aflpp-onnx-native] (set ALLOW_UNINSTRUMENTED=1 for a deliberate baseline build)" >&2
  exit 1
fi

staged_commit "$STAGED" "$OUT" || exit 1
trap - EXIT

echo "[build-aflpp-onnx-native] done"
echo "src: $SRC"
echo "out: $OUT"
echo "so: $SO"
echo "instrumentation: $INSTRUMENTATION"
