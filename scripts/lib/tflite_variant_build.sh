#!/usr/bin/env bash
# Shared implementation for the TFL-05 guided and source-coverage builds.
# The variants reuse only the already pinned source/dependency checkouts from
# TFL-01; every object is rebuilt in a separate CMake tree with its own flags.
set -euo pipefail

MODE="${1:-}"
if [[ "$MODE" != guided && "$MODE" != coverage ]]; then
  printf 'usage: %s guided|coverage\n' "$0" >&2
  exit 2
fi
shift
[[ $# -eq 0 ]] || { printf '[tflite-%s-build] unexpected arguments\n' "$MODE" >&2; exit 2; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/../.." && pwd -P)}"
TARGET_ROOT="${TFLITE_TARGET_ROOT:-$PROJECT_ROOT/data/targets/tflite/v2.20.0}"
SOURCE_DIR="${TFLITE_SOURCE_DIR:-$TARGET_ROOT/build/source}"
BASE_BUILD="${TFLITE_BASE_BUILD_DIR:-$TARGET_ROOT/build/cmake}"
ARCHIVE="${TFLITE_ARCHIVE:-$TARGET_ROOT/source/v2.20.0.tar.gz}"
PATCH="$PROJECT_ROOT/patches/tflite_v2.20.0_xnnpack_off.cmake.patch"
FIXTURE="${TFLITE_FIXTURE:-$TARGET_ROOT/fixtures/add.tflite}"
JOBS="${JOBS:-4}"
CLANG_BUNDLE_DIR="${CLANG_BUNDLE_DIR:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin}"
CLANG="${CLANG:-$CLANG_BUNDLE_DIR/clang}"
CLANGXX="${CLANGXX:-$CLANG_BUNDLE_DIR/clang++}"
LLVM_NM="${LLVM_NM:-$CLANG_BUNDLE_DIR/llvm-nm}"
LLVM_OBJDUMP="${LLVM_OBJDUMP:-$CLANG_BUNDLE_DIR/llvm-objdump}"
CMAKE="${CMAKE:-$(command -v cmake || true)}"
NINJA="${NINJA:-$(command -v ninja || true)}"
TFLITE_SHA256="a640d1f97be316a09301dfc9347e3d929ad4d9a2336e3ca23c32c93b0ff7e5d0"
TFLITE_SIZE=84813578
TF_RELEASE_FLAGS="-DTF_MAJOR_VERSION=2 -DTF_MINOR_VERSION=20 -DTF_PATCH_VERSION=0 -DTF_VERSION_SUFFIX=''"

log() { printf '[tflite-%s-build] %s\n' "$MODE" "$*"; }
fail() { printf '[tflite-%s-build] fail: %s\n' "$MODE" "$*" >&2; exit 1; }

case "$TARGET_ROOT" in
  ""|/|"$PROJECT_ROOT"|"${HOME:-__unset_home__}") fail "unsafe TFLITE_TARGET_ROOT: $TARGET_ROOT" ;;
esac
for tool in "$CLANG" "$CLANGXX" "$LLVM_NM" "$LLVM_OBJDUMP" "$CMAKE" "$NINJA"; do
  [[ -x "$tool" ]] || fail "required tool is unavailable: $tool"
done
[[ -f "$ARCHIVE" ]] || fail "pinned source archive is missing: $ARCHIVE"
[[ "$(sha256sum "$ARCHIVE" | cut -d' ' -f1)" == "$TFLITE_SHA256" ]] \
  || fail "source archive hash mismatch"
[[ "$(stat -c '%s' "$ARCHIVE")" == "$TFLITE_SIZE" ]] \
  || fail "source archive size mismatch"
[[ -f "$PATCH" ]] || fail "pinned CMake patch is missing: $PATCH"
[[ -f "$SOURCE_DIR/.tool-source-sha256" ]] \
  && [[ "$(cat "$SOURCE_DIR/.tool-source-sha256")" == "$TFLITE_SHA256" ]] \
  || fail "pinned source tree is not prepared; run scripts/build_tflite_profiles.sh first"
[[ -f "$SOURCE_DIR/.tool-patch-sha256" ]] \
  && [[ "$(cat "$SOURCE_DIR/.tool-patch-sha256")" == "$(sha256sum "$PATCH" | cut -d' ' -f1)" ]] \
  || fail "source tree does not carry the pinned patch"
[[ -f "$SOURCE_DIR/tensorflow/lite/CMakeLists.txt" ]] \
  || fail "prepared source tree has no TensorFlow Lite CMake project"
[[ -f "$FIXTURE" ]] || fail "official ADD fixture is missing: $FIXTURE"

deps=(abseil-cpp cpuinfo eigen farmhash fft2d flatbuffers fp16_headers gemmlowp ml_dtypes neon2sse protobuf ruy)
fetch_args=()
for dep in "${deps[@]}"; do
  dep_dir="$BASE_BUILD/$dep"
  [[ -d "$dep_dir" ]] \
    || fail "pinned dependency checkout is missing: $dep_dir; run scripts/build_tflite_profiles.sh first"
  cache_name="$(printf '%s' "$dep" | tr '[:lower:]' '[:upper:]')"
  fetch_args+=("-DFETCHCONTENT_SOURCE_DIR_${cache_name}=$dep_dir")
done

if [[ "$MODE" == guided ]]; then
  BUILD_DIR="${TFLITE_GUIDED_BUILD_DIR:-$TARGET_ROOT/build/guided-cmake}"
  FLAGS="-O1 -g -DNDEBUG $TF_RELEASE_FLAGS -fsanitize=fuzzer-no-link"
  LINK_FLAGS=""
  BUILD_TARGET=tflite_loader_fuzzer
  BINARY="$BUILD_DIR/tflite_loader_fuzzer"
  MANIFEST="$TARGET_ROOT/guided-instrumentation.json"
else
  BUILD_DIR="${TFLITE_COVERAGE_BUILD_DIR:-$TARGET_ROOT/build/coverage-cmake}"
  FLAGS="-O1 -g -DNDEBUG $TF_RELEASE_FLAGS -fprofile-instr-generate -fcoverage-mapping"
  LINK_FLAGS="-fprofile-instr-generate"
  BUILD_TARGET=tflite_loader_replay
  BINARY="$BUILD_DIR/tflite_loader_replay"
  MANIFEST="$TARGET_ROOT/coverage-instrumentation.json"
fi
LIBRARY="$BUILD_DIR/tensorflow-lite/libtensorflow-lite.a"
COMMANDS="$TARGET_ROOT/$MODE-link-commands.txt"

mkdir -p -- "$BUILD_DIR"
log "configuring isolated $MODE object tree"
"$CMAKE" -G Ninja \
  -S "$PROJECT_ROOT/harnesses/tflite" \
  -B "$BUILD_DIR" \
  -DTENSORFLOW_SOURCE_DIR="$SOURCE_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CLANG" \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="$FLAGS" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="$FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO="$LINK_FLAGS" \
  -DFETCHCONTENT_UPDATES_DISCONNECTED=ON \
  "${fetch_args[@]}" \
  -DBUILD_SHARED_LIBS=OFF \
  -DTFLITE_ENABLE_EXTERNAL_DELEGATE=OFF \
  -DTFLITE_ENABLE_GPU=OFF \
  -DTFLITE_ENABLE_METAL=OFF \
  -DTFLITE_ENABLE_NNAPI=OFF \
  -DTFLITE_ENABLE_RUY=OFF \
  -DTFLITE_ENABLE_XNNPACK=OFF \
  -DTFLITE_KERNEL_TEST=OFF \
  >"$TARGET_ROOT/$MODE-configure.log" 2>&1 \
  || fail "CMake configure failed; see $TARGET_ROOT/$MODE-configure.log"

for setting in \
  'BUILD_SHARED_LIBS:UNINITIALIZED=OFF' \
  'TFLITE_ENABLE_EXTERNAL_DELEGATE:BOOL=OFF' \
  'TFLITE_ENABLE_GPU:BOOL=OFF' \
  'TFLITE_ENABLE_METAL:BOOL=OFF' \
  'TFLITE_ENABLE_NNAPI:BOOL=OFF' \
  'TFLITE_ENABLE_RUY:BOOL=OFF' \
  'TFLITE_ENABLE_XNNPACK:BOOL=OFF' \
  'TFLITE_KERNEL_TEST:BOOL=OFF'
do
  grep -Fqx -- "$setting" "$BUILD_DIR/CMakeCache.txt" \
    || fail "configured cache does not contain $setting"
done

log "building $BUILD_TARGET (jobs=$JOBS)"
"$CMAKE" --build "$BUILD_DIR" --target "$BUILD_TARGET" -j"$JOBS" \
  >"$TARGET_ROOT/$MODE-build.log" 2>&1 \
  || fail "build failed; see $TARGET_ROOT/$MODE-build.log"
[[ -f "$LIBRARY" ]] || fail "target archive was not produced: $LIBRARY"
[[ -x "$BINARY" ]] || fail "instrumented binary was not produced: $BINARY"
"$NINJA" -C "$BUILD_DIR" -t commands "$BUILD_TARGET" >"$COMMANDS"
grep -Fq -- "${FLAGS##* }" "$COMMANDS" \
  || fail "recorded compile commands do not contain the requested instrumentation flag"

if [[ "$MODE" == guided ]]; then
  NM_LIST="$TARGET_ROOT/guided-target-nm.txt"
  "$LLVM_NM" -A --undefined-only "$LIBRARY" >"$NM_LIST" 2>/dev/null \
    || fail "llvm-nm could not read $LIBRARY"
  hook_count="$(grep -c '__sanitizer_cov_' "$NM_LIST" || true)"
  object_count="$(awk -F: '/__sanitizer_cov_/ {print $1 ":" $2}' "$NM_LIST" | sort -u | wc -l)"
  [[ "$hook_count" -gt 0 && "$object_count" -gt 0 ]] \
    || fail "target archive has no sanitizer-coverage hooks"
  "$BINARY" -runs=1 -max_len=16777216 "$FIXTURE" >"$TARGET_ROOT/guided-smoke.log" 2>&1 \
    || fail "guided fuzzer smoke failed; see $TARGET_ROOT/guided-smoke.log"
  counter_count="$(sed -n 's/.*(\([0-9][0-9]*\) inline 8-bit counters).*/\1/p' \
    "$TARGET_ROOT/guided-smoke.log" | head -1)"
  [[ "${counter_count:-0}" -gt 29 ]] \
    || fail "guided binary exposes only ${counter_count:-0} counters; driver-only baseline is 29"
  detail_a="$hook_count"
  detail_b="$object_count"
  detail_c="$counter_count"
else
  NM_LIST="$TARGET_ROOT/coverage-target-nm.txt"
  SEC_LIST="$TARGET_ROOT/coverage-target-sections.txt"
  "$LLVM_NM" -A "$LIBRARY" >"$NM_LIST" 2>/dev/null \
    || fail "llvm-nm could not read $LIBRARY"
  "$LLVM_OBJDUMP" -h "$LIBRARY" >"$SEC_LIST" 2>/dev/null \
    || fail "llvm-objdump could not read $LIBRARY"
  profile_count="$(grep -c '__profc_' "$NM_LIST" || true)"
  covmap_count="$(grep -c '__llvm_covmap' "$SEC_LIST" || true)"
  [[ "$profile_count" -gt 0 ]] || fail "target archive has no source-profile counters"
  [[ "$covmap_count" -gt 0 ]] || fail "target archive has no coverage mapping sections"
  profile_probe="$TARGET_ROOT/coverage-build-probe.profraw"
  LLVM_PROFILE_FILE="$profile_probe" "$BINARY" "$FIXTURE" \
    >"$TARGET_ROOT/coverage-smoke.log" 2>&1 \
    || fail "coverage replay smoke failed; see $TARGET_ROOT/coverage-smoke.log"
  [[ -s "$profile_probe" ]] || fail "coverage replay emitted no non-empty raw profile"
  detail_a="$profile_count"
  detail_b="$covmap_count"
  detail_c="$(stat -c '%s' "$profile_probe")"
fi

manifest_tmp="$(mktemp "$TARGET_ROOT/.${MODE}-instrumentation.XXXXXX")" \
  || fail "could not create manifest staging file"
python3 -B - "$manifest_tmp" "$MODE" "$ARCHIVE" "$LIBRARY" "$BINARY" \
  "$CLANGXX" "$COMMANDS" "$FLAGS" "$detail_a" "$detail_b" "$detail_c" <<'PY'
import hashlib
import json
import os
import subprocess
import sys

(out, mode, archive, library, binary, compiler, commands, flags,
 detail_a, detail_b, detail_c) = sys.argv[1:]

def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

document = {
    "schema_version": "1",
    "target": "tflite",
    "target_version": "v2.20.0",
    "mode": mode,
    "source_archive_sha256": sha(archive),
    "compiler": {
        "path": os.path.realpath(compiler),
        "version": subprocess.check_output([compiler, "--version"], text=True).splitlines()[0],
        "sha256": sha(os.path.realpath(compiler)),
    },
    "compile_flags": flags.split(),
    "compile_commands_sha256": sha(commands),
    "target_archive": os.path.realpath(library),
    "target_archive_sha256": sha(library),
    "binary": os.path.realpath(binary),
    "binary_sha256": sha(binary),
}
if mode == "guided":
    document.update({
        "sanitizer_coverage_hooks": int(detail_a),
        "instrumented_target_objects": int(detail_b),
        "loaded_inline_counters": int(detail_c),
        "driver_only_counter_baseline": 29,
    })
else:
    document.update({
        "profile_counter_symbols": int(detail_a),
        "coverage_mapping_sections": int(detail_b),
        "probe_profile_bytes": int(detail_c),
    })
with open(out, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
mv -f -- "$manifest_tmp" "$MANIFEST"
log "verified target objects and wrote $MANIFEST"
printf 'binary=%s\nlibrary=%s\nmanifest=%s\n' "$BINARY" "$LIBRARY" "$MANIFEST"
