#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
LLAMA_VER="${LLAMA_VER:-b7921}"
TARGET_DIR="${TARGET_DIR:-$PROJECT_ROOT/data/targets/llama.cpp/$LLAMA_VER}"
ARCHIVE="${ARCHIVE:-$TARGET_DIR/source/$LLAMA_VER.tar.gz}"
META="${META:-$TARGET_DIR/meta.json}"
# Its own tree: the libFuzzer build under fuzz-build/ is compiled with a different
# compiler and different flags, and sharing a cmake dir silently mixes them.
BUILD_ROOT="${BUILD_ROOT:-$TARGET_DIR/aflpp-build}"
SRC_DIR="$BUILD_ROOT/src"
BUILD_DIR="$BUILD_ROOT/build"
PATCH="${PATCH:-$PROJECT_ROOT/patches/gguf_asan_clamp.patch}"
PATCH_MARKER="BUILD-TIME FUZZING PATCH"
SRC_CC="${SRC_CC:-$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_fuzzer.cc}"
OUT="${OUT:-$PROJECT_ROOT/harnesses/aflpp/gguf_loader_replay}"
JOBS="${JOBS:-4}"
AFL_CC="${AFL_CC:-afl-clang-fast}"
AFL_CXX="${AFL_CXX:-afl-clang-fast++}"
CMAKE="${CMAKE:-cmake}"

usage() {
  cat <<'EOF'
usage: build_aflpp_gguf_native.sh

Builds the AFL++ replay for GGUF with the PARSER ITSELF instrumented.

This deliberately does NOT copy build_aflpp_onnx_native.sh, which links a
pre-built libonnxruntime.so: that is the reason the ONNX arm's coverage is
driver-level only (G2). Here ggml-base is compiled from the pinned source with
afl-clang-fast++ and linked statically, so afl-fuzz sees edges inside gguf.cpp.

AFL_USE_ASAN=1 matches the libFuzzer arm's sanitizer conditions. With one arm
sanitized and the other not, the two arms' finding counts cannot be compared.

Run this inside the aflplusplus/aflplusplus container; afl-clang-fast++ is not
installed on the dev machine.

Environment:
  PROJECT_ROOT LLAMA_VER TARGET_DIR ARCHIVE META BUILD_ROOT PATCH SRC_CC OUT JOBS
  AFL_CC AFL_CXX CMAKE
  ALLOW_UNINSTRUMENTED=1   accept a build with no AFL++ instrumentation
  ALLOW_DRIVER_ONLY=1      accept a build whose parser is not linked in
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) echo "[build-aflpp-gguf] unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

log() {
  echo "[build-aflpp-gguf] $*"
}

fail() {
  echo "[build-aflpp-gguf] fail: $*" >&2
  exit 1
}

command -v "$AFL_CC"  >/dev/null 2>&1 || fail "$AFL_CC not found; run inside aflplusplus/aflplusplus"
command -v "$AFL_CXX" >/dev/null 2>&1 || fail "$AFL_CXX not found; run inside aflplusplus/aflplusplus"
command -v "$CMAKE"   >/dev/null 2>&1 || fail "cmake not found (set CMAKE)"
[[ -f "$SRC_CC"  ]] || fail "harness source not found: $SRC_CC"
[[ -f "$PATCH"   ]] || fail "clamp patch not found: $PATCH"
[[ -f "$ARCHIVE" ]] || fail "pinned source archive not found: $ARCHIVE"
[[ -f "$META"    ]] || fail "target metadata not found: $META"

expected_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["downloaded_sha256"])' "$META")"
actual_sha="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
[[ "$expected_sha" == "$actual_sha" ]] \
  || fail "archive sha256 mismatch: meta.json=$expected_sha actual=$actual_sha"
log "archive verified: $LLAMA_VER sha256=$actual_sha"

# Same extract/patch discipline as the libFuzzer build: a half-patched tree must never
# be reused, and editing the patch must force a re-extract.
PATCH_STAMP="$SRC_DIR/.patch-sha256"
PATCH_SHA="$(sha256sum "$PATCH" | cut -d' ' -f1)"
if [[ -f "$SRC_DIR/.extract-ok" && "$(cat "$PATCH_STAMP" 2>/dev/null || true)" != "$PATCH_SHA" ]]; then
  log "clamp patch changed since this tree was built; re-extracting"
  rm -f "$SRC_DIR/.extract-ok"
fi

if [[ ! -f "$SRC_DIR/.extract-ok" ]]; then
  log "extracting into $SRC_DIR"
  rm -rf "$SRC_DIR"
  mkdir -p "$SRC_DIR"
  tar -xzf "$ARCHIVE" -C "$SRC_DIR" --strip-components=1
  touch "$SRC_DIR/.extract-ok"
else
  log "reusing extracted tree $SRC_DIR"
fi

GGUF_CPP="$SRC_DIR/ggml/src/gguf.cpp"
[[ -f "$GGUF_CPP" ]] || fail "extracted tree has no ggml/src/gguf.cpp"

expected_markers="$(grep -c "^+.*$PATCH_MARKER" "$PATCH" || true)"
[[ "$expected_markers" -gt 0 ]] || fail "patch $PATCH carries no $PATCH_MARKER marker lines"

reject_file="$(find "$SRC_DIR" -name '*.rej' -print -quit)"
if [[ -n "$reject_file" ]]; then
  rm -f "$SRC_DIR/.extract-ok"
  fail "build tree holds a patch reject ($reject_file): it was left half-patched. Re-run to re-extract."
fi

found_markers="$(grep -c "$PATCH_MARKER" "$GGUF_CPP" || true)"
if [[ "$found_markers" -eq "$expected_markers" ]]; then
  log "clamp patch already applied ($found_markers markers)"
elif [[ "$found_markers" -ne 0 ]]; then
  rm -f "$SRC_DIR/.extract-ok"
  fail "build tree is half-patched ($found_markers of $expected_markers markers). Re-run to re-extract."
else
  log "applying clamp patch"
  if ! patch -p1 -d "$SRC_DIR" >"$BUILD_ROOT/patch.log" 2>&1 <"$PATCH"; then
    rm -f "$SRC_DIR/.extract-ok"
    cat "$BUILD_ROOT/patch.log" >&2
    fail "clamp patch did not apply; the tree will be re-extracted on the next run"
  fi
  found_markers="$(grep -c "$PATCH_MARKER" "$GGUF_CPP" || true)"
  [[ "$found_markers" -eq "$expected_markers" ]] \
    || { rm -f "$SRC_DIR/.extract-ok"; fail "clamp patch left $found_markers of $expected_markers markers"; }
fi
echo "$PATCH_SHA" >"$PATCH_STAMP"

# GGML_NATIVE=OFF keeps the build off -march=native, so the binary a container built
# still runs on the campaign host. GGML_BACKEND_DL=OFF keeps every backend in the
# archive rather than behind a dlopen the forkserver would never instrument.
log "configuring with $AFL_CXX ($("$CMAKE" --version | head -1))"
AFL_USE_ASAN=1 "$CMAKE" -S "$SRC_DIR" -B "$BUILD_DIR" \
  -DCMAKE_C_COMPILER="$AFL_CC" \
  -DCMAKE_CXX_COMPILER="$AFL_CXX" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_SHARED_LIBS=OFF \
  -DGGML_NATIVE=OFF \
  -DGGML_BACKEND_DL=OFF \
  -DGGML_CCACHE=OFF \
  -DLLAMA_BUILD_TESTS=OFF \
  -DLLAMA_BUILD_EXAMPLES=OFF \
  -DLLAMA_BUILD_TOOLS=OFF \
  -DLLAMA_BUILD_SERVER=OFF \
  -DLLAMA_BUILD_COMMON=OFF \
  -DLLAMA_CURL=OFF \
  >"$BUILD_ROOT/configure.log" 2>&1 || fail "cmake configure failed; see $BUILD_ROOT/configure.log"

# A cmake cache wipe (or any configure that silently drops the target) leaves the
# previous archive in place, and the link step below would happily reuse it while the
# scope gate reported success on stale objects. Remove it so "the file exists" means
# "this run built it".
LIB_A_PRE="$BUILD_DIR/ggml/src/libggml-base.a"
rm -f "$LIB_A_PRE"
log "building ggml-base (jobs=$JOBS)"
AFL_USE_ASAN=1 "$CMAKE" --build "$BUILD_DIR" --target ggml-base -j"$JOBS" \
  >"$BUILD_ROOT/build.log" 2>&1 || fail "ggml-base build failed; see $BUILD_ROOT/build.log"

LIB_A="$BUILD_DIR/ggml/src/libggml-base.a"
[[ -f "$LIB_A" ]] || fail "static library not produced: $LIB_A"

# The twin (build_libfuzzer_gguf_native.sh) checks the ARCHIVE, not just the finished
# binary, and the copy that produced this script dropped those checks. They matter more
# here: instrumentation_scope() can only see the linked binary, where "the parser is
# present" and "the parser was instrumented" are no longer separable facts. In the
# archive they still are.
NM_BIN="${LLVM_NM:-}"
if [[ -z "$NM_BIN" ]]; then
  NM_BIN="$(command -v llvm-nm || command -v nm || true)"
fi
[[ -n "$NM_BIN" ]] || fail "no llvm-nm/nm to verify $LIB_A"
NM_LIST="$BUILD_ROOT/nm-ggml-base.txt"
# A file, not a pipe: grep -q closes the pipe on its first match and pipefail would read
# the resulting SIGPIPE as a missing symbol.
"$NM_BIN" "$LIB_A" >"$NM_LIST" 2>/dev/null || fail "llvm-nm could not read $LIB_A"

grep -q 'gguf_init_from_file_impl' "$NM_LIST" \
  || fail "gguf.cpp is not in $LIB_A (no gguf_init_from_file_impl symbol; see $NM_LIST)"

# The AFL++ runtime references land in the archive's objects as undefined symbols; the
# runtime itself is linked in at the final link. Same for ASan under AFL_USE_ASAN.
afl_refs="$(grep -c '__afl_' "$NM_LIST" || true)"
asan_refs="$(grep -c '__asan_' "$NM_LIST" || true)"
log "archive symbols: __afl_=$afl_refs __asan_=$asan_refs (listing: $NM_LIST)"
if [[ "$afl_refs" -eq 0 || "$asan_refs" -eq 0 ]]; then
  if [[ "${ALLOW_UNINSTRUMENTED:-0}" == "1" ]]; then
    log "WARN: $LIB_A carries __afl_=$afl_refs __asan_=$asan_refs (ALLOW_UNINSTRUMENTED=1)"
  else
    echo "[build-aflpp-gguf] $LIB_A does not look instrumented: __afl_=$afl_refs __asan_=$asan_refs" >&2
    echo "[build-aflpp-gguf] the parser objects must carry AFL++ instrumentation and (AFL_USE_ASAN=1) ASan," >&2
    echo "[build-aflpp-gguf] or afl-fuzz sees the harness's edges only - the ONNX G2 situation." >&2
    echo "[build-aflpp-gguf] inspect $NM_LIST; set ALLOW_UNINSTRUMENTED=1 for a deliberate baseline build" >&2
    exit 1
  fi
fi

# R49/R55: never link straight onto the operational replay. scripts/lib/staged_install.sh
# carries the reasoning and the contract; it is shared so the six native builds cannot
# drift apart again.
# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT || exit 1
trap staged_cleanup EXIT
staged_new "$OUT" STAGED || exit 1

log "linking standalone replay"
AFL_USE_ASAN=1 "$AFL_CXX" -std=c++17 -O1 -g \
  -DGGUF_FUZZ_STANDALONE \
  -DGGUF_FUZZ_TARGET_ID="\"llama.cpp/$LLAMA_VER\"" \
  -DGGUF_FUZZ_CLAMP_PATCH=1 \
  -I"$SRC_DIR/ggml/include" \
  "$SRC_CC" "$LIB_A" -lpthread -lm -o "$STAGED"

# shellcheck source=lib/engine_mode.sh
. "$SCRIPT_DIR/lib/engine_mode.sh"

SCOPE="$(instrumentation_scope "$STAGED")"
case "$SCOPE" in
  library)
    log "instrumentation_scope: library (the parser itself is instrumented)"
    ;;
  driver_only)
    if [[ "${ALLOW_DRIVER_ONLY:-0}" == "1" ]]; then
      log "WARN: the new replay is instrumented but its parser is not linked in (ALLOW_DRIVER_ONLY=1)"
    else
      echo "[build-aflpp-gguf] the new replay is instrumented, but the parser is not inside it; $OUT left unchanged" >&2
      echo "[build-aflpp-gguf] this is the ONNX G2 situation: afl-fuzz would see driver edges only" >&2
      echo "[build-aflpp-gguf] (set ALLOW_DRIVER_ONLY=1 for a deliberate baseline build)" >&2
      exit 1
    fi
    ;;
  *)
    if [[ "${ALLOW_UNINSTRUMENTED:-0}" == "1" ]]; then
      log "WARN: the new replay has no AFL++ instrumentation (ALLOW_UNINSTRUMENTED=1)"
    else
      echo "[build-aflpp-gguf] the new replay has no AFL++ instrumentation; $OUT left unchanged" >&2
      echo "[build-aflpp-gguf] AFL_CXX=$AFL_CXX did not instrument; build inside aflplusplus/aflplusplus" >&2
      echo "[build-aflpp-gguf] (set ALLOW_UNINSTRUMENTED=1 for a deliberate baseline build)" >&2
      exit 1
    fi
    ;;
esac

staged_commit "$STAGED" "$OUT" || exit 1
trap - EXIT

log "done"
echo "src: $SRC_CC"
echo "lib: $LIB_A"
echo "out: $OUT"
echo "instrumentation_scope: $SCOPE"
