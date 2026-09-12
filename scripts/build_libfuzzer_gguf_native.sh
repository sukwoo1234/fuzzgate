#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
LLAMA_VER="${LLAMA_VER:-b7921}"
TARGET_DIR="${TARGET_DIR:-$PROJECT_ROOT/data/targets/llama.cpp/$LLAMA_VER}"
ARCHIVE="${ARCHIVE:-$TARGET_DIR/source/$LLAMA_VER.tar.gz}"
META="${META:-$TARGET_DIR/meta.json}"
BUILD_ROOT="${BUILD_ROOT:-$TARGET_DIR/fuzz-build}"
SRC_DIR="$BUILD_ROOT/src"
BUILD_DIR="$BUILD_ROOT/build"
PATCH="${PATCH:-$PROJECT_ROOT/patches/gguf_asan_clamp.patch}"
PATCH_MARKER="BUILD-TIME FUZZING PATCH"
SRC_CC="${SRC_CC:-$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_fuzzer.cc}"
OUT_FUZZER="${OUT_FUZZER:-$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_fuzzer}"
OUT_REPLAY="${OUT_REPLAY:-$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_replay}"
JOBS="${JOBS:-4}"
CLANG_BUNDLE_DIR="$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin"

usage() {
  cat <<'EOF'
usage: build_libfuzzer_gguf_native.sh

Builds the native GGUF harness from the PINNED llama.cpp source:

  1. check the archive against meta.json's sha256
  2. extract it into a build-only tree (never the committed target tree)
  3. apply patches/gguf_asan_clamp.patch there, idempotently
  4. cmake-build ggml-base with ASan + sancov
  5. verify gguf.cpp is really in the archive, by SYMBOL not by file existence
  6. link two binaries from one source: the libFuzzer target and the standalone
     replay the tool uses as its gguf probe

Environment:
  PROJECT_ROOT LLAMA_VER TARGET_DIR ARCHIVE META BUILD_ROOT PATCH
  SRC_CC OUT_FUZZER OUT_REPLAY JOBS CLANG CLANGXX LLVM_NM CMAKE
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) echo "[build-gguf-native] unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

log() {
  echo "[build-gguf-native] $*"
}

fail() {
  echo "[build-gguf-native] fail: $*" >&2
  exit 1
}

CLANG="${CLANG:-$CLANG_BUNDLE_DIR/clang}"
CLANGXX="${CLANGXX:-$CLANG_BUNDLE_DIR/clang++}"
LLVM_NM="${LLVM_NM:-$CLANG_BUNDLE_DIR/llvm-nm}"
if [[ ! -x "$CLANG" ]]; then CLANG="$(command -v clang || true)"; fi
if [[ ! -x "$CLANGXX" ]]; then CLANGXX="$(command -v clang++ || true)"; fi
if [[ ! -x "$LLVM_NM" ]]; then LLVM_NM="$(command -v llvm-nm || command -v nm || true)"; fi
CMAKE="${CMAKE:-$(command -v cmake || true)}"
if [[ ! -x "$CMAKE" && -x "$PROJECT_ROOT/.venv/bin/cmake" ]]; then
  CMAKE="$PROJECT_ROOT/.venv/bin/cmake"
fi

[[ -x "$CLANG"   ]] || fail "clang not found (set CLANG)"
[[ -x "$CLANGXX" ]] || fail "clang++ not found (set CLANGXX)"
[[ -x "$LLVM_NM" ]] || fail "llvm-nm/nm not found (set LLVM_NM)"
[[ -x "$CMAKE"   ]] || fail "cmake not found (set CMAKE)"
[[ -f "$SRC_CC"  ]] || fail "harness source not found: $SRC_CC"
[[ -f "$PATCH"   ]] || fail "clamp patch not found: $PATCH"
[[ -f "$ARCHIVE" ]] || fail "pinned source archive not found: $ARCHIVE"
[[ -f "$META"    ]] || fail "target metadata not found: $META"

# ---------------------------------------------------------------------------
# 1. the archive must be the pinned one
# ---------------------------------------------------------------------------
expected_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["downloaded_sha256"])' "$META")"
actual_sha="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
[[ "$expected_sha" == "$actual_sha" ]] \
  || fail "archive sha256 mismatch: meta.json=$expected_sha actual=$actual_sha"
log "archive verified: $LLAMA_VER sha256=$actual_sha"

# ---------------------------------------------------------------------------
# 2. extract into a build-only tree
# ---------------------------------------------------------------------------
# Re-extract when the patch itself changed: the guard below is a marker check on the
# tree, so without this an edited patches/gguf_asan_clamp.patch would be a permanent
# no-op against a tree some older version had already marked.
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

# ---------------------------------------------------------------------------
# 3. apply the clamp patch, idempotently
# ---------------------------------------------------------------------------
# `patch` applies the hunks it can BEFORE it exits non-zero, so a partial application
# leaves the marker in the file. A bare "is the marker present" guard then reports
# "already applied" on the next run and ships a half-patched parser - which is the
# false-crash factory this whole harness exists to remove. Count the markers instead,
# refuse a tree carrying rejects, and drop .extract-ok on any failure so the next run
# starts from a pristine tree rather than the wreckage.
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
  if [[ "$found_markers" -ne "$expected_markers" ]]; then
    rm -f "$SRC_DIR/.extract-ok"
    fail "clamp patch reported success but left $found_markers of $expected_markers markers"
  fi
fi
echo "$PATCH_SHA" >"$PATCH_STAMP"

# ---------------------------------------------------------------------------
# 4. build ggml-base
# ---------------------------------------------------------------------------
log "configuring ($("$CMAKE" --version | head -1))"
"$CMAKE" -S "$SRC_DIR" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CLANG" \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DBUILD_SHARED_LIBS=OFF \
  -DGGML_SANITIZE_ADDRESS=ON \
  -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link" \
  -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link" \
  -DLLAMA_BUILD_TESTS=OFF \
  -DLLAMA_BUILD_EXAMPLES=OFF \
  -DLLAMA_BUILD_TOOLS=OFF \
  -DLLAMA_BUILD_SERVER=OFF \
  >"$BUILD_ROOT/configure.log" 2>&1 || fail "cmake configure failed; see $BUILD_ROOT/configure.log"

# A cmake cache wipe (or any configure that silently drops the target) leaves the
# previous archive in place, and the link step below would happily reuse it while the
# scope gate reported success on stale objects. Remove it so "the file exists" means
# "this run built it".
LIB_A_PRE="$BUILD_DIR/ggml/src/libggml-base.a"
rm -f "$LIB_A_PRE"
log "building ggml-base (jobs=$JOBS)"
"$CMAKE" --build "$BUILD_DIR" --target ggml-base -j"$JOBS" \
  >"$BUILD_ROOT/build.log" 2>&1 || fail "ggml-base build failed; see $BUILD_ROOT/build.log"

LIB_A="$BUILD_DIR/ggml/src/libggml-base.a"
[[ -f "$LIB_A" ]] || fail "static library not produced: $LIB_A"

# ---------------------------------------------------------------------------
# 5. the archive must actually CONTAIN the parser
# ---------------------------------------------------------------------------
# libggml-base.a exists even if gguf.cpp dropped out of the target, so check for
# the symbol, not the file. The name is C++-mangled, hence the substring match.
# The listing goes to a file rather than through a pipe: grep -q closes the pipe
# on its first match, llvm-nm dies of SIGPIPE, and pipefail would read that as a
# missing symbol.
NM_LIST="$BUILD_ROOT/nm-ggml-base.txt"
"$LLVM_NM" "$LIB_A" >"$NM_LIST" 2>/dev/null || fail "llvm-nm could not read $LIB_A"
grep -q 'gguf_init_from_file_impl' "$NM_LIST" \
  || fail "gguf.cpp is not in $LIB_A (no gguf_init_from_file_impl symbol; see $NM_LIST)"
# An uninstrumented archive links and runs perfectly well - it just cannot report a
# memory error or feed the fuzzer a single edge. Nothing downstream would notice, so
# check here: GGML_SANITIZE_ADDRESS gives the __asan_ symbols, -fsanitize=fuzzer-no-link
# gives the coverage callbacks.
grep -q '__asan_report' "$NM_LIST" \
  || fail "$LIB_A is not ASan-instrumented (no __asan_report symbols; see $NM_LIST)"
grep -q '__sanitizer_cov' "$NM_LIST" \
  || fail "$LIB_A has no coverage instrumentation (no __sanitizer_cov symbols; see $NM_LIST)"
log "symbol check ok: parser present, ASan and coverage instrumentation present"

# ---------------------------------------------------------------------------
# 6. link both binaries from the one source
# ---------------------------------------------------------------------------
INC="$SRC_DIR/ggml/include"
# R55: both outputs go through the shared staging helper - a link failure used to
# unlink the operational binary, which .gitignore keeps untracked.
# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT_FUZZER || exit 1
staged_target OUT_REPLAY || exit 1
# Armed before the first staged_new: if the SECOND one fails, the first staging file is
# already on disk and nothing else would remove it.
trap staged_cleanup EXIT
staged_new "$OUT_FUZZER" STAGED_FUZZER || exit 1
staged_new "$OUT_REPLAY" STAGED_REPLAY || exit 1

common_flags=(
  -std=c++17 -O1 -g
  -I"$INC"
  -DGGUF_FUZZ_TARGET_ID="\"llama.cpp/$LLAMA_VER\""
  -DGGUF_FUZZ_CLAMP_PATCH=1
)

log "linking libFuzzer target"
"$CLANGXX" "${common_flags[@]}" -fsanitize=address,fuzzer \
  "$SRC_CC" "$LIB_A" -lpthread -lm -o "$STAGED_FUZZER"

# The replay binary keeps ASan too: the oracle has to see memory errors, and an
# ASan-instrumented archive cannot be linked without the runtime anyway.
log "linking standalone replay"
"$CLANGXX" "${common_flags[@]}" -fsanitize=address -DGGUF_FUZZ_STANDALONE \
  "$SRC_CC" "$LIB_A" -lpthread -lm -o "$STAGED_REPLAY"

# Both linked before either is installed, so a link failure never replaces just one of
# the pair. Not fully atomic: if the FIRST staged_commit succeeds and the second fails
# (empty staging file, chmod or rename error) the fuzzer is new and the replay is old.
# Two renames cannot be made one operation in shell; the window is a failing commit, not
# a failing build.
staged_commit "$STAGED_FUZZER" "$OUT_FUZZER" || exit 1
staged_commit "$STAGED_REPLAY" "$OUT_REPLAY" || exit 1
trap - EXIT

log "done"
echo "src: $SRC_CC"
echo "lib: $LIB_A"
echo "fuzzer: $OUT_FUZZER"
echo "replay: $OUT_REPLAY"
