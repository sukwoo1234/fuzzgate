#!/usr/bin/env bash
# Build a SOURCE-INSTRUMENTED (clang -fprofile-instr-generate -fcoverage-mapping)
# standalone gguf replay, so `tool coverage --target gguf` reports real line and
# function coverage of ggml/src/gguf.cpp instead of a proxy.
#
# Three deliberate differences from scripts/build_libfuzzer_gguf_native.sh:
#
#   1. NO CLAMP PATCH. patches/gguf_asan_clamp.patch rewrites gguf.cpp, so a
#      coverage number taken from a patched tree is a number about OUR parser, not
#      about llama.cpp b7921. The patch also shifts line numbers, which silently
#      misattributes every covered line. This tree stays pristine.
#   2. NO ASan and NO sancov. Coverage is not the crash oracle - the fuzz build is.
#      Mixing them only slows the replay and changes allocation behaviour.
#   3. A SEPARATE build root (cov-build). The fuzz build's tree is patched and
#      ASan-instrumented; sharing it would make each build silently invalidate the
#      other's guarantees.
#
# GGUF_FUZZ_COVERAGE additionally compiles in a SIGABRT handler that flushes the
# profile before dying, so a seed that trips a GGML_ASSERT still contributes its
# coverage. That block exists only under this define; verified by preprocessing the
# harness with and without it - the campaign build is token-identical.
#
# The harness SOURCE is the same file the campaign fuzzes
# (harnesses/libfuzzer/gguf_loader_fuzzer.cc, compiled with GGUF_FUZZ_STANDALONE).
# Not a copy: a copy would drift, and then the coverage number would describe code
# no campaign ever runs.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
LLAMA_VER="${LLAMA_VER:-b7921}"
TARGET_DIR="${TARGET_DIR:-$PROJECT_ROOT/data/targets/llama.cpp/$LLAMA_VER}"
ARCHIVE="${ARCHIVE:-$TARGET_DIR/source/$LLAMA_VER.tar.gz}"
META="${META:-$TARGET_DIR/meta.json}"
BUILD_ROOT="${BUILD_ROOT:-$TARGET_DIR/cov-build}"
SRC_DIR="$BUILD_ROOT/src"
BUILD_DIR="$BUILD_ROOT/build"
SRC_CC="${SRC_CC:-$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_fuzzer.cc}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
OUT_BIN="${OUT_BIN:-$BUILD_ROOT/gguf_loader_replay_cov}"
JOBS="${JOBS:-4}"
CLANG_BUNDLE_DIR="$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin"
COV_FLAGS="-fprofile-instr-generate -fcoverage-mapping"

usage() {
  cat <<'EOF'
usage: build_coverage_gguf.sh

Builds the source-instrumented GGUF coverage replay from the PINNED llama.cpp
source, WITHOUT the clamp patch and WITHOUT ASan:

  1. check the archive against meta.json's sha256
  2. extract into a pristine, coverage-only tree (never the fuzz-build tree)
  3. refuse to continue if that tree carries the clamp patch marker
  4. cmake-build ggml-base with -fprofile-instr-generate -fcoverage-mapping
  5. verify by SYMBOL that the archive holds both the parser and the profile
     counters (an uninstrumented archive links and runs fine - it just reports
     zero coverage forever)
  6. link the standalone replay and self-test its exit-code contract

Environment:
  PROJECT_ROOT LLAMA_VER TARGET_DIR ARCHIVE META BUILD_ROOT SRC_CC OUT_BIN JOBS
  CLANG CLANGXX LLVM_NM CMAKE
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) echo "[build-gguf-cov] unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

log()  { echo "[build-gguf-cov] $*"; }
fail() { echo "[build-gguf-cov] fail: $*" >&2; exit 1; }

CLANG="${CLANG:-$CLANG_BUNDLE_DIR/clang}"
CLANGXX="${CLANGXX:-$CLANG_BUNDLE_DIR/clang++}"
LLVM_NM="${LLVM_NM:-$CLANG_BUNDLE_DIR/llvm-nm}"
LLVM_OBJDUMP="${LLVM_OBJDUMP:-$CLANG_BUNDLE_DIR/llvm-objdump}"
# The clang-17 bundle is the version the profdata/cov readers in
# run_coverage_gguf.sh use. A system clang of another version produces profraw
# those tools reject, so this is a hard requirement, not a preference.
[[ -x "$CLANG"   ]] || fail "clang-17 bundle not found at $CLANG (set CLANG; data/toolchains is gitignored and must be transferred to an offline host)"
[[ -x "$CLANGXX" ]] || fail "clang++-17 not found at $CLANGXX (set CLANGXX)"
[[ -x "$LLVM_NM" ]] || fail "llvm-nm not found at $LLVM_NM (set LLVM_NM)"
[[ -x "$LLVM_OBJDUMP" ]] || fail "llvm-objdump not found at $LLVM_OBJDUMP (set LLVM_OBJDUMP)"

CMAKE="${CMAKE:-$(command -v cmake || true)}"
if [[ ! -x "$CMAKE" && -x "$PROJECT_ROOT/.venv/bin/cmake" ]]; then
  CMAKE="$PROJECT_ROOT/.venv/bin/cmake"
fi
[[ -x "$CMAKE"   ]] || fail "cmake not found (set CMAKE)"
[[ -f "$SRC_CC"  ]] || fail "harness source not found: $SRC_CC"
[[ -f "$ARCHIVE" ]] || fail "pinned source archive not found: $ARCHIVE"
[[ -f "$META"    ]] || fail "target metadata not found: $META"

mkdir -p "$BUILD_ROOT"

# ---------------------------------------------------------------------------
# 1. the archive must be the pinned one
# ---------------------------------------------------------------------------
expected_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["downloaded_sha256"])' "$META")"
actual_sha="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
[[ "$expected_sha" == "$actual_sha" ]] \
  || fail "archive sha256 mismatch: meta.json=$expected_sha actual=$actual_sha"
log "archive verified: $LLAMA_VER sha256=$actual_sha"

# ---------------------------------------------------------------------------
# 2. extract into a pristine coverage-only tree
# ---------------------------------------------------------------------------
if [[ ! -f "$SRC_DIR/.extract-ok" ]]; then
  log "extracting pristine tree into $SRC_DIR"
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
# 3. the tree must be PRISTINE
# ---------------------------------------------------------------------------
# If someone points BUILD_ROOT at the fuzz tree, or hand-applies the patch here,
# every line number llvm-cov reports is shifted and the coverage figure quietly
# describes a parser that upstream does not ship. Refuse instead.
if grep -q "BUILD-TIME FUZZING PATCH" "$GGUF_CPP"; then
  fail "$GGUF_CPP carries the clamp patch. The coverage build must measure pristine $LLAMA_VER; use a separate BUILD_ROOT."
fi
log "tree is pristine (no clamp patch marker)"

# ---------------------------------------------------------------------------
# 4. build ggml-base with source-coverage instrumentation
# ---------------------------------------------------------------------------
log "configuring ($("$CMAKE" --version | head -1))"
"$CMAKE" -S "$SRC_DIR" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CLANG" \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_FLAGS="$COV_FLAGS" \
  -DCMAKE_CXX_FLAGS="$COV_FLAGS" \
  -DLLAMA_BUILD_TESTS=OFF \
  -DLLAMA_BUILD_EXAMPLES=OFF \
  -DLLAMA_BUILD_TOOLS=OFF \
  -DLLAMA_BUILD_SERVER=OFF \
  >"$BUILD_ROOT/configure.log" 2>&1 || fail "cmake configure failed; see $BUILD_ROOT/configure.log"

# Same reason as the fuzz build: a configure that drops the target leaves the
# previous archive in place and the symbol gate below would pass on stale objects.
LIB_A="$BUILD_DIR/ggml/src/libggml-base.a"
rm -f "$LIB_A"
log "building ggml-base (jobs=$JOBS)"
"$CMAKE" --build "$BUILD_DIR" --target ggml-base -j"$JOBS" \
  >"$BUILD_ROOT/build.log" 2>&1 || fail "ggml-base build failed; see $BUILD_ROOT/build.log"
[[ -f "$LIB_A" ]] || fail "static library not produced: $LIB_A"

# ---------------------------------------------------------------------------
# 5. symbol gate: parser present AND profile counters present
# ---------------------------------------------------------------------------
# Measured on the fuzz-build archive: it carries __sanitizer_cov (61 symbols) but
# ZERO __profc_/__llvm_prf_names. sancov feeds libFuzzer; it produces no source
# coverage at all. So the gate below is what separates "instrumented for fuzzing"
# from "instrumented for coverage" - the exact confusion this cell exists to end.
NM_LIST="$BUILD_ROOT/nm-ggml-base.txt"
"$LLVM_NM" "$LIB_A" >"$NM_LIST" 2>/dev/null || fail "llvm-nm could not read $LIB_A"
grep -q 'gguf_init_from_file_impl' "$NM_LIST" \
  || fail "gguf.cpp is not in $LIB_A (no gguf_init_from_file_impl symbol; see $NM_LIST)"
grep -q '__profc_' "$NM_LIST" \
  || fail "$LIB_A has no profile counters (no __profc_ symbols; see $NM_LIST). It would report 0% coverage forever."
# The coverage MAPPING lives in the __llvm_covmap SECTION, not in a symbol, so it
# is invisible to llvm-nm - checking for it there is a gate that can never fire.
# Without the mapping, llvm-cov has counters but nothing to attribute them to.
# Measured discrimination: this archive 8, the fuzz-build archive 0.
SEC_LIST="$BUILD_ROOT/objdump-sections.txt"
"$LLVM_OBJDUMP" -h "$LIB_A" >"$SEC_LIST" 2>/dev/null \
  || fail "llvm-objdump could not read $LIB_A"
grep -q '__llvm_covmap' "$SEC_LIST" \
  || fail "$LIB_A has no __llvm_covmap section (see $SEC_LIST): built without -fcoverage-mapping, so llvm-cov could not attribute lines."
log "symbol check ok: parser present, profile counters present, coverage mapping present"

# ---------------------------------------------------------------------------
# 6. link the standalone replay
# ---------------------------------------------------------------------------
# GGUF_FUZZ_CLAMP_PATCH=0 so --selftest reports the truth about this tree.
# The coverage flags MUST be on the link line too, or the profile runtime is
# never pulled in and the binary emits no .profraw.
# R55: same staging discipline as the native builds. These outputs are rebuildable, but
# a link or copy that fails part-way still leaves a truncated binary where a working
# one was, and the coverage runners would then measure it.
# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT_BIN || exit 1
trap staged_cleanup EXIT
staged_new "$OUT_BIN" STAGED_BIN || exit 1

log "linking coverage replay"
"$CLANGXX" -std=c++17 -O1 -g $COV_FLAGS \
  -I"$SRC_DIR/ggml/include" \
  -DGGUF_FUZZ_TARGET_ID="\"llama.cpp/$LLAMA_VER\"" \
  -DGGUF_FUZZ_CLAMP_PATCH=0 \
  -DGGUF_FUZZ_STANDALONE \
  -DGGUF_FUZZ_COVERAGE=1 \
  "$SRC_CC" "$LIB_A" -lpthread -lm -o "$STAGED_BIN"

# Writing the selftest profile into the build root keeps default.profraw out of
# the working tree.
selftest_out="$(LLVM_PROFILE_FILE="$BUILD_ROOT/selftest-%p.profraw" "$STAGED_BIN" --selftest)" \
  || fail "coverage replay selftest failed"
grep -q 'clamp_patch=absent' <<<"$selftest_out" \
  || fail "selftest says the clamp patch is applied; the tree is not pristine:\n$selftest_out"
grep -q 'asan=off' <<<"$selftest_out" \
  || fail "selftest reports ASan on; the coverage build must not be ASan-instrumented:\n$selftest_out"

# Install only after the selftest has vouched for the binary: a replay that reports the
# clamp patch applied or ASan on is the wrong build, and the coverage runner would measure
# it. Committing first would leave exactly that binary in place when the check fails.
staged_commit "$STAGED_BIN" "$OUT_BIN" || exit 1
trap - EXIT
log "selftest ok (pristine, ASan off)"

log "done"
echo "src:     $GGUF_CPP"
echo "lib:     $LIB_A"
echo "replay:  $OUT_BIN"
