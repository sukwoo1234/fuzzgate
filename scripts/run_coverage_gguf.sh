#!/usr/bin/env bash
# The TOOL_COVERAGE_GGUF_CMD target. src/coverage.rs runs this as `bash -lc` with
# OUT_DIR, CORPUS_DIR, and SOURCE_CORPUS_DIR exported, and requires
# $OUT_DIR/coverage.json on exit 0.
#
# Replays the corpus through the source-instrumented gguf replay and emits real
# LLVM line/function coverage OF ggml/src/gguf.cpp.
#
# WHAT THIS NUMBER IS, AND IS NOT (read before quoting it anywhere):
#   * scope   : gguf.cpp only. run_coverage_onnx.sh instead measures the whole
#               libonnxruntime.so minus a regex. The two scoping rules are
#               different, so the two percentages are NOT comparable.
#   * parser  : pristine llama.cpp b7921. The clamp patch is NOT applied.
#   * depth   : GGUF_FUZZ_DEPTH (default tensor-info => no_alloc=true). At that
#               depth the tensor-data blob path is never entered by construction,
#               so those lines are permanently uncovered and stay in the
#               denominator. Raise the depth to move that boundary, do not
#               explain the number away.
#
# One process per input, on purpose: a GGML_ASSERT abort skips the atexit handler
# that writes .profraw, so batching every input into one process would let a single
# aborting seed erase the whole run's profile. Per-input isolation costs one exec
# each and loses at most that input's own counters.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
LLAMA_VER="${LLAMA_VER:-b7921}"
TARGET_DIR="${TARGET_DIR:-$PROJECT_ROOT/data/targets/llama.cpp/$LLAMA_VER}"
BUILD_ROOT="${BUILD_ROOT:-$TARGET_DIR/cov-build}"
REPLAY="${REPLAY:-$BUILD_ROOT/gguf_loader_replay_cov}"
GGUF_CPP="${GGUF_CPP:-$BUILD_ROOT/src/ggml/src/gguf.cpp}"
OUT_DIR="${OUT_DIR:?OUT_DIR must be set by the coverage runner}"
CORPUS_DIR="${CORPUS_DIR:?CORPUS_DIR must be set by the coverage runner}"
SOURCE_CORPUS_DIR="${SOURCE_CORPUS_DIR:-$CORPUS_DIR}"
CLANG_BUNDLE_DIR="$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin"
# Absolute paths on purpose: this runs under `bash -lc`, and a login shell's
# profile can put a rustup shim (or another clang) ahead of the pinned bundle on
# PATH. The profraw format is tied to the compiler that produced it.
LLVM_PROFDATA="${LLVM_PROFDATA:-$CLANG_BUNDLE_DIR/llvm-profdata}"
LLVM_COV="${LLVM_COV:-$CLANG_BUNDLE_DIR/llvm-cov}"

log()  { echo "[gguf-cov-run] $*"; }
fail() { echo "[gguf-cov-run] fail: $*" >&2; exit 1; }

[[ -d "$PROJECT_ROOT/scripts" ]] \
  || fail "PROJECT_ROOT=$PROJECT_ROOT does not look like the repo (no scripts/); set PROJECT_ROOT"

# Build the instrumented replay on demand so this is one self-contained command.
if [[ ! -x "$REPLAY" ]]; then
  log "instrumented replay missing; building it"
  PROJECT_ROOT="$PROJECT_ROOT" bash "$PROJECT_ROOT/scripts/build_coverage_gguf.sh" >/dev/null \
    || fail "build_coverage_gguf.sh failed"
fi
[[ -x "$REPLAY" ]]        || fail "instrumented replay not found at $REPLAY"
[[ -f "$GGUF_CPP" ]]      || fail "pristine gguf.cpp not found at $GGUF_CPP (run scripts/build_coverage_gguf.sh)"
[[ -x "$LLVM_PROFDATA" ]] || fail "llvm-profdata not found at $LLVM_PROFDATA (data/toolchains is gitignored; transfer it to offline hosts)"
[[ -x "$LLVM_COV" ]]      || fail "llvm-cov not found at $LLVM_COV"

RAW="$OUT_DIR/raw"
# Per-input profraw are named by array index, so re-running a SMALLER corpus into a
# reused OUT_DIR would leave the previous run's higher-indexed files behind and merge
# them into this number. run_coverage_onnx.sh guards the same way. Under
# src/coverage.rs OUT_DIR is always fresh; this protects the direct-invocation path,
# which is how the number gets re-measured by hand.
rm -rf "$RAW" "$OUT_DIR/cov.profdata" "$OUT_DIR/llvmcov.json" "$OUT_DIR/coverage.json"
mkdir -p "$RAW"

shopt -s nullglob
inputs=("$CORPUS_DIR"/*.gguf)
shopt -u nullglob
[[ ${#inputs[@]} -gt 0 ]] || fail "no *.gguf inputs in $CORPUS_DIR"

DEPTH="${GGUF_FUZZ_DEPTH:-tensor-info}"
log "replaying ${#inputs[@]} inputs (depth=$DEPTH, one process each)"

accepted=0; rejected=0; unavailable=0; aborted=0
for i in "${!inputs[@]}"; do
  rc=0
  LLVM_PROFILE_FILE="$RAW/cov-$i.profraw" GGUF_FUZZ_DEPTH="$DEPTH" \
    "$REPLAY" "${inputs[$i]}" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0)  accepted=$((accepted+1)) ;;
    9)  rejected=$((rejected+1)) ;;
    10) unavailable=$((unavailable+1)) ;;
    *)  aborted=$((aborted+1))
        # Expected for a PoC seed (a GGML_ASSERT abort is the finding). Reported
        # because it changes how the number was produced: the profile survives only
        # because the coverage build flushes it from a signal handler. If that ever
        # stops working the profraw comes back 0-byte and the guard below fires.
        log "note: $(basename "${inputs[$i]}") exited $rc (abort/crash); profile flushed by the coverage build"
        ;;
  esac
done
log "accepted=$accepted rejected=$rejected unavailable=$unavailable aborted=$aborted"

# A replay that refuses to run (exit 10 everywhere) would otherwise produce a
# perfectly-formed 0% coverage report that reads like a finding.
[[ "$unavailable" -lt "${#inputs[@]}" ]] \
  || fail "every input returned 'harness unavailable'; the replay never ran"

shopt -s nullglob
profs=("$RAW"/*.profraw)
shopt -u nullglob
[[ ${#profs[@]} -gt 0 ]] || fail "no profraw produced (instrumentation did not run)"

# A process that dies without flushing leaves a 0-BYTE profraw behind, and
# llvm-profdata merges those WITHOUT complaint. Left in, they turn a run where
# nothing was measured into a well-formed 0% report on exit 0 - the fake-clean
# result this project keeps legislating against. Measured before the coverage build
# learned to flush on abort: 3 PoC seeds -> 3 empty files -> "0/1018 lines", exit 0.
usable=()
for f in "${profs[@]}"; do [[ -s "$f" ]] && usable+=("$f"); done
empty_profiles=$(( ${#profs[@]} - ${#usable[@]} ))
if [[ "$empty_profiles" -gt 0 ]]; then
  log "WARN: $empty_profiles of ${#profs[@]} profraw files are empty (process died before flushing); dropped"
fi
[[ ${#usable[@]} -gt 0 ]] \
  || fail "every profraw is empty: no input produced a profile, so any percentage here would be fiction. Rebuild with scripts/build_coverage_gguf.sh (it compiles in the abort-time profile flush)."

"$LLVM_PROFDATA" merge -sparse "${usable[@]}" -o "$OUT_DIR/cov.profdata"

# llvm-cov's positional source filter FAILS OPEN. If the path does not byte-match a
# filename recorded in the binary's coverage mapping, llvm-cov does not error, does not
# warn and does not report zero - it silently ignores the filter and reports EVERY file
# in the binary. Measured: a repo reached through a symlink yielded 703/12525 (5.61%)
# with exit 0, still labelled as gguf.cpp, where the true figure is 381/1018 (37.43%).
# The mapping stores the ABSOLUTE path used at compile time, so this fires whenever the
# tree is relocated - which is exactly what transferring data/ to the offline fuzzing PC
# does. An existence check on the path cannot catch it: the path exists, it is simply
# not the one in the mapping.
#
# So do not guess the path. Ask the binary which file it actually mapped, and refuse if
# the answer is not exactly one gguf.cpp.
MAPPED_SRC="$("$LLVM_COV" export -summary-only -instr-profile="$OUT_DIR/cov.profdata" "$REPLAY" \
  | python3 -c 'import json,sys
for f in json.load(sys.stdin)["data"][0]["files"]:
    print(f["filename"])' | grep -E '/ggml/src/gguf\.cpp$' || true)"
[[ -n "$MAPPED_SRC" ]] \
  || fail "$REPLAY has no ggml/src/gguf.cpp in its coverage mapping; it was not built by scripts/build_coverage_gguf.sh"
[[ "$(wc -l <<<"$MAPPED_SRC")" -eq 1 ]] \
  || fail "coverage mapping names more than one gguf.cpp:\n$MAPPED_SRC"
if [[ "$MAPPED_SRC" != "$GGUF_CPP" ]]; then
  # Not fatal: the binary is self-describing, and its path is the authoritative one.
  # Say so loudly, because it means this tree was relocated since it was built.
  log "note: coverage mapping says $MAPPED_SRC (this run derived $GGUF_CPP); using the mapped path"
fi

"$LLVM_COV" report "$REPLAY" -instr-profile="$OUT_DIR/cov.profdata" "$MAPPED_SRC" \
  | tee "$OUT_DIR/llvm-cov-report.txt"
"$LLVM_COV" export -summary-only \
  -instr-profile="$OUT_DIR/cov.profdata" "$REPLAY" "$MAPPED_SRC" > "$OUT_DIR/llvmcov.json"

# Belt and braces: even with a resolved path, assert the export really is scoped to that
# one file before any number is published.
scoped="$(python3 -c 'import json,sys
files = json.load(open(sys.argv[1]))["data"][0]["files"]
print(len(files)); print(files[0]["filename"] if len(files) == 1 else "")' "$OUT_DIR/llvmcov.json")"
nfiles="$(head -1 <<<"$scoped")"
[[ "$nfiles" == "1" ]] \
  || fail "llvm-cov reported $nfiles files, not 1: the source filter matched nothing and fell back to the whole binary. Any percentage from this run would be fiction."
[[ "$(tail -1 <<<"$scoped")" == "$MAPPED_SRC" ]] \
  || fail "llvm-cov scoped to an unexpected file: $(tail -1 <<<"$scoped")"

TOOL_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo not_available)"
CLANG_VER="$("$CLANG_BUNDLE_DIR/clang++" --version | head -1)"
python3 - "$OUT_DIR/llvmcov.json" "$OUT_DIR/coverage.json" "$CLANG_VER" "$TOOL_COMMIT" \
  "$SOURCE_CORPUS_DIR" "${#inputs[@]}" "$DEPTH" "$LLAMA_VER" "$aborted" "$empty_profiles" \
  "$MAPPED_SRC" <<'PY'
import json, sys
(summ, out, clangver, commit, corpus, ninputs, depth, ver, aborted,
 empty_profiles, mapped_src) = sys.argv[1:12]
tot = json.load(open(summ))["data"][0]["totals"]
lines, funcs, regions = tot.get("lines", {}), tot.get("functions", {}), tot.get("regions", {})
cov = {
    "schema_version": "2.0",
    "target": "gguf",
    "coverage_kind": "line_function",
    "instrumentation": "llvm-source-cov",
    "toolchain": "clang",
    "toolchain_version": clangver,
    "tool_commit": commit,
    # Provenance for the caveats in the header comment: a reader must be able to
    # tell which parser, which depth and which scope produced this number.
    # Read back from the binary's coverage mapping, never asserted: a hardcoded
    # label is exactly what made the fail-open filter invisible.
    "measured_source": mapped_src[mapped_src.find("ggml/src/gguf.cpp"):] or mapped_src,
    "measured_source_abs": mapped_src,
    "target_version": f"llama.cpp/{ver}",
    "clamp_patch": "absent",
    "depth": depth,
    "source_corpus": corpus,
    "corpus_models": int(ninputs),
    "inputs_aborted": int(aborted),
    "inputs_without_profile": int(empty_profiles),
    "covered_lines": lines.get("covered"),
    "total_lines": lines.get("count"),
    "line_coverage": lines.get("percent"),
    "covered_functions": funcs.get("covered"),
    "total_functions": funcs.get("count"),
    "function_coverage": funcs.get("percent"),
    "covered_regions": regions.get("covered"),
    "total_regions": regions.get("count"),
}
cov = {k: v for k, v in cov.items() if v is not None}  # omit missing -> no fake values
json.dump(cov, open(out, "w"), indent=2)
print(f"[gguf-cov-run] coverage.json: lines {cov.get('covered_lines')}/{cov.get('total_lines')} "
      f"functions {cov.get('covered_functions')}/{cov.get('total_functions')}")
PY

echo "[gguf-cov-run] wrote $OUT_DIR/coverage.json"
