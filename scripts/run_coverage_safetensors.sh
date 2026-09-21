#!/usr/bin/env bash
# The TOOL_COVERAGE_SAFETENSORS_CMD target. src/coverage.rs verifies this file against
# the runner bytes embedded in the tool build, executes a private copy with bash, and
# requires real profile evidence plus $OUT_DIR/coverage.json on exit 0.
# Runs the instrumented replay over the corpus, merges profraw with the rustc-matched
# llvm tools (NOT the clang-17 ones), and emits a line_function coverage.json that
# src/coverage.rs already knows how to parse.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
FUZZ_DIR="${FUZZ_DIR:-$PROJECT_ROOT/fuzz}"
COV_TARGET_DIR="${COV_TARGET_DIR:-$FUZZ_DIR/target-cov}"
REPLAY="${REPLAY:-$COV_TARGET_DIR/safetensors_loader_replay_cov}"
OUT_DIR="${OUT_DIR:?OUT_DIR must be set by the coverage runner}"
CORPUS_DIR="${CORPUS_DIR:?CORPUS_DIR must be set by the coverage runner}"

log() { echo "[st-cov-run] $*"; }
fail() { echo "[st-cov-run] fail: $*" >&2; exit 1; }

# Build the instrumented replay on demand so this is a single self-contained command.
if [[ ! -x "$REPLAY" ]]; then
  log "instrumented replay missing; building it"
  bash "$PROJECT_ROOT/scripts/build_coverage_safetensors.sh" >/dev/null
fi
[[ -x "$REPLAY" ]] || fail "instrumented replay not found at $REPLAY"

# rustc-matched llvm tools: rustc -Cinstrument-coverage emits profraw whose format
# tracks the nightly's bundled LLVM. The clang-17 llvm-* in run_coverage_onnx.sh would
# reject it.
RUSTLIB="$(rustc +nightly --print target-libdir)/../bin"
LLVM_PROFDATA="$RUSTLIB/llvm-profdata"
LLVM_COV="$RUSTLIB/llvm-cov"
[[ -x "$LLVM_PROFDATA" && -x "$LLVM_COV" ]] || fail "rustc llvm tools missing under $RUSTLIB (run S0: llvm-tools-preview)"

RAW="$OUT_DIR/raw"
# profraw are named by PID, so a reused OUT_DIR keeps every previous run's files and the
# merge below folds them into this run's number. Measured 2026-09-13: a 4-input run
# followed by a 1-input run into the same OUT_DIR published lines 112/575 functions 12/64
# for a corpus that covers 21/575 and 2/64, with exit 0 and no warning. run_coverage_gguf.sh
# and run_coverage_onnx.sh guard the same way. Under src/coverage.rs OUT_DIR is always
# fresh; this protects the direct-invocation path, which is how the number gets re-measured
# by hand.
rm -rf "$RAW" "$OUT_DIR/cov.profdata" "$OUT_DIR/llvmcov.json" "$OUT_DIR/coverage.json"
mkdir -p "$RAW"

shopt -s nullglob
inputs=("$CORPUS_DIR"/*.safetensors)
shopt -u nullglob
[[ ${#inputs[@]} -gt 0 ]] || fail "no *.safetensors inputs in $CORPUS_DIR"

log "running instrumented replay over ${#inputs[@]} inputs"
# The replay processes every argv file and exits 9 if any was rejected; that is fine for
# coverage (we want the parser edges either way). Ignoring the status ALTOGETHER is not:
# every input goes through one process, so a replay that stops on input 7 of 40 leaves a
# profile covering seven inputs and the report is published against the whole corpus, exit
# 0, no diagnostic. Its own contract names the statuses (ok=0 rejected=9 unavailable=10
# crash=signal), so they can be told apart. R39.
replay_rc=0
LLVM_PROFILE_FILE="$RAW/cov-%p.profraw" "$REPLAY" "${inputs[@]}" \
  >"$OUT_DIR/replay.log" 2>&1 || replay_rc=$?
case "$replay_rc" in
  0|9) log "replay rc=$replay_rc over ${#inputs[@]} inputs" ;;
  10)  fail "the replay reported it could not run (rc=10); nothing was measured; see $OUT_DIR/replay.log" ;;
  *)   fail "the replay stopped partway (rc=$replay_rc); the profile covers only part of ${#inputs[@]} inputs, so any percentage here would be published against a corpus it did not measure; see $OUT_DIR/replay.log" ;;
esac
# LIMIT, said out loud: the replay prints nothing per input, so this establishes that it
# exited with a status its contract defines over ${#inputs[@]} argv paths - not that each
# of them was individually parsed. run_coverage_onnx.sh can say the stronger thing because
# its harness writes one record per input. Closing that gap needs the replay to emit
# records too.

shopt -s nullglob
profs=("$RAW"/*.profraw)
shopt -u nullglob
[[ ${#profs[@]} -gt 0 ]] || fail "no profraw produced (instrumentation did not run)"

# A process that dies without flushing leaves a 0-BYTE profraw and llvm-profdata merges it
# without complaint, turning a run where nothing was measured into a well-formed 0% report
# on exit 0. run_coverage_gguf.sh:106-118 drops them.
usable=()
for f in "${profs[@]}"; do [[ -s "$f" ]] && usable+=("$f"); done
empty_profiles=$(( ${#profs[@]} - ${#usable[@]} ))
[[ "$empty_profiles" -eq 0 ]] \
  || log "WARN: $empty_profiles of ${#profs[@]} profraw files are empty (process died before flushing); dropped"
[[ ${#usable[@]} -gt 0 ]] \
  || fail "every profraw is empty: no input produced a profile, so any percentage here would be fiction"

"$LLVM_PROFDATA" merge -sparse "${usable[@]}" -o "$OUT_DIR/cov.profdata"

# Restrict coverage to the safetensors crate source (positional source filter), so the
# totals are the parser's line/function coverage, not std/serde/harness.
ST_SRC="$(find "$PROJECT_ROOT/vendor" -maxdepth 2 -type d -path '*safetensors*/src' | head -1)"
[[ -n "$ST_SRC" ]] || fail "could not find vendored safetensors src under $PROJECT_ROOT/vendor"
"$LLVM_COV" export -summary-only \
  -instr-profile="$OUT_DIR/cov.profdata" "$REPLAY" "$ST_SRC" > "$OUT_DIR/llvmcov.json"

# llvm-cov's positional filter FAILS OPEN: a path that does not match anything in the
# binary's coverage mapping is silently ignored and the WHOLE binary is reported, exit 0,
# no diagnostic. ST_SRC is derived from $PROJECT_ROOT, while the mapping holds the
# absolute path used at build time - so relocating the tree (or reaching it through a
# symlink) turns these totals into std+serde+harness while the artifact still reads as
# crate coverage. Demonstrated on the gguf twin: 703/12525 published as 381/1018's label.
python3 - "$OUT_DIR/llvmcov.json" <<'PYCHECK'
import json, re, sys
files = json.load(open(sys.argv[1]))["data"][0]["files"]
if not files:
    sys.exit("[st-cov-run] fail: llvm-cov matched no source file; the filter did not apply")
stray = [f["filename"] for f in files if not re.search(r"/safetensors[^/]*/src/", f["filename"])]
if stray:
    sys.exit("[st-cov-run] fail: the source filter fell back to the whole binary - "
             f"{len(stray)} file(s) outside the safetensors crate, e.g. {stray[0]}. "
             "Any percentage from this run would be fiction.")
PYCHECK

python3 - "$OUT_DIR/llvmcov.json" "$OUT_DIR/coverage.json" "${#inputs[@]}" "$replay_rc" "$REPLAY" <<'PY'
import hashlib, json, os, subprocess, sys
totals = json.load(open(sys.argv[1]))["data"][0]["totals"]
tv = subprocess.check_output(["rustc", "+nightly", "--version"]).decode().strip()
binary_path = os.path.realpath(sys.argv[5])
binary_sha256 = hashlib.sha256(open(binary_path, "rb").read()).hexdigest()
out = {
    "schema_version": "2.0",
    "coverage_kind": "line_function",
    "instrumentation": "rustc-instrument-coverage",
    "toolchain_version": tv,
    "measured_binary": binary_path,
    "measured_binary_sha256": binary_sha256,
    "covered_lines": totals["lines"]["covered"],
    "total_lines": totals["lines"]["count"],
    "covered_functions": totals["functions"]["covered"],
    "total_functions": totals["functions"]["count"],
    # What the number was measured over, and how the run that measured it ended. Recorded
    # rather than assumed: the runner refuses to get here on any status but 0 or 9.
    "corpus_inputs": int(sys.argv[3]),
    "replay_exit": int(sys.argv[4]),
}
json.dump(out, open(sys.argv[2], "w"), indent=2)
print(f"[st-cov-run] coverage.json: lines {out['covered_lines']}/{out['total_lines']} "
      f"functions {out['covered_functions']}/{out['total_functions']}")
PY

echo "[st-cov-run] wrote $OUT_DIR/coverage.json"
