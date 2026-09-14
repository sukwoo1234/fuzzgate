#!/usr/bin/env bash
# V2 ONNX real-coverage run: compile the coverage harness against the
# instrumented libonnxruntime.so, replay a corpus of .onnx models through
# Ort::Session creation, and emit REAL LLVM source coverage (line/function) of
# onnxruntime as coverage.json + a human-readable report.
#
# This is the intended TOOL_COVERAGE_ONNX_CMD target. It is environment-gated and
# fully separate from the baseline run -> triage -> report pipeline.
#
# Prereq: scripts/build_coverage_onnx.sh has produced the instrumented .so.
# Tools MUST be version-matched to the compiler (clang 14 -> llvm-*-14).
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-/home/ssw/bugbounty}"
ORT_VER="${ORT_VER:-v1.23.2}"
ORT_SRC="${ORT_SRC:-$PROJECT_ROOT/data/targets/onnxruntime/$ORT_VER/onnxruntime-1.23.2}"
CONFIG="${CONFIG:-RelWithDebInfo}"
BUILD_DIR="${BUILD_DIR:-build/cov}"
SO_DIR="$ORT_SRC/$BUILD_DIR/$CONFIG"
SO="$SO_DIR/libonnxruntime.so"
HARNESS_SRC="${HARNESS_SRC:-$PROJECT_ROOT/harnesses/coverage-onnx/harness.cc}"
CORPUS_DIR="${CORPUS_DIR:-$PROJECT_ROOT/seeds/onnx}"
SOURCE_CORPUS_DIR="${SOURCE_CORPUS_DIR:-$CORPUS_DIR}"
# Required, like the gguf and safetensors runners. This used to default to
# data/coverage/onnx-smoke, which is a real measurement: the wipe below then deleted it
# whenever the script ran with no OUT_DIR, with no undo. src/coverage.rs always passes
# OUT_DIR, so only the by-hand path was ever exposed - and that is the path that
# re-measures the number.
OUT_DIR="${OUT_DIR:?OUT_DIR must be set by the coverage runner}"
# Toolchain MUST match the one used to build the instrumented .so (clang-17), so
# the harness compile and the profdata/cov readers are all version-consistent.
CLANG_DIR="${CLANG_DIR:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04}"
CLANGXX="${CLANGXX:-$CLANG_DIR/bin/clang++}"
LLVM_PROFDATA="${LLVM_PROFDATA:-$CLANG_DIR/bin/llvm-profdata}"
LLVM_COV="${LLVM_COV:-$CLANG_DIR/bin/llvm-cov}"
COV_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
INCLUDE="-I$ORT_SRC/include/onnxruntime/core/session"

[ -f "$SO" ] || { echo "[run-cov-onnx] instrumented lib not found: $SO (run scripts/build_coverage_onnx.sh first)"; exit 1; }
[ -f "$HARNESS_SRC" ] || { echo "[run-cov-onnx] harness source not found: $HARNESS_SRC"; exit 1; }

rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR/raw"
HARNESS_BIN="$OUT_DIR/onnx_cov_harness"
HARNESS_BUILD_CMD="$CLANGXX -std=c++17 -O1 -g $COV_FLAGS $INCLUDE $HARNESS_SRC -L$SO_DIR -lonnxruntime -Wl,-rpath,$SO_DIR -o $HARNESS_BIN"
echo "[run-cov-onnx] compiling harness"
eval "$HARNESS_BUILD_CMD"

echo "[run-cov-onnx] corpus: $CORPUS_DIR"
mapfile -t MODELS < <(find "$CORPUS_DIR" -type f -name '*.onnx' | sort)
[ "${#MODELS[@]}" -gt 0 ] || { echo "[run-cov-onnx] no .onnx in $CORPUS_DIR"; exit 1; }
echo "[run-cov-onnx] replaying ${#MODELS[@]} models"
# The harness writes one JSON record per input on stdout and a loaded/failed/total line on
# stderr; both used to go nowhere, and its exit status was dropped with `|| true`. Every
# model goes through ONE process here, so a model that kills it leaves a profile covering
# only the models before it - and the report below would still be published against the
# whole corpus, on exit 0, with corpus_models claiming the full count. That is the
# denominator run_coverage_gguf.sh:76-94 keeps by tallying each input's exit. R39.
RECORDS="$OUT_DIR/harness-records.jsonl"
HARNESS_LOG="$OUT_DIR/harness.log"
harness_rc=0
LLVM_PROFILE_FILE="$OUT_DIR/raw/cov-%p-%m.profraw" "$HARNESS_BIN" "${MODELS[@]}" \
  >"$RECORDS" 2>"$HARNESS_LOG" || harness_rc=$?
RECORDED="$(grep -c '^{' "$RECORDS" || true)"
if [ "$harness_rc" -ne 0 ] || [ "$RECORDED" -ne "${#MODELS[@]}" ]; then
  echo "[run-cov-onnx] fail: the harness recorded $RECORDED of ${#MODELS[@]} models (rc=$harness_rc);" \
       "the profile covers only those, so any percentage here would be published against a" \
       "corpus it did not measure. See $HARNESS_LOG and $RECORDS"
  exit 1
fi
# bytes:-1 is the harness's "cannot open file": the input never reached onnxruntime. If
# that is every input, the library was never entered and a 0% report would read like a
# finding - the shape run_coverage_gguf.sh:98-99 refuses as "the replay never ran".
UNOPENED="$(grep -c '"bytes":-1' "$RECORDS" || true)"
if [ "$UNOPENED" -eq "${#MODELS[@]}" ]; then
  echo "[run-cov-onnx] fail: none of the ${#MODELS[@]} models could be opened; nothing reached onnxruntime"
  exit 1
fi
LOADED="$(grep -c '"session_ok":true' "$RECORDS" || true)"
echo "[run-cov-onnx] recorded=$RECORDED loaded=$LOADED unopened=$UNOPENED of ${#MODELS[@]}"

echo "[run-cov-onnx] merging profiles"
# A process that dies without flushing leaves a 0-BYTE profraw, and llvm-profdata merges
# those without complaint - a run where nothing was measured becomes a well-formed 0%
# report on exit 0. run_coverage_gguf.sh:106-118 drops them; this used to hand the merge a
# raw glob.
shopt -s nullglob
PROFS=("$OUT_DIR"/raw/*.profraw)
shopt -u nullglob
[ "${#PROFS[@]}" -gt 0 ] || { echo "[run-cov-onnx] fail: no profraw produced (instrumentation did not run)"; exit 1; }
USABLE=()
for f in "${PROFS[@]}"; do [ -s "$f" ] && USABLE+=("$f"); done
EMPTY=$(( ${#PROFS[@]} - ${#USABLE[@]} ))
[ "$EMPTY" -eq 0 ] \
  || echo "[run-cov-onnx] WARN: $EMPTY of ${#PROFS[@]} profraw files are empty (process died before flushing); dropped"
[ "${#USABLE[@]}" -gt 0 ] \
  || { echo "[run-cov-onnx] fail: every profraw is empty; no model produced a profile, so any percentage here would be fiction"; exit 1; }
"$LLVM_PROFDATA" merge -sparse "${USABLE[@]}" -o "$OUT_DIR/cov.profdata"

# onnxruntime sources only: exclude fetched deps / generated build files.
IGNORE='(_deps/|/build/|/external/|/test/)'
echo "[run-cov-onnx] llvm-cov report"
"$LLVM_COV" report "$SO" -instr-profile="$OUT_DIR/cov.profdata" \
  -ignore-filename-regex="$IGNORE" | tee "$OUT_DIR/llvm-cov-report.txt"
"$LLVM_COV" export "$SO" -instr-profile="$OUT_DIR/cov.profdata" -summary-only \
  -ignore-filename-regex="$IGNORE" > "$OUT_DIR/llvm-cov-summary.json"

echo "[run-cov-onnx] writing coverage.json (V2 schema fields; missing fields omitted, no fake values)"
TOOL_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo not_available)"
CLANG_VER="$("$CLANGXX" --version | head -1)"
MACHINE_LABEL="${TOOL_MACHINE_LABEL:-}"
python3 - "$OUT_DIR/llvm-cov-summary.json" "$OUT_DIR/coverage.json" \
  "$HARNESS_BIN" "$SOURCE_CORPUS_DIR" "$TOOL_COMMIT" "$CLANG_VER" "$HARNESS_BUILD_CMD" \
  "${#MODELS[@]}" "$MACHINE_LABEL" "$RECORDED" "$LOADED" <<'PY'
import json, sys
(summ_path, out_path, harness, corpus, commit, clangver,
 buildcmd, nmodels, machine, recorded, loaded) = sys.argv[1:12]
with open(summ_path) as f:
    data = json.load(f)
tot = data["data"][0]["totals"]
lines = tot.get("lines", {}); funcs = tot.get("functions", {}); regions = tot.get("regions", {})
cov = {
  "schema_version": "2.0",
  "target": "onnx",
  "coverage_kind": "line_function",
  "instrumentation": "llvm-source-cov",
  "toolchain": "clang",
  "toolchain_version": clangver,
  "tool_commit": commit,
  "harness_path": harness,
  "harness_build_command": buildcmd,
  "source_corpus": corpus,
  # corpus_models is what was HANDED to the harness. models_recorded is what it reported
  # back, and the runner refuses to get here unless the two agree - so the denominator is
  # observed, not claimed. sessions_loaded is how many of those built a full session; it is
  # deliberately not a pass/fail, since a corpus of malformed models covers the parser
  # precisely by failing.
  "corpus_models": int(nmodels),
  "models_recorded": int(recorded),
  "sessions_loaded": int(loaded),
  "covered_lines": lines.get("covered"),
  "total_lines": lines.get("count"),
  "line_coverage": lines.get("percent"),
  "covered_functions": funcs.get("covered"),
  "total_functions": funcs.get("count"),
  "function_coverage": funcs.get("percent"),
  "covered_regions": regions.get("covered"),
  "total_regions": regions.get("count"),
  "machine_label": machine or None,
}
cov = {k: v for k, v in cov.items() if v is not None}  # omit missing -> no fake values
with open(out_path, "w") as f:
    json.dump(cov, f, indent=2)
print(json.dumps(cov, indent=2))
PY
echo "[run-cov-onnx] done. artifacts in $OUT_DIR"
