#!/usr/bin/env bash
# Trusted TFL-05 runner: measure pinned TensorFlow Lite source paths, not the
# harness driver. src/coverage.rs authenticates these exact bytes before use.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
TARGET_ROOT="${TFLITE_TARGET_ROOT:-$PROJECT_ROOT/data/targets/tflite/v2.20.0}"
BUILD_DIR="${TFLITE_COVERAGE_BUILD_DIR:-$TARGET_ROOT/build/coverage-cmake}"
REPLAY="${TFLITE_COVERAGE_REPLAY:-$BUILD_DIR/tflite_loader_replay}"
TARGET_LIBRARY="${TFLITE_COVERAGE_LIBRARY:-$BUILD_DIR/tensorflow-lite/libtensorflow-lite.a}"
OUT_DIR="${OUT_DIR:?OUT_DIR must be set by the coverage runner}"
CORPUS_DIR="${CORPUS_DIR:?CORPUS_DIR must be set by the coverage runner}"
SOURCE_CORPUS_DIR="${SOURCE_CORPUS_DIR:-$CORPUS_DIR}"
CLANG_BUNDLE_DIR="${CLANG_BUNDLE_DIR:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin}"
LLVM_PROFDATA="${LLVM_PROFDATA:-$CLANG_BUNDLE_DIR/llvm-profdata}"
LLVM_COV="${LLVM_COV:-$CLANG_BUNDLE_DIR/llvm-cov}"
CLANGXX="${CLANGXX:-$CLANG_BUNDLE_DIR/clang++}"

log() { printf '[tflite-cov-run] %s\n' "$*"; }
fail() { printf '[tflite-cov-run] fail: %s\n' "$*" >&2; exit 1; }

[[ -d "$PROJECT_ROOT/scripts" ]] \
  || fail "PROJECT_ROOT=$PROJECT_ROOT does not look like the repository"
if [[ ! -x "$REPLAY" || ! -f "$TARGET_LIBRARY" ]]; then
  log "instrumented replay missing; building isolated coverage objects"
  PROJECT_ROOT="$PROJECT_ROOT" TFLITE_TARGET_ROOT="$TARGET_ROOT" \
    bash "$PROJECT_ROOT/scripts/build_coverage_tflite.sh" >/dev/null \
    || fail "build_coverage_tflite.sh failed"
fi
[[ -x "$REPLAY" ]] || fail "coverage replay is missing: $REPLAY"
[[ -f "$TARGET_LIBRARY" ]] || fail "coverage target archive is missing: $TARGET_LIBRARY"
[[ -x "$LLVM_PROFDATA" ]] || fail "llvm-profdata is missing: $LLVM_PROFDATA"
[[ -x "$LLVM_COV" ]] || fail "llvm-cov is missing: $LLVM_COV"
[[ -x "$CLANGXX" ]] || fail "matching clang++ is missing: $CLANGXX"

RAW="$OUT_DIR/raw"
rm -rf -- "$RAW" "$OUT_DIR/cov.profdata" "$OUT_DIR/llvmcov.json" \
  "$OUT_DIR/coverage.json" "$OUT_DIR/replay.log"
mkdir -p -- "$RAW"

shopt -s nullglob
inputs=("$CORPUS_DIR"/*.tflite)
shopt -u nullglob
[[ ${#inputs[@]} -gt 0 ]] || fail "no *.tflite inputs in $CORPUS_DIR"

accepted=0
rejected=0
: >"$OUT_DIR/replay.log"
for i in "${!inputs[@]}"; do
  rc=0
  LLVM_PROFILE_FILE="$RAW/cov-$i-%p.profraw" "$REPLAY" "${inputs[$i]}" \
    >>"$OUT_DIR/replay.log" 2>&1 || rc=$?
  case "$rc" in
    0) accepted=$((accepted + 1)) ;;
    9) rejected=$((rejected + 1)) ;;
    10) fail "replay unavailable for $(basename "${inputs[$i]}"); nothing was measured" ;;
    *) fail "replay stopped with rc=$rc for $(basename "${inputs[$i]}"); see $OUT_DIR/replay.log" ;;
  esac
done
log "replayed ${#inputs[@]} inputs (accepted=$accepted rejected=$rejected)"

shopt -s nullglob
profiles=("$RAW"/*.profraw)
shopt -u nullglob
[[ ${#profiles[@]} -eq ${#inputs[@]} ]] \
  || fail "expected ${#inputs[@]} raw profiles, observed ${#profiles[@]}"
usable=()
for profile in "${profiles[@]}"; do
  [[ -s "$profile" ]] && usable+=("$profile")
done
[[ ${#usable[@]} -eq ${#profiles[@]} ]] \
  || fail "one or more raw profiles are empty; refusing a partial measurement"

"$LLVM_PROFDATA" merge -sparse "${usable[@]}" -o "$OUT_DIR/cov.profdata"
"$LLVM_COV" export -instr-profile="$OUT_DIR/cov.profdata" "$REPLAY" \
  >"$OUT_DIR/llvmcov.json"

python3 -B - "$OUT_DIR/llvmcov.json" "$OUT_DIR/coverage.json" "$REPLAY" \
  "$TARGET_LIBRARY" "$SOURCE_CORPUS_DIR" "${#inputs[@]}" "$accepted" "$rejected" \
  "$CLANGXX" <<'PY'
import hashlib
import json
import os
import subprocess
import sys

(export_path, output_path, replay_path, library_path, source_corpus,
 input_count, accepted, rejected, compiler) = sys.argv[1:]
document = json.load(open(export_path, encoding="utf-8"))
data = document.get("data")
if not isinstance(data, list) or len(data) != 1:
    raise SystemExit("[tflite-cov-run] fail: llvm-cov export has unexpected data rows")
files = data[0].get("files")
if not isinstance(files, list) or not files:
    raise SystemExit("[tflite-cov-run] fail: llvm-cov export contains no mapped files")

def normalized(path):
    return path.replace("\\", "/")

def target_source(path):
    value = normalized(path)
    return "/tensorflow/lite/" in value or "/tensorflow/compiler/mlir/lite/" in value

def hit_in_range(entry, start, end):
    for segment in entry.get("segments", []):
        if len(segment) >= 4:
            line, _column, count, has_count = segment[:4]
            if start <= line <= end and has_count and count > 0:
                return line, count
    return None

# These ranges are pinned to TensorFlow v2.20.0. They name the implementation
# entered by the public loader contract: verified model construction, allocation,
# and checked tensor access. A hit in loader.cc alone cannot satisfy any probe.
probes = {
    "model_loading": [
        ("/tensorflow/compiler/mlir/lite/core/model_builder_base.h", 196, 204),
        ("/tensorflow/compiler/mlir/lite/core/model_builder_base.h", 371, 407),
    ],
    "allocation": [
        ("/tensorflow/lite/core/interpreter.cc", 190, 201),
        ("/tensorflow/lite/core/subgraph.cc", 980, 1035),
    ],
    "tensor_access": [
        ("/tensorflow/lite/core/interpreter.h", 288, 301),
        ("/tensorflow/lite/core/subgraph.h", 185, 206),
    ],
}

evidence = {}
for label, candidates in probes.items():
    found = None
    for suffix, start, end in candidates:
        for entry in files:
            filename = normalized(entry.get("filename", ""))
            if filename.endswith(suffix):
                hit = hit_in_range(entry, start, end)
                if hit is not None:
                    found = {
                        "source": filename[filename.find("tensorflow/"):],
                        "line": hit[0],
                        "count": hit[1],
                    }
                    break
        if found is not None:
            break
    if found is None:
        raise SystemExit(
            f"[tflite-cov-run] fail: no executed target-source line for {label}; "
            "driver-only evidence is not accepted"
        )
    evidence[label] = found

target_files = [entry for entry in files if target_source(entry.get("filename", ""))]
if not target_files:
    raise SystemExit("[tflite-cov-run] fail: no TensorFlow Lite target source in coverage mapping")
line_count = sum(entry.get("summary", {}).get("lines", {}).get("count", 0) for entry in target_files)
line_covered = sum(entry.get("summary", {}).get("lines", {}).get("covered", 0) for entry in target_files)
function_count = sum(entry.get("summary", {}).get("functions", {}).get("count", 0) for entry in target_files)
function_covered = sum(entry.get("summary", {}).get("functions", {}).get("covered", 0) for entry in target_files)
if line_count <= 0 or line_covered <= 0 or function_count <= 0 or function_covered <= 0:
    raise SystemExit("[tflite-cov-run] fail: target-source coverage totals are empty")

def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

binary_path = os.path.realpath(replay_path)
output = {
    "schema_version": "2.0",
    "target": "tflite",
    "target_version": "v2.20.0",
    "coverage_kind": "line_function",
    "instrumentation": "llvm-source-cov",
    "toolchain_version": subprocess.check_output([compiler, "--version"], text=True).splitlines()[0],
    "measured_binary": binary_path,
    "measured_binary_sha256": sha(binary_path),
    "measured_target_archive": os.path.realpath(library_path),
    "measured_target_archive_sha256": sha(library_path),
    "measured_sources": sorted({row["source"] for row in evidence.values()}),
    "required_path_hits": {label: True for label in probes},
    "required_path_evidence": evidence,
    "driver_only_evidence_accepted": False,
    "source_corpus": source_corpus,
    "corpus_models": int(input_count),
    "accepted_models": int(accepted),
    "rejected_models": int(rejected),
    "covered_lines": line_covered,
    "total_lines": line_count,
    "covered_functions": function_covered,
    "total_functions": function_count,
}
with open(output_path, "w", encoding="utf-8") as stream:
    json.dump(output, stream, indent=2, sort_keys=True)
    stream.write("\n")
print(
    f"[tflite-cov-run] coverage.json: target lines {line_covered}/{line_count} "
    f"functions {function_covered}/{function_count}"
)
for label, row in evidence.items():
    print(f"[tflite-cov-run] {label}: {row['source']}:{row['line']} count={row['count']}")
PY

log "wrote $OUT_DIR/coverage.json"
