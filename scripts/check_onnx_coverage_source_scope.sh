#!/usr/bin/env bash
# R138: prove the ONNX coverage runner scopes llvm-cov to the source paths recorded
# in the instrumented library instead of excluding them because an ancestor directory
# happens to be named "build".
#
# The BASE-02 recovery build lives below an evidence path containing
# build/onnx-coverage-source.  The old regex ignored every filename containing /build/,
# so llvm-cov returned a well-formed all-zero report after 26 models had really run.
# This fixture keeps the mapped ONNX source below /build/, puts the runnable library in
# an unrelated view, and makes llvm-cov return positive coverage only when the runner
# discovers and reuses the mapped source root.  The repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
RUNNER="$PROJECT_ROOT/scripts/run_coverage_onnx.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/onnx-coverage-source-scope-XXXXXX")"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

VIEW="$WORK/view"
OUT="$WORK/out"
CORPUS="$WORK/corpus"
TOOLCHAIN="$WORK/toolchain"
BIN="$TOOLCHAIN/bin"
MAPPED_DIST="$WORK/evidence/build/onnx-coverage-source/onnxruntime-1.23.2"
MAPPED_ROOT="$MAPPED_DIST/onnxruntime"
MAPPED_INCLUDE_ROOT="$MAPPED_DIST/include/onnxruntime"
SO_DIR="$VIEW/build/cov/RelWithDebInfo"
mkdir -p "$SO_DIR" "$VIEW/include/onnxruntime/core/session" "$CORPUS" "$BIN" \
         "$MAPPED_ROOT/core/session" "$MAPPED_INCLUDE_ROOT/core/session"
printf 'instrumented-library-fixture' >"$SO_DIR/libonnxruntime.so"
printf '// harness fixture\n' >"$WORK/harness.cc"
printf 'onnx fixture\n' >"$CORPUS/model.onnx"
printf '// mapped source fixture\n' >"$MAPPED_ROOT/core/session/inference_session.cc"
printf '// mapped public header fixture\n' >"$MAPPED_INCLUDE_ROOT/core/session/onnxruntime_cxx_api.h"

cat >"$BIN/clang++" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == --version ]]; then
  printf 'clang version 17.0.6 (fixture)\n'
  exit 0
fi
out=''
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then out="$2"; shift 2; else shift; fi
done
[[ -n "$out" ]]
cat >"$out" <<'HARNESS'
#!/usr/bin/env bash
set -euo pipefail
raw_dir="$(dirname -- "${LLVM_PROFILE_FILE:?}")"
printf 'non-empty profile\n' >"$raw_dir/cov-fixture.profraw"
for model in "$@"; do
  printf '{"path":"%s","bytes":1,"session_ok":true}\n' "$model"
done
HARNESS
chmod +x "$out"
SH
chmod +x "$BIN/clang++"

cat >"$BIN/llvm-profdata" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
out=''
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then out="$2"; shift 2; else shift; fi
done
[[ -n "$out" ]]
printf 'merged profile fixture\n' >"$out"
SH
chmod +x "$BIN/llvm-profdata"

cat >"$BIN/llvm-cov" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cmd="${1:?}"; shift
mapped="${EXPECTED_MAPPED_ROOT:?}"
mapped_include="${EXPECTED_MAPPED_INCLUDE_ROOT:?}"
printf '%s %s\n' "$cmd" "$*" >>"${LLVM_COV_CALLS:?}"
has_source=no
has_include=no
old_ignore=no
for arg in "$@"; do
  [[ "$arg" == "$mapped" ]] && has_source=yes
  [[ "$arg" == "$mapped_include" ]] && has_include=yes
  [[ "$arg" == *ignore-filename-regex*'/build/'* ]] && old_ignore=yes
done
scoped=no
[[ "$has_source" == yes && "$has_include" == yes ]] && scoped=yes
if [[ "$cmd" == report ]]; then
  if [[ "$scoped" == yes ]]; then
    printf 'TOTAL 100 0 40 40.00%% 10 0 4 40.00%%\n'
  else
    printf 'TOTAL 0 0 0 0.00%% 0 0 0 0.00%%\n'
  fi
  exit 0
fi
[[ "$cmd" == export ]]
if [[ "$scoped" == yes ]]; then
  cat <<JSON
{"data":[{"files":[{"filename":"$mapped/core/session/inference_session.cc"},{"filename":"$mapped_include/core/session/onnxruntime_cxx_api.h"}],"totals":{"lines":{"count":100,"covered":40,"percent":40.0},"functions":{"count":10,"covered":4,"percent":40.0},"regions":{"count":120,"covered":48,"percent":40.0}}}],"type":"llvm.coverage.json.export","version":"2.0.1"}
JSON
elif [[ "$old_ignore" == yes ]]; then
  cat <<'JSON'
{"data":[{"files":[],"totals":{"lines":{"count":0,"covered":0,"percent":0.0},"functions":{"count":0,"covered":0,"percent":0.0},"regions":{"count":0,"covered":0,"percent":0.0}}}],"type":"llvm.coverage.json.export","version":"2.0.1"}
JSON
else
  cat <<JSON
{"data":[{"files":[{"filename":"$mapped/core/session/inference_session.cc"},{"filename":"$mapped_include/core/session/onnxruntime_cxx_api.h"},{"filename":"$WORKSPACE_DEP/source.cc"}],"totals":{"lines":{"count":150,"covered":60,"percent":40.0},"functions":{"count":15,"covered":6,"percent":40.0},"regions":{"count":180,"covered":72,"percent":40.0}}}],"type":"llvm.coverage.json.export","version":"2.0.1"}
JSON
fi
SH
chmod +x "$BIN/llvm-cov"

runner_rc=0
env PROJECT_ROOT="$PROJECT_ROOT" ORT_SRC="$VIEW" BUILD_DIR=build/cov \
    HARNESS_SRC="$WORK/harness.cc" CORPUS_DIR="$CORPUS" SOURCE_CORPUS_DIR="$CORPUS" \
    OUT_DIR="$OUT" CLANG_DIR="$TOOLCHAIN" EXPECTED_MAPPED_ROOT="$MAPPED_ROOT" \
    EXPECTED_MAPPED_INCLUDE_ROOT="$MAPPED_INCLUDE_ROOT" \
    LLVM_COV_CALLS="$WORK/llvm-cov.calls" WORKSPACE_DEP="$WORK/dependency" \
    bash "$RUNNER" >"$WORK/runner.log" 2>&1 || runner_rc=$?

if [[ "$runner_rc" -eq 0 ]]; then
  ok 'the real ONNX runner completed against the mapped-source fixture'
else
  bad "the real ONNX runner failed against the mapped-source fixture (rc=$runner_rc)"
  tail -20 "$WORK/runner.log" | sed 's/^/       /'
fi

if [[ -f "$OUT/coverage.json" ]] && python3 - "$OUT/coverage.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["covered_lines"] == 40 and d["total_lines"] == 100
assert d["covered_functions"] == 4 and d["total_functions"] == 10
assert d["covered_regions"] == 48 and d["total_regions"] == 120
PY
then
  ok 'coverage.json contains the positive ONNX-only totals (40/100 lines)'
else
  bad 'coverage.json published zero, missing, or unscoped totals'
  [[ ! -f "$OUT/coverage.json" ]] || sed 's/^/       /' "$OUT/coverage.json"
fi

if [[ -f "$WORK/llvm-cov.calls" ]] \
   && grep -q '^export ' "$WORK/llvm-cov.calls" \
   && grep -Fq "$MAPPED_ROOT" "$WORK/llvm-cov.calls" \
   && grep -Fq "$MAPPED_INCLUDE_ROOT" "$WORK/llvm-cov.calls" \
   && ! grep -Fq 'ignore-filename-regex=(_deps/|/build/' "$WORK/llvm-cov.calls"; then
  ok 'llvm-cov was scoped with mapped ONNX source and public-header roots'
else
  bad 'llvm-cov did not receive both mapped ONNX roots cleanly'
  [[ ! -f "$WORK/llvm-cov.calls" ]] || sed 's/^/       /' "$WORK/llvm-cov.calls"
fi

printf '[onnx-coverage-source-scope] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
