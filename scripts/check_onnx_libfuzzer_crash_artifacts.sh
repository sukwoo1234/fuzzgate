#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
DATA_DIR="${DATA_DIR:-$PROJECT_ROOT/data/onnx-libfuzzer-artifact-check}"
CRASH_POC="${ONNX_CRASH_POC:-${ONNX_SIGSEGV_POC:-}}"
REQUIRE_POC=0

SIGSEGV_SHA256="61d1c65cde3c8ba65433229f23704f5163708f001664c5a5cced5e28cc202ac8"

usage() {
  cat <<'EOF'
usage: check_onnx_libfuzzer_crash_artifacts.sh [--require-poc]

PoC files are intentionally not committed. Provide a local known-crash path via:
  ONNX_SIGSEGV_POC=/path/to/crash_protobuf.onnx
or:
  ONNX_CRASH_POC=/path/to/crash_protobuf.onnx

Checks:
  - native libFuzzer harness is built
  - libFuzzer writes a crash artifact under artifact_prefix
  - tool run ingests backend artifacts
  - automatic backend triage reproduces at least one crash

Without --require-poc, a missing PoC env var leaves the private artifact check unrun and
exits non-zero; set ALLOW_SKIPPED_CASES=1 only if you accept that unverified run.
With --require-poc, a missing PoC env var or failed check is a hard failure that
ALLOW_SKIPPED_CASES=1 does not excuse.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-poc) REQUIRE_POC=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[onnx-libfuzzer-artifact-check] unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

log() {
  echo "[onnx-libfuzzer-artifact-check] $*"
}

fail() {
  echo "[onnx-libfuzzer-artifact-check] fail: $*" >&2
  exit 1
}

json_number_field() {
  local file="$1"
  local key="$2"
  python3 - "$file" "$key" <<'PY'
import json, sys
path, key = sys.argv[1:3]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
value = data.get(key, 0)
print(value if isinstance(value, int) else 0)
PY
}

latest_status() {
  find "$DATA_DIR/runs" -mindepth 2 -maxdepth 2 -type f -name status.json 2>/dev/null \
    | sort \
    | tail -n 1
}

# R86: a check that observed nothing must not report success. The PoC is deliberately not
# committed (see usage above), and seeds/ and harnesses/ are gitignored too, so a freshly
# prepared fuzzing host is exactly the host that takes this branch - `exit 0` here put the
# private artifact case into the suite's rc-only tally without observing anything. Measured
# 2026-09-19 on a tree extracted with `git archive HEAD`: no PoC env var, one skip line,
# rc=0, and check_gate_tool_precondition.sh scored that as a skip rather than a defect. The
# skip line stays - the operator still needs to read which precondition is missing - and the
# exit does not. ALLOW_SKIPPED_CASES=1 is the documented opt-out, the same variable and the
# same register as check_engine_mode_labels.sh:630 (R42); --require-poc refuses above,
# before the opt-out is ever consulted, so the strict flag stays strictly stricter.
#
# Before R113, using "this gate cannot run" here made check_gate_tool_precondition.sh
# fail an unrelated opposite-polarity assertion (measured pass=13 fail=1 skip=1).
# That assertion now checks for the exact absent TOOL_BIN path; a PoC-only refusal
# cannot be mistaken for a refusal about the binary by sharing the phrase.
if [[ -z "$CRASH_POC" ]]; then
  if [[ "$REQUIRE_POC" -eq 1 ]]; then
    fail "ONNX_SIGSEGV_POC or ONNX_CRASH_POC is required"
  fi
  log "skip: ONNX_SIGSEGV_POC/ONNX_CRASH_POC not set"
  if [[ "${ALLOW_SKIPPED_CASES:-0}" != "1" ]]; then
    fail "the private artifact case (known-crash PoC ingest and backend triage) did not run; set ALLOW_SKIPPED_CASES=1 only if you accept an unverified run"
  fi
  echo "[onnx-libfuzzer-artifact-check] WARN: continuing with skipped cases (ALLOW_SKIPPED_CASES=1)" >&2
  exit 0
fi

[[ -f "$CRASH_POC" ]] || fail "PoC not found: $CRASH_POC"
actual_sha="$(sha256sum "$CRASH_POC" | awk '{print $1}')"
[[ "$actual_sha" == "$SIGSEGV_SHA256" ]] || fail "PoC sha256 mismatch: got $actual_sha expected $SIGSEGV_SHA256"

# The PoC is deliberately not committed (see usage above), so the path handed in here is
# usually the operator's only local copy - and the path most likely to be handed in is the
# one a previous run left inside the default DATA_DIR, which `rm -rf "$DATA_DIR"` below
# removes. The A11 guard next to that rm inspects DATA_DIR's *name* only, so it cannot see
# this case: the name is exactly the dedicated one it demands. Compare resolved paths and
# not text, because a symlink or a `..` walks straight through a string test. Refusing here,
# before the tool and the harness are built, makes the refusal immediate instead of costing
# a native build first.
poc_real="$(realpath -- "$CRASH_POC")"
data_real="$(realpath -m -- "$DATA_DIR")"
case "$poc_real" in
  "$data_real" | "$data_real"/*)
    fail "PoC '$CRASH_POC' is inside DATA_DIR '$DATA_DIR', which this check wipes; copy it outside that tree (or point DATA_DIR elsewhere) and rerun"
    ;;
esac

# R95/R92: not a build, for the same reason the PoC case above is not a silent skip - a check
# that had to manufacture its own precondition observed a tree it made, not the tree it was
# given. `cargo build --offline` here is R92's mechanism: measured 2026-09-19 on a tree
# extracted with `git archive HEAD`, check_aflpp_asan_env.sh ends rc=1 before its sibling
# ONNX gate runs and rc=0 after, on the same tree. It cannot even work for a caller who
# redirected TOOL_BIN, since the build installs at target/debug/tool. Unlike the PoC refusal
# above, this one names the missing TOOL_BIN path and says "this gate cannot run";
# both are required by check_gate_tool_precondition.sh's absent-tool verdict.
if [[ ! -x "$TOOL_BIN" ]]; then
  printf '[onnx-libfuzzer-artifact-check] fail: tool binary not executable: %s\n' "$TOOL_BIN" >&2
  printf '[onnx-libfuzzer-artifact-check] build it with `cargo build` or point TOOL_BIN at one; this gate cannot run\n' >&2
  exit 1
fi

log "build native libFuzzer harness"
"$PROJECT_ROOT/scripts/build_libfuzzer_onnx_native.sh" >/tmp/onnx-libfuzzer-artifact-build.log

# A11 guard: never wipe a caller-supplied DATA_DIR that is not the dedicated scratch
# dir. Exporting DATA_DIR=<real data root> for a fuzzing session is a documented
# convention, and an unguarded `rm -rf "$DATA_DIR"` would delete the entire data tree.
case "$DATA_DIR" in
  */onnx-libfuzzer-artifact-check | */onnx-libfuzzer-artifact-check/) : ;;
  *) fail "refusing to wipe DATA_DIR='$DATA_DIR': must be a dedicated onnx-libfuzzer-artifact-check scratch dir (unset DATA_DIR or point it at one)" ;;
esac
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
corpus_dir="$(mktemp -d "$DATA_DIR/corpus.XXXXXX")"
cp "$CRASH_POC" "$corpus_dir/crash_protobuf.onnx"

export TOOL_LIBFUZZER_CMD='mkdir -p {artifact_dir} && LLVM_PROFILE_FILE={artifact_dir}/onnx-native-%p.profraw '"$PROJECT_ROOT"'/harnesses/libfuzzer/onnxruntime_loader_fuzzer -artifact_prefix={artifact_dir}/ -runs=1 {corpus_dir} >/dev/null 2>&1'

log "run backend libFuzzer with known-crash corpus"
set +e
"$TOOL_BIN" --data-dir "$DATA_DIR" run \
  --target onnx \
  --backend libfuzzer \
  --corpus-dir "$corpus_dir" \
  --workers 1 \
  --timeout-sec 30 \
  --restart-limit 0 \
  >"$DATA_DIR/tool-run.log" 2>&1
run_rc=$?
set -e

if [[ "$run_rc" -eq 0 ]]; then
  fail "tool run unexpectedly succeeded for known-crash libFuzzer corpus"
fi

status="$(latest_status)"
[[ -n "$status" && -f "$status" ]] || { cat "$DATA_DIR/tool-run.log" >&2 || true; fail "status.json not found"; }

artifacts="$(json_number_field "$status" backend_crash_artifacts)"
triaged="$(json_number_field "$status" backend_crashes_triaged)"
errors="$(json_number_field "$status" backend_crash_triage_errors)"

[[ "$artifacts" -ge 1 ]] || { cat "$DATA_DIR/tool-run.log" >&2 || true; fail "backend_crash_artifacts=$artifacts status=$status"; }
[[ "$triaged" -ge 1 ]] || { cat "$DATA_DIR/tool-run.log" >&2 || true; fail "backend_crashes_triaged=$triaged status=$status"; }
[[ "$errors" -eq 0 ]] || { cat "$DATA_DIR/tool-run.log" >&2 || true; fail "backend_crash_triage_errors=$errors status=$status"; }

log "done: artifacts=$artifacts triaged=$triaged status=$status"
