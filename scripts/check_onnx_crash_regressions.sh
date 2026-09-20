#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
DATA_DIR="${DATA_DIR:-$PROJECT_ROOT/data/onnx-crash-regressions}"
REQUIRE_POCS=0

SIGFPE_SHA256="85ed3df33cc1f612a69276bb038e6fd7191108ce3cd9f52f0ff26217a4ff1b5a"
SIGSEGV_SHA256="61d1c65cde3c8ba65433229f23704f5163708f001664c5a5cced5e28cc202ac8"

usage() {
  cat <<'EOF'
usage: check_onnx_crash_regressions.sh [--require-pocs]

PoC files are intentionally not committed. Provide local paths via:
  ONNX_SIGFPE_POC=/path/to/poc_checker_valid_sigfpe.onnx
  ONNX_SIGSEGV_POC=/path/to/crash_protobuf.onnx

Checks:
  - sha256 matches the expected private PoC
  - tool triage reproduces the crash
  - summary verdict is reproduced
  - signal matches SIGFPE/SIGSEGV respectively

Without --require-pocs, a missing env var leaves the corresponding private regression unrun
and exits non-zero; set ALLOW_SKIPPED_CASES=1 only if you accept that unverified run.
With --require-pocs, missing env vars or failed checks are hard failures that
ALLOW_SKIPPED_CASES=1 does not excuse.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-pocs) REQUIRE_POCS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[onnx-crash-regression] unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

log() {
  echo "[onnx-crash-regression] $*"
}

fail() {
  echo "[onnx-crash-regression] fail: $*" >&2
  exit 1
}

json_string_field() {
  local file="$1"
  local key="$2"
  python3 - "$file" "$key" <<'PY'
import json, sys
path, key = sys.argv[1:3]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
value = data.get(key, "")
print(value if isinstance(value, str) else "")
PY
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

latest_summary() {
  local before="$1"
  find "$DATA_DIR/triage" -mindepth 2 -maxdepth 2 -type f -name summary.json -newer "$before" 2>/dev/null \
    | sort \
    | tail -n 1
}

check_one() {
  local label="$1"
  local path="$2"
  local expected_sha="$3"
  local expected_signal="$4"

  [[ -n "$path" ]] || fail "$label path is empty"
  [[ -f "$path" ]] || fail "$label PoC not found: $path"

  local actual_sha
  actual_sha="$(sha256sum "$path" | awk '{print $1}')"
  [[ "$actual_sha" == "$expected_sha" ]] || fail "$label sha256 mismatch: got $actual_sha expected $expected_sha"

  mkdir -p "$DATA_DIR"
  local marker
  marker="$(mktemp "$DATA_DIR/.triage-before-${label}.XXXXXX")"

  log "$label triage start"
  if ! "$TOOL_BIN" --data-dir "$DATA_DIR" triage \
    --target onnx \
    --input "$path" \
    --repro-retries 1 \
    --timeout-sec 30 \
    >"$DATA_DIR/${label}.triage.log" 2>&1
  then
    cat "$DATA_DIR/${label}.triage.log" >&2 || true
    rm -f "$marker"
    fail "$label triage command failed"
  fi

  local summary
  summary="$(latest_summary "$marker")"
  rm -f "$marker"
  [[ -n "$summary" && -f "$summary" ]] || fail "$label summary not found"

  local verdict signal crashed clean
  verdict="$(json_string_field "$summary" verdict)"
  signal="$(json_string_field "$summary" signal)"
  crashed="$(json_number_field "$summary" crashed_count)"
  clean="$(json_number_field "$summary" clean_count)"

  [[ "$verdict" == "reproduced" ]] || fail "$label verdict=$verdict summary=$summary"
  [[ "$signal" == "$expected_signal" ]] || fail "$label signal=$signal expected=$expected_signal summary=$summary"
  [[ "$crashed" -ge 1 ]] || fail "$label crashed_count=$crashed summary=$summary"
  [[ "$clean" -eq 0 ]] || fail "$label clean_count=$clean summary=$summary"

  log "$label ok: verdict=$verdict signal=$signal summary=$summary"
}

# R95/R92: not a build. This gate drives the real tool, so without the binary it observes
# nothing, and the shape for that is a refusal - check_aflpp_asan_env.sh:12-15, copied word
# for word so an operator reads the same sentence from every gate that needs the tool. It ran
# `cargo build --offline` here instead, which is R92's mechanism: one gate manufacturing
# another gate's precondition, after which a suite verdict depends on run order. Measured
# 2026-09-19 on a tree extracted with `git archive HEAD`: check_aflpp_asan_env.sh rc=1, then
# this gate, then check_aflpp_asan_env.sh rc=0 - the same gate on the same tree, passing
# because this one had built its binary for it. The build also installs at target/debug/tool
# and never at TOOL_BIN, so under a redirected TOOL_BIN it could not produce the file the
# check below is looking for.
if [[ ! -x "$TOOL_BIN" ]]; then
  printf '[onnx-crash-regression] fail: tool binary not executable: %s\n' "$TOOL_BIN" >&2
  printf '[onnx-crash-regression] build it with `cargo build` or point TOOL_BIN at one; this gate cannot run\n' >&2
  exit 1
fi

ran=0
SKIPPED=""
note_skip() { SKIPPED="${SKIPPED:+$SKIPPED|}$1"; }

if [[ -n "${ONNX_SIGFPE_POC:-}" ]]; then
  check_one "sigfpe" "$ONNX_SIGFPE_POC" "$SIGFPE_SHA256" "SIGFPE"
  ran=$((ran + 1))
elif [[ "$REQUIRE_POCS" -eq 1 ]]; then
  fail "ONNX_SIGFPE_POC is required"
else
  log "skip sigfpe: ONNX_SIGFPE_POC not set"
  note_skip "sigfpe: the SIGFPE regression (ONNX_SIGFPE_POC not set)"
fi

if [[ -n "${ONNX_SIGSEGV_POC:-}" ]]; then
  check_one "sigsegv" "$ONNX_SIGSEGV_POC" "$SIGSEGV_SHA256" "SIGSEGV"
  ran=$((ran + 1))
elif [[ "$REQUIRE_POCS" -eq 1 ]]; then
  fail "ONNX_SIGSEGV_POC is required"
else
  log "skip sigsegv: ONNX_SIGSEGV_POC not set"
  note_skip "sigsegv: the SIGSEGV regression (ONNX_SIGSEGV_POC not set)"
fi

if [[ "$ran" -eq 0 ]]; then
  log "no private PoCs checked"
else
  log "done: checked $ran private ONNX crash regression(s)"
fi

# R114: a case that did not run is not a case that passed. Both PoCs are deliberately not
# committed (see usage above), so a host that has not been handed them takes both skip
# branches - and that printed two skip lines, "no private PoCs checked", and exited 0, which
# put two unrun ONNX crash regressions into the suite's rc-only tally. Measured 2026-09-19 on
# a tree extracted with `git archive HEAD` with the tool binary in place and no PoC env vars:
# three lines, rc=0, and ALLOW_SKIPPED_CASES=1 changed nothing because nothing read it. Same
# defect and same prescription as check_onnx_libfuzzer_crash_artifacts.sh:70-94 (R86, commit
# 4cbd996). The register is R42's, check_engine_mode_labels.sh:627-634, reused down to the
# wording so that the ledger reader written for that gate
# (check_engine_mode_skip_accounting.sh:107) parses this one unchanged.
#
# Per case, not "none of them ran": a host with only the SIGSEGV PoC printed "done: checked 1
# private ONNX crash regression(s)" and exited 0 with the SIGFPE regression unrun, and one of
# two is precisely the shortfall nobody can see in a suite tally afterwards. --require-pocs
# refuses above, before the ledger is consulted, so the strict flag stays strictly stricter.
#
# Two constraints on the shape, both measured rather than assumed:
#   - R113 removed the old generic-phrase trap: the opposite-polarity assertion now looks
#     for the exact absent TOOL_BIN path. A PoC-only refusal may use "this gate cannot run"
#     without being mistaken for a refusal about the binary. The historical
#     pass=28 fail=1 skip=1 was measured before that correction.
#   - the TOOL_BIN refusal above stays FIRST. The sibling reaches its PoC branch before its
#     TOOL_BIN check, which is why that gate scores it `preempted rc=1` and takes it out of the
#     score. Moving this one up the same way does NOT buy that hatch: it is granted only to a
#     line matching `^\[label\] skip: `, and these skips are spelled "skip sigfpe:" /
#     "skip sigsegv:", so the run reads as `silent rc=1` - refused without naming the missing
#     binary - measured pass=28 fail=1 skip=1 against pass=29 fail=0 skip=1 with the order kept.
#     Only the kept order leaves the TOOL_BIN arm aecfd7b added actually exercised on this gate.
#
# What pins it afterwards: nothing in the suite yet. The sibling's refusal is held by
# check_gate_tool_precondition.sh, which scores a skip line that exits 0 as `vacuous rc=0`;
# that arm cannot reach this branch, since the TOOL_BIN refusal answers its probe first. R119
# is where that class gets a gate; until then this contract is held by its text and this note.
if [[ -n "$SKIPPED" ]]; then
  echo "[onnx-crash-regression] these cases did NOT run:" >&2
  printf '%s\n' "$SKIPPED" | tr '|' '\n' | sed '/^$/d;s/^/  - /' >&2
  if [[ "${ALLOW_SKIPPED_CASES:-0}" != "1" ]]; then
    fail "some cases were skipped; set ALLOW_SKIPPED_CASES=1 only if you accept an unverified run"
  fi
  echo "[onnx-crash-regression] WARN: continuing with skipped cases (ALLOW_SKIPPED_CASES=1)" >&2
fi
