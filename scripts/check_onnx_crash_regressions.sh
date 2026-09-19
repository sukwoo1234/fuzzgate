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

Without --require-pocs, missing env vars skip the corresponding private regression.
With --require-pocs, missing env vars or failed checks are hard failures.
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

if [[ -n "${ONNX_SIGFPE_POC:-}" ]]; then
  check_one "sigfpe" "$ONNX_SIGFPE_POC" "$SIGFPE_SHA256" "SIGFPE"
  ran=$((ran + 1))
elif [[ "$REQUIRE_POCS" -eq 1 ]]; then
  fail "ONNX_SIGFPE_POC is required"
else
  log "skip sigfpe: ONNX_SIGFPE_POC not set"
fi

if [[ -n "${ONNX_SIGSEGV_POC:-}" ]]; then
  check_one "sigsegv" "$ONNX_SIGSEGV_POC" "$SIGSEGV_SHA256" "SIGSEGV"
  ran=$((ran + 1))
elif [[ "$REQUIRE_POCS" -eq 1 ]]; then
  fail "ONNX_SIGSEGV_POC is required"
else
  log "skip sigsegv: ONNX_SIGSEGV_POC not set"
fi

if [[ "$ran" -eq 0 ]]; then
  log "no private PoCs checked"
else
  log "done: checked $ran private ONNX crash regression(s)"
fi
