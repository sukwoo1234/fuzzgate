#!/usr/bin/env bash
# R38: pins the OUT_DIR contract shared by every scripts/run_coverage_*.sh.
#
# A coverage runner wipes its output directory before it writes a new run, because a
# reused OUT_DIR would merge the previous run's profraw into this run's number. That is
# correct. What is not correct is combining it with a DEFAULT OUT_DIR that points at a
# real evidence directory: running the script with no OUT_DIR then deletes the evidence
# before doing anything else, and there is no undo. run_coverage_gguf.sh and
# run_coverage_safetensors.sh already require OUT_DIR (`${OUT_DIR:?...}`); the onnx
# runner defaulted it to data/coverage/onnx-smoke, where a real 2026-06-02 measurement
# lives.
#
# Two assertions, because either alone rots:
#   1. behavioural - run the real runner with no OUT_DIR against a sandbox PROJECT_ROOT
#      and prove a pre-existing default output directory survives.
#   2. class scan - no run_coverage_*.sh may give OUT_DIR a default, so the defect
#      cannot come back one runner at a time.
# A negative control drives the scan against a runner that does default OUT_DIR, so a
# passing scan means something.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
RUNNER_GLOB="$PROJECT_ROOT/scripts/run_coverage_"*.sh

WORK="$(mktemp -d "${TMPDIR:-/tmp}/coverage-runner-contract-XXXXXX")"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

# --- 1. behavioural: the onnx runner must not delete a default OUT_DIR ----------------
# Everything the runner touches hangs off PROJECT_ROOT, so a sandbox root is enough to
# reach the destructive line: it only stats the .so and the harness source first.
SENTINEL='IRREPLACEABLE-COVERAGE-EVIDENCE'
PR="$WORK/root"
mkdir -p "$PR/data/targets/onnxruntime/v1.23.2/onnxruntime-1.23.2/build/cov/RelWithDebInfo" \
         "$PR/harnesses/coverage-onnx" \
         "$PR/data/coverage/onnx-smoke"
: >"$PR/data/targets/onnxruntime/v1.23.2/onnxruntime-1.23.2/build/cov/RelWithDebInfo/libonnxruntime.so"
: >"$PR/harnesses/coverage-onnx/harness.cc"
printf '%s' "$SENTINEL" >"$PR/data/coverage/onnx-smoke/coverage.json"

# The runner is expected to fail here (no real toolchain in the sandbox). What is being
# measured is whether it destroyed the directory on its way out, not its exit code.
env -u OUT_DIR PROJECT_ROOT="$PR" \
  bash "$PROJECT_ROOT/scripts/run_coverage_onnx.sh" >"$WORK/onnx.log" 2>&1 || true

if [[ -f "$PR/data/coverage/onnx-smoke/coverage.json" ]] \
   && [[ "$(cat "$PR/data/coverage/onnx-smoke/coverage.json")" == "$SENTINEL" ]]; then
  ok 'run_coverage_onnx.sh with no OUT_DIR left the existing evidence intact'
else
  bad 'run_coverage_onnx.sh with no OUT_DIR destroyed the existing evidence directory'
fi

# --- 2. class scan: no runner may default OUT_DIR -------------------------------------
# `${OUT_DIR:?...}` is the required form. `${OUT_DIR:-...}` hands the script a writable
# path nobody asked for, which is exactly how the evidence got deleted.
scan_runner() {
  local file="$1" name
  name="$(basename "$file")"
  if grep -qE '^OUT_DIR="\$\{OUT_DIR:\?' "$file"; then
    return 0
  fi
  if grep -qE '^OUT_DIR="\$\{OUT_DIR:-' "$file"; then
    printf 'defaults'
    return 1
  fi
  printf 'unset-or-unrecognised'
  return 1
}

for runner in $RUNNER_GLOB; do
  [[ -f "$runner" ]] || continue
  if why="$(scan_runner "$runner")"; then
    ok "$(basename "$runner") requires OUT_DIR"
  else
    bad "$(basename "$runner") does not require OUT_DIR ($why)"
  fi
done

# --- 3. negative control: the scan must catch a runner that defaults OUT_DIR -----------
cat >"$WORK/run_coverage_fake.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="${PROJECT_ROOT:-/nowhere}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/data/coverage/fake}"
rm -rf "$OUT_DIR"
FAKE
if scan_runner "$WORK/run_coverage_fake.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a runner that defaults OUT_DIR'
else
  ok 'negative control: scan rejects a runner that defaults OUT_DIR'
fi

printf '[coverage-runner-contract] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
