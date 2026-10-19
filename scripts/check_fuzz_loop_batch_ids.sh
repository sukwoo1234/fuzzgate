#!/usr/bin/env bash
# A32: the fuzz loop resumes its iteration counter from the batch directories on
# disk and prunes the oldest ones. Both used lexicographic order, which inverts
# once the counter needs a seventh digit: the loop re-mints an iteration that
# already exists, and retention deletes the newest batch instead of the oldest.
# Fixture-only: a fake tool binary, one iteration, no fuzzing.
set -euo pipefail

PROJECT_ROOT_REPO="${PROJECT_ROOT_REPO:-$(pwd)}"
LOOP="$PROJECT_ROOT_REPO/ops/scripts/fuzz-loop.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() {
  echo "[fuzz-loop-batch-check] $*"
}

fail() {
  echo "[fuzz-loop-batch-check] fail: $*" >&2
  exit 1
}

MUTATED_ROOT="$WORK/data/corpus/mutated/onnx"
mkdir -p "$MUTATED_ROOT" "$WORK/bin" "$WORK/seeds/onnx"
printf 'seed' > "$WORK/seeds/onnx/seed.onnx"

# The loop only needs mutate and run to succeed. It must NOT create the batch dir,
# so the batch count stays at the two the fixture pre-created.
cat > "$WORK/bin/tool" <<'TOOLEOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "target-spec" ]]; then
  printf 'target_id=onnx\nseed_subdir=onnx\ninput_ext=onnx\nmutation_supported=1\ncampaign_supported=1\n'
fi
exit 0
TOOLEOF
chmod +x "$WORK/bin/tool"

# run_loop <max_batches_keep>
run_loop() {
  : > "$WORK/loop.log"
  PROJECT_ROOT="$WORK" TOOL_BIN="$WORK/bin/tool" \
    FUZZ_LOOP_MAX_ITERATIONS=1 ITERATION_SLEEP_SEC=0 MAX_BATCHES_KEEP="$1" \
    timeout -k 2 30 bash "$LOOP" > "$WORK/loop.log" 2>&1 < /dev/null || true
}

# --- case 1: resume picks the highest iteration, not the longest prefix -------
mkdir -p "$MUTATED_ROOT/batch-iter999999-20260101-000000" \
         "$MUTATED_ROOT/batch-iter1000000-20260101-000100"

run_loop 99
grep -q 'resume from iter=1000000' "$WORK/loop.log" \
  || fail "resume did not pick the highest iteration; log: $(cat "$WORK/loop.log")"
log "ok: resume picks the highest iteration number"

# --- case 2: retention deletes the oldest batch, not the newest ---------------
rm -rf "$MUTATED_ROOT"
mkdir -p "$MUTATED_ROOT/batch-iter999999-20260101-000000" \
         "$MUTATED_ROOT/batch-iter1000000-20260101-000100"

run_loop 1
[[ ! -e "$MUTATED_ROOT/batch-iter999999-20260101-000000" ]] \
  || fail "retention kept the older batch"
[[ -e "$MUTATED_ROOT/batch-iter1000000-20260101-000100" ]] \
  || fail "retention deleted the newest batch"
log "ok: retention prunes by iteration number, oldest first"

log "all checks passed"
