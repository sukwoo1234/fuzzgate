#!/usr/bin/env bash
# A later successful run must not hide an earlier failure from the campaign.
# Real launchers, fixture tool/clock/notifications; no fuzzing or network.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
WORK="$(mktemp -d)"
cleanup() {
  local rc=$?
  if [[ "$rc" -eq 0 ]]; then
    rm -rf "$WORK"
  else
    echo "[backend-exit-check] evidence preserved: $WORK" >&2
  fi
}
trap cleanup EXIT

mkdir -p "$WORK/bin" "$WORK/seeds/onnx"
printf 'seed' > "$WORK/seeds/onnx/seed.onnx"
REAL_DATE="$(command -v date)"

# Each arm owns its clock through DATA_DIR, including in parallel campaigns.
# The clock advances once per tool invocation, making run counts deterministic.
cat > "$WORK/bin/date" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == '+%s' ]]; then
  if [[ -f "$DATA_DIR/calls" ]]; then cat "$DATA_DIR/calls"; else echo 0; fi
else
  exec "$CHECK_REAL_DATE" "$@"
fi
EOF
cat > "$WORK/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >> "$DATA_DIR/notifications"
EOF
cat > "$WORK/bin/tool" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
backend=local-harness
while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend) backend="$2"; shift 2 ;;
    *) shift ;;
  esac
done
sequence="$CHECK_SEQUENCE"
if [[ "$backend" == libfuzzer ]]; then sequence='0 0 0'; fi
read -r -a codes <<< "$sequence"
count=0
if [[ -f "$DATA_DIR/calls" ]]; then read -r count < "$DATA_DIR/calls"; fi
ec="${codes[$count]:?unexpected extra invocation}"
count=$((count + 1))
mkdir -p "$DATA_DIR/runs/run-$count"
printf '%s\n' "$count" > "$DATA_DIR/calls"
cat > "$DATA_DIR/runs/run-$count/status.json" <<STATUS
{
  "failed": $((ec != 0)),
  "timeout": 0
}
STATUS
echo "fixture run=$count exit=$ec"
exit "$ec"
EOF
chmod +x "$WORK/bin/"*

fixture_env() {
  env -i PATH="$WORK/bin:$PATH" HOME="$WORK" \
    WORKDIR="$PROJECT_ROOT" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" \
    CHECK_REAL_DATE="$REAL_DATE" CHECK_SEQUENCE="$sequence" LOOP_SLEEP_SEC=0 \
    HOOK_FILE="$WORK/no-hook" DISCORD_WEBHOOK='https://fixture.invalid/hook' \
    TOOL_LIBFUZZER_CMD=true "$@"
}

check_loop_result() {
  local data_dir="$1" log_dir="$2" tag="$3" expected_ec="$4" expected_runs="$5" expected_failures="$6"
  python3 - "$data_dir" "$log_dir" "$tag" "$expected_ec" "$expected_runs" "$expected_failures" <<'PY'
import pathlib
import sys

data, logs = map(pathlib.Path, sys.argv[1:3])
tag = sys.argv[3]
ec, runs, failures = map(int, sys.argv[4:])
record = dict(line.split("=", 1) for line in (logs / f"run-{tag}.exit").read_text().splitlines())
for key, value in {"exit_code": ec, "runs": runs, "failures": failures}.items():
    assert int(record[key]) == value, (key, record[key], value)
assert (logs / f"run-{tag}.done").read_text().strip()
assert int((data / "calls").read_text()) == runs
assert len(list((data / "runs").glob("run-*/status.json"))) == runs
summary = f"exit={ec} runs={runs} failures={failures}"
assert summary in (logs / f"run-{tag}.log").read_text()
notifications = (data / "notifications").read_text()
label = "FAIL" if ec else "DONE"
assert f"[{label}] {tag} " in notifications, notifications
assert summary in notifications, notifications
if ec:
    assert f"[DONE] {tag} " not in notifications, notifications
PY
}

run_loop_case() {
  local name="$1" sequence="$2" expected_ec="$3" expected_runs="$4" expected_failures="$5"
  local data="$WORK/$name" rc=0
  fixture_env DATA_DIR="$data" TARGET=onnx BACKEND=local-harness \
    CORPUS_DIR="$WORK/seeds/onnx" TAG="$name" DURATION_SECONDS="$expected_runs" \
    timeout -k 2 15 bash "$PROJECT_ROOT/scripts/run_backend_loop.sh" > "$WORK/$name.log" 2>&1 || rc=$?
  [[ "$rc" -eq "$expected_ec" ]] || {
    echo "[backend-exit-check] fail: $name rc=$rc expected=$expected_ec" >&2
    return 1
  }
  check_loop_result "$data" "$data/longrun" "$name" "$expected_ec" "$expected_runs" "$expected_failures"
  echo "[backend-exit-check] ok: $name rc=$rc runs=$expected_runs failures=$expected_failures"
}

run_campaign_case() {
  local mode="$1" sequence="$2" arm_ec="$3" failures="$4"
  local name="${mode}-${arm_ec}" rc=0 expected_rc=0
  [[ "$arm_ec" -eq 0 ]] || expected_rc=1
  fixture_env timeout -k 2 15 bash "$PROJECT_ROOT/scripts/run_campaign.sh" \
    --mode "$mode" --target onnx --duration-seconds 2 --campaign-id "$name" \
    --backends local-harness,libfuzzer --corpus-dir "$WORK/seeds/onnx" \
    --data-root "$WORK/campaigns" > "$WORK/$name.log" 2>&1 || rc=$?
  [[ "$rc" -eq "$expected_rc" ]] || {
    echo "[backend-exit-check] fail: campaign $name rc=$rc expected=$expected_rc" >&2
    return 1
  }
  local root="$WORK/campaigns/$name"
  python3 - "$root" "$arm_ec" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
ec = int(sys.argv[2])
state = "failed" if ec else "finished"
campaign = json.loads((root / "status.json").read_text())
assert campaign["state"] == state, campaign
assert campaign["completed_backends"] == 2, campaign
assert campaign["failed_backends"] == int(ec != 0), campaign
for backend, code in [("local-harness", ec), ("libfuzzer", 0)]:
    arm = json.loads((root / "arms" / backend / "status.json").read_text())
    assert arm["state"] == ("failed" if code else "finished"), arm
    assert arm["exit_code"] == code, arm
PY
  local backend
  for backend in local-harness libfuzzer; do
    local code=0 count=0
    if [[ "$backend" == local-harness ]]; then code="$arm_ec"; count="$failures"; fi
    check_loop_result "$root/arms/$backend/data" "$root/arms/$backend/longrun" \
      "${name}_onnx_${backend}" "$code" 2 "$count"
  done
  echo "[backend-exit-check] ok: campaign $name rc=$rc completed=2 failed=$expected_rc"
}

run_loop_case success '0 0' 0 2 0
run_loop_case recovered '5 0' 5 2 1
run_loop_case failure '5' 5 1 1
run_loop_case final-failure '0 5' 5 2 1
run_loop_case multiple-failures '5 7 0' 5 3 2
run_loop_case signal-exit '137 0' 137 2 1
for mode in serial parallel; do
  run_campaign_case "$mode" '0 0' 0 0
  run_campaign_case "$mode" '5 0' 5 1
done
echo '[backend-exit-check] all checks passed'
