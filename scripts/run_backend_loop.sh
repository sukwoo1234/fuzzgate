#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WORKDIR:-$PWD}"
DATA_DIR="${DATA_DIR:-$WORKDIR/data}"
TOOL_BIN="${TOOL_BIN:-$WORKDIR/target/debug/tool}"
TARGET="${TARGET:-onnx}"
BACKEND="${BACKEND:-local-harness}"
CORPUS_DIR="${CORPUS_DIR:-seeds/${TARGET}}"
WORKERS="${WORKERS:-2}"
TIMEOUT_SEC="${TIMEOUT_SEC:-30}"
RESTART_LIMIT="${RESTART_LIMIT:-1}"
MAX_JOBS="${MAX_JOBS:-}"
LOOP_SLEEP_SEC="${LOOP_SLEEP_SEC:-2}"
HOOK_FILE="${HOOK_FILE:-$HOME/.config/bugbounty/discord_webhook}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"

DURATION_HOURS="${DURATION_HOURS:-6}"
DURATION_SECONDS="${DURATION_SECONDS:-}"
if [[ -n "${DURATION_SECONDS}" ]]; then
  DURATION_SECS="${DURATION_SECONDS}"
  DURATION_LABEL="${DURATION_SECONDS}s"
else
  DURATION_SECS=$((DURATION_HOURS * 3600))
  DURATION_LABEL="${DURATION_HOURS}h"
fi

LOG_DIR="${LOG_DIR:-$DATA_DIR/longrun}"
mkdir -p "$LOG_DIR"

TAG="${TAG:-${TARGET}_${BACKEND}_${DURATION_LABEL}}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/run-${TAG}.log}"
DONE_FILE="${DONE_FILE:-$LOG_DIR/run-${TAG}.done}"
EXIT_FILE="${EXIT_FILE:-$LOG_DIR/run-${TAG}.exit}"

discord_webhook_url() {
  if [[ -n "$DISCORD_WEBHOOK" ]]; then
    printf '%s' "$DISCORD_WEBHOOK"
    return 0
  fi
  if [[ -f "$HOOK_FILE" ]]; then
    cat "$HOOK_FILE"
    return 0
  fi
  return 1
}

discord_notify() {
  local msg="$1"
  local hook=""
  if ! hook="$(discord_webhook_url)"; then
    return 0
  fi
  if [[ -z "$hook" ]]; then
    return 0
  fi

  # Minimal JSON escaping for Discord content payload
  local escaped
  escaped="$(printf '%s' "$msg" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
  curl -sS -H "Content-Type: application/json" \
    -d "{\"content\":\"${escaped}\"}" \
    "$hook" >/dev/null || true
}

json_num_field() {
  local key="$1"
  local file="$2"
  awk -v k="\"$key\"" '
    BEGIN { found = 0 }
    $0 ~ k {
      gsub(/[^0-9]/, "", $0);
      if ($0 == "") { print 0; exit }
      print $0;
      found = 1;
      exit
    }
    END { if (found == 0) print 0 }
  ' "$file"
}

run_once() {
  local -a cmd
  cmd=(
    "$TOOL_BIN" --data-dir "$DATA_DIR" run
    --target "$TARGET"
    --backend "$BACKEND"
    --corpus-dir "$CORPUS_DIR"
    --workers "$WORKERS"
    --timeout-sec "$TIMEOUT_SEC"
    --restart-limit "$RESTART_LIMIT"
  )
  if [[ -n "$MAX_JOBS" ]]; then
    cmd+=(--max-jobs "$MAX_JOBS")
  fi

  "${cmd[@]}"
}

ts_start="$(date -Iseconds)"
echo "[START] ${TAG} ts=${ts_start} host=$(hostname)" | tee -a "$LOG_FILE"
discord_notify "[START] ${TAG} ts=${ts_start} host=$(hostname)"

end_ts=$(( $(date +%s) + DURATION_SECS ))
runs=0
failures=0
loop_ec=0
last_alert_sig=""

cd "$WORKDIR"
while true; do
  now_ts=$(date +%s)
  if [[ "$now_ts" -ge "$end_ts" ]]; then
    break
  fi

  set +e
  run_once >>"$LOG_FILE" 2>&1
  ec=$?
  set -e

  runs=$((runs + 1))
  if [[ "$ec" -ne 0 ]]; then
    failures=$((failures + 1))
    # Keep running until the deadline, but never let recovery erase a failure.
    # Preserve the first failing tool code for both the record and the caller.
    if [[ "$loop_ec" -eq 0 ]]; then
      loop_ec="$ec"
    fi
  fi

  latest_status="$(ls -1t "$DATA_DIR"/runs/run-*/status.json 2>/dev/null | head -n 1 || true)"
  if [[ -n "$latest_status" && -f "$latest_status" ]]; then
    run_failed="$(json_num_field failed "$latest_status")"
    run_timeout="$(json_num_field timeout "$latest_status")"
    if [[ "$run_failed" -gt 0 || "$run_timeout" -gt 0 ]]; then
      alert_sig="${latest_status}:${run_failed}:${run_timeout}"
      if [[ "$alert_sig" != "$last_alert_sig" ]]; then
        discord_notify "[ALERT] ${TAG} status=${latest_status} failed=${run_failed} timeout=${run_timeout} host=$(hostname)"
        last_alert_sig="$alert_sig"
      fi
    fi
  fi

  sleep "$LOOP_SLEEP_SEC"
done

ts_end="$(date -Iseconds)"
echo "[DONE] ${TAG} ts=${ts_end} exit=${loop_ec} runs=${runs} failures=${failures} host=$(hostname)" | tee -a "$LOG_FILE"
echo "${ts_end}" > "$DONE_FILE"
cat > "$EXIT_FILE" <<EOF
timestamp=${ts_end}
exit_code=${loop_ec}
runs=${runs}
failures=${failures}
tag=${TAG}
EOF

if [[ "$loop_ec" -eq 0 ]]; then
  discord_notify "[DONE] ${TAG} ts=${ts_end} exit=${loop_ec} runs=${runs} failures=${failures} host=$(hostname)"
else
  discord_notify "[FAIL] ${TAG} ts=${ts_end} exit=${loop_ec} runs=${runs} failures=${failures} host=$(hostname)"
fi

# terminal bell for local attention
printf '\a'
exit "$loop_ec"
