#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: run_campaign.sh --mode <serial|parallel> --target <onnx|gguf|safetensors> (--hours <N>|--duration-seconds <N>) --campaign-id <ID> [--backends <local-harness,libfuzzer,aflpp>] [--corpus-dir <dir>] [--data-root <dir>] [--workers <n>] [--timeout-sec <n>] [--restart-limit <n>] [--max-jobs <n>] [--dry-run]
EOF
}

WORKDIR="${WORKDIR:-$PWD}"
TOOL_BIN="${TOOL_BIN:-$WORKDIR/target/debug/tool}"
MODE=""
TARGET=""
HOURS=""
DURATION_SECONDS=""
CAMPAIGN_ID=""
BACKENDS="local-harness,libfuzzer,aflpp"
CORPUS_DIR=""
DATA_ROOT=""
WORKERS="1"
TIMEOUT_SEC="30"
RESTART_LIMIT="1"
MAX_JOBS=""
DRY_RUN="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --hours) HOURS="${2:-}"; shift 2 ;;
    --duration-seconds) DURATION_SECONDS="${2:-}"; shift 2 ;;
    --campaign-id) CAMPAIGN_ID="${2:-}"; shift 2 ;;
    --backends) BACKENDS="${2:-}"; shift 2 ;;
    --corpus-dir) CORPUS_DIR="${2:-}"; shift 2 ;;
    --data-root) DATA_ROOT="${2:-}"; shift 2 ;;
    --workers) WORKERS="${2:-}"; shift 2 ;;
    --timeout-sec) TIMEOUT_SEC="${2:-}"; shift 2 ;;
    --restart-limit) RESTART_LIMIT="${2:-}"; shift 2 ;;
    --max-jobs) MAX_JOBS="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[campaign] unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$MODE" || -z "$TARGET" || -z "$CAMPAIGN_ID" ]]; then
  echo "[campaign] required args missing" >&2
  usage
  exit 2
fi
if [[ -z "$HOURS" && -z "$DURATION_SECONDS" ]]; then
  echo "[campaign] either --hours or --duration-seconds is required" >&2
  usage
  exit 2
fi
if [[ -n "$HOURS" && -n "$DURATION_SECONDS" ]]; then
  echo "[campaign] use only one of --hours or --duration-seconds" >&2
  usage
  exit 2
fi

case "$MODE" in
  serial|parallel) ;;
  *) echo "[campaign] unsupported mode: $MODE" >&2; exit 2 ;;
esac

case "$TARGET" in
  onnx|gguf|safetensors) ;;
  *) echo "[campaign] unsupported target: $TARGET" >&2; exit 2 ;;
esac

if [[ ! "$CAMPAIGN_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "[campaign] campaign-id allows only A-Z, a-z, 0-9, dot, underscore, dash" >&2
  exit 2
fi
if [[ -n "$HOURS" && ( ! "$HOURS" =~ ^[0-9]+$ || "$HOURS" -lt 1 ) ]]; then
  echo "[campaign] hours must be an integer >= 1" >&2
  exit 2
fi
if [[ -n "$DURATION_SECONDS" && ( ! "$DURATION_SECONDS" =~ ^[0-9]+$ || "$DURATION_SECONDS" -lt 1 ) ]]; then
  echo "[campaign] duration-seconds must be an integer >= 1" >&2
  exit 2
fi
if [[ ! "$WORKERS" =~ ^[0-9]+$ || "$WORKERS" -lt 1 ]]; then
  echo "[campaign] workers must be an integer >= 1" >&2
  exit 2
fi
if [[ ! "$TIMEOUT_SEC" =~ ^[0-9]+$ || "$TIMEOUT_SEC" -lt 1 ]]; then
  echo "[campaign] timeout-sec must be an integer >= 1" >&2
  exit 2
fi
if [[ ! "$RESTART_LIMIT" =~ ^[0-9]+$ ]]; then
  echo "[campaign] restart-limit must be an integer >= 0" >&2
  exit 2
fi
if [[ -n "$MAX_JOBS" && ( ! "$MAX_JOBS" =~ ^[0-9]+$ || "$MAX_JOBS" -lt 1 ) ]]; then
  echo "[campaign] max-jobs must be an integer >= 1" >&2
  exit 2
fi

if [[ -z "$CORPUS_DIR" ]]; then
  CORPUS_DIR="seeds/${TARGET}"
fi
if [[ -z "$DATA_ROOT" ]]; then
  DATA_ROOT="data/campaigns"
fi

abs_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    printf '%s' "$path"
  else
    printf '%s/%s' "$WORKDIR" "$path"
  fi
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

join_by_comma() {
  local first="1"
  local out=""
  local item
  for item in "$@"; do
    if [[ "$first" == "1" ]]; then
      first="0"
    else
      out+=","
    fi
    out+="$item"
  done
  printf '%s' "$out"
}

backend_array_json() {
  local first="1"
  local out="["
  local backend
  for backend in "${BACKEND_LIST[@]}"; do
    if [[ "$first" == "1" ]]; then
      first="0"
    else
      out+=", "
    fi
    out+="\"$(json_escape "$backend")\""
  done
  out+="]"
  printf '%s' "$out"
}

seed_snapshot_hash() {
  local dir="$1"
  if ! command -v sha256sum >/dev/null 2>&1; then
    printf 'sha256sum_not_available'
    return 0
  fi
  (
    cd "$dir"
    find . -type f -print0 | sort -z | while IFS= read -r -d '' file; do
      sha256sum "$file"
    done
  ) | sha256sum | awk '{print $1}'
}

IFS=',' read -r -a RAW_BACKENDS <<< "$BACKENDS"
BACKEND_LIST=()
for raw_backend in "${RAW_BACKENDS[@]}"; do
  backend="${raw_backend//[[:space:]]/}"
  if [[ -n "$backend" ]]; then
    BACKEND_LIST+=("$backend")
  fi
done
if [[ "${#BACKEND_LIST[@]}" -eq 0 ]]; then
  echo "[campaign] no backends selected" >&2
  exit 2
fi
for backend in "${BACKEND_LIST[@]}"; do
  case "$backend" in
    local-harness|libfuzzer|aflpp) ;;
    *) echo "[campaign] unsupported backend: $backend" >&2; exit 2 ;;
  esac
done
BACKENDS="$(join_by_comma "${BACKEND_LIST[@]}")"

if [[ -n "$DURATION_SECONDS" ]]; then
  DURATION_LABEL="${DURATION_SECONDS}s"
else
  DURATION_LABEL="${HOURS}h"
fi
HOURS_JSON="${HOURS:-null}"
DURATION_SECONDS_JSON="${DURATION_SECONDS:-null}"
MAX_JOBS_JSON="${MAX_JOBS:-null}"

CORPUS_SOURCE="$(abs_path "$CORPUS_DIR")"
DATA_ROOT="$(abs_path "$DATA_ROOT")"
CAMPAIGN_ROOT="$DATA_ROOT/$CAMPAIGN_ID"
SEED_SNAPSHOT="$CAMPAIGN_ROOT/seeds/$TARGET"
MANIFEST_PATH="$CAMPAIGN_ROOT/manifest.json"
STATUS_PATH="$CAMPAIGN_ROOT/status.json"
SEED_HASH="not_available"
completed=0
failed=0
interrupted=0

declare -A ARM_STATE
declare -A ARM_PID
declare -A ARM_EXIT
pids=()
pid_backends=()

for backend in "${BACKEND_LIST[@]}"; do
  ARM_STATE["$backend"]="pending"
  ARM_PID["$backend"]=""
  ARM_EXIT["$backend"]=""
done

arm_statuses_label() {
  local first="1"
  local out=""
  local backend
  for backend in "${BACKEND_LIST[@]}"; do
    if [[ "$first" == "1" ]]; then
      first="0"
    else
      out+=","
    fi
    out+="${backend}=${ARM_STATE[$backend]:-pending}"
  done
  printf '%s' "$out"
}

write_manifest() {
  local path="$1"
  local backends_json
  backends_json="$(backend_array_json)"
  cat > "$path" <<EOF
{
  "schema_version": "1.0",
  "campaign_id": "$(json_escape "$CAMPAIGN_ID")",
  "mode": "$(json_escape "$MODE")",
  "target": "$(json_escape "$TARGET")",
  "backends": $backends_json,
  "backends_label": "$(json_escape "$BACKENDS")",
  "hours": $HOURS_JSON,
  "duration_seconds": $DURATION_SECONDS_JSON,
  "duration_label": "$(json_escape "$DURATION_LABEL")",
  "workers": $WORKERS,
  "timeout_sec": $TIMEOUT_SEC,
  "restart_limit": $RESTART_LIMIT,
  "max_jobs": $MAX_JOBS_JSON,
  "corpus_source": "$(json_escape "$CORPUS_SOURCE")",
  "seed_snapshot": "$(json_escape "$SEED_SNAPSHOT")",
  "seed_snapshot_hash": "$(json_escape "$SEED_HASH")",
  "tool_bin": "$(json_escape "$TOOL_BIN")",
  "started_at": "$(date -Iseconds)"
}
EOF
}

write_status() {
  local state="$1"
  local completed_count="$2"
  local failed_count="$3"
  local summary="$4"
  local backends_json
  backends_json="$(backend_array_json)"
  cat > "$STATUS_PATH" <<EOF
{
  "schema_version": "1.0",
  "campaign_id": "$(json_escape "$CAMPAIGN_ID")",
  "mode": "$(json_escape "$MODE")",
  "target": "$(json_escape "$TARGET")",
  "backends": $backends_json,
  "backends_label": "$(json_escape "$BACKENDS")",
  "arms_label": "$(json_escape "$(arm_statuses_label)")",
  "state": "$(json_escape "$state")",
  "completed_backends": $completed_count,
  "failed_backends": $failed_count,
  "duration_label": "$(json_escape "$DURATION_LABEL")",
  "summary": "$(json_escape "$summary")",
  "updated_at": "$(date -Iseconds)"
}
EOF
}

write_arm_status() {
  local backend="$1"
  local state="$2"
  local pid="${3:-}"
  local exit_code="${4:-}"
  local summary="${5:-}"
  local arm_root="$CAMPAIGN_ROOT/arms/$backend"
  mkdir -p "$arm_root"
  ARM_STATE["$backend"]="$state"
  ARM_PID["$backend"]="$pid"
  ARM_EXIT["$backend"]="$exit_code"
  if [[ -z "$pid" ]]; then
    pid="null"
  fi
  if [[ -z "$exit_code" ]]; then
    exit_code="null"
  fi
  cat > "$arm_root/status.json" <<EOF
{
  "schema_version": "1.0",
  "campaign_id": "$(json_escape "$CAMPAIGN_ID")",
  "backend": "$(json_escape "$backend")",
  "target": "$(json_escape "$TARGET")",
  "state": "$(json_escape "$state")",
  "pid": $pid,
  "exit_code": $exit_code,
  "data_dir": "$(json_escape "$arm_root/data")",
  "corpus_dir": "$(json_escape "$arm_root/corpus/$TARGET")",
  "log_path": "$(json_escape "$arm_root/campaign.log")",
  "summary": "$(json_escape "$summary")",
  "updated_at": "$(date -Iseconds)"
}
EOF
}

terminate_pid_tree() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return 0
  fi
  kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
}

kill_pid_tree() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return 0
  fi
  kill -KILL "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}

cleanup_children() {
  local signal="$1"
  if [[ "$interrupted" -eq 1 ]]; then
    exit 130
  fi
  interrupted=1
  echo "[campaign] interrupted signal=$signal; terminating backend processes" >&2
  local backend
  for backend in "${BACKEND_LIST[@]}"; do
    local pid="${ARM_PID[$backend]:-}"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      write_arm_status "$backend" "interrupted" "$pid" "" "signal=$signal"
      terminate_pid_tree "$pid"
    fi
  done
  sleep 1
  for backend in "${BACKEND_LIST[@]}"; do
    local pid="${ARM_PID[$backend]:-}"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill_pid_tree "$pid"
    fi
  done
  write_status "interrupted" "$completed" "$failed" "signal=$signal"
  exit 130
}

if [[ "$DRY_RUN" == "1" ]]; then
  echo "[campaign] dry-run mode=$MODE target=$TARGET duration=$DURATION_LABEL campaign=$CAMPAIGN_ID"
  for backend in "${BACKEND_LIST[@]}"; do
    duration_arg="--hours $HOURS"
    if [[ -n "$DURATION_SECONDS" ]]; then
      duration_arg="--duration-seconds $DURATION_SECONDS"
    fi
    max_jobs_arg=""
    if [[ -n "$MAX_JOBS" ]]; then
      max_jobs_arg=" --max-jobs $MAX_JOBS"
    fi
    echo "DATA_DIR=$CAMPAIGN_ROOT/arms/$backend/data TOOL_BIN=$TOOL_BIN scripts/run_long.sh --target $TARGET --backend $backend $duration_arg --tag ${CAMPAIGN_ID}_${TARGET}_${backend} --corpus-dir $CAMPAIGN_ROOT/arms/$backend/corpus/$TARGET --seed-fixture $SEED_SNAPSHOT --workers $WORKERS --timeout-sec $TIMEOUT_SEC --restart-limit $RESTART_LIMIT$max_jobs_arg"
  done
  exit 0
fi

if [[ ! -d "$CORPUS_SOURCE" ]]; then
  echo "[campaign] corpus dir not found: $CORPUS_SOURCE" >&2
  exit 2
fi

if [[ -e "$CAMPAIGN_ROOT" ]]; then
  echo "[campaign] campaign already exists; use a new --campaign-id: $CAMPAIGN_ROOT" >&2
  exit 2
fi

mkdir -p "$CAMPAIGN_ROOT" "$CAMPAIGN_ROOT/arms" "$SEED_SNAPSHOT"
cp -a "$CORPUS_SOURCE"/. "$SEED_SNAPSHOT"/
SEED_HASH="$(seed_snapshot_hash "$SEED_SNAPSHOT")"
write_manifest "$MANIFEST_PATH"
write_status "running" 0 0 "campaign started"
trap 'cleanup_children INT' INT
trap 'cleanup_children TERM' TERM

start_arm() {
  local backend="$1"
  local arm_root="$CAMPAIGN_ROOT/arms/$backend"
  local arm_data_dir="$arm_root/data"
  local arm_corpus_dir="$arm_root/corpus/$TARGET"
  local arm_log_dir="$arm_root/longrun"
  local tag="${CAMPAIGN_ID}_${TARGET}_${backend}"
  local -a duration_args
  local -a max_jobs_args
  if [[ -n "$DURATION_SECONDS" ]]; then
    duration_args=(--duration-seconds "$DURATION_SECONDS")
  else
    duration_args=(--hours "$HOURS")
  fi
  if [[ -n "$MAX_JOBS" ]]; then
    max_jobs_args=(--max-jobs "$MAX_JOBS")
  else
    max_jobs_args=()
  fi

  mkdir -p "$arm_data_dir" "$arm_corpus_dir" "$arm_log_dir"
  cp -a "$SEED_SNAPSHOT"/. "$arm_corpus_dir"/

  write_arm_status "$backend" "starting" "" "" "preparing backend"
  if command -v setsid >/dev/null 2>&1; then
    DATA_DIR="$arm_data_dir" \
    LOG_DIR="$arm_log_dir" \
    TOOL_BIN="$TOOL_BIN" \
    WORKDIR="$WORKDIR" \
    setsid bash "$WORKDIR/scripts/run_long.sh" \
      --target "$TARGET" \
      --backend "$backend" \
      "${duration_args[@]}" \
      --tag "$tag" \
      --corpus-dir "$arm_corpus_dir" \
      --seed-fixture "$SEED_SNAPSHOT" \
      --workers "$WORKERS" \
      --timeout-sec "$TIMEOUT_SEC" \
      --restart-limit "$RESTART_LIMIT" \
      "${max_jobs_args[@]}" \
      >"$arm_root/campaign.log" 2>&1 &
  else
    DATA_DIR="$arm_data_dir" \
    LOG_DIR="$arm_log_dir" \
    TOOL_BIN="$TOOL_BIN" \
    WORKDIR="$WORKDIR" \
    bash "$WORKDIR/scripts/run_long.sh" \
      --target "$TARGET" \
      --backend "$backend" \
      "${duration_args[@]}" \
      --tag "$tag" \
      --corpus-dir "$arm_corpus_dir" \
      --seed-fixture "$SEED_SNAPSHOT" \
      --workers "$WORKERS" \
      --timeout-sec "$TIMEOUT_SEC" \
      --restart-limit "$RESTART_LIMIT" \
      "${max_jobs_args[@]}" \
      >"$arm_root/campaign.log" 2>&1 &
  fi
  local pid="$!"
  ARM_PID["$backend"]="$pid"
  write_arm_status "$backend" "running" "$pid" "" "started"
  pids+=("$pid")
  pid_backends+=("$backend")
}

wait_arm() {
  local pid="$1"
  local backend="$2"
  local ec
  set +e
  wait "$pid"
  ec=$?
  set -e
  completed=$((completed + 1))
  if [[ "$ec" -eq 0 ]]; then
    write_arm_status "$backend" "finished" "$pid" "$ec" "exit=$ec"
  else
    failed=$((failed + 1))
    write_arm_status "$backend" "failed" "$pid" "$ec" "exit=$ec"
  fi
  write_status "running" "$completed" "$failed" "last_backend=$backend exit=$ec"
}

if [[ "$MODE" == "serial" ]]; then
  for backend in "${BACKEND_LIST[@]}"; do
    echo "[campaign] serial start backend=$backend"
    start_arm "$backend"
    last_idx=$((${#pids[@]} - 1))
    wait_arm "${pids[$last_idx]}" "$backend"
  done
else
  for backend in "${BACKEND_LIST[@]}"; do
    echo "[campaign] parallel start backend=$backend"
    start_arm "$backend"
  done
  for idx in "${!pids[@]}"; do
    wait_arm "${pids[$idx]}" "${pid_backends[$idx]}"
  done
fi

trap - INT TERM
if [[ "$failed" -eq 0 ]]; then
  write_status "finished" "$completed" "$failed" "campaign finished"
  echo "[campaign] done id=$CAMPAIGN_ID mode=$MODE completed=$completed failed=$failed"
else
  write_status "failed" "$completed" "$failed" "campaign finished with backend failures"
  echo "[campaign] failed id=$CAMPAIGN_ID mode=$MODE completed=$completed failed=$failed" >&2
  exit 1
fi
