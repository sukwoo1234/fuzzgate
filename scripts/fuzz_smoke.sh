#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: fuzz_smoke.sh [--target <registered-target>] [--backend <backend>|--backends <list>|--all] [--seconds <n>] [--id <campaign-id>] [--data-dir <dir>] [--seeds-dir <dir>] [--max-jobs <n>] [--workers <n>] [--timeout-sec <n>] [--dry-run]
EOF
}

WORKDIR="${WORKDIR:-$PWD}"
TOOL_BIN="${TOOL_BIN:-$WORKDIR/target/debug/tool}"
TARGET="onnx"
BACKENDS="local-harness"
SMOKE_SECONDS="10"
CAMPAIGN_ID=""
DATA_DIR="$WORKDIR/data"
SEEDS_DIR="$WORKDIR/seeds"
MAX_JOBS="1"
WORKERS="1"
TIMEOUT_SEC="10"
RESTART_LIMIT="0"
DRY_RUN="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target|-t) TARGET="${2:-}"; shift 2 ;;
    --backend|-b) BACKENDS="${2:-}"; shift 2 ;;
    --backends) BACKENDS="${2:-}"; shift 2 ;;
    --all) BACKENDS="local-harness,libfuzzer,aflpp"; shift ;;
    --seconds|-s) SMOKE_SECONDS="${2:-}"; shift 2 ;;
    --id|-i) CAMPAIGN_ID="${2:-}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
    --seeds-dir) SEEDS_DIR="${2:-}"; shift 2 ;;
    --max-jobs) MAX_JOBS="${2:-}"; shift 2 ;;
    --workers) WORKERS="${2:-}"; shift 2 ;;
    --timeout-sec) TIMEOUT_SEC="${2:-}"; shift 2 ;;
    --restart-limit) RESTART_LIMIT="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[smoke] unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ ! -x "$TOOL_BIN" ]]; then
  echo "[smoke] tool binary missing: $TOOL_BIN" >&2
  echo "[smoke] run: cargo build --offline" >&2
  exit 1
fi
TARGET_SPEC="$("$TOOL_BIN" target-spec --target "$TARGET" --format shell 2>/dev/null)" || {
  echo "[smoke] unsupported target: $TARGET" >&2
  exit 2
}
TARGET_ID="$(sed -n 's/^target_id=//p' <<<"$TARGET_SPEC")"
SEED_SUBDIR="$(sed -n 's/^seed_subdir=//p' <<<"$TARGET_SPEC")"
INPUT_EXT="$(sed -n 's/^input_ext=//p' <<<"$TARGET_SPEC")"
if [[ "$TARGET_ID" != "$TARGET" \
  || ! "$TARGET_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "[smoke] registered target has an invalid or mismatched target_id: $TARGET" >&2
  exit 2
fi
if [[ ! "$SEED_SUBDIR" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "[smoke] registered target has an invalid seed_subdir: $TARGET" >&2
  exit 2
fi
if [[ ! "$INPUT_EXT" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
  echo "[smoke] registered target has an invalid input_ext: $TARGET" >&2
  exit 2
fi
if ! grep -Fqx 'campaign_supported=1' <<<"$TARGET_SPEC"; then
  echo "[smoke] target is registered but campaign dispatch is unavailable: $TARGET" >&2
  exit 2
fi
TARGET="$TARGET_ID"
if [[ ! "$SMOKE_SECONDS" =~ ^[0-9]+$ || "$SMOKE_SECONDS" -lt 1 ]]; then
  echo "[smoke] seconds must be an integer >= 1" >&2
  exit 2
fi
if [[ ! "$MAX_JOBS" =~ ^[0-9]+$ || "$MAX_JOBS" -lt 1 ]]; then
  echo "[smoke] max-jobs must be an integer >= 1" >&2
  exit 2
fi
if [[ ! "$WORKERS" =~ ^[0-9]+$ || "$WORKERS" -lt 1 ]]; then
  echo "[smoke] workers must be an integer >= 1" >&2
  exit 2
fi

safe_backends="$(printf '%s' "$BACKENDS" | tr ', ' '--' | tr -cd 'A-Za-z0-9._-')"
if [[ -z "$CAMPAIGN_ID" ]]; then
  CAMPAIGN_ID="smoke-${TARGET}-${safe_backends}-$(date +%Y%m%d-%H%M%S)"
fi

cmd=(
  "$TOOL_BIN"
  --data-dir "$DATA_DIR"
  --seeds-dir "$SEEDS_DIR"
  campaign
  --mode parallel
  --target "$TARGET"
  --duration-seconds "$SMOKE_SECONDS"
  --campaign-id "$CAMPAIGN_ID"
  --backends "$BACKENDS"
  --corpus-dir "$SEEDS_DIR/$SEED_SUBDIR"
  --workers "$WORKERS"
  --timeout-sec "$TIMEOUT_SEC"
  --restart-limit "$RESTART_LIMIT"
  --max-jobs "$MAX_JOBS"
)
if [[ "$DRY_RUN" == "1" ]]; then
  cmd+=(--dry-run)
fi

echo "[smoke] target=$TARGET seed_subdir=$SEED_SUBDIR input_ext=$INPUT_EXT backends=$BACKENDS seconds=$SMOKE_SECONDS id=$CAMPAIGN_ID"
printf '[smoke] command:'
printf ' %q' "${cmd[@]}"
printf '\n'
"${cmd[@]}"
