#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WORKDIR:-$PWD}"
TOOL_BIN="${TOOL_BIN:-$WORKDIR/target/debug/tool}"

usage() {
  cat <<'EOF'
usage: export_experiment_summary.sh \
  --experiment-id <id> \
  --machine-label <label> \
  --target <registered-target> \
  --backend <local-harness|libfuzzer|aflpp> \
  --duration-hours <n> \
  [--out-dir <dir>] \
  [--data-dir <dir>] \
  [--triage-root <dir>] \
  [--reports-root <dir>] \
  [--corpus-dir <dir>] \
  [--workers <n>] \
  [--timeout-sec <n>] \
  [--restart-limit <n>] \
  [--metrics-file <path>] \
  [--run-status-file <path>] \
  [--notes <text>]
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[export-experiment] required command not found: $1" >&2
    exit 2
  fi
}

file_size_bytes() {
  wc -c < "$1" | tr -d ' '
}

file_sha256() {
  local hash_line=""
  hash_line="$(sha256sum "$1")"
  printf '%s' "${hash_line%% *}"
}

write_file_index() {
  local out_dir="$1"
  shift
  local index_path="$out_dir/file-index.tsv"
  local relative_path=""
  local artifact_path=""
  local size_bytes=""
  local hash_line=""

  {
    echo -e "relative_path\tsize_bytes\tsha256"
    for relative_path in "$@"; do
      artifact_path="$out_dir/$relative_path"
      [[ -f "$artifact_path" ]] || continue
      size_bytes="$(file_size_bytes "$artifact_path")"
      hash_line="$(file_sha256 "$artifact_path")"
      echo -e "${relative_path}\t${size_bytes}\t${hash_line}"
    done
  } > "$index_path"
}

append_source_index_row() {
  local source_type="$1"
  local source_path="$2"
  [[ -f "$source_path" ]] || return 0
  printf '%s\t%s\t%s\t%s\n' \
    "$source_type" \
    "$source_path" \
    "$(file_size_bytes "$source_path")" \
    "$(file_sha256 "$source_path")"
}

write_source_index() {
  local index_path="$1"
  {
    echo -e "source_type\tpath\tsize_bytes\tsha256"
    append_source_index_row "run_status" "$RUN_STATUS_FILE"
    append_source_index_row "metrics_latest" "$METRICS_FILE"
    if [[ -n "$MUTATION_MANIFEST" ]]; then
      append_source_index_row "mutation_manifest" "$MUTATION_MANIFEST"
    fi
    if [[ -d "$TRIAGE_ROOT" ]]; then
      while IFS= read -r source_path; do
        append_source_index_row "triage_summary" "$source_path"
      done < <(find "$TRIAGE_ROOT" -mindepth 2 -maxdepth 2 -type f -path '*/triage-*/summary.json' | sort)
    fi
    if [[ -d "$REPORTS_ROOT" ]]; then
      while IFS= read -r source_path; do
        append_source_index_row "report_meta" "$source_path"
      done < <(find "$REPORTS_ROOT" -mindepth 2 -maxdepth 2 -type f -path '*/report-*/meta.json' | sort)
    fi
  } > "$index_path"
}

EXPERIMENT_ID=""
MACHINE_LABEL=""
TARGET=""
BACKEND=""
DURATION_HOURS=""
OUT_DIR=""
DATA_DIR="data"
TRIAGE_ROOT=""
REPORTS_ROOT=""
CORPUS_DIR=""
WORKERS="1"
TIMEOUT_SEC="30"
RESTART_LIMIT="1"
METRICS_FILE=""
RUN_STATUS_FILE=""
NOTES_TEXT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --experiment-id) EXPERIMENT_ID="${2:-}"; shift 2 ;;
    --machine-label) MACHINE_LABEL="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --backend) BACKEND="${2:-}"; shift 2 ;;
    --duration-hours) DURATION_HOURS="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
    --triage-root) TRIAGE_ROOT="${2:-}"; shift 2 ;;
    --reports-root) REPORTS_ROOT="${2:-}"; shift 2 ;;
    --corpus-dir) CORPUS_DIR="${2:-}"; shift 2 ;;
    --workers) WORKERS="${2:-}"; shift 2 ;;
    --timeout-sec) TIMEOUT_SEC="${2:-}"; shift 2 ;;
    --restart-limit) RESTART_LIMIT="${2:-}"; shift 2 ;;
    --metrics-file) METRICS_FILE="${2:-}"; shift 2 ;;
    --run-status-file) RUN_STATUS_FILE="${2:-}"; shift 2 ;;
    --notes) NOTES_TEXT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[export-experiment] unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$EXPERIMENT_ID" || -z "$MACHINE_LABEL" || -z "$TARGET" || -z "$BACKEND" || -z "$DURATION_HOURS" ]]; then
  echo "[export-experiment] required args missing" >&2
  usage
  exit 2
fi

if [[ ! -x "$TOOL_BIN" ]]; then
  echo "[export-experiment] tool binary missing or not executable: $TOOL_BIN" >&2
  exit 2
fi
TARGET_SPEC="$("$TOOL_BIN" target-spec --target "$TARGET" --format shell 2>/dev/null)" || {
  echo "[export-experiment] unsupported target: $TARGET" >&2
  exit 2
}
TARGET_ID="$(sed -n 's/^target_id=//p' <<<"$TARGET_SPEC")"
SEED_SUBDIR="$(sed -n 's/^seed_subdir=//p' <<<"$TARGET_SPEC")"
INPUT_EXT="$(sed -n 's/^input_ext=//p' <<<"$TARGET_SPEC")"
if [[ "$TARGET_ID" != "$TARGET" \
  || ! "$TARGET_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "[export-experiment] registered target has an invalid or mismatched target_id: $TARGET" >&2
  exit 2
fi
if [[ ! "$SEED_SUBDIR" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "[export-experiment] registered target has an invalid seed_subdir: $TARGET" >&2
  exit 2
fi
if [[ ! "$INPUT_EXT" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
  echo "[export-experiment] registered target has an invalid input_ext: $TARGET" >&2
  exit 2
fi
TARGET="$TARGET_ID"

if [[ -z "$CORPUS_DIR" ]]; then
  CORPUS_DIR="$WORKDIR/seeds/${SEED_SUBDIR}"
fi

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="results/experiments/${EXPERIMENT_ID}"
fi

DATA_DIR="${DATA_DIR%/}"
if [[ -z "$METRICS_FILE" ]]; then
  METRICS_FILE="${DATA_DIR}/metrics/latest.json"
fi
if [[ -z "$TRIAGE_ROOT" ]]; then
  TRIAGE_ROOT="${DATA_DIR}/triage"
fi
if [[ -z "$REPORTS_ROOT" ]]; then
  REPORTS_ROOT="${DATA_DIR}/reports"
fi
RUNS_ROOT="${DATA_DIR}/runs"

need_cmd jq
need_cmd git
need_cmd sha256sum

if [[ ! -f "$METRICS_FILE" ]]; then
  echo "[export-experiment] metrics file not found: $METRICS_FILE" >&2
  exit 2
fi

if [[ -z "$RUN_STATUS_FILE" && -d "$RUNS_ROOT" ]]; then
  RUN_STATUS_FILE="$(
    find "$RUNS_ROOT" -mindepth 2 -maxdepth 2 -type f -path '*/run-*/status.json' -printf '%T@\t%p\n' 2>/dev/null \
      | sort -nr \
      | sed -n '1p' \
      | cut -f2-
  )"
fi
if [[ -z "$RUN_STATUS_FILE" || ! -f "$RUN_STATUS_FILE" ]]; then
  echo "[export-experiment] run status file not found" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

cp "$RUN_STATUS_FILE" "$OUT_DIR/run-status.json"
cp "$METRICS_FILE" "$OUT_DIR/metrics-latest.json"

SEED_COUNT=0
if [[ -d "$CORPUS_DIR" ]]; then
  SEED_COUNT="$(find "$CORPUS_DIR" -maxdepth 1 -type f -name "*.${INPUT_EXT}" | wc -l | tr -d ' ')"
fi
MUTATION_MANIFEST=""
MUTATED_COUNT=0
if [[ -f "$CORPUS_DIR/manifest.json" ]]; then
  MUTATION_MANIFEST="$CORPUS_DIR/manifest.json"
  MUTATED_COUNT="$(jq -r '.generated // 0' "$MUTATION_MANIFEST")"
fi

TOTAL_RUNS="$(jq -r '.total // 0' "$OUT_DIR/run-status.json")"
SUCCESS="$(jq -r '.success // 0' "$OUT_DIR/run-status.json")"
FAILED="$(jq -r '.failed // 0' "$OUT_DIR/run-status.json")"
TIMEOUT="$(jq -r '.timeout // 0' "$OUT_DIR/run-status.json")"
RETRIES="$(jq -r '.retries // 0' "$OUT_DIR/run-status.json")"
REJECTED="$(jq -r '.rejected // 0' "$OUT_DIR/run-status.json")"
# G2/G4: whether this run was really native/instrumented or a black-box fallback
ENGINE_MODE="$(jq -r '.engine_mode // "unlabeled"' "$OUT_DIR/run-status.json")"

NEW_CRASHES_PER_HOUR="$(jq -r '.metrics.new_crashes_per_hour // 0' "$OUT_DIR/metrics-latest.json")"
VALID_CRASH_RATIO="$(jq -r 'if (.metrics.valid_crash_ratio_status // "legacy_unverified") == "available" then (.metrics.valid_crash_ratio // "not_available") else (.metrics.valid_crash_ratio_status // "legacy_unverified") end' "$OUT_DIR/metrics-latest.json")"
VALID_CRASH_RATIO_SOURCE="$(jq -r '.metrics.valid_crash_ratio_source // "legacy_event_log"' "$OUT_DIR/metrics-latest.json")"
SUCCESSFUL_RUNS_PER_HOUR_PROXY="$(jq -r '.metrics.successful_runs_per_hour_proxy // .metrics.new_paths_per_hour // 0' "$OUT_DIR/metrics-latest.json")"
GLOBAL_ERROR_RATE_5M="$(jq -r 'if (.metrics.global_error_rate_5m_status // "available") == "available" then (.metrics.global_error_rate_5m // "not_available") else (.metrics.global_error_rate_5m_status) end' "$OUT_DIR/metrics-latest.json")"
# A27: an engine-backend block counts workers, not inputs, so it has its own
# counters. On an aflpp/libfuzzer arm the per-input rows above read 0 by design -
# that is "not this arm's unit", not "nothing happened".
BACKEND_WORKER_RUNS_PER_HOUR="$(jq -r '.metrics.backend_worker_runs_per_hour // "not_available"' "$OUT_DIR/metrics-latest.json")"
BACKEND_WORKER_ERRORS_5M="$(jq -r '.metrics.backend_worker_errors_5m // "not_available"' "$OUT_DIR/metrics-latest.json")"

TRIAGE_INDEX="$OUT_DIR/triage-index.tsv"
{
  echo -e "triage_id\tverdict\tinput_path\tcrash_kind\tsanitizer\tsignal\tnormalized_frame_hash\tsignature_top1\tdeep_triage_version\tdeep_triage_grouping_confidence\tdeep_triage_evidence_quality\tsummary_path\tsummary_size_bytes\tsummary_sha256"
  if [[ -d "$TRIAGE_ROOT" ]]; then
    while IFS= read -r f; do
    triage_id="$(jq -r '.triage_id // ""' "$f")"
    verdict="$(jq -r '.verdict // ""' "$f")"
    input_path="$(jq -r '.input // ""' "$f")"
    crash_kind="$(jq -r '.crash_kind // ""' "$f")"
    sanitizer="$(jq -r '.sanitizer // ""' "$f")"
    signal="$(jq -r '.signal // ""' "$f")"
    normalized_frame_hash="$(jq -r '.normalized_frame_hash // ""' "$f")"
    sig="$(jq -r '.attempts[0].signature_top3[0] // ""' "$f")"
    deep_triage_version="$(jq -r '.deep_triage.version // ""' "$f")"
    deep_triage_grouping_confidence="$(jq -r '.deep_triage.grouping_confidence // ""' "$f")"
    deep_triage_evidence_quality="$(jq -r '.deep_triage.evidence_quality // ""' "$f")"
    summary_size_bytes="$(file_size_bytes "$f")"
    summary_sha256="$(file_sha256 "$f")"
    echo -e "${triage_id}\t${verdict}\t${input_path}\t${crash_kind}\t${sanitizer}\t${signal}\t${normalized_frame_hash}\t${sig}\t${deep_triage_version}\t${deep_triage_grouping_confidence}\t${deep_triage_evidence_quality}\t${f}\t${summary_size_bytes}\t${summary_sha256}"
    done < <(find "$TRIAGE_ROOT" -mindepth 2 -maxdepth 2 -type f -path '*/triage-*/summary.json' | sort)
  fi
} > "$TRIAGE_INDEX"

REPORT_INDEX="$OUT_DIR/report-index.tsv"
{
  echo -e "report_id\tsource_triage_id\tcrash_kind\tsanitizer\tsignal\tnormalized_frame_hash\tsuggested_severity\tseverity_confidence\treport_path\tmeta_path\tmeta_size_bytes\tmeta_sha256"
  if [[ -d "$REPORTS_ROOT" ]]; then
    while IFS= read -r f; do
    report_id="$(jq -r '.report_id // ""' "$f")"
    source_triage_id="$(jq -r '.source_triage_id // ""' "$f")"
    crash_kind="$(jq -r '.crash_kind // ""' "$f")"
    sanitizer="$(jq -r '.sanitizer // ""' "$f")"
    signal="$(jq -r '.signal // ""' "$f")"
    normalized_frame_hash="$(jq -r '.normalized_frame_hash // ""' "$f")"
    suggested_severity="$(jq -r '.suggested_severity // ""' "$f")"
    severity_confidence="$(jq -r '.severity_confidence // ""' "$f")"
    report_path="$(dirname "$f")/report.md"
    meta_size_bytes="$(file_size_bytes "$f")"
    meta_sha256="$(file_sha256 "$f")"
    echo -e "${report_id}\t${source_triage_id}\t${crash_kind}\t${sanitizer}\t${signal}\t${normalized_frame_hash}\t${suggested_severity}\t${severity_confidence}\t${report_path}\t${f}\t${meta_size_bytes}\t${meta_sha256}"
    done < <(find "$REPORTS_ROOT" -mindepth 2 -maxdepth 2 -type f -path '*/report-*/meta.json' | sort)
  fi
} > "$REPORT_INDEX"

REPRODUCED_COUNT="$(awk -F'\t' 'NR>1 && $2=="reproduced" {c++} END{print c+0}' "$TRIAGE_INDEX")"
REPORT_COUNT="$(awk 'END{print NR-1}' "$REPORT_INDEX")"
UNIQUE_SIGNATURE_COUNT="$(awk -F'\t' 'NR>1 && $2=="reproduced" {sig=($7!="" ? $7 : $8); if (sig!="") print sig}' "$TRIAGE_INDEX" | sort -u | wc -l | tr -d ' ')"

GIT_COMMIT="$(git rev-parse --short HEAD)"
STARTED_AT="$(date -Iseconds)"
FINISHED_AT="$(date -Iseconds)"

cat > "$OUT_DIR/manifest.json" <<EOF
{
  "schema_version": "1.1",
  "bundle_type": "experiment_summary",
  "generated_by": "scripts/export_experiment_summary.sh",
  "experiment_id": "${EXPERIMENT_ID}",
  "machine_label": "${MACHINE_LABEL}",
  "target": "${TARGET}",
  "backend": "${BACKEND}",
  "workers": ${WORKERS},
  "timeout_sec": ${TIMEOUT_SEC},
  "restart_limit": ${RESTART_LIMIT},
  "duration_hours": ${DURATION_HOURS},
  "data_dir": "${DATA_DIR}",
  "triage_root": "${TRIAGE_ROOT}",
  "reports_root": "${REPORTS_ROOT}",
  "corpus_dir": "${CORPUS_DIR}",
  "seed_count": ${SEED_COUNT},
  "mutation_manifest": "${MUTATION_MANIFEST}",
  "mutated_count": ${MUTATED_COUNT},
  "git_commit": "${GIT_COMMIT}",
  "started_at": "${STARTED_AT}",
  "finished_at": "${FINISHED_AT}",
  "metrics_file": "${METRICS_FILE}",
  "run_status_file": "${RUN_STATUS_FILE}",
  "file_index": "file-index.tsv",
  "source_index": "source-index.tsv"
}
EOF

cat > "$OUT_DIR/summary.md" <<EOF
# Experiment Summary

## Conditions
- experiment_id: \`${EXPERIMENT_ID}\`
- machine: \`${MACHINE_LABEL}\`
- target: \`${TARGET}\`
- backend: \`${BACKEND}\`
- duration_hours: \`${DURATION_HOURS}\`
- data_dir: \`${DATA_DIR}\`
- triage_root: \`${TRIAGE_ROOT}\`
- reports_root: \`${REPORTS_ROOT}\`
- corpus_dir: \`${CORPUS_DIR}\`
- seed_count: \`${SEED_COUNT}\`
- mutation_manifest: \`${MUTATION_MANIFEST:-none}\`
- mutated_count: \`${MUTATED_COUNT}\`
- workers: \`${WORKERS}\`
- timeout_sec: \`${TIMEOUT_SEC}\`
- restart_limit: \`${RESTART_LIMIT}\`
- git_commit: \`${GIT_COMMIT}\`

## Metrics
| key | value |
| --- | ---: |
| total_runs | ${TOTAL_RUNS} |
| success | ${SUCCESS} |
| failed | ${FAILED} |
| timeout | ${TIMEOUT} |
| rejected | ${REJECTED} |
| retries | ${RETRIES} |
| engine_mode | ${ENGINE_MODE} |
| new_crashes_per_hour | ${NEW_CRASHES_PER_HOUR} |
| valid_crash_ratio | ${VALID_CRASH_RATIO} |
| valid_crash_ratio_source | ${VALID_CRASH_RATIO_SOURCE} |
| reproduced_count | ${REPRODUCED_COUNT} |
| report_count | ${REPORT_COUNT} |
| unique_signature_count | ${UNIQUE_SIGNATURE_COUNT} |
| successful_runs_per_hour_proxy | ${SUCCESSFUL_RUNS_PER_HOUR_PROXY} |
| global_error_rate_5m | ${GLOBAL_ERROR_RATE_5M} |
| backend_worker_runs_per_hour | ${BACKEND_WORKER_RUNS_PER_HOUR} |
| backend_worker_errors_5m | ${BACKEND_WORKER_ERRORS_5M} |

## Caveat
- \`successful_runs_per_hour_proxy\` is a success-count proxy metric, not true edge/path coverage.
- \`new_crashes_per_hour\` is based on triage inputs where a crash was observed.
- \`global_error_rate_5m\` is computed as recent \`errors / total\` over **local-harness run** events only, and is \`not_available\` when no such event falls in the window. A triage event's \`errors\` counts attempts in which the crash reproduced - the desired outcome - so it is not an operational error and is excluded.
- \`successful_runs_per_hour_proxy\` likewise counts local-harness per-input runs only. On an \`aflpp\` or \`libfuzzer\` arm both rows read 0 / \`not_available\` **by construction**: that arm's unit is a worker, not an input. Read \`backend_worker_runs_per_hour\` and \`backend_worker_errors_5m\` instead.
- Rows exported before the per-kind split mixed all three units, so they are not comparable with rows exported after it.
- \`valid_crash_ratio\` is calculated from \`data/triage/triage-*/summary.json\` when \`valid_crash_ratio_source=triage_summary_scan\`.
- \`valid_crash_ratio\` is \`not_available\` when there are no triage crash observations to support the ratio.
- \`unique_signature_count\` counts only \`reproduced\` triage rows, using \`normalized_frame_hash\` when present and falling back to legacy \`signature_top1\`.
- \`mutation_manifest\` is recorded when the experiment corpus directory contains a mutator-generated \`manifest.json\`.
- Legacy metrics without \`valid_crash_ratio_status\` are reported as \`legacy_unverified\`.
EOF

{
  echo "- generated_by: scripts/export_experiment_summary.sh"
  echo "- experiment_id: \`${EXPERIMENT_ID}\`"
  if [[ -n "$NOTES_TEXT" ]]; then
    echo "- note: ${NOTES_TEXT}"
  fi
} > "$OUT_DIR/notes.md"

write_source_index "$OUT_DIR/source-index.tsv"

write_file_index \
  "$OUT_DIR" \
  "manifest.json" \
  "summary.md" \
  "run-status.json" \
  "metrics-latest.json" \
  "triage-index.tsv" \
  "report-index.tsv" \
  "source-index.tsv" \
  "notes.md"

echo "[export-experiment] done"
echo "out_dir: $OUT_DIR"
echo "files:"
echo "  - $OUT_DIR/manifest.json"
echo "  - $OUT_DIR/summary.md"
echo "  - $OUT_DIR/run-status.json"
echo "  - $OUT_DIR/metrics-latest.json"
echo "  - $OUT_DIR/triage-index.tsv"
echo "  - $OUT_DIR/report-index.tsv"
echo "  - $OUT_DIR/source-index.tsv"
echo "  - $OUT_DIR/notes.md"
echo "  - $OUT_DIR/file-index.tsv"
