#!/usr/bin/env bash
# Continuous ONNX AFL++ fuzzing wrapper for 1-week systemd run on 퍼징컴 (Arm C).
# Decision context: results/experiments/2026-05-19-onnx-local-harness-1week-06-211-01/notes.md §"Suggested Follow-up"
# and the libfuzzer (Arm B) ops pair ops/scripts/fuzz-loop-libfuzzer.sh / ops/systemd/tool-fuzz-onnx-libfuzzer.service.
#
# Difference vs ops/scripts/fuzz-loop-libfuzzer.sh (Arm B):
#   - AFL++ runs as a hardened Docker container (aflplusplus/aflplusplus).
#     If harnesses/aflpp/onnxruntime_loader_replay exists AND carries AFL++/sancov
#     instrumentation, AFL++ drives that native ONNX binary without `-n` (aflpp_mode=instrumented);
#     otherwise it warns and falls back to `-n` black-box mode over `tool harness`
#     (aflpp_mode=blackbox_n). REQUIRE_INSTRUMENTED=1 turns that fallback into a hard failure.
#     Verify both paths with scripts/check_engine_mode_labels.sh.
#   - TOOL_AFLPP_CMD env var must be set; this wrapper exports the hardened template (matches
#     scripts/run_long.sh aflpp leg + docs/specs.md §Docker hardening). run.rs substitutes the
#     {docker_*}/{workdir_abs}/{corpus_dir_abs}/{run_dir_abs}/{container_*} placeholders at run time.
#   - WORKERS defaults to 1 (NOT 12): each container reserves --cpus 2 + --memory 4g, so this is
#     the safe default for WSL 8GB-class 퍼징컴 runs. Override only after memory/swap monitoring.
#
# Loop: run (workers 1 by default, each container -V 5) -> archive metadata -> clean old AFL++ run dirs -> sleep 2s -> next.
# Graceful stop: SIGTERM finishes current run, then exits.
# Cleanup: keep newest AFLPP_MAX_RUN_DIRS_KEEP AFL++ run dirs, archive status/stats/crash metadata before deleting old dirs.
# Smoke: FUZZ_LOOP_MAX_ITERATIONS=N exits after N iterations (test only).
#
# Prerequisites on 퍼징컴:
#   - docker.io installed; service user in the `docker` group (so afl-out is not root-owned;
#     {docker_user_flag} also enforces uid:gid). Verify: `docker run --rm aflplusplus/aflplusplus afl-fuzz -h`.
#   - target/release/tool built (orchestrator and in-container target). Override with
#     AFLPP_CONTAINER_TOOL only if intentionally validating a different binary.
#   - .venv with onnxruntime present under the workdir (mounted /work:ro) — Docker runs with
#     --network none, so onnxruntime cannot be pip-installed at runtime; it must already be present.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DEFAULT_PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

canonical_path() {
    local path="$1"

    if command -v realpath >/dev/null 2>&1; then
        realpath -m "${path}"
    elif command -v readlink >/dev/null 2>&1; then
        readlink -f "${path}" 2>/dev/null || printf '%s\n' "${path}"
    else
        printf '%s\n' "${path}"
    fi
}

PROJECT_ROOT="${PROJECT_ROOT:-${DEFAULT_PROJECT_ROOT}}"
TARGET="${TARGET:-onnx}"
BACKEND="${BACKEND:-aflpp}"
TOOL_BIN="${TOOL_BIN:-${PROJECT_ROOT}/target/release/tool}"
WORKERS="${WORKERS:-1}"
TIMEOUT_SEC="${TIMEOUT_SEC:-30}"
RESTART_LIMIT="${RESTART_LIMIT:-1}"
TARGET_SPEC="$("${TOOL_BIN}" target-spec --target "${TARGET}" --format shell)" || {
    printf 'failed to resolve target spec for %s\n' "${TARGET}" >&2
    exit 2
}
if ! grep -Fqx 'campaign_supported=1' <<<"${TARGET_SPEC}"; then
    printf 'target is registered but campaign dispatch is unavailable: %s\n' "${TARGET}" >&2
    exit 2
fi
SEED_SUBDIR="$(printf '%s\n' "${TARGET_SPEC}" | sed -n 's/^seed_subdir=//p')"
if [[ ! "${SEED_SUBDIR}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    printf 'target spec for %s has an unsafe seed_subdir\n' "${TARGET}" >&2
    exit 2
fi
if [[ -z "${CORPUS_DIR:-}" ]]; then
    CORPUS_DIR="${PROJECT_ROOT}/seeds/${SEED_SUBDIR}"
fi
ITERATION_SLEEP_SEC="${ITERATION_SLEEP_SEC:-2}"
MAX_ITERATIONS="${FUZZ_LOOP_MAX_ITERATIONS:-0}"
# G2: refuse the silent uninstrumented fallback when the run is meant to be native.
REQUIRE_INSTRUMENTED="${REQUIRE_INSTRUMENTED:-0}"
RUNS_ROOT="${RUNS_ROOT:-$(canonical_path "${PROJECT_ROOT}/data/runs")}"
AFLPP_MAX_RUN_DIRS_KEEP="${AFLPP_MAX_RUN_DIRS_KEEP:-20}"
AFLPP_RUN_SUMMARY_ROOT="${AFLPP_RUN_SUMMARY_ROOT:-$(canonical_path "${PROJECT_ROOT}/data/experiments/aflpp-arm-c-retention")}"
AFLPP_ARCHIVE_MAX_CRASH_FILES="${AFLPP_ARCHIVE_MAX_CRASH_FILES:-200}"

# In-container target binary path (relative to {container_workdir}=/work).
AFLPP_CONTAINER_TOOL_WAS_SET="${AFLPP_CONTAINER_TOOL+x}"
AFLPP_CONTAINER_TOOL="${AFLPP_CONTAINER_TOOL:-target/release/tool}"
# The native replay is per target, not per project. Hardcoding onnx here meant the
# gguf arm could never be anything but blackbox_n no matter what had been built.
# An empty value means "this target has no native replay at all", which is a different
# statement from "it is not built yet" and gets a different warning.
case "${TARGET}" in
    onnx) AFLPP_NATIVE_DRIVER="harnesses/aflpp/onnxruntime_loader_replay" ;;
    gguf) AFLPP_NATIVE_DRIVER="harnesses/aflpp/gguf_loader_replay" ;;
    safetensors) AFLPP_NATIVE_DRIVER="harnesses/aflpp/safetensors_loader_replay" ;;
    *)    AFLPP_NATIVE_DRIVER="" ;;
esac
AFLPP_NATIVE_MODE=0
AFLPP_MODE=blackbox_n
AFLPP_SCOPE=none

# G2: a replay binary without the AFL++ runtime carries no feedback, so driving it
# without -n is not coverage-guided (afl-fuzz may even abort with "No instrumentation
# detected"). Only an instrumented binary earns the native path; everything else is
# labelled and runs in explicit -n black-box mode.
# shellcheck source=../../scripts/lib/engine_mode.sh
. "${SCRIPT_DIR}/../../scripts/lib/engine_mode.sh"

if [ -z "${AFLPP_CONTAINER_TOOL_WAS_SET}" ] && [ -n "${AFLPP_NATIVE_DRIVER}" ] \
    && has_afl_instrumentation "${PROJECT_ROOT}/${AFLPP_NATIVE_DRIVER}"; then
    AFLPP_CONTAINER_TOOL="${AFLPP_NATIVE_DRIVER}"
    AFLPP_NATIVE_MODE=1
    AFLPP_MODE=instrumented
    # "instrumented" alone does not say WHAT was instrumented. ONNX drives an
    # uninstrumented libonnxruntime.so, so its scope is driver_only; gguf links ggml
    # statically, so its scope is library. Record which one this run actually got.
    AFLPP_SCOPE="$(instrumentation_scope "${PROJECT_ROOT}/${AFLPP_NATIVE_DRIVER}")"
fi

# onnxruntime lives in a .so the loader must find inside the container. gguf links ggml
# statically and needs nothing - and pointing a gguf run at the onnxruntime tree would
# be a copy-paste tell that the two arms were never really separated.
case "${TARGET}" in
    onnx) AFLPP_LD_LIBRARY_PATH="{container_workdir}/data/targets/onnxruntime/v1.23.2/onnxruntime-1.23.2/build/Linux/Release:{container_workdir}/data/targets/onnxruntime/v1.23.2/onnxruntime-1.23.2/build/cov-o0/RelWithDebInfo:{container_workdir}/data/targets/onnxruntime/v1.23.2/onnxruntime-1.23.2/build/cov/RelWithDebInfo" ;;
    *)    AFLPP_LD_LIBRARY_PATH="" ;;
esac

log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] fuzz-loop-aflpp: $*"
}

cd "${PROJECT_ROOT}" || {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] fuzz-loop-aflpp: PROJECT_ROOT is invalid: ${PROJECT_ROOT}" >&2
    exit 2
}
mkdir -p "${AFLPP_RUN_SUMMARY_ROOT}" || {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] fuzz-loop-aflpp: failed to create AFLPP_RUN_SUMMARY_ROOT=${AFLPP_RUN_SUMMARY_ROOT}" >&2
    exit 2
}

# G2: TOOL_AFLPP_MODE is recorded in the run status by `tool run`, so a black-box arm
# can never be reported as a native coverage-guided one after the fact.
export TOOL_AFLPP_MODE="${AFLPP_MODE}"

if [ "${AFLPP_MODE}" != "instrumented" ]; then
    if [ -z "${AFLPP_NATIVE_DRIVER}" ]; then
        log "WARN: target ${TARGET} has no native AFL++ replay binary; running -n black-box mode over 'tool harness'. This run is NOT coverage-guided."
    elif [ -x "${PROJECT_ROOT}/${AFLPP_NATIVE_DRIVER}" ]; then
        log "WARN: ${AFLPP_NATIVE_DRIVER} has no AFL++/sancov instrumentation; falling back to -n black-box mode. This run is NOT coverage-guided."
    else
        log "WARN: no native AFL++ replay binary at ${AFLPP_NATIVE_DRIVER}; running -n black-box mode over 'tool harness'. This run is NOT coverage-guided."
    fi
    if [ "${REQUIRE_INSTRUMENTED}" = "1" ]; then
        log "REQUIRE_INSTRUMENTED=1 is set; refusing to run without instrumentation"
        exit 3
    fi
fi
log "aflpp_mode=${AFLPP_MODE}"
log "aflpp_instrumentation_scope=${AFLPP_SCOPE}"

stop_requested=0
trap 'stop_requested=1; log "SIGTERM received, will exit after current iteration"' TERM INT

copy_run_metadata_file() {
    local run_dir="$1"
    local summary_dir="$2"
    local source_path="$3"
    local rel_path
    local dest_path

    rel_path="${source_path#${run_dir}/}"
    dest_path="${summary_dir}/${rel_path}"
    mkdir -p "$(dirname "${dest_path}")"
    cp -p "${source_path}" "${dest_path}" 2>/dev/null || true
}

archive_run_dir_metadata() {
    local run_dir="$1"
    local run_name
    local summary_dir
    local source_size

    [ -d "${run_dir}" ] || return 0

    run_name="$(basename "${run_dir}")"
    summary_dir="${AFLPP_RUN_SUMMARY_ROOT}/${run_name}"
    mkdir -p "${summary_dir}"

    source_size="$(du -sh "${run_dir}" 2>/dev/null | awk '{print $1}')"
    {
        echo "archived_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "source_run_dir=${run_dir}"
        echo "source_size=${source_size:-unknown}"
        echo "retention_policy=keep_newest_${AFLPP_MAX_RUN_DIRS_KEEP}_aflpp_run_dirs"
    } > "${summary_dir}/retention.txt"

    if [ -f "${run_dir}/status.json" ]; then
        cp -p "${run_dir}/status.json" "${summary_dir}/status.json" 2>/dev/null || true
    fi

    if [ -f "${run_dir}/.fuzz-loop-aflpp" ]; then
        cp -p "${run_dir}/.fuzz-loop-aflpp" "${summary_dir}/fuzz-loop-aflpp.marker" 2>/dev/null || true
    fi

    if [ -d "${run_dir}/logs" ]; then
        find "${run_dir}/logs" -type f -size -10M -print 2>/dev/null \
            | while IFS= read -r path; do
                copy_run_metadata_file "${run_dir}" "${summary_dir}" "${path}"
            done
    fi

    if [ -d "${run_dir}/afl-out" ]; then
        find "${run_dir}/afl-out" -maxdepth 2 -type f \( -name fuzzer_stats -o -name plot_data -o -name cmdline \) -size -10M -print 2>/dev/null \
            | while IFS= read -r path; do
                copy_run_metadata_file "${run_dir}" "${summary_dir}" "${path}"
            done

        for evidence_dir in "${run_dir}"/afl-out/*/crashes "${run_dir}"/afl-out/*/hangs; do
            [ -d "${evidence_dir}" ] || continue
            find "${evidence_dir}" -maxdepth 1 -type f -size -10M -print 2>/dev/null \
                | sort \
                | head -n "${AFLPP_ARCHIVE_MAX_CRASH_FILES}" \
                | while IFS= read -r path; do
                    copy_run_metadata_file "${run_dir}" "${summary_dir}" "${path}"
                done
        done
    fi
}

is_aflpp_run_dir() {
    local run_dir="$1"

    [ -f "${run_dir}/.fuzz-loop-aflpp" ] || [ -d "${run_dir}/afl-out" ]
}

cleanup_old_aflpp_runs() {
    local list_file
    local run_count
    local excess

    case "${AFLPP_MAX_RUN_DIRS_KEEP}" in
        ''|*[!0-9]*)
            log "invalid AFLPP_MAX_RUN_DIRS_KEEP=${AFLPP_MAX_RUN_DIRS_KEEP}, skipping cleanup"
            return 0
            ;;
    esac

    [ -d "${RUNS_ROOT}" ] || return 0

    list_file="$(mktemp)"
    find "${RUNS_ROOT}" -maxdepth 1 -type d -name 'run-*' -printf '%T@ %p\n' 2>/dev/null \
        | sort -n \
        | while IFS= read -r line; do
            run_dir="${line#* }"
            if is_aflpp_run_dir "${run_dir}"; then
                echo "${line}"
            fi
        done > "${list_file}"

    run_count="$(wc -l < "${list_file}" | tr -d ' ')"
    if [ "${run_count}" -le "${AFLPP_MAX_RUN_DIRS_KEEP}" ]; then
        rm -f "${list_file}"
        return 0
    fi

    excess=$((run_count - AFLPP_MAX_RUN_DIRS_KEEP))
    head -n "${excess}" "${list_file}" \
        | while IFS= read -r line; do
            old_run="${line#* }"
            archive_run_dir_metadata "${old_run}"
            rm -rf "${old_run:?}"
        done
    rm -f "${list_file}"
    log "cleaned ${excess} old AFL++ run dirs (kept newest ${AFLPP_MAX_RUN_DIRS_KEEP}; metadata in ${AFLPP_RUN_SUMMARY_ROOT})"
}

mark_latest_aflpp_run() {
    local run_dir="$1"
    local iter="$2"
    local exit_code="$3"
    local run_abs

    [ -n "${run_dir}" ] || return 0
    case "${run_dir}" in
        /*) run_abs="${run_dir}" ;;
        ./*) run_abs="${PROJECT_ROOT}/${run_dir#./}" ;;
        *) run_abs="${PROJECT_ROOT}/${run_dir}" ;;
    esac
    [ -d "${run_abs}" ] || return 0

    {
        echo "created_by=fuzz-loop-aflpp"
        echo "marked_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "iter=${iter}"
        echo "exit_code=${exit_code}"
        echo "target=${TARGET}"
        echo "backend=${BACKEND}"
        echo "container_tool=${AFLPP_CONTAINER_TOOL}"
        echo "aflpp_mode=${AFLPP_MODE}"
        echo "corpus_dir=${CORPUS_DIR}"
    } > "${run_abs}/.fuzz-loop-aflpp"
}

# AFL++ docker invocation contract (hardened; matches scripts/run_long.sh aflpp leg and
# docs/specs.md §Docker hardening). Placeholders are substituted by `tool run --backend aflpp`:
#   {docker_user_flag}      = --user uid:gid (afl-out ownership)
#   {docker_hardening_flags}= --network none --memory 4g --cpus 2 --pids-limit 512
#   {docker_readonly_flags} = --read-only --tmpfs /tmp:rw,size=1g --tmpfs /dev/shm:rw,size=1g
#   {workdir_abs}/{corpus_dir_abs}/{run_dir_abs} = host mounts; {container_*} = in-container paths
if [ "${AFLPP_NATIVE_MODE}" = "1" ]; then
    if [ -n "${AFLPP_LD_LIBRARY_PATH}" ]; then
        AFLPP_ENV_PREFIX="LD_LIBRARY_PATH=${AFLPP_LD_LIBRARY_PATH}:\\\$LD_LIBRARY_PATH "
    else
        AFLPP_ENV_PREFIX=""
    fi
    export TOOL_AFLPP_CMD="docker run --rm {docker_user_flag} {docker_hardening_flags} {docker_readonly_flags} -v {workdir_abs}:/work:ro -v {corpus_dir_abs}:/corpus:ro -v {run_dir_abs}:/out -w /work aflplusplus/aflplusplus bash -lc \"${AFLPP_ENV_PREFIX}AFL_IGNORE_SEED_PROBLEMS=1 afl-fuzz -V 5 -i {container_corpus_dir} -o {container_run_dir}/afl-out -- {container_workdir}/${AFLPP_CONTAINER_TOOL} @@ >/dev/null 2>&1\""
else
    # G3: in -n black-box mode AFL++ only records signal deaths, but the tool wrapper
    # never dies by signal - it reports a library crash as exit 4 (rejected inputs use 9
    # and an unavailable harness 10, see EXIT_HARNESS_* in src/main.rs). Without
    # AFL_CRASH_EXITCODE a real crash is invisible to this arm. AFL_IGNORE_SEED_PROBLEMS
    # keeps a corpus that already holds a crashing seed from aborting the whole run.
    export TOOL_AFLPP_CMD="docker run --rm {docker_user_flag} {docker_hardening_flags} {docker_readonly_flags} -v {workdir_abs}:/work:ro -v {corpus_dir_abs}:/corpus:ro -v {run_dir_abs}:/out -w /work aflplusplus/aflplusplus bash -lc \"AFL_CRASH_EXITCODE=4 AFL_IGNORE_SEED_PROBLEMS=1 afl-fuzz -n -V 5 -i {container_corpus_dir} -o {container_run_dir}/afl-out -- {container_workdir}/${AFLPP_CONTAINER_TOOL} harness --target ${TARGET} --input @@ >/dev/null 2>&1\""
fi

iter=0
log "starting aflpp loop (target=${TARGET}, workers=${WORKERS}, container_tool=${AFLPP_CONTAINER_TOOL}, corpus=${CORPUS_DIR})"
log "TOOL_AFLPP_CMD=${TOOL_AFLPP_CMD}"
log "retention: keep newest ${AFLPP_MAX_RUN_DIRS_KEEP} AFL++ run dirs; metadata root=${AFLPP_RUN_SUMMARY_ROOT}"
cleanup_old_aflpp_runs

while :; do
    if [ "${stop_requested}" = "1" ]; then
        log "stop_requested, exiting at iter=${iter}"
        exit 0
    fi

    iter=$((iter + 1))
    log "iter=${iter} starting"

    run_log="$(mktemp)"
    "${TOOL_BIN}" run \
        --target "${TARGET}" \
        --backend "${BACKEND}" \
        --workers "${WORKERS}" \
        --timeout-sec "${TIMEOUT_SEC}" \
        --restart-limit "${RESTART_LIMIT}" \
        --corpus-dir "${CORPUS_DIR}" 2>&1 | tee "${run_log}"
    run_exit=${PIPESTATUS[0]}
    run_dir="$(awk -F': ' '/^run_dir: / {print $2; exit}' "${run_log}")"
    rm -f "${run_log}"
    mark_latest_aflpp_run "${run_dir}" "${iter}" "${run_exit}"
    cleanup_old_aflpp_runs

    if [ "${run_exit}" -ne 0 ]; then
        log "iter=${iter} run failed, continuing to next iteration"
    fi

    if [ "${MAX_ITERATIONS}" -ne 0 ] && [ "${iter}" -ge "${MAX_ITERATIONS}" ]; then
        log "reached MAX_ITERATIONS=${MAX_ITERATIONS}, exiting"
        exit 0
    fi

    sleep "${ITERATION_SLEEP_SEC}"
done
