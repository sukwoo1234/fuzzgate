#!/usr/bin/env bash
# Continuous ONNX libfuzzer fuzzing wrapper for 1-week systemd run on 퍼징컴.
# Decision context: results/experiments/2026-05-19-onnx-local-harness-1week-06-211-01/notes.md §"Suggested Follow-up".
#
# Difference vs ops/scripts/fuzz-loop.sh (local-harness):
#   - libfuzzer manages its own corpus + mutation internally, so no `tool mutate` step.
#   - Loop is just: `tool run --backend libfuzzer` → sleep → repeat.
#   - TOOL_LIBFUZZER_CMD env var must be set; this wrapper exports a default.
#   - Without the native ONNX driver the wrapper warns and runs the black-box tool driver
#     (libfuzzer_mode=blackbox); REQUIRE_NATIVE=1 makes that a hard failure instead.
#     Verify both paths with scripts/check_engine_mode_labels.sh.
#
# Loop: run (workers 12, timeout 30s) -> sleep 2s -> next.
# Graceful stop: SIGTERM finishes current run, then exits.
# Smoke: FUZZ_LOOP_MAX_ITERATIONS=N exits after N iterations (test only).

set -uo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-/home/ssw/bugbounty}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=../../scripts/lib/gguf_corpus.sh
. "${SCRIPT_DIR}/../../scripts/lib/gguf_corpus.sh"
TARGET="${TARGET:-onnx}"
BACKEND="${BACKEND:-libfuzzer}"
WORKERS="${WORKERS:-12}"
TIMEOUT_SEC="${TIMEOUT_SEC:-30}"
RESTART_LIMIT="${RESTART_LIMIT:-1}"
# libFuzzer WRITES every interesting unit back into the directory it is given, so the
# corpus it runs on cannot be a directory anything else depends on. For gguf that
# matters twice over: seeds/gguf is the 19-file fixture Stage A's oracle check asserts
# on (all 19 must parse cleanly at three depths), and the shipped gguf AFL++ unit reads
# the same directory as its -i set - so a libFuzzer run would both break the fixture and
# feed its own work into the other arm of the comparison.
# onnx is deliberately left as it was: its arms have always shared seeds/onnx by design
# (see ops/systemd/tool-fuzz-onnx-libfuzzer.service), and published Arm B/C numbers rest
# on that. Changing it now would make old and new runs incomparable.
if [ -z "${CORPUS_DIR:-}" ]; then
    case "${TARGET}" in
        gguf) CORPUS_DIR="${PROJECT_ROOT}/data/corpus/libfuzzer/${TARGET}" ;;
        *)    CORPUS_DIR="${PROJECT_ROOT}/seeds/${TARGET}" ;;
    esac
fi
ITERATION_SLEEP_SEC="${ITERATION_SLEEP_SEC:-2}"
MAX_ITERATIONS="${FUZZ_LOOP_MAX_ITERATIONS:-0}"
# G4: refuse the silent black-box fallback when the run is meant to be native.
REQUIRE_NATIVE="${REQUIRE_NATIVE:-0}"

LIBFUZZER_MAX_TOTAL_TIME="${LIBFUZZER_MAX_TOTAL_TIME:-30}"
# R16: gguf has attacker-controlled allocation lengths. The build-time parser clamp
# rejects the known V4 shape, but the campaign still needs process-level backstops for
# any equivalent path the fuzzer reaches. Keep these explicit in the command so the
# loop log is also an auditable record of the limits used.
case "${TARGET}" in
    gguf) LIBFUZZER_RESOURCE_LIMITS="-rss_limit_mb=2048 -malloc_limit_mb=2048" ;;
    *)    LIBFUZZER_RESOURCE_LIMITS="" ;;
esac
# The native driver is per target, not per project: hardcoding onnx here meant a gguf
# run with a perfectly good native driver next to it was labelled blackbox and fuzzed
# through the tool wrapper instead. An empty NATIVE_DRIVER means "no native driver
# exists for this target", which is a different thing from "it is not built yet".
case "${TARGET}" in
    onnx) NATIVE_DRIVER="${PROJECT_ROOT}/harnesses/libfuzzer/onnxruntime_loader_fuzzer" ;;
    gguf) NATIVE_DRIVER="${PROJECT_ROOT}/harnesses/libfuzzer/gguf_loader_fuzzer" ;;
    safetensors) NATIVE_DRIVER="${PROJECT_ROOT}/harnesses/libfuzzer/safetensors_loader_fuzzer" ;;
    *)    NATIVE_DRIVER="" ;;
esac
TOOL_DRIVER="${PROJECT_ROOT}/harnesses/libfuzzer/tool_harness_driver"

if [[ -z "${LIBFUZZER_DRIVER:-}" ]]; then
    if [[ -n "${NATIVE_DRIVER}" && -x "${NATIVE_DRIVER}" ]]; then
        LIBFUZZER_DRIVER="${NATIVE_DRIVER}"
    else
        LIBFUZZER_DRIVER="${TOOL_DRIVER}"
    fi
fi

TOOL_BIN="${TOOL_BIN:-${PROJECT_ROOT}/target/release/tool}"

log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] fuzz-loop-libfuzzer: $*"
}

cd "${PROJECT_ROOT}"

# A private corpus starts empty; seed it from the read-only fixture. The copy never
# overwrites what the fuzzer has since produced, and the fixture itself is only ever
# read - but a fixture CHANGE evicts what the previous one left, or the arm would keep
# fuzzing the units the new fixture exists to replace (see scripts/lib/gguf_corpus.sh).
# C3: the gguf arm seeds from the under-cap derivative when there is one. The choice
# lives in scripts/lib/gguf_corpus.sh so run_long.sh makes the same one.
SEED_FIXTURE="${PROJECT_ROOT}/seeds/${TARGET}"
if [ "${TARGET}" = "gguf" ]; then
    if SEED_FIXTURE="$(gguf_libfuzzer_seed_fixture "${PROJECT_ROOT}")"; then
        :
    else
        log "WARN no usable libfuzzer-sized corpus at ${PROJECT_ROOT}/data/corpus/gguf-libfuzzer; seeding from seeds/gguf, whose oversized units libFuzzer can never reproduce (build it with scripts/build_gguf_libfuzzer_corpus.sh)"
    fi
fi
log "seed_fixture=${SEED_FIXTURE}"

CORPUS_DIR="${CORPUS_DIR%/}"
if [ "${CORPUS_DIR}" != "${SEED_FIXTURE}" ]; then
    EVICTED="$(gguf_seed_working_corpus "${CORPUS_DIR}" "${SEED_FIXTURE}")"
    if [ "${EVICTED}" != "0" ]; then
        log "evicted ${EVICTED} working-corpus units left by a previous seed fixture"
    fi
fi

# G4: the loop used to fall back to the black-box tool wrapper without a word, so a
# "libfuzzer onnx run" could silently stop being a native run. Label every run and say
# so loudly; TOOL_LIBFUZZER_MODE is recorded in the run status by `tool run`.
# -x as well as the name match: an operator can point LIBFUZZER_DRIVER at the native
# path before it has been built, and a label of "native" on a driver that cannot run
# would defeat REQUIRE_NATIVE with no warning anywhere.
if [[ -n "${NATIVE_DRIVER}" && "${LIBFUZZER_DRIVER}" == "${NATIVE_DRIVER}" && -x "${NATIVE_DRIVER}" ]]; then
    LIBFUZZER_MODE=native
else
    LIBFUZZER_MODE=blackbox
fi
export TOOL_LIBFUZZER_MODE="${LIBFUZZER_MODE}"

if [[ "${LIBFUZZER_MODE}" == "blackbox" ]]; then
    if [[ -n "${NATIVE_DRIVER}" ]]; then
        log "WARN: no native libFuzzer driver at ${NATIVE_DRIVER}; running the black-box tool wrapper (${LIBFUZZER_DRIVER}). This run is NOT a native libFuzzer run."
    else
        log "WARN: target ${TARGET} has no native libFuzzer driver; running the black-box tool wrapper (${LIBFUZZER_DRIVER}). This run is NOT a native libFuzzer run."
    fi
    if [[ "${REQUIRE_NATIVE}" == "1" ]]; then
        log "REQUIRE_NATIVE=1 is set; refusing to run in black-box mode"
        exit 3
    fi
fi
log "libfuzzer_mode=${LIBFUZZER_MODE}"

stop_requested=0
trap 'stop_requested=1; log "SIGTERM received, will exit after current iteration"' TERM INT

# libfuzzer driver invocation contract (matches docs/experiment-ops.md §libfuzzer):
#   {corpus_dir} is substituted by `tool run --backend libfuzzer` with CORPUS_DIR
#   verbatim (src/run.rs). It is NOT a copy: libFuzzer writes new units straight into
#   it, which is why CORPUS_DIR above must not be a directory anything else owns. {artifact_dir} is a per-worker run dir
#   for libFuzzer crash artifacts. -max_total_time bounds per-invocation runtime.
if [[ "${LIBFUZZER_MODE}" == "native" ]]; then
    # LLVM_PROFILE_FILE only helps a driver built with source-based coverage
    # (-fprofile-instr-generate), which is the onnx coverage build. The gguf driver is
    # sancov+ASan only, so setting it there just promises a .profraw that never appears.
    # The name carries the target: two arms writing onnx-native-%p.profraw into the same
    # artifact dir would overwrite each other.
    case "${TARGET}" in
        onnx) LIBFUZZER_PROFILE_PREFIX="LLVM_PROFILE_FILE={artifact_dir}/${TARGET}-native-%p.profraw " ;;
        *)    LIBFUZZER_PROFILE_PREFIX="" ;;
    esac
    export TOOL_LIBFUZZER_CMD="mkdir -p {artifact_dir} && ${LIBFUZZER_PROFILE_PREFIX}${LIBFUZZER_DRIVER} ${LIBFUZZER_RESOURCE_LIMITS} -artifact_prefix={artifact_dir}/ -max_total_time=${LIBFUZZER_MAX_TOTAL_TIME} {corpus_dir} >/dev/null 2>&1"
else
    export TOOL_LIBFUZZER_CMD="mkdir -p {artifact_dir} && TOOL_HARNESS_TOOL=${TOOL_BIN} TOOL_HARNESS_TARGET=${TARGET} TOOL_HARNESS_EXT=${TARGET} ${LIBFUZZER_DRIVER} ${LIBFUZZER_RESOURCE_LIMITS} -artifact_prefix={artifact_dir}/ -max_total_time=${LIBFUZZER_MAX_TOTAL_TIME} {corpus_dir} >/dev/null 2>&1"
fi

iter=0
log "starting libfuzzer loop (target=${TARGET}, workers=${WORKERS}, libfuzzer max_total_time=${LIBFUZZER_MAX_TOTAL_TIME}s, corpus=${CORPUS_DIR})"
log "TOOL_LIBFUZZER_CMD=${TOOL_LIBFUZZER_CMD}"

while :; do
    if [ "${stop_requested}" = "1" ]; then
        log "stop_requested, exiting at iter=${iter}"
        exit 0
    fi

    iter=$((iter + 1))
    log "iter=${iter} starting"

    if ! "${TOOL_BIN}" run \
        --target "${TARGET}" \
        --backend "${BACKEND}" \
        --workers "${WORKERS}" \
        --timeout-sec "${TIMEOUT_SEC}" \
        --restart-limit "${RESTART_LIMIT}" \
        --seed-fixture "${SEED_FIXTURE}" \
        --corpus-dir "${CORPUS_DIR}"
    then
        log "iter=${iter} run failed, continuing to next iteration"
    fi

    if [ "${MAX_ITERATIONS}" -ne 0 ] && [ "${iter}" -ge "${MAX_ITERATIONS}" ]; then
        log "reached MAX_ITERATIONS=${MAX_ITERATIONS}, exiting"
        exit 0
    fi

    sleep "${ITERATION_SLEEP_SEC}"
done
