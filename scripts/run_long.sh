#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: run_long.sh --target <onnx|gguf|safetensors> --backend <local-harness|libfuzzer|aflpp> (--hours <N>|--duration-seconds <N>) --tag <TAG> [--corpus-dir <dir>] [--data-dir <dir>] [--workers <n>] [--timeout-sec <n>] [--restart-limit <n>] [--max-jobs <n>]
GGUF libFuzzer uses generated commands with memory limits; unset TOOL_LIBFUZZER_CMD before running.
EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/engine_mode.sh
. "$SCRIPT_DIR/lib/engine_mode.sh"
# shellcheck source=lib/gguf_corpus.sh
. "$SCRIPT_DIR/lib/gguf_corpus.sh"

WORKDIR="${WORKDIR:-$PWD}"
DATA_DIR="${DATA_DIR:-$WORKDIR/data}"
# G2/G4: refuse a silent fallback when the run is meant to be native/instrumented.
REQUIRE_NATIVE="${REQUIRE_NATIVE:-0}"
REQUIRE_INSTRUMENTED="${REQUIRE_INSTRUMENTED:-0}"
TOOL_BIN="${TOOL_BIN:-$WORKDIR/target/debug/tool}"
TARGET=""
BACKEND=""
HOURS=""
DURATION_SECONDS=""
TAG=""
CORPUS_DIR=""
WORKERS="1"
TIMEOUT_SEC="30"
RESTART_LIMIT="1"
MAX_JOBS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:-}"; shift 2 ;;
    --backend) BACKEND="${2:-}"; shift 2 ;;
    --hours) HOURS="${2:-}"; shift 2 ;;
    --duration-seconds) DURATION_SECONDS="${2:-}"; shift 2 ;;
    --tag) TAG="${2:-}"; shift 2 ;;
    --corpus-dir) CORPUS_DIR="${2:-}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
    --workers) WORKERS="${2:-}"; shift 2 ;;
    --timeout-sec) TIMEOUT_SEC="${2:-}"; shift 2 ;;
    --restart-limit) RESTART_LIMIT="${2:-}"; shift 2 ;;
    --max-jobs) MAX_JOBS="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[run-long] unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$TARGET" || -z "$BACKEND" || -z "$TAG" ]]; then
  echo "[run-long] required args missing" >&2
  usage
  exit 2
fi
if [[ -z "$HOURS" && -z "$DURATION_SECONDS" ]]; then
  echo "[run-long] either --hours or --duration-seconds is required" >&2
  usage
  exit 2
fi
if [[ -n "$HOURS" && -n "$DURATION_SECONDS" ]]; then
  echo "[run-long] use only one of --hours or --duration-seconds" >&2
  usage
  exit 2
fi

SEED_FIXTURE=""
if [[ -z "$CORPUS_DIR" ]]; then
  CORPUS_DIR="seeds/${TARGET}"
  # C3: a gguf libFuzzer run seeds from the under-cap derivative when one is built.
  # Only libFuzzer: AFL++ has no input-length cap and its arm keeps the originals.
  if [[ "$TARGET" == gguf && "$BACKEND" == libfuzzer ]]; then
    if SEED_FIXTURE="$(gguf_libfuzzer_seed_fixture "$WORKDIR")"; then
      :
    else
      echo "[run-long] WARN no usable libfuzzer-sized corpus at $WORKDIR/data/corpus/gguf-libfuzzer; seeding from $SEED_FIXTURE, whose oversized units libFuzzer can never reproduce (build it with scripts/build_gguf_libfuzzer_corpus.sh)" >&2
    fi
    CORPUS_DIR="$SEED_FIXTURE"
  fi
fi

if [[ ! -d "$CORPUS_DIR" ]]; then
  echo "[run-long] corpus dir not found: $CORPUS_DIR" >&2
  exit 2
fi

case "$BACKEND" in
  local-harness)
    ;;
  libfuzzer)
    # R16: the pinned GGUF parser has attacker-controlled allocation lengths. The
    # source clamp handles the known V4 shape; explicit libFuzzer limits remain the
    # campaign-level backstop and keep allocator events bounded and recognizable.
    if [[ "$TARGET" == "gguf" ]]; then
      LIBFUZZER_RESOURCE_LIMITS="-rss_limit_mb=2048 -malloc_limit_mb=2048"
    else
      LIBFUZZER_RESOURCE_LIMITS=""
    fi
    if [[ -z "${TOOL_LIBFUZZER_CMD:-}" ]]; then
      # Same per-target resolution as ops/scripts/fuzz-loop-libfuzzer.sh: this is the
      # path the campaign runners take, and the two must decide identically or a
      # campaign and its systemd twin fuzz different things under the same label.
      case "$TARGET" in
        onnx) NATIVE_DRIVER="${WORKDIR}/harnesses/libfuzzer/onnxruntime_loader_fuzzer" ;;
        gguf) NATIVE_DRIVER="${WORKDIR}/harnesses/libfuzzer/gguf_loader_fuzzer" ;;
        safetensors) NATIVE_DRIVER="${WORKDIR}/harnesses/libfuzzer/safetensors_loader_fuzzer" ;;
        *)    NATIVE_DRIVER="" ;;
      esac
      # Keep an explicit override only when it names the canonical driver for the
      # selected target. Checking -x alone lets an arbitrary executable earn the
      # permanent native label in status.json, and defeats REQUIRE_NATIVE. This exact
      # path comparison mirrors ops/scripts/fuzz-loop-libfuzzer.sh.
      LIBFUZZER_OVERRIDE_MISMATCH=0
      if [[ -n "${LIBFUZZER_DRIVER:-}" ]]; then
        if [[ "$LIBFUZZER_DRIVER" != "$NATIVE_DRIVER" ]]; then
          LIBFUZZER_OVERRIDE_MISMATCH=1
          echo "[run-long] WARN: LIBFUZZER_DRIVER=$LIBFUZZER_DRIVER does not match target $TARGET native driver $NATIVE_DRIVER; refusing to label it native" >&2
        fi
      fi
      if [[ "$LIBFUZZER_OVERRIDE_MISMATCH" -eq 0 \
        && -n "$NATIVE_DRIVER" && -x "$NATIVE_DRIVER" ]]; then
        export TOOL_LIBFUZZER_MODE="native"
        export TOOL_LIBFUZZER_CMD="mkdir -p {artifact_dir} && LLVM_PROFILE_FILE={artifact_dir}/${TARGET}-native-%p.profraw ${NATIVE_DRIVER} ${LIBFUZZER_RESOURCE_LIMITS} -artifact_prefix={artifact_dir}/ -max_total_time=5 {corpus_dir} >/dev/null 2>&1"
      else
        export TOOL_LIBFUZZER_MODE="blackbox"
        if [[ "$LIBFUZZER_OVERRIDE_MISMATCH" -eq 1 ]]; then
          echo "[run-long] WARN: target $TARGET has no accepted native libFuzzer override; using the black-box tool wrapper. This run is NOT a native libFuzzer run." >&2
        elif [[ -n "$NATIVE_DRIVER" ]]; then
          echo "[run-long] WARN: no native libFuzzer driver at ${NATIVE_DRIVER}; running the black-box tool wrapper. This run is NOT a native libFuzzer run." >&2
        else
          echo "[run-long] WARN: target ${TARGET} has no native libFuzzer driver; running the black-box tool wrapper. This run is NOT a native libFuzzer run." >&2
        fi
        if [[ "$REQUIRE_NATIVE" == "1" ]]; then
          echo "[run-long] REQUIRE_NATIVE=1 is set; refusing to run in black-box mode" >&2
          exit 3
        fi
        export TOOL_LIBFUZZER_CMD="mkdir -p {artifact_dir} && TOOL_HARNESS_TOOL=${TOOL_BIN} TOOL_HARNESS_TARGET=${TARGET} TOOL_HARNESS_EXT=${TARGET} ${WORKDIR}/harnesses/libfuzzer/tool_harness_driver ${LIBFUZZER_RESOURCE_LIMITS} -artifact_prefix={artifact_dir}/ -max_total_time=5 {corpus_dir} >/dev/null 2>&1"
      fi
      echo "[run-long] libfuzzer_mode=${TOOL_LIBFUZZER_MODE}"
      echo "[run-long] TOOL_LIBFUZZER_CMD=${TOOL_LIBFUZZER_CMD}"
    else
      # The backend evaluates templates with bash -lc. Token checks cannot prove
      # which limits reach the engine after quoting, expansion or extra commands.
      # Refuse overrides explicitly rather than silently discarding caller intent.
      if [[ "$TARGET" == "gguf" ]]; then
        echo "[run-long] GGUF libFuzzer does not accept TOOL_LIBFUZZER_CMD; unset TOOL_LIBFUZZER_CMD to use the generated command with -rss_limit_mb=2048 -malloc_limit_mb=2048" >&2
        exit 2
      fi
      echo "[run-long] libfuzzer_mode=${TOOL_LIBFUZZER_MODE:-unlabeled} (TOOL_LIBFUZZER_CMD provided by caller)"
    fi
    ;;
  aflpp)
    if [[ -z "${TOOL_AFLPP_CMD:-}" ]]; then
      # Same per-target resolution as ops/scripts/fuzz-loop-aflpp.sh; the campaign path
      # and the systemd path must agree or the same label means two different runs.
      case "$TARGET" in
        onnx)
          NATIVE_AFLPP_REPLAY_REL="harnesses/aflpp/onnxruntime_loader_replay"
          AFLPP_LD_LIBRARY_PATH="{container_workdir}/data/targets/onnxruntime/v1.23.2/onnxruntime-1.23.2/build/Linux/Release:{container_workdir}/data/targets/onnxruntime/v1.23.2/onnxruntime-1.23.2/build/cov-o0/RelWithDebInfo:{container_workdir}/data/targets/onnxruntime/v1.23.2/onnxruntime-1.23.2/build/cov/RelWithDebInfo"
          ;;
        gguf)
          # ggml is linked statically into the replay, so there is no library path.
          NATIVE_AFLPP_REPLAY_REL="harnesses/aflpp/gguf_loader_replay"
          AFLPP_LD_LIBRARY_PATH=""
          ;;
        safetensors)
          # the safetensors crate is linked statically into the Rust replay, so there
          # is no library path. Build it with build_aflpp_safetensors_native.sh on the
          # fuzzing host; a fresh checkout without that gitignored artifact still falls
          # back to blackbox with a warning unless REQUIRE_INSTRUMENTED=1 is set.
          NATIVE_AFLPP_REPLAY_REL="harnesses/aflpp/safetensors_loader_replay"
          AFLPP_LD_LIBRARY_PATH=""
          ;;
        *)
          NATIVE_AFLPP_REPLAY_REL=""
          AFLPP_LD_LIBRARY_PATH=""
          ;;
      esac
      NATIVE_AFLPP_DRIVER=""
      [[ -n "$NATIVE_AFLPP_REPLAY_REL" ]] && NATIVE_AFLPP_DRIVER="${WORKDIR}/${NATIVE_AFLPP_REPLAY_REL}"
      if [[ -n "$AFLPP_LD_LIBRARY_PATH" ]]; then
        AFLPP_ENV_PREFIX="LD_LIBRARY_PATH=${AFLPP_LD_LIBRARY_PATH}:\\\$LD_LIBRARY_PATH "
      else
        AFLPP_ENV_PREFIX=""
      fi
      # G2: only a binary carrying the AFL++ runtime may drive afl-fuzz without -n.
      if [[ -n "$NATIVE_AFLPP_DRIVER" ]] && has_afl_instrumentation "$NATIVE_AFLPP_DRIVER"; then
        export TOOL_AFLPP_MODE="instrumented"
        echo "[run-long] aflpp_instrumentation_scope=$(instrumentation_scope "$NATIVE_AFLPP_DRIVER")"
        export TOOL_AFLPP_CMD="docker run --rm {docker_user_flag} {docker_hardening_flags} {docker_readonly_flags} -v {workdir_abs}:/work:ro -v {corpus_dir_abs}:/corpus:ro -v {run_dir_abs}:/out -w /work aflplusplus/aflplusplus bash -lc \"${AFLPP_ENV_PREFIX}AFL_IGNORE_SEED_PROBLEMS=1 afl-fuzz -V 5 -i {container_corpus_dir} -o {container_run_dir}/afl-out -- {container_workdir}/${NATIVE_AFLPP_REPLAY_REL} @@ >/dev/null 2>&1\""
      else
        export TOOL_AFLPP_MODE="blackbox_n"
        if [[ -z "$NATIVE_AFLPP_DRIVER" ]]; then
          echo "[run-long] WARN: target ${TARGET} has no native AFL++ replay binary; running -n black-box mode over 'tool harness'. This run is NOT coverage-guided." >&2
        elif [[ -x "$NATIVE_AFLPP_DRIVER" ]]; then
          echo "[run-long] WARN: ${NATIVE_AFLPP_DRIVER} has no AFL++ instrumentation; falling back to -n black-box mode. This run is NOT coverage-guided." >&2
        else
          echo "[run-long] WARN: no native AFL++ replay binary at ${NATIVE_AFLPP_DRIVER}; running -n black-box mode over 'tool harness'. This run is NOT coverage-guided." >&2
        fi
        if [[ "$REQUIRE_INSTRUMENTED" == "1" ]]; then
          echo "[run-long] REQUIRE_INSTRUMENTED=1 is set; refusing to run without instrumentation" >&2
          exit 3
        fi
        # AFL_CRASH_EXITCODE: in -n mode AFL++ only records signal deaths, but the tool
        # wrapper reports a library crash as exit 4. AFL_IGNORE_SEED_PROBLEMS: a corpus
        # that already contains a crashing seed must not abort the whole run.
        export TOOL_AFLPP_CMD="docker run --rm {docker_user_flag} {docker_hardening_flags} {docker_readonly_flags} -v {workdir_abs}:/work:ro -v {corpus_dir_abs}:/corpus:ro -v {run_dir_abs}:/out -w /work aflplusplus/aflplusplus bash -lc \"AFL_CRASH_EXITCODE=4 AFL_IGNORE_SEED_PROBLEMS=1 afl-fuzz -n -V 5 -i {container_corpus_dir} -o {container_run_dir}/afl-out -- {container_workdir}/target/debug/tool harness --target ${TARGET} --input @@ >/dev/null 2>&1\""
      fi
      echo "[run-long] aflpp_mode=${TOOL_AFLPP_MODE}"
      echo "[run-long] TOOL_AFLPP_CMD=${TOOL_AFLPP_CMD}"
    else
      echo "[run-long] aflpp_mode=${TOOL_AFLPP_MODE:-unlabeled} (TOOL_AFLPP_CMD provided by caller)"
    fi
    ;;
  *)
    echo "[run-long] unsupported backend: $BACKEND" >&2
    exit 2
    ;;
esac

# R26: fixtures are inputs, never the writable libFuzzer corpus. Only an omitted
# --corpus-dir uses this shared working copy; campaign arm copies stay caller-owned.
# Seed after the source and engine checks so refused runs do not alter the corpus.
if [[ -n "$SEED_FIXTURE" ]]; then
  CORPUS_DIR="$WORKDIR/data/corpus/libfuzzer/gguf"
  EVICTED="$(gguf_seed_working_corpus "$CORPUS_DIR" "$SEED_FIXTURE")"
  echo "[run-long] seed_fixture=$SEED_FIXTURE"
  if [[ "$EVICTED" -ne 0 ]]; then
    echo "[run-long] evicted $EVICTED old fixture units from $CORPUS_DIR"
  fi
fi

if [[ -n "$DURATION_SECONDS" ]]; then
  DURATION_LABEL="${DURATION_SECONDS}s"
else
  DURATION_LABEL="${HOURS}h"
fi

echo "[run-long] target=$TARGET backend=$BACKEND duration=$DURATION_LABEL tag=$TAG corpus=$CORPUS_DIR data_dir=$DATA_DIR workers=$WORKERS timeout=$TIMEOUT_SEC restart=$RESTART_LIMIT max_jobs=${MAX_JOBS:-all}"

TAG="$TAG" \
WORKDIR="$WORKDIR" \
DATA_DIR="$DATA_DIR" \
TOOL_BIN="$TOOL_BIN" \
TARGET="$TARGET" \
BACKEND="$BACKEND" \
CORPUS_DIR="$CORPUS_DIR" \
WORKERS="$WORKERS" \
TIMEOUT_SEC="$TIMEOUT_SEC" \
RESTART_LIMIT="$RESTART_LIMIT" \
MAX_JOBS="$MAX_JOBS" \
DURATION_HOURS="$HOURS" \
DURATION_SECONDS="$DURATION_SECONDS" \
bash "$WORKDIR/scripts/run_backend_loop.sh"
