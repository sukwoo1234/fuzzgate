#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
SEED="${SEED:-$PROJECT_ROOT/seeds/onnx/onnx_5_mul_1.onnx}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/data/native-engine-checks/onnx}"
REQUIRE_AFLPP=0

usage() {
  cat <<'EOF'
usage: check_onnx_native_engines.sh [--require-aflpp]

Checks native ONNX fuzz engine plumbing without committing PoCs:
  - builds native libFuzzer ONNX harness
  - builds native standalone replay
  - runs a known-good seed through both
  - when AFL++ tools exist, builds AFL++ native replay and verifies afl-showmap coverage
  - with --require-aflpp, missing AFL++ tools or zero coverage is a hard failure
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-aflpp) REQUIRE_AFLPP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[onnx-native-check] unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

log() {
  echo "[onnx-native-check] $*"
}

fail() {
  echo "[onnx-native-check] fail: $*" >&2
  exit 1
}

# -s, not -f: every assertion below this line is "the harness exited 0", and both the
# libFuzzer target and the standalone replay exit 0 on empty input without parsing a
# byte. An empty seed would let this check report that both arms ran having run
# nothing. -s does not replace -f: -s is true for a directory, so dropping -f would trade
# one hole for another. ONNX-ENG-03, the BASE-01 case that pins this same run, gates on -s.
#
# It buys one byte, not a valid model: a 1-byte junk seed still exits 0 through both arms
# with the same log shape, and seeds/onnx holds exactly such a leftover today. That residue
# is R82; this guard closes the zero-byte and directory cases only.
[[ -f "$SEED" && -s "$SEED" ]] || fail "seed missing, empty or not a regular file: $SEED"
mkdir -p "$OUT_DIR"

# The instrumented ONNX harnesses write one .profraw per process; without a contained
# LLVM_PROFILE_FILE they drop default.profraw into the working directory. Naming them by
# PID inside OUT_DIR meant every run added two more and nothing removed them - measured
# 2026-09-13: 26 files / 1.1 GB in data/native-engine-checks/onnx, the oldest from
# 2026-06-12. Nothing reads them: this check asserts on its logs, and a repository-wide
# grep finds no other consumer. Scratch that goes away is where they belong, the shape
# check_safetensors_native_engines.sh:34-45 already uses; OUT_DIR keeps the logs, which
# this check rewrites by design.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/onnx-native-check-XXXXXX")"
cleanup() {
  local rc=$?
  if [[ "$rc" -eq 0 ]]; then
    rm -rf "$WORK"
  else
    log "scratch preserved: $WORK" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT

# Build only when the harness is missing, the shape check_safetensors_native_engines.sh
# already uses. Building unconditionally reinstalled harnesses/libfuzzer/onnxruntime_*
# on every run of the check suite: this script observes those binaries, so rewriting
# them is a side effect, and SO_DIR auto-detection can pick a differently instrumented
# build than the one that was originally installed.
LF_FUZZER="$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer"
LF_REPLAY="$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_replay"

if [[ ! -x "$LF_FUZZER" ]]; then
  log "libFuzzer harness missing; building"
  "$PROJECT_ROOT/scripts/build_libfuzzer_onnx_native.sh" >/tmp/onnx-native-libfuzzer-build.log
fi

if [[ ! -x "$LF_REPLAY" ]]; then
  log "standalone replay missing; building"
  BUILD_STANDALONE=1 "$PROJECT_ROOT/scripts/build_libfuzzer_onnx_native.sh" >/tmp/onnx-native-standalone-build.log
fi

log "run libFuzzer fixed-input smoke"
LLVM_PROFILE_FILE="$WORK/libfuzzer-%p.profraw" \
  "$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer" -runs=1 "$SEED" \
  >"$OUT_DIR/libfuzzer-smoke.log" 2>&1

log "run standalone replay smoke"
LLVM_PROFILE_FILE="$WORK/replay-%p.profraw" \
  "$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_replay" "$SEED" \
  >"$OUT_DIR/replay-smoke.log" 2>&1

# shellcheck source=lib/engine_mode.sh
. "$PROJECT_ROOT/scripts/lib/engine_mode.sh"

if command -v afl-clang-fast++ >/dev/null 2>&1 && command -v afl-showmap >/dev/null 2>&1; then
  log "build AFL++ native replay"
  "$PROJECT_ROOT/scripts/build_aflpp_onnx_native.sh" >"$OUT_DIR/aflpp-build.log" 2>&1

  AFLPP_REPLAY="$PROJECT_ROOT/harnesses/aflpp/onnxruntime_loader_replay"
  [[ -x "$AFLPP_REPLAY" ]] || fail "AFL++ replay not produced: $AFLPP_REPLAY"

  # driver_only, not library: onnxruntime is a separate .so, so AFL++ instruments this
  # driver and none of the parser - the G2 situation the paper had to describe after the
  # fact. It is the expected answer here, and check_engine_mode_labels.sh:234-246 already
  # asserts it for the shipped drivers. Asserted rather than logged because the failure it
  # rules out is 'none': a replay that carries no forkserver at all still produces a map
  # under afl-showmap's non-instrumented mode, and the tuple count below would then be
  # reported as engine coverage. Measured 2026-09-14: /bin/true as the replay passed this
  # arm with tuples=5.
  scope="$(instrumentation_scope "$AFLPP_REPLAY")"
  [[ "$scope" == "driver_only" ]] \
    || fail "AFL++ replay scope is '$scope', expected 'driver_only': $AFLPP_REPLAY"
  log "OK   instrumentation_scope=$scope"

  log "run afl-showmap coverage smoke"
  AFL_MAP="$OUT_DIR/afl-showmap.txt"
  # Removed first, the shape check_gguf_native_engines.sh:164 uses: OUT_DIR is reused
  # across runs, so a map left by an earlier one is counted as this run's coverage by any
  # afl-showmap that exits without writing. Measured 2026-09-14 with a stub showmap: a
  # 7-line map from a previous run was reported as `tuples=7` and the check exited 0.
  rm -f "$AFL_MAP"
  afl-showmap -q -o "$AFL_MAP" -- "$AFLPP_REPLAY" "$SEED" \
    >"$OUT_DIR/afl-showmap.log" 2>&1
  # No `|| showmap_rc=$?` here, deliberately: `:2 set -euo pipefail` already makes a
  # non-zero afl-showmap abort the check, which is stricter than the gguf and safetensors
  # arms that capture the status and assert on it later (R36). This says what happened
  # when it exits 0 having written nothing at all.
  [[ -f "$AFL_MAP" ]] \
    || fail "afl-showmap wrote no map; see $OUT_DIR/afl-showmap.log"
  tuples="$(wc -l < "$AFL_MAP" | tr -d ' ')"
  if [[ "$tuples" -le 0 ]]; then
    fail "afl-showmap produced zero tuples"
  fi
  log "afl-showmap tuples=$tuples"
else
  msg="AFL++ tools missing: afl-clang-fast++ and/or afl-showmap"
  if [[ "$REQUIRE_AFLPP" -eq 1 ]]; then
    fail "$msg"
  fi
  log "skip AFL++ proof: $msg"
fi

log "done: $OUT_DIR"
