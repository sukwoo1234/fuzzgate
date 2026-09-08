#!/usr/bin/env bash
# G2/G4: the engine loops must never fall back to a black-box run silently.
# Verifies, with fake binaries only (no docker, no AFL++, no libFuzzer needed):
#   - a missing native libFuzzer driver logs a WARN and labels the run blackbox
#   - a present native driver labels the run native
#   - a non-instrumented AFL++ replay binary logs a WARN and labels the run blackbox_n
#   - an instrumented AFL++ replay binary labels the run instrumented
#   - REQUIRE_NATIVE / REQUIRE_INSTRUMENTED turn the fallback into a hard failure
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# run_long.sh sends lifecycle notifications when the operator's real hook file exists.
# This fixture must be hermetic and must never contact that external endpoint.
export HOOK_FILE="$WORK/no-discord-hook"
export DISCORD_WEBHOOK=""

log() {
  echo "[engine-mode-check] $*"
}

fail() {
  echo "[engine-mode-check] fail: $*" >&2
  exit 1
}

# A case that does not run is not a case that passed. Every skip is recorded and, by
# default, fails the script at the end: the gguf cases used to self-disable whenever a
# gitignored build artifact was missing, which silently switched off the regression test
# for the systemd defect this project has already shipped once (1e8261f).
SKIPPED=""
note_skip() {
  SKIPPED="${SKIPPED}|$*"
  echo "[engine-mode-check] SKIP: $*"
}

mkdir -p "$WORK/bin" "$WORK/seeds/onnx" "$WORK/harnesses/libfuzzer" "$WORK/harnesses/aflpp"
printf 'seed' > "$WORK/seeds/onnx/seed.onnx"

# stand-in for target/release/tool: the loops only need one iteration to complete
cat > "$WORK/bin/tool" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$WORK/bin/tool"

run_loop() {
  local script="$1"
  shift
  set +e
  env -u REQUIRE_NATIVE -u REQUIRE_INSTRUMENTED -u LIBFUZZER_DRIVER -u AFLPP_CONTAINER_TOOL \
    -u RUNS_ROOT -u AFLPP_RUN_SUMMARY_ROOT -u AFLPP_MAX_RUN_DIRS_KEEP -u TOOL_AFLPP_CMD \
    -u TOOL_LIBFUZZER_CMD -u WORKERS -u TIMEOUT_SEC -u RESTART_LIMIT \
    PROJECT_ROOT="$WORK" \
    TARGET=onnx \
    TOOL_BIN="$WORK/bin/tool" \
    CORPUS_DIR="$WORK/seeds/onnx" \
    FUZZ_LOOP_MAX_ITERATIONS=1 \
    ITERATION_SLEEP_SEC=0 \
    "$@" \
    bash "$PROJECT_ROOT/ops/scripts/$script" >"$WORK/out.log" 2>&1
  LOOP_EXIT=$?
  set -e
  LOOP_OUT="$(cat "$WORK/out.log")"
}

assert_contains() {
  case "$LOOP_OUT" in
    *"$1"*) ;;
    *) fail "expected output to contain '$1'; got:\n$LOOP_OUT" ;;
  esac
}

assert_not_contains() {
  case "$LOOP_OUT" in
    *"$1"*) fail "expected output NOT to contain '$1'; got:\n$LOOP_OUT" ;;
    *) ;;
  esac
}

# The Environment= lines a shipped systemd unit hands the loop, as VAR=VALUE arguments.
unit_env() {
  sed -n 's/^Environment=//p' "$1"
}

# --- instrumentation_scope (B1) -------------------------------------------------
# G2 again, one level deeper. has_afl_instrumentation() answers "does this binary
# carry the forkserver", which is NOT "is the parser instrumented": a driver that is
# instrumented but reaches its parser through a separate .so gives driver-level
# coverage only. That is exactly what the ONNX arm was labelled "instrumented" for.
# The fixtures are real ELF binaries with the AFL marker appended, because the
# decision turns on DEFINED symbols and a shell script has none.
. "$PROJECT_ROOT/scripts/lib/engine_mode.sh"

log "safetensors: AFL++ build route must be present"
SAFETENSORS_AFLPP_BUILD="$PROJECT_ROOT/scripts/build_aflpp_safetensors_native.sh"
[ -x "$SAFETENSORS_AFLPP_BUILD" ] \
  || fail "missing executable safetensors AFL++ build script: $SAFETENSORS_AFLPP_BUILD"
grep -q 'cargo.*afl' "$SAFETENSORS_AFLPP_BUILD" \
  || fail "safetensors AFL++ build script does not use cargo-afl: $SAFETENSORS_AFLPP_BUILD"

afl_marked_copy() {
  # afl_marked_copy <src> <dst>: a real binary that also looks AFL-instrumented.
  cp "$1" "$2"
  printf '__AFL_SHM_ID __afl_area_ptr' >>"$2"
  chmod +x "$2"
}

SCOPE_CC="${SCOPE_CC:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin/clang}"
[ -x "$SCOPE_CC" ] || SCOPE_CC="$(command -v cc || command -v gcc || command -v clang || true)"
SCOPE_CXX="${SCOPE_CXX:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin/clang++}"
[ -x "$SCOPE_CXX" ] || SCOPE_CXX="$(command -v c++ || command -v g++ || command -v clang++ || true)"

# build_scope_fixture <dst> <with_parser_symbol:0|1>
# A real ELF that carries the AFL marker and either does or does not DEFINE a parser
# symbol. Built here rather than copied from harnesses/, which is gitignored: borrowing
# it made every case below vanish on a fresh clone.
build_scope_fixture() {
  local dst="$1" with_parser="$2" src="$WORK/fixture_${2}.c"
  [ -n "$SCOPE_CC" ] && [ -x "$SCOPE_CC" ] || return 1
  {
    printf 'long fixture_pad_a = 1;\nlong fixture_pad_b = 2;\n'
    [ "$with_parser" = "1" ] && printf 'void gguf_init_from_file_impl(void) { }\n'
    printf 'int main(void) { return 0; }\n'
  } > "$src"
  "$SCOPE_CC" -O0 "$src" -o "$dst" 2>/dev/null || return 1
  printf '__AFL_SHM_ID __afl_area_ptr' >>"$dst"
  chmod +x "$dst"
}

# Rust names are demangled as `safetensors::...`, so use a C++ namespace fixture to
# exercise the same symbol-shape without relying on the gitignored Rust build artifact.
build_safetensors_scope_fixture() {
  local dst="$1" src="$WORK/safetensors_fixture.cpp"
  [ -n "$SCOPE_CXX" ] && [ -x "$SCOPE_CXX" ] || return 1
  {
    printf 'namespace safetensors { void parser_symbol() {} }\n'
    printf 'int main() { safetensors::parser_symbol(); return 0; }\n'
  } > "$src"
  "$SCOPE_CXX" -O0 "$src" -o "$dst" 2>/dev/null || return 1
  printf '__AFL_SHM_ID __afl_area_ptr' >>"$dst"
  chmod +x "$dst"
}

# has_afl_instrumentation() decides whether the AFL++ arm runs instrumented or
# black-box, and its nm branch matches symbols (__afl_prev_loc, __afl_shm, __afl_fuzz)
# that the raw-bytes fallback below it does NOT list. All three callers run under
# `set -o pipefail`, so if that branch loses its answer to a SIGPIPE the whole arm
# silently drops to blackbox_n - G2 again. This fixture is a real binary carrying only
# __afl_prev_loc, padded so nm's output is far larger than a pipe buffer.
SCOPE_CC="${SCOPE_CC:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin/clang}"
[ -x "$SCOPE_CC" ] || SCOPE_CC="$(command -v cc || command -v gcc || command -v clang || true)"
if [ -n "$SCOPE_CC" ] && [ -x "$SCOPE_CC" ]; then
  log "has_afl_instrumentation: a large symbol table must not lose the answer to SIGPIPE"
  {
    printf 'void *__afl_prev_loc;\n'
    awk 'BEGIN { for (i = 0; i < 4000; i++) printf "long pad_symbol_%d = %d;\n", i, i }'
    printf 'int main(void) { return 0; }\n'
  } > "$WORK/afl_symbols.c"
  if "$SCOPE_CC" -O0 "$WORK/afl_symbols.c" -o "$WORK/harnesses/aflpp/big_symtab" 2>/dev/null; then
    # The fallback list must NOT cover this binary, or the case proves nothing.
    if grep -qaE '__AFL_SHM_ID|__AFL_SHM_FUZZ_ID|__afl_area_initial|__afl_area_ptr' \
        "$WORK/harnesses/aflpp/big_symtab"; then
      fail "fixture is covered by the raw-bytes fallback; it cannot exercise the nm branch"
    fi
    has_afl_instrumentation "$WORK/harnesses/aflpp/big_symtab" \
      || fail "has_afl_instrumentation lost __afl_prev_loc on a large symbol table"
  else
    log "skip SIGPIPE case: $SCOPE_CC could not build the fixture"
  fi
else
  log "skip SIGPIPE case: no C compiler available"
fi

log "instrumentation_scope: a binary without the forkserver is none"
cp /bin/true "$WORK/harnesses/aflpp/plain_bin"
scope="$(instrumentation_scope "$WORK/harnesses/aflpp/plain_bin")"
[ "$scope" = "none" ] || fail "expected none, got '$scope'"

# /bin/true is stripped, so it would answer driver_only even if the logic were broken.
# The compiled fixture HAS symbols and simply does not define the parser: that makes the
# case pass for the reason it claims.
log "instrumentation_scope: a driver whose parser is not linked in is driver_only"
if build_scope_fixture "$WORK/harnesses/aflpp/dyn_replay" 0; then
  [ "$(nm --defined-only "$WORK/harnesses/aflpp/dyn_replay" 2>/dev/null | wc -l)" -gt 0 ] \
    || fail "the driver_only fixture has no symbols; it cannot exercise the logic"
  scope="$(instrumentation_scope "$WORK/harnesses/aflpp/dyn_replay")"
  [ "$scope" = "driver_only" ] || fail "expected driver_only, got '$scope'"
else
  note_skip "instrumentation_scope driver_only case (no C compiler at ${SCOPE_CC:-<none>})"
fi

log "instrumentation_scope: a missing binary is none, not a crash"
scope="$(instrumentation_scope "$WORK/harnesses/aflpp/does-not-exist")"
[ "$scope" = "none" ] || fail "expected none for a missing binary, got '$scope'"

# The gguf harness links ggml statically (BUILD_SHARED_LIBS=OFF), so the parser really
# is inside the binary - that is what makes library-wide scope claimable for gguf and
# not for onnx.
GGUF_REPLAY="$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_replay"
log "instrumentation_scope: a statically linked parser is library scope"
if build_scope_fixture "$WORK/harnesses/aflpp/static_replay" 1; then
  scope="$(instrumentation_scope "$WORK/harnesses/aflpp/static_replay")"
  [ "$scope" = "library" ] || fail "expected library, got '$scope'"
elif [ -x "$GGUF_REPLAY" ]; then
  afl_marked_copy "$GGUF_REPLAY" "$WORK/harnesses/aflpp/static_replay"
  scope="$(instrumentation_scope "$WORK/harnesses/aflpp/static_replay")"
  [ "$scope" = "library" ] || fail "expected library, got '$scope'"
else
  note_skip "instrumentation_scope library case (no C compiler and no built gguf replay)"
fi

log "instrumentation_scope: a statically linked safetensors parser is library scope"
if build_safetensors_scope_fixture "$WORK/harnesses/aflpp/safetensors_replay"; then
  scope="$(instrumentation_scope "$WORK/harnesses/aflpp/safetensors_replay")"
  [ "$scope" = "library" ] || fail "expected library for safetensors, got '$scope'"
else
  note_skip "instrumentation_scope safetensors case (no C++ compiler at ${SCOPE_CXX:-<none>})"
fi

# The real shipped binary, when it happens to be built, is worth checking too: it is the
# one whose scope the campaign will actually claim.
if [ -x "$GGUF_REPLAY" ]; then
  log "instrumentation_scope: the shipped gguf replay is library scope once instrumented"
  afl_marked_copy "$GGUF_REPLAY" "$WORK/harnesses/aflpp/shipped_replay"
  scope="$(instrumentation_scope "$WORK/harnesses/aflpp/shipped_replay")"
  [ "$scope" = "library" ] || fail "expected library for the shipped replay, got '$scope'"
fi

# The shipped ONNX drivers must NOT claim library scope: onnxruntime is a .so.
for onnx_driver in \
  "$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer" \
  "$PROJECT_ROOT/harnesses/aflpp/onnxruntime_loader_replay"
do
  [ -x "$onnx_driver" ] || continue
  log "instrumentation_scope: $(basename "$onnx_driver") must not claim library scope"
  afl_marked_copy "$onnx_driver" "$WORK/harnesses/aflpp/onnx_scope_probe"
  scope="$(instrumentation_scope "$WORK/harnesses/aflpp/onnx_scope_probe")"
  [ "$scope" = "driver_only" ] || fail "expected driver_only for $onnx_driver, got '$scope'"
done

log "libfuzzer: missing native driver must warn and label blackbox"
cp "$WORK/bin/tool" "$WORK/harnesses/libfuzzer/tool_harness_driver"
rm -f "$WORK/harnesses/libfuzzer/onnxruntime_loader_fuzzer"
run_loop fuzz-loop-libfuzzer.sh
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer blackbox loop exited $LOOP_EXIT"
assert_contains "WARN"
assert_contains "libfuzzer_mode=blackbox"

log "libfuzzer: REQUIRE_NATIVE=1 must fail instead of falling back"
run_loop fuzz-loop-libfuzzer.sh REQUIRE_NATIVE=1
[ "$LOOP_EXIT" -ne 0 ] || fail "REQUIRE_NATIVE=1 must exit non-zero when the native driver is missing"

log "libfuzzer: present native driver must label native"
cp "$WORK/bin/tool" "$WORK/harnesses/libfuzzer/onnxruntime_loader_fuzzer"
run_loop fuzz-loop-libfuzzer.sh
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer native loop exited $LOOP_EXIT"
assert_contains "libfuzzer_mode=native"
assert_not_contains "-rss_limit_mb="
assert_not_contains "-malloc_limit_mb="

# B2: the native-driver decision was hardcoded to onnx, so a gguf run with a perfectly
# good native driver sitting right there was labelled blackbox and ran through the
# black-box tool wrapper - a campaign that looks healthy and fuzzes the wrong thing.
mkdir -p "$WORK/seeds/gguf"
printf 'GGUF' > "$WORK/seeds/gguf/seed.gguf"

log "libfuzzer: a missing native gguf driver must still warn and label blackbox"
rm -f "$WORK/harnesses/libfuzzer/gguf_loader_fuzzer"
run_loop fuzz-loop-libfuzzer.sh TARGET=gguf CORPUS_DIR="$WORK/seeds/gguf"
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer gguf blackbox loop exited $LOOP_EXIT"
assert_contains "WARN"
assert_contains "libfuzzer_mode=blackbox"
assert_contains "gguf_loader_fuzzer"

log "libfuzzer: a native gguf driver must label native, not blackbox"
cp "$WORK/bin/tool" "$WORK/harnesses/libfuzzer/gguf_loader_fuzzer"
run_loop fuzz-loop-libfuzzer.sh TARGET=gguf CORPUS_DIR="$WORK/seeds/gguf"
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer gguf native loop exited $LOOP_EXIT"
assert_contains "libfuzzer_mode=native"
assert_contains "gguf_loader_fuzzer"
# R16: the parser has attacker-controlled allocation lengths. The shared wrapper is
# the systemd/manual-loop path, so a GGUF command without both limits is unbounded even
# when the short native-engine check itself used safe flags.
assert_contains "-rss_limit_mb=2048"
assert_contains "-malloc_limit_mb=2048"
# the profile file name must follow the target, or two arms overwrite each other
assert_not_contains "onnx-native-%p.profraw"

# libFuzzer writes new units into the directory it is given. For gguf that directory
# must NOT be seeds/gguf: that is the 19-file fixture the oracle check asserts on, and
# the shipped gguf AFL++ unit reads the same path as its -i set.
log "libfuzzer: the gguf arm must not fuzz out of the seed fixture"
# CORPUS_DIR= (empty) so the loop takes its own default, which is the thing under test.
run_loop fuzz-loop-libfuzzer.sh TARGET=gguf CORPUS_DIR=
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer gguf default-corpus loop exited $LOOP_EXIT"
assert_contains "data/corpus/libfuzzer/gguf"
assert_not_contains "corpus=$WORK/seeds/gguf"
# ...and the seed fixture must still be exactly what it was.
seed_count_after="$(find "$WORK/seeds/gguf" -type f | wc -l | tr -d ' ')"
[ "$seed_count_after" = "1" ] \
  || fail "the seed fixture grew to $seed_count_after files; libFuzzer is writing into it"

# C3: without the under-cap derivative the arm must still run, and say out loud that it
# is seeding from files libFuzzer can never reproduce.
assert_contains "WARN no usable libfuzzer-sized corpus"
assert_contains "seed_fixture=$WORK/seeds/gguf"

# A derived corpus that does not cover the seed set (a half-finished build) must NOT be
# preferred: silently fuzzing a subset of the seeds is worse than fuzzing oversized ones.
log "libfuzzer: an incomplete derived corpus is refused, not silently preferred"
mkdir -p "$WORK/data/corpus/gguf-libfuzzer"
printf 'GGUFreduced' > "$WORK/data/corpus/gguf-libfuzzer/not-a-seed-name.gguf"
run_loop fuzz-loop-libfuzzer.sh TARGET=gguf CORPUS_DIR=
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer gguf partial-corpus loop exited $LOOP_EXIT"
assert_contains "WARN no usable libfuzzer-sized corpus"
assert_contains "seed_fixture=$WORK/seeds/gguf"

# The real regression: the working corpus was seeded from seeds/gguf by the runs above,
# and `cp -n` will not replace those units. Building the derived corpus afterwards has
# to evict them, or the arm keeps fuzzing exactly the files the derivative replaces
# while the log claims the derivative is in use.
log "libfuzzer: a new seed fixture evicts what the previous one left behind"
[ -f "$WORK/data/corpus/libfuzzer/gguf/seed.gguf" ] \
  || fail "precondition: the working corpus should already hold the oversized unit"
rm -f "$WORK/data/corpus/gguf-libfuzzer/not-a-seed-name.gguf"
printf 'GGUFreduced' > "$WORK/data/corpus/gguf-libfuzzer/seed.gguf"
run_loop fuzz-loop-libfuzzer.sh TARGET=gguf CORPUS_DIR=
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer gguf reduced-corpus loop exited $LOOP_EXIT"
assert_contains "seed_fixture=$WORK/data/corpus/gguf-libfuzzer"
assert_not_contains "WARN no usable libfuzzer-sized corpus"
assert_contains "evicted 1 working-corpus units"
[ "$(cat "$WORK/data/corpus/libfuzzer/gguf/seed.gguf")" = "GGUFreduced" ] \
  || fail "the working corpus still holds the unit the previous fixture put there"

# ...and a unit libFuzzer itself discovered must survive the eviction.
log "libfuzzer: eviction spares what the fuzzer produced"
printf 'DISCOVERED' > "$WORK/data/corpus/libfuzzer/gguf/found-by-libfuzzer.gguf"
printf 'GGUFreduced2' > "$WORK/data/corpus/gguf-libfuzzer/seed.gguf"
mkdir -p "$WORK/seeds/gguf"
run_loop fuzz-loop-libfuzzer.sh TARGET=gguf CORPUS_DIR=
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer gguf loop exited $LOOP_EXIT"
[ -f "$WORK/data/corpus/libfuzzer/gguf/found-by-libfuzzer.gguf" ] \
  || fail "eviction deleted a unit the fuzzer produced"


# onnx is deliberately unchanged: its arms have always shared seeds/onnx and the
# published Arm B/C numbers rest on that.
log "libfuzzer: the onnx arm keeps its historical corpus default"
run_loop fuzz-loop-libfuzzer.sh TARGET=onnx CORPUS_DIR=
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer onnx default-corpus loop exited $LOOP_EXIT"
assert_contains "corpus=$WORK/seeds/onnx"

log "libfuzzer: an unsupported target has no native driver and says so"
run_loop fuzz-loop-libfuzzer.sh TARGET=safetensors CORPUS_DIR="$WORK/seeds/gguf"
[ "$LOOP_EXIT" -eq 0 ] || fail "libfuzzer safetensors loop exited $LOOP_EXIT"
assert_contains "libfuzzer_mode=blackbox"

log "aflpp: non-instrumented replay binary must warn and label blackbox_n"
cp "$WORK/bin/tool" "$WORK/harnesses/aflpp/onnxruntime_loader_replay"
run_loop fuzz-loop-aflpp.sh
[ "$LOOP_EXIT" -eq 0 ] || fail "aflpp blackbox loop exited $LOOP_EXIT"
assert_contains "WARN"
assert_contains "aflpp_mode=blackbox_n"
assert_contains "afl-fuzz -n "
# G3: in black-box mode AFL++ only sees signals, so a library crash (tool exit 4) is
# invisible unless the exit code is declared a crash.
assert_contains "AFL_CRASH_EXITCODE=4"
assert_contains "AFL_IGNORE_SEED_PROBLEMS=1"

log "aflpp: REQUIRE_INSTRUMENTED=1 must fail instead of falling back"
run_loop fuzz-loop-aflpp.sh REQUIRE_INSTRUMENTED=1
[ "$LOOP_EXIT" -ne 0 ] || fail "REQUIRE_INSTRUMENTED=1 must exit non-zero without instrumentation"

log "aflpp: sancov-only binary is NOT AFL++ instrumentation"
{
  printf '#!/usr/bin/env bash\nexit 0\n'
  printf '# __sanitizer_cov_trace_pc_guard __sanitizer_cov_trace_cmp1\n'
} > "$WORK/harnesses/aflpp/onnxruntime_loader_replay"
chmod +x "$WORK/harnesses/aflpp/onnxruntime_loader_replay"
run_loop fuzz-loop-aflpp.sh
[ "$LOOP_EXIT" -eq 0 ] || fail "aflpp sancov-only loop exited $LOOP_EXIT"
assert_contains "aflpp_mode=blackbox_n"

log "aflpp: instrumented replay binary must label instrumented and drop -n"
{
  printf '#!/usr/bin/env bash\nexit 0\n'
  printf '# __AFL_SHM_ID __afl_area_ptr\n'
} > "$WORK/harnesses/aflpp/onnxruntime_loader_replay"
chmod +x "$WORK/harnesses/aflpp/onnxruntime_loader_replay"
run_loop fuzz-loop-aflpp.sh
[ "$LOOP_EXIT" -eq 0 ] || fail "aflpp instrumented loop exited $LOOP_EXIT"
assert_contains "aflpp_mode=instrumented"
assert_not_contains "afl-fuzz -n "

# The loop treats an operator-set AFLPP_CONTAINER_TOOL as a deliberate override and will
# not replace it with the instrumented replay. A shipped unit that sets it - even to the
# value the loop already defaults to - therefore pins the arm to blackbox_n forever.
log "aflpp: the shipped systemd unit must not disable the native path"
# shellcheck disable=SC2046
run_loop fuzz-loop-aflpp.sh $(unit_env "$PROJECT_ROOT/ops/systemd/tool-fuzz-onnx-aflpp.service")
[ "$LOOP_EXIT" -eq 0 ] || fail "aflpp systemd-env loop exited $LOOP_EXIT"
assert_contains "aflpp_mode=instrumented"
assert_not_contains "afl-fuzz -n "

# B3: the AFL++ arm resolved its native replay for onnx only, so gguf could never be
# anything but blackbox_n no matter what was built. And because the gguf harness links
# ggml statically, its instrumentation scope is library-wide - the thing ONNX cannot
# claim - so the loop must say which one it got.
log "aflpp: a gguf run without a native replay must warn and label blackbox_n"
rm -f "$WORK/harnesses/aflpp/gguf_loader_replay"
run_loop fuzz-loop-aflpp.sh TARGET=gguf CORPUS_DIR="$WORK/seeds/gguf"
[ "$LOOP_EXIT" -eq 0 ] || fail "aflpp gguf blackbox loop exited $LOOP_EXIT"
assert_contains "WARN"
assert_contains "aflpp_mode=blackbox_n"
assert_contains "gguf_loader_replay"

# The fixture is BUILT, not borrowed from the gitignored harnesses/ tree: borrowing it
# switched this whole block off on any machine that had not built the libFuzzer arm -
# including the regression test for the unit defect of 1e8261f.
GGUF_AFLPP_FIXTURE_OK=0
if build_scope_fixture "$WORK/harnesses/aflpp/gguf_loader_replay" 1; then
  GGUF_AFLPP_FIXTURE_OK=1
elif [ -x "$GGUF_REPLAY" ]; then
  afl_marked_copy "$GGUF_REPLAY" "$WORK/harnesses/aflpp/gguf_loader_replay"
  GGUF_AFLPP_FIXTURE_OK=1
fi

if [ "$GGUF_AFLPP_FIXTURE_OK" = "1" ]; then
  log "aflpp: an instrumented gguf replay must label instrumented with library scope"
  run_loop fuzz-loop-aflpp.sh TARGET=gguf CORPUS_DIR="$WORK/seeds/gguf"
  [ "$LOOP_EXIT" -eq 0 ] || fail "aflpp gguf native loop exited $LOOP_EXIT"
  assert_contains "aflpp_mode=instrumented"
  assert_contains "aflpp_instrumentation_scope=library"
  assert_not_contains "afl-fuzz -n "
  # gguf links ggml statically; dragging the onnxruntime library path into a gguf
  # command line would be a copy-paste tell that the arms were never separated.
  assert_not_contains "onnxruntime-1.23.2"

  # 1e8261f: a unit that sets AFLPP_CONTAINER_TOOL - even to the loop's own default -
  # reads as an operator override and pins the arm to blackbox_n forever.
  log "aflpp: the shipped gguf unit must not disable the native path"
  GGUF_UNIT="$PROJECT_ROOT/ops/systemd/tool-fuzz-gguf-aflpp.service"
  [ -f "$GGUF_UNIT" ] || fail "shipped gguf unit not found: $GGUF_UNIT"
  # Without this the case would pass on a unit that never selects gguf at all: the loop
  # would default to TARGET=onnx and happily report instrumented for the onnx fixture.
  unit_env "$GGUF_UNIT" | grep -qx 'TARGET=gguf' \
    || fail "$GGUF_UNIT does not set TARGET=gguf; this case would be testing the onnx arm"
  # shellcheck disable=SC2046
  run_loop fuzz-loop-aflpp.sh $(unit_env "$GGUF_UNIT")
  [ "$LOOP_EXIT" -eq 0 ] || fail "aflpp gguf systemd-env loop exited $LOOP_EXIT"
  assert_contains "target=gguf"
  assert_contains "aflpp_mode=instrumented"
  assert_not_contains "afl-fuzz -n "
else
  note_skip "gguf aflpp cases incl. the 1e8261f unit regression (no C compiler and no built gguf replay)"
fi

# scripts/run_long.sh is the path the campaign runners take (run_campaign.sh /
# run_onnx_abc_week.sh), so it must make the same decision as the systemd loops.
ln -s "$PROJECT_ROOT/scripts" "$WORK/scripts"
log "run_long: non-instrumented aflpp driver must warn and label blackbox_n"
cp "$WORK/bin/tool" "$WORK/harnesses/aflpp/onnxruntime_loader_replay"
set +e
LOOP_OUT="$(env -u REQUIRE_NATIVE -u REQUIRE_INSTRUMENTED -u TOOL_AFLPP_CMD \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target onnx --backend aflpp \
    --duration-seconds 1 --tag engine-mode-check --corpus-dir "$WORK/seeds/onnx" 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -eq 0 ] || fail "run_long aflpp exited $LOOP_EXIT: $LOOP_OUT"
assert_contains "WARN"
assert_contains "aflpp_mode=blackbox_n"
assert_contains "AFL_CRASH_EXITCODE=4"
# a corpus that already contains a crashing seed must not abort the whole afl-fuzz run
assert_contains "AFL_IGNORE_SEED_PROBLEMS=1"

log "run_long: REQUIRE_INSTRUMENTED=1 must fail instead of falling back"
set +e
LOOP_OUT="$(env -u TOOL_AFLPP_CMD REQUIRE_INSTRUMENTED=1 \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target onnx --backend aflpp \
    --duration-seconds 1 --tag engine-mode-check --corpus-dir "$WORK/seeds/onnx" 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -ne 0 ] || fail "run_long REQUIRE_INSTRUMENTED=1 must exit non-zero: $LOOP_OUT"

# run_long is the campaign path; it must resolve the gguf driver exactly as the systemd
# loop does, or a campaign and its unit fuzz different things under the same label.
# run_long is the campaign path for the AFL++ arm too, and a74314d changed it as well.
# (This lives here, not with the loop cases above, because run_long needs $WORK/scripts.)
if [ "$GGUF_AFLPP_FIXTURE_OK" = "1" ]; then
  log "run_long: an instrumented gguf aflpp replay must label instrumented with library scope"
  set +e
  LOOP_OUT="$(env -u REQUIRE_INSTRUMENTED -u TOOL_AFLPP_CMD \
    WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
    bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend aflpp \
      --duration-seconds 1 --tag engine-mode-check --corpus-dir "$WORK/seeds/gguf" 2>&1)"
  LOOP_EXIT=$?
  set -e
  [ "$LOOP_EXIT" -eq 0 ] || fail "run_long gguf aflpp exited $LOOP_EXIT: $LOOP_OUT"
  assert_contains "aflpp_mode=instrumented"
  assert_contains "aflpp_instrumentation_scope=library"
  assert_contains "harnesses/aflpp/gguf_loader_replay"
  assert_not_contains "onnxruntime-1.23.2"
fi

log "run_long: a native gguf driver must label native"
cp "$WORK/bin/tool" "$WORK/harnesses/libfuzzer/gguf_loader_fuzzer"
set +e
LOOP_OUT="$(env -u REQUIRE_NATIVE -u TOOL_LIBFUZZER_CMD \
  LIBFUZZER_DRIVER="$WORK/harnesses/libfuzzer/gguf_loader_fuzzer" \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend libfuzzer \
    --duration-seconds 1 --tag engine-mode-check --corpus-dir "$WORK/seeds/gguf" 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -eq 0 ] || fail "run_long gguf libfuzzer exited $LOOP_EXIT: $LOOP_OUT"
assert_contains "libfuzzer_mode=native"
assert_contains "gguf-native-%p.profraw"
assert_contains "-rss_limit_mb=2048"
assert_contains "-malloc_limit_mb=2048"

# A caller-provided template bypasses run_long's generated command. That escape hatch
# must fail closed for GGUF unless it carries both positive limits, or a stale shell
# environment can silently turn an otherwise safe campaign back into an OOM campaign.
log "run_long: a custom gguf libfuzzer command without memory limits must fail"
set +e
LOOP_OUT="$(env -u REQUIRE_NATIVE TOOL_LIBFUZZER_CMD='true {corpus_dir}' \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend libfuzzer \
    --duration-seconds 1 --tag engine-mode-check --corpus-dir "$WORK/seeds/gguf" 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -ne 0 ] || fail "run_long accepted an unbounded custom gguf libfuzzer command: $LOOP_OUT"
assert_contains "requires positive -rss_limit_mb and -malloc_limit_mb"

log "run_long: a later zero must not override an earlier positive gguf limit"
set +e
LOOP_OUT="$(env -u REQUIRE_NATIVE \
  TOOL_LIBFUZZER_CMD='true -rss_limit_mb=2048 -rss_limit_mb=0 -malloc_limit_mb=2048 {corpus_dir}' \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend libfuzzer \
    --duration-seconds 1 --tag engine-mode-check --corpus-dir "$WORK/seeds/gguf" 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -ne 0 ] || fail "run_long accepted duplicate gguf limits with an effective zero: $LOOP_OUT"
assert_contains "requires positive -rss_limit_mb and -malloc_limit_mb"

log "run_long: a custom gguf libfuzzer command with both memory limits may run"
set +e
LOOP_OUT="$(env -u REQUIRE_NATIVE \
  TOOL_LIBFUZZER_CMD='true -rss_limit_mb=2048 -malloc_limit_mb=2048 {corpus_dir}' \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend libfuzzer \
    --duration-seconds 1 --tag engine-mode-check --corpus-dir "$WORK/seeds/gguf" 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -eq 0 ] || fail "run_long refused a bounded custom gguf libfuzzer command: $LOOP_OUT"

log "run_long: LIBFUZZER_DRIVER override must match the selected target before native label"
cp "$WORK/bin/tool" "$WORK/harnesses/libfuzzer/onnxruntime_loader_fuzzer"
set +e
LOOP_OUT="$(env -u TOOL_LIBFUZZER_CMD REQUIRE_NATIVE=1 \
  LIBFUZZER_DRIVER="$WORK/harnesses/libfuzzer/onnxruntime_loader_fuzzer" \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend libfuzzer \
    --duration-seconds 1 --tag engine-mode-check --corpus-dir "$WORK/seeds/gguf" 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -ne 0 ] || fail "run_long accepted an onnx LIBFUZZER_DRIVER override as native for gguf: $LOOP_OUT"
assert_contains "does not match target gguf"
assert_not_contains "libfuzzer_mode=native"

# C3: run_long.sh is the entry point the runbook prescribes for a gguf libFuzzer
# campaign - there is no gguf libFuzzer systemd unit - so it must choose the same seed
# fixture the loop does. Neither case passes --corpus-dir: the default IS the thing
# under test.
log "run_long: a gguf libfuzzer run defaults to the libfuzzer-sized corpus"
set +e
LOOP_OUT="$(env -u REQUIRE_NATIVE -u REQUIRE_INSTRUMENTED -u TOOL_LIBFUZZER_CMD \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend libfuzzer \
    --duration-seconds 1 --tag engine-mode-check 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -eq 0 ] || fail "run_long gguf libfuzzer exited $LOOP_EXIT: $LOOP_OUT"
assert_contains "corpus=$WORK/data/corpus/gguf-libfuzzer"

# ...and the AFL++ arm deliberately keeps the full-size originals: AFL++ has no input
# length cap, and switching it would silently change what the two arms compare.
log "run_long: the gguf aflpp arm keeps the full-size seed fixture"
set +e
LOOP_OUT="$(env -u REQUIRE_NATIVE -u REQUIRE_INSTRUMENTED -u TOOL_AFLPP_CMD \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend aflpp \
    --duration-seconds 1 --tag engine-mode-check 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -eq 0 ] || fail "run_long gguf aflpp exited $LOOP_EXIT: $LOOP_OUT"
# the aflpp branch keeps run_long's own relative default, unchanged by C3
assert_contains "corpus=seeds/gguf"
assert_not_contains "corpus=$WORK/data/corpus/gguf-libfuzzer"

log "run_long: missing native libfuzzer driver must warn and label blackbox"
rm -f "$WORK/harnesses/libfuzzer/onnxruntime_loader_fuzzer"
set +e
LOOP_OUT="$(env -u REQUIRE_NATIVE -u TOOL_LIBFUZZER_CMD \
  WORKDIR="$WORK" DATA_DIR="$WORK/data" TOOL_BIN="$WORK/bin/tool" LOOP_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target onnx --backend libfuzzer \
    --duration-seconds 1 --tag engine-mode-check --corpus-dir "$WORK/seeds/onnx" 2>&1)"
LOOP_EXIT=$?
set -e
[ "$LOOP_EXIT" -eq 0 ] || fail "run_long libfuzzer exited $LOOP_EXIT: $LOOP_OUT"
assert_contains "WARN"
assert_contains "libfuzzer_mode=blackbox"

if [ -n "$SKIPPED" ]; then
  echo "[engine-mode-check] these cases did NOT run:" >&2
  printf '%s\n' "$SKIPPED" | tr '|' '\n' | sed '/^$/d;s/^/  - /' >&2
  if [ "${ALLOW_SKIPPED_CASES:-0}" != "1" ]; then
    fail "some cases were skipped; set ALLOW_SKIPPED_CASES=1 only if you accept an unverified run"
  fi
  echo "[engine-mode-check] WARN: continuing with skipped cases (ALLOW_SKIPPED_CASES=1)" >&2
fi
log "done: engine mode labels verified"
