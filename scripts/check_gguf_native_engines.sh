#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
SEED_ROOT="${SEED_ROOT:-$PROJECT_ROOT/seeds}"
SEED="${SEED:-$SEED_ROOT/gguf/align_ok.gguf}"
POC="${POC:-$SEED_ROOT/gguf-malformed/align_wrongtype.gguf}"
FUZZER="${FUZZER:-$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_fuzzer}"
REPLAY="${REPLAY:-$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_replay}"
AFLPP_REPLAY="${AFLPP_REPLAY:-$PROJECT_ROOT/harnesses/aflpp/gguf_loader_replay}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/data/native-engine-checks/gguf-engines}"
REQUIRE_AFLPP=0

usage() {
  cat <<'EOF'
usage: check_gguf_native_engines.sh [--require-aflpp]

Proves both GGUF engine arms actually run the parser:
  - builds the native libFuzzer target and the standalone replay
  - RUNS the libFuzzer target on a good seed (clean) and on a known PoC (crash
    artifact). The ONNX check only builds; GGUF must run, because the libFuzzer
    entry stages input through a memfd while the replay opens a real path - two
    different code paths, so one passing says nothing about the other.
  - when AFL++ tools exist, builds the instrumented replay and requires
    afl-showmap coverage AND library-wide instrumentation scope
  - with --require-aflpp, missing AFL++ tools or driver-only scope is a failure
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-aflpp) REQUIRE_AFLPP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[gguf-engines] unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

log() {
  echo "[gguf-engines] $*"
}

fail() {
  echo "[gguf-engines] fail: $*" >&2
  exit 1
}

mkdir -p "$OUT_DIR"

# clean/crash/poc-corpus are scratch, not output: every step needs them empty, so the
# check wipes them. Hanging them off OUT_DIR pointed that wipe at a caller's directory,
# and the default OUT_DIR is data/native-engine-checks/gguf-engines - gitignored, no undo.
# check_safetensors_native_engines.sh:34-45 already holds the shape this class uses: a
# mktemp scratch dir, preserved on failure so a real finding stays inspectable. OUT_DIR
# keeps the logs and the afl-showmap map, which this check rewrites by design.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/gguf-engines-XXXXXX")"
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

log "generating the seeds this check depends on"
SEED_ROOT="$SEED_ROOT" bash "$PROJECT_ROOT/scripts/gen_gguf_malformed_seeds.sh" \
  >"$OUT_DIR/seeds.log" 2>&1 || fail "seed generator failed; see $OUT_DIR/seeds.log"
# -s, not -f: the clean-seed arm below asserts that the libFuzzer target exits 0, which
# an empty input satisfies without reaching the parser - a vacuous pass on the arm this
# check exists to prove. Matches check_onnx_native_engines.sh and ONNX-ENG-03. It buys one
# byte, not a valid model - a 1-byte junk seed is still vacuous here (R82).
[[ -f "$SEED" && -s "$SEED" ]] || fail "seed missing, empty or not a regular file: $SEED"
[[ -f "$POC"  ]] || fail "poc not found: $POC"

# Build only when the harness is missing, the shape check_safetensors_native_engines.sh
# already uses. Building unconditionally reinstalled harnesses/libfuzzer/gguf_loader_*
# on every run of the check suite: this script observes those binaries, so rewriting
# them is a side effect, and BASE-02 pins them by hash.
if [[ ! -x "$FUZZER" || ! -x "$REPLAY" ]]; then
  log "harness missing; building native libFuzzer target and standalone replay"
  bash "$PROJECT_ROOT/scripts/build_libfuzzer_gguf_native.sh" >"$OUT_DIR/libfuzzer-build.log" 2>&1 \
    || fail "native build failed; see $OUT_DIR/libfuzzer-build.log"
fi
[[ -x "$FUZZER" ]] || fail "libFuzzer target not produced: $FUZZER"
[[ -x "$REPLAY" ]] || fail "standalone replay not produced: $REPLAY"

# -rss_limit_mb / -malloc_limit_mb are not optional for gguf: the parser allocates from
# a 64-bit length field before it validates it (R16/V4), so an unbounded session dies
# on memory rather than on a finding.
LIBFUZZER_LIMITS=(-rss_limit_mb=2048 -malloc_limit_mb=2048)

log "libFuzzer target must run a good seed cleanly"
clean_dir="$WORK/clean"
rm -rf "$clean_dir"; mkdir -p "$clean_dir"
rc=0
"$FUZZER" -runs=1 "${LIBFUZZER_LIMITS[@]}" -artifact_prefix="$clean_dir/" "$SEED" \
  >"$OUT_DIR/libfuzzer-clean.log" 2>&1 || rc=$?
[[ "$rc" -eq 0 ]] || fail "libFuzzer target exited $rc on a good seed; see $OUT_DIR/libfuzzer-clean.log"
# "exit 0 and no artifacts" is also what a fuzzer that never ran the input looks like -
# the fd-starvation failure Stage A had to fix. Require proof the input was executed.
grep -q "Executed .*$(basename "$SEED")" "$OUT_DIR/libfuzzer-clean.log" \
  || fail "the libFuzzer target exited 0 without executing $SEED; see $OUT_DIR/libfuzzer-clean.log"
artifacts="$(find "$clean_dir" -type f | wc -l | tr -d ' ')"
[[ "$artifacts" -eq 0 ]] || fail "a good seed produced $artifacts crash artifact(s) in $clean_dir"
log "OK   good seed: executed, exit 0, no artifacts"

# Two separate claims, because libFuzzer treats them differently. Handed an input
# FILE it crashes but writes no artifact - the bytes are already on disk. Handed a
# corpus DIRECTORY it crashes while loading and writes crash-* , which is the path a
# campaign's artifact gate depends on.
log "libFuzzer target must die on a known PoC given as a file"
crash_dir="$WORK/crash"
rm -rf "$crash_dir"; mkdir -p "$crash_dir"
rc=0
"$FUZZER" -runs=1 "${LIBFUZZER_LIMITS[@]}" -artifact_prefix="$crash_dir/" "$POC" \
  >"$OUT_DIR/libfuzzer-crash.log" 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || fail "the PoC did not crash the libFuzzer target; see $OUT_DIR/libfuzzer-crash.log"
grep -q 'deadly signal\|ERROR: AddressSanitizer\|GGML_ASSERT' "$OUT_DIR/libfuzzer-crash.log" \
  || fail "the libFuzzer target exited $rc without reporting a crash; see $OUT_DIR/libfuzzer-crash.log"
log "OK   poc as a file: rc=$rc, crash reported"

log "libFuzzer target must write a crash artifact when the PoC is in the corpus"
corpus_dir="$WORK/poc-corpus"
rm -rf "$corpus_dir" "$crash_dir"; mkdir -p "$corpus_dir" "$crash_dir"
cp "$POC" "$corpus_dir/"
rc=0
"$FUZZER" -runs=1 "${LIBFUZZER_LIMITS[@]}" -artifact_prefix="$crash_dir/" "$corpus_dir" \
  >"$OUT_DIR/libfuzzer-corpus-crash.log" 2>&1 || rc=$?
[[ "$rc" -ne 0 ]] || fail "the PoC in a corpus did not crash the target"
artifact="$(find "$crash_dir" -type f -name 'crash-*' | head -1)"
[[ -n "$artifact" ]] || fail "the PoC crashed (rc=$rc) but wrote no artifact into $crash_dir"
# The memfd path and the real-path replay must agree about the same bytes: the fuzzer
# stages input through /proc/self/fd, the replay opens the file, and a disagreement
# would mean one of the two arms is not reproducing what the other found.
replay_rc=0
"$REPLAY" "$artifact" >"$OUT_DIR/replay-artifact.log" 2>&1 || replay_rc=$?
[[ "$replay_rc" -eq 134 ]] \
  || fail "the replay disagrees with the fuzzer about $artifact (rc=$replay_rc, expected 134)"
log "OK   poc in corpus: artifact written, replay reproduces it (134)"

# shellcheck source=lib/engine_mode.sh
. "$PROJECT_ROOT/scripts/lib/engine_mode.sh"

if command -v afl-clang-fast++ >/dev/null 2>&1 && command -v afl-showmap >/dev/null 2>&1; then
  log "build AFL++ replay with the parser instrumented"
  bash "$PROJECT_ROOT/scripts/build_aflpp_gguf_native.sh" >"$OUT_DIR/aflpp-build.log" 2>&1 \
    || fail "AFL++ build failed; see $OUT_DIR/aflpp-build.log"
  [[ -x "$AFLPP_REPLAY" ]] || fail "AFL++ replay not produced: $AFLPP_REPLAY"

  scope="$(instrumentation_scope "$AFLPP_REPLAY")"
  if [[ "$scope" != "library" ]]; then
    # driver_only here means afl-fuzz sees the harness's own edges and none of the
    # parser's - the ONNX G2 situation, which is the whole thing this arm avoids.
    fail "AFL++ replay scope is '$scope', expected 'library'"
  fi
  log "OK   instrumentation_scope=library"

  log "afl-showmap must report coverage"
  AFL_MAP="$OUT_DIR/afl-showmap.txt"
  # Remove it first and keep the exit status: `|| true` over a map file left by an
  # earlier run means a completely failed afl-showmap still counts its tuples.
  rm -f "$AFL_MAP"
  showmap_rc=0
  afl-showmap -q -o "$AFL_MAP" -- "$AFLPP_REPLAY" "$SEED" >"$OUT_DIR/afl-showmap.log" 2>&1 \
    || showmap_rc=$?
  [[ -f "$AFL_MAP" ]] \
    || fail "afl-showmap wrote no map (rc=$showmap_rc); see $OUT_DIR/afl-showmap.log"
  tuples="$(wc -l < "$AFL_MAP" | tr -d ' ')"
  [[ "$tuples" -gt 0 ]] \
    || fail "afl-showmap produced zero tuples (rc=$showmap_rc); see $OUT_DIR/afl-showmap.log"
  # A nonempty map is not proof the run was healthy: afl-showmap can write the map and
  # still fail (target fault, timeout, forkserver mismatch). Capturing showmap_rc into a
  # log line was never a gate, so the whole arm passed on a broken run. Checked last so
  # the more specific "no map" / "zero tuples" diagnostics still win when they apply.
  [[ "$showmap_rc" -eq 0 ]] \
    || fail "afl-showmap exited $showmap_rc with a $tuples-tuple map; see $OUT_DIR/afl-showmap.log"
  log "OK   afl-showmap tuples=$tuples (rc=$showmap_rc)"
else
  msg="AFL++ tools missing: afl-clang-fast++ and/or afl-showmap"
  if [[ "$REQUIRE_AFLPP" -eq 1 ]]; then
    fail "$msg"
  fi
  log "skip AFL++ proof: $msg (build inside aflplusplus/aflplusplus)"
fi

log "done: $OUT_DIR"
