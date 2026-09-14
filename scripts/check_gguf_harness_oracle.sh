#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
REPLAY="${REPLAY:-$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_replay}"
FUZZER="${FUZZER:-$PROJECT_ROOT/harnesses/libfuzzer/gguf_loader_fuzzer}"
LEGACY_PROBE="${LEGACY_PROBE:-$PROJECT_ROOT/tools/llama.cpp/build/bin/llama-gguf-hash}"
SEED_ROOT="${SEED_ROOT:-$PROJECT_ROOT/seeds}"
SEED_DIR="$SEED_ROOT/gguf"
MALFORMED_DIR="$SEED_ROOT/gguf-malformed"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/data/native-engine-checks/gguf}"
REQUIRE_NATIVE=0

usage() {
  cat <<'EOF'
usage: check_gguf_harness_oracle.sh [--require-native]

Proves the native GGUF replay harness answers the parser honestly:

  well-formed seeds                 -> exit 0
  files the parser rejects          -> exit 9   (NOT a crash)
  files that trip a GGML_ASSERT     -> death by signal (SIGABRT = 134)

The reject cases are the point: llama-gguf-hash dereferences the NULL that
gguf_init_from_file returns, so it dies with SIGSEGV on files the parser
deliberately turned down. This check records that contrast.

Without --require-native, a missing replay binary is a skip (exit 0) so the
check can sit in an offline suite. With it, the missing binary is a failure.

Environment:
  PROJECT_ROOT   (default: cwd)
  REPLAY         native standalone replay binary
  LEGACY_PROBE   llama-gguf-hash, for the contrast assertion (optional)
  SEED_DIR / MALFORMED_DIR / OUT_DIR
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-native) REQUIRE_NATIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[gguf-oracle] unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

log() {
  echo "[gguf-oracle] $*"
}

fail() {
  echo "[gguf-oracle] fail: $*" >&2
  exit 1
}

FAILURES=0

check() {
  # check <label> <expected> <actual>
  local label="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    log "OK   $label rc=$actual"
  else
    log "FAIL $label expected rc=$expected actual rc=$actual"
    FAILURES=$((FAILURES + 1))
  fi
}

rc_of() {
  # runs a command, echoes its exit status; 128+N when killed by signal N
  local rc=0
  "$@" >>"$RUN_LOG" 2>&1 || rc=$?
  echo "$rc"
}

if [[ ! -x "$REPLAY" ]]; then
  msg="native replay binary not found: $REPLAY"
  if [[ "$REQUIRE_NATIVE" -eq 1 ]]; then
    fail "$msg"
  fi
  log "skip: $msg (build it with scripts/build_libfuzzer_gguf_native.sh)"
  exit 0
fi

mkdir -p "$OUT_DIR"
RUN_LOG="$OUT_DIR/oracle-runs.log"
: >"$RUN_LOG"

log "regenerating the malformed seeds"
SEED_ROOT="$SEED_ROOT" bash "$PROJECT_ROOT/scripts/gen_gguf_malformed_seeds.sh" >>"$RUN_LOG" 2>&1 \
  || fail "seed generator failed; see $RUN_LOG"

log "replay selftest"
check "selftest" 0 "$(rc_of "$REPLAY" --selftest)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# A header the parser reads cleanly and then turns down: version 99 is not a
# GGUF version it supports. 24 bytes = magic + version + n_tensors + n_kv.
python3 - "$tmp_dir/badversion.gguf" <<'PY'
import struct
import sys

with open(sys.argv[1], "wb") as fh:
    fh.write(b"GGUF" + struct.pack("<IQQ", 99, 0, 0))
PY
: >"$tmp_dir/empty.gguf"

log "rejected inputs must be exit 9, never a crash"
check "reject: version 99 header" 9 "$(rc_of "$REPLAY" "$tmp_dir/badversion.gguf")"
check "reject: empty file"        9 "$(rc_of "$REPLAY" "$tmp_dir/empty.gguf")"
check "reject: missing path"      9 "$(rc_of "$REPLAY" "$tmp_dir/does-not-exist.gguf")"
check "reject: no argument"       9 "$(rc_of "$REPLAY")"

# The binary has to be the sanitized, clamped one. --selftest reports what it was
# compiled with; the two oversized-length cases below prove the clamp by behaviour,
# because a compile-time flag would still say "applied" for a tree the patch missed.
log "the replay under test must be the ASan build"
selftest_out="$("$REPLAY" --selftest 2>&1 || true)"
grep -q 'asan=on' <<<"$selftest_out" || fail "replay is not an ASan build: $selftest_out"
grep -q 'clamp_patch=applied' <<<"$selftest_out" || fail "replay reports no clamp patch"

log "an oversized length field is a rejection, not a sanitizer abort (clamp patch)"
# key_len = 0x0000FFFFFFFFFFFF: unclamped this is an ASan allocation-size-too-big
# abort, i.e. a crash attributed to a target that did nothing wrong.
python3 - "$tmp_dir/hugekey.gguf" <<'SEEDPY'
import struct
import sys

with open(sys.argv[1], "wb") as fh:
    fh.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + struct.pack("<Q", 0x0000FFFFFFFFFFFF))
SEEDPY
check "reject: oversized key length" 9 "$(rc_of "$REPLAY" "$tmp_dir/hugekey.gguf")"

# One tensor claiming 0x100000000000 elements in a 57-byte file. At the no_alloc
# depths upstream accepts it (the blob is never read) so the harness must agree; at
# full depth upstream would fail the blob read, so a rejection is the faithful answer
# and the multi-terabyte allocation must never happen.
python3 - "$tmp_dir/hugetensor.gguf" <<'SEEDPY'
import struct
import sys

header = b"GGUF" + struct.pack("<IQQ", 3, 1, 0)
tensor = (
    struct.pack("<Q", 1)
    + b"t"
    + struct.pack("<I", 1)
    + struct.pack("<q", 0x100000000000)
    + struct.pack("<I", 0)
    + struct.pack("<Q", 0)
)
with open(sys.argv[1], "wb") as fh:
    fh.write(header + tensor)
SEEDPY
check "oversized tensor blob (depth=metadata)"     0 "$(GGUF_FUZZ_DEPTH=metadata    rc_of "$REPLAY" "$tmp_dir/hugetensor.gguf")"
check "oversized tensor blob (depth=tensor-info)"  0 "$(GGUF_FUZZ_DEPTH=tensor-info rc_of "$REPLAY" "$tmp_dir/hugetensor.gguf")"
check "reject: oversized tensor blob (depth=full)" 9 "$(GGUF_FUZZ_DEPTH=full        rc_of "$REPLAY" "$tmp_dir/hugetensor.gguf")"

# __asan_default_options() is only a default: an ASAN_OPTIONS in the environment
# overrides it, and a disabled abort turns every memory finding into a quiet exit 1.
log "an environment that would discard findings must stop the harness (exit 10)"
for opts in "abort_on_error=0" "abort_on_error=false" "detect_leaks=0:abort_on_error=0"; do
  check "guard: ASAN_OPTIONS=$opts" 10 "$(ASAN_OPTIONS="$opts" rc_of "$REPLAY" "$SEED_DIR/align_ok.gguf")"
done

log "an unrecognised depth must fail loudly, not fall back to the default"
check "guard: GGUF_FUZZ_DEPTH=tensorinfo" 10 "$(GGUF_FUZZ_DEPTH=tensorinfo rc_of "$REPLAY" "$SEED_DIR/align_ok.gguf")"

# The line numbers matter as much as the exit status: an upstream report is written
# from this evidence. The clamp patch inserts code above two of these asserts, and its
# #line directives put the numbering back, so what we print must be the line the
# upstream file actually has (verified against tools/llama.cpp: 183, 864, 132).
log "assert-tripping inputs must really die (SIGABRT = 134) at the upstream line"
for poc in align_wrongtype:183 align_array2:864 emptykey:132; do
  name="${poc%%:*}"
  upstream_line="${poc##*:}"
  path="$MALFORMED_DIR/$name.gguf"
  [[ -f "$path" ]] || fail "malformed seed missing: $path"
  err="$tmp_dir/$name.err"
  rc=0
  "$REPLAY" "$path" >>"$RUN_LOG" 2>"$err" || rc=$?
  cat "$err" >>"$RUN_LOG"
  check "crash: $name" 134 "$rc"
  if grep -q "gguf\.cpp:$upstream_line" "$err"; then
    log "OK   crash: $name cites the upstream line gguf.cpp:$upstream_line"
  else
    log "FAIL crash: $name must cite gguf.cpp:$upstream_line, said: $(head -1 "$err")"
    FAILURES=$((FAILURES + 1))
  fi
done

# The fuzzer stages each input in a memfd and hands ggml /proc/self/fd/N. ggml
# reports "could not open" as the same NULL it reports for "rejected", so a process
# that cannot open its own staged path would run at full speed reporting clean execs
# forever. Starving it of file descriptors is the cheapest way to force that state.
if [[ -x "$FUZZER" ]]; then
  log "a fuzzer that cannot open its own staged input must not report clean execs"
  # The input has to be one the target processes CLEANLY when it is not starved. This ran
  # on $MALFORMED_DIR/align_wrongtype.gguf, which is one of the three seeds this same
  # script asserts must die by SIGABRT: it aborted whether or not the staged path was
  # openable, so "rc is non-zero" was already true before ulimit was applied. Measured
  # 2026-09-14 with the real target: rc=77 unstarved, rc=77 at `ulimit -n 4`, rc=77 at
  # `ulimit -n 8`. On a well-formed seed the same three conditions give 0, 77, 0 - the
  # difference this case is supposed to observe. R43.
  shopt -s nullglob
  starve_seeds=("$SEED_DIR"/*.gguf)
  shopt -u nullglob
  if [[ "${#starve_seeds[@]}" -eq 0 ]]; then
    log "FAIL fd-starvation check: no well-formed seed under $SEED_DIR to starve on"
    FAILURES=$((FAILURES + 1))
  else
    starve_seed="${starve_seeds[0]}"
    baseline_rc=0
    "$FUZZER" -runs=1 "$starve_seed" >>"$RUN_LOG" 2>&1 || baseline_rc=$?
    starved_err="$tmp_dir/fd-starved.err"
    starved_rc=0
    bash -c "ulimit -n 4; exec '$FUZZER' -runs=1 '$starve_seed'" >"$starved_err" 2>&1 \
      || starved_rc=$?
    cat "$starved_err" >>"$RUN_LOG"
    # Non-zero is not enough either: a death from an unrelated cause is not evidence that
    # the staging probe fired. gguf_loader_fuzzer.cc:396-438 prints one of these three
    # before it abort()s, and that line is what says the harness noticed.
    if [[ "$baseline_rc" -ne 0 ]]; then
      log "FAIL fd-starved $(basename "$starve_seed") is not clean unstarved (rc=$baseline_rc); the starved verdict would prove nothing"
      FAILURES=$((FAILURES + 1))
    elif [[ "$starved_rc" -eq 0 ]]; then
      log "FAIL fd-starved fuzzer called an input it could not open a clean exec"
      FAILURES=$((FAILURES + 1))
    elif ! grep -qE 'gguf-harness: (staged input .* is not openable|memfd_create failed|short write staging)' "$starved_err"; then
      log "FAIL fd-starved fuzzer died (rc=$starved_rc) without reporting a staging failure; see $RUN_LOG"
      FAILURES=$((FAILURES + 1))
    else
      log "OK   fd-starved fuzzer refuses to run what it cannot open (clean rc=$baseline_rc, starved rc=$starved_rc)"
    fi
  fi
else
  log "skip fd-starvation check: no libFuzzer target at $FUZZER"
fi

log "well-formed seeds must pass at every depth"
shopt -s nullglob
seeds=("$SEED_DIR"/*.gguf)
shopt -u nullglob
[[ "${#seeds[@]}" -gt 0 ]] || fail "no seeds under $SEED_DIR"
for depth in metadata tensor-info full; do
  clean=0
  for seed in "${seeds[@]}"; do
    rc="$(GGUF_FUZZ_DEPTH="$depth" rc_of "$REPLAY" "$seed")"
    if [[ "$rc" != "0" ]]; then
      log "FAIL seed $depth $(basename "$seed") rc=$rc"
      FAILURES=$((FAILURES + 1))
    else
      clean=$((clean + 1))
    fi
  done
  log "OK   seeds depth=$depth clean=$clean/${#seeds[@]}"
done

# The contrast that justifies this harness: the same rejected file kills the
# probe we are replacing, because it dereferences the parser's NULL.
if [[ -x "$LEGACY_PROBE" ]]; then
  legacy_rc="$(GGML_NO_BACKTRACE=1 rc_of "$LEGACY_PROBE" --sha256 "$tmp_dir/badversion.gguf")"
  check "contrast: legacy probe segfaults on the rejected file" 139 "$legacy_rc"
else
  log "skip contrast: legacy probe not built at $LEGACY_PROBE"
fi

# prepare-target has to produce the same thing the harness links, and prove the
# parser is in it: libggml-base.a is produced even when gguf.cpp drops out of the
# target, so checking that the file exists checks nothing.
log "prepared target must build the archive the harness links, and prove gguf.cpp is in it"
# Strip comments first: a string sitting in a comment satisfied these assertions
# even when the code below it had been reverted.
prepared_code="$(grep -v '^[[:space:]]*#' "$PROJECT_ROOT/scripts/build_prepared_target.sh")"
grep -q -- '--target ggml-base' <<<"$prepared_code" \
  || fail "build_prepared_target.sh does not build the ggml-base target for gguf"
grep -q 'libggml-base\.a' <<<"$prepared_code" \
  || fail "build_prepared_target.sh does not name libggml-base.a as the gguf artifact"
grep -q "grep -q 'gguf_init_from_file_impl'" <<<"$prepared_code" \
  || fail "build_prepared_target.sh does not verify the gguf symbol"

if [[ "$FAILURES" -ne 0 ]]; then
  fail "$FAILURES check(s) failed; run log: $RUN_LOG"
fi
log "done: all checks passed (run log: $RUN_LOG)"
