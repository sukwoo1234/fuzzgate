#!/usr/bin/env bash
# R43: pins that the gguf oracle's fd-starvation case tests fd starvation.
#
# check_gguf_harness_oracle.sh:197-207 (pre-fix) ran the libFuzzer target under
# `ulimit -n 4` on seeds/gguf-malformed/align_wrongtype.gguf and counted every non-zero
# exit as a pass. That seed is one of the three the same script asserts must die by
# SIGABRT: it aborts whether or not the process can open its staged input. Measured on dev
# 2026-09-14 with the real target: rc=77 unstarved, rc=77 under `ulimit -n 4`, rc=77 under
# `ulimit -n 8`. The verdict was satisfied before the starvation was applied.
#
# What the case exists to catch is specific. gguf_loader_fuzzer.cc:396-438 stages each
# input in a memfd and hands ggml /proc/self/fd/N, and gguf_init_from_file returns the
# same NULL for "could not open" as for "the parser rejected it". A process that cannot
# open its own staged path would run at full speed reporting clean execs and find
# nothing - so the harness proves the path is openable and abort()s with its own
# diagnostic when it is not. Measured on dev with a well-formed seed: rc=0 unstarved,
# rc=77 under `ulimit -n 4` with "gguf-harness: staged input /proc/self/fd/3 is not
# openable: Too many open files" on stderr, and rc=0 again at `ulimit -n 6`.
#
# So the verdict needs three things the old one had none of: a seed whose unstarved run is
# CLEAN (asserted, not assumed), a non-zero starved run, and the harness's own staging
# diagnostic in that run's output - otherwise "it died" is not "it noticed".
#
# Assertions, because none of them holds alone:
#   1. a fuzzer that dies the same way starved or not must be REPORTED, not credited. This
#      is the shape the real target had and the reason the case proved nothing.
#   2. a fuzzer that reports a clean exec when starved must still be reported - the
#      original defect the case was written for must keep being caught.
#   3. a fuzzer that dies when starved without saying why must be reported: a death from
#      an unrelated cause is not evidence the staging probe fired.
#   4. the opposite polarity - a fuzzer that runs clean unstarved and aborts with the
#      staging diagnostic when starved must PASS, so the fix does not reject everything.
#   5. the probe must reach the case at all; a run whose output has no fd-starvation
#      verdict line judges nothing.
#
# The four fuzzers are stubs, deliberately. The real target cannot be asked to fail in
# three different ways on demand, and this gate must mean the same thing on a host where
# harnesses/ was never built - which is every freshly prepared fuzzing host, since
# harnesses/ is gitignored.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
CHECKER="$PROJECT_ROOT/scripts/check_gguf_harness_oracle.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gguf-oracle-verdicts-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

DIAG='gguf-harness: staged input /proc/self/fd/3 is not openable: Too many open files'

# A replay stub that gets the checker past its two hard exits (:121-122 require an ASan
# build and the clamp patch) without being a replay. Every later verdict about the replay
# is wrong in this sandbox and is ignored: this gate reads one line of the output.
mkdir -p "$WORK/bin" "$WORK/seeds/gguf" "$WORK/out"
cat >"$WORK/bin/replay" <<'STUB'
#!/usr/bin/env bash
[[ "${1:-}" == "--selftest" ]] && { echo "asan=on clamp_patch=applied"; exit 0; }
exit 0
STUB
chmod +x "$WORK/bin/replay"

# A well-formed seed, because the fixed verdict requires the unstarved run to be clean.
# Taken from the repository's own seeds when they are there, and otherwise a 24-byte GGUF
# header - the stubs never parse it, so its only job is to exist.
if [[ -f "$PROJECT_ROOT/seeds/gguf/align_ok.gguf" ]]; then
  cp "$PROJECT_ROOT/seeds/gguf/align_ok.gguf" "$WORK/seeds/gguf/align_ok.gguf"
else
  printf 'GGUF\3\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' >"$WORK/seeds/gguf/align_ok.gguf"
fi

# fuzzer_stub <name> <starved_rc> <unstarved_rc> [diagnostic]
# The stub tells the two arms apart by call order - the checker runs the unstarved
# baseline first and the starved run second - and not by reading its own fd limit. At
# `ulimit -n 4` a shell can do almost nothing: bash saves the original descriptor to fd
# >= 10 before any redirection, which is already over the limit, and `$(ulimit -n)` needs
# a pipe. Measured 2026-09-14: a stub that tried either died with "cannot make pipe for
# command substitution" and "redirection error: cannot duplicate fd". So the starved
# branch writes its diagnostic to stdout with NO redirection (the checker is already
# capturing stdout and stderr together), and the baseline branch leaves the marker with
# `touch`, which opens exactly one descriptor and runs unstarved anyway. The marker is
# also what proves the baseline arm ran at all.
fuzzer_stub() {
  local path="$WORK/bin/$1" starved="$2" unstarved="$3" diag="${4:-}"
  cat >"$path" <<STUB
#!/usr/bin/env bash
MARK="$WORK/called-$1"
if [ -e "\$MARK.baseline" ]; then
  touch "\$MARK.starved"
  [ -n "$diag" ] && printf '%s\n' "$diag"
  exit $starved
fi
touch "\$MARK.baseline"
exit $unstarved
STUB
  chmod +x "$path"
  printf '%s' "$path"
}

ran_both_arms() { [[ -e "$WORK/called-$1.baseline" && -e "$WORK/called-$1.starved" ]]; }

# Runs the real checker against the sandbox and returns its fd-starvation verdict line.
verdict() { # verdict <fuzzer> <log>
  local fuzzer="$1" log="$2"
  env PROJECT_ROOT="$PROJECT_ROOT" REPLAY="$WORK/bin/replay" FUZZER="$fuzzer" \
      SEED_ROOT="$WORK/seeds" OUT_DIR="$WORK/out" TMPDIR="$WORK" \
      timeout 300 bash "$CHECKER" >"$log" 2>&1 || true
  grep -m1 'fd-starv' "$log" || true
}

if [[ ! -f "$CHECKER" ]]; then
  bad "$(basename "$CHECKER") is missing; nothing to pin"
else
  # 5, first: a probe that never reaches the case would make every verdict below vacuous.
  honest="$(fuzzer_stub honest 77 0 "$DIAG")"
  line="$(verdict "$honest" "$WORK/honest.log")"
  if [[ -z "$line" ]]; then
    bad "the probe never reached the fd-starvation case; every verdict below would be vacuous"
    sed -n '1,6p' "$WORK/honest.log" | sed 's/^/       /'
  else
    ok "the probe reaches the fd-starvation case"

    # The stub tells the arms apart by call order, so a checker that stopped running the
    # unstarved baseline would silently turn every verdict below into the starved branch.
    if ran_both_arms honest; then
      ok "the checker runs both arms: an unstarved baseline and then the starved run"
    else
      bad "the checker ran only one arm ($(ls "$WORK" | grep -c '^called-honest\.' || true) of 2); with one call the stubs cannot tell the arms apart and every verdict below is about the baseline branch"
    fi

    # 4. opposite polarity, judged on the same run.
    case "$line" in
      *OK*) ok "a fuzzer that runs clean unstarved and diagnoses the starved open passes ($line)" ;;
      *)    bad "the honest fuzzer was rejected; the verdict refuses everything ($line)" ;;
    esac

    # 1. the shape the real target had: dies the same way either way.
    line="$(verdict "$(fuzzer_stub always-dies 77 77)" "$WORK/always.log")"
    case "$line" in
      *FAIL*) ok "a fuzzer that dies starved or not is reported ($line)" ;;
      *)      bad "a fuzzer that dies with or without starvation was credited ($line)" ;;
    esac

    # 2. the original defect: a clean exec on an input it could not open.
    line="$(verdict "$(fuzzer_stub always-clean 0 0)" "$WORK/clean.log")"
    case "$line" in
      *FAIL*) ok "a fuzzer that calls the starved run a clean exec is reported ($line)" ;;
      *)      bad "a fuzzer that reported a clean exec while starved was credited ($line)" ;;
    esac

    # 3. died, but not of the thing being tested.
    line="$(verdict "$(fuzzer_stub undiagnosed 1 0)" "$WORK/undiag.log")"
    case "$line" in
      *FAIL*) ok "a starved death with no staging diagnostic is reported ($line)" ;;
      *)      bad "a starved death from an unrelated cause was credited as the staging probe firing ($line)" ;;
    esac
  fi
fi

printf '[gguf-oracle-verdicts] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
