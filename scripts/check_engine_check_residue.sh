#!/usr/bin/env bash
# R70: pins what the native engine checkers may LEAVE in a caller's OUT_DIR.
#
# check_onnx_native_engines.sh named its coverage profiles by PID
# (LLVM_PROFILE_FILE="$OUT_DIR/libfuzzer-%p.profraw"), so every run added two more and
# nothing ever removed them. Measured on dev 2026-09-13: 26 files / 1.1 GB, the oldest
# from 2026-06-12, +84 MB per run. Nothing reads them - the check asserts on its logs,
# and a repository-wide grep finds no other consumer - so the growth is pure waste, and
# stale profiles sitting next to fresh ones is how a coverage number stops meaning "this
# run". The profile variable itself is not optional: without it the instrumented harness
# drops default.profraw into the working directory.
#
# Two assertions, because either alone rots:
#   1. behavioural - run the real onnx checker twice into one OUT_DIR and require the
#      file set to be identical the second time, with no .profraw in it at all.
#   2. class scan - no check_*_native_engines.sh may point LLVM_PROFILE_FILE at a path
#      derived from OUT_DIR, so the defect cannot come back one checker at a time.
# Negative controls drive both against a fake checker that does accumulate, so a passing
# run means something.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
CHECKER_GLOB="$PROJECT_ROOT/scripts/check_"*"_native_engines.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/engine-check-residue-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  skip %s\n' "$*"; }

# --- 1. behavioural: two runs into one OUT_DIR must leave the same files ---------------
# The real checker, not a stub: it costs 0.3s per run here, and the whole point is what
# the instrumented harness writes, which a stub would have to invent.
ONNX_FUZZER="$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer"
ONNX_REPLAY="$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_replay"

if [[ -x "$ONNX_FUZZER" && -x "$ONNX_REPLAY" ]]; then
  OUT="$WORK/onnx-out"
  mkdir -p "$OUT"
  # PATH is trimmed so the AFL++ arm takes its skip branch: this gate is about residue,
  # and building the AFL++ replay would rewrite an operational binary.
  run_onnx() {
    env PATH=/usr/bin:/bin PROJECT_ROOT="$PROJECT_ROOT" OUT_DIR="$OUT" \
      timeout 300 bash "$PROJECT_ROOT/scripts/check_onnx_native_engines.sh"
  }

  if run_onnx >"$WORK/onnx-1.log" 2>&1; then
    ls -1 "$OUT" | sort >"$WORK/after-1.txt"
    if run_onnx >"$WORK/onnx-2.log" 2>&1; then
      ls -1 "$OUT" | sort >"$WORK/after-2.txt"

      if diff -q "$WORK/after-1.txt" "$WORK/after-2.txt" >/dev/null; then
        ok "onnx checker left the same file set after a second run into the same OUT_DIR"
      else
        bad "onnx checker's OUT_DIR grew on the second run"
        { diff "$WORK/after-1.txt" "$WORK/after-2.txt" || true; } | sed -n '1,6p' | sed 's/^/       /'
      fi

      strays="$(find "$OUT" -name '*.profraw' | wc -l | tr -d ' ')"
      if [[ "$strays" -eq 0 ]]; then
        ok "onnx checker wrote no .profraw into the caller's OUT_DIR"
      else
        bad "onnx checker left $strays .profraw file(s) in the caller's OUT_DIR"
      fi

      # A checker that failed early leaves a small OUT_DIR and no growth, which would read
      # as success. Require proof both harnesses actually ran. Only the libFuzzer log can
      # carry that proof in its text: replay-smoke.log is legitimately 0 bytes because the
      # replay prints nothing (measured here and in the operational directory), so an
      # emptiness test on it would fail a healthy run. What proves the replay ran is the
      # checker's own exit status - it invokes the replay under `set -e` with no `|| true`,
      # so rc=0 above already means the replay was executed and exited 0.
      if grep -q 'Executed .*\.onnx' "$OUT/libfuzzer-smoke.log" 2>/dev/null \
         && [[ -f "$OUT/replay-smoke.log" ]]; then
        ok 'onnx checker executed the seed and wrote its logs into the caller OUT_DIR'
      else
        bad 'onnx checker did not execute the seed; the residue result proves nothing'
        sed -n '1,8p' "$WORK/onnx-2.log" | sed 's/^/       /'
      fi
    else
      bad "onnx checker failed on its second run"
      sed -n '1,8p' "$WORK/onnx-2.log" | sed 's/^/       /'
    fi
  else
    bad "onnx checker failed on its first run"
    sed -n '1,8p' "$WORK/onnx-1.log" | sed 's/^/       /'
  fi
else
  skip "onnx harness not built, nothing to observe (building it here is the side effect this class avoids)"
  skip "onnx harness not built: .profraw placement unobserved"
  skip "onnx harness not built: run-reached assertion unobserved"
fi

# --- 2. class scan: no checker may aim LLVM_PROFILE_FILE at OUT_DIR --------------------
# The profile path can go through a variable, so a literal grep for OUT_DIR next to
# LLVM_PROFILE_FILE is not enough. Resolve one level of assignment and require every
# profile path to resolve to the script's own mktemp scratch. Names are never trusted,
# only the right-hand side: a checker that assigned WORK="$OUT_DIR/scratch" would pass a
# name-based skip while writing exactly where this gate exists to keep clean.
scan_checker() {
  local file="$1" line var rhs
  while IFS= read -r line; do
    for var in $(printf '%s\n' "$line" | grep -oE '\$\{?[A-Za-z_][A-Za-z0-9_]*\}?' | tr -d '${}'); do
      rhs="$(grep -m1 -E "^[[:space:]]*$var=" "$file" || true)"
      if [[ "$rhs" != *'$WORK'* && "$rhs" != *'mktemp'* ]]; then
        printf '%s' "$line"
        return 1
      fi
    done
  done < <(grep -E 'LLVM_PROFILE_FILE=' "$file")
  return 0
}

for checker in $CHECKER_GLOB; do
  [[ -f "$checker" ]] || continue
  if offender="$(scan_checker "$checker")"; then
    ok "$(basename "$checker") keeps its coverage profiles out of the caller's OUT_DIR"
  else
    bad "$(basename "$checker") writes coverage profiles into a caller path: $offender"
  fi
done

# --- 3. negative controls: both assertions must catch a checker that accumulates -------
cat >"$WORK/check_fake_native_engines.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="${OUT_DIR:-/nowhere}"
mkdir -p "$OUT_DIR"
LLVM_PROFILE_FILE="$OUT_DIR/fake-%p.profraw" true
: >"$OUT_DIR/fake-$$.profraw"
FAKE

if scan_checker "$WORK/check_fake_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a checker aiming LLVM_PROFILE_FILE at OUT_DIR'
else
  ok 'negative control: scan rejects a checker aiming LLVM_PROFILE_FILE at OUT_DIR'
fi

# The same path hidden behind the name this gate's own scratch uses.
cat >"$WORK/check_named-work_native_engines.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="${OUT_DIR:-/nowhere}"
WORK="$OUT_DIR/scratch"
LLVM_PROFILE_FILE="$WORK/cov-%p.profraw" true
FAKE

if scan_checker "$WORK/check_named-work_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a profile path held in a variable named WORK'
else
  ok 'negative control: scan rejects a profile path held in a variable named WORK'
fi

FAKE_OUT="$WORK/fake-out"
mkdir -p "$FAKE_OUT"
OUT_DIR="$FAKE_OUT" bash "$WORK/check_fake_native_engines.sh" >/dev/null 2>&1 || true
ls -1 "$FAKE_OUT" | sort >"$WORK/fake-1.txt"
OUT_DIR="$FAKE_OUT" bash "$WORK/check_fake_native_engines.sh" >/dev/null 2>&1 || true
ls -1 "$FAKE_OUT" | sort >"$WORK/fake-2.txt"
if diff -q "$WORK/fake-1.txt" "$WORK/fake-2.txt" >/dev/null; then
  bad 'negative control: the growth check did not notice an OUT_DIR that gains a file per run'
else
  ok 'negative control: the growth check notices an OUT_DIR that gains a file per run'
fi

printf '[engine-check-residue] pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
