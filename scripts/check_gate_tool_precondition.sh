#!/usr/bin/env bash
# R86: a gate that cannot observe anything must refuse readably, not crash and not invent
# failures.
#
# Three of this suite's gates drive the real `tool` binary and default TOOL_BIN to
# target/debug/tool, which is gitignored and therefore absent on any host that has not run
# cargo yet - a freshly prepared fuzzing host being the obvious one. Measured 2026-09-14 on
# a tree extracted with `git archive HEAD`: check_aflpp_asan_env.sh ended in a raw python
# FileNotFoundError traceback, and check_run_seed_provenance.sh reported "0/15 passed" -
# fifteen separate FAIL lines for one absent precondition. Both exit non-zero, so the suite
# rc was not the problem; what an operator reads is. A traceback looks like a broken gate
# and fifteen failures look like fifteen defects, and neither says "build the tool first".
#
# check_checker_wipe_safety.sh:101-106 already had the right shape - name what is missing,
# say the gate cannot run, exit non-zero - so this is the odd-one-out class, not a new
# contract. This gate pins that shape for every gate that takes TOOL_BIN.
#
# Assertions, because none of them holds alone:
#   1. behavioural - with TOOL_BIN pointing at a path that does not exist, each gate must
#      exit non-zero, name that path, and say it cannot run.
#   2. it must not crash - no python traceback in the output. Exit status alone does not
#      separate "refused" from "died", which is what the traceback case proves.
#   3. it must not invent failures - no per-case FAIL lines and no "N/M passed" summary.
#      One missing precondition is one refusal, not fifteen defects.
#   4. the opposite polarity - with TOOL_BIN pointing at a real executable the refusal must
#      NOT appear, so the guard cannot degrade into refusing every run.
#   5. negative controls - the verdict function must reject a stub that tracebacks, reject
#      one that prints a passed-summary, and accept one that refuses in the right shape.
#
# Writes only under its own mktemp directory. The gates it drives write their own evidence
# under TMPDIR, which is pointed into that directory.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/gate-tool-precondition-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  skip %s\n' "$*"; }

# The gates that take TOOL_BIN, discovered rather than listed: a new one must not be able to
# join the suite without this contract applying to it.
mapfile -t GATES < <(grep -l 'TOOL_BIN:-\$PROJECT_ROOT/target/debug/tool' "$PROJECT_ROOT"/scripts/check_*.sh | sort)

# refusal_verdict <rc> <output> <absent-path>
# Four words the caller decides about: died (a traceback), invented (per-case failures or a
# passed-summary), silent (non-zero but never named the missing binary), refused.
refusal_verdict() {
  local rc="$1" out="$2" absent="$3"
  if grep -q 'Traceback (most recent call last)' <<<"$out"; then printf 'died'; return; fi
  if grep -qE '^\[[a-z0-9-]+\] (FAIL|[0-9]+/[0-9]+ passed)' <<<"$out"; then printf 'invented'; return; fi
  # A gate can refuse for a DIFFERENT missing precondition before it ever reaches TOOL_BIN.
  # That is not this contract failing - the arm simply could not run - so it is reported as a
  # skip. Ending rc=0 there is its own defect (R86 proper) and is reported separately; saying
  # so here rather than scoring it would make this gate the vacuous pass it exists to forbid.
  if grep -qE '^\[[a-z0-9-]+\] skip: ' <<<"$out" && ! grep -qF "$absent" <<<"$out"; then
    printf 'preempted rc=%s' "$rc"; return
  fi
  if [[ "$rc" -eq 0 ]]; then printf 'silent rc=0'; return; fi
  if ! grep -qF "$absent" <<<"$out" || ! grep -q 'this gate cannot run' <<<"$out"; then
    printf 'silent rc=%s' "$rc"; return
  fi
  printf 'refused rc=%s' "$rc"
}

ABSENT="$WORK/no-such-tool-binary"

if [[ "${#GATES[@]}" -eq 0 ]]; then
  bad 'no gate takes TOOL_BIN; either the scan broke or the contract has no subjects'
fi

for gate in "${GATES[@]}"; do
  name="$(basename "$gate")"
  out=""; rc=0
  out="$(TMPDIR="$WORK" TOOL_BIN="$ABSENT" timeout 300 bash "$gate" 2>&1)" || rc=$?
  verdict="$(refusal_verdict "$rc" "$out" "$ABSENT")"
  case "$verdict" in
    refused*) ok "$name refuses readably when the tool binary is absent ($verdict)" ;;
    died*)    bad "$name died on an absent tool binary instead of refusing; an operator reads a traceback as a broken gate"
              grep -m1 'Error\|Traceback' <<<"$out" | sed 's/^/       /' ;;
    invented*) bad "$name turned one absent precondition into per-case failures"
              grep -m2 -E '^\[[a-z0-9-]+\] (FAIL|[0-9]+/[0-9]+ passed)' <<<"$out" | sed 's/^/       /' ;;
    preempted*)
              skip "$name refuses earlier for another missing precondition, so this contract could not be exercised ($verdict)"
              grep -m1 -E '^\[[a-z0-9-]+\] skip: ' <<<"$out" | sed 's/^/       /' ;;
    *)        bad "$name exited non-zero without naming the missing binary ($verdict)"
              tail -2 <<<"$out" | sed 's/^/       /' ;;
  esac

  # Opposite polarity. /bin/true is executable, so the guard must stay quiet; the gate is
  # free to fail afterwards for its own reasons and this arm says nothing about that.
  out2="$(TMPDIR="$WORK" TOOL_BIN=/bin/true timeout 300 bash "$gate" 2>&1)" || true
  if grep -q 'this gate cannot run' <<<"$out2"; then
    bad "$name refuses even when TOOL_BIN is executable; the guard is not about the binary"
  else
    ok "$name does not refuse when TOOL_BIN is executable"
  fi
done

# Negative controls for the verdict function itself. Without them "refused" cannot be told
# from "the scan matches anything".
printf '[stub] fail: tool binary not executable: %s\n[stub] this gate cannot run\n' "$ABSENT" >"$WORK/good.out"
printf 'Traceback (most recent call last):\n  File "x", line 1\nFileNotFoundError: %s\n' "$ABSENT" >"$WORK/died.out"
printf '[stub] FAIL case-one: []\n[stub] 0/15 passed\n' >"$WORK/invented.out"
printf '[stub] something went wrong\n' >"$WORK/silent.out"

check_control() { # check_control <label> <file> <rc> <want-prefix>
  local label="$1" got
  got="$(refusal_verdict "$3" "$(cat "$2")" "$ABSENT")"
  case "$got" in
    "$4"*) ok "negative control: $label reads as '$got'" ;;
    *)     bad "negative control: $label read as '$got', wanted $4*" ;;
  esac
}
check_control 'a readable refusal'              "$WORK/good.out"     1 refused
check_control 'a python traceback'              "$WORK/died.out"     1 died
check_control 'per-case failures'               "$WORK/invented.out" 1 invented
check_control 'a non-zero exit that says nothing' "$WORK/silent.out" 1 silent
check_control 'a refusal shape that exited 0'   "$WORK/good.out"     0 silent
printf '[stub] skip: PoC env vars not set\n' >"$WORK/preempted.out"
check_control 'an earlier precondition refusal'  "$WORK/preempted.out" 0 preempted
# and it must not swallow a real miss: a gate that names the absent binary is never preempted
printf '[stub] skip: something\n[stub] fail: tool binary not executable: %s\n[stub] this gate cannot run\n' "$ABSENT" >"$WORK/both.out"
check_control 'a refusal that also logged a skip' "$WORK/both.out"    1 refused

printf '[gate-tool-precondition] pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
