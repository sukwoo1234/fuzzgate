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
#   6. structural - the subject's own text must route the binary through TOOL_BIN and must
#      not run `cargo build`. Assertion 1 can be unreachable, so text is the only witness.
#   7. coverage - the gates that drive the tool WITHOUT naming the binary are counted and
#      held against a record, so a new one cannot join the suite unnoticed.
#
# R96: assertion 1 has an escape hatch - "this gate refused earlier, for a precondition that
# is not TOOL_BIN" - and that hatch used to be granted on a skip line alone, with no
# constraint on the exit status, evaluated before the rc=0 test below it. Measured
# 2026-09-19 on a tree extracted with `git archive HEAD`:
# check_onnx_libfuzzer_crash_artifacts.sh printed one skip line and exited 0, and this gate
# took it out of the score as `preempted rc=0` - which is the "observed nothing and passed"
# shape the gate exists to forbid. The hatch now costs two things: a non-zero exit, and an
# outcome the absent path did not change (so the executable-TOOL_BIN run of assertion 4 now
# happens before the verdict, which needs it). A skip line with rc=0 gets its own verdict,
# `vacuous rc=0`, and is counted as a failure.
#
# Residual, named rather than papered over: a gate that reads TOOL_BIN, decides to skip
# because of it, and prints the same thing under an executable TOOL_BIN still gets the
# hatch. /bin/true is executable without being a working tool, so an identical outcome shows
# only that the absent path did not change the result - not that TOOL_BIN was never read.
#
# R95: discovery by one spelling is not discovery. The scan below used to match the literal
# default assignment `TOOL_BIN:-$PROJECT_ROOT/target/debug/tool`, and e2b8a82's body claimed
# from that that "a new gate cannot join the suite without the contract applying". Measured
# 2026-09-19: that spelling matched 3 of the suite's 35 gates, while
# check_onnx_crash_regressions.sh drove the very same binary by writing its path out inline,
# with no TOOL_BIN variable at all, and so was not a subject. Discovery is now by what a gate
# that drives the tool has to name - the path - which finds 5, with a floor under the count
# because without one `subjects=3 ... fail=0` still exits 0: the failure this gate exists to
# catch, happening to this gate. It is excluded from its own scan by name, since it names the
# path in the pattern itself - executable code, not prose.
#
# Assertion 6 exists because assertion 1 can be unreachable, and both ways of it were measured
# on 2026-09-19. check_onnx_libfuzzer_crash_artifacts.sh refuses over a missing PoC before it
# reaches TOOL_BIN, which this gate scores as a skip. And both ONNX gates ran
# `cargo build --offline` when the binary was missing, so there was no absent binary left to
# refuse over - the same self-build that is R92's mechanism, one gate manufacturing another
# gate's precondition until suite verdicts depend on run order. `cargo build` installs at
# target/debug/tool and never at TOOL_BIN, so under a redirected TOOL_BIN it could not even
# produce the thing it was standing in for.
#
# Assertion 7 is a counted class and deliberately not a skip: a gate started with
# `cargo run --offline --` builds and runs the tool without ever naming the binary, so no path
# scan finds it and this contract cannot reach it. check_ui_routes.sh was its one member until
# R95's second half gave it a TOOL_BIN default, so the class is now empty - measured
# 2026-09-19: subjects=5 uncovered=0. Empty is still a decision that needs recording: a bucket
# with no expected value is how the next such gate would join the suite silently, which is R95
# again, so its members are held against a record instead.
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

# code_hits <file> <pattern> - matching lines as `<lineno>:<text>`, comment lines dropped, so
# a path or a command named in a rationale header is not read as something the gate runs.
code_hits() { grep -n -- "$2" "$1" | grep -vE '^[0-9]+:[[:space:]]*#' || true; }

# The gates that drive the tool, discovered rather than listed: a new one must not be able to
# join the suite without this contract applying to it. By the path and not by the spelling of
# the TOOL_BIN default - see R95 above - and without this gate, which names the path in the
# pattern on the next line.
mapfile -t GATES < <(grep -l 'target/debug/tool' "$PROJECT_ROOT"/scripts/check_*.sh \
                       | grep -v '/check_gate_tool_precondition\.sh$' | sort)

# The gates that drive the tool without naming the binary: `cargo run` compiles and runs it,
# so the scan above cannot see them and TOOL_BIN cannot redirect them. Excluded the same two
# ways as above - this gate by name, because the pattern below is executable code in it
# (measured 2026-09-19: without that, uncovered=1 and this gate is in its own bucket), and
# comment lines everywhere, so prose about `cargo run` is not read as running it.
mapfile -t UNCOVERED < <(
  for g in "$PROJECT_ROOT"/scripts/check_*.sh; do
    [[ "$(basename "$g")" == 'check_gate_tool_precondition.sh' ]] && continue
    if [[ -n "$(code_hits "$g" 'cargo run')" ]]; then basename "$g"; fi
  done | sort
)
UNCOVERED_ON_RECORD=()

# The subject count the floor below is held to, kept next to the record above it so the
# failure message cannot drift from the test.
SUBJECTS_ON_RECORD=5

# refusal_verdict <rc> <output> <absent-path> <rc-with-executable-tool-bin> <that-output>
# Five words the caller decides about: died (a traceback), invented (per-case failures or a
# passed-summary), vacuous (observed nothing and exited 0), silent (non-zero but never named
# the missing binary), refused.
refusal_verdict() {
  local rc="$1" out="$2" absent="$3" rc2="$4" out2="$5"
  if grep -q 'Traceback (most recent call last)' <<<"$out"; then printf 'died'; return; fi
  if grep -qE '^\[[a-z0-9-]+\] (FAIL|[0-9]+/[0-9]+ passed)' <<<"$out"; then printf 'invented'; return; fi
  # A gate can refuse for a DIFFERENT missing precondition before it ever reaches TOOL_BIN.
  # That is not this contract failing - the arm simply could not run - so it is reported as a
  # skip. Two conditions buy that, because R96 measured the branch granting it on neither.
  # It must have REFUSED: a skip line with rc=0 is the vacuous pass this gate exists to
  # forbid, and scoring it as a skip would make the gate an instance of it. And the skip must
  # not be about TOOL_BIN: the run with an executable TOOL_BIN has to be indistinguishable
  # from this one. That comparison licenses only the claim that the absent path did not
  # change the outcome - /bin/true is executable without being a working tool, so it cannot
  # show TOOL_BIN went unread. A skip that appears only when the binary is absent therefore
  # falls through to 'silent', which is the correct verdict for it anyway: the gate refused
  # over the missing binary without naming it.
  if grep -qE '^\[[a-z0-9-]+\] skip: ' <<<"$out" && ! grep -qF "$absent" <<<"$out"; then
    if [[ "$rc" -eq 0 ]]; then printf 'vacuous rc=0'; return; fi
    if [[ "$rc" -eq "$rc2" && "$out" == "$out2" ]]; then printf 'preempted rc=%s' "$rc"; return; fi
  fi
  if [[ "$rc" -eq 0 ]]; then printf 'silent rc=0'; return; fi
  if ! grep -qF "$absent" <<<"$out" || ! grep -q 'this gate cannot run' <<<"$out"; then
    printf 'silent rc=%s' "$rc"; return
  fi
  printf 'refused rc=%s' "$rc"
}

# Both polarities go through here so that nothing the operator exported can decide the
# verdict: ALLOW_SKIPPED_CASES=1 downgrades a subject's refusal to a warning (R42's opt-out,
# and now check_onnx_libfuzzer_crash_artifacts.sh's too), and an exported PoC path would
# carry that subject straight past the branch under test into a native build.
run_gate() { # run_gate <gate> <tool-bin>
  env -u ALLOW_SKIPPED_CASES -u ONNX_SIGSEGV_POC -u ONNX_CRASH_POC -u ONNX_SIGFPE_POC \
    TMPDIR="$WORK" TOOL_BIN="$2" timeout 300 bash "$1" 2>&1
}

ABSENT="$WORK/no-such-tool-binary"

# A floor, not just an emptiness test: R95 was a scan that found 3 where 4 drive the tool,
# and `subjects=3 ... fail=0` exits 0. Raise it when a subject is added on purpose.
if [[ "${#GATES[@]}" -lt "$SUBJECTS_ON_RECORD" ]]; then
  bad "only ${#GATES[@]} gate(s) name the tool binary, fewer than the $SUBJECTS_ON_RECORD on record; either the scan broke or a gate stopped naming what it drives"
fi

# Assertion 7, held against a record of members and not a count, so that a swap - one gate
# leaving the class as another joins - cannot balance out. See R95 in the header for why this
# is scored and not skipped.
if [[ "${UNCOVERED[*]:-}" == "${UNCOVERED_ON_RECORD[*]:-}" ]]; then
  ok "the ${#UNCOVERED[@]} gate(s) that drive the tool without naming the binary are the ones on record (${UNCOVERED[*]:-none})"
else
  bad "the set of gates that drive the tool without naming the binary changed: found '${UNCOVERED[*]:-none}', on record '${UNCOVERED_ON_RECORD[*]:-none}'. This contract cannot reach them, so which ones exist has to be a decision someone made, not a number nobody looked at"
fi

for gate in "${GATES[@]}"; do
  name="$(basename "$gate")"
  out=""; rc=0
  out="$(run_gate "$gate" "$ABSENT")" || rc=$?

  # Opposite polarity. /bin/true is executable, so the guard must stay quiet; the gate is
  # free to fail afterwards for its own reasons and this arm says nothing about that. It runs
  # before the verdict because the verdict needs it: R96's narrowing asks whether the absent
  # path changed anything, and that question takes both runs.
  out2=""; rc2=0
  out2="$(run_gate "$gate" /bin/true)" || rc2=$?

  verdict="$(refusal_verdict "$rc" "$out" "$ABSENT" "$rc2" "$out2")"
  case "$verdict" in
    refused*) ok "$name refuses readably when the tool binary is absent ($verdict)" ;;
    died*)    bad "$name died on an absent tool binary instead of refusing; an operator reads a traceback as a broken gate"
              grep -m1 'Error\|Traceback' <<<"$out" | sed 's/^/       /' ;;
    invented*) bad "$name turned one absent precondition into per-case failures"
              grep -m2 -E '^\[[a-z0-9-]+\] (FAIL|[0-9]+/[0-9]+ passed)' <<<"$out" | sed 's/^/       /' ;;
    vacuous*) bad "$name observed nothing and exited 0; a case that did not run is not a case that passed ($verdict)"
              grep -m1 -E '^\[[a-z0-9-]+\] skip: ' <<<"$out" | sed 's/^/       /' ;;
    preempted*)
              skip "$name refuses earlier for another missing precondition, so this contract could not be exercised ($verdict)"
              grep -m1 -E '^\[[a-z0-9-]+\] skip: ' <<<"$out" | sed 's/^/       /' ;;
    *)        bad "$name did not refuse readably over the absent tool binary ($verdict)"
              tail -2 <<<"$out" | sed 's/^/       /' ;;
  esac

  # The phrase is the whole tell here, so it is reserved for refusals about TOOL_BIN itself:
  # a gate refusing over an unrelated missing precondition must word it differently or this
  # arm fires for the wrong contract (measured 2026-09-19 against an ONNX refusal worded
  # with it: pass=13 fail=1 skip=1).
  if grep -q 'this gate cannot run' <<<"$out2"; then
    bad "$name refuses even when TOOL_BIN is executable; the guard is not about the binary"
  else
    ok "$name does not refuse when TOOL_BIN is executable"
  fi

  # Assertion 6, on the text, because the two arms above can both be unreachable - see R95 in
  # the header. Every mention of the path outside the TOOL_BIN default is a use the caller
  # cannot redirect, and a missing default is no routing at all.
  stray="$(code_hits "$gate" 'target/debug/tool' | grep -v 'TOOL_BIN:-' || true)"
  if [[ -z "$stray" && -n "$(code_hits "$gate" 'TOOL_BIN:-.*target/debug/tool')" ]]; then
    ok "$name reaches the tool binary only through TOOL_BIN"
  else
    bad "$name does not route the tool binary through TOOL_BIN, so pointing TOOL_BIN elsewhere does not change what it runs"
    printf '%s\n' "${stray:-(no TOOL_BIN default)}" | head -2 | sed 's/^/       /'
  fi

  # Anchored at the start of the line, because `cargo build` also appears inside the refusal
  # message the contract asks for ("build it with `cargo build` or point TOOL_BIN at one") -
  # measured 2026-09-19: unanchored, this arm failed check_aflpp_asan_env.sh and
  # check_run_seed_provenance.sh on their own refusal text. A build tucked in after a `;` on a
  # line that starts with something else would slip past; both real ones were plain statements.
  builds="$(code_hits "$gate" '^[[:space:]]*cargo build')"
  if [[ -z "$builds" ]]; then
    ok "$name does not build the binary whose absence it has to refuse over"
  else
    bad "$name builds the tool itself, so it never has an absent binary to refuse over - and the build installs at target/debug/tool, never at TOOL_BIN"
    printf '%s\n' "$builds" | head -2 | sed 's/^/       /'
  fi
done

# Negative controls for the verdict function itself. Without them "refused" cannot be told
# from "the scan matches anything".
printf '[stub] fail: tool binary not executable: %s\n[stub] this gate cannot run\n' "$ABSENT" >"$WORK/good.out"
printf 'Traceback (most recent call last):\n  File "x", line 1\nFileNotFoundError: %s\n' "$ABSENT" >"$WORK/died.out"
printf '[stub] FAIL case-one: []\n[stub] 0/15 passed\n' >"$WORK/invented.out"
printf '[stub] something went wrong\n' >"$WORK/silent.out"

check_control() { # check_control <label> <file> <rc> <want-prefix> [executable-tool-bin file] [its rc]
  local label="$1" got
  got="$(refusal_verdict "$3" "$(cat "$2")" "$ABSENT" "${6:-$3}" "$(cat "${5:-$2}")")"
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
check_control 'an earlier precondition refusal'  "$WORK/preempted.out" 1 preempted
# R96: the same text with rc=0 is not an earlier refusal, it is a pass that observed nothing.
# Before the narrowing this exact stub read as 'preempted rc=0' and left the score.
check_control 'a skip line that exited 0'        "$WORK/preempted.out" 0 vacuous
# ... and a skip that shows up only when the binary is absent IS about the binary: the run
# with an executable TOOL_BIN gets through instead, so the hatch is refused and the gate is
# scored for refusing without naming what was missing.
printf '[stub] done: all cases ran\n' >"$WORK/tool-dependent.out"
check_control 'a skip that only appears when the tool binary is absent' \
                                                "$WORK/preempted.out" 1 silent "$WORK/tool-dependent.out" 0
# and it must not swallow a real miss: a gate that names the absent binary is never preempted
printf '[stub] skip: something\n[stub] fail: tool binary not executable: %s\n[stub] this gate cannot run\n' "$ABSENT" >"$WORK/both.out"
check_control 'a refusal that also logged a skip' "$WORK/both.out"    1 refused

# subjects= and uncovered= are on the ledger line because that line is what the runbook asks
# an operator to copy back (`tail -1`), and R95 was a subject count nobody could see.
printf '[gate-tool-precondition] pass=%d fail=%d skip=%d subjects=%d uncovered=%d\n' \
  "$PASS" "$FAIL" "$SKIP" "${#GATES[@]}" "${#UNCOVERED[@]}"
[[ "$FAIL" -eq 0 ]]
