#!/usr/bin/env bash
# R45: a check must not rebuild the operational harness binaries it is checking.
#
# check_gguf_native_engines.sh and check_onnx_native_engines.sh called their native
# build script on every run with no output override, so the build script's defaults
# (harnesses/libfuzzer/*) were rewritten each time the check suite ran. Running the
# suite is supposed to be an observation; it was silently reinstalling the artifacts
# that BASE-02 pins by hash, and it burned a full native build doing it.
# check_safetensors_native_engines.sh:59 already had the right shape - build only when
# the harness is missing - so this is the odd-one-out class, not a new contract.
#
# The assertion is behavioural and deliberately uses mtime, not just content. Back to
# back rebuilds of these harnesses are byte-identical, so a content-only check passes
# while the rebuild still happens. Over longer gaps the bytes do change - three distinct
# gguf_loader_fuzzer hashes turned up in a single session, cause not identified (R68) -
# so content is unreliable in both directions. mtime always moves when a build runs,
# which is the signal this gate actually needs.
#
# Skips (not fails) a checker whose harness is absent: with nothing built there is
# nothing to protect, and building one here to create the precondition would be the
# very side effect this gate exists to forbid.
#
# The child's exit status is part of the verdict, not noise. A checker that never ran -
# refused by a guard, no seeds, build tools missing, an early fail - leaves harnesses/
# untouched just as surely as one that behaved, and the snapshot cannot tell the two
# apart. Measured 2026-09-14 with all three children replaced by a stub that printed a
# refusal and exited 1 without doing anything: pass=4 fail=0, every one of them reported
# as having "left harnesses/ untouched". COMMON-BLD-22's evidence rested on that. So the
# child must be shown to have RUN first - a zero exit and its own completion line - and
# only then is the snapshot diff worth reading. R69.
#
# Writes only under its own mktemp directory plus the checkers' own OUT_DIR, which is
# pointed into that mktemp directory.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
HARNESS_DIR="$PROJECT_ROOT/harnesses"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/engine-check-isolation-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  skip %s\n' "$*"; }

# `%Y` is whole seconds; a rebuild inside the same second would be missed, but a native
# build takes seconds, and the content hash below closes the gap either way.
snapshot() {
  local out="$1"
  find "$HARNESS_DIR" -type f -printf '%p %T@ ' -exec sha256sum {} \; \
    | awk '{print $1, $2, $3}' | sort >"$out"
}

# probe_isolated <script> <label> <completion-pattern>
# Runs one checker against a snapshot of harnesses/ and says what happened, in four
# words the caller decides about: notrun (non-zero exit), noreport (exited 0 without its
# own completion line, so it may have stopped early with the status swallowed), rebuilt,
# or clean. Separated from the verdict so the negative controls below can drive the same
# probe with a checker that is known not to run.
probe_isolated() {
  local script="$1" label="$2" done_re="$3" rc=0
  snapshot "$WORK/$label.before"
  OUT_DIR="$WORK/$label-out" timeout 600 bash "$script" >"$WORK/$label.log" 2>&1 || rc=$?
  snapshot "$WORK/$label.after"
  if [[ "$rc" -ne 0 ]]; then
    printf 'notrun rc=%s' "$rc"
    return
  fi
  if ! grep -qE "$done_re" "$WORK/$label.log"; then
    printf 'noreport rc=0'
    return
  fi
  if diff -q "$WORK/$label.before" "$WORK/$label.after" >/dev/null; then
    printf 'clean rc=0'
  else
    printf 'rebuilt rc=0'
  fi
}

run_isolated() { # run_isolated <checker> <label> <completion-pattern> <required-binary>...
  local checker="$1" label="$2" done_re="$3"; shift 3
  local script="$PROJECT_ROOT/scripts/$checker"
  if [[ ! -f "$script" ]]; then
    skip "$label: $checker not present"
    return
  fi
  local missing=0 b
  for b in "$@"; do
    [[ -x "$b" ]] || missing=1
  done
  if [[ "$missing" -eq 1 ]]; then
    skip "$label: harness not built, nothing to protect"
    return
  fi

  local verdict
  verdict="$(probe_isolated "$script" "$label" "$done_re")"
  case "$verdict" in
    clean*)
      ok "$label ran to completion and left harnesses/ untouched ($verdict)" ;;
    rebuilt*)
      bad "$label rebuilt or rewrote files under harnesses/"
      # `diff` exits 1 when it finds differences, which is the expected case here; without
      # the guard `set -e` plus `pipefail` would kill the gate before the other checkers run.
      { diff "$WORK/$label.before" "$WORK/$label.after" || true; } \
        | sed -n '1,8p' | sed 's/^/       /' ;;
    notrun*)
      bad "$label did not run to completion ($verdict); a checker that never ran leaves harnesses/ untouched too, so this run proves nothing about rebuilding"
      tail -3 "$WORK/$label.log" | sed 's/^/       /' ;;
    noreport*)
      bad "$label exited 0 without printing its completion line ($verdict); it may have stopped early, and an untouched harnesses/ would then mean nothing"
      tail -3 "$WORK/$label.log" | sed 's/^/       /' ;;
  esac
}

# The completion pattern is each checker's own last line, so "it finished" is read off
# what the checker says rather than assumed from a zero exit. If one of them is reworded
# this gate says so, which is the right outcome: it no longer knows the child finished.
run_isolated check_gguf_native_engines.sh gguf '\[gguf-engines\] done: ' \
  "$HARNESS_DIR/libfuzzer/gguf_loader_fuzzer" "$HARNESS_DIR/libfuzzer/gguf_loader_replay"
run_isolated check_onnx_native_engines.sh onnx '\[onnx-native-check\] done: ' \
  "$HARNESS_DIR/libfuzzer/onnxruntime_loader_fuzzer" "$HARNESS_DIR/libfuzzer/onnxruntime_loader_replay"
run_isolated check_safetensors_native_engines.sh safetensors '\[st-engines\] ok' \
  "$HARNESS_DIR/libfuzzer/safetensors_loader_fuzzer" "$HARNESS_DIR/libfuzzer/safetensors_loader_replay"

# Negative controls for the half the snapshot cannot see. Both stubs leave harnesses/
# untouched, which is exactly why "untouched" alone was never evidence.
printf '#!/usr/bin/env bash\necho "[stub] refusing: seed missing or empty" >&2\nexit 1\n' \
  >"$WORK/refuses.sh"
chmod +x "$WORK/refuses.sh"
verdict="$(probe_isolated "$WORK/refuses.sh" negctl-refuses '\] done: ')"
case "$verdict" in
  notrun*) ok "negative control: a checker that refuses to start is not credited with leaving harnesses/ untouched ($verdict)" ;;
  *)       bad "negative control: a checker that never ran was read as '$verdict'" ;;
esac

printf '#!/usr/bin/env bash\nexit 0\n' >"$WORK/silent.sh"
chmod +x "$WORK/silent.sh"
verdict="$(probe_isolated "$WORK/silent.sh" negctl-silent '\] done: ')"
case "$verdict" in
  noreport*) ok "negative control: a checker that exits 0 without its completion line is not credited either ($verdict)" ;;
  *)         bad "negative control: a silent zero-exit checker was read as '$verdict'" ;;
esac

# Negative control: the snapshot must actually notice a rebuild. Touching a real file
# would mutate the tree this gate protects, so the comparison runs against a copy.
cp -a "$HARNESS_DIR" "$WORK/harness-copy"
HARNESS_DIR="$WORK/harness-copy" snapshot "$WORK/neg.before"
victim="$(find "$WORK/harness-copy" -type f | head -1)"
touch "$victim"
HARNESS_DIR="$WORK/harness-copy" snapshot "$WORK/neg.after"
if diff -q "$WORK/neg.before" "$WORK/neg.after" >/dev/null; then
  bad 'negative control: snapshot did not notice a touched harness file'
else
  ok 'negative control: snapshot notices a touched harness file'
fi

printf '[engine-check-isolation] pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
