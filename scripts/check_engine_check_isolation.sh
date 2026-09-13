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

run_isolated() { # run_isolated <checker> <label> <required-binary>...
  local checker="$1" label="$2"; shift 2
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

  snapshot "$WORK/$label.before"
  OUT_DIR="$WORK/$label-out" timeout 600 bash "$script" >"$WORK/$label.log" 2>&1 || true
  snapshot "$WORK/$label.after"

  if diff -q "$WORK/$label.before" "$WORK/$label.after" >/dev/null; then
    ok "$label left harnesses/ untouched (no rebuild, no rewrite)"
  else
    bad "$label rebuilt or rewrote files under harnesses/"
    # `diff` exits 1 when it finds differences, which is the expected case here; without
    # the guard `set -e` plus `pipefail` would kill the gate before the other checkers run.
    { diff "$WORK/$label.before" "$WORK/$label.after" || true; } \
      | sed -n '1,8p' | sed 's/^/       /'
  fi
}

run_isolated check_gguf_native_engines.sh gguf \
  "$HARNESS_DIR/libfuzzer/gguf_loader_fuzzer" "$HARNESS_DIR/libfuzzer/gguf_loader_replay"
run_isolated check_onnx_native_engines.sh onnx \
  "$HARNESS_DIR/libfuzzer/onnxruntime_loader_fuzzer" "$HARNESS_DIR/libfuzzer/onnxruntime_loader_replay"
run_isolated check_safetensors_native_engines.sh safetensors \
  "$HARNESS_DIR/libfuzzer/safetensors_loader_fuzzer" "$HARNESS_DIR/libfuzzer/safetensors_loader_replay"

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
