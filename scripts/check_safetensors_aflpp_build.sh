#!/usr/bin/env bash
# R46: the AFL++ safetensors build must never destroy the existing replay before it has
# a verified replacement. scripts/check_safetensors_native_engines.sh calls the build on
# every cargo-afl run regardless of whether the replay already exists, and on the fuzzing
# computer that replay is the only copy (it is the binary behind R21's tuples=612
# evidence). A build that fails for any reason - offline resolution, toolchain, RAM -
# must leave it byte-identical.
#
# Real build script, fake cargo. No cargo-afl, no AFL++, no network, no Rust compile.
# Everything this test writes lives under its own mktemp directory; the repository's
# harnesses/ and data/ are only ever read.
set -euo pipefail
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
BUILD="$PROJECT_ROOT/scripts/build_aflpp_safetensors_native.sh"
[[ -f "$BUILD" ]] || { echo "[st-aflpp-build] fail: missing $BUILD" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/st-aflpp-build-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

BIN="$WORK/bin"
mkdir -p "$BIN"
# `command -v cargo-afl` is only a presence probe; the build drives cargo itself.
printf '#!/bin/sh\nexit 0\n' >"$BIN/cargo-afl"
chmod +x "$BIN/cargo-afl"

# A fixture toolchain keeps the test off whatever rustup the host happens to have.
printf '#!/bin/sh\necho "fixturechain-x86_64-unknown-linux-gnu (default)"\n' >"$BIN/rustup"
chmod +x "$BIN/rustup"

cat >"$BIN/fake-cargo" <<'FAKE'
#!/usr/bin/env bash
# Stands in for `cargo +<toolchain> afl`. FAKE_CARGO_MODE picks the outcome under test.
set -uo pipefail
target_dir=""
prev=""
for arg in "$@"; do
  # The build probes `cargo +<toolchain> afl --version` before it builds anything.
  [[ "$arg" == "--version" ]] && { echo "cargo-afl 0.18.2 fixture"; exit 0; }
  [[ "$prev" == "--target-dir" ]] && target_dir="$arg"
  prev="$arg"
done
case "${FAKE_CARGO_MODE:-ok}" in
  fail)
    echo "fixture: could not compile safetensors (offline)" >&2
    exit 101
    ;;
  empty)
    # Exits clean but produces no binary, e.g. a cargo that only refreshed the index.
    exit 0
    ;;
  ok)
    mkdir -p "$target_dir/release"
    printf 'FRESH-REPLAY-FIXTURE' >"$target_dir/release/safetensors_loader_replay"
    chmod +x "$target_dir/release/safetensors_loader_replay"
    exit 0
    ;;
esac
exit 3
FAKE
chmod +x "$BIN/fake-cargo"

passed=0
failures=()

note() { echo "[st-aflpp-build] $*"; }
expect() {
  local what="$1" want="$2" got="$3"
  if [[ "$want" == "$got" ]]; then
    passed=$((passed + 1))
  else
    failures+=("$what: want [$want] got [$got]")
  fi
}

# Sets CASE_STATE to the replay's contents after the run, or <absent>.
# Never called through $( ) - the assertions below mutate shell state, and a command
# substitution would run them in a subshell and silently discard every one.
# mode | prior OUT contents ('' = no prior file) | allow_uninstrumented | expected rc
run_case() {
  local name="$1" mode="$2" prior="$3" allow="$4" want_rc="$5"
  local root="$WORK/$name"
  mkdir -p "$root"
  local out="$root/safetensors_loader_replay"
  if [[ -n "$prior" ]]; then
    printf '%s' "$prior" >"$out"
    chmod +x "$out"
  fi

  local rc=0
  env PATH="$BIN:$PATH" \
      PROJECT_ROOT="$PROJECT_ROOT" \
      CARGO="$BIN/fake-cargo" \
      CARGO_AFL_TOOLCHAIN="fixturechain" \
      FAKE_CARGO_MODE="$mode" \
      AFLPP_TARGET_DIR="$root/target-aflpp" \
      OUT="$out" \
      ${allow:+ALLOW_UNINSTRUMENTED=1} \
      bash "$BUILD" >"$root/log.txt" 2>&1 || rc=$?
  expect "$name rc" "$want_rc" "$rc"

  if [[ -e "$out" ]]; then CASE_STATE="$(cat "$out")"; else CASE_STATE="<absent>"; fi
}

note "case 1: build failure must preserve the existing replay"
run_case keep-on-build-fail fail 'ORIGINAL-REPLAY' '' 101
expect "keep-on-build-fail preserved" "ORIGINAL-REPLAY" "$CASE_STATE"

note "case 2: a build that produces nothing must preserve the existing replay"
run_case keep-on-empty-build empty 'ORIGINAL-REPLAY' '' 1
expect "keep-on-empty-build preserved" "ORIGINAL-REPLAY" "$CASE_STATE"

note "case 3: a rejected instrumentation scope must preserve the existing replay"
run_case keep-on-scope-reject ok 'ORIGINAL-REPLAY' '' 1
expect "keep-on-scope-reject preserved" "ORIGINAL-REPLAY" "$CASE_STATE"

note "case 4: a build failure with no prior replay must not leave a stub behind"
run_case no-stub-on-build-fail fail '' '' 101
expect "no-stub-on-build-fail absent" "<absent>" "$CASE_STATE"

note "case 5: an accepted build must install the fresh replay"
run_case install-on-success ok 'ORIGINAL-REPLAY' 1 0
expect "install-on-success replaced" "FRESH-REPLAY-FIXTURE" "$CASE_STATE"
if [[ -x "$WORK/install-on-success/safetensors_loader_replay" ]]; then
  passed=$((passed + 1))
else
  failures+=("install-on-success executable: replay is not executable")
fi

note "case 6: a first-time accepted build must create the replay"
run_case create-on-first-build ok '' 1 0
expect "create-on-first-build created" "FRESH-REPLAY-FIXTURE" "$CASE_STATE"

if ((${#failures[@]})); then
  printf '[st-aflpp-build] FAIL %d/%d\n' "${#failures[@]}" "$((passed + ${#failures[@]}))" >&2
  for f in "${failures[@]}"; do echo "  - $f" >&2; done
  exit 1
fi
note "ok $passed/$passed"
