#!/usr/bin/env bash
# R42: pins that check_engine_mode_labels.sh records every case it does not run.
#
# That checker already owns the doctrine and the mechanism. Its own comment at :28-31
# says "A case that does not run is not a case that passed. Every skip is recorded and,
# by default, fails the script at the end: the gguf cases used to self-disable whenever a
# gitignored build artifact was missing, which silently switched off the regression test
# for the systemd defect this project has already shipped once (1e8261f)." note_skip()
# at :33 is that mechanism, and :627-634 is the gate that fails on a non-empty ledger.
#
# Three sites bypassed it. Measured on dev 2026-09-14 against a sandbox PROJECT_ROOT whose
# harnesses/ is empty - which is the state of a freshly prepared fuzzing host, because
# harnesses/ is gitignored and does not travel with the repository: the checker printed
# "done: engine mode labels verified" and exited 0 having skipped the shipped gguf replay
# case and both shipped ONNX driver cases, with an EMPTY ledger. A fourth state, no C
# compiler, hid the SIGPIPE case the same way: it announced itself with log() rather than
# note_skip(), so it printed a line nobody counts.
#
# So the failure is not "it exits 0 when it should not" alone - it is that the ledger the
# operator reads to decide whether a green run meant anything is missing entries. This is
# the check-level half of R86.
#
# Assertions, because none of them holds alone:
#   1. behavioural, missing binaries - with harnesses/ emptied and compilers present, the
#      checker must exit non-zero AND name the shipped gguf replay and both ONNX drivers
#      in its ledger.
#   2. behavioural, missing compiler - with the bundled toolchain and the PATH compilers
#      hidden too, the ledger must also name the SIGPIPE case. SCOPE_CC is re-derived a
#      second time at :152, so hiding the PATH compilers alone does not hide it: the
#      bundled clang under data/toolchains has to go as well (an instance of R84).
#   3. the opposite polarity - against the real PROJECT_ROOT, the three cases must RUN
#      (their own log lines appear) and must NOT be in the ledger, so the fix cannot
#      degrade into "record everything". Reported as a skip, not a pass, on a host that
#      does not have those binaries built - saying so rather than passing vacuously.
#   4. scan - no log() call in that checker may announce a skip, since note_skip() exists
#      for exactly that and log() does not reach the ledger.
#   5. negative controls - the scan must reject a log()-announced skip and accept a
#      note_skip one; the behavioural harness must report a checker that exits 0 having
#      run nothing, or its verdicts mean nothing.
#
# Writes only under its own mktemp directory. The real-root case is read-only: the
# checker's harnesses/ listing is compared before and after, because a checker that
# reinstalls binaries is the hazard COMMON-BLD-22 exists for.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
CHECKER="$PROJECT_ROOT/scripts/check_engine_mode_labels.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/engine-mode-skip-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  skip %s\n' "$*"; }

GGUF_REPLAY_REL="harnesses/libfuzzer/gguf_loader_replay"
ONNX_FUZZER_REL="harnesses/libfuzzer/onnxruntime_loader_fuzzer"
ONNX_REPLAY_REL="harnesses/aflpp/onnxruntime_loader_replay"

# A root that is the real one except for the entries named, which are replaced by empty
# directories. Symlinks, so nothing is copied and nothing in the repository is written.
# Dotfiles are deliberately left out: .git symlinked into a sandbox would let anything
# that runs git there act on the real repository.
sandbox_root() { # sandbox_root <dst> <hide>...
  local dst="$1"; shift
  local entry base hide keep
  mkdir -p "$dst"
  for entry in "$PROJECT_ROOT"/*; do
    [[ -e "$entry" ]] || continue
    base="${entry##*/}"
    keep=1
    for hide in "$@"; do [[ "$base" == "$hide" ]] && keep=0; done
    [[ "$keep" -eq 1 ]] && ln -sfn "$entry" "$dst/$base"
  done
}

# PATH with every C/C++ compiler hidden. The directory is replaced by a shim that links
# everything in it except those names: dropping the directory outright would take bash,
# env and timeout with it, and the checker would then fail to start - which would make
# "the case was skipped" true for the wrong reason.
compiler_free_path() {
  local d out=() dirs entry n=0 shim found name
  IFS=: read -ra dirs <<<"$PATH"
  for d in "${dirs[@]}"; do
    [[ -n "$d" ]] || continue
    found=0
    for name in cc gcc clang c++ g++ clang++; do
      [[ -x "$d/$name" ]] && found=1
    done
    if [[ "$found" -eq 1 ]]; then
      shim="$WORK/pathshim/$((n++))"
      mkdir -p "$shim"
      for entry in "$d"/*; do
        case "${entry##*/}" in cc|gcc|clang|c++|g++|clang++|'*') continue ;; esac
        ln -sfn "$entry" "$shim/${entry##*/}" 2>/dev/null || true
      done
      out+=("$shim")
    else
      out+=("$d")
    fi
  done
  (IFS=:; printf '%s' "${out[*]}")
}

# The entries the checker lists at the end under "these cases did NOT run".
ledger() { sed -n '/these cases did NOT run:/,$p' "$1" | sed -n 's/^  - //p'; }

run_checker() { # run_checker <root> <log> [env...]
  local root="$1" log="$2"; shift 2
  local rc=0
  mkdir -p "$root/tmp"
  env TMPDIR="$root/tmp" PROJECT_ROOT="$root" "$@" \
    timeout 900 bash "$CHECKER" >"$log" 2>&1 || rc=$?
  printf '%s' "$rc"
}

[[ -f "$CHECKER" ]] || { bad "$(basename "$CHECKER") is missing; nothing to pin"; }

if [[ -f "$CHECKER" ]]; then
# --- 1. behavioural: binaries that were never built ---------------------------------------
A="$WORK/no-harnesses"
sandbox_root "$A" harnesses
mkdir -p "$A/harnesses/libfuzzer" "$A/harnesses/aflpp"
# Said out loud rather than assumed: if the sandbox still exposes the binaries, the cases
# below would run and "it did not record a skip" would be true for the wrong reason.
if [[ -e "$A/$GGUF_REPLAY_REL" || -e "$A/$ONNX_FUZZER_REL" || -e "$A/$ONNX_REPLAY_REL" ]]; then
  bad "the sandbox still exposes a shipped binary; the missing-binary case proves nothing"
else
  ok "the sandbox hides the shipped gguf replay and both ONNX drivers"
  rc="$(run_checker "$A" "$WORK/a.log")"
  entries="$(ledger "$WORK/a.log")"
  missing=""
  grep -q 'shipped gguf replay' <<<"$entries" || missing="$missing shipped-gguf-replay"
  grep -q 'onnxruntime_loader_fuzzer' <<<"$entries" || missing="$missing onnx-libfuzzer-driver"
  grep -q 'onnxruntime_loader_replay' <<<"$entries" || missing="$missing onnx-aflpp-replay"
  if [[ "$rc" -eq 0 ]]; then
    bad "$(basename "$CHECKER") verified engine mode labels with three cases unrun (rc=0, ledger=$(grep -c . <<<"$entries" || true) entries)"
    tail -1 "$WORK/a.log" | sed 's/^/       /'
  elif [[ -n "$missing" ]]; then
    bad "the ledger does not name:$missing (rc=$rc)"
  else
    ok "$(basename "$CHECKER") records the three cases it could not run (rc=$rc)"
  fi
fi

# --- 2. behavioural: no compiler at all ---------------------------------------------------
B="$WORK/no-compiler"
sandbox_root "$B" harnesses data
mkdir -p "$B/harnesses/libfuzzer" "$B/harnesses/aflpp" "$B/data"
for entry in "$PROJECT_ROOT"/data/*; do
  [[ -e "$entry" ]] || continue
  [[ "${entry##*/}" == toolchains ]] || ln -sfn "$entry" "$B/data/${entry##*/}"
done
SAFE_PATH="$(compiler_free_path)"
if env PATH="$SAFE_PATH" "$BASH" -c 'command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1'; then
  bad "the compiler-free PATH still finds a C compiler; the SIGPIPE case would run"
elif ! env PATH="$SAFE_PATH" "$BASH" -c 'command -v timeout >/dev/null 2>&1 && command -v env >/dev/null 2>&1'; then
  bad "the compiler-free PATH lost tools the checker needs; every skip below would be true for the wrong reason"
else
  ok "the compiler-free PATH hides every compiler and keeps the tools the checker needs"
  rc="$(run_checker "$B" "$WORK/b.log" PATH="$SAFE_PATH")"
  entries="$(ledger "$WORK/b.log")"
  if grep -qi 'SIGPIPE' <<<"$entries"; then
    ok "the SIGPIPE case reaches the ledger when there is no compiler (rc=$rc)"
  else
    bad "the SIGPIPE case did not reach the ledger (rc=$rc); it announced itself with log(), which nobody counts"
    grep -n 'SIGPIPE' "$WORK/b.log" | sed 's/^/       /'
  fi
fi

# --- 3. the opposite polarity -------------------------------------------------------------
# Against the real root the three cases must RUN, and must not be recorded as skipped.
if [[ -x "$PROJECT_ROOT/$GGUF_REPLAY_REL" && -x "$PROJECT_ROOT/$ONNX_FUZZER_REL" \
      && -x "$PROJECT_ROOT/$ONNX_REPLAY_REL" ]]; then
  before="$(ls -l "$PROJECT_ROOT/harnesses/libfuzzer" "$PROJECT_ROOT/harnesses/aflpp")"
  rc="$(run_checker "$PROJECT_ROOT" "$WORK/c.log")"
  after="$(ls -l "$PROJECT_ROOT/harnesses/libfuzzer" "$PROJECT_ROOT/harnesses/aflpp")"
  entries="$(ledger "$WORK/c.log")"
  ran=1
  grep -q 'the shipped gguf replay is library scope' "$WORK/c.log" || ran=0
  grep -q 'onnxruntime_loader_fuzzer must not claim library scope' "$WORK/c.log" || ran=0
  grep -q 'onnxruntime_loader_replay must not claim library scope' "$WORK/c.log" || ran=0
  if [[ "$ran" -ne 1 ]]; then
    bad "the three cases did not run against the real root even though their binaries exist (rc=$rc)"
  elif grep -qE 'shipped gguf replay|onnxruntime_loader' <<<"$entries"; then
    bad "a case that ran was still recorded as skipped; the ledger records everything (rc=$rc)"
  else
    ok "the three cases run and stay out of the ledger when their binaries exist (rc=$rc)"
  fi
  if [[ "$before" == "$after" ]]; then
    ok "the real-root run left harnesses/ untouched"
  else
    bad "the real-root run rewrote harnesses/; this gate must not have that side effect"
  fi
else
  skip "the opposite-polarity case needs the shipped gguf replay and both ONNX drivers built on this host"
  skip "harnesses/ was not re-listed because the opposite-polarity case did not run"
fi
fi

# --- 4. scan ------------------------------------------------------------------------------
# note_skip() is the only announcement that reaches the ledger. A log() line that says
# "skip" reads like a recorded skip in the output and is not one - the exact shape the
# SIGPIPE case had.
scan_logged_skips() { # scan_logged_skips <file>
  grep -nE '(^|[^_[:alnum:]])log[[:space:]]+"[^"]*[Ss][Kk][Ii][Pp]' "$1" || true
}
if [[ -f "$CHECKER" ]]; then
  hits="$(scan_logged_skips "$CHECKER")"
  if [[ -n "$hits" ]]; then
    bad "$(basename "$CHECKER") announces a skip through log(), which never reaches the ledger"
    sed 's/^/       /' <<<"$hits"
  else
    ok "$(basename "$CHECKER") announces every skip through note_skip()"
  fi
fi

# --- 5. negative controls -----------------------------------------------------------------
printf '%s\n' 'log "skip SIGPIPE case: no C compiler available"' >"$WORK/logged.sh"
if [[ -n "$(scan_logged_skips "$WORK/logged.sh")" ]]; then
  ok 'negative control: the scan sees a skip announced through log()'
else
  bad 'negative control: the scan missed a skip announced through log()'
fi

printf '%s\n' 'note_skip "SIGPIPE case: no C compiler available"' >"$WORK/noted.sh"
if [[ -n "$(scan_logged_skips "$WORK/noted.sh")" ]]; then
  bad 'negative control: the scan read note_skip() as a logged skip'
else
  ok 'negative control: the scan does not read note_skip() as a logged skip'
fi

# The harness must be able to see a checker that skips everything silently, or the
# behavioural verdicts above are untested.
cat >"$WORK/silent-checker.sh" <<'FAKE'
#!/usr/bin/env bash
echo "[engine-mode-check] done: engine mode labels verified"
exit 0
FAKE
rc=0; env TMPDIR="$WORK/tmp" PROJECT_ROOT="$WORK" timeout 60 bash "$WORK/silent-checker.sh" \
  >"$WORK/fake.log" 2>&1 || rc=$?
if [[ "$rc" -eq 0 && -z "$(ledger "$WORK/fake.log")" ]]; then
  ok 'negative control: the harness reads an empty ledger from a checker that ran nothing'
else
  bad "negative control: an empty ledger was not read as empty (rc=$rc)"
fi

printf '[engine-mode-skip-accounting] pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
