#!/usr/bin/env bash
# R37: pins what a checker's scratch wipe may take with it.
#
# check_onnx_libfuzzer_crash_artifacts.sh wipes DATA_DIR before it stages a corpus, and
# guards that wipe with an A11 test on DATA_DIR's *name* only. The PoC it replays is
# deliberately not committed, so the path an operator hands it is usually their only local
# copy - and the most natural path to hand it is the one a previous run left behind inside
# the default DATA_DIR. Measured on dev 2026-09-13: two files under
# data/onnx-libfuzzer-artifact-check carry the expected sha256, so pointing
# ONNX_SIGSEGV_POC at either one passed the hash check, was deleted by the wipe, and the
# run then died on `cp: cannot stat`. The name guard cannot see this: DATA_DIR's name was
# exactly the dedicated one it demands.
#
# Assertions, because none of them holds alone:
#   1. behavioural - the real checker, handed a PoC inside DATA_DIR, must refuse and leave
#      the file alone. Only the two commands the checker itself parameterises (PROJECT_ROOT
#      and TOOL_BIN) are stubbed; the `rm -rf` under test is the real one.
#   2. it must refuse BEFORE it builds anything - a refusal that costs a native build is a
#      refusal an operator waits minutes for.
#   3. the opposite polarity - a PoC outside DATA_DIR must still get through, and the wipe
#      must still happen, so the fix cannot be "stop wiping".
#   4. the two spellings an operator actually types. The guard is only worth anything if it
#      holds a path it has to resolve: a RELATIVE path from the repository root (the form
#      tab-completion produces) and a SYMLINK outside DATA_DIR whose target is inside it.
#      Both reach the same file as assertion 1 by a name that is not a prefix of DATA_DIR,
#      and both carry assertion 1's full verdict - survival AND a non-zero exit - because
#      survival alone also describes a guard degraded to `exit 0`, which touches nothing and
#      builds nothing. Measured on dev 2026-09-14: against such a variant these two cases
#      reported ok on survived=yes built=no while rc was 0.
#   5. negative controls - the same harness, pointed at a checker that does destroy its
#      input, must report the destruction; and the guard degraded to a string comparison
#      must lose the file in both spellings of assertion 4. Without the second one,
#      assertion 4 could hold for a reason unrelated to resolving the path - it measured
#      pass=6 fail=0 against the string-comparison variant before assertion 4 existed.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
CHECKER="$PROJECT_ROOT/scripts/check_onnx_libfuzzer_crash_artifacts.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/checker-wipe-safety-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

# The checker verifies its input against this sha256 before doing anything with it, so the
# gate cannot use arbitrary bytes: the fixture below is the file itself, copied out of the
# repository if it is present. Without it the hash check would reject the input and the
# wipe would never be reached, which would make every assertion below vacuous.
SIGSEGV_SHA256="$(grep -m1 '^SIGSEGV_SHA256=' "$CHECKER" | cut -d'"' -f2)"

find_poc() {
  local f
  while IFS= read -r f; do
    [[ "$(sha256sum "$f" | cut -d' ' -f1)" == "$SIGSEGV_SHA256" ]] && { printf '%s' "$f"; return 0; }
  done < <(find "$PROJECT_ROOT/data/onnx-libfuzzer-artifact-check" -type f ! -size +1M 2>/dev/null)
  return 1
}

# A sandbox PROJECT_ROOT: the checker's build step becomes a marker drop, and TOOL_BIN a
# stub that exits non-zero (the checker requires a failing run). Nothing here builds.
make_sandbox() {
  local root="$1"
  mkdir -p "$root/scripts"
  cat >"$root/scripts/build_libfuzzer_onnx_native.sh" <<'STUB'
#!/usr/bin/env bash
: >"$(dirname -- "$0")/../build-was-reached"
STUB
  chmod +x "$root/scripts/build_libfuzzer_onnx_native.sh"
  cat >"$root/tool" <<'STUB'
#!/usr/bin/env bash
exit 1
STUB
  chmod +x "$root/tool"
}

# Runs a checker against a DATA_DIR and reports, on one line: rc, whether the input
# survived, whether the build step was reached.
#
# `poc` is the path as an operator would type it, and that is not always a path this gate
# can test for afterwards: a relative one only means anything from the caller's directory,
# and a symlink's loss shows up at its target, not at the link. So `survivor` (default: the
# path handed over) names the file whose survival is the finding, and `cwd` (default: the
# sandbox root) is the directory the checker is invoked from.
probe() {
  local script="$1" root="$2" data_dir="$3" poc="$4" log="$5"
  local survivor="${6:-$poc}" cwd="${7:-$root}" rc=0
  rm -f "$root/build-was-reached"
  ( cd "$cwd" && env PROJECT_ROOT="$root" TOOL_BIN="$root/tool" DATA_DIR="$data_dir" \
      ONNX_SIGSEGV_POC="$poc" \
      timeout 120 bash "$script" ) >"$log" 2>&1 || rc=$?
  printf 'rc=%s survived=%s built=%s' "$rc" \
    "$([[ -f "$survivor" ]] && echo yes || echo no)" \
    "$([[ -f "$root/build-was-reached" ]] && echo yes || echo no)"
}

POC_SRC="$(find_poc || true)"
if [[ -z "$POC_SRC" ]]; then
  # Not a skip: without the fixture the gate cannot observe anything, and a gate that
  # reports success when it observed nothing is the failure mode this suite exists to stop.
  printf '[checker-wipe-safety] fail: no file matching SIGSEGV_SHA256 under data/onnx-libfuzzer-artifact-check\n' >&2
  printf '[checker-wipe-safety] the PoC is not committed; provide the tree or this gate cannot run\n' >&2
  exit 1
fi

# --- 1+2. a PoC inside DATA_DIR must survive, and be refused before any build ----------
R1="$WORK/case1"; make_sandbox "$R1"
DD1="$R1/data/onnx-libfuzzer-artifact-check"
mkdir -p "$DD1/corpus.previous"
cp "$POC_SRC" "$DD1/corpus.previous/crash_protobuf.onnx"
res1="$(probe "$CHECKER" "$R1" "$DD1" "$DD1/corpus.previous/crash_protobuf.onnx" "$WORK/case1.log")"

case "$res1" in
  *survived=yes*) ok "a PoC inside DATA_DIR survives the checker ($res1)" ;;
  *) bad "the checker deleted the PoC it was handed ($res1)"
     sed -n '1,6p' "$WORK/case1.log" | sed 's/^/       /' ;;
esac
# rc alone proves little - the unguarded checker also exits non-zero, just after the
# damage, when `cp` cannot find the file it deleted. It is survived=yes AND built=no that
# make this a refusal rather than a crash; this assertion only rules out a silent accept.
case "$res1" in
  rc=0*) bad "the checker exited 0 for a PoC inside the directory it wipes ($res1)" ;;
  *)     ok "the checker does not exit 0 for a PoC inside the directory it wipes ($res1)" ;;
esac
case "$res1" in
  *built=no*) ok 'the refusal costs no native build' ;;
  *)          bad "the checker built the harness before refusing ($res1)" ;;
esac

# --- 3. opposite polarity: a PoC outside DATA_DIR still runs, and the wipe still wipes --
R2="$WORK/case2"; make_sandbox "$R2"
DD2="$R2/data/onnx-libfuzzer-artifact-check"
mkdir -p "$DD2"
: >"$DD2/stale-from-a-previous-run"
OUTSIDE="$WORK/outside-poc.onnx"
cp "$POC_SRC" "$OUTSIDE"
res2="$(probe "$CHECKER" "$R2" "$DD2" "$OUTSIDE" "$WORK/case2.log")"

case "$res2" in
  *survived=yes*built=yes*) ok "a PoC outside DATA_DIR is not refused ($res2)" ;;
  *) bad "the guard also refuses a PoC outside DATA_DIR ($res2)"
     sed -n '1,6p' "$WORK/case2.log" | sed 's/^/       /' ;;
esac
if [[ -e "$DD2/stale-from-a-previous-run" ]]; then
  bad 'the checker stopped wiping DATA_DIR; stale state from a previous run survived'
else
  ok 'the checker still wipes DATA_DIR on the path it is allowed to take'
fi

# --- 4. the spellings that do not look like DATA_DIR ------------------------------------
# Both stage the same file as case 1 and hand it over under a name that no prefix test on
# DATA_DIR can match. DATA_DIR stays absolute, because that is what its default expands to.
stage_inside() { # stage_inside <sandbox root> -> prints the staged file
  local root="$1"
  make_sandbox "$root"
  mkdir -p "$root/data/onnx-libfuzzer-artifact-check/corpus.previous"
  cp "$POC_SRC" "$root/data/onnx-libfuzzer-artifact-check/corpus.previous/crash_protobuf.onnx"
  printf '%s' "$root/data/onnx-libfuzzer-artifact-check/corpus.previous/crash_protobuf.onnx"
}
REL_POC='data/onnx-libfuzzer-artifact-check/corpus.previous/crash_protobuf.onnx'

R4="$WORK/case4"; VICTIM4="$(stage_inside "$R4")"
res4="$(probe "$CHECKER" "$R4" "$R4/data/onnx-libfuzzer-artifact-check" \
        "$REL_POC" "$WORK/case4.log" "$VICTIM4" "$R4")"
case "$res4" in
  *survived=yes*built=no*) ok "a relative-path PoC inside DATA_DIR survives, unbuilt ($res4)" ;;
  *) bad "a relative-path PoC inside DATA_DIR was not refused ($res4)"
     sed -n '1,6p' "$WORK/case4.log" | sed 's/^/       /' ;;
esac
case "$res4" in
  rc=0*) bad "the checker exited 0 for a relative-path PoC inside the directory it wipes ($res4)" ;;
  *)     ok "the checker does not exit 0 for a relative-path PoC inside DATA_DIR ($res4)" ;;
esac

R5="$WORK/case5"; VICTIM5="$(stage_inside "$R5")"
ln -s "$VICTIM5" "$R5/poc-link.onnx"
res5="$(probe "$CHECKER" "$R5" "$R5/data/onnx-libfuzzer-artifact-check" \
        "$R5/poc-link.onnx" "$WORK/case5.log" "$VICTIM5")"
case "$res5" in
  *survived=yes*built=no*) ok "a symlink resolving into DATA_DIR survives, unbuilt ($res5)" ;;
  *) bad "a symlink whose target is inside DATA_DIR was not refused ($res5)"
     sed -n '1,6p' "$WORK/case5.log" | sed 's/^/       /' ;;
esac
case "$res5" in
  rc=0*) bad "the checker exited 0 for a symlink resolving into the directory it wipes ($res5)" ;;
  *)     ok "the checker does not exit 0 for a symlink resolving into DATA_DIR ($res5)" ;;
esac

# --- 5. negative control: the harness must catch a checker that destroys its input ------
cat >"$WORK/check_fake_artifacts.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="${PROJECT_ROOT:?}"
DATA_DIR="${DATA_DIR:?}"
POC="${ONNX_SIGSEGV_POC:?}"
case "$DATA_DIR" in
  */onnx-libfuzzer-artifact-check) : ;;
  *) echo "refusing"; exit 1 ;;
esac
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
cp "$POC" "$DATA_DIR/copy.onnx"
FAKE

R3="$WORK/case3"; make_sandbox "$R3"
DD3="$R3/data/onnx-libfuzzer-artifact-check"
mkdir -p "$DD3"
cp "$POC_SRC" "$DD3/crash_protobuf.onnx"
res3="$(probe "$WORK/check_fake_artifacts.sh" "$R3" "$DD3" "$DD3/crash_protobuf.onnx" "$WORK/case3.log")"
case "$res3" in
  *survived=no*) ok "negative control: the harness reports a checker that deletes its input ($res3)" ;;
  *)             bad "negative control: a checker that deletes its input was reported as safe ($res3)" ;;
esac

# --- 5b. negative control on the guard itself ------------------------------------------
# Case 4 must fail for the reason it claims. The variant below is the real checker with the
# path resolution - and only that - removed, so the guard keeps its shape and compares the
# strings it was handed. If the substitution stops applying the gate says so rather than
# reporting a control it never ran.
WEAK="$WORK/check_weakened.sh"
sed -e 's|^poc_real="$(realpath -- "$CRASH_POC")"$|poc_real="$CRASH_POC"|' \
    -e 's|^data_real="$(realpath -m -- "$DATA_DIR")"$|data_real="$DATA_DIR"|' \
    "$CHECKER" >"$WEAK"
if [[ "$(grep -c '^poc_real="\$CRASH_POC"$' "$WEAK")" -ne 1 ]] \
   || [[ "$(grep -c '^data_real="\$DATA_DIR"$' "$WEAK")" -ne 1 ]]; then
  bad 'could not derive the string-comparison variant; the guard was renamed, and cases 4-5 are unanchored'
else
  R6="$WORK/case6"; VICTIM6="$(stage_inside "$R6")"
  res6="$(probe "$WEAK" "$R6" "$R6/data/onnx-libfuzzer-artifact-check" \
          "$REL_POC" "$WORK/case6.log" "$VICTIM6" "$R6")"
  case "$res6" in
    *survived=no*) ok "negative control: comparing strings loses the relative-path PoC ($res6)" ;;
    *)             bad "negative control: the relative-path case passes without resolving the path, so it pins nothing ($res6)" ;;
  esac

  R7="$WORK/case7"; VICTIM7="$(stage_inside "$R7")"
  ln -s "$VICTIM7" "$R7/poc-link.onnx"
  res7="$(probe "$WEAK" "$R7" "$R7/data/onnx-libfuzzer-artifact-check" \
          "$R7/poc-link.onnx" "$WORK/case7.log" "$VICTIM7")"
  case "$res7" in
    *survived=no*) ok "negative control: comparing strings loses the symlinked PoC ($res7)" ;;
    *)             bad "negative control: the symlink case passes without resolving the path, so it pins nothing ($res7)" ;;
  esac
fi

printf '[checker-wipe-safety] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
