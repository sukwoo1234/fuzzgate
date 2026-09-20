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
# The gate also has to survive the host it meets first, which has nothing built. Both
# arms that read harnesses/ directly assumed it held at least one file: the rebuild probe
# picked its victim with `find ... | head -1` and ran touch on the empty string when that
# came back empty, and snapshot() let find fail outright when the directory was gone.
# Either way set -e killed the run before the verdict line, so the suite saw rc=1 with no
# ledger and could not tell "a checker rebuilt harnesses/" from "the gate never got to
# look". Measured 2026-09-14: an emptied harnesses/ gave "touch: cannot touch" on an empty
# name, rc=1; a removed one gave "cp: cannot stat", rc=1; neither printed a verdict line.
# A checkout carrying only the tracked sources does NOT hit this - it has five files under
# harnesses/ - so the earlier note that a freshly prepared host would crash here is wrong.
# R91.
#
# Writes only under its own mktemp directory, and proves it rather than claiming it. Every
# probe is bracketed by a stamp of the repository, reported as its own arm: a checker can
# leave harnesses/ untouched and still write elsewhere in the tree, so one verdict cannot
# carry both. It had to become an assertion because the claim was false. OUT_DIR was the
# only write target this gate redirected, so check_gguf_native_engines.sh:5 kept its
# default SEED_ROOT and :68 handed it to the seed generator, which rewrote the repository's
# own gguf seeds on every probe. Measured 2026-09-19 in a sandbox checkout with seeds and
# harnesses copied in: one run moved all four gguf seeds from mtime 1789811098 to
# 1789811118, sha256 unchanged, while the gate reported pass=10 fail=0 skip=0 - a gate
# whose entire signal is mtime (see above), moving mtimes in the tree it guards.
#
# The children are deliberately not changed: a direct run of check_gguf_native_engines.sh
# is supposed to produce the repository's seeds, so moving that default would break an
# operational checker to fix a gate. The consequence stands - running the check suite still
# has to happen in a copy of the tree.
#
# Stamp scope is $PROJECT_ROOT's top level by name and type only, plus a full mtime/size
# listing of seeds/ and data/native-engine-checks - the two subtrees these checkers write
# into. Top level is name+type because TMPDIR may sit inside the tree and a mktemp there
# moves a directory mtime without anything being written to the repository. All of data/
# was rejected three times over. Measured 2026-09-19 against the real repository: this
# scope is 154 entries in under 0.02s per stamp, all of data/ is 505594 entries and took
# between 0.67s and 9.1s across runs, cache- and load-dependent; two run directories under
# it are unreadable, so find would fail and pipefail would kill the gate; and data/ is
# campaign output that moves for reasons of its own, so it would fail runs that did nothing
# wrong. Do not "tighten" it. R97.
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
  # A tree where nothing has been built yet may carry no harnesses/ at all. Creating one
  # would be a side effect this gate exists to forbid, and an empty inventory is the
  # truthful snapshot of that tree. No verdict rests on it: run_isolated skips before it
  # ever probes when the binaries it needs are missing, so "clean" is unreachable here.
  # Without this the gate does not die: find fails inside $(probe_isolated ...), whose
  # status is its last command's, so errexit never sees it; the guard removes find(1) noise
  # an operator cannot read. Measured 2026-09-19, guard deleted, harnesses/ absent: rc=0,
  # pass=3 fail=0 skip=3, four find: lines; the pre-fix shape died at the cp -a below. R98.
  if [[ ! -d "$HARNESS_DIR" ]]; then
    : >"$out"
    return
  fi
  find "$HARNESS_DIR" -type f -printf '%p %T@ ' -exec sha256sum {} \; \
    | awk '{print $1, $2, $3}' | sort >"$out"
}

# stamp_repo <out>
# Name+type at the top level, mtime and size below it, for the reasons in the header. An
# absent subtree is stamped as a line of its own rather than skipped: seeds/ need not exist
# yet, and skipping it would let a probe that creates it look unchanged.
stamp_repo() {
  local out="$1" d
  {
    find "$PROJECT_ROOT" -mindepth 1 -maxdepth 1 -printf '%y %p\n' | sort
    for d in seeds data/native-engine-checks; do
      if [[ -e "$PROJECT_ROOT/$d" ]]; then
        find "$PROJECT_ROOT/$d" -printf '%y %p %T@ %s\n' | sort
      else
        printf 'absent %s\n' "$PROJECT_ROOT/$d"
      fi
    done
  } >"$out"
}

# probe_isolated <script> <label> <completion-pattern>
# Runs one checker against a snapshot of harnesses/ and says what happened, in four
# words the caller decides about: notrun (non-zero exit), noreport (exited 0 without its
# own completion line, so it may have stopped early with the status swallowed), rebuilt,
# or clean, plus repo=clean|dirty for the rest of the tree. Separated from the verdict so
# the negative controls below can drive the same probe with a checker that is known not to
# run.
probe_isolated() {
  local script="$1" label="$2" done_re="$3" rc=0
  # Every target these checkers default into the repository, pointed into this gate's
  # scratch alongside the OUT_DIR it always redirected: SEED_ROOT for the gguf checker's
  # seed generator, MAL_DIR and VALID_DIR for the safetensors one's, AFLPP_CHECK_DIR for
  # its AFL++ arm. One list for every probe, so a checker that later grows one of these is
  # contained by default; the onnx checker needs none of them, which is a claim the stamp
  # below verifies rather than assumes. Read paths stay on the repository on purpose -
  # FUZZER and REPLAY are the harnesses this probe observes, SEED_DIR is the real corpus.
  # check_engine_check_scratch.sh:91-93 and check_engine_check_seed_validity.sh:161 already
  # drive these children this way, so this is the odd-one-out shape R45 left, not a new
  # contract. R97.
  local redirect=(OUT_DIR="$WORK/$label-out")
  redirect+=(SEED_ROOT="$WORK/$label-seeds" MAL_DIR="$WORK/$label-mal" VALID_DIR="$WORK/$label-valid" AFLPP_CHECK_DIR="$WORK/$label-aflpp")
  snapshot "$WORK/$label.before"
  stamp_repo "$WORK/$label.repo-before"
  env "${redirect[@]}" timeout 600 bash "$script" >"$WORK/$label.log" 2>&1 || rc=$?
  stamp_repo "$WORK/$label.repo-after"
  snapshot "$WORK/$label.after"
  local repo=clean
  if ! diff -q "$WORK/$label.repo-before" "$WORK/$label.repo-after" >/dev/null; then
    repo=dirty
  fi
  if [[ "$rc" -ne 0 ]]; then
    printf 'notrun rc=%s repo=%s' "$rc" "$repo"
    return
  fi
  if ! grep -qE "$done_re" "$WORK/$label.log"; then
    printf 'noreport rc=0 repo=%s' "$repo"
    return
  fi
  if diff -q "$WORK/$label.before" "$WORK/$label.after" >/dev/null; then
    printf 'clean rc=0 repo=%s' "$repo"
  else
    printf 'rebuilt rc=0 repo=%s' "$repo"
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

  # Its own arm, because the two are independent: the gguf checker left harnesses/ untouched
  # and rewrote seeds/ in the same run, and folding that into the verdict above would have
  # hidden it behind a "clean". R97.
  case "$verdict" in
    *repo=clean)
      ok "$label left the repository outside harnesses/ untouched ($verdict)" ;;
    *)
      bad "$label wrote into the repository outside harnesses/ ($verdict)"
      { diff "$WORK/$label.repo-before" "$WORK/$label.repo-after" || true; } \
        | sed -n '1,8p' | sed 's/^/       /' ;;
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
# would mutate the tree this gate protects, so the comparison runs against a copy. The
# victim is a fixture this gate plants in that copy rather than whichever file the tree
# happens to hold: harnesses/ can legitimately contain nothing - the tracked sources are
# the only members that travel, and a tree that has had them cleaned holds no files at
# all - and `find ... | head -1` then yields the empty string, so `touch ""` failed and
# set -e killed the gate before it printed a verdict line. R91.
mkdir -p "$WORK/harness-copy"
if [[ -d "$HARNESS_DIR" ]]; then
  cp -a "$HARNESS_DIR/." "$WORK/harness-copy/"
fi
victim="$WORK/harness-copy/.rebuild-probe"
printf 'isolation gate rebuild probe\n' >"$victim"
HARNESS_DIR="$WORK/harness-copy" snapshot "$WORK/neg.before"
# An explicit timestamp rather than a bare touch: %T@ is sub-second, so a same-instant
# touch is not guaranteed to move it, and this arm must not be able to pass by luck.
touch -t 200001010000 "$victim"
HARNESS_DIR="$WORK/harness-copy" snapshot "$WORK/neg.after"
if diff -q "$WORK/neg.before" "$WORK/neg.after" >/dev/null; then
  bad 'negative control: snapshot did not notice a touched harness file'
else
  ok 'negative control: snapshot notices a touched harness file'
fi

# The arms above are all this gate can assert about a host that has everything built. The
# host it actually meets first has nothing built, and the failure mode there is not a bad
# verdict but no verdict at all: the gate died before its last line, so the suite saw rc=1
# with an empty ledger and no way to tell "a checker rebuilt harnesses/" from "the gate
# could not run". Re-entering itself against a tree with an empty harnesses/ is the only
# way to pin that, so the child is told not to recurse. R91.
if [[ -z "${ENGINE_CHECK_ISOLATION_SELFTEST:-}" ]]; then
  # Two shapes, because they died in two different places: an empty harnesses/ killed the
  # rebuild probe, and a missing one killed snapshot() one arm earlier.
  for shape in empty absent; do
    SELFROOT="$WORK/selftest-$shape"
    mkdir -p "$SELFROOT"
    [[ "$shape" = empty ]] && mkdir -p "$SELFROOT/harnesses"
    # The real scripts/, so every child checker is present and skips for the honest reason -
    # its binaries are missing - which is the shape of a freshly prepared host, not of a
    # repository with no checkers in it.
    ln -s "$PROJECT_ROOT/scripts" "$SELFROOT/scripts"
    self_rc=0
    # This selftest asks whether the ledger is reached, not whether missing harnesses
    # should make a top-level suite pass. Permit its intentional skips explicitly.
    ALLOW_SKIPPED_CASES=1 ENGINE_CHECK_ISOLATION_SELFTEST=1 PROJECT_ROOT="$SELFROOT" \
      timeout 600 bash "${BASH_SOURCE[0]}" >"$WORK/selftest-$shape.log" 2>&1 || self_rc=$?
    if [[ "$self_rc" -eq 0 ]] && grep -q '^\[engine-check-isolation\] pass=' "$WORK/selftest-$shape.log"; then
      ok "a tree whose harnesses/ is $shape still reaches a verdict line"
    else
      bad "a tree whose harnesses/ is $shape killed the gate (rc=$self_rc)"
      tail -3 "$WORK/selftest-$shape.log" | sed 's/^/       /'
    fi
    # Reaching the verdict line is not enough on the absent shape. Without the guard in
    # snapshot() the run still ends rc=0, but every snapshot prints a find(1) error first,
    # and an operator reading a suite log cannot tell those from a checker failing. The
    # guard is what makes "nothing is built here" a stated state instead of tool noise.
    if [[ "$shape" = absent ]]; then
      if grep -q '^find: ' "$WORK/selftest-$shape.log"; then
        bad 'a tree whose harnesses/ is absent makes the gate emit find(1) errors an operator cannot read'
        grep -m2 '^find: ' "$WORK/selftest-$shape.log" | sed 's/^/       /'
      else
        ok 'a tree whose harnesses/ is absent produces a verdict without tool errors'
      fi
    fi
  done

  # Opposite polarity: the arm above must be able to fail. A copy of this script with the
  # fixture line removed is the pre-fix shape, and it must NOT reach a verdict line there.
  sed 's|^victim="\$WORK/harness-copy/\.rebuild-probe"$|victim="$(find "$WORK/harness-copy" -type f \| head -1)"|; /^printf .isolation gate rebuild probe/d' \
    "${BASH_SOURCE[0]}" >"$WORK/prefix-shape.sh"
  pre_rc=0
  ALLOW_SKIPPED_CASES=1 ENGINE_CHECK_ISOLATION_SELFTEST=1 PROJECT_ROOT="$WORK/selftest-empty" \
    timeout 600 bash "$WORK/prefix-shape.sh" >"$WORK/prefix-shape.log" 2>&1 || pre_rc=$?
  if [[ "$pre_rc" -ne 0 ]] && ! grep -q '^\[engine-check-isolation\] pass=' "$WORK/prefix-shape.log"; then
    ok "negative control: the pre-fix shape still dies without a verdict line (rc=$pre_rc)"
  else
    bad "negative control: the pre-fix shape survived (rc=$pre_rc); this arm proves nothing"
  fi

  # Opposite polarity for the repository arm: a copy of this script with the redirect line
  # removed is the pre-fix shape - OUT_DIR redirected, everything else defaulting into the
  # tree - and it must be caught. If the line is ever renamed the sed removes nothing, the
  # copy behaves like this script, and this arm fails rather than quietly passing.
  #
  # It needs a root of its own: the two above have nothing built, so every checker skips and
  # no probe ever runs. Two stub binaries under harnesses/libfuzzer are what it takes to
  # make the gguf checker reach its seed generator, which is the write this arm is about.
  # They exit 1, so the harnesses/ verdict there reads notrun - which is the point of
  # reporting the two arms separately, and only the repository arm is read here. TMPDIR
  # points into this gate's scratch because that failing child preserves its own mktemp dir
  # on a non-zero exit, the same reason check_engine_check_seed_validity.sh:140-142 gives.
  # R97.
  CTLROOT="$WORK/selftest-redirect"
  mkdir -p "$CTLROOT/harnesses/libfuzzer" "$WORK/ctl-tmp"
  ln -s "$PROJECT_ROOT/scripts" "$CTLROOT/scripts"
  for stub in gguf_loader_fuzzer gguf_loader_replay; do
    printf '#!/usr/bin/env bash\nexit 1\n' >"$CTLROOT/harnesses/libfuzzer/$stub"
    chmod +x "$CTLROOT/harnesses/libfuzzer/$stub"
  done
  sed '/^  redirect+=(SEED_ROOT=/d' "${BASH_SOURCE[0]}" >"$WORK/noredirect.sh"
  ALLOW_SKIPPED_CASES=1 ENGINE_CHECK_ISOLATION_SELFTEST=1 PROJECT_ROOT="$CTLROOT" TMPDIR="$WORK/ctl-tmp" \
    timeout 600 bash "$WORK/noredirect.sh" >"$WORK/noredirect.log" 2>&1 || true
  if grep -q '^  FAIL gguf wrote into the repository outside harnesses/' "$WORK/noredirect.log"; then
    ok 'negative control: the pre-fix shape is caught writing into the tree it guards'
  else
    bad 'negative control: the pre-fix shape was not caught writing into the tree; the repository arm proves nothing'
    tail -3 "$WORK/noredirect.log" | sed 's/^/       /'
  fi
fi

if [[ "$SKIP" -gt 0 ]]; then
  if [[ "${ALLOW_SKIPPED_CASES:-0}" == 1 ]]; then
    printf '[engine-check-isolation] WARN: continuing with %d skipped case(s) (ALLOW_SKIPPED_CASES=1)\n' "$SKIP" >&2
  else
    bad "$SKIP case(s) did not run; set ALLOW_SKIPPED_CASES=1 only if you accept an unverified run"
  fi
fi
printf '[engine-check-isolation] pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
