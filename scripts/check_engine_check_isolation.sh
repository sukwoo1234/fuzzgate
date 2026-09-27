#!/usr/bin/env bash
# R45: a check must not rebuild the operational harness binaries it is checking.
#
# check_gguf_native_engines.sh and check_onnx_native_engines.sh called their native
# build script on every run with no output override, so the build script's defaults
# (harnesses/libfuzzer/*) were rewritten each time the check suite ran. Running the
# suite is supposed to be an observation; it was silently reinstalling the artifacts
# that BASE-02 pins by hash, and it burned a full native build doing it.
# check_safetensors_native_engines.sh already skipped the libFuzzer build when the complete
# pair existed, but partial-pair preservation was still missing. R73 extends the same
# no-rewrite contract to partial pairs, every AFL++ arm, and the private ONNX artifact
# checker; it is still an existing contract, not a new one.
#
# The assertion is behavioural and deliberately uses mtime, not just content. Back to
# back rebuilds of these harnesses are byte-identical, so a content-only check passes
# while the rebuild still happens. Over longer gaps the bytes do change - three distinct
# gguf_loader_fuzzer hashes turned up in a single session, cause not identified (R68) -
# so content is unreliable in both directions. mtime always moves when a build runs,
# which is the signal this gate actually needs.
#
# Skips (not fails) a full checker run whose pair is incomplete: with both outputs absent
# there is nothing to protect, while a one-present/one-absent pair is exercised separately
# below with stub builders. Building a real peer here to create the full-run precondition
# would be the very side effect this gate exists to forbid.
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
  local missing=0 present=0 b
  for b in "$@"; do
    if [[ -x "$b" ]]; then
      present=$((present + 1))
    else
      missing=$((missing + 1))
    fi
  done
  if [[ "$missing" -gt 0 ]]; then
    if [[ "$present" -gt 0 ]]; then
      skip "$label: harness pair incomplete; partial-pair routing is covered by fixtures"
    else
      skip "$label: harness not built, nothing to protect"
    fi
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

# A complete pair is not the only operational state. If just one libFuzzer output is
# missing, the pair builders still produce two files; sending both to their defaults
# rewrites the executable that was already present. The full-pair probes above skip that
# state because one required binary is absent. Exercise both partial states with the real
# checker prefix and a builder stub that honours the builders' documented output variables.
write_pair_builder() { # write_pair_builder <format> <sandbox-root> [ignore-overrides]
  local format="$1" root="$2" ignore_overrides="${3:-0}"
  local builder="$root/scripts/build_libfuzzer_${format}_native.sh"
  case "$format" in
    gguf|safetensors)
      cat >"$builder" <<PAIR_BUILDER
#!/usr/bin/env bash
set -euo pipefail
root="\${PROJECT_ROOT:?}"
if [[ "$ignore_overrides" == 1 ]]; then
  out_f="\$root/harnesses/libfuzzer/${format}_loader_fuzzer"
  out_r="\$root/harnesses/libfuzzer/${format}_loader_replay"
else
  out_f="\${OUT_FUZZER:-\$root/harnesses/libfuzzer/${format}_loader_fuzzer}"
  out_r="\${OUT_REPLAY:-\$root/harnesses/libfuzzer/${format}_loader_replay}"
fi
for out in "\$out_f" "\$out_r"; do
  mkdir -p "\$(dirname -- "\$out")"
  printf '#!/usr/bin/env bash\\nexit 0\\n' >"\$out"
  chmod +x "\$out"
done
printf 'built\\n' >>"\$root/build-was-run"
PAIR_BUILDER
      ;;
    onnx)
      cat >"$builder" <<PAIR_BUILDER
#!/usr/bin/env bash
set -euo pipefail
root="\${PROJECT_ROOT:?}"
if [[ "$ignore_overrides" == 1 ]]; then
  out="\$root/harnesses/libfuzzer/onnxruntime_loader_fuzzer"
  standalone="\$root/harnesses/libfuzzer/onnxruntime_loader_replay"
else
  out="\${OUT:-\$root/harnesses/libfuzzer/onnxruntime_loader_fuzzer}"
  standalone="\${STANDALONE_OUT:-\$root/harnesses/libfuzzer/onnxruntime_loader_replay}"
fi
mkdir -p "\$(dirname -- "\$out")"
printf '#!/usr/bin/env bash\\nexit 0\\n' >"\$out"
chmod +x "\$out"
if [[ "\${BUILD_STANDALONE:-0}" == 1 ]]; then
  mkdir -p "\$(dirname -- "\$standalone")"
  printf '#!/usr/bin/env bash\\nexit 0\\n' >"\$standalone"
  chmod +x "\$standalone"
fi
printf 'built\\n' >>"\$root/build-was-run"
PAIR_BUILDER
      ;;
  esac
  chmod +x "$builder"
}

make_pair_probe() { # make_pair_probe <format> <sandbox-root> [ignore-overrides]
  local format="$1" root="$2" ignore_overrides="${3:-0}"
  local source="$PROJECT_ROOT/scripts/check_${format}_native_engines.sh"
  local checker="$root/check_${format}_native_engines.sh"
  mkdir -p "$root/scripts" "$root/harnesses/libfuzzer" "$root/tmp" "$root/out"
  case "$format" in
    gguf)
      awk '/^# -rss_limit_mb / { print "exit 0"; exit } { print }' "$source" >"$checker"
      mkdir -p "$root/seeds/gguf" "$root/seeds/gguf-malformed"
      printf 'seed' >"$root/seeds/gguf/align_ok.gguf"
      printf 'poc' >"$root/seeds/gguf-malformed/align_wrongtype.gguf"
      printf '#!/usr/bin/env bash\nexit 0\n' >"$root/scripts/gen_gguf_malformed_seeds.sh"
      chmod +x "$root/scripts/gen_gguf_malformed_seeds.sh"
      ;;
    onnx)
      awk '/^log "run libFuzzer fixed-input smoke"/ { print "exit 0"; exit } { print }' \
        "$source" >"$checker"
      mkdir -p "$root/seeds/onnx"
      printf 'seed' >"$root/seeds/onnx/onnx_5_mul_1.onnx"
      ;;
    safetensors)
      awk '/^# 1\. Run the real corpus cleanly/ { print "exit 0"; exit } { print }' \
        "$source" >"$checker"
      ;;
  esac
  chmod +x "$checker"
  write_pair_builder "$format" "$root" "$ignore_overrides"
}

pair_names() { # pair_names <format> -> fuzzer-name replay-name
  case "$1" in
    onnx) printf '%s %s\n' onnxruntime_loader_fuzzer onnxruntime_loader_replay ;;
    *) printf '%s %s\n' "${1}_loader_fuzzer" "${1}_loader_replay" ;;
  esac
}

probe_partial_pair() { # probe_partial_pair <format> <existing-side> [ignore-overrides]
  local format="$1" existing_side="$2" ignore_overrides="${3:-0}"
  local root="$WORK/r73-pair-${format}-${existing_side}-${ignore_overrides}"
  local fuzzer_name replay_name existing missing before after rc=0
  read -r fuzzer_name replay_name < <(pair_names "$format")
  make_pair_probe "$format" "$root" "$ignore_overrides"
  if [[ "$existing_side" == fuzzer ]]; then
    existing="$root/harnesses/libfuzzer/$fuzzer_name"
    missing="$root/harnesses/libfuzzer/$replay_name"
  else
    existing="$root/harnesses/libfuzzer/$replay_name"
    missing="$root/harnesses/libfuzzer/$fuzzer_name"
  fi
  printf '#!/usr/bin/env bash\n# existing-%s-%s\nexit 0\n' "$format" "$existing_side" \
    >"$existing"
  chmod +x "$existing"
  before="$(stat -c '%d:%i:%s:%a:%Y:%Z' "$existing"):$(sha256sum "$existing" | awk '{print $1}')"
  (
    cd "$root"
    env PROJECT_ROOT="$root" TMPDIR="$root/tmp" OUT_DIR="$root/out" \
      timeout 30 bash "$root/check_${format}_native_engines.sh"
  ) >"$root/probe.log" 2>&1 || rc=$?
  after="$(stat -c '%d:%i:%s:%a:%Y:%Z' "$existing"):$(sha256sum "$existing" | awk '{print $1}')"
  printf 'rc=%s built=%s preserved=%s missing_created=%s' "$rc" \
    "$([[ -s "$root/build-was-run" ]] && echo yes || echo no)" \
    "$([[ "$before" == "$after" ]] && echo yes || echo no)" \
    "$([[ -x "$missing" ]] && echo yes || echo no)"
}

for format in gguf onnx safetensors; do
  for existing_side in fuzzer replay; do
    partial="$(probe_partial_pair "$format" "$existing_side")"
    case "$partial" in
      'rc=0 built=yes preserved=yes missing_created=yes')
        ok "$format partial pair preserves the existing $existing_side and installs only the missing peer" ;;
      *)
        bad "$format partial pair is not preservation-safe ($partial)" ;;
    esac
  done
done

# Negative control: the same probe must notice a pair builder that ignores the selected
# scratch output and writes its defaults, which is the operational shape fixed by R73.
partial="$(probe_partial_pair onnx fuzzer 1)"
case "$partial" in
  *preserved=no*) ok "negative control: partial-pair probe catches a builder that overwrites the existing peer ($partial)" ;;
  *) bad "negative control: partial-pair probe missed an overwrite of the existing peer ($partial)" ;;
esac

# GGUF was the only affected AFL++ checker that accepted an AFLPP_REPLAY override without
# forwarding it to the builder. Guarding that selected path is not enough: the builder must
# receive the same path as OUT. Otherwise a missing custom path replaces the already-present
# default output, after which the checker still fails because the custom path was not created.
write_gguf_afl_builder() { # write_gguf_afl_builder <sandbox-root> [ignore-out]
  local root="$1" ignore_out="${2:-0}"
  cat >"$root/scripts/build_aflpp_gguf_native.sh" <<AFL_BUILDER
#!/usr/bin/env bash
set -euo pipefail
root="\${PROJECT_ROOT:?}"
if [[ "$ignore_out" == 1 ]]; then
  out="\$root/harnesses/aflpp/gguf_loader_replay"
else
  out="\${OUT:-\$root/harnesses/aflpp/gguf_loader_replay}"
fi
mkdir -p "\$(dirname -- "\$out")"
printf '#!/usr/bin/env bash\n# rebuilt-default\nexit 0\n' >"\$out"
chmod +x "\$out"
printf 'built\n' >>"\$root/afl-build-was-run"
AFL_BUILDER
  chmod +x "$root/scripts/build_aflpp_gguf_native.sh"
}

probe_gguf_afl_output() { # probe_gguf_afl_output [ignore-out]
  local ignore_out="${1:-0}"
  local root="$WORK/r73-gguf-afl-output-$ignore_out"
  local checker="$root/check_gguf_native_engines.sh"
  local default_replay="$root/harnesses/aflpp/gguf_loader_replay"
  local custom_replay="$root/custom/gguf_loader_replay"
  local before after rc=0
  mkdir -p "$root/scripts/lib" "$root/harnesses/libfuzzer" \
    "$root/harnesses/aflpp" "$root/seeds/gguf" "$root/seeds/gguf-malformed" \
    "$root/tmp" "$root/out" "$root/bin"

  # Run the actual checker, not an extracted code fragment. Small harness and tool stubs
  # make every GGUF oracle execute while keeping the probe bounded.
  cp "$PROJECT_ROOT/scripts/check_gguf_native_engines.sh" "$checker"
  chmod +x "$checker"
  cat >"$root/scripts/gen_gguf_malformed_seeds.sh" <<'GGUF_GENERATOR'
#!/usr/bin/env bash
exit 0
GGUF_GENERATOR
  cat >"$root/scripts/lib/engine_mode.sh" <<'ENGINE_MODE'
instrumentation_scope() { printf 'library\n'; }
ENGINE_MODE
  cat >"$root/harnesses/libfuzzer/gguf_loader_fuzzer" <<'GGUF_FUZZER'
#!/usr/bin/env bash
set -euo pipefail
artifact_prefix=''
for arg in "$@"; do
  case "$arg" in -artifact_prefix=*) artifact_prefix="${arg#*=}" ;; esac
done
input="${!#}"
if [[ -d "$input" ]]; then
  printf 'crash bytes\n' >"${artifact_prefix}crash-stub"
  printf 'ERROR: AddressSanitizer\n' >&2
  exit 1
fi
if [[ "$input" == *align_wrongtype.gguf ]]; then
  printf 'ERROR: AddressSanitizer\n' >&2
  exit 1
fi
printf 'Executed %s\n' "$input" >&2
GGUF_FUZZER
  cat >"$root/harnesses/libfuzzer/gguf_loader_replay" <<'GGUF_REPLAY'
#!/usr/bin/env bash
exit 134
GGUF_REPLAY
  cat >"$root/bin/afl-clang-fast++" <<'AFL_TOOL'
#!/usr/bin/env bash
exit 0
AFL_TOOL
  cat >"$root/bin/afl-showmap" <<'AFL_TOOL'
#!/usr/bin/env bash
set -euo pipefail
out=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$out" ]]
printf '1:1\n' >"$out"
exit 0
AFL_TOOL
  chmod +x "$root/scripts/gen_gguf_malformed_seeds.sh" \
    "$root/harnesses/libfuzzer/gguf_loader_fuzzer" \
    "$root/harnesses/libfuzzer/gguf_loader_replay" "$root/bin/afl-clang-fast++" \
    "$root/bin/afl-showmap"
  printf 'seed\n' >"$root/seeds/gguf/align_ok.gguf"
  printf 'poc\n' >"$root/seeds/gguf-malformed/align_wrongtype.gguf"
  printf '#!/usr/bin/env bash\n# original-default\nexit 0\n' >"$default_replay"
  chmod +x "$default_replay"
  write_gguf_afl_builder "$root" "$ignore_out"

  before="$(stat -c '%d:%i:%s:%a:%Y:%Z' "$default_replay"):$(sha256sum "$default_replay" | awk '{print $1}')"
  (
    cd "$root"
    env PROJECT_ROOT="$root" SEED_ROOT="$root/seeds" \
      AFLPP_REPLAY="$custom_replay" OUT_DIR="$root/out" TMPDIR="$root/tmp" \
      PATH="$root/bin:$PATH" timeout 30 bash "$checker"
  ) >"$root/probe.log" 2>&1 || rc=$?
  after="$(stat -c '%d:%i:%s:%a:%Y:%Z' "$default_replay"):$(sha256sum "$default_replay" | awk '{print $1}')"
  printf 'rc=%s built=%s default_preserved=%s custom_created=%s completed=%s' "$rc" \
    "$([[ -s "$root/afl-build-was-run" ]] && echo yes || echo no)" \
    "$([[ "$before" == "$after" ]] && echo yes || echo no)" \
    "$([[ -x "$custom_replay" ]] && echo yes || echo no)" \
    "$(grep -Fq '[gguf-engines] done:' "$root/probe.log" && echo yes || echo no)"
}

if [[ -z "${ENGINE_CHECK_ISOLATION_SELFTEST:-}" ]]; then
  gguf_afl="$(probe_gguf_afl_output)"
  case "$gguf_afl" in
    'rc=0 built=yes default_preserved=yes custom_created=yes completed=yes')
      ok "gguf AFL++ bootstrap installs the selected missing replay without replacing its default ($gguf_afl)" ;;
    *)
      bad "gguf AFL++ bootstrap did not honour the selected replay path ($gguf_afl)" ;;
  esac

  # Opposite polarity: if the builder ignores OUT, the same behavioural probe must fail the
  # checker and observe the overwrite. This keeps the success arm from passing vacuously.
  gguf_afl="$(probe_gguf_afl_output 1)"
  case "$gguf_afl" in
    'rc=1 built=yes default_preserved=no custom_created=no completed=no')
      ok "negative control: GGUF AFL output probe catches a builder that ignores OUT ($gguf_afl)" ;;
    *)
      bad "negative control: GGUF AFL output probe failed for an unrelated reason ($gguf_afl)" ;;
  esac
fi

# Inventory every direct native-builder invocation and every variable assignment that can
# hide one. The four R73 guards below are intentionally explicit because each output
# variable is part of the contract, but that list alone would silently miss a fifth caller.
# This lightweight lexer skips comments and heredoc bodies, joins continued lines, and
# records the executable call/assignment surface. It is not a general shell parser: any
# new shape changes the inventory and fails closed until it is classified here.
discover_native_build_surface() { # discover_native_build_surface <scripts-dir>
  local scripts_dir="$1"
  python3 - "$scripts_dir" <<'PY'
from collections import Counter
from pathlib import Path
import re
import shlex
import sys

scripts_dir = Path(sys.argv[1])
builder = re.compile(r"(?:^|/)(build_(?:aflpp|libfuzzer)_[A-Za-z0-9_]+_native\.sh)$")
assignment = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=(.*)$")
heredoc_start = re.compile(
    r"<<(-?)(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z_][A-Za-z0-9_]*))"
)
separators = {";", "&&", "||", "|", "(", ")"}
calls = Counter()

for path in sorted(scripts_dir.glob("check_*.sh")):
    pending = ""
    heredoc = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if heredoc is not None:
            delimiter, strip_tabs = heredoc
            probe = raw.lstrip("\t") if strip_tabs else raw
            if probe == delimiter:
                heredoc = None
            continue

        logical = pending + raw
        if logical.endswith("\\"):
            pending = logical[:-1] + " "
            continue
        pending = ""

        marker = heredoc_start.search(logical)
        if marker:
            heredoc = (
                marker.group(2) or marker.group(3) or marker.group(4),
                bool(marker.group(1)),
            )

        # Most shell source is irrelevant, and shlex is intentionally not a full Bash
        # parser (notably for nested command substitutions). Every in-repository builder
        # reference uses a scripts/build_*_native.sh path, so narrow before tokenizing.
        if "scripts/build_" not in logical or "_native.sh" not in logical:
            continue

        try:
            lexer = shlex.shlex(logical, posix=True, punctuation_chars=";&|()")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            tokens = list(lexer)
        except ValueError as exc:
            raise SystemExit(f"cannot tokenize {path}: {exc}")

        for index, token in enumerate(tokens):
            assigned = assignment.match(token)
            if assigned:
                match = builder.search(assigned.group(1))
                if match:
                    calls[(path.name, "assign", match.group(1))] += 1
                continue

            match = builder.search(token)
            if not match:
                continue
            basename = match.group(1)
            if token != basename and not token.endswith("/" + basename):
                continue

            segment = 0
            for prior in range(index - 1, -1, -1):
                if tokens[prior] in separators:
                    segment = prior + 1
                    break
            first = segment
            while first < index and assignment.match(tokens[first]):
                first += 1
            if first == index or (index > first and tokens[index - 1] in {"bash", "sh"}):
                calls[(path.name, "call", basename)] += 1

for (name, kind, basename), count in sorted(calls.items()):
    print(f"{name}|{kind}|{basename}|{count}")
PY
}

cat >"$WORK/r73-build-surface.expected" <<'R73_SURFACE'
check_aflpp_native_build.sh|assign|build_aflpp_gguf_native.sh|1
check_aflpp_native_build.sh|assign|build_aflpp_onnx_native.sh|1
check_engine_mode_labels.sh|assign|build_aflpp_safetensors_native.sh|1
check_gguf_native_engines.sh|call|build_aflpp_gguf_native.sh|1
check_gguf_native_engines.sh|call|build_libfuzzer_gguf_native.sh|1
check_onnx_libfuzzer_crash_artifacts.sh|call|build_libfuzzer_onnx_native.sh|1
check_onnx_native_engines.sh|call|build_aflpp_onnx_native.sh|1
check_onnx_native_engines.sh|call|build_libfuzzer_onnx_native.sh|1
check_safetensors_aflpp_build.sh|assign|build_aflpp_safetensors_native.sh|1
check_safetensors_native_engines.sh|call|build_aflpp_safetensors_native.sh|1
check_safetensors_native_engines.sh|call|build_libfuzzer_safetensors_native.sh|1
check_staged_install.sh|call|build_libfuzzer_onnx_native.sh|1
R73_SURFACE

if ! command -v python3 >/dev/null 2>&1; then
  bad 'native-build caller inventory cannot run: python3 is missing'
elif ! discover_native_build_surface "$PROJECT_ROOT/scripts" >"$WORK/r73-build-surface.actual"; then
  bad 'native-build caller inventory could not parse scripts/check_*.sh'
elif cmp -s "$WORK/r73-build-surface.expected" "$WORK/r73-build-surface.actual"; then
  ok 'native-build caller inventory has no unclassified call or indirection'
else
  bad 'native-build caller inventory changed; classify every new call or indirection'
  { diff -u "$WORK/r73-build-surface.expected" "$WORK/r73-build-surface.actual" || true; } \
    | sed -n '1,24p' | sed 's/^/       /'
fi

# Scanner polarity: a future direct caller and a future variable indirection must both
# appear in the inventory. Otherwise the real-tree equality above could pass because the
# scanner found nothing.
mkdir "$WORK/r73-discovery-fixture"
cat >"$WORK/r73-discovery-fixture/check_future_direct.sh" <<'R73_FUTURE'
#!/usr/bin/env bash
bash "$PROJECT_ROOT/scripts/build_aflpp_onnx_native.sh"
R73_FUTURE
cat >"$WORK/r73-discovery-fixture/check_future_indirect.sh" <<'R73_FUTURE'
#!/usr/bin/env bash
FUTURE_BUILD="$PROJECT_ROOT/scripts/build_aflpp_onnx_native.sh"
bash "$FUTURE_BUILD"
R73_FUTURE
discover_native_build_surface "$WORK/r73-discovery-fixture" \
  >"$WORK/r73-discovery-fixture.actual"
if grep -Fqx 'check_future_direct.sh|call|build_aflpp_onnx_native.sh|1' \
     "$WORK/r73-discovery-fixture.actual"; then
  ok 'negative control: native-build inventory discovers a new direct caller'
else
  bad 'negative control: native-build inventory missed a new direct caller'
fi
if grep -Fqx 'check_future_indirect.sh|assign|build_aflpp_onnx_native.sh|1' \
     "$WORK/r73-discovery-fixture.actual"; then
  ok 'negative control: native-build inventory discovers a new builder indirection'
else
  bad 'negative control: native-build inventory missed a new builder indirection'
fi

# R73: the behavioural probes above see only the three native-engine checkers, and their
# AFL++ arms run only on hosts that have the relevant tools. That left four unconditional
# installs invisible on the dev host: the three AFL++ arms plus the private ONNX artifact
# checker. Pin the class as source structure too. Each operational build call must sit in
# an executable-missing guard for the selected replay/harness variable. Output routing is a
# separate behavioural assertion above for the one caller that accepts a custom path.
# Reformatting the guard into a shape this small scanner cannot prove fails closed; these
# are four call sites, not a general shell parser.
guarded_build_call() { # guarded_build_call <file> <output-var> <build-script-basename>
  local file="$1" output_var="$2" build_name="$3"
  awk -v output_var="$output_var" -v build_name="$build_name" '
    BEGIN { in_guard = 0; calls = 0; guarded = 0 }
    {
      line = $0
      trimmed = line
      sub(/^[[:space:]]*/, "", trimmed)
      if (trimmed ~ /^#/) next

      guard = "if [[ ! -x \"$" output_var "\" ]]; then"
      if (trimmed == guard) {
        in_guard = 1
        next
      }

      # This is deliberately an exact-shape proof, not a shell parser. A call in
      # else/elif (or after fi on the same line) is outside the missing-output arm.
      if (in_guard && trimmed ~ /^(else|elif|fi)([[:space:];]|$)/) in_guard = 0

      if (index(trimmed, build_name) > 0) {
        calls++
        if (in_guard) guarded++
      }
    }
    END { exit(calls == 1 && guarded == 1 ? 0 : 1) }
  ' "$file"
}

while IFS='|' read -r checker output_var build_name; do
  checker_path="$PROJECT_ROOT/scripts/$checker"
  if [[ ! -f "$checker_path" ]]; then
    bad "R73 guard target is missing: $checker"
  elif guarded_build_call "$checker_path" "$output_var" "$build_name"; then
    ok "$checker builds $build_name only when \$$output_var is missing"
  else
    bad "$checker can run $build_name without an executable-missing guard for \$$output_var"
  fi
done <<'R73_GUARDS'
check_gguf_native_engines.sh|AFLPP_REPLAY|build_aflpp_gguf_native.sh
check_onnx_native_engines.sh|AFLPP_REPLAY|build_aflpp_onnx_native.sh
check_safetensors_native_engines.sh|AFLPP_REPLAY|build_aflpp_safetensors_native.sh
check_onnx_libfuzzer_crash_artifacts.sh|LF_FUZZER|build_libfuzzer_onnx_native.sh
R73_GUARDS

# Opposite polarity for the structural arm: one unguarded call and one guard for the wrong
# output must both be rejected. Without these, a typo in the scanner could bless all four
# real scripts without reading their control flow.
cat >"$WORK/r73-unguarded.sh" <<'R73_BAD'
#!/usr/bin/env bash
AFLPP_REPLAY=/tmp/replay
bash "$PROJECT_ROOT/scripts/build_aflpp_onnx_native.sh"
R73_BAD
if guarded_build_call "$WORK/r73-unguarded.sh" AFLPP_REPLAY build_aflpp_onnx_native.sh; then
  bad 'negative control: R73 scan accepted an unguarded native build'
else
  ok 'negative control: R73 scan rejects an unguarded native build'
fi

cat >"$WORK/r73-wrong-output.sh" <<'R73_BAD'
#!/usr/bin/env bash
AFLPP_REPLAY=/tmp/replay
OTHER_REPLAY=/tmp/other
if [[ ! -x "$OTHER_REPLAY" ]]; then
  bash "$PROJECT_ROOT/scripts/build_aflpp_onnx_native.sh"
fi
R73_BAD
if guarded_build_call "$WORK/r73-wrong-output.sh" AFLPP_REPLAY build_aflpp_onnx_native.sh; then
  bad 'negative control: R73 scan accepted a guard for the wrong output'
else
  ok 'negative control: R73 scan rejects a guard for the wrong output'
fi

cat >"$WORK/r73-opposite-branch.sh" <<'R73_BAD'
#!/usr/bin/env bash
AFLPP_REPLAY=/tmp/replay
if [[ ! -x "$AFLPP_REPLAY" ]]; then
  :
else
  bash "$PROJECT_ROOT/scripts/build_aflpp_onnx_native.sh"
fi
R73_BAD
if guarded_build_call "$WORK/r73-opposite-branch.sh" AFLPP_REPLAY build_aflpp_onnx_native.sh; then
  bad 'negative control: R73 scan accepted a build in the opposite branch of the missing-output guard'
else
  ok 'negative control: R73 scan rejects a build in the opposite branch of the missing-output guard'
fi

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
