#!/usr/bin/env bash
# R63: pins that a native engine checker refuses a seed it can learn nothing from.
#
# Before this gate, check_onnx_native_engines.sh:39 and check_gguf_native_engines.sh:70
# (pre-fix line numbers) gated their seed with
# `[[ -f "$SEED" ]]` - existence, not content. A zero-byte file passes that test, and every
# assertion downstream of it is "the harness exited 0": the libFuzzer target and the
# standalone replay both return 0 on empty input without parsing anything. So the check
# reports that both engine arms ran while neither parsed a byte - the exact proof it exists
# to produce is the one it cannot produce from an empty input.
#
# An odd-one-out, not a new contract: ONNX-ENG-03, the BASE-01 case that pins the same ONNX
# engine run, already gates on `[ -s "$SEED" ]`, and check_safetensors_native_engines.sh:70
# requires a non-empty corpus rather than a path that exists. Empty seeds are not
# hypothetical here - seeds/onnx carries a 1-byte leftover and the AFL++ arms ingest a
# directory unfiltered (R51).
#
# Assertions, because none of them holds alone:
#   1. behavioural - each checker, handed a zero-byte seed against a sandbox PROJECT_ROOT
#      whose harnesses are stubs that record being called, must exit non-zero AND leave
#      every stub unrun. A refusal that arrives after the run is not a refusal.
#   2. the opposite polarity - a non-empty seed through the same sandbox must still reach
#      the harnesses, so the fix cannot degrade into "refuse everything".
#   3. class scan - every check_*_native_engines.sh that names a single $SEED must require
#      it to be a regular file AND to have content, so neither half can come back missing
#      one checker at a time. -s does not imply -f: `[[ -s some/dir ]]` is true, so
#      swapping -f for -s trades one hole for another.
#   4. negative controls - the behavioural harness must report a checker that accepts an
#      empty seed, and the scan must reject -f alone, -s alone, and no guard at all.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
CHECKER_GLOB="$PROJECT_ROOT/scripts/check_"*"_native_engines.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/engine-check-seed-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

# The AFL++ arm of both checkers builds, so this gate hides afl-clang-fast++ and afl-showmap
# and lets that arm take its documented skip branch - on a machine with AFL++ installed just
# as on one without. The gate must not mean something different depending on the machine.
#
# Dropping the whole PATH entry is not good enough: `apt install afl++` puts afl-showmap in
# /usr/bin, and dropping /usr/bin takes bash, env and timeout with it. The checker would then
# fail to start, and "refuses without running anything" would be true for the wrong reason.
# So each offending directory is replaced by a shim that links everything in it except those
# two names.
afl_free_path() {
  local d out=() dirs entry n=0 shim
  IFS=: read -ra dirs <<<"$PATH"
  for d in "${dirs[@]}"; do
    [[ -n "$d" ]] || continue
    if [[ -x "$d/afl-clang-fast++" || -x "$d/afl-showmap" ]]; then
      shim="$WORK/pathshim/$((n++))"
      mkdir -p "$shim"
      for entry in "$d"/*; do
        case "${entry##*/}" in afl-clang-fast++|afl-showmap|'*') continue ;; esac
        ln -sfn "$entry" "$shim/${entry##*/}" 2>/dev/null || true
      done
      out+=("$shim")
    else
      out+=("$d")
    fi
  done
  (IFS=:; printf '%s' "${out[*]}")
}
SAFE_PATH="$(afl_free_path)"

# Said out loud rather than assumed: if the shimmed PATH lost a tool the checkers need, every
# "refuses without running anything" below would be true because nothing could start. And if
# it still finds the AFL++ tools, the arm this gate means to skip would build.
# Asked in a fresh shell with PATH in its ENVIRONMENT: a `PATH=... command -v` prefix does
# not change the lookup the current shell performs, and bash answers `command -v` from its
# hash table, so both spellings would report on the gate's own PATH instead of the sandbox's.
lookup() { env PATH="$SAFE_PATH" "$BASH" -c 'command -v "$1" >/dev/null 2>&1' bash "$1"; }
path_is_usable() {
  local t
  for t in bash env timeout mktemp grep sed; do
    lookup "$t" || { printf 'lost %s' "$t"; return 1; }
  done
  for t in afl-clang-fast++ afl-showmap; do
    lookup "$t" && { printf 'still finds %s' "$t"; return 1; }
  done
  return 0
}
if why="$(path_is_usable)"; then
  ok 'the sandbox PATH keeps the tools the checkers need and hides the AFL++ tools'
else
  bad "the sandbox PATH is unusable ($why); every refusal below would be true for the wrong reason"
fi

# A stub that answers like a harness that found nothing wrong, and records that it was
# asked. Its exit 0 is the point: it is what lets an unguarded checker run to completion.
stub() { # stub <path> <marker>
  cat >"$1" <<STUB
#!/usr/bin/env bash
printf '%s %s\n' "\$(basename -- "\$0")" "\$*" >>"$2"
exit 0
STUB
  chmod +x "$1"
}

# --- 1+2. behavioural, both checkers ----------------------------------------------------
onnx_sandbox() { # onnx_sandbox <root>
  local root="$1"
  mkdir -p "$root/harnesses/libfuzzer" "$root/scripts/lib"
  # Sourced at the top of the AFL++ arm since R41, the way the gguf checker already did:
  # without it the checker dies before the harnesses and the opposite-polarity case below
  # would read as a refusal.
  cp "$PROJECT_ROOT/scripts/lib/engine_mode.sh" "$root/scripts/lib/engine_mode.sh"
  stub "$root/harnesses/libfuzzer/onnxruntime_loader_fuzzer" "$root/harness-was-run"
  stub "$root/harnesses/libfuzzer/onnxruntime_loader_replay" "$root/harness-was-run"
  # A separate marker: the build script runs BEFORE the harnesses, so counting it as
  # "reached the harnesses" would let the opposite-polarity assertion pass having observed
  # no harness run at all - and that assertion is the only thing keeping the guard honest.
  stub "$root/scripts/build_libfuzzer_onnx_native.sh" "$root/build-was-run"
}

gguf_sandbox() { # gguf_sandbox <root>
  local root="$1"
  mkdir -p "$root/harnesses/libfuzzer" "$root/scripts/lib" "$root/seeds/gguf-malformed"
  cp "$PROJECT_ROOT/scripts/lib/engine_mode.sh" "$root/scripts/lib/engine_mode.sh"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$root/scripts/gen_gguf_malformed_seeds.sh"
  chmod +x "$root/scripts/gen_gguf_malformed_seeds.sh"
  printf 'GGUF' >"$root/seeds/gguf-malformed/poc.gguf"
  stub "$root/harnesses/libfuzzer/gguf_loader_fuzzer" "$root/harness-was-run"
  stub "$root/harnesses/libfuzzer/gguf_loader_replay" "$root/harness-was-run"
  stub "$root/scripts/build_libfuzzer_gguf_native.sh" "$root/build-was-run"
}

# Runs a checker over a seed and prints rc, whether a HARNESS ran, and whether the build
# script ran. The two are separate because they answer different questions and a checker
# reaches the build first.
#
# TMPDIR points into this gate's own scratch: check_gguf_native_engines.sh makes its mktemp
# dir before the seed guard and preserves it on any non-zero exit, so a gate whose job is to
# make that checker exit non-zero would otherwise leave one /tmp directory behind per probe.
probe() { # probe <name> <checker> <root> <seed> <log> [extra env...]
  local name="$1" checker="$2" root="$3" seed="$4" log="$5"; shift 5
  local hm="$root/harness-was-run" bm="$root/build-was-run" rc=0
  : >"$hm"; : >"$bm"
  [[ -f "$hm" && -f "$bm" ]] || { printf 'rc=- ran=- built=- markers=unwritable'; return; }
  mkdir -p "$root/tmp"
  env PATH="$SAFE_PATH" TMPDIR="$root/tmp" PROJECT_ROOT="$root" OUT_DIR="$root/out" SEED="$seed" "$@" \
    timeout 300 bash "$checker" >"$log" 2>&1 || rc=$?
  printf 'rc=%s ran=%s built=%s' "$rc" \
    "$([[ -s "$hm" ]] && echo yes || echo no)" \
    "$([[ -s "$bm" ]] && echo yes || echo no)"
}

for fmt in onnx gguf; do
  checker="$PROJECT_ROOT/scripts/check_${fmt}_native_engines.sh"
  [[ -f "$checker" ]] || { bad "$(basename "$checker") is missing; the class is incomplete"; continue; }

  ROOT="$WORK/$fmt"; "${fmt}_sandbox" "$ROOT"
  extra=(); [[ "$fmt" == gguf ]] && extra=(SEED_ROOT="$ROOT/seeds" POC="$ROOT/seeds/gguf-malformed/poc.gguf" \
                                          FUZZER="$ROOT/harnesses/libfuzzer/gguf_loader_fuzzer" \
                                          REPLAY="$ROOT/harnesses/libfuzzer/gguf_loader_replay")

  : >"$ROOT/empty.seed"
  res="$(probe "$fmt" "$checker" "$ROOT" "$ROOT/empty.seed" "$WORK/$fmt-empty.log" "${extra[@]}")"
  case "$res" in
    rc=0*) bad "$(basename "$checker") accepted a zero-byte seed ($res)"
           sed -n '1,6p' "$WORK/$fmt-empty.log" | sed 's/^/       /' ;;
    *ran=yes*)   bad "$(basename "$checker") ran the harnesses on a zero-byte seed before refusing ($res)" ;;
    *built=yes*) bad "$(basename "$checker") built before refusing a zero-byte seed ($res)" ;;
    *) ok "$(basename "$checker") refuses a zero-byte seed without running or building ($res)" ;;
  esac

  # A directory is the hole -s alone would have left open, so it is checked behaviourally
  # and not only in the scan.
  mkdir -p "$ROOT/dir.seed"
  res="$(probe "$fmt" "$checker" "$ROOT" "$ROOT/dir.seed" "$WORK/$fmt-dir.log" "${extra[@]}")"
  case "$res" in
    rc=0*)       bad "$(basename "$checker") accepted a directory as its seed ($res)" ;;
    *ran=yes*)   bad "$(basename "$checker") ran the harnesses on a directory before refusing ($res)" ;;
    *built=yes*) bad "$(basename "$checker") built before refusing a directory seed ($res)" ;;
    *)           ok "$(basename "$checker") refuses a directory as its seed without running or building ($res)" ;;
  esac

  # Opposite polarity: the same sandbox, one byte of content. Both checkers assert on their
  # own logs past this point and the stubs are not real harnesses, so rc is not the finding
  # here - reaching the harnesses at all is.
  printf 'x' >"$ROOT/real.seed"
  res="$(probe "$fmt" "$checker" "$ROOT" "$ROOT/real.seed" "$WORK/$fmt-real.log" "${extra[@]}")"
  case "$res" in
    *ran=yes*) ok "$(basename "$checker") still reaches the harnesses for a non-empty seed ($res)" ;;
    *) bad "$(basename "$checker") refuses a non-empty seed too; the guard rejects everything ($res)"
       sed -n '1,6p' "$WORK/$fmt-real.log" | sed 's/^/       /' ;;
  esac
done

# --- 3. class scan ----------------------------------------------------------------------
# Two halves, because each alone is evadable: the spelling of any guard on $SEED, and the
# existence of a guard at all when $SEED is handed to something.
# A sufficient guard establishes BOTH halves and both must be REQUIRED, not merely present
# in the text: a regular file (-f, which -s does not imply - `[[ -s dir ]]` is true) and
# content (-s, which -f does not imply). Grepping for the two spellings on one line was not
# enough. Measured 2026-09-14 against the grep version: `[[ -f "$SEED" || -s "$SEED" ]]`
# scanned as compliant (the OR requires neither half), a line whose only mention of -s was a
# trailing `# TODO: also require -s "$SEED"` comment scanned as compliant, `test -f "$SEED"
# && test -s "$SEED"` was FAILED and misdiagnosed as having no guard, and dropping the quotes
# (`$SEED`) exempted the file from the contract entirely.
#
# So the conditions are read structurally, the way check_coverage_raw_reset.sh reads removals:
# comments and heredoc bodies are not code, `[[ ]]`/`[ ]`/`test` are all conditions, `||`
# alternatives only require what ALL of them require, and a guard inside a branch or a
# function body is not one the checker always runs.
#
# What it does NOT establish, said out loud so a green scan is not over-read: that the path
# the harness finally receives is the one that was guarded. The behavioural half above is
# what pins that, and only for the two checkers it sandboxes. Nor does -s mean "a seed worth
# running": one junk byte satisfies it and is just as vacuous (R82).
scan_checker() {
  python3 - "$1" <<'PY'
import re, sys

text = open(sys.argv[1], encoding="utf-8").read()

# --- lexer: only shell lines, and only the code part of them ---------------------------
def code_of(line, sq, dq):
    """Return (code, sq, dq): the line with any comment removed, plus quote state after it."""
    i, cut = 0, len(line)
    while i < len(line):
        c = line[i]
        if sq:
            if c == "'":
                sq = False
        elif dq:
            if c == "\\":
                i += 1
            elif c == '"':
                dq = False
        elif c == "\\":
            i += 1
        elif c == "'":
            sq = True
        elif c == '"':
            dq = True
        elif c == "#" and (i == 0 or line[i - 1] in " \t;&|("):
            cut = i
            break
        i += 1
    return line[:cut], sq, dq

HEREDOC = re.compile(r"""<<-?\s*(?!<)(['"]?)([A-Za-z_]\w*)\1""")

def shell_lines(text):
    out, term, sq, dq = [], None, False, False
    for line in text.splitlines():
        if term is not None:
            if line.strip() == term:
                term = None
            continue
        if sq or dq:
            _, sq, dq = code_of(line, sq, dq)
            continue
        code, nsq, ndq = code_of(line, False, False)
        out.append(code)
        m = HEREDOC.search(line)
        if m:
            term = m.group(2)
            continue
        sq, dq = nsq, ndq
    return out

lines = shell_lines(text)

# The boundary is not decoration: without it `$SEED_DIR` and `$SEED_ROOT` - which
# check_safetensors_native_engines.sh uses and which name directories, not a seed - read as
# references to $SEED and pull that checker into a contract it is not part of.
SEED = re.compile(r'"?\$\{SEED\}"?|"?\$SEED(?![A-Za-z0-9_])"?')
OPEN = re.compile(r'^\s*(if|for|while|until|select|case)\b')
CLOSE = re.compile(r'^\s*(fi|done|esac)\b')
FUNC = re.compile(r'^\s*(?:function\s+)?[A-Za-z_][\w-]*\s*\(\s*\)\s*\{')
GROUP = re.compile(r'^\s*\{(?:\s|$)')
BRACE_CLOSE = re.compile(r'^\s*\}\s*$')
LEADIN = re.compile(r'^\s*(?:then|else|do)\s+')

# --- conditions on one line ------------------------------------------------------------
COND = re.compile(r'\[\[(.+?)\]\]|(?<!\[)\[(?!\[)(.+?)(?<!\])\](?!\])|\btest\b([^;&|]*)')

def required_ops(interior):
    """Operators applied to $SEED that this condition REQUIRES. `||` alternatives only
    require what every branch requires; a negated test requires nothing."""
    alts = [a for a in re.split(r'\|\|', interior)]
    sets = []
    for a in alts:
        if re.search(r'(^|\s)!\s', a):
            sets.append(set())
            continue
        sets.append({m.group(1) for m in re.finditer(r'-([a-zA-Z])\s+(?=%s)' % SEED.pattern, a)})
    return set.intersection(*sets) if sets else set()

def guard_ops(line):
    """Operators the line REQUIRES before its first top-level `||` fallback."""
    spans, kept = [], []
    for m in COND.finditer(line):
        interior = next(g for g in m.groups() if g is not None)
        spans.append((m.start(), m.end(), interior))
    # blank out the conditions, so a `||` inside one is not read as the line's fallback
    masked = list(line)
    for a, b, _ in spans:
        for i in range(a, b):
            masked[i] = "\x01"
    masked = "".join(masked)
    cut = masked.find("||")
    if cut == -1:
        cut = len(masked)
    ops = set()
    for a, b, interior in spans:
        if a < cut:                  # only what must hold before the fallback
            ops |= required_ops(interior)
    return ops, bool(spans)

depth = 0
sufficient = []
any_cond = False
used = any(SEED.search(l) for l in lines)
for line in lines:
    frag = LEADIN.sub('', line)
    ops, had = guard_ops(line)
    if had:
        any_cond = any_cond or bool(SEED.search(line))
    if ops >= {"f", "s"} and depth == 0:
        sufficient.append(line.strip())
    # Depth is counted per fragment, not per line: `log() { echo ...; }` opens and closes on
    # one line, and so does `if ...; then ...; fi`. Counted whole-line they never close, and
    # every guard below them reads as living inside a block.
    for k, piece in enumerate(re.split(r'(;;|;|&&|\|\|)', line)):
        if k % 2:
            continue
        pfrag = LEADIN.sub('', piece)
        if FUNC.search(piece) or OPEN.match(pfrag) or GROUP.match(pfrag):
            depth += 1
        elif CLOSE.match(pfrag) or BRACE_CLOSE.match(piece):
            depth -= 1

if depth != 0:
    print("its block structure did not balance (depth=%d); a top-level guard cannot be "
          "told from one inside a branch" % depth)
    sys.exit(1)
if not used:
    sys.exit(2)                      # no single-seed concept; out of this contract
if not sufficient:
    if any_cond:
        print("guards $SEED without unconditionally requiring both a regular file and "
              "content (-f and -s, conjoined, outside any branch or function)")
    else:
        print("uses $SEED with no guard at all")
    sys.exit(1)
sys.exit(0)
PY
}

for checker in $CHECKER_GLOB; do
  [[ -f "$checker" ]] || continue
  why="$(scan_checker "$checker")" && rc=0 || rc=$?
  case "$rc" in
    0) ok "$(basename "$checker") requires its seed to be a regular file with content" ;;
    2) ok "$(basename "$checker") names no single \$SEED; out of this contract (not an observation of one)" ;;
    *) bad "$(basename "$checker") $why" ;;
  esac
done

# --- 4. negative controls ---------------------------------------------------------------
mk_fake() { printf '%s\n' "$2" >"$WORK/$1"; chmod +x "$WORK/$1"; }

mk_fake check_weak_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
[[ -f "$SEED" ]] || exit 1
exit 0'
if scan_checker "$WORK/check_weak_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a checker that tests $SEED with -f'
else
  ok 'negative control: scan rejects a checker that tests $SEED with -f'
fi

mk_fake check_sizeonly_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
[[ -s "$SEED" ]] || exit 1
exit 0'
if scan_checker "$WORK/check_sizeonly_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted -s alone, which is true for a directory'
else
  ok 'negative control: scan rejects -s alone, which is true for a directory'
fi

mk_fake check_strong_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
[[ -f "$SEED" && -s "$SEED" ]] || exit 1
exit 0'
if scan_checker "$WORK/check_strong_native_engines.sh" >/dev/null 2>&1; then
  ok 'negative control: scan accepts a checker that requires a regular non-empty file'
else
  bad "negative control: scan rejected the correct spelling ($(scan_checker "$WORK/check_strong_native_engines.sh" || true))"
fi

# Every shape below was DEMONSTRATED against the earlier text-grep version of this scan
# (2026-09-14 adversarial round). Each one is a plausible careless edit, not a contrivance.
mk_fake check_orguard_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
[[ -f "$SEED" || -s "$SEED" ]] || exit 1
harness "$SEED"'
if scan_checker "$WORK/check_orguard_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted `-f || -s`, which requires neither half'
else
  ok 'negative control: scan rejects `-f || -s`, which requires neither half'
fi

mk_fake check_comment_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
[[ -f "$SEED" ]] || exit 1   # TODO: also require -s "$SEED" once the 1-byte leftover is gone
harness "$SEED"'
if scan_checker "$WORK/check_comment_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan read a -s mentioned in a trailing comment as part of the guard'
else
  ok 'negative control: scan does not read a trailing comment as part of the guard'
fi

mk_fake check_heredoc_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
cat >/dev/null <<EOF
[[ -f "$SEED" && -s "$SEED" ]] || exit 1
EOF
harness "$SEED"'
if scan_checker "$WORK/check_heredoc_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan read a guard inside a heredoc body as code'
else
  ok 'negative control: scan does not read a guard inside a heredoc body as code'
fi

mk_fake check_deadbranch_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
if [[ "${STRICT:-0}" == 1 ]]; then
  [[ -f "$SEED" && -s "$SEED" ]] || exit 1
fi
harness "$SEED"'
if scan_checker "$WORK/check_deadbranch_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan credited a guard reached only through a branch'
else
  ok 'negative control: scan rejects a guard reached only through a branch'
fi

mk_fake check_unquoted_native_engines.sh '#!/usr/bin/env bash
SEED=${SEED:?}
harness $SEED'
if scan_checker "$WORK/check_unquoted_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: dropping the quotes exempted an unguarded checker from the contract'
else
  ok 'negative control: dropping the quotes does not exempt a checker from the contract'
fi

# The opposite polarity of the four above: correct guards written a different way must NOT
# be failed. A scan that only accepts one spelling teaches people to write that spelling.
mk_fake check_testcmd_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
test -f "$SEED" && test -s "$SEED" || exit 1
harness "$SEED"'
if scan_checker "$WORK/check_testcmd_native_engines.sh" >/dev/null 2>&1; then
  ok 'negative control: scan accepts the same contract written with `test`'
else
  bad "negative control: scan failed a correct guard written with \`test\` ($(scan_checker "$WORK/check_testcmd_native_engines.sh" || true))"
fi

mk_fake check_posix_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
[ -f "$SEED" ] && [ -s "$SEED" ] || exit 1
harness "${SEED}"'
if scan_checker "$WORK/check_posix_native_engines.sh" >/dev/null 2>&1; then
  ok 'negative control: scan accepts the same contract written with two [ ] tests'
else
  bad "negative control: scan failed a correct guard written with [ ] ($(scan_checker "$WORK/check_posix_native_engines.sh" || true))"
fi

# A flag that is not a test operator must not be mistaken for one.
mk_fake check_flagnoise_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
[[ -f "$SEED" ]] && echo "seed is $(du -s "$SEED" | cut -f1) blocks"
harness "$SEED"'
if scan_checker "$WORK/check_flagnoise_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan read `du -s` as a test operator on $SEED'
else
  ok 'negative control: scan does not read an ordinary command flag as a test operator'
fi

# Deleting the guard must not read as compliance - the -f scan alone would pass this.
mk_fake check_unguarded_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
harness "$SEED"'
if scan_checker "$WORK/check_unguarded_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a checker that uses $SEED with no guard at all'
else
  ok 'negative control: scan rejects a checker that uses $SEED with no guard at all'
fi

# And the behavioural half must be able to see an acceptance, or its verdicts mean nothing.
FR="$WORK/fakeroot"; mkdir -p "$FR"
mk_fake check_fake_native_engines.sh '#!/usr/bin/env bash
SEED="${SEED:?}"
[[ -f "$SEED" ]] || exit 1
"$PROJECT_ROOT/harnesses/libfuzzer/onnxruntime_loader_fuzzer" "$SEED"'
onnx_sandbox "$FR"
: >"$FR/empty.seed"
res_fake="$(probe fake "$WORK/check_fake_native_engines.sh" "$FR" "$FR/empty.seed" "$WORK/fake.log")"
case "$res_fake" in
  rc=0*ran=yes*) ok "negative control: the harness reports a checker that accepts an empty seed ($res_fake)" ;;
  *) bad "negative control: an accepting checker was not reported as accepting ($res_fake)" ;;
esac

printf '[engine-check-seed-validity] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
