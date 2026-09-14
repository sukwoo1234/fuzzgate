#!/usr/bin/env bash
# R40: pins that a coverage runner starts from an empty raw/ directory.
#
# Sibling contract to scripts/check_coverage_runner_contract.sh (R38), which pins that no
# runner may DEFAULT OUT_DIR. This one pins what happens once OUT_DIR is given and reused:
# the profraw of the previous run must not survive into this run's number.
#
# run_coverage_safetensors.sh named its profraw by PID (cov-%p.profraw) and only ran
# `mkdir -p "$RAW"`, so a reused OUT_DIR kept every earlier file and llvm-profdata merged
# them all. Measured on dev 2026-09-13: a 4-input run followed by a 1-input run into the
# same OUT_DIR published lines 112/575 functions 12/64 for a corpus whose honest coverage
# is lines 21/575 functions 2/64 - a 5.3x inflation, reported with no warning and exit 0.
# run_coverage_gguf.sh:65 and run_coverage_onnx.sh already delete first.
#
# src/coverage.rs always hands over a fresh OUT_DIR, so this never fires through the tool.
# It fires on the by-hand path - which is exactly the path that re-measures a number for a
# document.
#
# Three assertions, because none of them holds alone:
#   1. behavioural - run the REAL safetensors runner twice into one OUT_DIR, big corpus
#      then small, and require the small run to report what the small corpus really covers
#      (measured in the same gate run against a fresh OUT_DIR; no number is hardcoded).
#   2. class scan - every scripts/run_coverage_*.sh must remove each directory it creates
#      under OUT_DIR before creating it, so the defect cannot come back one runner at a
#      time. Paths are resolved through their assignments; names are never trusted.
#   3. negative controls - the scan must reject a runner that skips the removal, one that
#      removes a different path, one whose removal is reached only through a branch that is
#      false at run time, and one whose removal is guarded by `&&`; it must still accept a
#      runner that removes the right path under a name it has never seen, one that creates
#      conditionally after removing unconditionally, and one whose embedded python opens
#      blocks that shell never closes; and it must say so instead of judging when a
#      script's structure does not balance.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
RUNNER_GLOB="$PROJECT_ROOT/scripts/run_coverage_"*.sh

WORK="$(mktemp -d "${TMPDIR:-/tmp}/coverage-raw-reset-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  skip %s\n' "$*"; }

# --- 1. behavioural: a reused OUT_DIR must not inflate the number ----------------------
# The real runner and the real instrumented replay: a stub would have to invent the
# profraw, which is the thing under test. The runner builds the replay when it is missing,
# so the prerequisite is checked here first - building an operational artifact is a side
# effect this gate must not have.
REPLAY="$PROJECT_ROOT/fuzz/target-cov/safetensors_loader_replay_cov"
RUSTBIN="$(rustc +nightly --print target-libdir 2>/dev/null)/../bin"

covered() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["covered_lines"], d["covered_functions"])' "$1"; }

if [[ -x "$REPLAY" && -x "$RUSTBIN/llvm-profdata" && -x "$RUSTBIN/llvm-cov" ]]; then
  BIG="$WORK/corpus-big"; SMALL="$WORK/corpus-small"
  mkdir -p "$BIG" "$SMALL"
  # Two corpora that must differ in coverage: the 15-byte minimal header alone, against it
  # plus the generated dtype/metadata seeds. If they ever stop differing the assertion
  # below says so instead of passing vacuously.
  cp "$PROJECT_ROOT/seeds/safetensors/min.safetensors" "$SMALL/"
  cp "$PROJECT_ROOT/seeds/safetensors/min.safetensors" "$BIG/"
  for s in gen_mixed gen_metadata gen_bf16 safe_04; do
    [[ -f "$PROJECT_ROOT/seeds/safetensors/$s.safetensors" ]] && cp "$PROJECT_ROOT/seeds/safetensors/$s.safetensors" "$BIG/"
  done

  run_cov() { # run_cov <out_dir> <corpus_dir>
    env PROJECT_ROOT="$PROJECT_ROOT" OUT_DIR="$1" CORPUS_DIR="$2" \
      timeout 300 bash "$PROJECT_ROOT/scripts/run_coverage_safetensors.sh" >>"$WORK/runner.log" 2>&1
  }

  if run_cov "$WORK/honest" "$SMALL" && run_cov "$WORK/rich" "$BIG"; then
    honest="$(covered "$WORK/honest/coverage.json")"
    rich="$(covered "$WORK/rich/coverage.json")"
    if [[ "$honest" == "$rich" ]]; then
      bad "the two corpora cover the same lines/functions ($honest); the reuse assertion would prove nothing"
    else
      ok "the small and large corpora differ in coverage (small=$honest large=$rich)"
      # The reuse: the large run first, then the small one into the SAME OUT_DIR.
      if run_cov "$WORK/reused" "$BIG" && run_cov "$WORK/reused" "$SMALL"; then
        reused="$(covered "$WORK/reused/coverage.json")"
        if [[ "$reused" == "$honest" ]]; then
          ok "a reused OUT_DIR reports the small corpus's own coverage ($reused)"
        else
          bad "a reused OUT_DIR reported $reused for a corpus that covers $honest (previous run merged in)"
        fi
        left="$(find "$WORK/reused/raw" -name '*.profraw' | wc -l | tr -d ' ')"
        if [[ "$left" -eq 1 ]]; then
          ok "raw/ holds only the last run's profile ($left)"
        else
          bad "raw/ holds $left profraw after two runs; the previous run's profiles survived"
        fi
      else
        bad "the runner failed on the reuse pair"
        tail -5 "$WORK/runner.log" | sed 's/^/       /'
      fi
    fi
  else
    bad "the runner failed on its baseline runs"
    tail -5 "$WORK/runner.log" | sed 's/^/       /'
  fi
else
  skip "instrumented safetensors replay or rustc nightly llvm tools absent; reuse unobserved (building them here is the side effect this gate avoids)"
  skip "instrumented safetensors replay absent: raw/ contents unobserved"
  skip "instrumented safetensors replay absent: corpora-differ precondition unobserved"
fi

# --- 2. class scan: every directory a runner creates under OUT_DIR is removed first -----
# Names are never trusted - a runner could hold its raw path in any variable, so each
# mkdir and rm target is resolved through the script's own assignments and OUT_DIR is
# reduced to a sentinel. What is required is the relation between the two, not a spelling.
scan_runner() {
  python3 - "$1" <<'PY'
import posixpath, re, sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()

# --- lexer -----------------------------------------------------------------------------
# Structure can only be read off lines that are shell. These runners embed python through
# heredocs and through multi-line single-quoted `python3 -c` arguments, and that python has
# `for`/`if` at the start of a line. Counted as shell those would open blocks that never
# close, and every real command after them would read as conditional.
def scan_quotes(line, sq, dq):
    i = 0
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
            break                      # comment: the rest of the line is not code
        i += 1
    return sq, dq

HEREDOC = re.compile(r"""<<-?\s*(?!<)(['"]?)([A-Za-z_]\w*)\1""")

def shell_lines(text):
    out, term, sq, dq = [], None, False, False
    for i, line in enumerate(text.splitlines()):
        if term is not None:
            if line.strip() == term:
                term = None
            continue
        if sq or dq:                   # continuation of a string opened earlier
            sq, dq = scan_quotes(line, sq, dq)
            continue
        out.append((i, line))
        m = HEREDOC.search(line)
        if m:
            term = m.group(2)
            continue
        sq, dq = scan_quotes(line, False, False)
    return out

lines = shell_lines(text)

assigns = {}
for _, line in lines:
    m = re.match(r'\s*([A-Za-z_]\w*)=(.*)$', line)
    if m and m.group(1) != "OUT_DIR":
        assigns[m.group(1)] = m.group(2).strip()

SENT = "\x00OUT\x00"

def expand(text):
    for _ in range(4):
        def sub(m):
            name = m.group(1) or m.group(2)
            if name == "OUT_DIR":
                return SENT
            return assigns.get(name, m.group(0))
        new = re.sub(r'\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)', sub, text)
        if new == text:
            break
        text = new
    # ${OUT_DIR:?...} and ${OUT_DIR:-...} never survive as a path fragment
    text = re.sub(r'\$\{OUT_DIR[:$][^}]*\}', SENT, text)
    return text

def strip_quotes(text):
    return text.replace('"', "").replace("'", "").strip()

def trailing_glob(text):
    """True only when the token ends in an UNQUOTED /*. `"$D/*"` keeps the star inside the
    quotes, so bash hands rm one literal path ending in an asterisk and nothing is removed -
    a spelling that looks like the working one and empties nothing."""
    seen, sq, dq = [], False, False
    for ch in text:
        if sq:
            if ch == "'":
                sq = False
            else:
                seen.append((ch, True))
        elif dq:
            if ch == '"':
                dq = False
            else:
                seen.append((ch, True))
        elif ch == "'":
            sq = True
        elif ch == '"':
            dq = True
        else:
            seen.append((ch, False))
    while seen and seen[-1] == ("/", False):
        seen.pop()                    # `"$D"/*/` means the same thing as `"$D"/*`
    return len(seen) >= 2 and seen[-1] == ("*", False) and seen[-2] == ("/", False)

REDIR = re.compile(r'^\d*(?:>>?|<|&>|>&)')

# --- ordered stream of (op, target, guarded) -------------------------------------------
# `guarded` is the R77 distinction: a removal only counts if it runs every time the script
# runs. Text order alone credited `if false; then rm -rf "$RAW"; fi`, and a
# `[[ ... ]] && rm -rf "$RAW"` reads the same way one fragment later.
OPEN = re.compile(r'^\s*(if|for|while|until|select|case)\b')
CLOSE = re.compile(r'^\s*(fi|done|esac)\b')
FUNC = re.compile(r'^\s*(?:function\s+)?[A-Za-z_][\w-]*\s*\(\s*\)\s*\{')
# `cmd || { echo ...; exit 1; }` - the group is a block too, and without it the closing
# brace drives the balance negative and the whole file reads as unparseable.
GROUP = re.compile(r'^\s*\{(?:\s|$)')
BRACE_CLOSE = re.compile(r'^\s*\}\s*$')
LEADIN = re.compile(r'^\s*(?:then|else|do)\s+')

ops = []
depth = 0
for _, line in lines:
    parts = re.split(r'(;;|;|&&|\|\|)', line)
    prev_sep = None
    for k, piece in enumerate(parts):
        if k % 2:
            prev_sep = piece
            continue
        frag = LEADIN.sub('', piece)
        if FUNC.search(piece) or OPEN.match(frag) or GROUP.match(frag):
            depth += 1
        elif CLOSE.match(frag) or BRACE_CLOSE.match(piece):
            depth -= 1
        # `rm -fr` and `rm -r -f` are the same command as `rm -rf`. Pinning one spelling
        # rejected correct runners and then told the operator they removed nothing.
        m = re.match(r'\s*(rm|mkdir)\s+((?:-[A-Za-z]+\s+)+)(.*)$', frag)
        if m:
            flags = set(m.group(2).replace("-", " ").replace(" ", ""))
            if m.group(1) == "rm" and not {"r", "f"} <= flags:
                m = None
            elif m.group(1) == "mkdir" and "p" not in flags:
                m = None
        if m:
            op = m.group(1)
            guarded = depth > 0 or prev_sep in ("&&", "||")
            for target in m.group(3).split():
                if target.startswith("-") or REDIR.match(target):
                    continue          # a flag, or `2>/dev/null`: not a path being removed
                raw = expand(target)
                ops.append((op, strip_quotes(raw), guarded, trailing_glob(raw)))
        prev_sep = None

if depth != 0:
    # Better to say the structure was unreadable than to judge it anyway: an unbalanced
    # count means every `guarded` flag after the imbalance is arbitrary.
    print("its block structure did not balance (depth=%d); conditional and unconditional "
          "cannot be told apart" % depth)
    sys.exit(1)

# `rm -rf "$D"/*` empties D without removing D, which satisfies this contract just as well
# - what it pins is that nothing from the previous run survives, not which of the two
# spellings the runner picked. Only a removal whose trailing `/*` is OUTSIDE the quotes
# counts: `"$D/*.profraw"` removes a subset, and `"$D/*"` removes nothing at all.
def covers(removal, globbed, target):
    base = removal[:-2] if globbed else removal
    # `$OUT_DIR/raw/../raw2` starts with `$OUT_DIR/raw/` as text but is a sibling on disk.
    base = posixpath.normpath(base.rstrip("/")) if base.rstrip("/") else base
    target = posixpath.normpath(target)
    if target == base:
        return True
    if not target.startswith(base + "/"):
        return False
    # `*` does not match a leading dot unless dotglob is set, so emptying a directory with a
    # glob leaves its dot-named children behind.
    return not (globbed and any(seg.startswith(".") for seg in target[len(base) + 1:].split("/")))

removed_all = [(t, g) for op, t, guarded, g in ops if op == "rm" and not guarded]
problems = []
removed = []
conditional = []
for op, target, guarded, globbed in ops:
    if op == "rm":
        (conditional if guarded else removed).append((target, globbed))
        continue
    if SENT not in target:          # not under OUT_DIR; not this contract's business
        continue
    if any(covers(r, g, target) for r, g in removed):
        continue
    # One line is all an operator gets, so it has to name the right cause. Reporting a
    # misdirected `rm` as a missing one sends them looking for code that is already there.
    # Each branch is a claim about the WHOLE script, so it is checked against the whole op
    # stream - `removed` only holds what was seen before this create.
    shown = target.replace(SENT, "$OUT_DIR")
    if any(covers(r, g, target) for r, g in removed_all):
        problems.append("%s, but the removal that covers it runs after the create, not "
                        "before" % shown)
    elif any(covers(r, g, target) for r, g in conditional):
        problems.append("%s, but its removal is reached only through a branch, a && guard "
                        "or a function body, so it does not run every time" % shown)
    elif removed_all:
        others = sorted({r.replace(SENT, "$OUT_DIR") for r, _ in removed_all})
        problems.append("%s, but the only unconditional removals target %s"
                        % (shown, ", ".join(others)))
    else:
        problems.append("%s, and the script removes nothing unconditionally" % shown)

if problems:
    print("creates " + "; ".join(problems))
    sys.exit(1)
if not any(op == "mkdir" and SENT in t for op, t, _, _ in ops):
    print("creates nothing under OUT_DIR; scan had nothing to judge")
    sys.exit(1)
sys.exit(0)
PY
}

for runner in $RUNNER_GLOB; do
  [[ -f "$runner" ]] || continue
  if why="$(scan_runner "$runner")"; then
    ok "$(basename "$runner") clears every directory it creates under OUT_DIR"
  else
    bad "$(basename "$runner") $why"
  fi
done

# --- 3. negative controls --------------------------------------------------------------
mk_fake() { printf '%s\n' "$2" >"$WORK/$1"; }

mk_fake run_coverage_nofix.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_nofix.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a runner that creates raw/ without removing it'
else
  ok 'negative control: scan rejects a runner that creates raw/ without removing it'
fi

mk_fake run_coverage_wrongpath.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -rf "$OUT_DIR/old"
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_wrongpath.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a removal of a different path than the one created'
else
  ok 'negative control: scan rejects a removal of a different path than the one created'
fi

mk_fake run_coverage_othername.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
PROFILE_SCRATCH="$OUT_DIR/profiles"
rm -rf "$PROFILE_SCRATCH"
mkdir -p "$PROFILE_SCRATCH"'
if scan_runner "$WORK/run_coverage_othername.sh" >/dev/null 2>&1; then
  ok 'negative control: scan accepts the right relation under a name it has never seen'
else
  bad 'negative control: scan rejected a correct runner because of the variable name'
fi

mk_fake run_coverage_deadbranch.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
if [[ -n "${NEVER_SET:-}" ]]; then
  rm -rf "$RAW"
fi
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_deadbranch.sh" >/dev/null 2>&1; then
  bad 'negative control: scan credited a removal that only runs inside a branch'
else
  ok 'negative control: scan rejects a removal reached only through a branch'
fi

mk_fake run_coverage_andguard.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
[[ -n "${NEVER_SET:-}" ]] && rm -rf "$RAW"
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_andguard.sh" >/dev/null 2>&1; then
  bad 'negative control: scan credited a removal guarded by &&'
else
  ok 'negative control: scan rejects a removal guarded by &&'
fi

# The opposite polarity of those two: conditional is only disqualifying for the REMOVAL.
mk_fake run_coverage_condmkdir.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -rf "$RAW"
if [[ -n "${WANT:-}" ]]; then
  mkdir -p "$RAW"
fi'
if scan_runner "$WORK/run_coverage_condmkdir.sh" >/dev/null 2>&1; then
  ok 'negative control: scan accepts a conditional create after an unconditional removal'
else
  bad 'negative control: scan rejected a conditional create that is preceded by a real removal'
fi

# The lexer: every real runner embeds python, whose `for`/`if` sit at the start of a line.
# Read as shell they open blocks nothing closes, and the removal below them - which runs
# every time - would be filed as conditional. The python here deliberately precedes it.
mk_fake run_coverage_embedded.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
python3 - <<PY
for x in range(3):
    if x:
        pass
PY
v="$(python3 -c '"'"'import sys
for x in range(3):
    print(x)
'"'"')"
RAW="$OUT_DIR/raw"
rm -rf "$RAW"
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_embedded.sh" >/dev/null 2>&1; then
  ok 'negative control: embedded python does not turn an unconditional removal conditional'
else
  bad "negative control: the lexer read embedded python as shell ($(scan_runner "$WORK/run_coverage_embedded.sh" || true))"
fi

# --- R78: `rm -rf "$DIR"/*` empties the directory instead of removing it ----------------
# The contract is about what survives into the next run, not about which of the two
# spellings a runner picked, and `/*` is the spelling an operator reaches for when the
# directory itself must stay (a mount point, a symlink, a path someone else holds open).
# Before this, the scan compared the removal target verbatim, so the trailing `/*` matched
# nothing and the runner was reported as never removing anything.
mk_fake run_coverage_globwipe.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -rf "$RAW"/*
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_globwipe.sh" >/dev/null 2>&1; then
  ok 'negative control: scan accepts a directory emptied with a trailing /* instead of removed'
else
  bad "negative control: scan rejected a runner that empties raw/ with a trailing /* ($(scan_runner "$WORK/run_coverage_globwipe.sh" 2>&1 || true))"
fi

# The opposite polarity: stripping the `/*` must not make every glob match.
mk_fake run_coverage_globwrongpath.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -rf "$OUT_DIR/old"/*
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_globwrongpath.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a trailing /* on a path other than the one created'
else
  ok 'negative control: scan still rejects a trailing /* on a different path'
fi

# Two ways stripping the `/*` could have gone wrong, pinned so it cannot drift back:
# a glob that removes only SOME of the directory, and a prefix that is not a parent.
mk_fake run_coverage_globsubset.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -rf "$RAW"/*.profraw
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_globsubset.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a glob that removes only part of the directory'
else
  ok 'negative control: scan rejects a glob that removes only part of the directory'
fi

mk_fake run_coverage_globprefix.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
rm -rf "$OUT_DIR/raw"/*
mkdir -p "$OUT_DIR/rawdata"'
if scan_runner "$WORK/run_coverage_globprefix.sh" >/dev/null 2>&1; then
  bad 'negative control: scan treated $OUT_DIR/raw as covering the sibling $OUT_DIR/rawdata'
else
  ok 'negative control: a removed path does not cover a sibling that merely shares its prefix'
fi

# Three more ways stripping the `/*` could have gone wrong, all demonstrated against the
# first version of this fix (2026-09-14 adversarial round).
mk_fake run_coverage_globinquotes.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -rf "$RAW/*"
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_globinquotes.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted "$RAW/*" - the star is quoted, so nothing is removed'
else
  ok 'negative control: scan rejects "$RAW/*", where the quoted star removes nothing'
fi

mk_fake run_coverage_dotchild.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
rm -rf "$OUT_DIR"/*
mkdir -p "$OUT_DIR/.raw"'
if scan_runner "$WORK/run_coverage_dotchild.sh" >/dev/null 2>&1; then
  bad 'negative control: scan credited "$OUT_DIR"/* with removing a dot-named child'
else
  ok 'negative control: a /* glob is not credited with removing a dot-named child'
fi

mk_fake run_coverage_redirect.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -rf "$OUT_DIR/other" 2>/dev/null
mkdir -p "$RAW"'
why_redirect="$(scan_runner "$WORK/run_coverage_redirect.sh" 2>&1 || true)"
case "$why_redirect" in
  *"2>/dev/null"*) bad "negative control: a redirection was listed as a removal target ($why_redirect)" ;;
  *"removals target \$OUT_DIR/other"*) ok 'a redirection on the rm line is not listed as a removal target' ;;
  *) bad "negative control: unexpected verdict for a redirection on the rm line (${why_redirect:-nothing})" ;;
esac

# The verdict is a prefix question - a removal below the create does not help this run - but
# the REASON is a statement about the whole script, and must not deny code that is there.
mk_fake run_coverage_rmafter.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
mkdir -p "$RAW"
rm -rf "$RAW"'
why_after="$(scan_runner "$WORK/run_coverage_rmafter.sh" 2>&1 || true)"
case "$why_after" in
  *"runs after the create, not before"*) ok 'a removal placed after the create is reported as ordered wrongly, not as missing' ;;
  *) bad "a removal after the create was reported as something else (said: ${why_after:-nothing})" ;;
esac

# Spellings of the same command that must not be rejected, and a text prefix that is not a
# parent on disk. All three were demonstrated rejections/acceptances (2026-09-14).
mk_fake run_coverage_flagorder.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -fr "$RAW"
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_flagorder.sh" >/dev/null 2>&1; then
  ok 'negative control: scan accepts `rm -fr`, the same command spelled differently'
else
  bad "negative control: scan rejected \`rm -fr\` ($(scan_runner "$WORK/run_coverage_flagorder.sh" 2>&1 || true))"
fi

mk_fake run_coverage_splitflags.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -r -f "$RAW"
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_splitflags.sh" >/dev/null 2>&1; then
  ok 'negative control: scan accepts `rm -r -f`, the same command spelled differently'
else
  bad "negative control: scan rejected \`rm -r -f\` ($(scan_runner "$WORK/run_coverage_splitflags.sh" 2>&1 || true))"
fi

# A single-file removal is still out of scope - widening the flag match must not widen that.
mk_fake run_coverage_nonrecursive.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -f "$RAW"
mkdir -p "$RAW"'
if scan_runner "$WORK/run_coverage_nonrecursive.sh" >/dev/null 2>&1; then
  bad 'negative control: scan credited a non-recursive `rm -f` with clearing a directory'
else
  ok 'negative control: scan does not credit a non-recursive `rm -f` with clearing a directory'
fi

mk_fake run_coverage_dotdot.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
rm -rf "$OUT_DIR/raw"
mkdir -p "$OUT_DIR/raw/../raw2"'
if scan_runner "$WORK/run_coverage_dotdot.sh" >/dev/null 2>&1; then
  bad 'negative control: scan read $OUT_DIR/raw/../raw2 as living inside $OUT_DIR/raw'
else
  ok 'negative control: a .. that walks back out is not covered by the removal it passed through'
fi

# --- R78b: the reason has to be the reason -----------------------------------------------
# The scan prints one line and that line is what an operator acts on. A single message for
# every rejection sent them looking for a missing `rm` when the `rm` was there and pointed
# somewhere else. Each of the three distinguishable causes must name itself.
why_wrongpath="$(scan_runner "$WORK/run_coverage_wrongpath.sh" 2>&1 || true)"
case "$why_wrongpath" in
  *"unconditional removals target"*) ok 'a path mismatch is reported as a path mismatch' ;;
  *) bad "a path mismatch was diagnosed as something else (said: ${why_wrongpath:-nothing})" ;;
esac

why_deadbranch="$(scan_runner "$WORK/run_coverage_deadbranch.sh" 2>&1 || true)"
case "$why_deadbranch" in
  *"does not run every time"*) ok 'a removal that exists but is conditional is reported as conditional' ;;
  *) bad "a conditional removal was diagnosed as something else (said: ${why_deadbranch:-nothing})" ;;
esac

why_nofix="$(scan_runner "$WORK/run_coverage_nofix.sh" 2>&1 || true)"
case "$why_nofix" in
  *"removes nothing unconditionally"*) ok 'a runner that removes nothing is reported as removing nothing' ;;
  *) bad "a missing removal was diagnosed as something else (said: ${why_nofix:-nothing})" ;;
esac

# And when the lexer cannot follow a script, the gate must say so rather than judge it: the
# runner below removes correctly, so any verdict other than "unreadable" is luck.
mk_fake run_coverage_unbalanced.sh '#!/usr/bin/env bash
OUT_DIR="${OUT_DIR:?}"
RAW="$OUT_DIR/raw"
rm -rf "$RAW"
if [[ -n "${X:-}" ]]; then
mkdir -p "$RAW"'
why_unbalanced="$(scan_runner "$WORK/run_coverage_unbalanced.sh" 2>&1 || true)"
case "$why_unbalanced" in
  *"did not balance"*) ok 'negative control: scan reports an unreadable structure instead of judging it' ;;
  *) bad "negative control: scan judged a script whose structure it could not follow (said: ${why_unbalanced:-nothing})" ;;
esac

printf '[coverage-raw-reset] pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
