#!/usr/bin/env bash
# R41: pins that a native engine checker's afl-showmap number is evidence from THIS run,
# measured on a binary whose instrumentation scope the checker verified.
#
# check_onnx_native_engines.sh:104-111 (pre-fix) wrote the map into a reused OUT_DIR
# without removing it first and never asked what afl-showmap had instrumented. Measured on
# dev 2026-09-14 against a sandbox PROJECT_ROOT: with a stub afl-showmap that exits 0 and
# writes nothing, and a 7-line map left in OUT_DIR by an earlier run, the checker reported
# `afl-showmap tuples=7` and exited 0 - a coverage claim carried over from a run that is
# not the one being reported. The same run used /bin/true as the AFL++ replay: a binary
# with no AFL++ instrumentation at all passed the arm whose entire purpose is to show the
# engine sees edges.
#
# An odd-one-out, not a new contract. check_gguf_native_engines.sh:152-169 and
# check_safetensors_native_engines.sh:142-153 both assert instrumentation_scope and both
# `rm -f "$AFL_MAP"` before the run, gguf saying why in a comment: "`|| true` over a map
# file left by an earlier run means a completely failed afl-showmap still counts its
# tuples." ONNX was the one checker that did neither.
#
# ONNX's expected scope is driver_only, not library: onnxruntime is a separate .so, so the
# AFL++ driver carries its own edges only. That is the value already asserted for the
# shipped ONNX drivers by check_engine_mode_labels.sh:234-246, so this is the same
# contract read where the number is produced, not only where the binary is labelled.
# A file:line is never split across two lines here: a citation sweep reads one line.
#
# Assertions, because none of them holds alone:
#   1. behavioural - the REAL ONNX checker, against a sandbox PROJECT_ROOT and a stub
#      afl-showmap, must refuse a map it did not write this run, and must refuse a replay
#      that carries no AFL++ instrumentation.
#   2. the opposite polarity - the same sandbox with a fresh map and an AFL-marked replay
#      must still pass and still report the tuple count, so the fix cannot degrade into
#      "refuse everything". The stub records being called, so a vacuous run is visible.
#   3. class scan - every check_*_native_engines.sh that writes an afl-showmap map must
#      remove that map, unconditionally, before the run that writes it, and must decide the
#      replay's instrumentation_scope against a named scope before measuring it. Neither
#      half can then come back one checker at a time.
#   4. negative controls - the scan must reject a missing removal, a removal of a different
#      path, one that runs after the showmap, one reached only through a branch or an `&&`,
#      a scope that is only logged, a scope test that names no scope, and a contract
#      written inside a heredoc body; and it must still accept the same contract written
#      with other variable names, `test`, and `rm -f --`. The behavioural harness must be
#      able to report a checker that accepts a stale map, or its verdicts mean nothing.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
CHECKER_GLOB="$PROJECT_ROOT/scripts/check_"*"_native_engines.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/engine-check-showmap-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

# --- stubs -------------------------------------------------------------------------------
# The AFL++ tools are stubbed rather than required: this gate must mean the same thing on a
# machine with AFL++ installed and on one without, and a real afl-showmap cannot be made to
# write nothing on demand. The stub is placed FIRST on PATH, so it also shadows a real one.
#
# LINES is how many tuples it writes; empty means "exit 0 having written no map", which is
# the shape that makes a leftover map look like this run's answer. It records every call,
# so an arm that never reached afl-showmap cannot pass as one that did.
mkdir -p "$WORK/bin"
cat >"$WORK/bin/afl-showmap" <<'STUB'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf 'afl-showmap -o %s\n' "$out" >>"${SHOWMAP_CALLS:?}"
if [[ -n "${SHOWMAP_LINES:-}" && -n "$out" ]]; then
  seq 1 "$SHOWMAP_LINES" >"$out"
fi
exit 0
STUB
printf '#!/usr/bin/env bash\nexit 0\n' >"$WORK/bin/afl-clang-fast++"
chmod +x "$WORK/bin/afl-showmap" "$WORK/bin/afl-clang-fast++"

# A real ELF that also looks AFL-instrumented, the shape check_engine_mode_labels.sh:103
# uses. /bin/true defines no parser symbol, so instrumentation_scope answers driver_only -
# which is what a correctly built ONNX driver answers. Built from /bin/true and not
# borrowed from harnesses/, which is gitignored: borrowing makes the case vanish on a
# fresh clone.
afl_marked_copy() {
  cp /bin/true "$1"
  printf '__AFL_SHM_ID __afl_area_ptr' >>"$1"
  chmod +x "$1"
}

# The sandbox the checker runs against. Stubs exit 0, which is the point: they are what let
# an unguarded checker run all the way to its tuple count.
onnx_sandbox() { # onnx_sandbox <root> <marked:0|1>
  local root="$1" marked="$2"
  mkdir -p "$root/harnesses/libfuzzer" "$root/harnesses/aflpp" "$root/scripts/lib" "$root/tmp"
  local b
  for b in onnxruntime_loader_fuzzer onnxruntime_loader_replay; do
    printf '#!/usr/bin/env bash\nexit 0\n' >"$root/harnesses/libfuzzer/$b"
    chmod +x "$root/harnesses/libfuzzer/$b"
  done
  printf '#!/usr/bin/env bash\nexit 0\n' >"$root/scripts/build_aflpp_onnx_native.sh"
  chmod +x "$root/scripts/build_aflpp_onnx_native.sh"
  cp "$PROJECT_ROOT/scripts/lib/engine_mode.sh" "$root/scripts/lib/engine_mode.sh"
  if [[ "$marked" -eq 1 ]]; then
    afl_marked_copy "$root/harnesses/aflpp/onnxruntime_loader_replay"
  else
    cp /bin/true "$root/harnesses/aflpp/onnxruntime_loader_replay"
  fi
  printf 'x' >"$root/seed.onnx"
}

# Runs a checker and prints rc, the tuple count it reported, and whether afl-showmap was
# reached at all. TMPDIR points inside this gate's scratch: the ONNX checker preserves its
# mktemp directory on a non-zero exit, and this gate's job is to produce non-zero exits.
probe() { # probe <checker> <root> <showmap_lines> <stale_lines> <log>
  local checker="$1" root="$2" lines="$3" stale="$4" log="$5" rc=0
  local out="$root/out" calls="$root/showmap-calls"
  rm -rf "$out"; mkdir -p "$out"; : >"$calls"
  [[ -n "$stale" ]] && seq 1 "$stale" >"$out/afl-showmap.txt"
  env PATH="$WORK/bin:$PATH" TMPDIR="$root/tmp" \
      PROJECT_ROOT="$root" OUT_DIR="$out" SEED="$root/seed.onnx" \
      SHOWMAP_CALLS="$calls" SHOWMAP_LINES="$lines" \
      timeout 300 bash "$checker" --require-aflpp >"$log" 2>&1 || rc=$?
  printf 'rc=%s tuples=%s showmap=%s' "$rc" \
    "$(sed -n 's/.*tuples=\([0-9]*\).*/\1/p' "$log" | tail -1)" \
    "$([[ -s "$calls" ]] && echo yes || echo no)"
}

# --- 1+2. behavioural ---------------------------------------------------------------------
CHECKER="$PROJECT_ROOT/scripts/check_onnx_native_engines.sh"
if [[ ! -f "$CHECKER" ]]; then
  bad "$(basename "$CHECKER") is missing; the behavioural half cannot run"
else
  ROOT="$WORK/onnx-marked"; onnx_sandbox "$ROOT" 1

  # A map afl-showmap did not write this run must not be counted. The stale map is 7 lines
  # so a carried-over pass is recognisable in the output by its number.
  res="$(probe "$CHECKER" "$ROOT" "" 7 "$WORK/stale.log")"
  case "$res" in
    *showmap=no*) bad "the stale-map probe never reached afl-showmap ($res); it proves nothing" ;;
    rc=0*)        bad "$(basename "$CHECKER") counted a map left by an earlier run ($res)"
                  grep -n 'tuples=' "$WORK/stale.log" | sed 's/^/       /' ;;
    *)            ok "$(basename "$CHECKER") refuses a map it did not write this run ($res)" ;;
  esac

  # An uninstrumented replay cannot produce engine coverage, whatever a map says.
  ROOT_PLAIN="$WORK/onnx-plain"; onnx_sandbox "$ROOT_PLAIN" 0
  res="$(probe "$CHECKER" "$ROOT_PLAIN" 5 "" "$WORK/plain.log")"
  case "$res" in
    rc=0*) bad "$(basename "$CHECKER") measured coverage on a replay with no AFL++ instrumentation ($res)"
           grep -n 'tuples=' "$WORK/plain.log" | sed 's/^/       /' ;;
    *)     ok "$(basename "$CHECKER") refuses a replay with no AFL++ instrumentation ($res)" ;;
  esac

  # Opposite polarity: a fresh map on an instrumented replay must still pass, and must still
  # report the count. A guard that refuses everything would satisfy both cases above.
  res="$(probe "$CHECKER" "$ROOT" 5 "" "$WORK/fresh.log")"
  case "$res" in
    rc=0*tuples=5*showmap=yes*) ok "$(basename "$CHECKER") still reports a map written this run ($res)" ;;
    *) bad "$(basename "$CHECKER") rejects a fresh map on an instrumented replay ($res)"
       sed -n '1,8p' "$WORK/fresh.log" | sed 's/^/       /' ;;
  esac

  # And the harness must be able to see an acceptance, or every verdict above is untested.
  cat >"$WORK/check_stalefake_native_engines.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
AFL_MAP="$OUT_DIR/afl-showmap.txt"
afl-showmap -q -o "$AFL_MAP" -- "$PROJECT_ROOT/harnesses/aflpp/onnxruntime_loader_replay" "$SEED" \
  >"$OUT_DIR/afl-showmap.log" 2>&1
tuples="$(wc -l < "$AFL_MAP" | tr -d ' ')"
[[ "$tuples" -gt 0 ]] || exit 1
echo "[fake] afl-showmap tuples=$tuples"
FAKE
  res="$(probe "$WORK/check_stalefake_native_engines.sh" "$ROOT" "" 7 "$WORK/fake.log")"
  case "$res" in
    rc=0*tuples=7*) ok "negative control: the harness reports a checker that counts a stale map ($res)" ;;
    *) bad "negative control: a checker that counts a stale map was not reported as accepting ($res)" ;;
  esac
fi

# --- 3. class scan ------------------------------------------------------------------------
# Two clauses, read structurally rather than by grep: the map must be removed before the run
# that writes it, and the replay's scope must be decided before the number is taken.
#
# Paths are resolved through their assignments, so the contract does not depend on what the
# variable is called. Comments and heredoc bodies are not code. A removal counts only when it
# runs whenever the showmap runs: not deeper in the block structure, not behind `&&`.
#
# What it does NOT establish, said out loud so a green scan is not over-read: that the binary
# whose scope was decided is the one afl-showmap was handed (the behavioural half pins that,
# and only for ONNX); that a variable reassigned between the removal and the run still names
# the same path (R84); and it does not credit a glob removal such as `rm -rf "$OUT_DIR"/*` -
# remove the map path itself, or the scan will say the map is not removed.
scan_checker() {
  python3 - "$1" <<'PY'
import posixpath, re, sys

text = open(sys.argv[1], encoding="utf-8").read()

# --- lexer: only shell lines, and only the code part of them -----------------------------
def code_of(line, sq, dq):
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

# A command split across lines is one command: `-o` may sit on the continuation.
def join_continuations(lines):
    out, buf = [], ""
    for line in lines:
        s = line.rstrip()
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        out.append(buf + line)
        buf = ""
    if buf:
        out.append(buf)
    return out

lines = join_continuations(shell_lines(text))

# --- variable expansion ------------------------------------------------------------------
# Both sides of the comparison go through the same expansion, so an unresolved $OUT_DIR is
# not a problem: it stays literal in the removal and in the -o argument alike.
assigns = {}
for line in lines:
    m = re.match(r'\s*(?:local\s+)?([A-Za-z_]\w*)=(.*)$', line)
    if m:
        assigns[m.group(1)] = m.group(2).strip()

def expand(s):
    for _ in range(4):
        new = re.sub(r'\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)',
                     lambda m: assigns.get(m.group(1) or m.group(2), m.group(0)), s)
        if new == s:
            break
        s = new
    return s

def path_of(token):
    return expand(token).replace('"', "").replace("'", "").strip()

# --- ordered stream of operations ---------------------------------------------------------
OPEN = re.compile(r'^\s*(if|for|while|until|select|case)\b')
CLOSE = re.compile(r'^\s*(fi|done|esac)\b')
FUNC = re.compile(r'^\s*(?:function\s+)?[A-Za-z_][\w-]*\s*\(\s*\)\s*\{')
GROUP = re.compile(r'^\s*\{(?:\s|$)')
BRACE_CLOSE = re.compile(r'^\s*\}\s*$')
LEADIN = re.compile(r'^\s*(?:then|else|do)\s+')

# run_aflpp_showmap is check_safetensors_native_engines.sh:117's wrapper over the cargo-afl
# and standalone spellings. Only an invocation that names an output file writes a map: the
# `command -v afl-showmap` probes and the wrapper's own inner calls carry no -o.
SHOWMAP = re.compile(r'(?:^|[\s;&|(])(?:afl-showmap|run_aflpp_showmap|cargo(?:\s+\+\S+)?\s+afl\s+showmap)(?:\s|$)')
DASH_O = re.compile(r'(?:^|\s)-o(?:=|\s+)(\S+)')
SCOPE_ASSIGN = re.compile(r'^\s*(?:local\s+)?([A-Za-z_]\w*)=.*\binstrumentation_scope\b')
COND = re.compile(r'\[\[(.+?)\]\]|(?<!\[)\[(?!\[)(.+?)(?<!\])\](?!\])|\btest\b([^;&|]*)')
CASE_OPEN = re.compile(r'^\s*case\s+(.+?)\s+in\b')
SCOPE_NAME = re.compile(r'\b(library|driver_only|none)\b')
REDIR = re.compile(r'^\d*(?:>>?|<|&>|>&)')

ops, cases, depth = [], [], 0
for line in lines:
    parts = re.split(r'(;;|;|&&|\|\|)', line)
    prev_sep = None
    for k, piece in enumerate(parts):
        if k % 2:
            prev_sep = piece
            continue
        frag = LEADIN.sub('', piece)
        here = depth
        if FUNC.search(piece) or OPEN.match(frag) or GROUP.match(frag):
            depth += 1
        elif CLOSE.match(frag) or BRACE_CLOSE.match(piece):
            depth -= 1
        guarded = prev_sep in ("&&", "||")
        prev_sep = None

        m = re.match(r'\s*rm\s+((?:-[A-Za-z-]+\s+)+)(.*)$', frag)
        if m and "f" in set(m.group(1).replace("-", " ").replace(" ", "")):
            for target in m.group(2).split():
                if target.startswith("-") or REDIR.match(target):
                    continue
                ops.append(("rm", path_of(target), here, guarded))
        if SHOWMAP.search(frag):
            o = DASH_O.search(frag)
            if o:
                ops.append(("showmap", path_of(o.group(1)), here, guarded,
                            o.group(1).replace('"', "").replace("'", "")))
        m = SCOPE_ASSIGN.match(frag)
        if m:
            ops.append(("scope", m.group(1), here, guarded))
        for m in COND.finditer(frag):
            interior = next(g for g in m.groups() if g is not None)
            if SCOPE_NAME.search(interior):
                for name in re.findall(r'\$\{?([A-Za-z_]\w*)\}?', interior):
                    ops.append(("scopetest", name, here, guarded))
        # `case "$scope" in library) ... esac` decides just as a test does, and its
        # branch labels usually sit on later lines than its subject. Held open until
        # esac so the subject and the scope name it is matched against can be read
        # together; without that the whole spelling reads as a scope that is never
        # decided, and the scan would teach people to write `[[ ]]` instead.
        m = CASE_OPEN.match(frag)
        if m:
            cases.append([re.findall(r'\$\{?([A-Za-z_]\w*)\}?', m.group(1)),
                          bool(SCOPE_NAME.search(frag)), here, guarded])
        elif cases:
            if CLOSE.match(frag) and frag.strip().startswith("esac"):
                names, named, d_case, g_case = cases.pop()
                if named:
                    for name in names:
                        ops.append(("scopetest", name, d_case, g_case))
            elif SCOPE_NAME.search(frag):
                cases[-1][1] = True

if depth != 0:
    print("its block structure did not balance (depth=%d); conditional and unconditional "
          "cannot be told apart" % depth)
    sys.exit(1)

maps = [(i, o) for i, o in enumerate(ops) if o[0] == "showmap"]
if not maps:
    print("not in the class: it writes no afl-showmap map")
    sys.exit(2)

def covers(removed, target):
    a = posixpath.normpath(removed.rstrip("/")) if removed.rstrip("/") else removed
    b = posixpath.normpath(target)
    return b == a or b.startswith(a + "/")

problems = []
for i, (_, target, d_run, _, shown) in maps:
    fresh = [o for j, o in enumerate(ops)
             if j < i and o[0] == "rm" and not o[3] and o[2] <= d_run and covers(o[1], target)]
    if not fresh:
        problems.append("%s is measured without an unconditional removal before the run "
                        "that writes it" % shown)
    decided = set()
    for j, o in enumerate(ops):
        if j < i and o[0] == "scope" and not o[3] and o[2] <= d_run:
            decided.add(o[1])
    tested = {o[1] for j, o in enumerate(ops)
              if j < i and o[0] == "scopetest" and o[1] in decided}
    if not decided:
        problems.append("%s is measured without asking instrumentation_scope first" % shown)
    elif not tested:
        problems.append("instrumentation_scope is recorded but never decided against a "
                        "named scope before %s is measured" % shown)

if problems:
    print("; ".join(problems))
    sys.exit(1)
PY
}

CLASS=0
for checker in $CHECKER_GLOB; do
  [[ -f "$checker" ]] || continue
  name="$(basename "$checker")"
  why="$(scan_checker "$checker")" && verdict=0 || verdict=$?
  case "$verdict" in
    0) CLASS=$((CLASS + 1)); ok "$name removes its map before the run and decides the replay's scope first" ;;
    2) printf '  --   %s %s\n' "$name" "$why" ;;
    *) CLASS=$((CLASS + 1)); bad "$name $why" ;;
  esac
done
# A class that quietly empties is the way a scan stops meaning anything: the three native
# engine checkers that run afl-showmap today are onnx, gguf and safetensors.
if [[ "$CLASS" -ge 3 ]]; then
  ok "the scan covered $CLASS checkers that write an afl-showmap map"
else
  bad "only $CLASS checker(s) were scanned; the class has shrunk and the contract is no longer pinned"
fi

# --- 4. negative controls -----------------------------------------------------------------
# Each shape is a plausible careless edit of the compliant text, not a contrivance.
mk_fake() { printf '%s\n' "$2" >"$WORK/$1"; }

COMPLIANT='#!/usr/bin/env bash
scope="$(instrumentation_scope "$REPLAY")"
[[ "$scope" == "driver_only" ]] || exit 1
AFL_MAP="$OUT_DIR/afl-showmap.txt"
rm -f "$AFL_MAP"
afl-showmap -q -o "$AFL_MAP" -- "$REPLAY" "$SEED"'

expect_reject() { # expect_reject <file> <what>
  if scan_checker "$WORK/$1" >/dev/null 2>&1; then
    bad "negative control: scan accepted $2"
  else
    ok "negative control: scan rejects $2"
  fi
}
expect_accept() { # expect_accept <file> <what>
  if scan_checker "$WORK/$1" >/dev/null 2>&1; then
    ok "negative control: scan accepts $2"
  else
    bad "negative control: scan failed $2 ($(scan_checker "$WORK/$1" || true))"
  fi
}

mk_fake check_norm_native_engines.sh "${COMPLIANT/rm -f \"\$AFL_MAP\"$'\n'/}"
expect_reject check_norm_native_engines.sh 'a map that is never removed'

mk_fake check_otherpath_native_engines.sh '#!/usr/bin/env bash
scope="$(instrumentation_scope "$REPLAY")"
[[ "$scope" == "driver_only" ]] || exit 1
AFL_MAP="$OUT_DIR/afl-showmap.txt"
rm -f "$OUT_DIR/afl-showmap.log"
afl-showmap -q -o "$AFL_MAP" -- "$REPLAY" "$SEED"'
expect_reject check_otherpath_native_engines.sh 'a removal of a neighbouring path'

mk_fake check_after_native_engines.sh '#!/usr/bin/env bash
scope="$(instrumentation_scope "$REPLAY")"
[[ "$scope" == "driver_only" ]] || exit 1
AFL_MAP="$OUT_DIR/afl-showmap.txt"
afl-showmap -q -o "$AFL_MAP" -- "$REPLAY" "$SEED"
rm -f "$AFL_MAP"'
expect_reject check_after_native_engines.sh 'a removal that runs after the map is written'

mk_fake check_branch_native_engines.sh '#!/usr/bin/env bash
scope="$(instrumentation_scope "$REPLAY")"
[[ "$scope" == "driver_only" ]] || exit 1
AFL_MAP="$OUT_DIR/afl-showmap.txt"
if [[ "${FRESH:-0}" == 1 ]]; then
  rm -f "$AFL_MAP"
fi
afl-showmap -q -o "$AFL_MAP" -- "$REPLAY" "$SEED"'
expect_reject check_branch_native_engines.sh 'a removal reached only through a branch'

mk_fake check_andand_native_engines.sh '#!/usr/bin/env bash
scope="$(instrumentation_scope "$REPLAY")"
[[ "$scope" == "driver_only" ]] || exit 1
AFL_MAP="$OUT_DIR/afl-showmap.txt"
[[ -f "$AFL_MAP" ]] && rm -f "$AFL_MAP"
afl-showmap -q -o "$AFL_MAP" -- "$REPLAY" "$SEED"'
expect_reject check_andand_native_engines.sh 'a removal behind `&&`'

mk_fake check_logscope_native_engines.sh '#!/usr/bin/env bash
scope="$(instrumentation_scope "$REPLAY")"
echo "scope=$scope"
AFL_MAP="$OUT_DIR/afl-showmap.txt"
rm -f "$AFL_MAP"
afl-showmap -q -o "$AFL_MAP" -- "$REPLAY" "$SEED"'
expect_reject check_logscope_native_engines.sh 'a scope that is logged but never decided'

mk_fake check_emptyscope_native_engines.sh '#!/usr/bin/env bash
scope="$(instrumentation_scope "$REPLAY")"
[[ -n "$scope" ]] || exit 1
AFL_MAP="$OUT_DIR/afl-showmap.txt"
rm -f "$AFL_MAP"
afl-showmap -q -o "$AFL_MAP" -- "$REPLAY" "$SEED"'
expect_reject check_emptyscope_native_engines.sh 'a scope test that names no scope'

mk_fake check_noscope_native_engines.sh '#!/usr/bin/env bash
AFL_MAP="$OUT_DIR/afl-showmap.txt"
rm -f "$AFL_MAP"
afl-showmap -q -o "$AFL_MAP" -- "$REPLAY" "$SEED"'
expect_reject check_noscope_native_engines.sh 'a map measured without asking the scope at all'

mk_fake check_heredoc_native_engines.sh '#!/usr/bin/env bash
AFL_MAP="$OUT_DIR/afl-showmap.txt"
cat >/dev/null <<EOF
scope="$(instrumentation_scope "$REPLAY")"
[[ "$scope" == "driver_only" ]] || exit 1
rm -f "$AFL_MAP"
EOF
afl-showmap -q -o "$AFL_MAP" -- "$REPLAY" "$SEED"'
expect_reject check_heredoc_native_engines.sh 'a contract written inside a heredoc body'

# The opposite polarity of the eight above: the same contract spelled differently must not
# be failed. A scan that accepts one spelling teaches people to write that spelling.
mk_fake check_rename_native_engines.sh '#!/usr/bin/env bash
layer="$(instrumentation_scope "$BIN")"
case "$layer" in library) ;; *) exit 1 ;; esac
MAP_PATH="$CHECK_DIR/map.txt"
rm -f -- "$MAP_PATH"
run_aflpp_showmap -q -o "$MAP_PATH" -- "$BIN" "$GOOD"'
expect_accept check_rename_native_engines.sh 'the same contract under other names, with `case` and `rm -f --`'

mk_fake check_testcmd_native_engines.sh '#!/usr/bin/env bash
scope="$(instrumentation_scope "$REPLAY")"
test "$scope" = driver_only || exit 1
AFL_MAP="$OUT_DIR/afl-showmap.txt"
rm -rf "$AFL_MAP"
afl-showmap -q -o "$AFL_MAP" \
  -- "$REPLAY" "$SEED"'
expect_accept check_testcmd_native_engines.sh 'the same contract with `test`, `rm -rf` and a continued line'

mk_fake check_probeonly_native_engines.sh '#!/usr/bin/env bash
if command -v afl-showmap >/dev/null 2>&1; then
  echo "AFL++ present"
fi'
if scan_checker "$WORK/check_probeonly_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: a checker that only probes for afl-showmap was scanned as compliant'
else
  [[ $? -eq 2 ]] \
    && ok 'negative control: a checker that only probes for afl-showmap is reported as out of the class' \
    || bad 'negative control: a checker that only probes for afl-showmap was failed rather than excluded'
fi

printf '[engine-check-showmap-evidence] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
