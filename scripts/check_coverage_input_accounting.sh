#!/usr/bin/env bash
# R39: pins that a coverage runner knows how much of its corpus it actually measured.
#
# run_coverage_onnx.sh and run_coverage_safetensors.sh handed the whole corpus to one
# process and threw the exit status away with `|| true`. A target that dies on input 7 of
# 60 leaves a profile covering seven inputs, and the report that follows is published
# against the whole corpus with exit 0 and no diagnostic. The onnx harness already writes
# one JSON record per input on stdout (harnesses/coverage-onnx/harness.cc:126-131) and a
# loaded/failed/total line on stderr - the runner sent both to nowhere.
#
# run_coverage_gguf.sh:76-118 is the sibling contract and the one that says why: it runs
# one process per input, tallies accepted/rejected/unavailable/aborted, refuses a run
# where every input came back "harness unavailable" ("the replay never ran"), and drops
# 0-byte profraw before merging because "llvm-profdata merges those WITHOUT complaint.
# Left in, they turn a run where nothing was measured into a well-formed 0% report on
# exit 0". run_coverage_onnx.sh merged "$OUT_DIR"/raw/*.profraw unfiltered.
#
# Two clauses, then, and both are about the same thing - whether the number's denominator
# is known:
#   A. the status of the run that writes the profile must be captured and decided, not
#      discarded. `|| true` over the instrumented target is the defect.
#   B. the merge must not be handed a raw glob of the profile directory; empty profiles
#      have to be filtered out first.
#
# Assertions:
#   1. behavioural - the real safetensors runner against stub replays: one that dies
#      partway must be reported, one that returns the documented "rejected" status must
#      not be (that is a normal corpus, and its edges are the point), and one that says
#      it could never run must be reported.
#   2. class scan - every scripts/run_coverage_*.sh must satisfy A and B, so neither can
#      come back one runner at a time.
#   3. negative controls - the scan must reject `|| true`, a status captured and never
#      decided, a glob handed to merge, a missing -s filter and one applied after the
#      merge; and must still accept the same contract written with other names, `test`,
#      and a per-input loop.
#
# What it does NOT establish, said out loud: that the number of inputs the target
# REPORTS having processed is the number it really parsed. For onnx that is checkable
# from the records and this gate's clause A makes the runner read them; for safetensors
# the replay prints nothing per input, so the strongest available statement there is "the
# replay exited with a status the contract defines" - closing that gap needs the replay
# itself to emit records, which is carried forward, not done here.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
RUNNER_GLOB="$PROJECT_ROOT/scripts/run_coverage_"*.sh

WORK="$(mktemp -d "${TMPDIR:-/tmp}/coverage-input-accounting-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  skip %s\n' "$*"; }

# --- 1. behavioural: the safetensors runner ----------------------------------------------
ST_RUNNER="$PROJECT_ROOT/scripts/run_coverage_safetensors.sh"
RUSTBIN="$(rustc +nightly --print target-libdir 2>/dev/null)/../bin"

# A stub in place of the instrumented replay. The runner checks the rust llvm tools before
# it ever runs the replay, so those still have to be there; everything after the replay is
# unreachable in these probes by design - the accounting verdict comes first.
st_stub() { # st_stub <name> <rc>
  local path="$WORK/$1"
  cat >"$path" <<STUB
#!/usr/bin/env bash
printf 'stub replay: %s inputs\n' "\$#"
exit $2
STUB
  chmod +x "$path"
  printf '%s' "$path"
}

st_probe() { # st_probe <replay> <log>
  local replay="$1" log="$2" out="$WORK/st-out"
  rm -rf "$out"
  env PROJECT_ROOT="$PROJECT_ROOT" REPLAY="$replay" \
      CORPUS_DIR="$WORK/st-corpus" OUT_DIR="$out" TMPDIR="$WORK" \
      timeout 300 bash "$ST_RUNNER" >"$log" 2>&1 || true
  # The verdict is the fail line when there is one; otherwise the run got past the
  # accounting and the last line says where it ended up instead.
  grep -m1 'st-cov-run\] fail:' "$log" || tail -1 "$log"
}

if [[ ! -f "$ST_RUNNER" ]]; then
  bad "$(basename "$ST_RUNNER") is missing; the class is incomplete"
elif [[ ! -x "$RUSTBIN/llvm-profdata" || ! -x "$RUSTBIN/llvm-cov" ]]; then
  skip "the safetensors runner refuses to start without the rustc llvm tools under $RUSTBIN"
  skip "so the three behavioural probes (died partway / rejected / unavailable) did not run"
else
  mkdir -p "$WORK/st-corpus"
  for n in a b c; do printf '{"__metadata__":{}}' >"$WORK/st-corpus/$n.safetensors"; done

  # A target that died partway leaves a profile for part of the corpus. Exit 134 is the
  # SIGABRT the replay's own contract calls a crash.
  log_line="$(st_probe "$(st_stub died 134)" "$WORK/died.log")"
  # The reason has to be the right one: "no profraw produced" is also a fail line and
  # would let this pass without the accounting existing at all.
  if grep -q 'stopped partway' <<<"$log_line"; then
    ok "a replay that died partway is reported ($log_line)"
  else
    bad "a replay that died partway was not reported ($log_line)"
    tail -2 "$WORK/died.log" | sed 's/^/       /'
  fi

  # Exit 10 is "the harness could not run" - the gguf runner already refuses a run where
  # that was the answer for everything.
  log_line="$(st_probe "$(st_stub unavailable 10)" "$WORK/unavail.log")"
  if grep -q 'could not run' <<<"$log_line"; then
    ok "a replay that says it could not run is reported ($log_line)"
  else
    bad "a replay that could not run was not reported ($log_line)"
    tail -2 "$WORK/unavail.log" | sed 's/^/       /'
  fi

  # The opposite polarity: exit 9 means some input was rejected, which is a normal corpus
  # and exactly the coverage this runner exists to collect. It must NOT be a failure - the
  # run has to get past the accounting and die later, on the stub's missing profraw.
  st_probe "$(st_stub rejected 9)" "$WORK/rejected.log" >/dev/null
  if grep -q 'no profraw produced' "$WORK/rejected.log"; then
    ok "a replay that rejected an input still gets past the accounting"
  else
    bad "a replay that only rejected inputs was stopped by the accounting: $(grep -m1 'fail:' "$WORK/rejected.log" || echo '(no fail line)')"
  fi
fi

# --- 2. class scan ------------------------------------------------------------------------
scan_runner() {
  python3 - "$1" <<'PY'
import re, sys

text = open(sys.argv[1], encoding="utf-8").read()

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

PROFILED = re.compile(r'\bLLVM_PROFILE_FILE=')
MERGE = re.compile(r'profdata', re.I)   # llvm-profdata, $LLVM_PROFDATA, $PROFDATA alike
CAPTURE = re.compile(r'\|\|\s*(?:local\s+)?([A-Za-z_]\w*)=\$\?')
DISCARD = re.compile(r'\|\|\s*(?:true|:)\s*(?:$|;)')
COND = re.compile(r'\[\[(.+?)\]\]|(?<!\[)\[(?!\[)(.+?)(?<!\])\](?!\])|\btest\b([^;&|]*)|\bcase\b(.+?)\bin\b')
DASH_S = re.compile(r'(?<![-\w])-s\s+("?\$\{?[A-Za-z_]\w*)')

problems = []

# --- A. the status of the profile-writing run --------------------------------------------
profiled = [(i, l) for i, l in enumerate(lines) if PROFILED.search(l)]
if not profiled:
    print("not in the class: it never sets LLVM_PROFILE_FILE")
    sys.exit(2)

for i, line in profiled:
    if DISCARD.search(line):
        problems.append("the run that writes the profile discards its exit status with "
                        "`|| true`, so a target that died partway is published as a whole "
                        "corpus")
        continue
    m = CAPTURE.search(line)
    if not m:
        # No `||` at all under `set -e` means a non-zero status aborts the script, which
        # is a decision too - the status is not being thrown away.
        if re.search(r'\|\|', line):
            problems.append("the run that writes the profile handles its status with "
                            "something other than a capture; it cannot be decided later")
        continue
    var = m.group(1)
    decided = any(
        any(g is not None and re.search(r'\$\{?%s\}?(?![A-Za-z0-9_])' % re.escape(var), g)
            for g in c.groups())
        for later in lines[i + 1:]
        for c in COND.finditer(later)
    )
    if not decided:
        problems.append("the profile run's status is captured into $%s and never decided"
                        % var)

# --- B. what the merge is handed ----------------------------------------------------------
merges = [(i, l) for i, l in enumerate(lines) if MERGE.search(l) and ' merge' in l]
if not merges:
    problems.append("it writes a profile but never merges one; the report's inputs are unknown")
for i, line in merges:
    args = line.split(' merge', 1)[1]
    if re.search(r'\*', args):
        problems.append("the merge is handed a glob of the profile directory, so 0-byte "
                        "profraw from a process that died before flushing are merged in")
    filtered = any(
        any(g is not None and DASH_S.search(g) for g in c.groups())
        for earlier in lines[:i]
        for c in COND.finditer(earlier)
    )
    if not filtered:
        problems.append("nothing tests a profile for content before the merge")

if problems:
    print("; ".join(problems))
    sys.exit(1)
PY
}

CLASS=0
for runner in $RUNNER_GLOB; do
  [[ -f "$runner" ]] || continue
  name="$(basename "$runner")"
  why="$(scan_runner "$runner")" && verdict=0 || verdict=$?
  case "$verdict" in
    0) CLASS=$((CLASS + 1)); ok "$name captures the profile run's status and filters the profiles it merges" ;;
    2) printf '  --   %s %s\n' "$name" "$why" ;;
    *) CLASS=$((CLASS + 1)); bad "$name $why" ;;
  esac
done
if [[ "$CLASS" -ge 3 ]]; then
  ok "the scan covered $CLASS coverage runners"
else
  bad "only $CLASS runner(s) were scanned; the class has shrunk and the contract is no longer pinned"
fi

# --- 3. negative controls -----------------------------------------------------------------
mk() { printf '%s\n' "$2" >"$WORK/run_coverage_$1.sh"; }
reject() {
  if scan_runner "$WORK/run_coverage_$1.sh" >/dev/null 2>&1; then
    bad "negative control: scan accepted $2"
  else
    ok "negative control: scan rejects $2"
  fi
}
accept() {
  if scan_runner "$WORK/run_coverage_$1.sh" >/dev/null 2>&1; then
    ok "negative control: scan accepts $2"
  else
    bad "negative control: scan failed $2 ($(scan_runner "$WORK/run_coverage_$1.sh" || true))"
  fi
}

GOOD='#!/usr/bin/env bash
rc=0
LLVM_PROFILE_FILE="$RAW/cov-%p.profraw" "$REPLAY" "${inputs[@]}" || rc=$?
[[ "$rc" -eq 0 || "$rc" -eq 9 ]] || fail "the replay died (rc=$rc)"
usable=()
for f in "${profs[@]}"; do [[ -s "$f" ]] && usable+=("$f"); done
"$LLVM_PROFDATA" merge -sparse "${usable[@]}" -o "$OUT/cov.profdata"'

mk good "$GOOD"; accept good 'a runner that captures, decides and filters'

mk discard "${GOOD/|| rc=\$?/|| true}"
reject discard 'a profile run whose status is discarded with `|| true`'

mk undecided "${GOOD/'[[ "$rc" -eq 0 || "$rc" -eq 9 ]] || fail "the replay died (rc=$rc)"'/'log "replay rc=$rc"'}"
reject undecided 'a status captured into a variable and only logged'

mk globbed "${GOOD/'"${usable[@]}"'/'"$RAW"/*.profraw'}"
reject globbed 'a merge handed a glob of the profile directory'

mk unfiltered "${GOOD/'for f in "${profs[@]}"; do [[ -s "$f" ]] && usable+=("$f"); done'/'usable=("${profs[@]}")'}"
reject unfiltered 'a merge with nothing testing a profile for content'

mk late '#!/usr/bin/env bash
rc=0
LLVM_PROFILE_FILE="$RAW/cov-%p.profraw" "$REPLAY" "${inputs[@]}" || rc=$?
[[ "$rc" -eq 0 ]] || fail "the replay died (rc=$rc)"
"$LLVM_PROFDATA" merge -sparse "${profs[@]}" -o "$OUT/cov.profdata"
for f in "${profs[@]}"; do [[ -s "$f" ]] && usable+=("$f"); done'
reject late 'a content test that runs after the merge'

mk renamed '#!/usr/bin/env bash
status=0
for i in "${!inputs[@]}"; do
  LLVM_PROFILE_FILE="$RAW/cov-$i.profraw" "$BIN" "${inputs[$i]}" || status=$?
  case "$status" in 0|9) ;; *) note "$status" ;; esac
done
keep=()
for p in "${profiles[@]}"; do test -s "$p" && keep+=("$p"); done
"$PROFDATA" merge -sparse "${keep[@]}" -o "$OUT/cov.profdata"'
accept renamed 'the same contract with other names, `case`, `test -s` and a per-input loop'

mk notinclass '#!/usr/bin/env bash
echo "this runner analyses an existing profile"
"$LLVM_COV" export "$BIN" -instr-profile="$P"'
if scan_runner "$WORK/run_coverage_notinclass.sh" >/dev/null 2>&1; then
  bad 'negative control: a runner that writes no profile was scanned as compliant'
else
  [[ $? -eq 2 ]] \
    && ok 'negative control: a runner that writes no profile is reported as out of the class' \
    || bad 'negative control: a runner that writes no profile was failed rather than excluded'
fi

printf '[coverage-input-accounting] pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
