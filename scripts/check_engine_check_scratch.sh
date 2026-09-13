#!/usr/bin/env bash
# R45(1): pins where the native engine checkers are allowed to delete.
#
# check_gguf_native_engines.sh wiped $OUT_DIR/{clean,crash,poc-corpus} on every run. Those
# three are scratch the check needs empty, but OUT_DIR is caller-supplied and defaults to
# data/native-engine-checks/gguf-engines, which is gitignored: a run against an evidence
# directory deleted whatever crash artifacts were collected there, with no undo. The two
# siblings already avoid this - check_safetensors_native_engines.sh keeps its scratch in a
# mktemp dir, check_onnx_native_engines.sh deletes nothing - so this is one outlier, not a
# missing feature.
#
# Two assertions, because either alone rots:
#   1. behavioural - run the real gguf checker against a sandbox PROJECT_ROOT with stub
#      binaries, far enough to reach all three wipes, and prove sentinels planted in the
#      caller's OUT_DIR survive while the check still writes its logs there.
#   2. class scan - no check_*_native_engines.sh may recursively delete a path derived
#      from OUT_DIR, so the defect cannot come back one checker at a time.
# Negative controls drive both against a fake checker that does wipe OUT_DIR, so a passing
# run means something.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
CHECKER_GLOB="$PROJECT_ROOT/scripts/check_"*"_native_engines.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/engine-check-scratch-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

SENTINEL='IRREPLACEABLE-ENGINE-EVIDENCE'

# Plant a sentinel in each scratch-named subdirectory of a caller-supplied OUT_DIR.
plant() {
  local out="$1" d
  for d in clean crash poc-corpus; do
    mkdir -p "$out/$d"
    printf '%s' "$SENTINEL" >"$out/$d/keep"
  done
}

survived() { # survived <out> <subdir>
  [[ -f "$1/$2/keep" ]] && [[ "$(cat "$1/$2/keep")" == "$SENTINEL" ]]
}

# --- 1. behavioural: the gguf checker must not delete inside a caller's OUT_DIR --------
# A sandbox PROJECT_ROOT plus stub binaries is what it takes to reach the wipes: the real
# check builds nothing when FUZZER/REPLAY are already executable, and its seed generator is
# the only other repository script it runs before them.
PR="$WORK/root"
mkdir -p "$PR/scripts/lib" "$PR/bin" "$PR/seeds/gguf" "$PR/seeds/gguf-malformed"
cp "$PROJECT_ROOT/scripts/lib/engine_mode.sh" "$PR/scripts/lib/engine_mode.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$PR/scripts/gen_gguf_malformed_seeds.sh"
printf 'GGUF' >"$PR/seeds/gguf/align_ok.gguf"
printf 'GGUF' >"$PR/seeds/gguf-malformed/poc.gguf"

# Stub libFuzzer target: clean on the seed, crashing on the PoC, and writing an artifact
# when handed a corpus directory - the three outcomes the check asserts, so the run walks
# past all three wipes instead of aborting at the first one.
cat >"$PR/bin/fuzzer" <<'STUB'
#!/usr/bin/env bash
prefix=""; input=""
for arg in "$@"; do
  case "$arg" in
    -artifact_prefix=*) prefix="${arg#-artifact_prefix=}" ;;
    -*) ;;
    *) input="$arg" ;;
  esac
done
echo "Executed $input (1 runs)"
if [[ -d "$input" ]]; then
  echo "ERROR: libFuzzer: deadly signal"
  printf 'poc' >"${prefix}crash-0000000000000000000000000000000000000000"
  exit 77
fi
case "$input" in
  *poc.gguf) echo "ERROR: libFuzzer: deadly signal"; exit 77 ;;
esac
exit 0
STUB
printf '#!/usr/bin/env bash\nexit 134\n' >"$PR/bin/replay"
chmod +x "$PR/bin/fuzzer" "$PR/bin/replay"

OUT="$WORK/caller-out"
plant "$OUT"
# PATH is trimmed so the AFL++ arm takes its skip branch: this gate is about deletion, and
# the container's afl tools live in /usr/local/bin.
env PATH=/usr/bin:/bin PROJECT_ROOT="$PR" OUT_DIR="$OUT" SEED_ROOT="$PR/seeds" \
    SEED="$PR/seeds/gguf/align_ok.gguf" POC="$PR/seeds/gguf-malformed/poc.gguf" \
    FUZZER="$PR/bin/fuzzer" REPLAY="$PR/bin/replay" \
  timeout 300 bash "$PROJECT_ROOT/scripts/check_gguf_native_engines.sh" \
  >"$WORK/gguf.log" 2>&1 || true

for d in clean crash poc-corpus; do
  if survived "$OUT" "$d"; then
    ok "gguf checker left OUT_DIR/$d alone"
  else
    bad "gguf checker deleted OUT_DIR/$d (sentinel gone)"
  fi
done

# The sentinels above only mean something if the run actually reached the wipes. The last
# libFuzzer assertion is past all three, and the logs prove OUT_DIR is still the output
# directory - a guard that refused to run at all would fail here instead of passing.
if grep -q 'poc in corpus: artifact written' "$WORK/gguf.log" \
   && [[ -s "$OUT/libfuzzer-corpus-crash.log" ]]; then
  ok 'gguf checker completed its libFuzzer arm and wrote its logs into the caller OUT_DIR'
else
  bad 'gguf checker did not reach the corpus assertion; the sentinel result proves nothing'
  sed -n '1,8p' "$WORK/gguf.log" | sed 's/^/       /'
fi

# --- 2. class scan: no checker may recursively delete under OUT_DIR --------------------
# The wipes went through a variable (clean_dir="$OUT_DIR/clean"; rm -rf "$clean_dir"), so a
# literal grep for OUT_DIR next to rm sees nothing. Resolve one level of assignment and
# require every recursively removed path to resolve to the script's own mktemp scratch.
# Single-file removals (rm -f "$AFL_MAP") are out of scope: that is the check rewriting its
# own output, the same as the logs it overwrites every run.
scan_checker() {
  local file="$1" line var rhs
  while IFS= read -r line; do
    for var in $(printf '%s\n' "$line" | grep -oE '\$\{?[A-Za-z_][A-Za-z0-9_]*\}?' | tr -d '${}'); do
      # No name is trusted, not even WORK: a checker that assigned WORK="$OUT_DIR/scratch"
      # would pass a name-based skip while deleting exactly the caller path this gate
      # exists to protect. The legitimate form, WORK="$(mktemp -d)", passes on its rhs.
      rhs="$(grep -m1 -E "^[[:space:]]*$var=" "$file" || true)"
      if [[ "$rhs" != *'$WORK'* && "$rhs" != *'mktemp'* ]]; then
        printf '%s' "$line"
        return 1
      fi
    done
  done < <(grep -E '^[[:space:]]*rm[[:space:]]+-[A-Za-z]*r' "$file")
  return 0
}

for checker in $CHECKER_GLOB; do
  [[ -f "$checker" ]] || continue
  if offender="$(scan_checker "$checker")"; then
    ok "$(basename "$checker") removes directories only under its own scratch"
  else
    bad "$(basename "$checker") recursively removes a caller path: $offender"
  fi
done

# --- 3. negative controls: both assertions must catch a checker that wipes OUT_DIR -----
cat >"$WORK/check_fake_native_engines.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="${OUT_DIR:-/nowhere}"
clean_dir="$OUT_DIR/clean"
rm -rf "$clean_dir"; mkdir -p "$clean_dir"
FAKE

if scan_checker "$WORK/check_fake_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a checker that wipes a subdirectory of OUT_DIR'
else
  ok 'negative control: scan rejects a checker that wipes a subdirectory of OUT_DIR'
fi

# The same wipe hidden behind the name this gate's own scratch uses: a name-based scan
# accepts it, so this control is what keeps the resolution rhs-based.
cat >"$WORK/check_named-work_native_engines.sh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="${OUT_DIR:-/nowhere}"
WORK="$OUT_DIR/scratch"
rm -rf "$WORK"; mkdir -p "$WORK"
FAKE

if scan_checker "$WORK/check_named-work_native_engines.sh" >/dev/null 2>&1; then
  bad 'negative control: scan accepted a wipe of OUT_DIR held in a variable named WORK'
else
  ok 'negative control: scan rejects a wipe of OUT_DIR held in a variable named WORK'
fi

FAKE_OUT="$WORK/fake-out"
plant "$FAKE_OUT"
OUT_DIR="$FAKE_OUT" bash "$WORK/check_fake_native_engines.sh" >/dev/null 2>&1 || true
if survived "$FAKE_OUT" clean; then
  bad 'negative control: the sentinel check did not notice a wiped OUT_DIR/clean'
else
  ok 'negative control: the sentinel check notices a wiped OUT_DIR/clean'
fi

printf '[engine-check-scratch] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
