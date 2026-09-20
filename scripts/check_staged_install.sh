#!/usr/bin/env bash
# R49/R55: pins scripts/lib/staged_install.sh, the single implementation every native
# build uses to replace an operational binary, and then scans the build scripts to make
# sure none of them has gone back to writing onto that binary directly.
#
# The scan is the part that matters over time. R49 fixed two AFL++ builds and left the
# same defect in five other places; a per-script test would have kept doing that. This
# check fails if ANY scripts/build_*.sh compiles or copies straight onto its own output
# variable, so the class cannot come back one script at a time.
#
# Writes only under its own mktemp directory; the repository is read-only here.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
LIB="$PROJECT_ROOT/scripts/lib/staged_install.sh"
[[ -f "$LIB" ]] || { echo "[staged-install] fail: missing $LIB" >&2; exit 1; }

REAL_CC="$(command -v cc || command -v gcc || true)"
[[ -n "$REAL_CC" ]] || { echo "[staged-install] fail: no cc/gcc" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/staged-install-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  skip %s\n' "$*"; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }

SENTINEL='ORIGINAL-IRREPLACEABLE-BINARY'
SENT_SHA="$(printf '%s' "$SENTINEL" | sha256sum | cut -d' ' -f1)"
state() { [[ -e "$1" ]] && sha256sum "$1" | cut -d' ' -f1 || echo '<absent>'; }

# A build that uses the helpers exactly as the contract documents. BUILD_MODE picks how
# the "compiler" behaves so each failure shape can be driven from outside.
cat >"$WORK/fakebuild.sh" <<FAKE
#!/usr/bin/env bash
set -euo pipefail
. "$LIB"
out="\$OUT"
staged_target out || exit 1
staged_new "\$out" staged || exit 1
trap staged_cleanup EXIT
case "\${BUILD_MODE:-ok}" in
  ok)          "$REAL_CC" -x c -o "\$staged" - <<<'int main(void){return 0;}' ;;
  empty)       : ;;                                   # exits 0, writes nothing
  link-fail)   rm -f "\$staged"; echo "fixture: link error" >&2; exit 1 ;;
  in-place)    "$REAL_CC" -x c -o "\$staged.tmp" - <<<'int main(void){return 0;}'
               cat "\$staged.tmp" >"\$staged"; rm -f "\$staged.tmp" ;;  # keeps 0600
esac
staged_commit "\$staged" "\$out" || exit 1
echo "installed: \$out"
FAKE
chmod +x "$WORK/fakebuild.sh"

run() { BUILD_MODE="$1" OUT="$2" bash "$WORK/fakebuild.sh" >"$WORK/build.log" 2>&1; }

echo "[staged-install] helper contract"
D="$WORK/out"; mkdir -p "$D"; OUTP="$D/binary"

for mode in link-fail empty; do
  printf '%s' "$SENTINEL" >"$OUTP"; chmod 755 "$OUTP"
  set +e; run "$mode" "$OUTP"; rc=$?; set -e
  check "$mode: reports failure" "nonzero" "$([[ $rc -ne 0 ]] && echo nonzero || echo "rc=$rc")"
  check "$mode: target byte-identical" "$SENT_SHA" "$(state "$OUTP")"
  check "$mode: no staging file left" "0" "$(find "$D" -name 'binary.new.*' | wc -l)"
done

printf '%s' "$SENTINEL" >"$OUTP"; chmod 755 "$OUTP"
set +e; run ok "$OUTP"; rc=$?; set -e
check "ok: succeeds" "0" "$rc"
[[ "$(state "$OUTP")" != "$SENT_SHA" ]] && ok "ok: target replaced" || bad "ok: target NOT replaced"
check "ok: installed mode is 755" "755" "$(stat -c%a "$OUTP")"
check "ok: no staging file left" "0" "$(find "$D" -name 'binary.new.*' | wc -l)"

# A linker that rewrites the staging file in place leaves mktemp's 0600 behind.
printf '%s' "$SENTINEL" >"$OUTP"; chmod 755 "$OUTP"
set +e; run in-place "$OUTP"; rc=$?; set -e
check "in-place linker: succeeds" "0" "$rc"
check "in-place linker: installed mode is 755" "755" "$(stat -c%a "$OUTP")"

# The staging file must be 0755 BEFORE the build writes to it: the instrumentation gates
# in the AFL++ builds read it while it is still staged, and a 0600 file reads as
# uninstrumented. Dropping the chmod inside staged_new survived every other assertion.
STAGED_MODE="$(bash -c '
  . "'"$LIB"'"
  out="'"$OUTP"'"; staged_target out; staged_new "$out" st
  stat -c%a "$st"; rm -f "$st"')"
check "staging file is 0755 at creation" "755" "$STAGED_MODE"

# A build that chmods its own staging file must not install a non-readable binary. This is
# what the commit-time chmod is for; without this case the creation-time chmod hides it.
printf '%s' "$SENTINEL" >"$OUTP"; chmod 755 "$OUTP"
MODE_AFTER="$(bash -c '
  . "'"$LIB"'"
  out="'"$OUTP"'"; staged_target out; staged_new "$out" st
  printf "x" >"$st"; chmod 700 "$st"
  staged_commit "$st" "$out" >/dev/null 2>&1
  stat -c%a "$out"')"
check "install repairs a mode the build dropped" "755" "$MODE_AFTER"

# Atomic install: rename keeps the inode, copy does not. Replacing the mv with cp/install
# reintroduces exactly the O_WRONLY|O_TRUNC window this whole change removes, and it
# survived every other assertion until this one.
printf '%s' "$SENTINEL" >"$OUTP"; chmod 755 "$OUTP"
INODES="$(bash -c '
  . "'"$LIB"'"
  out="'"$OUTP"'"; staged_target out; staged_new "$out" st
  printf "x" >"$st"; before="$(stat -c%i "$st")"
  staged_commit "$st" "$out"
  printf "%s %s\n" "$before" "$(stat -c%i "$out")"')"
check "install preserves the staging inode (rename, not copy)" "$(echo "$INODES" | cut -d' ' -f1)" "$(echo "$INODES" | cut -d' ' -f2)"

# Name handling. Every one of these survived mutation until now, and the name validation
# is load-bearing beyond tidiness: bash evaluates array subscripts inside ${!name}, so a
# caller-controlled name can run commands if it is not checked. Dropping eval was not
# enough on its own.
check "staged_target refuses a reserved name" "2" \
  "$(bash -c '. "'"$LIB"'"; __si_out=/x; staged_target __si_out >/dev/null 2>&1; echo $?')"
check "staged_new refuses a reserved name" "2" \
  "$(bash -c '. "'"$LIB"'"; staged_new /x __si_staged >/dev/null 2>&1; echo $?')"
check "staged_target refuses a malformed name" "2" \
  "$(bash -c '. "'"$LIB"'"; staged_target "1bad" >/dev/null 2>&1; echo $?')"
PWNPROBE="$WORK/pwned"; rm -f "$PWNPROBE"
bash -c '. "'"$LIB"'"; staged_target "a[\$(touch '"$PWNPROBE"')]"' >/dev/null 2>&1 || true
check "a name cannot execute commands through \${!var}" "absent" "$([[ -e "$PWNPROBE" ]] && echo created || echo absent)"

# Exit status and cleanup robustness (R56). A trap whose last command fails replaces the
# script's status, and under set -e a failing rm aborts the trap before it can restore it.
RCDIR="$WORK/rcprobe"; mkdir -p "$RCDIR"; printf 'x' >"$RCDIR/bin"
cat >"$WORK/rc.sh" <<RCEOF
set -euo pipefail
. "$LIB"
staged_new "\$1" S || exit 1
staged_new "\$1.two" T || exit 1
chmod 555 "\$(dirname "\$1")"
trap staged_cleanup EXIT
exit 101
RCEOF
set +e; bash "$WORK/rc.sh" "$RCDIR/bin" >/dev/null 2>&1; RCGOT=$?; set -e
chmod 755 "$RCDIR"
check "a failing cleanup does not replace the exit status" "101" "$RCGOT"

# Sibling staging: the commit must be a same-filesystem rename.
printf '%s' "$SENTINEL" >"$OUTP"; chmod 755 "$OUTP"
STAGED_SEEN="$(BUILD_MODE=ok OUT="$OUTP" bash -c '
  . "'"$LIB"'"
  out="'"$OUTP"'"
  staged_target out
  staged_new "$out" staged
  printf "%s\n" "$(cd "$(dirname "$staged")" && pwd -P)"
  rm -f "$staged"')"
check "staging file is a sibling of the target" "$(cd "$D" && pwd -P)" "$STAGED_SEEN"

# Symlinked target: the link survives and the real file behind it is replaced.
REAL="$WORK/elsewhere"; mkdir -p "$REAL"
printf '%s' "$SENTINEL" >"$REAL/binary"; chmod 755 "$REAL/binary"
LINK="$D/linked"; rm -f "$LINK"; ln -s "$REAL/binary" "$LINK"
set +e; run ok "$LINK"; rc=$?; set -e
check "symlink: succeeds" "0" "$rc"
check "symlink: still a symlink" "symlink" "$([[ -L "$LINK" ]] && echo symlink || echo regular)"
[[ "$(state "$REAL/binary")" != "$SENT_SHA" ]] && ok "symlink: real target replaced" || bad "symlink: real target NOT replaced"
check "symlink: staged beside the real target" "0" "$(find "$D" -name 'linked.new.*' | wc -l)"

# A directory where the binary belongs must fail before anything is built.
DIRP="$D/as-a-dir"; rm -rf "$DIRP"; mkdir -p "$DIRP"
set +e; run ok "$DIRP"; rc=$?; set -e
check "directory target: reports failure" "nonzero" "$([[ $rc -ne 0 ]] && echo nonzero || echo "rc=$rc")"
check "directory target: nothing written inside it" "0" "$(find "$DIRP" -type f | wc -l)"

echo "[staged-install] integration: real build scripts, fake toolchain"
# The class scan is static. These drive real scripts end to end so the contract is checked
# on the actual code paths, not just on the helper. Coverage is partial and the gap is
# stated rather than hidden - see the note after these cases.
INTDIR="$WORK/int"; mkdir -p "$INTDIR/bin"
cat >"$INTDIR/bin/clang++" <<FAKECXX
#!/usr/bin/env bash
out=""; prev=""
for a in "\$@"; do [[ "\$prev" == "-o" ]] && out="\$a"; prev="\$a"; done
case "\${FAKE_MODE:-ok}" in
  fail) rm -f "\$out"; echo "fixture: link error" >&2; exit 1 ;;
  *)    "$REAL_CC" -x c -o "\$out" - <<<'int main(void){return 0;}' ;;
esac
FAKECXX
chmod +x "$INTDIR/bin/clang++"

# 1) build_libfuzzer_tool_driver.sh - driven with the REAL clang++ when present.
if command -v clang++ >/dev/null 2>&1; then
  TD="$INTDIR/td"; mkdir -p "$TD"
  for mode in fail ok; do
    printf '%s' "$SENTINEL" >"$TD/driver"; chmod 755 "$TD/driver"
    # Own fixture source, not the repository's harness: the check must not depend on
    # harnesses/ being present (a mirror tree of scripts/ alone would fail for the wrong
    # reason, which is exactly how a mutation test lied to me once).
    # -fsanitize=fuzzer supplies its own main, so the fixture must be a fuzz entry point.
    src="$TD/good.cc"
    printf '#include <stddef.h>\n#include <stdint.h>\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }\n' >"$src"
    [[ "$mode" == fail ]] && { src="$TD/bad.cc"; printf 'not c++\n' >"$src"; }
    set +e; SRC="$src" OUT="$TD/driver" bash "$PROJECT_ROOT/scripts/build_libfuzzer_tool_driver.sh" >/dev/null 2>&1; rc=$?; set -e
    if [[ "$mode" == fail ]]; then
      check "tool_driver/fail: reports failure" "nonzero" "$([[ $rc -ne 0 ]] && echo nonzero || echo "rc=$rc")"
      check "tool_driver/fail: target byte-identical" "$SENT_SHA" "$(state "$TD/driver")"
    else
      check "tool_driver/ok: succeeds" "0" "$rc"
      # Compare against the sentinel, not just the mode: the sentinel is 755 too, so a
      # bare mode assertion passes even when nothing was installed.
      if [[ "$(state "$TD/driver")" != "$SENT_SHA" ]]; then ok "tool_driver/ok: target replaced"
      else bad "tool_driver/ok: target NOT replaced"; fi
      check "tool_driver/ok: installed mode 755" "755" "$(stat -c%a "$TD/driver")"
    fi
    check "tool_driver/$mode: no staging left" "0" "$(find "$TD" -name 'driver.new.*' | wc -l)"
  done
else
  skip "tool_driver: no clang++ on this host"
fi

# 2) build_libfuzzer_onnx_native.sh - fake clang++, fixture ORT tree. Covers the two-output
#    path: the fuzzer must NOT be installed when the standalone replay fails.
ON="$INTDIR/onnx"; mkdir -p "$ON/ort/include/onnxruntime/core/session" "$ON/so" "$ON/out"
printf '// fixture\n' >"$ON/ort/include/onnxruntime/core/session/onnxruntime_cxx_api.h"
printf 'fixture-so\n' >"$ON/so/libonnxruntime.so"
printf 'int main(void) { return 0; }\n' >"$ON/loader.cc"
cat >"$INTDIR/bin/clang++2" <<FAKE2
#!/usr/bin/env bash
out=""; prev=""; sa=0
for a in "\$@"; do [[ "\$prev" == "-o" ]] && out="\$a"; [[ "\$a" == "-DONNX_FUZZ_STANDALONE" ]] && sa=1; prev="\$a"; done
# Model a real link failure: the linker unlinks its output before it fails.
[[ "\$sa" == 1 && "\${FAIL_STANDALONE:-0}" == 1 ]] && { rm -f "\$out"; echo "fixture: standalone link error" >&2; exit 1; }
"$REAL_CC" -x c -o "\$out" - <<<'int main(void){return 0;}'
FAKE2
chmod +x "$INTDIR/bin/clang++2"
run_onnx_lf() { # run_onnx_lf <fail_standalone>
  FAIL_STANDALONE="$1" CLANGXX="$INTDIR/bin/clang++2" \
    PROJECT_ROOT="$ON/no-root" WORKDIR="$ON/no-root" ORT_SRC="$ON/ort" SO_DIR="$ON/so" \
    SRC="$ON/loader.cc" OUT="$ON/out/fuzzer" STANDALONE_OUT="$ON/out/replay" BUILD_STANDALONE=1 \
    bash "$PROJECT_ROOT/scripts/build_libfuzzer_onnx_native.sh" >/dev/null 2>&1
}
printf '%s' "$SENTINEL" >"$ON/out/fuzzer"; chmod 755 "$ON/out/fuzzer"
printf '%s' "$SENTINEL" >"$ON/out/replay"; chmod 755 "$ON/out/replay"
set +e; run_onnx_lf 1; rc=$?; set -e
check "libfuzzer-onnx/standalone-fails: reports failure" "nonzero" "$([[ $rc -ne 0 ]] && echo nonzero || echo "rc=$rc")"
check "libfuzzer-onnx/standalone-fails: fuzzer NOT half-installed" "$SENT_SHA" "$(state "$ON/out/fuzzer")"
check "libfuzzer-onnx/standalone-fails: replay byte-identical" "$SENT_SHA" "$(state "$ON/out/replay")"
check "libfuzzer-onnx/standalone-fails: no staging left" "0" "$(find "$ON/out" -name '*.new.*' | wc -l)"
set +e; run_onnx_lf 0; rc=$?; set -e
check "libfuzzer-onnx/ok: succeeds" "0" "$rc"
check "libfuzzer-onnx/ok: both installed 755" "755 755" "$(stat -c%a "$ON/out/fuzzer") $(stat -c%a "$ON/out/replay")"
check "libfuzzer-onnx/ok: no staging left" "0" "$(find "$ON/out" -name '*.new.*' | wc -l)"

# Honest limit. Nine build scripts go through the helper. Driven end to end somewhere:
#   here                              build_libfuzzer_tool_driver.sh, build_libfuzzer_onnx_native.sh
#   check_aflpp_native_build.sh       build_aflpp_gguf_native.sh, build_aflpp_onnx_native.sh
#   check_safetensors_aflpp_build.sh  build_aflpp_safetensors_native.sh
# Static checks only (need cargo-fuzz or a pinned llama.cpp archive plus cmake):
#   build_libfuzzer_gguf_native.sh, build_libfuzzer_safetensors_native.sh,
#   build_coverage_gguf.sh, build_coverage_safetensors.sh
# Five driven, four static. Stated here so the next session does not read "green" as
# "all executed".
log_note() { printf '  note %s\n' "$*"; }
log_note "executed here: tool_driver, libfuzzer-onnx. Covered elsewhere: aflpp gguf/onnx"
log_note "(check_aflpp_native_build.sh), aflpp safetensors (check_safetensors_aflpp_build.sh)."
log_note "Static only: libfuzzer gguf/safetensors, coverage gguf/safetensors (need cmake/cargo)."

echo "[staged-install] class scan: no build script may write onto its own output"

# One matcher, used both on the repository and on a positive-control corpus below. Two
# earlier versions were too narrow: a single regex missed 17 of 20 spellings, and its
# replacement went blind whenever anything followed the destination (`|| exit 1`, `;`,
# `2>/dev/null`) - 48% of realistic variants. The current one parses shell structure.
#
# It is still not exhaustive, and the gap is written down rather than implied: a command
# prefix (`env cp`, `sudo cp`, `VAR=1 cp`), a subshell or brace group around the write,
# `>|`, `--output=`, `${OUT:?}`, and a destination held in a differently named or aliased
# variable all slip through. None of those forms is in the tree today; the positive
# control below states exactly which ones are covered.
SCAN="$PROJECT_ROOT/scripts/lib/scan_direct_output.py"
[[ -f "$SCAN" ]] || { echo "[staged-install] fail: missing $SCAN" >&2; exit 1; }
scan_offending_lines() { python3 "$SCAN" "$1" || true; }

# Positive control first: the scan is only evidence if it is known to be sensitive. Each
# base spelling is crossed with the trailing forms this repository actually writes - the
# earlier corpus was all bare commands, and a review showed the matcher missed 48% of the
# realistic variants (`cp "$src" "$OUT" || exit 1` among them) while that corpus still
# reported full sensitivity. A tautological positive control is worse than none.
CTRL="$WORK/ctrl"; mkdir -p "$CTRL"
TAILS=('' ' || exit 1' ' || fail "install failed"' ';' ' 2>/dev/null' ' && echo ok')
i=0
while IFS= read -r base; do
  for tail in "${TAILS[@]}"; do
    i=$((i + 1))
    printf '#!/usr/bin/env bash\nOUT="$1"\nsrc=/dev/null\n%s%s\n' "$base" "$tail" >"$CTRL/build_ev_$i.sh"
  done
done <<'SPELLINGS'
cc x.c -o "$OUT"
cc x.c -o "${OUT}"
cc x.c -o"$OUT"
cc x.c -o $OUT
clang++ a.cc -O1 -o "$OUT_FUZZER"
clang++ a.cc -O1 -o "${OUT_REPLAY}"
cc x.c -o "$STANDALONE_OUT"
cc x.c -o "$OUT_BIN"
cp "$src" "$OUT"
cp -a "$src" "${OUT}"
mv "$src" "$OUT"
install -m755 "$src" "$OUT"
install "$src" "${OUT_BIN}"
cat "$src" > "$OUT"
tee "$OUT" < "$src"
cat "$src" >"${OUT_REPLAY}"
ln -f "$src" "$OUT"
dd if="$src" of="$OUT"
rsync -a "$src" "$OUT"
objcopy --strip-all "$src" "$OUT"
SPELLINGS
# A backslash continuation splits the -o from its target; the matcher must join them.
i=$((i + 1))
printf '#!/usr/bin/env bash\nOUT="$1"\n"$CC" a.c \\\n  -lpthread -o \\\n  "$OUT"\n' >"$CTRL/build_ev_$i.sh"
TOTAL_CTRL=$i
missed=0
for f in "$CTRL"/build_ev_*.sh; do
  [[ -n "$(scan_offending_lines "$f")" ]] || { missed=$((missed + 1)); printf '     missed: %s\n' "$(tail -1 "$f")"; }
done
check "class scan detects all $TOTAL_CTRL regression variants" "0" "$missed"

# Specificity: normal code must not trip it. Each of these once did.
SAFE="$WORK/safe.sh"
cat >"$SAFE" <<'SAFEEOF'
#!/usr/bin/env bash
staged_commit "$STAGED" "$OUT" || exit 1
cp "$REPLAY_BIN" "$STAGED"
echo "[build] $SRC => $OUT"
log "replay -> $OUT_REPLAY"
run_thing >"$OUT_DIR/mutate.log" 2>&1
SAFEEOF
check "class scan does not fire on correct code" "" "$(scan_offending_lines "$SAFE")"

OFFENDERS=0; SCANNED=0
while IFS= read -r script; do
  SCANNED=$((SCANNED + 1))
  hits="$(scan_offending_lines "$script")"
  if [[ -n "$hits" ]]; then
    OFFENDERS=$((OFFENDERS + 1))
    printf '     %s\n' "$(basename "$script")"
    printf '       %s\n' "$hits"
  fi
done < <(find "$PROJECT_ROOT/scripts" -maxdepth 1 -name 'build_*.sh' | sort)
check "build scripts writing directly onto their output" "0" "$OFFENDERS"
# A loop over zero files reports zero offenders. Assert it actually looked at the tree,
# or every one of these checks passes vacuously in a mirror that has no build scripts.
if [[ "$SCANNED" -ge 9 ]]; then ok "class scan examined $SCANNED build scripts"
else bad "class scan examined only $SCANNED build scripts (expected at least 9)"; fi

# "Sources the helper" is not enough - a comment mentioning the path would pass. Require a
# real source line AND at least one staged_commit call.
MISSING=0
while IFS= read -r f; do
  grep -qE '^[[:space:]]*\.[[:space:]]+.*lib/staged_install\.sh' "$f" || continue
  grep -qE '^[[:space:]]*staged_commit[[:space:]]' "$f" \
    || { MISSING=$((MISSING + 1)); printf '     %s sources the helper but never calls staged_commit\n' "$(basename "$f")"; }
done < <(find "$PROJECT_ROOT/scripts" -maxdepth 1 -name 'build_*.sh' | sort)
check "build scripts sourcing the helper but not using it" "0" "$MISSING"

# The EXIT trap must exist, be armed BEFORE the first staged_new, and be cleared only
# AFTER the last staged_commit. A rewrite of this file once dropped these assertions
# entirely and deleting `trap staged_cleanup EXIT` from a script went unnoticed.
BADTRAP=0
while IFS= read -r script; do
  grep -qE '^[[:space:]]*\.[[:space:]]+.*lib/staged_install\.sh' "$script" || continue
  # Code lines only: a comment mentioning staged_new must not count as a call. The first
  # version of this check matched its own explanatory comment and reported every script.
  # Hand-rolled staging is how the trap contract was bypassed once: delete staged_new and
  # `trap staged_cleanup EXIT`, open-code mktemp, and every ordering check skipped the
  # script. Sourcing the helper and then not using it is itself the violation.
  if grep -qE 'mktemp[[:space:]]+"\$[A-Za-z_]*(OUT|BIN)[A-Za-z0-9_]*\.new' "$script"; then
    BADTRAP=$((BADTRAP + 1)); printf '     %s: open-codes mktemp staging instead of staged_new\n' "$(basename "$script")"
  fi
  first_new="$(grep -nE '^[[:space:]]*staged_new[[:space:]]' "$script" 2>/dev/null | head -1 | cut -d: -f1 || true)"
  last_new="$(grep -nE '^[[:space:]]*staged_new[[:space:]]' "$script" 2>/dev/null | tail -1 | cut -d: -f1 || true)"
  last_commit="$(grep -nE '^[[:space:]]*staged_commit[[:space:]]' "$script" 2>/dev/null | tail -1 | cut -d: -f1 || true)"
  if [[ -z "$first_new" || -z "$last_commit" ]]; then
    BADTRAP=$((BADTRAP + 1))
    printf '     %s: sources the helper but has no staged_new/staged_commit pair\n' "$(basename "$script")"
    continue
  fi
  arm="$(grep -n '^[[:space:]]*trap staged_cleanup EXIT' "$script" 2>/dev/null | head -1 | cut -d: -f1 || true)"
  clr="$(grep -n '^[[:space:]]*trap - EXIT' "$script" 2>/dev/null | head -1 | cut -d: -f1 || true)"
  b="$(basename "$script")"
  if [[ -z "$arm" ]]; then
    BADTRAP=$((BADTRAP + 1)); printf '     %s: never arms `trap staged_cleanup EXIT`\n' "$b"
  elif [[ "$arm" -gt "$first_new" ]]; then
    BADTRAP=$((BADTRAP + 1)); printf '     %s: trap armed at :%s, after the first staged_new :%s\n' "$b" "$arm" "$first_new"
  fi
  if [[ -z "$clr" ]]; then
    BADTRAP=$((BADTRAP + 1)); printf '     %s: never clears the trap\n' "$b"
  elif [[ "$clr" -lt "$last_new" || "$clr" -lt "$last_commit" ]]; then
    BADTRAP=$((BADTRAP + 1))
    printf '     %s: trap cleared at :%s, before staged_new :%s / staged_commit :%s\n' "$b" "$clr" "$last_new" "$last_commit"
  fi
  # Sourcing "$SCRIPT_DIR/lib/..." without defining SCRIPT_DIR dies on `set -u` at the
  # source line - the gate used to pass a script that could not run at all.
  if grep -q 'SCRIPT_DIR' "$script" && ! grep -qE '^[[:space:]]*SCRIPT_DIR=' "$script"; then
    BADTRAP=$((BADTRAP + 1)); printf '     %s: uses $SCRIPT_DIR without defining it\n' "$b"
  fi
done < <(find "$PROJECT_ROOT/scripts" -maxdepth 1 -name 'build_*.sh' | sort)
check "build scripts with a broken EXIT-trap or SCRIPT_DIR contract" "0" "$BADTRAP"

# Verify-before-install: two builds run a --selftest on the staged binary and must only
# install once it passes. Moving the commits above the selftest survived every other
# assertion, and the result is a binary the build itself just rejected sitting in place.
BADORDER2=0; SELFTEST_SEEN=0
while IFS= read -r script; do
  st="$(grep -nE '^[[:space:]]*"\$STAGED[A-Z_]*"[[:space:]]+--selftest|^[[:space:]]*selftest_out=.*\$STAGED' "$script" 2>/dev/null | head -1 | cut -d: -f1 || true)"
  [[ -n "$st" ]] || continue
  SELFTEST_SEEN=$((SELFTEST_SEEN + 1))
  first_commit="$(grep -nE '^[[:space:]]*staged_commit[[:space:]]' "$script" 2>/dev/null | head -1 | cut -d: -f1 || true)"
  if [[ -z "$first_commit" || "$st" -gt "$first_commit" ]]; then
    BADORDER2=$((BADORDER2 + 1))
    printf '     %s: --selftest at :%s runs after the first staged_commit :%s\n' "$(basename "$script")" "$st" "${first_commit:-none}"
  fi
done < <(find "$PROJECT_ROOT/scripts" -maxdepth 1 -name 'build_*.sh' | sort)
check "builds that selftest do it before installing" "0" "$BADORDER2"
if [[ "$SELFTEST_SEEN" -ge 2 ]]; then ok "selftest ordering examined $SELFTEST_SEEN builds"
else bad "selftest ordering examined only $SELFTEST_SEEN builds (expected at least 2)"; fi

# Deliberately NOT checked: "every build script that makes a binary must source the
# helper". A variable name cannot distinguish an output from an input - build scripts hold
# TOOL_BIN, REPLAY_BIN, FUZZER_BIN as sources - so that check produced false positives on
# three scripts that write no binary at all. The writer scan above is the real gate: it
# fires on anything that puts bytes at an output-shaped destination, whether or not the
# script sources the helper.

if [[ "$SKIP" -gt 0 ]]; then
  if [[ "${ALLOW_SKIPPED_CASES:-0}" == 1 ]]; then
    echo "[staged-install] WARN: continuing with $SKIP skipped case(s) (ALLOW_SKIPPED_CASES=1)" >&2
  else
    bad "$SKIP case(s) did not run; set ALLOW_SKIPPED_CASES=1 only if you accept an unverified run"
  fi
fi
echo "[staged-install] passed $PASS, failed $FAIL, skipped $SKIP"
[[ "$FAIL" -eq 0 ]]
