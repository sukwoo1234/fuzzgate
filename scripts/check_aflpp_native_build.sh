#!/usr/bin/env bash
# R49: the AFL++ GGUF and ONNX builds must never destroy the existing replay before they
# have a verified replacement. Both scripts compile straight onto the operational path
# (build_aflpp_gguf_native.sh's `-o "$OUT"` link step, build_aflpp_onnx_native.sh's
# `-o "$OUT"`), and check_{gguf,onnx}_native_engines.sh call them on every run that finds
# AFL++ on PATH - no `[[ -x $replay ]]` skip. On the fuzzing computer
# harnesses/aflpp/onnxruntime_loader_replay is the only copy and .gitignore keeps the whole
# directory untracked, so git cannot restore it.
#
# The failure is narrower than R46's explicit `rm -f`, and this test pins the real
# behaviour rather than the assumed one: a compile-stage failure leaves the -o target
# alone, but a LINK-stage failure unlinks it. Both scripts compile and link in one
# command, so a link failure is a plain overwrite-to-nothing.
#
# Real build scripts, fake toolchain. No afl-clang-fast++, no cmake, no llama.cpp source,
# no onnxruntime. Everything this test writes lives under its own mktemp directory; the
# repository is only ever read.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
GGUF_BUILD="$PROJECT_ROOT/scripts/build_aflpp_gguf_native.sh"
ONNX_BUILD="$PROJECT_ROOT/scripts/build_aflpp_onnx_native.sh"
for f in "$GGUF_BUILD" "$ONNX_BUILD"; do
  [[ -f "$f" ]] || { echo "[aflpp-build] fail: missing $f" >&2; exit 1; }
done

REAL_CC="$(command -v cc || command -v gcc || true)"
[[ -n "$REAL_CC" ]] || { echo "[aflpp-build] fail: no cc/gcc to build fixtures" >&2; exit 1; }
REAL_AR="$(command -v ar || true)"
[[ -n "$REAL_AR" ]] || { echo "[aflpp-build] fail: no ar to build fixtures" >&2; exit 1; }
command -v nm >/dev/null 2>&1 || { echo "[aflpp-build] fail: no nm" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aflpp-build-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
check() { # check <desc> <expected> <actual>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

# The sentinel stands in for the irreplaceable replay. Its digest is the whole assertion:
# every failing build must leave this exact content in place.
SENTINEL='PRE-EXISTING-REPLAY-DO-NOT-DESTROY'
sentinel_state() { # sentinel_state <path> -> sha256 | <absent>
  [[ -e "$1" ]] && sha256sum "$1" | cut -d' ' -f1 || echo '<absent>'
}
SENTINEL_SHA="$(printf '%s' "$SENTINEL" | sha256sum | cut -d' ' -f1)"

# ---------------------------------------------------------------- fake toolchain ----
BIN="$WORK/bin"; mkdir -p "$BIN"

# Stands in for afl-clang-fast++. FAKE_CXX_MODE picks the outcome under test; the modes
# mirror what a real compiler driver does, which is why `link-fail` unlinks the target.
cat >"$BIN/afl-clang-fast++" <<FAKECXX
#!/usr/bin/env bash
set -uo pipefail
out=""; prev=""
for a in "\$@"; do
  [[ "\$prev" == "-o" ]] && out="\$a"
  prev="\$a"
done
case "\${FAKE_CXX_MODE:-ok}" in
  compile-fail)
    # cc1 rejects the source: the -o target is never opened, so it survives.
    echo "fixture: syntax error before code generation" >&2
    exit 1
    ;;
  link-fail)
    # ld opens the output, then fails on an undefined reference. Measured on cc/clang/g++:
    # the partially written file is unlinked.
    rm -f "\$out"
    echo "fixture: undefined reference to \\\`nope'" >&2
    exit 1
    ;;
  empty)
    # Exits clean but writes nothing (a wrapper that swallowed the real invocation).
    exit 0
    ;;
  inplace-ok)
    # A linker that rewrites the existing file instead of recreating it: the staging
    # file keeps mktemp's 0600, which instrumentation_scope()/has_afl_instrumentation()
    # read as "not instrumented" unless the build chmods it.
    src="\$(mktemp "${WORK}/inplace.XXXXXX.c")"
    {
      echo 'const char afl_marker[] = "__AFL_SHM_ID";'
      echo 'int gguf_init_from_file_impl(void) { return 0; }'
      echo 'const void *OrtGetApiBase = (const void *)0;'
      echo 'int main(void) { return 0; }'
    } >"\$src"
    tmpbin="\$(mktemp "${WORK}/inplace.XXXXXX.bin")"
    "$REAL_CC" "\$src" -o "\$tmpbin" 2>/dev/null || { rm -f "\$src" "\$tmpbin"; exit 1; }
    cat "\$tmpbin" >"\$out"          # in place: mode of \$out is preserved
    rm -f "\$src" "\$tmpbin"
    exit 0
    ;;
  none|driver-only|ok)
    # Record where the build staged its output: the sibling property is what makes the
    # final mv a same-filesystem rename rather than copy+unlink.
    printf '%s\n' "\$(cd "\$(dirname "\$out")" && pwd -P)" >>"${WORK}/staged-dirs.txt"
    src="\$(mktemp "\$out.fixture.XXXXXX.c" 2>/dev/null || mktemp "${WORK}/fixture.XXXXXX.c")"
    {
      case "\${FAKE_CXX_MODE}" in
        none) : ;;
        *) echo 'const char afl_marker[] = "__AFL_SHM_ID";' ;;
      esac
      case "\${FAKE_CXX_MODE}" in
        ok) echo 'int gguf_init_from_file_impl(void) { return 0; }'
            echo 'const void *OrtGetApiBase = (const void *)0;' ;;
        *)  : ;;
      esac
      echo 'int main(void) { return 0; }'
    } >"\$src"
    "$REAL_CC" "\$src" -o "\$out" 2>/dev/null || { rm -f "\$src"; exit 1; }
    rm -f "\$src"
    exit 0
    ;;
esac
exit 3
FAKECXX
chmod +x "$BIN/afl-clang-fast++"
cp "$BIN/afl-clang-fast++" "$BIN/afl-clang-fast"

# ------------------------------------------------------------------ gguf fixture ----
# A pinned-archive stand-in: the clamp markers are already in the extracted source, so
# the build takes its "patch already applied" path and never runs patch(1).
GSRC="$WORK/gguf-src/llama-fixture"
mkdir -p "$GSRC/ggml/src"
cat >"$GSRC/ggml/src/gguf.cpp" <<'CPP'
// BUILD-TIME FUZZING PATCH (fixture marker)
int gguf_init_from_file_impl(void) { return 0; }
CPP
GARCHIVE="$WORK/gguf-src/fixture.tar.gz"
tar -czf "$GARCHIVE" -C "$WORK/gguf-src" llama-fixture
GMETA="$WORK/gguf-src/meta.json"
printf '{"downloaded_sha256": "%s"}\n' "$(sha256sum "$GARCHIVE" | cut -d' ' -f1)" >"$GMETA"
GPATCH="$WORK/gguf-src/clamp.patch"
printf '+// BUILD-TIME FUZZING PATCH (fixture marker)\n' >"$GPATCH"
GHARNESS="$WORK/gguf-src/harness.cc"
printf 'int main(void) { return 0; }\n' >"$GHARNESS"

# Stands in for cmake: configure is a no-op, --build produces the static archive the
# build script then verifies with nm. The archive must carry the parser symbol plus
# __afl_/__asan_ references or the script's own archive gate rejects it.
cat >"$BIN/cmake" <<FAKECMAKE
#!/usr/bin/env bash
set -uo pipefail
for a in "\$@"; do
  if [[ "\$a" == "--build" ]]; then
    build_dir=""
    prev=""
    for b in "\$@"; do
      [[ "\$prev" == "--build" ]] && build_dir="\$b"
      prev="\$b"
    done
    mkdir -p "\$build_dir/ggml/src"
    c="\$(mktemp "${WORK}/ggml.XXXXXX.c")"
    cat >"\$c" <<'SRC'
extern int __afl_prev_loc;
extern void __asan_report_load1(void *);
int gguf_init_from_file_impl(void) { __asan_report_load1(&__afl_prev_loc); return __afl_prev_loc; }
SRC
    o="\${c%.c}.o"
    "$REAL_CC" -c "\$c" -o "\$o" 2>/dev/null || exit 1
    "$REAL_AR" rcs "\$build_dir/ggml/src/libggml-base.a" "\$o" || exit 1
    rm -f "\$c" "\$o"
    exit 0
  fi
done
exit 0
FAKECMAKE
chmod +x "$BIN/cmake"

run_gguf() { # run_gguf <mode> <out>
  FAKE_CXX_MODE="$1" PATH="$BIN:$PATH" \
    PROJECT_ROOT="$PROJECT_ROOT" \
    TARGET_DIR="$WORK/gguf-target" \
    ARCHIVE="$GARCHIVE" META="$GMETA" PATCH="$GPATCH" \
    SRC_CC="$GHARNESS" OUT="$2" JOBS=1 \
    bash "$GGUF_BUILD" >"$WORK/gguf.log" 2>&1
}

# ------------------------------------------------------------------ onnx fixture ----
# INCLUDE_DIR is NOT an env override - build_aflpp_onnx_native.sh:50 derives it from
# ORT_SRC. Passing INCLUDE_DIR here silently did nothing and the test then depended on the
# repository's real data/targets/onnxruntime tree, which a fresh clone and the fuzzing
# computer may not have. Point ORT_SRC at a fixture laid out the way the script expects.
OORT="$WORK/onnx/ort"
mkdir -p "$OORT/include/onnxruntime/core/session"
printf '// fixture\n' >"$OORT/include/onnxruntime/core/session/onnxruntime_cxx_api.h"
OSO="$WORK/onnx/so"; mkdir -p "$OSO"
printf 'fixture-so\n' >"$OSO/libonnxruntime.so"
OSRC="$WORK/onnx/loader.cc"
printf 'int main(void) { return 0; }\n' >"$OSRC"

run_onnx() { # run_onnx <mode> <out>
  FAKE_CXX_MODE="$1" PATH="$BIN:$PATH" \
    PROJECT_ROOT="$WORK/onnx/no-such-root" WORKDIR="$WORK/onnx/no-such-root" \
    ORT_SRC="$OORT" SO_DIR="$OSO" SRC="$OSRC" OUT="$2" \
    bash "$ONNX_BUILD" >"$WORK/onnx.log" 2>&1
}

# ------------------------------------------------------------------------ cases ----
echo "[aflpp-build] contract: a build that does not produce a verified binary leaves \$OUT untouched"

for target in gguf onnx; do
  echo "--- $target ---"
  OUTDIR="$WORK/$target-out"; mkdir -p "$OUTDIR"
  OUT="$OUTDIR/replay"

  for mode in compile-fail link-fail empty none; do
    printf '%s' "$SENTINEL" >"$OUT"; chmod +x "$OUT"
    set +e
    if [[ "$target" == gguf ]]; then run_gguf "$mode" "$OUT"; else run_onnx "$mode" "$OUT"; fi
    rc=$?
    set -e
    check "$target/$mode: build reports failure" "nonzero" "$([[ $rc -ne 0 ]] && echo nonzero || echo "rc=$rc")"
    check "$target/$mode: \$OUT is byte-identical" "$SENTINEL_SHA" "$(sentinel_state "$OUT")"
    leftovers="$(find "$OUTDIR" -name 'replay.new.*' | wc -l)"
    check "$target/$mode: no staging file left behind" "0" "$leftovers"
  done

  # The success path must still replace the binary, or the fix would be a regression.
  printf '%s' "$SENTINEL" >"$OUT"; chmod +x "$OUT"
  set +e
  if [[ "$target" == gguf ]]; then run_gguf ok "$OUT"; else run_onnx ok "$OUT"; fi
  rc=$?
  set -e
  check "$target/ok: build succeeds" "0" "$rc"
  if [[ "$(sentinel_state "$OUT")" == "$SENTINEL_SHA" ]]; then
    bad "$target/ok: \$OUT was NOT replaced"
  else
    ok "$target/ok: \$OUT replaced by the fresh build"
  fi
  check "$target/ok: no staging file left behind" "0" "$(find "$OUTDIR" -name 'replay.new.*' | wc -l)"

  # gguf rejects a driver_only scope on its own path (onnx only asks "instrumented?",
  # so the same binary is a legitimate pass there). Exercised only where it is a gate.
  if [[ "$target" == gguf ]]; then
    printf '%s' "$SENTINEL" >"$OUT"; chmod +x "$OUT"
    set +e; run_gguf driver-only "$OUT"; rc=$?; set -e
    check "gguf/driver-only: build reports failure" "nonzero" "$([[ $rc -ne 0 ]] && echo nonzero || echo "rc=$rc")"
    check "gguf/driver-only: \$OUT is byte-identical" "$SENTINEL_SHA" "$(sentinel_state "$OUT")"
    check "gguf/driver-only: no staging file left behind" "0" "$(find "$OUTDIR" -name 'replay.new.*' | wc -l)"

    # The documented escape hatch must still install the binary, or the gate would be
    # unusable for a deliberate baseline build.
    printf '%s' "$SENTINEL" >"$OUT"; chmod +x "$OUT"
    set +e
    ALLOW_DRIVER_ONLY=1 FAKE_CXX_MODE=driver-only PATH="$BIN:$PATH" \
      PROJECT_ROOT="$PROJECT_ROOT" TARGET_DIR="$WORK/gguf-target" \
      ARCHIVE="$GARCHIVE" META="$GMETA" PATCH="$GPATCH" \
      SRC_CC="$GHARNESS" OUT="$OUT" JOBS=1 \
      bash "$GGUF_BUILD" >"$WORK/gguf.log" 2>&1
    rc=$?
    set -e
    check "gguf/driver-only+ALLOW: build succeeds" "0" "$rc"
    if [[ "$(sentinel_state "$OUT")" == "$SENTINEL_SHA" ]]; then
      bad "gguf/driver-only+ALLOW: \$OUT was NOT replaced"
    else
      ok "gguf/driver-only+ALLOW: \$OUT replaced by the fresh build"
    fi
  fi

  # The staging file must be a sibling of $OUT, or the final mv is copy+unlink across
  # filesystems instead of an atomic rename. Both scripts' comments call this out; without
  # this assertion moving STAGED to /tmp passes every other case.
  : >"$WORK/staged-dirs.txt"
  printf '%s' "$SENTINEL" >"$OUT"; chmod 755 "$OUT"
  set +e
  if [[ "$target" == gguf ]]; then run_gguf ok "$OUT"; else run_onnx ok "$OUT"; fi
  set -e
  check "$target/ok: staged beside \$OUT (atomic rename)" \
    "$(cd "$(dirname "$OUT")" && pwd -P)" "$(tail -1 "$WORK/staged-dirs.txt" 2>/dev/null)"

  # The installed binary must keep the mode a fresh `-o <path>` link produces (0755 under
  # umask 022). Staging through mktemp starts at 0600 and a linker that rewrites the file
  # in place only ORs the exec bits, so a bare `chmod +x` would install 0711 - no read
  # permission for group/other. The documented build path runs as root inside the
  # aflplusplus container, and the host user's engine-mode probe reads the file.
  printf '%s' "$SENTINEL" >"$OUT"; chmod 755 "$OUT"
  set +e
  if [[ "$target" == gguf ]]; then run_gguf ok "$OUT"; else run_onnx ok "$OUT"; fi
  set -e
  check "$target/ok: installed mode is 755" "755" "$(stat -c%a "$OUT")"

  # The documented escape hatch must not turn a silently-empty build into an install.
  # Before the staging change a no-output compiler left $OUT alone; the fix must not
  # make that case worse by moving a 0-byte file into place.
  printf '%s' "$SENTINEL" >"$OUT"; chmod 755 "$OUT"
  set +e
  if [[ "$target" == gguf ]]; then
    ALLOW_UNINSTRUMENTED=1 FAKE_CXX_MODE=empty PATH="$BIN:$PATH" \
      PROJECT_ROOT="$PROJECT_ROOT" TARGET_DIR="$WORK/gguf-target" \
      ARCHIVE="$GARCHIVE" META="$GMETA" PATCH="$GPATCH" \
      SRC_CC="$GHARNESS" OUT="$OUT" JOBS=1 bash "$GGUF_BUILD" >"$WORK/gguf.log" 2>&1
  else
    ALLOW_UNINSTRUMENTED=1 FAKE_CXX_MODE=empty PATH="$BIN:$PATH" \
      PROJECT_ROOT="$WORK/onnx/no-such-root" WORKDIR="$WORK/onnx/no-such-root" \
      ORT_SRC="$OORT" SO_DIR="$OSO" SRC="$OSRC" OUT="$OUT" \
      bash "$ONNX_BUILD" >"$WORK/onnx.log" 2>&1
  fi
  set -e
  check "$target/empty+ALLOW: \$OUT is byte-identical" "$SENTINEL_SHA" "$(sentinel_state "$OUT")"

  # A directory where the binary belongs must fail loudly, not report success while the
  # binary lands inside it. `mv file dir/` succeeds, so set -e cannot catch this.
  DIRCASE="$OUTDIR/as-a-dir"; rm -rf "$DIRCASE"; mkdir -p "$DIRCASE"
  set +e
  if [[ "$target" == gguf ]]; then run_gguf ok "$DIRCASE"; else run_onnx ok "$DIRCASE"; fi
  rc=$?
  set -e
  check "$target/out-is-a-dir: build reports failure" "nonzero" "$([[ $rc -ne 0 ]] && echo nonzero || echo "rc=$rc")"
  check "$target/out-is-a-dir: nothing installed inside it" "0" "$(find "$DIRCASE" -type f | wc -l)"
  rm -rf "$DIRCASE"

  # A deployment may keep the binary on another filesystem and link to it. When $OUT is a symlink the
  # real target must be updated and the link preserved - before the staging change the
  # compiler followed the link, and a naive mv would replace the link itself.
  REALDIR="$OUTDIR/real"; rm -rf "$REALDIR"; mkdir -p "$REALDIR"
  printf '%s' "$SENTINEL" >"$REALDIR/binary"; chmod 755 "$REALDIR/binary"
  LINK="$OUTDIR/linked"; rm -f "$LINK"; ln -s "$REALDIR/binary" "$LINK"
  set +e
  if [[ "$target" == gguf ]]; then run_gguf ok "$LINK"; else run_onnx ok "$LINK"; fi
  rc=$?
  set -e
  check "$target/out-is-a-symlink: build succeeds" "0" "$rc"
  check "$target/out-is-a-symlink: link is still a link" "symlink" "$([[ -L "$LINK" ]] && echo symlink || echo regular)"
  if [[ "$(sentinel_state "$REALDIR/binary")" == "$SENTINEL_SHA" ]]; then
    bad "$target/out-is-a-symlink: the real target was NOT updated"
  else
    ok "$target/out-is-a-symlink: the real target was updated"
  fi
  rm -rf "$REALDIR" "$LINK"

  # Pins the chmod: mktemp makes the staging file 0600, and a linker that writes in place
  # leaves it that way. Both gates require an executable file, so without the chmod this
  # good build is rejected and $OUT never gets its replacement.
  printf '%s' "$SENTINEL" >"$OUT"; chmod +x "$OUT"
  set +e
  if [[ "$target" == gguf ]]; then run_gguf inplace-ok "$OUT"; else run_onnx inplace-ok "$OUT"; fi
  rc=$?
  set -e
  check "$target/inplace-ok: build succeeds on a 0600 staging file" "0" "$rc"
  if [[ "$(sentinel_state "$OUT")" == "$SENTINEL_SHA" ]]; then
    bad "$target/inplace-ok: \$OUT was NOT replaced"
  else
    ok "$target/inplace-ok: \$OUT replaced by the fresh build"
  fi
done

echo "[aflpp-build] passed $PASS, failed $FAIL"
[[ "$FAIL" -eq 0 ]]
