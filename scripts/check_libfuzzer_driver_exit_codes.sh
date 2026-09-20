#!/usr/bin/env bash
# G3: the black-box libFuzzer driver must file a library crash and only a library crash.
# `tool harness` exits 4 when the library crashed and 9 when it rejected the input before
# the library ran (missing input, precheck reject, unavailable probe) - see the exit code
# constants in src/main.rs. Aborting on 9 would record every rejected mutant as a crash
# artifact; not aborting on 4 would drop real crashes.
#
# Self-contained: compiles the driver against a test main (no libFuzzer runtime) and runs
# it against a fake `tool` whose exit code is scripted.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
SRC="${SRC:-$PROJECT_ROOT/harnesses/libfuzzer/tool_harness_driver.cc}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# the abort cases are expected; do not litter the tree with core dumps
ulimit -c 0 2>/dev/null || true

log() {
  echo "[libfuzzer-driver-check] $*"
}

fail() {
  echo "[libfuzzer-driver-check] fail: $*" >&2
  exit 1
}

if ! command -v clang++ >/dev/null 2>&1; then
  if [ "${REQUIRE_CLANG:-0}" = "1" ]; then
    fail "clang++ not found and REQUIRE_CLANG=1"
  fi
  log "skip: clang++ not found"
  if [ "${ALLOW_SKIPPED_CASES:-0}" != "1" ]; then
    fail "the driver exit-code contract did not run; set ALLOW_SKIPPED_CASES=1 only if you accept an unverified run"
  fi
  echo "[libfuzzer-driver-check] WARN: continuing with skipped cases (ALLOW_SKIPPED_CASES=1)" >&2
  exit 0
fi
[ -f "$SRC" ] || fail "driver source not found: $SRC"

cat > "$WORK/test_main.cc" <<'EOF'
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, size_t size);
int main() {
  const unsigned char data[] = "model-bytes";
  return LLVMFuzzerTestOneInput(data, sizeof(data) - 1);
}
EOF

cat > "$WORK/tool" <<'EOF'
#!/usr/bin/env bash
exit "${FAKE_TOOL_EXIT:-0}"
EOF
chmod +x "$WORK/tool"

log "compile driver with test main"
clang++ -O1 -std=c++17 "$SRC" "$WORK/test_main.cc" -o "$WORK/driver" 2>"$WORK/build.log" \
  || { cat "$WORK/build.log" >&2; fail "driver did not compile"; }

expect_exit() {
  local want="$1"
  local fake_exit="$2"
  local label="$3"
  local got=0

  set +e
  env TOOL_HARNESS_TOOL="$WORK/tool" TOOL_HARNESS_TARGET=onnx TOOL_HARNESS_EXT=onnx \
    FAKE_TOOL_EXIT="$fake_exit" "$WORK/driver" >/dev/null 2>&1
  got=$?
  set -e

  [ "$got" -eq "$want" ] || fail "$label: tool exit $fake_exit -> driver exit $got, expected $want"
  log "$label ok (tool exit $fake_exit -> driver exit $got)"
}

# 134 = SIGABRT, i.e. libFuzzer records a crash artifact for this input
expect_exit 0 0 "clean run is not a finding"
expect_exit 0 9 "rejected input is not a finding"
expect_exit 0 10 "unavailable harness is not a finding"
expect_exit 0 127 "tool that cannot be executed is not a finding"
expect_exit 0 126 "tool that is not executable is not a finding"
expect_exit 134 4 "library crash is a finding"
expect_exit 134 1 "unknown non-zero exit stays a finding"
expect_exit 134 139 "signal-killed harness stays a finding"

log "done: libfuzzer driver exit-code contract verified"
