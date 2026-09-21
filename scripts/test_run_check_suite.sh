#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
RUNNER="${SUITE_RUNNER_UNDER_TEST:-$ROOT/scripts/run_check_suite.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/check-suite-test-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
SOURCE="$WORK/source"
COPY="$WORK/copy"
mkdir -p "$SOURCE/scripts" "$SOURCE/data/native-engine-checks" \
  "$SOURCE/seeds/onnx" "$SOURCE/logs" "$SOURCE/tmp"
cp "$RUNNER" "$SOURCE/scripts/run_check_suite.sh"
printf 'untouched\n' >"$SOURCE/data/native-engine-checks/demo.log"
printf 'untouched\n' >"$SOURCE/seeds/onnx/seed.onnx"
printf 'untouched\n' >"$SOURCE/logs/fixture.log"
printf 'untouched\n' >"$SOURCE/tmp/fixture.tmp"

cat >"$SOURCE/scripts/check_pass.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ! ${ALLOW_SKIPPED_CASES+x} ]] || exit 2
[[ "$PWD" == "$PROJECT_ROOT" ]] || exit 3
printf 'rewritten in copy\n' >"$PROJECT_ROOT/data/native-engine-checks/demo.log"
printf 'rewritten in copy\n' >"${SEEDS_DIR:-$PROJECT_ROOT/seeds}/onnx/seed.onnx"
printf 'rewritten in copy\n' >"${LOG_DIR:-$PROJECT_ROOT/logs}/fixture.log"
printf 'rewritten in copy\n' >"${TMPDIR:-$PROJECT_ROOT/tmp}/fixture.tmp"
echo '[fixture-pass] pass=1 fail=0 skip=0'
EOF
cat >"$SOURCE/scripts/check_skip.sh" <<'EOF'
#!/usr/bin/env bash
echo '[fixture-skip] skip: prerequisite absent'
EOF
cat >"$SOURCE/scripts/check_fail.sh" <<'EOF'
#!/usr/bin/env bash
echo '[fixture-fail] skip: one case unavailable'
echo '[fixture-fail] fail: independent assertion failed'
exit 1
EOF
cp -a "$SOURCE/." "$COPY/"

rc=0
ALLOW_SKIPPED_CASES=1 SEEDS_DIR="$SOURCE/seeds" LOG_DIR="$SOURCE/logs" TMPDIR="$SOURCE/tmp" \
  bash "$SOURCE/scripts/run_check_suite.sh" --isolated-root "$COPY" \
  --log-dir "$WORK/logs" \
  >"$WORK/result.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || { cat "$WORK/result.log"; echo "expected suite rc=1, got $rc" >&2; exit 1; }
grep -Fq '[suite] pass=1 skip=1 fail=1 fail_with_skip=1 total=3' "$WORK/result.log"
grep -Fq 'check_pass.sh: PASS' "$WORK/result.log"
grep -Fq 'check_skip.sh: SKIP' "$WORK/result.log"
grep -Fq 'check_fail.sh: FAIL' "$WORK/result.log"
grep -Fxq 'untouched' "$SOURCE/data/native-engine-checks/demo.log"
grep -Fxq 'rewritten in copy' "$COPY/data/native-engine-checks/demo.log"
grep -Fxq 'untouched' "$SOURCE/seeds/onnx/seed.onnx" \
  || { echo 'suite wrote through inherited SEEDS_DIR into source' >&2; exit 1; }
grep -Fxq 'rewritten in copy' "$COPY/seeds/onnx/seed.onnx"
grep -Fxq 'untouched' "$SOURCE/logs/fixture.log"
grep -Fxq 'rewritten in copy' "$COPY/logs/fixture.log" \
  || { echo 'suite leaked LOG_DIR into a gate' >&2; exit 1; }
grep -Fxq 'untouched' "$SOURCE/tmp/fixture.tmp" \
  || { echo 'suite wrote through inherited TMPDIR into source' >&2; exit 1; }
grep -Fxq 'rewritten in copy' "$COPY/tmp/fixture.tmp"

# Bash reads BASH_ENV before a gate runs. A parent startup file must not be able
# to turn a failing gate into a successful empty shell.
cat >"$WORK/child-bashenv" <<'EOF'
if [[ ${PROJECT_ROOT:-} == "$SUITE_TEST_COPY" ]]; then
  exit 0
fi
EOF
rc=0
env BASH_ENV="$WORK/child-bashenv" SUITE_TEST_COPY="$COPY" \
  bash -p "$SOURCE/scripts/run_check_suite.sh" --isolated-root "$COPY" \
  --log-dir "$WORK/bashenv-logs" >"$WORK/bashenv.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || {
  cat "$WORK/bashenv.log"
  echo "parent BASH_ENV hid a failing gate (rc=$rc)" >&2
  exit 1
}
grep -Fq 'check_fail.sh: FAIL' "$WORK/bashenv.log"

# Exported Bash functions can override even the exit builtin in a gate.
rc=0
env 'BASH_FUNC_exit%%=() { return 0; }' \
  bash -p "$SOURCE/scripts/run_check_suite.sh" --isolated-root "$COPY" \
  --log-dir "$WORK/function-logs" >"$WORK/function.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || {
  cat "$WORK/function.log"
  echo "parent Bash function hid a failing gate (rc=$rc)" >&2
  exit 1
}
grep -Fq 'check_fail.sh: FAIL' "$WORK/function.log"

NESTED_SOURCE="$WORK/nested-source"
NESTED_COPY="$WORK/nested-copy"
cp -a "$SOURCE/." "$NESTED_SOURCE/"
rm "$NESTED_SOURCE"/scripts/check_*.sh
cat >"$NESTED_SOURCE/scripts/check_nested_fail.sh" <<'EOF'
#!/usr/bin/env bash
bash -c 'exit 1'
EOF
cp -a "$NESTED_SOURCE/." "$NESTED_COPY/"
rc=0
PROJECT_ROOT="$NESTED_SOURCE" bash "$NESTED_SOURCE/scripts/check_nested_fail.sh" \
  >"$WORK/nested-direct.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || { echo "nested gate did not fail without override (rc=$rc)" >&2; exit 1; }
rc=0
env 'BASH_FUNC_exit%%=() { return 0; }' \
  bash -p "$NESTED_SOURCE/scripts/run_check_suite.sh" --isolated-root "$NESTED_COPY" \
  --log-dir "$WORK/nested-logs" >"$WORK/nested.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || {
  cat "$WORK/nested.log"
  echo "parent Bash function hid a failing nested shell (rc=$rc)" >&2
  exit 1
}
grep -Fq 'check_nested_fail.sh: FAIL' "$WORK/nested.log"

CDPATH_SOURCE="$WORK/cdpath-source"
CDPATH_COPY="$WORK/cdpath-copy"
cp -a "$SOURCE/." "$CDPATH_SOURCE/"
rm "$CDPATH_SOURCE"/scripts/check_*.sh
mkdir -p "$CDPATH_SOURCE/target" "$WORK/outside/target"
cat >"$CDPATH_SOURCE/scripts/check_cdpath_fail.sh" <<'EOF'
#!/usr/bin/env bash
bash -c 'cd target || exit 2; [[ "$PWD" != "$PROJECT_ROOT/target" ]] && exit 0; exit 1'
EOF
cp -a "$CDPATH_SOURCE/." "$CDPATH_COPY/"
rc=0
(
  cd "$CDPATH_SOURCE"
  PROJECT_ROOT="$CDPATH_SOURCE" bash scripts/check_cdpath_fail.sh
) \
  >"$WORK/cdpath-direct.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || { echo "cdpath gate did not fail by default (rc=$rc)" >&2; exit 1; }
rc=0
env CDPATH="$WORK/outside" \
  bash -p "$CDPATH_SOURCE/scripts/run_check_suite.sh" --isolated-root "$CDPATH_COPY" \
  --log-dir "$WORK/cdpath-logs" >"$WORK/cdpath.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || {
  cat "$WORK/cdpath.log"
  echo "parent CDPATH redirected a failing nested shell (rc=$rc)" >&2
  exit 1
}
grep -Fq 'check_cdpath_fail.sh: FAIL' "$WORK/cdpath.log"

rc=0
bash "$SOURCE/scripts/run_check_suite.sh" --isolated-root "$SOURCE" \
  >"$WORK/same-root.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || { cat "$WORK/same-root.log"; echo "same root was accepted" >&2; exit 1; }
grep -Fq 'isolated root must differ from source' "$WORK/same-root.log"

printf '#!/usr/bin/env bash\nexit 0\n' >"$COPY/scripts/check_extra.sh"
rc=0
bash "$SOURCE/scripts/run_check_suite.sh" --isolated-root "$COPY" \
  >"$WORK/stale-copy.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || { cat "$WORK/stale-copy.log"; echo "mismatched gate list was accepted" >&2; exit 1; }
grep -Fq 'gate lists differ' "$WORK/stale-copy.log"
rm "$COPY/scripts/check_extra.sh"

ln -s "$SOURCE/data/native-engine-checks/demo.log" "$COPY/link-to-source"
rc=0
bash "$SOURCE/scripts/run_check_suite.sh" --isolated-root "$COPY" \
  >"$WORK/linked-copy.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || { cat "$WORK/linked-copy.log"; echo "linked copy was accepted" >&2; exit 1; }
grep -Fq 'isolated copy links into source' "$WORK/linked-copy.log"
rm "$COPY/link-to-source"

rm "$COPY/data/native-engine-checks/demo.log"
ln "$SOURCE/data/native-engine-checks/demo.log" \
  "$COPY/data/native-engine-checks/demo.log"
rc=0
bash "$SOURCE/scripts/run_check_suite.sh" --isolated-root "$COPY" \
  >"$WORK/hardlinked-copy.log" 2>&1 || rc=$?
grep -Fxq 'untouched' "$SOURCE/data/native-engine-checks/demo.log" \
  || { echo 'suite wrote through a hardlink into source' >&2; exit 1; }
[[ "$rc" -eq 2 ]] || {
  cat "$WORK/hardlinked-copy.log"
  echo "hardlinked copy was accepted (rc=$rc)" >&2
  exit 1
}
grep -Fq 'isolated copy contains hardlinked files' "$WORK/hardlinked-copy.log"

rm "$COPY/data/native-engine-checks/demo.log"
ln "$SOURCE/data/native-engine-checks/demo.log" "$WORK/outside-hardlink"
ln -s "$WORK/outside-hardlink" "$COPY/data/native-engine-checks/demo.log"
rc=0
bash "$SOURCE/scripts/run_check_suite.sh" --isolated-root "$COPY" \
  >"$WORK/outside-link.log" 2>&1 || rc=$?
grep -Fxq 'untouched' "$SOURCE/data/native-engine-checks/demo.log" \
  || { echo 'suite wrote through an outside link into source' >&2; exit 1; }
[[ "$rc" -eq 2 ]] || {
  cat "$WORK/outside-link.log"
  echo "outside link was accepted (rc=$rc)" >&2
  exit 1
}
grep -Fq 'isolated copy links outside isolated root' "$WORK/outside-link.log"

HELPER_SOURCE="$WORK/helper-source"
HELPER_COPY="$WORK/helper-copy"
mkdir -p "$HELPER_SOURCE/scripts/lib"
cp -a "$SOURCE/." "$HELPER_SOURCE/"
rm "$HELPER_SOURCE/scripts/check_fail.sh" "$HELPER_SOURCE/scripts/check_skip.sh"
printf 'false\n' >"$HELPER_SOURCE/scripts/lib/state.sh"
cat >"$HELPER_SOURCE/scripts/check_helper.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
. "$PROJECT_ROOT/scripts/lib/state.sh"
EOF
cp -a "$HELPER_SOURCE/." "$HELPER_COPY/"
printf ':\n' >"$HELPER_COPY/scripts/lib/state.sh"
rc=0
PROJECT_ROOT="$HELPER_SOURCE" bash "$HELPER_SOURCE/scripts/check_helper.sh" \
  >"$WORK/helper-direct.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || { echo "source helper did not fail (rc=$rc)" >&2; exit 1; }
rc=0
bash "$HELPER_SOURCE/scripts/run_check_suite.sh" --isolated-root "$HELPER_COPY" \
  --log-dir "$WORK/helper-logs" >"$WORK/helper-drift.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || {
  cat "$WORK/helper-drift.log"
  echo "helper drift was accepted (rc=$rc)" >&2
  exit 1
}
grep -Fq 'scripts differs from source' "$WORK/helper-drift.log"

BIN_SOURCE="$WORK/bin-source"
BIN_COPY="$WORK/bin-copy"
mkdir -p "$BIN_SOURCE/target/debug"
cp -a "$SOURCE/." "$BIN_SOURCE/"
rm "$BIN_SOURCE/scripts/check_fail.sh" "$BIN_SOURCE/scripts/check_skip.sh"
printf '#!/usr/bin/env bash\nexit 1\n' >"$BIN_SOURCE/target/debug/tool"
chmod +x "$BIN_SOURCE/target/debug/tool"
cat >"$BIN_SOURCE/scripts/check_tool.sh" <<'EOF'
#!/usr/bin/env bash
"$TOOL_BIN"
EOF
cp -a "$BIN_SOURCE/." "$BIN_COPY/"
printf '#!/usr/bin/env bash\nexit 0\n' >"$BIN_COPY/target/debug/tool"
rc=0
TOOL_BIN="$BIN_SOURCE/target/debug/tool" bash "$BIN_SOURCE/scripts/check_tool.sh" \
  >"$WORK/bin-direct.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || { echo "source tool did not fail (rc=$rc)" >&2; exit 1; }
rc=0
bash "$BIN_SOURCE/scripts/run_check_suite.sh" --isolated-root "$BIN_COPY" \
  --log-dir "$WORK/bin-logs" >"$WORK/bin-drift.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || {
  cat "$WORK/bin-drift.log"
  echo "binary drift was accepted (rc=$rc)" >&2
  exit 1
}
grep -Fq 'target/debug/tool differs from source' "$WORK/bin-drift.log"

cp "$BIN_COPY/target/debug/tool" "$BIN_SOURCE/target/debug/tool"
chmod -x "$BIN_SOURCE/target/debug/tool"
rc=0
TOOL_BIN="$BIN_SOURCE/target/debug/tool" bash "$BIN_SOURCE/scripts/check_tool.sh" \
  >"$WORK/bin-mode-direct.log" 2>&1 || rc=$?
[[ "$rc" -eq 126 ]] || { echo "source tool did not refuse execution (rc=$rc)" >&2; exit 1; }
rc=0
bash "$BIN_SOURCE/scripts/run_check_suite.sh" --isolated-root "$BIN_COPY" \
  --log-dir "$WORK/bin-mode-logs" >"$WORK/bin-mode-drift.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || {
  cat "$WORK/bin-mode-drift.log"
  echo "binary mode drift was accepted (rc=$rc)" >&2
  exit 1
}
grep -Fq 'target/debug/tool mode differs from source' "$WORK/bin-mode-drift.log"

REPLAY_SOURCE="$WORK/replay-source"
REPLAY_COPY="$WORK/replay-copy"
mkdir -p "$REPLAY_SOURCE/fuzz/target-cov"
cp -a "$SOURCE/." "$REPLAY_SOURCE/"
rm "$REPLAY_SOURCE/scripts/check_fail.sh" "$REPLAY_SOURCE/scripts/check_skip.sh"
printf '#!/usr/bin/env bash\nexit 1\n' \
  >"$REPLAY_SOURCE/fuzz/target-cov/safetensors_loader_replay_cov"
chmod +x "$REPLAY_SOURCE/fuzz/target-cov/safetensors_loader_replay_cov"
cat >"$REPLAY_SOURCE/scripts/check_replay.sh" <<'EOF'
#!/usr/bin/env bash
"$PROJECT_ROOT/fuzz/target-cov/safetensors_loader_replay_cov"
EOF
cp -a "$REPLAY_SOURCE/." "$REPLAY_COPY/"
printf '#!/usr/bin/env bash\nexit 0\n' \
  >"$REPLAY_COPY/fuzz/target-cov/safetensors_loader_replay_cov"
rc=0
PROJECT_ROOT="$REPLAY_SOURCE" bash "$REPLAY_SOURCE/scripts/check_replay.sh" \
  >"$WORK/replay-direct.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || { echo "source replay did not fail (rc=$rc)" >&2; exit 1; }
rc=0
bash "$REPLAY_SOURCE/scripts/run_check_suite.sh" --isolated-root "$REPLAY_COPY" \
  --log-dir "$WORK/replay-logs" >"$WORK/replay-drift.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || {
  cat "$WORK/replay-drift.log"
  echo "coverage replay drift was accepted (rc=$rc)" >&2
  exit 1
}
grep -Fq 'fuzz/target-cov/safetensors_loader_replay_cov differs from source' \
  "$WORK/replay-drift.log"

NATIVE_SOURCE="$WORK/native-source"
NATIVE_COPY="$WORK/native-copy"
cp -a "$SOURCE/." "$NATIVE_SOURCE/"
rm "$NATIVE_SOURCE"/scripts/check_*.sh
cp "$ROOT/scripts/check_safetensors_harness_oracle.sh" "$NATIVE_SOURCE/scripts/"
mkdir -p "$NATIVE_SOURCE/seeds/safetensors" \
  "$NATIVE_SOURCE/seeds/safetensors-malformed" \
  "$NATIVE_SOURCE/harnesses/libfuzzer"
printf 'valid\n' >"$NATIVE_SOURCE/seeds/safetensors/safe_00.safetensors"
printf 'invalid\n' >"$NATIVE_SOURCE/seeds/safetensors-malformed/bad.safetensors"
printf '#!/usr/bin/env bash\nexit 1\n' \
  >"$NATIVE_SOURCE/harnesses/libfuzzer/safetensors_loader_replay"
chmod +x "$NATIVE_SOURCE/harnesses/libfuzzer/safetensors_loader_replay"
cp -a "$NATIVE_SOURCE/." "$NATIVE_COPY/"

cat >"$WORK/outside-replay" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == --selftest ]]; then
  echo 'exit_codes: ok=0 rejected=9 unavailable=10'
  exit 0
fi
case "$1" in
  *malformed*) exit 9 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$WORK/outside-replay"
rc=0
env -u REPLAY bash "$NATIVE_SOURCE/scripts/run_check_suite.sh" \
  --isolated-root "$NATIVE_COPY" --log-dir "$WORK/native-default-logs" \
  >"$WORK/native-default.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || {
  cat "$WORK/native-default.log"
  echo "missing native replay did not fail (rc=$rc)" >&2
  exit 1
}
grep -Fq 'replay --selftest did not print the expected contract' \
  "$WORK/native-default-logs/check_safetensors_harness_oracle.sh.log"

rc=0
REPLAY="$WORK/outside-replay" bash "$NATIVE_SOURCE/scripts/run_check_suite.sh" \
  --isolated-root "$NATIVE_COPY" --log-dir "$WORK/native-override-logs" \
  >"$WORK/native-override.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || {
  cat "$WORK/native-override.log"
  echo "suite accepted a parent REPLAY outside the copy (rc=$rc)" >&2
  exit 1
}
grep -Fq 'replay --selftest did not print the expected contract' \
  "$WORK/native-override-logs/check_safetensors_harness_oracle.sh.log"

echo '[suite-test] pass: copy isolation, verdicts, root, gate-list, link guards, dependency drift and parent environment guards'
