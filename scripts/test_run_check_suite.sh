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
# A copy-local coverage replay is expected to differ from the source binary: its
# coverage mapping contains the copy's absolute source path. The runner must trust
# only an output that it rebuilt itself from already-verified scripts and sources.
cat >"$REPLAY_SOURCE/scripts/build_coverage_safetensors.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" == "$PROJECT_ROOT" ]] || { echo 'builder ran from the wrong cwd' >&2; exit 81; }
[[ ! ${FUZZ_DIR+x} ]] \
  || { echo 'builder inherited a fuzz-root override' >&2; exit 82; }
[[ "$COV_TARGET_DIR" == "$PROJECT_ROOT/fuzz/.check-suite-target-cov-"* \
   && -d "$COV_TARGET_DIR" \
   && "$OUT_BIN" == "$PROJECT_ROOT/fuzz/target-cov/safetensors_loader_replay_cov" ]] \
  || { echo 'builder did not receive a fresh controlled output path' >&2; exit 84; }
[[ ! ${CARGO_TARGET_DIR+x} && ! ${RUSTFLAGS+x} && ! ${LLVM_PROFILE_FILE+x} ]] \
  || { echo 'builder inherited a compiler-output override' >&2; exit 83; }
mkdir -p "$PROJECT_ROOT/fuzz/target-cov"
cat >"$PROJECT_ROOT/fuzz/target-cov/safetensors_loader_replay_cov" <<'REPLAY'
#!/usr/bin/env bash
echo 'rebuilt inside verified copy'
exit 0
REPLAY
chmod +x "$PROJECT_ROOT/fuzz/target-cov/safetensors_loader_replay_cov"
printf 'copy-local build\n' >"$PROJECT_ROOT/replay-build.marker"
echo '[fixture-build] rebuilt copy-local replay'
EOF
chmod +x "$REPLAY_SOURCE/scripts/build_coverage_safetensors.sh"
printf '#!/usr/bin/env bash\nexit 1\n' \
  >"$REPLAY_SOURCE/fuzz/target-cov/safetensors_loader_replay_cov"
chmod +x "$REPLAY_SOURCE/fuzz/target-cov/safetensors_loader_replay_cov"
cat >"$REPLAY_SOURCE/scripts/check_replay.sh" <<'EOF'
#!/usr/bin/env bash
output="$("$PROJECT_ROOT/fuzz/target-cov/safetensors_loader_replay_cov")"
[[ "$output" == 'rebuilt inside verified copy' ]]
[[ -f "$PROJECT_ROOT/replay-build.marker" ]]
EOF
cp -a "$REPLAY_SOURCE/." "$REPLAY_COPY/"
printf '#!/usr/bin/env bash\necho arbitrary-prebuilt\nexit 0\n' \
  >"$REPLAY_COPY/fuzz/target-cov/safetensors_loader_replay_cov"
rc=0
PROJECT_ROOT="$REPLAY_SOURCE" bash "$REPLAY_SOURCE/scripts/check_replay.sh" \
  >"$WORK/replay-direct.log" 2>&1 || rc=$?
[[ "$rc" -eq 1 ]] || { echo "source replay did not fail (rc=$rc)" >&2; exit 1; }
rc=0
CARGO_TARGET_DIR="$SOURCE/escaped-cargo-target" \
FUZZ_DIR="$SOURCE/escaped-fuzz" COV_TARGET_DIR="$SOURCE/escaped-cov" \
OUT_BIN="$SOURCE/escaped-replay" RUSTFLAGS='-Copt-level=0' \
LLVM_PROFILE_FILE="$SOURCE/escaped-%p.profraw" \
bash "$REPLAY_SOURCE/scripts/run_check_suite.sh" --isolated-root "$REPLAY_COPY" \
  --log-dir "$WORK/replay-logs" >"$WORK/replay-drift.log" 2>&1 || rc=$?
[[ "$rc" -eq 0 ]] || {
  cat "$WORK/replay-drift.log"
  echo "copy-local coverage replay was not rebuilt (rc=$rc)" >&2
  exit 1
}
grep -Fq 'check_replay.sh: PASS' "$WORK/replay-drift.log"
grep -Fq '[fixture-build] rebuilt copy-local replay' \
  "$WORK/replay-logs/setup-safetensors-coverage-replay.log"
grep -Fxq 'copy-local build' "$REPLAY_COPY/replay-build.marker"
grep -Fq 'rebuilt inside verified copy' \
  "$REPLAY_COPY/fuzz/target-cov/safetensors_loader_replay_cov"
[[ -z "$(find "$REPLAY_COPY/fuzz" -maxdepth 1 -type d \
  -name '.check-suite-target-cov-*' -print -quit)" ]] || {
  echo 'runner left its temporary coverage build directory behind' >&2
  exit 1
}
[[ ! -e "$SOURCE/escaped-cargo-target" && ! -e "$SOURCE/escaped-fuzz" \
   && ! -e "$SOURCE/escaped-cov" && ! -e "$SOURCE/escaped-replay" ]] || {
  echo 'copy-local builder wrote through an inherited output path' >&2
  exit 1
}

# A real host can lack nightly/llvm-tools. That is a setup refusal, not a gate
# verdict, and the runner must still remove the fresh target directory it made.
cat >"$REPLAY_SOURCE/scripts/build_coverage_safetensors.sh" <<'EOF'
#!/usr/bin/env bash
echo 'fixture: nightly toolchain unavailable' >&2
exit 77
EOF
cp "$REPLAY_SOURCE/scripts/build_coverage_safetensors.sh" \
  "$REPLAY_COPY/scripts/build_coverage_safetensors.sh"
rc=0
bash "$REPLAY_SOURCE/scripts/run_check_suite.sh" --isolated-root "$REPLAY_COPY" \
  --log-dir "$WORK/replay-build-failure-logs" \
  >"$WORK/replay-build-failure.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || {
  cat "$WORK/replay-build-failure.log"
  echo "coverage replay build failure was not a setup refusal (rc=$rc)" >&2
  exit 1
}
grep -Fq 'copy-local safetensors coverage replay build failed rc=77' \
  "$WORK/replay-build-failure.log"
grep -Fq 'fixture: nightly toolchain unavailable' \
  "$WORK/replay-build-failure-logs/setup-safetensors-coverage-replay.log"
[[ -z "$(find "$REPLAY_COPY/fuzz" -maxdepth 1 -type d \
  -name '.check-suite-target-cov-*' -print -quit)" ]] || {
  echo 'failed builder left its temporary coverage build directory behind' >&2
  exit 1
}

HDF5_SOURCE="$WORK/hdf5-source"
HDF5_COPY="$WORK/hdf5-copy"
cp -a "$SOURCE/." "$HDF5_SOURCE/"
rm "$HDF5_SOURCE/scripts/check_fail.sh" "$HDF5_SOURCE/scripts/check_skip.sh"
HDF5_SOURCE_TARGET="$HDF5_SOURCE/data/targets/hdf5-weights/2.2.0"
mkdir -p "$HDF5_SOURCE_TARGET/source" "$HDF5_SOURCE_TARGET/install/lib" \
  "$HDF5_SOURCE_TARGET/bin" "$HDF5_SOURCE_TARGET/evidence" "$HDF5_SOURCE/toolchain"
printf '#!/usr/bin/env bash\nexit 0\n' >"$HDF5_SOURCE/toolchain/clang-17"
chmod +x "$HDF5_SOURCE/toolchain/clang-17"
ln -s clang-17 "$HDF5_SOURCE/toolchain/clang++"
printf 'pinned HDF5 archive fixture\n' >"$HDF5_SOURCE_TARGET/source/2.2.0.tar.gz"
printf 'source core\n' >"$HDF5_SOURCE_TARGET/install/lib/libhdf5.so"
printf 'source high level\n' >"$HDF5_SOURCE_TARGET/install/lib/libhdf5_hl.so"
printf '#!/usr/bin/env bash\nexit 0\n' >"$HDF5_SOURCE_TARGET/bin/probe"
chmod +x "$HDF5_SOURCE_TARGET/bin/probe"
printf 'source evidence\n' >"$HDF5_SOURCE_TARGET/evidence/build.log"
printf '{}\n' >"$HDF5_SOURCE_TARGET/linkage-manifest.json"
cat >"$HDF5_SOURCE_TARGET/build-profile.json" <<EOF
{
  "toolchain": {
    "cmake": {"path": "/usr/bin/true"},
    "c_compiler": {"path": "$HDF5_SOURCE/toolchain/clang-17"},
    "cxx_compiler": {"path": "$HDF5_SOURCE/toolchain/clang-17"},
    "linker": {"path": "/usr/bin/true"},
    "ninja": {"path": "/usr/bin/true"},
    "readelf": {"path": "/usr/bin/true"}
  },
  "components": {
    "core": {"path": "$HDF5_SOURCE_TARGET/install/lib/libhdf5.so"},
    "high_level": {"path": "$HDF5_SOURCE_TARGET/install/lib/libhdf5_hl.so"},
    "probe": {"path": "$HDF5_SOURCE_TARGET/bin/probe"}
  },
  "evidence_files": {
    "build_log": {"path": "$HDF5_SOURCE_TARGET/evidence/build.log"}
  },
  "linkage_manifest": "$HDF5_SOURCE_TARGET/linkage-manifest.json"
}
EOF
cat >"$HDF5_SOURCE/scripts/check_hdf5_profile.py" <<'PY'
#!/usr/bin/env python3
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[sys.argv.index("--target-root") + 1]).resolve()
profile = json.loads((root / "build-profile.json").read_text(encoding="utf-8"))
paths = [row["path"] for row in profile["components"].values()]
paths += [row["path"] for row in profile["evidence_files"].values()]
paths.append(profile["linkage_manifest"])
for raw in paths:
    path = pathlib.Path(raw).resolve()
    path.relative_to(root)
    if not path.is_file():
        raise SystemExit(f"missing profile artifact: {path}")
print("[fixture-hdf5-profile] pass=1 fail=0")
PY
chmod +x "$HDF5_SOURCE/scripts/check_hdf5_profile.py"
cat >"$HDF5_SOURCE/scripts/build_hdf5_profiles.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target="$PROJECT_ROOT/data/targets/hdf5-weights/2.2.0"
[[ "$PWD" == "$PROJECT_ROOT" && "$HDF5_TARGET_ROOT" == "$target" ]] \
  || { echo 'HDF5 builder ran outside the isolated copy' >&2; exit 81; }
[[ "$HDF5_ARCHIVE" == "$target/source/2.2.0.tar.gz" && -f "$HDF5_ARCHIVE" ]] \
  || { echo 'HDF5 builder did not receive the copy-local archive' >&2; exit 82; }
[[ "$JOBS" == 4 && "$CMAKE" == /usr/bin/true && "$NINJA" == /usr/bin/true \
   && "${CLANGXX##*/}" == clang++ \
   && "$(readlink -f "$CLANG")" == "$(readlink -f "$CLANGXX")" \
   && "$READELF" == /usr/bin/true ]] \
  || { echo 'HDF5 builder did not receive the pinned source toolchain' >&2; exit 83; }
rm -rf "$target/install" "$target/bin" "$target/evidence"
mkdir -p "$target/install/lib" "$target/bin" "$target/evidence"
printf 'copy core\n' >"$target/install/lib/libhdf5.so"
printf 'copy high level\n' >"$target/install/lib/libhdf5_hl.so"
printf '#!/usr/bin/env bash\nexit 0\n' >"$target/bin/probe"
chmod +x "$target/bin/probe"
printf 'copy evidence\n' >"$target/evidence/build.log"
printf '{}\n' >"$target/linkage-manifest.json"
cat >"$target/build-profile.json" <<PROFILE
{
  "toolchain": {
    "cmake": {"path": "/usr/bin/true"},
    "c_compiler": {"path": "$(readlink -f "$CLANG")"},
    "cxx_compiler": {"path": "$(readlink -f "$CLANGXX")"},
    "linker": {"path": "/usr/bin/true"},
    "ninja": {"path": "/usr/bin/true"},
    "readelf": {"path": "/usr/bin/true"}
  },
  "components": {
    "core": {"path": "$target/install/lib/libhdf5.so"},
    "high_level": {"path": "$target/install/lib/libhdf5_hl.so"},
    "probe": {"path": "$target/bin/probe"}
  },
  "evidence_files": {
    "build_log": {"path": "$target/evidence/build.log"}
  },
  "linkage_manifest": "$target/linkage-manifest.json"
}
PROFILE
printf 'copy-local HDF5 build\n' >"$target/built.marker"
echo '[fixture-hdf5-build] rebuilt copy-local HDF5 profile'
EOF
chmod +x "$HDF5_SOURCE/scripts/build_hdf5_profiles.sh"
cat >"$HDF5_SOURCE/scripts/check_hdf5_copy.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target="$PROJECT_ROOT/data/targets/hdf5-weights/2.2.0"
[[ "$HDF5_TARGET_ROOT" == "$target" ]]
python3 -B "$PROJECT_ROOT/scripts/check_hdf5_profile.py" --target-root "$target"
grep -Fxq 'copy-local HDF5 build' "$target/built.marker"
EOF
chmod +x "$HDF5_SOURCE/scripts/check_hdf5_copy.sh"
cp -a "$HDF5_SOURCE/." "$HDF5_COPY/"
rc=0
HDF5_TARGET_ROOT="$SOURCE/escaped-hdf5-root" \
HDF5_ARCHIVE="$SOURCE/escaped-hdf5-archive" \
CMAKE="$SOURCE/escaped-cmake" NINJA="$SOURCE/escaped-ninja" \
CLANG="$SOURCE/escaped-clang" CLANGXX="$SOURCE/escaped-clangxx" \
READELF="$SOURCE/escaped-readelf" JOBS=99 \
bash "$HDF5_SOURCE/scripts/run_check_suite.sh" --isolated-root "$HDF5_COPY" \
  --log-dir "$WORK/hdf5-logs" >"$WORK/hdf5.log" 2>&1 || rc=$?
[[ "$rc" -eq 0 ]] || {
  cat "$WORK/hdf5.log"
  echo "copy-local HDF5 profile was not rebuilt (rc=$rc)" >&2
  exit 1
}
grep -Fq 'check_hdf5_copy.sh: PASS' "$WORK/hdf5.log"
grep -Fq '[fixture-hdf5-build] rebuilt copy-local HDF5 profile' \
  "$WORK/hdf5-logs/setup-hdf5.log"
grep -Fxq 'copy-local HDF5 build' \
  "$HDF5_COPY/data/targets/hdf5-weights/2.2.0/built.marker"
[[ ! -e "$SOURCE/escaped-hdf5-root" \
   && ! -e "$SOURCE/escaped-hdf5-archive" ]] || {
  echo 'copy-local HDF5 builder wrote through an inherited output path' >&2
  exit 1
}

TFLITE_SOURCE="$WORK/tflite-source"
TFLITE_COPY="$WORK/tflite-copy"
cp -a "$SOURCE/." "$TFLITE_SOURCE/"
rm "$TFLITE_SOURCE/scripts/check_fail.sh" "$TFLITE_SOURCE/scripts/check_skip.sh"
mkdir -p "$TFLITE_SOURCE/data/targets/tflite/v2.20.0/source" \
  "$TFLITE_SOURCE/harnesses/tflite"
printf 'pinned archive fixture\n' \
  >"$TFLITE_SOURCE/data/targets/tflite/v2.20.0/source/v2.20.0.tar.gz"
cat >"$TFLITE_SOURCE/scripts/build_tflite_profiles.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" == "$PROJECT_ROOT" ]] || { echo 'TFLite builder ran from the wrong cwd' >&2; exit 81; }
[[ "$TFLITE_TARGET_ROOT" == "$PROJECT_ROOT/data/targets/tflite/.check-suite-v2.20.0-"* \
   && -d "$TFLITE_TARGET_ROOT" ]] \
  || { echo 'TFLite builder did not receive a fresh copy-local target root' >&2; exit 82; }
[[ "$TFLITE_ARCHIVE" == "$PROJECT_ROOT/data/targets/tflite/v2.20.0/source/v2.20.0.tar.gz" ]] \
  || { echo 'TFLite builder did not receive the verified copy archive' >&2; exit 83; }
[[ "$TFLITE_REPLAY" == "$PROJECT_ROOT/harnesses/tflite/tflite_loader_replay" \
   && "$TFLITE_FUZZER" == "$PROJECT_ROOT/harnesses/tflite/tflite_loader_fuzzer" \
   && "$TFLITE_MUTATOR" == "$PROJECT_ROOT/harnesses/tflite/tflite_structural_mutator" ]] \
  || { echo 'TFLite builder outputs escaped the copy' >&2; exit 84; }
[[ "$JOBS" == 4 && ! ${CMAKE+x} && ! ${NINJA+x} && ! ${CLANG+x} && ! ${CLANGXX+x} ]] \
  || { echo 'TFLite builder inherited a tool or jobs override' >&2; exit 85; }
printf '#!/usr/bin/env bash\necho copy-local-tflite-replay\n' >"$TFLITE_REPLAY"
printf '#!/usr/bin/env bash\necho copy-local-tflite-fuzzer\n' >"$TFLITE_FUZZER"
printf '#!/usr/bin/env bash\necho copy-local-tflite-mutator\n' >"$TFLITE_MUTATOR"
chmod +x "$TFLITE_REPLAY" "$TFLITE_FUZZER" "$TFLITE_MUTATOR"
printf '{}\n' >"$TFLITE_TARGET_ROOT/meta.json"
printf '{}\n' >"$TFLITE_TARGET_ROOT/profile.json"
printf '{}\n' >"$TFLITE_TARGET_ROOT/build-identity.json"
printf 'copy-local TFLite build\n' >"$TFLITE_TARGET_ROOT/built.marker"
echo '[fixture-tflite-build] rebuilt copy-local TFLite artifacts'
EOF
chmod +x "$TFLITE_SOURCE/scripts/build_tflite_profiles.sh"
cat >"$TFLITE_SOURCE/scripts/build_tflite_guided.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" == "$PROJECT_ROOT" && "$JOBS" == 4 ]] \
  || { echo 'guided builder ran with the wrong cwd or jobs' >&2; exit 86; }
[[ "$TFLITE_ARCHIVE" == "$PROJECT_ROOT/data/targets/tflite/v2.20.0/source/v2.20.0.tar.gz" ]] \
  || { echo 'guided builder did not receive the verified copy archive' >&2; exit 90; }
[[ ! ${TFLITE_GUIDED_BUILD_DIR+x} && ! ${TFLITE_SOURCE_DIR+x} \
   && ! ${TFLITE_BASE_BUILD_DIR+x} && ! ${TFLITE_FIXTURE+x} \
   && ! ${LLVM_NM+x} && ! ${LLVM_OBJDUMP+x} && ! ${CLANG_BUNDLE_DIR+x} ]] \
  || { echo 'guided builder inherited a path or tool override' >&2; exit 87; }
root="$TFLITE_TARGET_ROOT/build/guided-cmake"
mkdir -p "$root/tensorflow-lite"
printf 'guided target archive\n' >"$root/tensorflow-lite/libtensorflow-lite.a"
printf '#!/usr/bin/env bash\necho guided fuzzer\n' >"$root/tflite_loader_fuzzer"
chmod +x "$root/tflite_loader_fuzzer"
printf '{}\n' >"$TFLITE_TARGET_ROOT/guided-instrumentation.json"
printf 'copy-local guided build\n' >"$TFLITE_TARGET_ROOT/guided.marker"
echo '[fixture-tflite-guided-build] rebuilt copy-local guided artifacts'
EOF
cat >"$TFLITE_SOURCE/scripts/build_coverage_tflite.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" == "$PROJECT_ROOT" && "$JOBS" == 4 ]] \
  || { echo 'coverage builder ran with the wrong cwd or jobs' >&2; exit 88; }
[[ "$TFLITE_ARCHIVE" == "$PROJECT_ROOT/data/targets/tflite/v2.20.0/source/v2.20.0.tar.gz" ]] \
  || { echo 'coverage builder did not receive the verified copy archive' >&2; exit 91; }
[[ ! ${TFLITE_COVERAGE_BUILD_DIR+x} && ! ${TFLITE_SOURCE_DIR+x} \
   && ! ${TFLITE_BASE_BUILD_DIR+x} && ! ${TFLITE_FIXTURE+x} \
   && ! ${LLVM_NM+x} && ! ${LLVM_OBJDUMP+x} && ! ${CLANG_BUNDLE_DIR+x} ]] \
  || { echo 'coverage builder inherited a path or tool override' >&2; exit 89; }
root="$TFLITE_TARGET_ROOT/build/coverage-cmake"
mkdir -p "$root/tensorflow-lite"
printf 'coverage target archive\n' >"$root/tensorflow-lite/libtensorflow-lite.a"
printf '#!/usr/bin/env bash\necho coverage replay\n' >"$root/tflite_loader_replay"
chmod +x "$root/tflite_loader_replay"
printf '{}\n' >"$TFLITE_TARGET_ROOT/coverage-instrumentation.json"
printf 'copy-local coverage build\n' >"$TFLITE_TARGET_ROOT/coverage.marker"
echo '[fixture-tflite-coverage-build] rebuilt copy-local coverage artifacts'
EOF
chmod +x "$TFLITE_SOURCE/scripts/build_tflite_guided.sh" \
  "$TFLITE_SOURCE/scripts/build_coverage_tflite.sh"
cat >"$TFLITE_SOURCE/scripts/check_tflite_copy.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$TFLITE_TARGET_ROOT" == "$PROJECT_ROOT/data/targets/tflite/.check-suite-v2.20.0-"* ]]
grep -Fxq 'copy-local TFLite build' "$TFLITE_TARGET_ROOT/built.marker"
[[ "$("$PROJECT_ROOT/harnesses/tflite/tflite_loader_replay")" == copy-local-tflite-replay ]]
[[ "$("$PROJECT_ROOT/harnesses/tflite/tflite_loader_fuzzer")" == copy-local-tflite-fuzzer ]]
[[ "$("$PROJECT_ROOT/harnesses/tflite/tflite_structural_mutator")" == copy-local-tflite-mutator ]]
grep -Fxq 'copy-local guided build' "$TFLITE_TARGET_ROOT/guided.marker"
grep -Fxq 'copy-local coverage build' "$TFLITE_TARGET_ROOT/coverage.marker"
EOF
chmod +x "$TFLITE_SOURCE/scripts/check_tflite_copy.sh"
cp -a "$TFLITE_SOURCE/." "$TFLITE_COPY/"
rc=0
TFLITE_TARGET_ROOT="$SOURCE/escaped-tflite-root" \
TFLITE_ARCHIVE="$SOURCE/escaped-tflite-archive" \
TFLITE_REPLAY="$SOURCE/escaped-tflite-replay" \
TFLITE_FUZZER="$SOURCE/escaped-tflite-fuzzer" \
TFLITE_MUTATOR="$SOURCE/escaped-tflite-mutator" \
TFLITE_SOURCE_DIR="$SOURCE/escaped-tflite-source" \
TFLITE_BASE_BUILD_DIR="$SOURCE/escaped-tflite-base" \
TFLITE_GUIDED_BUILD_DIR="$SOURCE/escaped-tflite-guided" \
TFLITE_COVERAGE_BUILD_DIR="$SOURCE/escaped-tflite-coverage" \
TFLITE_FIXTURE="$SOURCE/escaped-tflite-fixture" \
CMAKE="$SOURCE/escaped-cmake" NINJA="$SOURCE/escaped-ninja" \
CLANG="$SOURCE/escaped-clang" CLANGXX="$SOURCE/escaped-clangxx" \
LLVM_NM="$SOURCE/escaped-llvm-nm" LLVM_OBJDUMP="$SOURCE/escaped-llvm-objdump" \
CLANG_BUNDLE_DIR="$SOURCE/escaped-clang-bundle" JOBS=99 \
bash "$TFLITE_SOURCE/scripts/run_check_suite.sh" --isolated-root "$TFLITE_COPY" \
  --log-dir "$WORK/tflite-logs" >"$WORK/tflite.log" 2>&1 || rc=$?
[[ "$rc" -eq 0 ]] || {
  cat "$WORK/tflite.log"
  echo "copy-local TFLite artifacts were not rebuilt (rc=$rc)" >&2
  exit 1
}
grep -Fq 'check_tflite_copy.sh: PASS' "$WORK/tflite.log"
grep -Fq '[fixture-tflite-build] rebuilt copy-local TFLite artifacts' \
  "$WORK/tflite-logs/setup-tflite.log"
grep -Fq '[fixture-tflite-guided-build] rebuilt copy-local guided artifacts' \
  "$WORK/tflite-logs/setup-tflite-guided.log"
grep -Fq '[fixture-tflite-coverage-build] rebuilt copy-local coverage artifacts' \
  "$WORK/tflite-logs/setup-tflite-coverage.log"
[[ -z "$(find "$TFLITE_COPY/data/targets/tflite" -maxdepth 1 -type d \
  -name '.check-suite-v2.20.0-*' -print -quit)" ]] || {
  echo 'runner left its temporary TFLite target root behind' >&2
  exit 1
}
[[ ! -e "$SOURCE/escaped-tflite-root" \
   && ! -e "$SOURCE/escaped-tflite-archive" \
   && ! -e "$SOURCE/escaped-tflite-replay" \
   && ! -e "$SOURCE/escaped-tflite-fuzzer" \
   && ! -e "$SOURCE/escaped-tflite-mutator" \
   && ! -e "$SOURCE/escaped-tflite-source" \
   && ! -e "$SOURCE/escaped-tflite-base" \
   && ! -e "$SOURCE/escaped-tflite-guided" \
   && ! -e "$SOURCE/escaped-tflite-coverage" \
   && ! -e "$SOURCE/escaped-tflite-fixture" ]] || {
  echo 'copy-local TFLite builder wrote through an inherited output path' >&2
  exit 1
}

cat >"$TFLITE_SOURCE/scripts/build_tflite_guided.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'fixture: guided configure detail\n' >"$TFLITE_TARGET_ROOT/guided-configure.log"
printf 'fixture: guided build detail\n' >"$TFLITE_TARGET_ROOT/guided-build.log"
echo 'fixture: guided TFLite build failed' >&2
exit 77
EOF
chmod +x "$TFLITE_SOURCE/scripts/build_tflite_guided.sh"
TFLITE_VARIANT_FAILURE_COPY="$WORK/tflite-variant-failure-copy"
cp -a "$TFLITE_SOURCE/." "$TFLITE_VARIANT_FAILURE_COPY/"
rc=0
bash "$TFLITE_SOURCE/scripts/run_check_suite.sh" \
  --isolated-root "$TFLITE_VARIANT_FAILURE_COPY" \
  --log-dir "$WORK/tflite-variant-failure-logs" \
  >"$WORK/tflite-variant-failure.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || {
  cat "$WORK/tflite-variant-failure.log"
  echo "TFLite variant failure was not a setup refusal (rc=$rc)" >&2
  exit 1
}
grep -Fq 'copy-local TFLite guided build failed rc=77' \
  "$WORK/tflite-variant-failure.log"
grep -Fq 'fixture: guided TFLite build failed' \
  "$WORK/tflite-variant-failure-logs/setup-tflite-guided.log"
grep -Fxq 'fixture: guided configure detail' \
  "$WORK/tflite-variant-failure-logs/setup-tflite-guided-configure.log"
grep -Fxq 'fixture: guided build detail' \
  "$WORK/tflite-variant-failure-logs/setup-tflite-guided-build.log"
[[ -z "$(find "$TFLITE_VARIANT_FAILURE_COPY/data/targets/tflite" -maxdepth 1 -type d \
  -name '.check-suite-v2.20.0-*' -print -quit)" ]] || {
  echo 'failed TFLite variant builder left its temporary target root behind' >&2
  exit 1
}

cat >"$TFLITE_SOURCE/scripts/build_tflite_profiles.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'fixture: dependency download failed\n' >"$TFLITE_TARGET_ROOT/configure.log"
echo 'fixture: TFLite configure failed' >&2
exit 77
EOF
chmod +x "$TFLITE_SOURCE/scripts/build_tflite_profiles.sh"
TFLITE_FAILURE_COPY="$WORK/tflite-failure-copy"
cp -a "$TFLITE_SOURCE/." "$TFLITE_FAILURE_COPY/"
rc=0
bash "$TFLITE_SOURCE/scripts/run_check_suite.sh" --isolated-root "$TFLITE_FAILURE_COPY" \
  --log-dir "$WORK/tflite-build-failure-logs" \
  >"$WORK/tflite-build-failure.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || {
  cat "$WORK/tflite-build-failure.log"
  echo "TFLite build failure was not a setup refusal (rc=$rc)" >&2
  exit 1
}
grep -Fq 'copy-local TFLite build failed rc=77' "$WORK/tflite-build-failure.log"
grep -Fq 'fixture: TFLite configure failed' \
  "$WORK/tflite-build-failure-logs/setup-tflite.log"
grep -Fxq 'fixture: dependency download failed' \
  "$WORK/tflite-build-failure-logs/setup-tflite-configure.log"
[[ -z "$(find "$TFLITE_FAILURE_COPY/data/targets/tflite" -maxdepth 1 -type d \
  -name '.check-suite-v2.20.0-*' -print -quit)" ]] || {
  echo 'failed builder left its temporary TFLite target root behind' >&2
  exit 1
}

OPENVINO_SOURCE="$WORK/openvino-source"
OPENVINO_COPY="$WORK/openvino-copy"
cp -a "$SOURCE/." "$OPENVINO_SOURCE/"
rm "$OPENVINO_SOURCE"/scripts/check_*.sh
OPENVINO_SOURCE_TARGET="$OPENVINO_SOURCE/data/targets/openvino-ir/2026.4.1"
mkdir -p "$OPENVINO_SOURCE_TARGET/source/dependencies" \
  "$OPENVINO_SOURCE_TARGET/install/lib" "$OPENVINO_SOURCE/toolchain"
for archive in \
  2026.4.1.tar.gz \
  dependencies/pugixml-ee86beb30e4973f5feffe3ce63bfa4fbadf72f38.tar.gz \
  dependencies/xbyak-431abd865e70a46d56f5aa0e1f87572decb60169.tar.gz \
  dependencies/nlohmann-json-9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03.tar.gz
do
  printf 'verified OpenVINO archive fixture: %s\n' "$archive" \
    >"$OPENVINO_SOURCE_TARGET/source/$archive"
done
printf '#!/usr/bin/env bash\nexit 0\n' >"$OPENVINO_SOURCE/toolchain/clang-17"
chmod +x "$OPENVINO_SOURCE/toolchain/clang-17"
ln -s clang-17 "$OPENVINO_SOURCE/toolchain/clang"
ln -s clang-17 "$OPENVINO_SOURCE/toolchain/clang++"
printf 'source OpenVINO core\n' >"$OPENVINO_SOURCE_TARGET/install/lib/libopenvino.so"
cat >"$OPENVINO_SOURCE_TARGET/build-profile.json" <<EOF
{
  "toolchain": {
    "cmake": {"path": "/usr/bin/true"},
    "compiler": {"path": "$OPENVINO_SOURCE/toolchain/clang-17"},
    "linker": {"path": "$OPENVINO_SOURCE/toolchain/clang-17"},
    "ninja": {"path": "/usr/bin/true"},
    "readelf": {"path": "/usr/bin/true"}
  },
  "components": {
    "core": {"path": "$OPENVINO_SOURCE_TARGET/install/lib/libopenvino.so"}
  },
  "linkage_manifest": "$OPENVINO_SOURCE_TARGET/linkage-manifest.json"
}
EOF
printf '{}\n' >"$OPENVINO_SOURCE_TARGET/linkage-manifest.json"
cat >"$OPENVINO_SOURCE/scripts/check_openvino_profile.py" <<'PY'
#!/usr/bin/env python3
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[sys.argv.index("--target-root") + 1]).resolve()
profile = json.loads((root / "build-profile.json").read_text(encoding="utf-8"))
for row in profile["components"].values():
    if not pathlib.Path(row["path"]).is_file():
        raise SystemExit("OpenVINO component is missing")
print("[fixture-openvino-profile] pass=1 fail=0")
PY
chmod +x "$OPENVINO_SOURCE/scripts/check_openvino_profile.py"
cat >"$OPENVINO_SOURCE/scripts/build_openvino_profiles.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" == "$PROJECT_ROOT" ]] || exit 81
[[ "$OPENVINO_TARGET_ROOT" == "$PROJECT_ROOT/data/targets/openvino-ir/.check-suite-2026.4.1-"* \
   && -d "$OPENVINO_TARGET_ROOT" ]] || exit 82
[[ "$OPENVINO_ARCHIVE" == "$OPENVINO_TARGET_ROOT/source/2026.4.1.tar.gz" \
   && -f "$OPENVINO_ARCHIVE" ]] || exit 83
[[ "$JOBS" == 4 && "$CMAKE" == /usr/bin/true && "$NINJA" == /usr/bin/true \
   && "${CLANG##*/}" == clang && "${CLANGXX##*/}" == clang++ \
   && "$READELF" == /usr/bin/true ]] || exit 84
mkdir -p "$OPENVINO_TARGET_ROOT/install/lib"
printf 'copy-local OpenVINO core\n' >"$OPENVINO_TARGET_ROOT/install/lib/libopenvino.so"
cat >"$OPENVINO_TARGET_ROOT/build-profile.json" <<PROFILE
{
  "toolchain": {
    "cmake": {"path": "$CMAKE"},
    "compiler": {"path": "$(readlink -f "$CLANG")"},
    "linker": {"path": "$(readlink -f "$CLANGXX")"},
    "ninja": {"path": "$NINJA"},
    "readelf": {"path": "$READELF"}
  },
  "components": {
    "core": {"path": "$OPENVINO_TARGET_ROOT/install/lib/libopenvino.so"}
  },
  "linkage_manifest": "$OPENVINO_TARGET_ROOT/linkage-manifest.json"
}
PROFILE
printf '{}\n' >"$OPENVINO_TARGET_ROOT/meta.json"
printf '{}\n' >"$OPENVINO_TARGET_ROOT/linkage-manifest.json"
printf 'copy-local OpenVINO normal build\n' >"$OPENVINO_TARGET_ROOT/normal.marker"
echo '[fixture-openvino-build] rebuilt copy-local normal profile'
EOF
cat >"$OPENVINO_SOURCE/scripts/build_openvino_guided.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" == "$PROJECT_ROOT" && "$JOBS" == 4 ]] || exit 85
[[ "$OPENVINO_TARGET_ROOT" == "$PROJECT_ROOT/data/targets/openvino-ir/.check-suite-2026.4.1-"* ]] || exit 86
printf '{}\n' >"$OPENVINO_TARGET_ROOT/guided-instrumentation.json"
printf 'copy-local OpenVINO guided build\n' >"$OPENVINO_TARGET_ROOT/guided.marker"
echo '[fixture-openvino-guided] rebuilt copy-local guided artifacts'
EOF
cat >"$OPENVINO_SOURCE/scripts/build_coverage_openvino.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" == "$PROJECT_ROOT" && "$JOBS" == 4 ]] || exit 87
[[ "$OPENVINO_TARGET_ROOT" == "$PROJECT_ROOT/data/targets/openvino-ir/.check-suite-2026.4.1-"* ]] || exit 88
printf '{}\n' >"$OPENVINO_TARGET_ROOT/coverage-instrumentation.json"
printf 'copy-local OpenVINO coverage build\n' >"$OPENVINO_TARGET_ROOT/coverage.marker"
echo '[fixture-openvino-coverage] rebuilt copy-local coverage artifacts'
EOF
cat >"$OPENVINO_SOURCE/scripts/run_coverage_openvino.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$PWD" == "$PROJECT_ROOT" && "$OUT_DIR" == \
   "$OPENVINO_TARGET_ROOT/instrumentation-evidence/coverage" ]] || exit 89
[[ ! -e "$OUT_DIR" ]] || exit 90
mkdir -p "$OUT_DIR"
printf '{}\n' >"$OUT_DIR/coverage.json"
printf 'copy-local OpenVINO coverage evidence\n' >"$OUT_DIR/evidence.marker"
echo '[fixture-openvino-coverage-run] wrote copy-local coverage evidence'
EOF
chmod +x "$OPENVINO_SOURCE/scripts/build_openvino_profiles.sh" \
  "$OPENVINO_SOURCE/scripts/build_openvino_guided.sh" \
  "$OPENVINO_SOURCE/scripts/build_coverage_openvino.sh" \
  "$OPENVINO_SOURCE/scripts/run_coverage_openvino.sh"
cat >"$OPENVINO_SOURCE/scripts/check_openvino_instrumentation.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$OPENVINO_TARGET_ROOT" == "$PROJECT_ROOT/data/targets/openvino-ir/.check-suite-2026.4.1-"* ]]
grep -Fxq 'copy-local OpenVINO normal build' "$OPENVINO_TARGET_ROOT/normal.marker"
grep -Fxq 'copy-local OpenVINO guided build' "$OPENVINO_TARGET_ROOT/guided.marker"
grep -Fxq 'copy-local OpenVINO coverage build' "$OPENVINO_TARGET_ROOT/coverage.marker"
grep -Fxq 'copy-local OpenVINO coverage evidence' \
  "$OPENVINO_TARGET_ROOT/instrumentation-evidence/coverage/evidence.marker"
EOF
chmod +x "$OPENVINO_SOURCE/scripts/check_openvino_instrumentation.sh"
cp -a "$OPENVINO_SOURCE/." "$OPENVINO_COPY/"
rc=0
OPENVINO_TARGET_ROOT="$SOURCE/escaped-openvino-root" \
OPENVINO_ARCHIVE="$SOURCE/escaped-openvino-archive" \
OPENVINO_COVERAGE_EVIDENCE="$SOURCE/escaped-openvino-evidence" \
CMAKE="$SOURCE/escaped-cmake" NINJA="$SOURCE/escaped-ninja" \
CLANG="$SOURCE/escaped-clang" CLANGXX="$SOURCE/escaped-clangxx" \
READELF="$SOURCE/escaped-readelf" JOBS=99 \
bash "$OPENVINO_SOURCE/scripts/run_check_suite.sh" \
  --isolated-root "$OPENVINO_COPY" --log-dir "$WORK/openvino-logs" \
  >"$WORK/openvino.log" 2>&1 || rc=$?
[[ "$rc" -eq 0 ]] || {
  cat "$WORK/openvino.log"
  echo "copy-local OpenVINO instrumentation was not rebuilt (rc=$rc)" >&2
  exit 1
}
grep -Fq 'check_openvino_instrumentation.sh: PASS' "$WORK/openvino.log"
grep -Fq '[fixture-openvino-build] rebuilt copy-local normal profile' \
  "$WORK/openvino-logs/setup-openvino.log"
grep -Fq '[fixture-openvino-guided] rebuilt copy-local guided artifacts' \
  "$WORK/openvino-logs/setup-openvino-guided.log"
grep -Fq '[fixture-openvino-coverage] rebuilt copy-local coverage artifacts' \
  "$WORK/openvino-logs/setup-openvino-coverage.log"
grep -Fq '[fixture-openvino-coverage-run] wrote copy-local coverage evidence' \
  "$WORK/openvino-logs/setup-openvino-coverage-run.log"
[[ -z "$(find "$OPENVINO_COPY/data/targets/openvino-ir" -maxdepth 1 -type d \
  -name '.check-suite-2026.4.1-*' -print -quit)" ]] || {
  echo 'runner left its temporary OpenVINO target root behind' >&2
  exit 1
}
[[ ! -e "$SOURCE/escaped-openvino-root" \
   && ! -e "$SOURCE/escaped-openvino-archive" \
   && ! -e "$SOURCE/escaped-openvino-evidence" ]] || {
  echo 'copy-local OpenVINO builder wrote through an inherited output path' >&2
  exit 1
}

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
