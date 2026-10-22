#!/usr/bin/env bash
# Run the current check_*.sh suite in a caller-prepared copy. The checkers deliberately
# retain their operating output and seed defaults; this runner keeps those writes out of
# the source tree and reports an rc=0 with skipped cases separately from a clean pass.
set -euo pipefail
export LC_ALL=C

SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
ISOLATED_ROOT=""
LOG_DIR=""

usage() {
  cat <<'EOF'
usage: run_check_suite.sh --isolated-root DIR [--log-dir DIR]

Start the runner with a clean Bash entry:
  env -u BASH_ENV -u ENV -u BASHOPTS -u SHELLOPTS bash -p scripts/run_check_suite.sh ...

DIR must be a separate, complete copy of the current source tree, including required
gitignored seeds, native harnesses, the built tool, and target data. Run this script
from the source tree; all check_*.sh scripts execute from DIR. DIR must contain no
hardlinked files or symbolic links that resolve outside DIR. Logs are preserved.
The scripts, ops scripts, Rust and fuzz source, Cargo manifests, templates,
vendored dependencies, harnesses, and debug tool must match the source before
any gate runs. The safetensors coverage replay is then rebuilt inside DIR from
those verified inputs; its bytes are expected to differ because coverage maps
contain the copy's absolute path. Input data under data/ and seeds/ is supplied
by the caller and is not compared. Parent native executable, source-path,
build-output, and Bash startup overrides are removed.

PASS means rc=0 with no recognized skip; SKIP means rc=0 with a recognized skip.
FAIL means rc!=0, even if a skip was also reported. fail_with_skip is the number
of FAIL gates that also reported a skip. Skip detection uses the checkers' skip
messages and numeric ledgers; inspect each preserved log for case-level detail.
EOF
}

fail_setup() {
  printf '[suite] fail: %s\n' "$*" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --isolated-root)
      [[ $# -ge 2 && -z "$ISOLATED_ROOT" ]] || fail_setup '--isolated-root needs one directory'
      ISOLATED_ROOT="$2"
      shift 2
      ;;
    --log-dir)
      [[ $# -ge 2 && -z "$LOG_DIR" ]] || fail_setup '--log-dir needs one new directory'
      LOG_DIR="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail_setup "unknown argument: $1" ;;
  esac
done

[[ -n "$ISOLATED_ROOT" ]] || fail_setup '--isolated-root is required'
[[ -d "$ISOLATED_ROOT" ]] || fail_setup "isolated root is not a directory: $ISOLATED_ROOT"
ISOLATED_ROOT="$(cd -- "$ISOLATED_ROOT" && pwd -P)"
case "$ISOLATED_ROOT/" in
  "$SOURCE_ROOT/"|"$SOURCE_ROOT/"*)
    fail_setup 'isolated root must differ from source and cannot be inside it' ;;
esac
case "$SOURCE_ROOT/" in
  "$ISOLATED_ROOT/"*)
    fail_setup 'isolated root must differ from source and cannot contain it' ;;
esac
[[ -d "$ISOLATED_ROOT/scripts" && ! -L "$ISOLATED_ROOT/scripts" ]] \
  || fail_setup 'isolated root needs its own scripts directory'

# A linked copy can quietly write through to the source, including ignored paths.
# Refuse symbolic links outside the copy and any multiply linked file in the copy.
# A copy-side check also covers source directories that the caller cannot read.
scan_dir="$(mktemp -d /tmp/check-suite-scan-XXXXXX)"
trap 'rm -rf -- "$scan_dir"' EXIT
find "$ISOLATED_ROOT" -type l -print0 >"$scan_dir/links" \
  || fail_setup 'could not inspect links in isolated copy'
while IFS= read -r -d '' link; do
  resolved="$(realpath -m -- "$link")"
  case "$resolved/" in
    "$SOURCE_ROOT/"|"$SOURCE_ROOT/"*)
      fail_setup "isolated copy links into source: $link -> $resolved" ;;
  esac
  case "$resolved/" in
    "$ISOLATED_ROOT/"|"$ISOLATED_ROOT/"*) : ;;
    *) fail_setup "isolated copy links outside isolated root: $link -> $resolved" ;;
  esac
done <"$scan_dir/links"
hardlinked_file="$(find "$ISOLATED_ROOT" -type f -links +1 -print -quit)" \
  || fail_setup 'could not inspect hardlinks in isolated copy'
[[ -z "$hardlinked_file" ]] \
  || fail_setup "isolated copy contains hardlinked files: $hardlinked_file"
rm -rf -- "$scan_dir"
trap - EXIT

shopt -s nullglob
source_checks=("$SOURCE_ROOT"/scripts/check_*.sh)
copy_checks=("$ISOLATED_ROOT"/scripts/check_*.sh)
[[ ${#source_checks[@]} -gt 0 ]] || fail_setup 'source has no check_*.sh scripts'
[[ ${#source_checks[@]} -eq ${#copy_checks[@]} ]] || fail_setup 'gate lists differ between source and isolated copy'
for i in "${!source_checks[@]}"; do
  name="$(basename -- "${source_checks[$i]}")"
  [[ "$(basename -- "${copy_checks[$i]}")" == "$name" ]] \
    || fail_setup 'gate lists differ between source and isolated copy'
  cmp -s -- "${source_checks[$i]}" "${copy_checks[$i]}" \
    || fail_setup "gate content differs from source: $name"
done

# The gate files alone are not enough: they source helpers, launch other scripts,
# inspect source, and execute built tools and native harnesses. A stale copy can
# otherwise turn a source failure into a PASS. Compare these dependencies before
# running any gate; mutable data and seeds are caller-supplied test inputs.
for dependency in scripts ops/scripts src Cargo.toml Cargo.lock \
    fuzz/Cargo.toml fuzz/Cargo.lock fuzz/src fuzz/fuzz_targets \
    templates vendor harnesses target/debug/tool; do
  source_path="$SOURCE_ROOT/$dependency"
  copy_path="$ISOLATED_ROOT/$dependency"
  if [[ ! -e "$source_path" && ! -L "$source_path" \
        && ! -e "$copy_path" && ! -L "$copy_path" ]]; then
    continue
  fi
  diff -qr -- "$source_path" "$copy_path" >/dev/null 2>&1 \
    || fail_setup "$dependency differs from source"
  if [[ -d "$source_path" ]]; then
    source_modes="$(cd -- "$source_path" && find . -printf '%P:%m\n' | sort)" \
      || fail_setup "could not inspect source modes: $dependency"
    copy_modes="$(cd -- "$copy_path" && find . -printf '%P:%m\n' | sort)" \
      || fail_setup "could not inspect isolated modes: $dependency"
    [[ "$source_modes" == "$copy_modes" ]] \
      || fail_setup "$dependency modes differ from source"
  else
    [[ "$(stat -c %a -- "$source_path")" == "$(stat -c %a -- "$copy_path")" ]] \
      || fail_setup "$dependency mode differs from source"
  fi
done

if [[ -n "$LOG_DIR" ]]; then
  LOG_DIR="$(realpath -m -- "$LOG_DIR")"
  case "$LOG_DIR/" in
    "$SOURCE_ROOT/"|"$SOURCE_ROOT/"*) fail_setup 'log dir cannot be inside source' ;;
  esac
  [[ ! -e "$LOG_DIR" ]] || fail_setup "log dir already exists: $LOG_DIR"
  mkdir -p -- "$LOG_DIR"
else
  LOG_DIR="$(mktemp -d /tmp/check-suite-XXXXXX)"
fi

# An exported Bash function can survive the first shell and be imported by a
# nested Bash process. Remove function exports as well as startup controls.
shell_env_unsets=(-u BASH_ENV -u ENV -u BASHOPTS -u SHELLOPTS \
  -u CDPATH -u GLOBIGNORE)
while IFS= read -r -d '' assignment; do
  name="${assignment%%=*}"
  case "$name" in
    BASH_FUNC_*) shell_env_unsets+=(-u "$name") ;;
  esac
done < <(env -0)

suite_cleanup_paths=()
suite_cleanup() {
  local path
  for path in "${suite_cleanup_paths[@]}"; do
    [[ -n "$path" ]] && rm -rf -- "$path"
  done
}
trap suite_cleanup EXIT
suite_gate_env=()

# R117: a source-built coverage binary embeds absolute source paths, so copying
# the source-tree binary into the isolated tree makes raw-reset filtering fail.
# The build script is already covered by the scripts/ identity check above.
# Rebuild from the verified copy cwd, with every supported output/compiler
# override removed, and accept only the fixed copy-local output.
coverage_builder_source="$SOURCE_ROOT/scripts/build_coverage_safetensors.sh"
coverage_builder_copy="$ISOLATED_ROOT/scripts/build_coverage_safetensors.sh"
coverage_replay_source="$SOURCE_ROOT/fuzz/target-cov/safetensors_loader_replay_cov"
coverage_replay_copy="$ISOLATED_ROOT/fuzz/target-cov/safetensors_loader_replay_cov"
if [[ -e "$coverage_builder_source" || -L "$coverage_builder_source" ]]; then
  [[ -f "$coverage_builder_copy" && ! -L "$coverage_builder_copy" ]] \
    || fail_setup 'isolated copy needs its own regular safetensors coverage builder'
  [[ -d "$ISOLATED_ROOT/fuzz" && ! -L "$ISOLATED_ROOT/fuzz" ]] \
    || fail_setup 'isolated copy needs its own regular fuzz directory'
  build_target_dir="$(mktemp -d -- "$ISOLATED_ROOT/fuzz/.check-suite-target-cov-XXXXXX")" \
    || fail_setup 'could not create a fresh copy-local coverage build directory'
  build_log="$LOG_DIR/setup-safetensors-coverage-replay.log"
  build_rc=0
  (
    cd -- "$ISOLATED_ROOT"
    env "${shell_env_unsets[@]}" \
      -u FUZZ_DIR -u COV_TARGET_DIR -u OUT_BIN \
      -u CARGO_TARGET_DIR -u CARGO_BUILD_TARGET_DIR -u CARGO_BUILD_TARGET \
      -u RUSTC -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
      -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u LLVM_PROFILE_FILE \
      -u PROJECT_ROOT -u WORKDIR -u TOOL_BIN \
      PROJECT_ROOT="$ISOLATED_ROOT" COV_TARGET_DIR="$build_target_dir" \
      OUT_BIN="$coverage_replay_copy" \
      bash -p scripts/build_coverage_safetensors.sh
  ) >"$build_log" 2>&1 || build_rc=$?
  rm -rf -- "$build_target_dir" \
    || fail_setup "could not remove temporary coverage build directory: $build_target_dir"
  [[ "$build_rc" -eq 0 ]] \
    || fail_setup "copy-local safetensors coverage replay build failed rc=$build_rc (log: $build_log)"
  [[ -f "$coverage_replay_copy" && ! -L "$coverage_replay_copy" \
     && -x "$coverage_replay_copy" ]] \
    || fail_setup 'copy-local safetensors coverage replay is not a regular executable file'
  replay_resolved="$(realpath -e -- "$coverage_replay_copy")" \
    || fail_setup 'could not resolve copy-local safetensors coverage replay'
  case "$replay_resolved/" in
    "$ISOLATED_ROOT/"*) : ;;
    *) fail_setup "coverage replay escaped isolated root: $replay_resolved" ;;
  esac
  replay_sha256="$(sha256sum -- "$coverage_replay_copy" | awk '{print $1}')" \
    || fail_setup 'could not hash copy-local safetensors coverage replay'
  printf '[suite] rebuilt safetensors coverage replay sha256=%s log=%s\n' \
    "$replay_sha256" "$build_log"
elif [[ -e "$coverage_replay_source" || -L "$coverage_replay_source" \
     || -e "$coverage_replay_copy" || -L "$coverage_replay_copy" ]]; then
  fail_setup 'safetensors coverage replay exists without its verified build script'
fi

# TFLite profile and fixture gates bind absolute paths for flatc, replay, the
# shared-loader fuzzer, and linked libraries. A byte-for-byte copy therefore
# cannot be valid in another root. Rebuild those artifacts inside a fresh,
# runner-owned target root and pass only that root to the gates.
tflite_builder_source="$SOURCE_ROOT/scripts/build_tflite_profiles.sh"
tflite_builder_copy="$ISOLATED_ROOT/scripts/build_tflite_profiles.sh"
tflite_archive_copy="$ISOLATED_ROOT/data/targets/tflite/v2.20.0/source/v2.20.0.tar.gz"
tflite_replay_copy="$ISOLATED_ROOT/harnesses/tflite/tflite_loader_replay"
tflite_fuzzer_copy="$ISOLATED_ROOT/harnesses/tflite/tflite_loader_fuzzer"
tflite_mutator_copy="$ISOLATED_ROOT/harnesses/tflite/tflite_structural_mutator"
if [[ -e "$tflite_builder_source" || -L "$tflite_builder_source" ]]; then
  [[ -f "$tflite_builder_copy" && ! -L "$tflite_builder_copy" ]] \
    || fail_setup 'isolated copy needs its own regular TFLite builder'
  [[ -f "$tflite_archive_copy" && ! -L "$tflite_archive_copy" ]] \
    || fail_setup 'isolated copy needs the pinned regular TFLite source archive'
  archive_resolved="$(realpath -e -- "$tflite_archive_copy")" \
    || fail_setup 'could not resolve copy-local TFLite source archive'
  case "$archive_resolved/" in
    "$ISOLATED_ROOT/"*) : ;;
    *) fail_setup "TFLite source archive escaped isolated root: $archive_resolved" ;;
  esac
  [[ -d "$ISOLATED_ROOT/data/targets/tflite" \
     && ! -L "$ISOLATED_ROOT/data/targets/tflite" ]] \
    || fail_setup 'isolated copy needs its own regular TFLite target parent'
  tflite_target_root="$(mktemp -d -- \
    "$ISOLATED_ROOT/data/targets/tflite/.check-suite-v2.20.0-XXXXXX")" \
    || fail_setup 'could not create a fresh copy-local TFLite target root'
  suite_cleanup_paths+=("$tflite_target_root")
  tflite_build_log="$LOG_DIR/setup-tflite.log"
  tflite_build_rc=0
  (
    cd -- "$ISOLATED_ROOT"
    env "${shell_env_unsets[@]}" \
      -u PROJECT_ROOT -u WORKDIR -u TOOL_BIN \
      -u TFLITE_TARGET_ROOT -u TFLITE_ARCHIVE \
      -u TFLITE_REPLAY -u TFLITE_FUZZER -u TFLITE_MUTATOR \
      -u JOBS -u CMAKE -u NINJA -u CLANG -u CLANGXX -u CC -u CXX \
      PROJECT_ROOT="$ISOLATED_ROOT" \
      TFLITE_TARGET_ROOT="$tflite_target_root" \
      TFLITE_ARCHIVE="$tflite_archive_copy" \
      TFLITE_REPLAY="$tflite_replay_copy" \
      TFLITE_FUZZER="$tflite_fuzzer_copy" \
      TFLITE_MUTATOR="$tflite_mutator_copy" JOBS=4 \
      bash -p scripts/build_tflite_profiles.sh
  ) >"$tflite_build_log" 2>&1 || tflite_build_rc=$?
  if [[ "$tflite_build_rc" -ne 0 ]]; then
    for build_log_name in configure.log patch.log build.log; do
      build_log_path="$tflite_target_root/$build_log_name"
      if [[ -f "$build_log_path" && ! -L "$build_log_path" ]]; then
        cp -- "$build_log_path" \
          "$LOG_DIR/setup-tflite-${build_log_name%.log}.log" \
          || fail_setup "could not preserve failed TFLite $build_log_name"
      fi
    done
    fail_setup "copy-local TFLite build failed rc=$tflite_build_rc (log: $tflite_build_log)"
  fi
  for artifact in \
    "$tflite_replay_copy" \
    "$tflite_fuzzer_copy" \
    "$tflite_mutator_copy" \
    "$tflite_target_root/meta.json" \
    "$tflite_target_root/profile.json" \
    "$tflite_target_root/build-identity.json"
  do
    [[ -f "$artifact" && ! -L "$artifact" ]] \
      || fail_setup "copy-local TFLite build produced no regular artifact: $artifact"
    artifact_resolved="$(realpath -e -- "$artifact")" \
      || fail_setup "could not resolve copy-local TFLite artifact: $artifact"
    case "$artifact_resolved/" in
      "$ISOLATED_ROOT/"*) : ;;
      *) fail_setup "TFLite build artifact escaped isolated root: $artifact_resolved" ;;
    esac
  done
  [[ -x "$tflite_replay_copy" && -x "$tflite_fuzzer_copy" \
     && -x "$tflite_mutator_copy" ]] \
    || fail_setup 'copy-local TFLite replay, fuzzer, and mutator must be executable'

  # TFL-05: the normal fuzzer intentionally instruments only its driver. Build
  # both target-object variants inside this same copy so the new gate cannot
  # pass by reading absolute mappings or archives left in the source tree.
  for tflite_variant in guided coverage; do
    case "$tflite_variant" in
      guided) tflite_variant_builder=scripts/build_tflite_guided.sh ;;
      coverage) tflite_variant_builder=scripts/build_coverage_tflite.sh ;;
    esac
    tflite_variant_log="$LOG_DIR/setup-tflite-$tflite_variant.log"
    tflite_variant_rc=0
    (
      cd -- "$ISOLATED_ROOT"
      env "${shell_env_unsets[@]}" \
        -u PROJECT_ROOT -u WORKDIR -u TOOL_BIN \
        -u TFLITE_TARGET_ROOT -u TFLITE_ARCHIVE -u TFLITE_SOURCE_DIR \
        -u TFLITE_BASE_BUILD_DIR -u TFLITE_GUIDED_BUILD_DIR \
        -u TFLITE_COVERAGE_BUILD_DIR -u TFLITE_FIXTURE \
        -u JOBS -u CMAKE -u NINJA -u CLANG -u CLANGXX -u CC -u CXX \
        -u LLVM_NM -u LLVM_OBJDUMP -u CLANG_BUNDLE_DIR \
        PROJECT_ROOT="$ISOLATED_ROOT" \
        TFLITE_TARGET_ROOT="$tflite_target_root" \
        TFLITE_ARCHIVE="$tflite_archive_copy" JOBS=4 \
        bash -p "$tflite_variant_builder"
    ) >"$tflite_variant_log" 2>&1 || tflite_variant_rc=$?
    [[ "$tflite_variant_rc" -eq 0 ]] \
      || fail_setup "copy-local TFLite $tflite_variant build failed rc=$tflite_variant_rc (log: $tflite_variant_log)"
  done
  for artifact in \
    "$tflite_target_root/build/guided-cmake/tensorflow-lite/libtensorflow-lite.a" \
    "$tflite_target_root/build/guided-cmake/tflite_loader_fuzzer" \
    "$tflite_target_root/guided-instrumentation.json" \
    "$tflite_target_root/build/coverage-cmake/tensorflow-lite/libtensorflow-lite.a" \
    "$tflite_target_root/build/coverage-cmake/tflite_loader_replay" \
    "$tflite_target_root/coverage-instrumentation.json"
  do
    [[ -f "$artifact" && ! -L "$artifact" ]] \
      || fail_setup "copy-local TFLite instrumentation build produced no regular artifact: $artifact"
    artifact_resolved="$(realpath -e -- "$artifact")" \
      || fail_setup "could not resolve copy-local TFLite instrumentation artifact: $artifact"
    case "$artifact_resolved/" in
      "$ISOLATED_ROOT/"*) : ;;
      *) fail_setup "TFLite instrumentation artifact escaped isolated root: $artifact_resolved" ;;
    esac
  done
  [[ -x "$tflite_target_root/build/guided-cmake/tflite_loader_fuzzer" \
     && -x "$tflite_target_root/build/coverage-cmake/tflite_loader_replay" ]] \
    || fail_setup 'copy-local TFLite guided fuzzer and coverage replay must be executable'
  suite_gate_env+=(
    "TFLITE_TARGET_ROOT=$tflite_target_root"
    "TFLITE_ARCHIVE=$tflite_archive_copy"
    "TFLITE_REPLAY=$tflite_replay_copy"
    "TFLITE_FUZZER=$tflite_fuzzer_copy"
    "TFLITE_MUTATOR=$tflite_mutator_copy"
    "TFLITE_GUIDED_BUILD_DIR=$tflite_target_root/build/guided-cmake"
    "TFLITE_COVERAGE_BUILD_DIR=$tflite_target_root/build/coverage-cmake"
  )
  printf '[suite] rebuilt TFLite artifacts target_root=%s log=%s\n' \
    "$tflite_target_root" "$tflite_build_log"
elif compgen -G "$SOURCE_ROOT/scripts/check_tflite_*.sh" >/dev/null; then
  fail_setup 'TFLite gates exist without their verified build script'
fi

printf '[suite] source=%s\n[suite] isolated=%s\n[suite] logs=%s\n' \
  "$SOURCE_ROOT" "$ISOLATED_ROOT" "$LOG_DIR"
printf '[suite] ALLOW_SKIPPED_CASES is unset for every gate\n'
printf 'gate\tverdict\trc\tskip_seen\tlog\n' >"$LOG_DIR/summary.tsv"

has_skip_evidence() {
  local log="$1"
  grep -Eq '^\[[^]]+\][[:space:]]+(SKIP:|skip([[:space:]:]|$)|.*skipping([[:space:](]|$)|WARN: continuing with .*skipp?ed|.*[[:space:]]skip=[1-9][0-9]*([[:space:]]|$)|.*[[:space:]]skipped[[:space:]]+[1-9][0-9]*([[:space:]]|$))' "$log"
}

pass=0
skip=0
fail=0
fail_with_skip=0
for gate in "${copy_checks[@]}"; do
  name="$(basename -- "$gate")"
  log="$LOG_DIR/$name.log"
  rc=0
  if ! env "${shell_env_unsets[@]}" \
      bash -p -n "$gate" >"$log" 2>&1; then
    rc=2
  else
    (
      cd -- "$ISOLATED_ROOT"
      env "${shell_env_unsets[@]}" \
        -u ALLOW_SKIPPED_CASES -u OUT_DIR -u AFLPP_CHECK_DIR -u LOG_DIR -u TMPDIR \
        -u SEED_ROOT -u SEED_DIR -u SEEDS_DIR -u VALID_DIR -u MAL_DIR -u DATA_DIR \
        -u CARGO_TARGET_DIR \
        -u REPLAY -u FUZZER -u AFLPP_REPLAY -u LEGACY_PROBE -u SRC \
        -u LIBFUZZER_DRIVER -u AFLPP_CONTAINER_TOOL \
        -u TOOL_LIBFUZZER_CMD -u TOOL_AFLPP_CMD \
        "${suite_gate_env[@]}" \
        PROJECT_ROOT="$ISOLATED_ROOT" WORKDIR="$ISOLATED_ROOT" \
        TOOL_BIN="$ISOLATED_ROOT/target/debug/tool" \
        bash -p "scripts/$name"
    ) >"$log" 2>&1 || rc=$?
  fi

  skip_seen=0
  if has_skip_evidence "$log"; then
    skip_seen=1
  fi
  if [[ "$rc" -ne 0 ]]; then
    verdict=FAIL
    fail=$((fail + 1))
    if [[ "$skip_seen" -eq 1 ]]; then
      fail_with_skip=$((fail_with_skip + 1))
    fi
  elif [[ "$skip_seen" -eq 1 ]]; then
    verdict=SKIP
    skip=$((skip + 1))
  else
    verdict=PASS
    pass=$((pass + 1))
  fi
  printf '[suite] %s: %s rc=%d skip_seen=%d log=%s\n' \
    "$name" "$verdict" "$rc" "$skip_seen" "$log"
  printf '%s\t%s\t%d\t%d\t%s\n' \
    "$name" "$verdict" "$rc" "$skip_seen" "$log" >>"$LOG_DIR/summary.tsv"
done

printf '[suite] pass=%d skip=%d fail=%d fail_with_skip=%d total=%d\n' \
  "$pass" "$skip" "$fail" "$fail_with_skip" "${#copy_checks[@]}"
[[ "$fail" -eq 0 ]]
