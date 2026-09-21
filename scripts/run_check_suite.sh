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
vendored dependencies, harnesses, debug tool, and coverage replay must match
the source before any gate runs. Input data under data/ and seeds/ is supplied
by the caller and is not compared. Parent native executable, source-path,
and Bash startup overrides are removed from each gate environment.

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
    templates vendor harnesses target/debug/tool \
    fuzz/target-cov/safetensors_loader_replay_cov; do
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

printf '[suite] source=%s\n[suite] isolated=%s\n[suite] logs=%s\n' \
  "$SOURCE_ROOT" "$ISOLATED_ROOT" "$LOG_DIR"
printf '[suite] ALLOW_SKIPPED_CASES is unset for every gate\n'
printf 'gate\tverdict\trc\tskip_seen\tlog\n' >"$LOG_DIR/summary.tsv"

has_skip_evidence() {
  local log="$1"
  grep -Eq '^\[[^]]+\][[:space:]]+(SKIP:|skip([[:space:]:]|$)|.*skipping([[:space:](]|$)|WARN: continuing with .*skipp?ed|.*[[:space:]]skip=[1-9][0-9]*([[:space:]]|$)|.*[[:space:]]skipped[[:space:]]+[1-9][0-9]*([[:space:]]|$))' "$log"
}

# An exported Bash function can survive the first gate shell and be imported by
# a nested Bash process. Remove function exports as well as startup controls.
shell_env_unsets=(-u BASH_ENV -u ENV -u BASHOPTS -u SHELLOPTS \
  -u CDPATH -u GLOBIGNORE)
while IFS= read -r -d '' assignment; do
  name="${assignment%%=*}"
  case "$name" in
    BASH_FUNC_*) shell_env_unsets+=(-u "$name") ;;
  esac
done < <(env -0)

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
