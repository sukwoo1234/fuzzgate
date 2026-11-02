#!/usr/bin/env bash
# HDF-05 source coverage: replay a built-in-filter fixture through HDF-03's
# common LoadImage path and require executed HDF5 reader/dataset/filter lines.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd -P)}"
TARGET_ROOT="${HDF5_TARGET_ROOT:-$PROJECT_ROOT/data/targets/hdf5-weights/2.2.0}"
COVERAGE_MANIFEST="${HDF5_COVERAGE_MANIFEST:-$TARGET_ROOT/coverage-instrumentation.json}"
OUT_DIR="${OUT_DIR:?OUT_DIR must name a new coverage evidence directory}"
FIXTURE="${HDF5_INSTRUMENTATION_FIXTURE:-$TARGET_ROOT/instrumentation-fixtures/shuffle-fletcher32.h5}"
TOOL_BIN="${CLANG_BUNDLE_DIR:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin}"
LLVM_PROFDATA="${LLVM_PROFDATA:-$TOOL_BIN/llvm-profdata}"
LLVM_COV="${LLVM_COV:-$TOOL_BIN/llvm-cov}"

log() { printf '[hdf5-cov-run] %s\n' "$*"; }
fail() { printf '[hdf5-cov-run] fail: %s\n' "$*" >&2; exit 1; }
blocked() { printf '[hdf5-cov-run] blocked: %s\n' "$*" >&2; exit 2; }

[[ -f "$COVERAGE_MANIFEST" && ! -L "$COVERAGE_MANIFEST" ]] \
  || blocked "coverage manifest unavailable: $COVERAGE_MANIFEST"
[[ -f "$FIXTURE" && ! -L "$FIXTURE" ]] || blocked "filtered fixture unavailable: $FIXTURE"
for tool in "$LLVM_PROFDATA" "$LLVM_COV"; do
  [[ -x "$tool" ]] || blocked "LLVM coverage tool unavailable: $tool"
done
[[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] \
  || fail "coverage output must be fresh: $OUT_DIR"

mapfile -t components < <(python3 -B - "$COVERAGE_MANIFEST" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("schema_version") != "hdf5-weights-instrumentation-v1":
    raise SystemExit("coverage manifest schema mismatch")
if document.get("mode") != "coverage":
    raise SystemExit("coverage manifest mode mismatch")
for role in ("driver", "core", "high_level"):
    print(document["components"][role]["path"])
PY
) || fail 'could not read coverage component identities'
[[ ${#components[@]} -eq 3 ]] || fail 'coverage component identities are incomplete'
REPLAY="${components[0]}"
CORE_LIBRARY="${components[1]}"
HL_LIBRARY="${components[2]}"
for component in "$REPLAY" "$CORE_LIBRARY" "$HL_LIBRARY"; do
  [[ -f "$component" && ! -L "$component" ]] || fail "coverage component unavailable: $component"
done
[[ -x "$REPLAY" ]] || fail "coverage replay is not executable: $REPLAY"

mkdir -p -- "$(dirname -- "$OUT_DIR")"
mkdir -- "$OUT_DIR"
mkdir -- "$OUT_DIR/raw"
RUN_ID="$(python3 -B - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)"
RUN_STARTED_NS="$(python3 -B - "$OUT_DIR/raw" <<'PY'
import pathlib
import sys

print(pathlib.Path(sys.argv[1]).stat().st_mtime_ns)
PY
)" || fail 'could not read the coverage output filesystem clock'
[[ "$RUN_ID" =~ ^[0-9a-f]{32}$ && "$RUN_STARTED_NS" =~ ^[0-9]+$ ]] \
  || fail 'could not create coverage run identity'

LD_LIBRARY_PATH="$(dirname -- "$CORE_LIBRARY")" HDF5_PLUGIN_PATH= \
LLVM_PROFILE_FILE="$OUT_DIR/raw/$RUN_ID-%m-%p.profraw" \
  "$REPLAY" "$FIXTURE" >"$OUT_DIR/replay.log" 2>&1 \
  || fail "coverage replay failed; see $OUT_DIR/replay.log"
grep -Fq 'HDF5_RESULT classification=accepted stage=complete reason=loaded' "$OUT_DIR/replay.log" \
  || fail 'coverage replay did not accept the filtered fixture'
grep -Fq 'path_hex=2f696e737472756d656e746564' "$OUT_DIR/replay.log" \
  || fail 'coverage replay omitted the filtered dataset'
grep -Fq 'values=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16' "$OUT_DIR/replay.log" \
  || fail 'coverage replay did not decode the filtered values'
grep -Fq 'HDF5_ACCESS_OK datasets=1 attributes=0 h5dread_calls=1 read_bytes=128' "$OUT_DIR/replay.log" \
  || fail 'coverage replay did not finish the dataset read path'

shopt -s nullglob
profiles=("$OUT_DIR/raw/$RUN_ID-"*.profraw)
shopt -u nullglob
[[ ${#profiles[@]} -gt 0 ]] || fail 'coverage replay emitted no run-owned raw profile'
for profile in "${profiles[@]}"; do
  [[ -s "$profile" ]] || fail "empty raw profile: $profile"
  [[ "$(stat -c '%Y' "$profile")" -ge "$((RUN_STARTED_NS / 1000000000))" ]] \
    || fail "raw profile predates this run: $profile"
done

python3 -B - "$LLVM_PROFDATA" "$OUT_DIR/profile-map.json" "$OUT_DIR" "${profiles[@]}" <<'PY'
import json
import pathlib
import subprocess
import sys

tool, output_text, root_text, *profile_texts = sys.argv[1:]
root = pathlib.Path(root_text).resolve()
markers = {
    "driver": ("_ZN4tool11hdf5_loader9LoadImage",),
    "high_level": ("H5LTopen_file_image",),
    "core": ("H5D__read", "H5F_shared_block_read", "H5Z_pipeline"),
}
mapping = {role: [] for role in markers}
for profile_text in profile_texts:
    profile = pathlib.Path(profile_text).resolve()
    completed = subprocess.run(
        [tool, "show", "--all-functions", str(profile)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0 or completed.stderr:
        raise SystemExit(f"could not classify {profile.name}: {completed.stderr!r}")
    matches = [role for role, required in markers.items() if all(marker in completed.stdout for marker in required)]
    if len(matches) != 1:
        raise SystemExit(f"ambiguous raw profile ownership: {profile.name} matches={matches!r}")
    mapping[matches[0]].append(profile.relative_to(root).as_posix())
if any(not paths for paths in mapping.values()):
    raise SystemExit(f"incomplete raw profile ownership: {mapping!r}")
pathlib.Path(output_text).write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

mapfile -t core_profiles < <(python3 -B - "$OUT_DIR/profile-map.json" "$OUT_DIR" <<'PY'
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for relative in document["core"]:
    print(pathlib.Path(sys.argv[2], relative))
PY
)
mapfile -t hl_profiles < <(python3 -B - "$OUT_DIR/profile-map.json" "$OUT_DIR" <<'PY'
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for relative in document["high_level"]:
    print(pathlib.Path(sys.argv[2], relative))
PY
)
[[ ${#core_profiles[@]} -gt 0 && ${#hl_profiles[@]} -gt 0 ]] \
  || fail 'component-specific raw profile list is empty'
"$LLVM_PROFDATA" merge -sparse "${core_profiles[@]}" -o "$OUT_DIR/core.profdata" \
  || fail 'core profile merge failed'
"$LLVM_PROFDATA" merge -sparse "${hl_profiles[@]}" -o "$OUT_DIR/high-level.profdata" \
  || fail 'high-level profile merge failed'
if ! "$LLVM_COV" export -instr-profile="$OUT_DIR/core.profdata" "$CORE_LIBRARY" \
  "$TARGET_ROOT/build/source/src/H5Fio.c" \
  "$TARGET_ROOT/build/source/src/H5Dio.c" \
  "$TARGET_ROOT/build/source/src/H5Dchunk.c" \
  "$TARGET_ROOT/build/source/src/H5Z.c" \
  "$TARGET_ROOT/build/source/src/H5Zshuffle.c" \
  "$TARGET_ROOT/build/source/src/H5Zfletcher32.c" \
  >"$OUT_DIR/core-llvmcov.json" 2>"$OUT_DIR/core-llvmcov.log"; then
  fail 'core llvm-cov export failed'
fi
[[ -s "$OUT_DIR/core-llvmcov.json" && ! -s "$OUT_DIR/core-llvmcov.log" ]] \
  || fail 'core llvm-cov export is empty or has mismatch diagnostics'

python3 -B - \
  "$OUT_DIR/core-llvmcov.json" "$OUT_DIR/coverage.json" "$OUT_DIR" \
  "$RUN_ID" "$RUN_STARTED_NS" "$TARGET_ROOT/build/source" \
  "$COVERAGE_MANIFEST" "$REPLAY" "$CORE_LIBRARY" "$HL_LIBRARY" "$FIXTURE" \
  "$SCRIPT_DIR/run_coverage_hdf5.sh" "$OUT_DIR/profile-map.json" \
  "$OUT_DIR/core.profdata" "$OUT_DIR/high-level.profdata" "$OUT_DIR/core-llvmcov.log" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    llvmcov_text, output_text, output_root_text, run_id, started_text,
    source_root_text, manifest_text, replay_text, core_text, hl_text,
    fixture_text, runner_text, profile_map_text, core_profdata_text,
    hl_profdata_text, diagnostics_text,
) = sys.argv[1:]
output_root = pathlib.Path(output_root_text).resolve()
source_root = pathlib.Path(source_root_text).resolve()
document = json.loads(pathlib.Path(llvmcov_text).read_text(encoding="utf-8"))
files = []
for row in document.get("data", []):
    files.extend(entry for entry in row.get("files", []) if isinstance(entry, dict))
if not files:
    raise SystemExit("llvm-cov export has no file mappings")

def sha(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def identity(path):
    resolved = pathlib.Path(path).resolve()
    return {"path": str(resolved), "sha256": sha(resolved)}

def relative_identity(path):
    resolved = pathlib.Path(path).resolve()
    return {
        "path": resolved.relative_to(output_root).as_posix(),
        "sha256": sha(resolved),
        "size_bytes": resolved.stat().st_size,
    }

indexed = {}
for entry in files:
    filename = pathlib.Path(str(entry.get("filename", ""))).resolve()
    try:
        relative = filename.relative_to(source_root).as_posix()
    except ValueError:
        continue
    indexed.setdefault(relative, []).append(entry)

probes = {
    "reader_block_read": ("src/H5Fio.c", 77, 102),
    "dataset_read": ("src/H5Dio.c", 77, 491),
    "chunk_unfilter": ("src/H5Dchunk.c", 4825, 4885),
    "filter_pipeline": ("src/H5Z.c", 1372, 1515),
    "shuffle_decode": ("src/H5Zshuffle.c", 108, 214),
    "fletcher32_decode": ("src/H5Zfletcher32.c", 49, 108),
}

def hit(entries, source, start, end):
    choices = []
    source_lines = (source_root / source).read_text(encoding="utf-8").splitlines()
    for entry in entries:
        for segment in entry.get("segments", []):
            if len(segment) >= 4:
                line, _column, count, has_count = segment[:4]
                text = source_lines[line - 1].strip() if 0 < line <= len(source_lines) else ""
                is_code = bool(text) and not text.startswith(("/*", "*", "//"))
                if start <= line <= end and has_count and count > 0 and is_code:
                    choices.append((int(line), int(count)))
    return min(choices) if choices else None

evidence = {}
for label, (source, start, end) in probes.items():
    observed = hit(indexed.get(source, []), source, start, end)
    if observed is None:
        raise SystemExit(f"no executed HDF5 target line for {label}")
    evidence[label] = {"source": source, "line": observed[0], "count": observed[1]}

scope = sorted({row[0] for row in probes.values()})
covered_lines = total_lines = covered_functions = total_functions = 0
for source in scope:
    for entry in indexed.get(source, []):
        summary = entry.get("summary", {})
        covered_lines += int(summary.get("lines", {}).get("covered", 0))
        total_lines += int(summary.get("lines", {}).get("count", 0))
        covered_functions += int(summary.get("functions", {}).get("covered", 0))
        total_functions += int(summary.get("functions", {}).get("count", 0))
if min(covered_lines, total_lines, covered_functions, total_functions) <= 0:
    raise SystemExit("target-source coverage totals are empty")

profiles = []
for path in sorted((output_root / "raw").glob(f"{run_id}-*.profraw")):
    metadata = path.stat()
    profiles.append({
        "path": path.relative_to(output_root).as_posix(),
        "sha256": sha(path),
        "size_bytes": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
    })
if not profiles or any(row["size_bytes"] <= 0 for row in profiles):
    raise SystemExit("run-owned raw profile set is empty")

profile_components = json.loads(pathlib.Path(profile_map_text).read_text(encoding="utf-8"))
result = {
    "schema_version": "hdf5-weights-source-coverage-v1",
    "target": "hdf5-weights",
    "target_version": "2.2.0",
    "instrumentation": "llvm-source-cov",
    "coverage_manifest_sha256": sha(manifest_text),
    "runner": identity(runner_text),
    "fresh_output_created": True,
    "profile_run_id": run_id,
    "run_started_ns": int(started_text),
    "profile_files": profiles,
    "profile_components": profile_components,
    "component_profdata": {
        "core": relative_identity(core_profdata_text),
        "high_level": relative_identity(hl_profdata_text),
    },
    "coverage_export": {
        "output": relative_identity(llvmcov_text),
        "diagnostics": relative_identity(diagnostics_text),
    },
    "measured_components": {
        "driver": identity(replay_text),
        "core": identity(core_text),
        "high_level": identity(hl_text),
    },
    "source_scope": scope,
    "measured_sources": scope,
    "required_path_hits": {label: True for label in probes},
    "required_path_evidence": evidence,
    "driver_only_evidence_accepted": False,
    "source_inputs": [{
        "name": pathlib.Path(fixture_text).name,
        "sha256": sha(fixture_text),
        "size_bytes": pathlib.Path(fixture_text).stat().st_size,
    }],
    "accepted_inputs": 1,
    "rejected_inputs": 0,
    "covered_lines": covered_lines,
    "total_lines": total_lines,
    "covered_functions": covered_functions,
    "total_functions": total_functions,
}
pathlib.Path(output_text).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"[hdf5-cov-run] target lines {covered_lines}/{total_lines} functions {covered_functions}/{total_functions}")
for label, row in evidence.items():
    print(f"[hdf5-cov-run] {label}: {row['source']}:{row['line']} count={row['count']}")
PY

log "wrote fresh source coverage evidence $OUT_DIR/coverage.json"
