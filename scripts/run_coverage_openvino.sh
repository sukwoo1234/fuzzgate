#!/usr/bin/env bash
# OVI-05 source coverage: replay the exact FZB1 Constant pair through the
# OVI-03 common loader and require executed OpenVINO target-source ranges.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd -P)}"
TARGET_ROOT="${OPENVINO_TARGET_ROOT:-$PROJECT_ROOT/data/targets/openvino-ir/2026.4.1}"
COVERAGE_MANIFEST="${OPENVINO_COVERAGE_MANIFEST:-$TARGET_ROOT/coverage-instrumentation.json}"
OUT_DIR="${OUT_DIR:?OUT_DIR must name a new coverage evidence directory}"
CORPUS_DIR="${CORPUS_DIR:-$TARGET_ROOT/instrumentation-fixtures}"
TOOL_BIN="${CLANG_BUNDLE_DIR:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin}"
LLVM_PROFDATA="${LLVM_PROFDATA:-$TOOL_BIN/llvm-profdata}"
LLVM_COV="${LLVM_COV:-$TOOL_BIN/llvm-cov}"

log() { printf '[openvino-cov-run] %s\n' "$*"; }
fail() { printf '[openvino-cov-run] fail: %s\n' "$*" >&2; exit 1; }
blocked() { printf '[openvino-cov-run] blocked: %s\n' "$*" >&2; exit 2; }

[[ -f "$COVERAGE_MANIFEST" && ! -L "$COVERAGE_MANIFEST" ]] \
  || blocked "coverage build manifest unavailable: $COVERAGE_MANIFEST"
for tool in "$LLVM_PROFDATA" "$LLVM_COV"; do
  [[ -x "$tool" ]] || blocked "required LLVM coverage tool unavailable: $tool"
done
for input in "$CORPUS_DIR/constant-one.fzb" "$CORPUS_DIR/constant-two.fzb"; do
  [[ -f "$input" && ! -L "$input" ]] || blocked "required FZB1 pair member unavailable: $input"
done
[[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] \
  || fail "coverage output must be fresh; refusing existing path: $OUT_DIR"

mapfile -t components < <(python3 -B - "$COVERAGE_MANIFEST" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("schema_version") != "openvino-ir-instrumentation-v1":
    raise SystemExit("coverage manifest schema mismatch")
if document.get("mode") != "coverage":
    raise SystemExit("coverage manifest mode mismatch")
for role in ("driver", "core", "ir_frontend"):
    print(document["components"][role]["path"])
PY
) || fail 'could not read coverage component identities'
[[ ${#components[@]} -eq 3 ]] || fail 'coverage component identities are incomplete'
REPLAY="${components[0]}"
CORE_LIBRARY="${components[1]}"
IR_LIBRARY="${components[2]}"
for spec in "replay:$REPLAY" "Core:$CORE_LIBRARY" "IR frontend:$IR_LIBRARY"; do
  label="${spec%%:*}"
  path="${spec#*:}"
  [[ -f "$path" && ! -L "$path" ]] || fail "$label component unavailable: $path"
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
RUN_STARTED_NS="$(date +%s%N)"
[[ "$RUN_ID" =~ ^[0-9a-f]{32}$ ]] || fail 'could not create coverage run id'
[[ "$RUN_STARTED_NS" =~ ^[0-9]+$ ]] || fail 'could not record coverage run start'

PROFILE_PATTERN="$OUT_DIR/raw/$RUN_ID-%m-%p.profraw"
LD_LIBRARY_PATH="$(dirname -- "$CORE_LIBRARY")" \
LLVM_PROFILE_FILE="$PROFILE_PATTERN" \
  "$REPLAY" "$CORPUS_DIR/constant-one.fzb" "$CORPUS_DIR/constant-two.fzb" \
  >"$OUT_DIR/replay.log" 2>&1 \
  || fail "coverage replay failed; see $OUT_DIR/replay.log"
grep -Fq 'payload_hex=0000c03f' "$OUT_DIR/replay.log" \
  || fail 'coverage replay omitted constant-one payload evidence'
grep -Fq 'payload_hex=000010c0' "$OUT_DIR/replay.log" \
  || fail 'coverage replay omitted constant-two payload evidence'
[[ "$(grep -Fc 'OPENVINO_ACCESS_OK nodes=4 constants=1 constant_bytes=4' "$OUT_DIR/replay.log")" -eq 2 ]] \
  || fail 'coverage replay did not finish both reader/validation/Constant paths'

shopt -s nullglob
profiles=("$OUT_DIR/raw/$RUN_ID-"*.profraw)
shopt -u nullglob
[[ ${#profiles[@]} -gt 0 ]] || fail 'coverage replay emitted no run-owned raw profiles'
for profile in "${profiles[@]}"; do
  [[ -s "$profile" ]] || fail "coverage replay emitted an empty raw profile: $profile"
  [[ "$(stat -c '%Y' "$profile")" -ge "$((RUN_STARTED_NS / 1000000000))" ]] \
    || fail "coverage replay profile predates this run: $profile"
done

python3 -B - "$LLVM_PROFDATA" "$OUT_DIR/profile-map.json" "$OUT_DIR" "${profiles[@]}" <<'PY'
import json
import pathlib
import subprocess
import sys

tool, output_text, output_root_text, *profile_texts = sys.argv[1:]
output_root = pathlib.Path(output_root_text).resolve()
markers = {
    "driver": ("_ZN4tool15openvino_loader10LoadBundle",),
    "ir_frontend": ("_ZNK2ov8frontend2ir8FrontEnd14supported_impl",),
    "core": (
        "_ZNK2ov5Model30validate_nodes_and_infer_typesEv",
        "_ZNK2ov2op2v08Constant12get_data_ptrEv",
    ),
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
        raise SystemExit(
            f"[openvino-cov-run] fail: could not classify {profile.name}: "
            f"rc={completed.returncode} stderr={completed.stderr!r}"
        )
    matches = [
        role for role, required in markers.items()
        if all(marker in completed.stdout for marker in required)
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"[openvino-cov-run] fail: raw profile has ambiguous component ownership: "
            f"{profile.name} matches={matches!r}"
        )
    mapping[matches[0]].append(profile.relative_to(output_root).as_posix())
if any(not paths for paths in mapping.values()):
    raise SystemExit(f"[openvino-cov-run] fail: incomplete raw profile ownership: {mapping!r}")
pathlib.Path(output_text).write_text(
    json.dumps(mapping, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
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
mapfile -t ir_profiles < <(python3 -B - "$OUT_DIR/profile-map.json" "$OUT_DIR" <<'PY'
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for relative in document["ir_frontend"]:
    print(pathlib.Path(sys.argv[2], relative))
PY
)
[[ ${#core_profiles[@]} -gt 0 && ${#ir_profiles[@]} -gt 0 ]] \
  || fail 'component-specific profile lists are empty'

"$LLVM_PROFDATA" merge -sparse "${core_profiles[@]}" -o "$OUT_DIR/core.profdata" \
  || fail 'Core llvm-profdata merge failed'
"$LLVM_PROFDATA" merge -sparse "${ir_profiles[@]}" -o "$OUT_DIR/ir-frontend.profdata" \
  || fail 'IR frontend llvm-profdata merge failed'
[[ -s "$OUT_DIR/core.profdata" && -s "$OUT_DIR/ir-frontend.profdata" ]] \
  || fail 'component-specific merged source profile is empty'

if ! "$LLVM_COV" export -instr-profile="$OUT_DIR/core.profdata" "$CORE_LIBRARY" \
  >"$OUT_DIR/core-llvmcov.json" 2>"$OUT_DIR/core-llvmcov.log"; then
  fail 'Core llvm-cov export failed'
fi
if ! "$LLVM_COV" export -instr-profile="$OUT_DIR/ir-frontend.profdata" "$IR_LIBRARY" \
  >"$OUT_DIR/ir-frontend-llvmcov.json" 2>"$OUT_DIR/ir-frontend-llvmcov.log"; then
  fail 'IR frontend llvm-cov export failed'
fi
[[ -s "$OUT_DIR/core-llvmcov.json" && -s "$OUT_DIR/ir-frontend-llvmcov.json" ]] \
  || fail 'component-specific llvm-cov export is empty'
[[ ! -s "$OUT_DIR/core-llvmcov.log" && ! -s "$OUT_DIR/ir-frontend-llvmcov.log" ]] \
  || fail 'llvm-cov emitted component/profile mismatch diagnostics'

python3 -B - \
  "$OUT_DIR/core-llvmcov.json" "$OUT_DIR/ir-frontend-llvmcov.json" \
  "$OUT_DIR/coverage.json" "$OUT_DIR" \
  "$RUN_ID" "$RUN_STARTED_NS" "$TARGET_ROOT/build/source" \
  "$COVERAGE_MANIFEST" "$REPLAY" "$CORE_LIBRARY" "$IR_LIBRARY" \
  "$CORPUS_DIR/constant-one.fzb" "$CORPUS_DIR/constant-two.fzb" \
  "$SCRIPT_DIR/run_coverage_openvino.sh" "$OUT_DIR/profile-map.json" \
  "$OUT_DIR/core.profdata" "$OUT_DIR/ir-frontend.profdata" \
  "$OUT_DIR/core-llvmcov.log" "$OUT_DIR/ir-frontend-llvmcov.log" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    core_llvmcov_text, ir_llvmcov_text, output_text, output_root_text, run_id, started_text,
    source_root_text, manifest_text, replay_text, core_text, ir_text,
    input_one_text, input_two_text, runner_text, profile_map_text,
    core_profdata_text, ir_profdata_text, core_log_text, ir_log_text,
) = sys.argv[1:]
output_root = pathlib.Path(output_root_text).resolve()
source_root = pathlib.Path(source_root_text).resolve()
files = []
for llvmcov_text in (core_llvmcov_text, ir_llvmcov_text):
    document = json.loads(pathlib.Path(llvmcov_text).read_text(encoding="utf-8"))
    data = document.get("data")
    if not isinstance(data, list) or not data:
        raise SystemExit("[openvino-cov-run] fail: llvm-cov export has no data rows")
    for row in data:
        if isinstance(row, dict) and isinstance(row.get("files"), list):
            files.extend(entry for entry in row["files"] if isinstance(entry, dict))
if not files:
    raise SystemExit("[openvino-cov-run] fail: llvm-cov export has no file mappings")

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
    relative = resolved.relative_to(output_root).as_posix()
    return {"path": relative, "sha256": sha(resolved), "size_bytes": resolved.stat().st_size}

def source_id(filename):
    path = pathlib.Path(filename).resolve()
    try:
        return path.relative_to(source_root).as_posix()
    except ValueError:
        return None

indexed = {}
for entry in files:
    relative = source_id(str(entry.get("filename", "")))
    if relative is not None:
        indexed.setdefault(relative, []).append(entry)

probes = {
    "ir_reader_load": ("src/frontends/ir/src/frontend.cpp", 160, 263),
    "ir_reader_convert": ("src/frontends/ir/src/input_model.cpp", 258, 280),
    "validation_type_inference": ("src/core/src/model.cpp", 238, 280),
    "constant_access": ("src/core/src/op/constant.cpp", 421, 431),
}

def hit_in_range(entries, start, end):
    best = None
    for entry in entries:
        for segment in entry.get("segments", []):
            if len(segment) < 4:
                continue
            line, _column, count, has_count = segment[:4]
            if start <= line <= end and has_count and count > 0:
                candidate = (int(line), int(count))
                if best is None or candidate < best:
                    best = candidate
    return best

evidence = {}
for label, (source, start, end) in probes.items():
    hit = hit_in_range(indexed.get(source, []), start, end)
    if hit is None:
        raise SystemExit(
            f"[openvino-cov-run] fail: no executed OpenVINO target line for {label}"
        )
    evidence[label] = {"source": source, "line": hit[0], "count": hit[1]}

scope = sorted({source for source, _start, _end in probes.values()})
covered_lines = 0
total_lines = 0
covered_functions = 0
total_functions = 0
for source in scope:
    for entry in indexed.get(source, []):
        summary = entry.get("summary", {})
        lines = summary.get("lines", {})
        functions = summary.get("functions", {})
        covered_lines += int(lines.get("covered", 0))
        total_lines += int(lines.get("count", 0))
        covered_functions += int(functions.get("covered", 0))
        total_functions += int(functions.get("count", 0))
if min(covered_lines, total_lines, covered_functions, total_functions) <= 0:
    raise SystemExit("[openvino-cov-run] fail: target-source coverage totals are empty")

profile_records = []
for path in sorted((output_root / "raw").glob(f"{run_id}-*.profraw")):
    metadata = path.stat()
    if metadata.st_size <= 0:
        raise SystemExit(f"[openvino-cov-run] fail: empty raw profile: {path}")
    profile_records.append({
        "path": path.relative_to(output_root).as_posix(),
        "sha256": sha(path),
        "size_bytes": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
    })
if not profile_records:
    raise SystemExit("[openvino-cov-run] fail: no run-owned raw profiles")
profile_components = json.loads(pathlib.Path(profile_map_text).read_text(encoding="utf-8"))

result = {
    "schema_version": "openvino-ir-source-coverage-v1",
    "target": "openvino-ir",
    "target_version": "2026.4.1",
    "instrumentation": "llvm-source-cov",
    "coverage_manifest_sha256": sha(manifest_text),
    "runner": identity(runner_text),
    "fresh_output_created": True,
    "profile_run_id": run_id,
    "run_started_ns": int(started_text),
    "profile_files": profile_records,
    "profile_components": profile_components,
    "component_profdata": {
        "core": relative_identity(core_profdata_text),
        "ir_frontend": relative_identity(ir_profdata_text),
    },
    "coverage_exports": {
        "core": {
            "output": relative_identity(core_llvmcov_text),
            "diagnostics": relative_identity(core_log_text),
        },
        "ir_frontend": {
            "output": relative_identity(ir_llvmcov_text),
            "diagnostics": relative_identity(ir_log_text),
        },
    },
    "measured_components": {
        "driver": identity(replay_text),
        "core": identity(core_text),
        "ir_frontend": identity(ir_text),
    },
    "source_scope": scope,
    "measured_sources": scope,
    "required_path_hits": {label: True for label in probes},
    "required_path_evidence": evidence,
    "driver_only_evidence_accepted": False,
    "source_inputs": [
        {"name": pathlib.Path(path).name, "sha256": sha(path), "size_bytes": pathlib.Path(path).stat().st_size}
        for path in (input_one_text, input_two_text)
    ],
    "accepted_models": 2,
    "rejected_models": 0,
    "covered_lines": covered_lines,
    "total_lines": total_lines,
    "covered_functions": covered_functions,
    "total_functions": total_functions,
}
pathlib.Path(output_text).write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(
    f"[openvino-cov-run] target lines {covered_lines}/{total_lines} "
    f"functions {covered_functions}/{total_functions}"
)
for label, row in evidence.items():
    print(f"[openvino-cov-run] {label}: {row['source']}:{row['line']} count={row['count']}")
PY

log "wrote fresh source coverage evidence $OUT_DIR/coverage.json"
