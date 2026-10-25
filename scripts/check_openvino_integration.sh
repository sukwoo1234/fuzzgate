#!/usr/bin/env bash
# OVI-06: prove OpenVINO IR registry/profile dispatch and complete FZB1
# preservation through tool, run, triage, report, strict export, and UI output.
set -u
ulimit -c 0 || true

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
TARGET_ROOT="${OPENVINO_TARGET_ROOT:-$PROJECT_ROOT/data/targets/openvino-ir/2026.4.1}"
BUILD_PROFILE="$TARGET_ROOT/build-profile.json"
PROFILE="${OPENVINO_PROFILE:-$TARGET_ROOT/profile.json}"
FIXTURES="${OPENVINO_FIXTURES:-$TARGET_ROOT/instrumentation-fixtures}"
CONSTANT_ONE="${OPENVINO_CONSTANT_ONE:-$FIXTURES/constant-one.fzb}"
CONSTANT_TWO="${OPENVINO_CONSTANT_TWO:-$FIXTURES/constant-two.fzb}"
MISSING_BIN="${OPENVINO_MISSING_BIN:-$FIXTURES/missing-bin.fzb}"
MALFORMED_XML="${OPENVINO_MALFORMED_XML:-$FIXTURES/malformed-xml.fzb}"

PASS=0
FAIL=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tool-openvino-integration.XXXXXX")" || exit 2
DATA_DIR="$WORK/data"
SEEDS_DIR="$WORK/seeds"

ok() {
  PASS=$((PASS + 1))
  printf '[openvino-integration] ok: %s\n' "$1"
}

bad() {
  FAIL=$((FAIL + 1))
  printf '[openvino-integration] fail: %s\n' "$1" >&2
}

finish() {
  rm -rf -- "$WORK"
}
trap finish EXIT

summary() {
  printf '[openvino-integration] pass=%d fail=%d blocked=0\n' "$PASS" "$FAIL"
}

stop_after_failure() {
  summary
  exit 1
}

blocked() {
  printf '[openvino-integration] blocked: %s\n' "$1" >&2
  printf '[openvino-integration] this gate cannot run\n' >&2
  printf '[openvino-integration] pass=%d fail=%d blocked=1\n' "$PASS" "$FAIL"
  exit 2
}

mkdir -p -- "$DATA_DIR" "$SEEDS_DIR"
if [[ ! -x "$TOOL_BIN" ]]; then
  blocked "tool binary is not executable: $TOOL_BIN"
fi
for command_name in python3 sha256sum grep find cp cmp cut kill; do
  command -v "$command_name" >/dev/null 2>&1 \
    || blocked "required command is unavailable: $command_name"
done

# Registry support is production code, while target artifacts are external build
# state. Check dispatch first so an unimplemented target is a RED, not a skip.
"$TOOL_BIN" target-spec --target openvino-ir --format json \
  >"$WORK/target-spec.json" 2>"$WORK/target-spec.err"
target_spec_rc=$?
if [[ "$target_spec_rc" -eq 0 ]] \
  && python3 -B - "$WORK/target-spec.json" <<'PY'
import json
import sys

spec = json.load(open(sys.argv[1], encoding="utf-8"))
assert spec["target_id"] == "openvino-ir"
assert spec["seed_subdir"] == "openvino-ir"
assert spec["input_ext"] == "fzb"
assert spec["coverage_env_key"] == "TOOL_COVERAGE_OPENVINO_CMD"
assert spec["coverage_runner"] == "scripts/run_coverage_openvino.sh"
assert spec["external_harness_env"] == "TOOL_OPENVINO_IR_HARNESS_CMD"
assert spec["mutation_supported"] is False
assert spec["campaign_supported"] is False
assert spec["ui_supported"] is False
PY
then
  ok "registry dispatches openvino-ir without promoting unqualified capabilities"
else
  bad "openvino-ir registry dispatch or capability boundary is unavailable"
  sed -n '1,12p' "$WORK/target-spec.err" >&2
  stop_after_failure
fi

if python3 -B - "$PROJECT_ROOT/src/main.rs" <<'PY'
import pathlib
import sys

lines = [
    line.strip()
    for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    if "Target type:" in line
]
if not lines:
    raise SystemExit("no target help declarations found")
stale = [line for line in lines if "openvino-ir" not in line]
if stale:
    raise SystemExit(f"{len(stale)} target help declarations omit openvino-ir")
PY
then
  ok "every CLI target help declaration names openvino-ir"
else
  bad "CLI target help is stale after registering openvino-ir"
  stop_after_failure
fi

for pair in \
  "build profile:$BUILD_PROFILE" \
  "execution profile:$PROFILE" \
  "constant-one fixture:$CONSTANT_ONE" \
  "constant-two fixture:$CONSTANT_TWO" \
  "missing-bin fixture:$MISSING_BIN" \
  "malformed-xml fixture:$MALFORMED_XML"
do
  label="${pair%%:*}"
  path="${pair#*:}"
  [[ -f "$path" && ! -L "$path" ]] || blocked "$label is unavailable: $path"
done

sha256sum "$BUILD_PROFILE" "$CONSTANT_ONE" "$CONSTANT_TWO" \
  "$MISSING_BIN" "$MALFORMED_XML" >"$WORK/preserved-before.sha256"

python3 -B - "$PROJECT_ROOT" "$PROFILE" "$CONSTANT_ONE" "$CONSTANT_TWO" \
  "$WORK/canonical.json" <<'PY'
import hashlib
import json
import pathlib
import sys

project, profile_path, one_path, two_path, output_path = sys.argv[1:]
sys.path.insert(0, str(pathlib.Path(project, "scripts")))
import model_bundle

profile = json.loads(pathlib.Path(profile_path).read_text(encoding="utf-8"))
assert profile["schema_version"] == "1"
assert profile["target_id"] == "openvino-ir"
assert profile["input_kind"] == {
    "kind": "fzb1",
    "extensions": ["fzb"],
    "subformats": ["model.bin", "model.xml"],
}
assert profile["depth"] == "read-validate-constants"
assert profile["engine_capabilities"] == [{
    "backend": "local-harness",
    "binary_role": "replay",
    "required_mode": "native",
    "instrumentation_scope": "openvino-core+ir-frontend",
}]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def identity(path):
    raw = pathlib.Path(path).read_bytes()
    entries = model_bundle.decode_bundle(raw)
    model_bundle.require_allowlist(entries, ["model.bin", "model.xml"])
    return {
        "bundle_sha256": sha(raw),
        "bundle_size_bytes": len(raw),
        "entries": {
            name: {"sha256": sha(data), "size_bytes": len(data)}
            for name, data in entries
        },
    }

one = identity(one_path)
two = identity(two_path)
assert one["entries"]["model.xml"] == two["entries"]["model.xml"]
assert one["entries"]["model.bin"] != two["entries"]["model.bin"]
pathlib.Path(output_path).write_text(
    json.dumps({"constant-one": one, "constant-two": two}, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
if [[ $? -eq 0 ]]; then
  ok "execution profile names the exact FZB1 pair and read-validate-constants depth"
else
  bad "execution profile or canonical pair identity is inconsistent"
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run ovi06-wrong-target \
  harness --target tflite --input "$CONSTANT_ONE" \
  >"$WORK/wrong-target.log" 2>&1
wrong_target_rc=$?
if [[ "$wrong_target_rc" -eq 2 ]] \
  && grep -Fq "target mismatch: requested 'tflite', profile names 'openvino-ir'" \
    "$WORK/wrong-target.log"; then
  ok "a different target cannot dispatch through the OpenVINO profile"
else
  bad "wrong-target profile dispatch was not rejected before execution"
  sed -n '1,16p' "$WORK/wrong-target.log" >&2
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run ovi06-harness \
  harness --target openvino-ir --input "$CONSTANT_ONE" \
  >"$WORK/harness.log" 2>&1
harness_rc=$?
if [[ "$harness_rc" -eq 0 ]] \
  && grep -Fq 'OPENVINO_LOAD_OK stage=read_validate_constants' "$WORK/harness.log" \
  && grep -Fq 'payload_hex=0000c03f' "$WORK/harness.log" \
  && grep -Fq 'library_outcome: session_ok' "$WORK/harness.log"; then
  ok "tool harness reaches the OVI-03 common loader with both pair components"
else
  bad "tool harness did not preserve the OVI-03 loader contract"
  sed -n '1,40p' "$WORK/harness.log" >&2
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run ovi06-missing-bin \
  harness --target openvino-ir --input "$MISSING_BIN" \
  >"$WORK/missing-bin.log" 2>&1
missing_bin_rc=$?
if [[ "$missing_bin_rc" -eq 9 ]] \
  && grep -Fq 'OPENVINO_LOAD_REJECT stage=bundle' "$WORK/missing-bin.log"; then
  ok "replay rejects an XML-only FZB1 instead of finding weights elsewhere"
else
  bad "replay accepted or misclassified an FZB1 without model.bin"
  sed -n '1,32p' "$WORK/missing-bin.log" >&2
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run ovi06-malformed-xml \
  harness --target openvino-ir --input "$MALFORMED_XML" \
  >"$WORK/malformed-xml.log" 2>&1
malformed_rc=$?
if [[ "$malformed_rc" -eq 9 ]] \
  && grep -Fq 'OPENVINO_LOAD_REJECT stage=frontend' "$WORK/malformed-xml.log"; then
  ok "the actual frontend loader failure remains a rejection"
else
  bad "the actual frontend loader failure was swallowed or misclassified"
  sed -n '1,32p' "$WORK/malformed-xml.log" >&2
  stop_after_failure
fi

NORMAL_CORPUS="$WORK/normal-corpus"
mkdir -p -- "$NORMAL_CORPUS"
cp -- "$CONSTANT_ONE" "$NORMAL_CORPUS/constant-one.fzb"
cp -- "$CONSTANT_TWO" "$NORMAL_CORPUS/ignored.tflite"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run ovi06-normal-run \
  run --target openvino-ir --backend local-harness --corpus-dir "$NORMAL_CORPUS" \
  --workers 1 --timeout-sec 30 --restart-limit 0 \
  >"$WORK/normal-run.log" 2>&1
normal_run_rc=$?
NORMAL_STATUS="$(sed -n 's/^status: //p' "$WORK/normal-run.log" | tail -n 1)"
if [[ "$normal_run_rc" -eq 0 && -f "$NORMAL_STATUS" ]] \
  && python3 -B - "$PROJECT_ROOT" "$NORMAL_STATUS" "$WORK/canonical.json" <<'PY'
import hashlib
import json
import pathlib
import sys

project, status_text, canonical_text = sys.argv[1:]
sys.path.insert(0, str(pathlib.Path(project, "scripts")))
import model_bundle

status_path = pathlib.Path(status_text)
status = json.loads(status_path.read_text(encoding="utf-8"))
manifest = json.loads((status_path.parent / "input-manifest.json").read_text(encoding="utf-8"))
execution = json.loads((status_path.parent / "execution.json").read_text(encoding="utf-8"))
expected = json.loads(pathlib.Path(canonical_text).read_text(encoding="utf-8"))["constant-one"]
assert status["target"] == "openvino-ir"
assert status["backend"] == "local-harness"
assert (status["total"], status["success"], status["rejected"], status["failed"]) == (1, 1, 0, 0)
assert execution["target_id"] == "openvino-ir"
assert execution["validation_run"] == "ovi06-normal-run"
assert [entry["path"] for entry in manifest["files"]] == ["inputs/constant-one.fzb"]
raw = (status_path.parent / manifest["files"][0]["path"]).read_bytes()
assert hashlib.sha256(raw).hexdigest() == expected["bundle_sha256"]
entries = model_bundle.decode_bundle(raw)
model_bundle.require_allowlist(entries, ["model.bin", "model.xml"])
observed = {
    name: {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    for name, data in entries
}
assert observed == expected["entries"]
PY
then
  ok "run selects only .fzb and preserves the original plus both components"
else
  bad "run dispatch or FZB1 preservation is inconsistent"
  sed -n '1,48p' "$WORK/normal-run.log" >&2
  stop_after_failure
fi

REJECT_CORPUS="$WORK/reject-corpus"
mkdir -p -- "$REJECT_CORPUS"
cp -- "$MALFORMED_XML" "$REJECT_CORPUS/malformed-xml.fzb"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run ovi06-reject-run \
  run --target openvino-ir --backend local-harness --corpus-dir "$REJECT_CORPUS" \
  --workers 1 --timeout-sec 30 --restart-limit 0 \
  >"$WORK/reject-run.log" 2>&1
reject_run_rc=$?
REJECT_STATUS="$(sed -n 's/^status: //p' "$WORK/reject-run.log" | tail -n 1)"
if [[ "$reject_run_rc" -eq 0 && -f "$REJECT_STATUS" ]] \
  && python3 -B - "$REJECT_STATUS" <<'PY'
import json
import pathlib
import sys

status_path = pathlib.Path(sys.argv[1])
status = json.loads(status_path.read_text(encoding="utf-8"))
assert (status["total"], status["success"], status["rejected"], status["failed"]) == (1, 0, 1, 0)
logs = "\n".join(path.read_text(encoding="utf-8") for path in (status_path.parent / "logs").glob("*.log"))
assert "OPENVINO_LOAD_REJECT stage=frontend" in logs
PY
then
  ok "run does not swallow an actual loader rejection as success"
else
  bad "run swallowed or lost the actual frontend rejection"
  sed -n '1,48p' "$WORK/reject-run.log" >&2
  stop_after_failure
fi

FAULT_DIR="$WORK/fault"
FAULT_REPLAY="$FAULT_DIR/replay"
FAULT_PROFILE="$FAULT_DIR/profile.json"
FAULT_OBSERVED="$FAULT_DIR/observed-sha256.txt"
FAULT_TRANSCRIPT="$FAULT_DIR/replay-transcript.txt"
mkdir -p -- "$FAULT_DIR"
python3 -B - "$PROFILE" "$FAULT_REPLAY" "$FAULT_OBSERVED" "$FAULT_TRANSCRIPT" <<'PY'
import json
import pathlib
import shlex
import sys

profile_path, replay_path, observed_path, transcript_path = map(pathlib.Path, sys.argv[1:])
profile = json.loads(profile_path.read_text(encoding="utf-8"))
source = next(binary for binary in profile["binaries"] if binary["role"] == "replay")
real_replay = pathlib.Path(source["path"])
script = f"""#!/usr/bin/env bash
set -u
input="${{1:?input required}}"
{shlex.quote(str(real_replay))} "$input" >>{shlex.quote(str(transcript_path))} 2>&1
status=$?
if (( status != 0 )); then
  exit "$status"
fi
sha256sum "$input" | cut -d' ' -f1 >>{shlex.quote(str(observed_path))}
printf 'ERROR: AddressSanitizer: SEGV after OVI-03 LoadBundle\\n' >&2
kill -SEGV $$
"""
replay_path.write_text(script, encoding="utf-8")
replay_path.chmod(0o755)
PY
python3 -B - "$PROFILE" "$FAULT_PROFILE" "$FAULT_REPLAY" <<'PY'
import hashlib
import json
import os
import sys

source_path, destination, wrapper = sys.argv[1:]
document = json.load(open(source_path, encoding="utf-8"))
digest = hashlib.sha256(open(wrapper, "rb").read()).hexdigest()
for binary in document["binaries"]:
    if binary["role"] == "replay":
        original = binary["path"]
        original_sha = binary["sha256"]
        binary["path"] = os.path.abspath(wrapper)
        binary["sha256"] = digest
        binary["linked_libraries"].append({"path": original, "sha256": original_sha})
document["toolchain"]["engine"] = {
    "version": "ovi06-fault-after-common-loader-v1",
    "path": os.path.abspath(wrapper),
    "sha256": digest,
}
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

FAULT_CORPUS="$FAULT_DIR/corpus"
mkdir -p -- "$FAULT_CORPUS"
cp -- "$CONSTANT_ONE" "$FAULT_CORPUS/fault.fzb"
: >"$FAULT_OBSERVED"
: >"$FAULT_TRANSCRIPT"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$FAULT_PROFILE" --validation-run ovi06-fault-run \
  run --target openvino-ir --backend local-harness --corpus-dir "$FAULT_CORPUS" \
  --workers 1 --timeout-sec 30 --restart-limit 0 \
  >"$WORK/fault-run.log" 2>&1
fault_run_rc=$?
FAULT_STATUS="$(sed -n 's/^status: //p' "$WORK/fault-run.log" | tail -n 1)"
FAULT_RUN_DIR="$(dirname -- "$FAULT_STATUS")"
FAULT_INPUT="$(find "$FAULT_RUN_DIR/crash-inputs" -maxdepth 1 -type f -name '*.fzb' -print 2>/dev/null | head -n 1)"
EXPECTED_SHA="$(python3 -B - "$WORK/canonical.json" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))["constant-one"]["bundle_sha256"])
PY
)"
if [[ "$fault_run_rc" -eq 0 && -f "$FAULT_STATUS" && -f "$FAULT_INPUT" ]] \
  && grep -Fq 'OPENVINO_ACCESS_OK nodes=4 constants=1 constant_bytes=4' "$FAULT_TRANSCRIPT" \
  && python3 -B - "$FAULT_STATUS" "$FAULT_INPUT" "$EXPECTED_SHA" <<'PY'
import hashlib
import json
import pathlib
import sys

status_path = pathlib.Path(sys.argv[1])
fault_input = pathlib.Path(sys.argv[2])
expected = sys.argv[3]
status = json.loads(status_path.read_text(encoding="utf-8"))
assert (status["total"], status["success"], status["failed"], status["rejected"]) == (1, 0, 1, 0)
assert hashlib.sha256(fault_input.read_bytes()).hexdigest() == expected
assert hashlib.sha256((status_path.parent / "inputs" / "fault.fzb").read_bytes()).hexdigest() == expected
PY
then
  ok "a post-loader fault preserves the exact canonical FZB1 input"
else
  bad "fault propagation bypassed the common loader or lost the FZB1 input"
  sed -n '1,48p' "$WORK/fault-run.log" >&2
  stop_after_failure
fi

: >"$FAULT_OBSERVED"
: >"$FAULT_TRANSCRIPT"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$FAULT_PROFILE" --validation-run ovi06-triage \
  triage --target openvino-ir --input "$FAULT_INPUT" --repro-retries 3 --timeout-sec 30 \
  >"$WORK/triage.log" 2>&1
triage_rc=$?
TRIAGE_SUMMARY="$(sed -n 's/^summary: //p' "$WORK/triage.log" | tail -n 1)"
TRIAGE_ID="$(basename -- "$(dirname -- "$TRIAGE_SUMMARY")")"
if [[ "$triage_rc" -eq 0 && -f "$TRIAGE_SUMMARY" ]] \
  && [[ "$(grep -Fc 'OPENVINO_ACCESS_OK nodes=4 constants=1 constant_bytes=4' "$FAULT_TRANSCRIPT")" -eq 4 ]] \
  && python3 -B - "$TRIAGE_SUMMARY" "$FAULT_OBSERVED" "$EXPECTED_SHA" <<'PY'
import hashlib
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
observed = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
expected = sys.argv[3]
summary = json.loads(summary_path.read_text(encoding="utf-8"))
manifest = json.loads((summary_path.parent / "input-manifest.json").read_text(encoding="utf-8"))
assert summary["target"] == "openvino-ir"
assert summary["verdict"] == "reproduced"
assert summary["crashed_count"] == 3
assert summary["signature_consistent"] is True
assert all(attempt["signal"] == "SIGSEGV" for attempt in summary["attempts"])
assert len(observed) == 4 and set(observed) == {expected}, observed
assert len(manifest["files"]) == 1
assert manifest["files"][0]["sha256"] == expected
assert hashlib.sha256(pathlib.Path(summary["input"]).read_bytes()).hexdigest() == expected
PY
then
  ok "generic triage repeats the same common-loader FZB1 before every fault"
else
  bad "generic triage changed the pair, target, or failure verdict"
  sed -n '1,64p' "$WORK/triage.log" >&2
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" show "$TRIAGE_ID" \
  >"$WORK/show-triage.json" 2>"$WORK/show-triage.err"
show_rc=$?
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" report \
  >"$WORK/report.log" 2>&1
report_rc=$?
REPORT_DIR="$(sed -n 's/^report_dir: //p' "$WORK/report.log" | tail -n 1)"
REPORT_ID="$(basename -- "$REPORT_DIR")"
if [[ "$show_rc" -eq 0 && "$report_rc" -eq 0 && -f "$REPORT_DIR/meta.json" ]] \
  && python3 -B - "$WORK/show-triage.json" "$REPORT_DIR/meta.json" "$EXPECTED_SHA" <<'PY'
import json
import sys

shown = json.load(open(sys.argv[1], encoding="utf-8"))
meta = json.load(open(sys.argv[2], encoding="utf-8"))
expected = sys.argv[3]
assert shown["kind"] == "triage"
assert shown["target_id"] == "openvino-ir"
assert shown["profiled"] is True
assert shown["primary"]["verdict"] == "reproduced"
assert meta["target"] == "openvino-ir"
assert meta["input_sha256"] == expected
assert meta["poc_collected"] is True
assert meta["poc_sha256"] == expected
PY
then
  ok "strict show and frozen generic report retain target and whole-bundle identity"
else
  bad "strict result validation or generic report identity propagation failed"
  sed -n '1,48p' "$WORK/report.log" >&2
  sed -n '1,24p' "$WORK/show-triage.err" >&2
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  export "$(basename -- "$FAULT_RUN_DIR")" >"$WORK/export-run.log" 2>&1
export_run_rc=$?
RUN_EXPORT="$(sed -n 's/^path: //p' "$WORK/export-run.log" | tail -n 1)"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  export "$TRIAGE_ID" >"$WORK/export-triage.log" 2>&1
export_triage_rc=$?
TRIAGE_EXPORT="$(sed -n 's/^path: //p' "$WORK/export-triage.log" | tail -n 1)"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  export "$REPORT_ID" >"$WORK/export-report.log" 2>&1
export_report_rc=$?
REPORT_EXPORT="$(sed -n 's/^path: //p' "$WORK/export-report.log" | tail -n 1)"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  dashboard --format html --out "$WORK/dashboard.html" >"$WORK/dashboard.log" 2>&1
dashboard_rc=$?
if [[ "$export_run_rc" -eq 0 && "$export_triage_rc" -eq 0 \
      && "$export_report_rc" -eq 0 && "$dashboard_rc" -eq 0 ]] \
  && grep -Fq "/report/$REPORT_ID" "$WORK/dashboard.html" \
  && grep -Fq "$EXPECTED_SHA" "$REPORT_DIR/report.md" \
  && python3 -B - "$PROJECT_ROOT" "$WORK/canonical.json" \
    "$RUN_EXPORT" "$TRIAGE_EXPORT" "$REPORT_EXPORT" <<'PY'
import hashlib
import json
import pathlib
import sys

project, canonical_text, *roots = sys.argv[1:]
sys.path.insert(0, str(pathlib.Path(project, "scripts")))
import model_bundle

expected = json.loads(pathlib.Path(canonical_text).read_text(encoding="utf-8"))["constant-one"]

def inspect(root_text):
    root = pathlib.Path(root_text)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    candidates = [entry["path"] for entry in manifest["files"] if entry["path"].endswith(".fzb")]
    assert candidates, sorted(entry["path"] for entry in manifest["files"])
    for relative in candidates:
        raw = (root / relative).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected["bundle_sha256"]
        entries = model_bundle.decode_bundle(raw)
        model_bundle.require_allowlist(entries, ["model.bin", "model.xml"])
        observed = {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
            for name, data in entries
        }
        assert observed == expected["entries"]

for root in roots:
    inspect(root)
PY
then
  ok "run/triage/report exports and UI keep the original and both component bytes"
else
  bad "strict export or UI evidence lost an FZB1 component or identity"
  sed -n '1,28p' "$WORK/export-run.log" >&2
  sed -n '1,28p' "$WORK/export-triage.log" >&2
  sed -n '1,28p' "$WORK/export-report.log" >&2
  stop_after_failure
fi

# Rebind every outer hash after replacing the preserved run input with the
# canonical XML-only negative fixture. Strict export must still decode the FZB1
# and reject missing weights, rather than trusting a self-consistent envelope.
XML_ONLY_RUN="$DATA_DIR/runs/run-ovi06-xml-only"
cp -a -- "$FAULT_RUN_DIR" "$XML_ONLY_RUN"
cp -- "$MISSING_BIN" "$XML_ONLY_RUN/inputs/fault.fzb"
python3 -B - "$XML_ONLY_RUN" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
input_path = root / "inputs/fault.fzb"
raw = input_path.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
manifest_path = root / "input-manifest.json"
manifest = {
    "schema_version": "1",
    "files": [{
        "path": "inputs/fault.fzb",
        "size_bytes": len(raw),
        "sha256": digest,
    }],
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
execution_path = root / "execution.json"
execution = json.loads(execution_path.read_text(encoding="utf-8"))
execution["profile_path"] = str(root / "profile.json")
execution["input_manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
row = f"fault.fzb\0{len(raw)}\0{digest}\n".encode()
execution["corpus_snapshot_sha256"] = hashlib.sha256(row).hexdigest()
execution_path.write_text(json.dumps(execution) + "\n", encoding="utf-8")
status_path = root / "status.json"
status = json.loads(status_path.read_text(encoding="utf-8"))
status["run_id"] = "ovi06-xml-only"
status_path.write_text(json.dumps(status) + "\n", encoding="utf-8")
PY
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  export run-ovi06-xml-only >"$WORK/export-xml-only.log" 2>&1
xml_only_rc=$?
if [[ "$xml_only_rc" -ne 0 ]] \
  && grep -Fq 'FZB1 entries do not match target allowlist' "$WORK/export-xml-only.log"; then
  ok "strict OpenVINO export rejects XML-only evidence after every outer hash is rebound"
else
  bad "strict OpenVINO export accepted XML-only evidence"
  sed -n '1,32p' "$WORK/export-xml-only.log" >&2
  stop_after_failure
fi

sha256sum "$BUILD_PROFILE" "$CONSTANT_ONE" "$CONSTANT_TWO" \
  "$MISSING_BIN" "$MALFORMED_XML" >"$WORK/preserved-after.sha256"
if cmp -s "$WORK/preserved-before.sha256" "$WORK/preserved-after.sha256"; then
  ok "pre-existing OpenVINO profile and OVI-04/05 fixtures stayed byte-identical"
else
  bad "the integration run changed preserved OpenVINO evidence"
  stop_after_failure
fi

summary
[[ "$FAIL" -eq 0 ]]
