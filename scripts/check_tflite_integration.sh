#!/usr/bin/env bash
# TFL-06: prove target dispatch, corpus selection, fault preservation,
# same-input reproduction, and UI/export input-hash agreement end to end.
set -u

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
TARGET_ROOT="${TFLITE_TARGET_ROOT:-$PROJECT_ROOT/data/targets/tflite/v2.20.0}"
PROFILE="${TFLITE_PROFILE:-$TARGET_ROOT/profile.json}"
ADD_MODEL="${TFLITE_ADD_MODEL:-$TARGET_ROOT/fixtures/add.tflite}"

PASS=0
FAIL=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tool-tflite-integration.XXXXXX")" || exit 2
DATA_DIR="$WORK/data"
SEEDS_DIR="$WORK/seeds"
CORPUS_DIR="$WORK/corpus"
FAULT_DIR="$WORK/fault"

ok() {
  PASS=$((PASS + 1))
  printf '[tflite-integration] ok: %s\n' "$1"
}

bad() {
  FAIL=$((FAIL + 1))
  printf '[tflite-integration] fail: %s\n' "$1" >&2
}

finish() {
  rm -rf -- "$WORK"
}
trap finish EXIT

stop_after_failure() {
  printf '[tflite-integration] pass=%d fail=%d\n' "$PASS" "$FAIL"
  exit 1
}

if [[ ! -x "$TOOL_BIN" ]]; then
  printf '[tflite-integration] fail: tool binary not executable: %s\n' "$TOOL_BIN" >&2
  printf '[tflite-integration] build it with `cargo build` or point TOOL_BIN at one; this gate cannot run\n' >&2
  exit 1
fi

for pair in \
  "target profile:$PROFILE" \
  "ADD model:$ADD_MODEL"
do
  label="${pair%%:*}"
  path="${pair#*:}"
  [[ -f "$path" ]] || { bad "$label is unavailable: $path"; stop_after_failure; }
done
for command_name in python3 sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 \
    || { bad "required command is unavailable: $command_name"; stop_after_failure; }
done

mkdir -p -- "$DATA_DIR" "$SEEDS_DIR" "$CORPUS_DIR" "$FAULT_DIR"
cp -- "$ADD_MODEL" "$CORPUS_DIR/add.tflite"
cp -- "$ADD_MODEL" "$CORPUS_DIR/ignored.onnx"
EXPECTED_SHA="$(sha256sum "$ADD_MODEL" | cut -d' ' -f1)"

"$TOOL_BIN" target-spec --target tflite --format json >"$WORK/target-spec.json" 2>&1
target_spec_rc=$?
if [[ "$target_spec_rc" -eq 0 ]] \
  && python3 -B - "$WORK/target-spec.json" <<'PY'
import json
import sys

spec = json.load(open(sys.argv[1], encoding="utf-8"))
assert spec["target_id"] == "tflite"
assert spec["seed_subdir"] == "tflite"
assert spec["input_ext"] == "tflite"
assert spec["external_harness_env"] == "TOOL_TFLITE_HARNESS_CMD"
assert spec["campaign_supported"] is False
assert spec["ui_supported"] is False
PY
then
  ok "registry dispatches TFLite without promoting unqualified campaign engines"
else
  bad "TFLite registry dispatch or capability boundary is inconsistent"
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run tfl06-normal \
  run --target tflite --backend local-harness --corpus-dir "$CORPUS_DIR" \
  --workers 1 --timeout-sec 5 --restart-limit 0 \
  >"$WORK/normal-run.log" 2>&1
normal_rc=$?
NORMAL_STATUS="$(sed -n 's/^status: //p' "$WORK/normal-run.log" | tail -n 1)"
if [[ "$normal_rc" -eq 0 && -f "$NORMAL_STATUS" ]] \
  && python3 -B - "$NORMAL_STATUS" "$EXPECTED_SHA" <<'PY'
import json
import pathlib
import sys

status_path = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
status = json.load(open(status_path, encoding="utf-8"))
manifest = json.load(open(status_path.parent / "input-manifest.json", encoding="utf-8"))
execution = json.load(open(status_path.parent / "execution.json", encoding="utf-8"))
assert status["target"] == "tflite"
assert status["backend"] == "local-harness"
assert (status["total"], status["success"], status["failed"]) == (1, 1, 0)
assert len(manifest["files"]) == 1
assert manifest["files"][0]["path"] == "inputs/add.tflite"
assert manifest["files"][0]["sha256"] == expected
assert execution["target_id"] == "tflite"
assert execution["backend"] == "local-harness"
assert execution["validation_run"] == "tfl06-normal"
PY
then
  ok "TFLite dispatch selects only the .tflite corpus and records its identity"
else
  bad "TFLite target dispatch or corpus selection is inconsistent"
  tail -n 32 "$WORK/normal-run.log" >&2
  stop_after_failure
fi

FAULT_REPLAY="$FAULT_DIR/fault-replay"
FAULT_OBSERVED="$FAULT_DIR/observed-sha256.txt"
FAULT_PROFILE="$FAULT_DIR/profile.json"
cat >"$FAULT_REPLAY" <<EOF
#!/usr/bin/env bash
set -u
sha256sum "\$1" | cut -d' ' -f1 >>"$FAULT_OBSERVED"
printf 'ERROR: AddressSanitizer: SEGV in tflite::Interpreter::AllocateTensors\n' >&2
kill -SEGV \$\$
EOF
chmod 0755 "$FAULT_REPLAY"
python3 -B - "$PROFILE" "$FAULT_PROFILE" "$FAULT_REPLAY" <<'PY'
import hashlib
import json
import os
import sys

source, destination, replay = sys.argv[1:]
document = json.load(open(source, encoding="utf-8"))
digest = hashlib.sha256(open(replay, "rb").read()).hexdigest()
for binary in document["binaries"]:
    if binary["role"] == "replay":
        binary["path"] = os.path.abspath(replay)
        binary["sha256"] = digest
        binary["linked_libraries"] = []
document["toolchain"]["engine"] = {
    "version": "tfl06-fault-replay-v1",
    "path": os.path.abspath(replay),
    "sha256": digest,
}
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

FAULT_CORPUS="$FAULT_DIR/corpus"
mkdir -p -- "$FAULT_CORPUS"
cp -- "$ADD_MODEL" "$FAULT_CORPUS/fault.tflite"
: >"$FAULT_OBSERVED"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$FAULT_PROFILE" --validation-run tfl06-fault-run \
  run --target tflite --backend local-harness --corpus-dir "$FAULT_CORPUS" \
  --workers 1 --timeout-sec 5 --restart-limit 0 \
  >"$WORK/fault-run.log" 2>&1
fault_run_rc=$?
FAULT_STATUS="$(sed -n 's/^status: //p' "$WORK/fault-run.log" | tail -n 1)"
FAULT_RUN_DIR="$(dirname -- "$FAULT_STATUS")"
FAULT_INPUT="$(find "$FAULT_RUN_DIR/crash-inputs" -maxdepth 1 -type f -name '*.tflite' -print 2>/dev/null | head -n 1)"
if [[ "$fault_run_rc" -eq 0 && -f "$FAULT_STATUS" && -f "$FAULT_INPUT" ]] \
  && python3 -B - "$FAULT_STATUS" "$FAULT_INPUT" "$EXPECTED_SHA" <<'PY'
import hashlib
import json
import pathlib
import sys

status_path = pathlib.Path(sys.argv[1])
fault_input = pathlib.Path(sys.argv[2])
expected = sys.argv[3]
status = json.load(open(status_path, encoding="utf-8"))
assert (status["total"], status["failed"], status["success"]) == (1, 1, 0)
assert hashlib.sha256(fault_input.read_bytes()).hexdigest() == expected
assert hashlib.sha256((status_path.parent / "inputs" / "fault.tflite").read_bytes()).hexdigest() == expected
PY
then
  ok "a TFLite replay fault preserves the exact run input"
else
  bad "TFLite fault evidence was lost or changed"
  tail -n 40 "$WORK/fault-run.log" >&2
  stop_after_failure
fi

: >"$FAULT_OBSERVED"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$FAULT_PROFILE" --validation-run tfl06-triage \
  triage --target tflite --input "$FAULT_INPUT" --repro-retries 3 --timeout-sec 5 \
  >"$WORK/triage.log" 2>&1
triage_rc=$?
TRIAGE_SUMMARY="$(sed -n 's/^summary: //p' "$WORK/triage.log" | tail -n 1)"
TRIAGE_ID="$(basename -- "$(dirname -- "$TRIAGE_SUMMARY")")"
if [[ "$triage_rc" -eq 0 && -f "$TRIAGE_SUMMARY" ]] \
  && python3 -B - "$TRIAGE_SUMMARY" "$FAULT_OBSERVED" "$EXPECTED_SHA" <<'PY'
import hashlib
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
observed_path = pathlib.Path(sys.argv[2])
expected = sys.argv[3]
summary = json.load(open(summary_path, encoding="utf-8"))
manifest = json.load(open(summary_path.parent / "input-manifest.json", encoding="utf-8"))
observed = observed_path.read_text(encoding="utf-8").splitlines()
assert summary["target"] == "tflite"
assert summary["verdict"] == "reproduced"
assert summary["crashed_count"] == 3
assert summary["signature_consistent"] is True
assert all(attempt["signal"] == "SIGSEGV" for attempt in summary["attempts"])
assert len(observed) == 4, observed
assert set(observed) == {expected}
assert len(manifest["files"]) == 1
assert manifest["files"][0]["sha256"] == expected
assert hashlib.sha256(pathlib.Path(summary["input"]).read_bytes()).hexdigest() == expected
PY
then
  ok "three fresh TFLite replays reproduce the identical preserved input"
else
  bad "TFLite same-input reproduction is inconsistent"
  tail -n 48 "$WORK/triage.log" >&2
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
assert shown["target_id"] == "tflite"
assert shown["profiled"] is True
assert shown["primary"]["verdict"] == "reproduced"
assert meta["target"] == "tflite"
assert meta["input_sha256"] == expected
assert meta["poc_collected"] is True
assert meta["poc_sha256"] == expected
PY
then
  ok "strict show and report retain the TFLite target and input hash"
else
  bad "strict result validation or report hash propagation failed"
  tail -n 40 "$WORK/report.log" >&2
  cat "$WORK/show-triage.err" >&2
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" export "$(basename -- "$FAULT_RUN_DIR")" \
  >"$WORK/export-run.log" 2>&1
export_run_rc=$?
RUN_EXPORT="$(sed -n 's/^path: //p' "$WORK/export-run.log" | tail -n 1)"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" export "$TRIAGE_ID" \
  >"$WORK/export-triage.log" 2>&1
export_triage_rc=$?
TRIAGE_EXPORT="$(sed -n 's/^path: //p' "$WORK/export-triage.log" | tail -n 1)"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  dashboard --format html --out "$WORK/dashboard.html" \
  >"$WORK/dashboard.log" 2>&1
dashboard_rc=$?

if [[ "$export_run_rc" -eq 0 && "$export_triage_rc" -eq 0 \
      && "$dashboard_rc" -eq 0 ]] \
  && grep -Fq "/report/$REPORT_ID" "$WORK/dashboard.html" \
  && grep -Fq "$EXPECTED_SHA" "$REPORT_DIR/report.md" \
  && python3 -B - "$FAULT_RUN_DIR/input-manifest.json" \
    "$RUN_EXPORT/manifest.json" "$TRIAGE_EXPORT/manifest.json" "$EXPECTED_SHA" <<'PY'
import json
import sys

ui_manifest = json.load(open(sys.argv[1], encoding="utf-8"))
run_export = json.load(open(sys.argv[2], encoding="utf-8"))
triage_export = json.load(open(sys.argv[3], encoding="utf-8"))
expected = sys.argv[4]
assert len(ui_manifest["files"]) == 1
assert ui_manifest["files"][0]["path"] == "inputs/fault.tflite"
assert ui_manifest["files"][0]["sha256"] == expected

def hashes(manifest):
    return {entry["path"]: entry["sha256"] for entry in manifest["files"]}

run_hashes = hashes(run_export)
triage_hashes = hashes(triage_export)
assert run_hashes["result/inputs/fault.tflite"] == expected
assert any(path.startswith("result/crash-inputs/") and value == expected
           for path, value in run_hashes.items())
assert any(path.startswith("result/input/") and value == expected
           for path, value in triage_hashes.items())
PY
then
  ok "UI and strict exports agree on the preserved TFLite input hash"
else
  bad "UI/export preserved-input hashes do not agree"
  tail -n 24 "$WORK/export-run.log" >&2
fi

printf '[tflite-integration] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
