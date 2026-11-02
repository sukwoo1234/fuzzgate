#!/usr/bin/env bash
# HDF-06: prove HDF5-only registry/profile dispatch before runtime evidence.
set -u
ulimit -c 0 || true

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
TARGET_ROOT="${HDF5_TARGET_ROOT:-$PROJECT_ROOT/data/targets/hdf5-weights/2.2.0}"
BUILD_PROFILE="$TARGET_ROOT/build-profile.json"
PROFILE="${HDF5_PROFILE:-$TARGET_ROOT/profile.json}"
FIXTURES="${HDF5_EXECUTION_FIXTURES:-$TARGET_ROOT/execution-fixtures}"

PASS=0
FAIL=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tool-hdf5-integration.XXXXXX")" || exit 2
trap 'rm -rf -- "$WORK"' EXIT

ok() { PASS=$((PASS + 1)); printf '[hdf5-integration] ok: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '[hdf5-integration] fail: %s\n' "$1" >&2; }
summary() { printf '[hdf5-integration] pass=%d fail=%d blocked=0\n' "$PASS" "$FAIL"; }
stop_after_failure() { summary; exit 1; }
blocked() {
  printf '[hdf5-integration] blocked: %s\n' "$1" >&2
  printf '[hdf5-integration] this gate cannot run\n' >&2
  printf '[hdf5-integration] pass=%d fail=%d blocked=1\n' "$PASS" "$FAIL"
  exit 2
}

[[ -x "$TOOL_BIN" ]] || blocked "tool binary is not executable: $TOOL_BIN"
for command_name in python3 sha256sum grep find cp cmp cut kill; do
  command -v "$command_name" >/dev/null 2>&1 \
    || blocked "required command is unavailable: $command_name"
done

# Production dispatch is checked before ignored target artifacts. Its absence is
# the intentional first HDF-06 RED, not an environment skip.
"$TOOL_BIN" target-spec --target hdf5-weights --format json \
  >"$WORK/target-spec.json" 2>"$WORK/target-spec.err"
target_spec_rc=$?
if [[ "$target_spec_rc" -ne 0 ]]; then
  bad "hdf5-weights is absent from the production target registry"
  sed -n '1,16p' "$WORK/target-spec.err" >&2
  stop_after_failure
fi

for pair in \
  "build profile:$BUILD_PROFILE" \
  "execution profile:$PROFILE" \
  "fixture manifest:$FIXTURES/manifest.json" \
  "normal fixture:$FIXTURES/tensor-chunked.h5" \
  "unsupported filter fixture:$FIXTURES/unsupported-filter.h5" \
  "unsupported dtype fixture:$FIXTURES/unsupported-dtype.h5" \
  "external link fixture:$FIXTURES/external-link.h5"
do
  label="${pair%%:*}"
  path="${pair#*:}"
  [[ -f "$path" && ! -L "$path" ]] || blocked "$label is unavailable: $path"
done

python3 -B "$PROJECT_ROOT/scripts/check_hdf5_scope.py" \
  --target-spec "$WORK/target-spec.json" \
  --build-profile "$BUILD_PROFILE" \
  --execution-profile "$PROFILE"
if [[ $? -eq 0 ]]; then
  ok "registry and profiles preserve the HDF5-only unqualified boundary"
else
  bad "HDF5 was promoted to Keras or an unsupported capability"
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
if any("hdf5-weights" not in line for line in lines):
    raise SystemExit("a target help declaration omits hdf5-weights")
if any("keras" in line.lower() for line in lines):
    raise SystemExit("a target help declaration aliases HDF5 to Keras")
PY
then
  ok "CLI help names hdf5-weights without a Keras alias"
else
  bad "CLI target help widens or omits the HDF5-only target"
  stop_after_failure
fi

DATA_DIR="$WORK/data"
SEEDS_DIR="$WORK/seeds"
mkdir -p -- "$DATA_DIR" "$SEEDS_DIR"

PRESERVED=(
  "$BUILD_PROFILE"
  "$TARGET_ROOT/instrumentation-fixtures/shuffle-fletcher32.h5"
  "$TARGET_ROOT/guided-instrumentation.json"
  "$TARGET_ROOT/coverage-instrumentation.json"
  "$TARGET_ROOT/instrumentation-evidence/coverage/coverage.json"
)
for path in "${PRESERVED[@]}"; do
  [[ -f "$path" && ! -L "$path" ]] || blocked "preserved HDF-01/05 evidence is unavailable: $path"
done
sha256sum "${PRESERVED[@]}" >"$WORK/preserved-before.sha256"

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  harness --target hdf5-weights --input "$FIXTURES/tensor-chunked.h5" \
  >"$WORK/unprofiled.log" 2>&1
unprofiled_rc=$?
if [[ "$unprofiled_rc" -eq 10 ]] \
  && grep -Fq 'hdf5-weights requires a pinned target profile' "$WORK/unprofiled.log"; then
  ok "unprofiled HDF5 cannot masquerade as supported execution"
else
  bad "unprofiled HDF5 execution did not fail closed"
  sed -n '1,24p' "$WORK/unprofiled.log" >&2
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run hdf06-wrong-target \
  harness --target tflite --input "$FIXTURES/tensor-chunked.h5" \
  >"$WORK/wrong-target.log" 2>&1
wrong_target_rc=$?
if [[ "$wrong_target_rc" -eq 2 ]] \
  && grep -Fq "target mismatch: requested 'tflite', profile names 'hdf5-weights'" \
    "$WORK/wrong-target.log"; then
  ok "the HDF5 profile cannot dispatch as another format"
else
  bad "wrong-target HDF5 profile dispatch was accepted"
  sed -n '1,24p' "$WORK/wrong-target.log" >&2
  stop_after_failure
fi

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run hdf06-harness \
  harness --target hdf5-weights --input "$FIXTURES/tensor-chunked.h5" \
  >"$WORK/harness.log" 2>&1
harness_rc=$?
if [[ "$harness_rc" -eq 0 ]] \
  && grep -Fq 'HDF5_RESULT classification=accepted stage=complete reason=loaded' "$WORK/harness.log" \
  && grep -Fq 'HDF5_ACCESS_OK datasets=1 attributes=0 h5dread_calls=1' "$WORK/harness.log" \
  && grep -Fq 'target: hdf5-weights' "$WORK/harness.log"; then
  ok "tool harness reaches the HDF-03 numeric dataset reader"
else
  bad "profiled HDF5 harness did not preserve the common-loader contract"
  sed -n '1,48p' "$WORK/harness.log" >&2
  stop_after_failure
fi

for negative in \
  'unsupported-filter.h5:stage=filter_policy reason=filter_unavailable_for_decode' \
  'unsupported-dtype.h5:stage=dtype_policy reason=non_numeric_dtype' \
  'external-link.h5:stage=link_policy reason=external_link'
do
  fixture="${negative%%:*}"
  marker="${negative#*:}"
  "$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
    --target-profile "$PROFILE" --validation-run "hdf06-negative-${fixture%.h5}" \
    harness --target hdf5-weights --input "$FIXTURES/$fixture" \
    >"$WORK/$fixture.log" 2>&1
  negative_rc=$?
  if [[ "$negative_rc" -eq 9 ]] \
    && grep -Fq 'classification=unsupported_feature' "$WORK/$fixture.log" \
    && grep -Fq "$marker" "$WORK/$fixture.log"; then
    ok "$fixture remains unsupported instead of becoming a support claim"
  else
    bad "$fixture was accepted or lost its unsupported boundary"
    sed -n '1,36p' "$WORK/$fixture.log" >&2
    stop_after_failure
  fi
done

NORMAL_CORPUS="$WORK/normal-corpus"
mkdir -p -- "$NORMAL_CORPUS"
cp -- "$FIXTURES/tensor-chunked.h5" "$NORMAL_CORPUS/tensor-chunked.h5"
cp -- "$FIXTURES/tensor-chunked.h5" "$NORMAL_CORPUS/ignored.keras"
cp -- "$FIXTURES/tensor-chunked.h5" "$NORMAL_CORPUS/ignored.hdf5"
EXPECTED_SHA="$(sha256sum "$FIXTURES/tensor-chunked.h5" | cut -d' ' -f1)"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run hdf06-normal-run \
  run --target hdf5-weights --backend local-harness --corpus-dir "$NORMAL_CORPUS" \
  --workers 1 --timeout-sec 30 --restart-limit 0 \
  >"$WORK/normal-run.log" 2>&1
normal_run_rc=$?
NORMAL_STATUS="$(sed -n 's/^status: //p' "$WORK/normal-run.log" | tail -n 1)"
if [[ "$normal_run_rc" -eq 0 && -f "$NORMAL_STATUS" ]] \
  && python3 -B - "$NORMAL_STATUS" "$EXPECTED_SHA" <<'PY'
import json
import pathlib
import sys

status_path = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
status = json.loads(status_path.read_text(encoding="utf-8"))
manifest = json.loads((status_path.parent / "input-manifest.json").read_text(encoding="utf-8"))
execution = json.loads((status_path.parent / "execution.json").read_text(encoding="utf-8"))
assert status["target"] == "hdf5-weights"
assert status["backend"] == "local-harness"
assert (status["total"], status["success"], status["rejected"], status["failed"]) == (1, 1, 0, 0)
assert execution["target_id"] == "hdf5-weights"
assert execution["validation_run"] == "hdf06-normal-run"
assert [entry["path"] for entry in manifest["files"]] == ["inputs/tensor-chunked.h5"]
assert manifest["files"][0]["sha256"] == expected
PY
then
  ok "run selects only .h5 and does not absorb .keras or unregistered extensions"
else
  bad "HDF5 corpus selection or preserved identity is inconsistent"
  sed -n '1,48p' "$WORK/normal-run.log" >&2
  stop_after_failure
fi

REJECT_CORPUS="$WORK/reject-corpus"
mkdir -p -- "$REJECT_CORPUS"
cp -- "$FIXTURES/unsupported-filter.h5" "$REJECT_CORPUS/unsupported-filter.h5"
cp -- "$FIXTURES/external-link.h5" "$REJECT_CORPUS/external-link.h5"
cp -- "$FIXTURES/unsupported-dtype.h5" "$REJECT_CORPUS/unsupported-dtype.h5"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$PROFILE" --validation-run hdf06-reject-run \
  run --target hdf5-weights --backend local-harness --corpus-dir "$REJECT_CORPUS" \
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
assert (status["total"], status["success"], status["rejected"], status["failed"]) == (3, 0, 3, 0)
logs = "\n".join(path.read_text(encoding="utf-8") for path in (status_path.parent / "logs").glob("*.log"))
for marker in ("stage=filter_policy", "stage=dtype_policy", "stage=link_policy"):
    assert marker in logs
PY
then
  ok "run preserves unsupported filter, dtype, and external-link classifications"
else
  bad "run swallowed or promoted an unsupported HDF5 input"
  sed -n '1,64p' "$WORK/reject-run.log" >&2
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
printf 'ERROR: AddressSanitizer: SEGV after HDF5 H5Dread\\n' >&2
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
    "version": "hdf06-fault-after-h5dread-v1",
    "path": os.path.abspath(wrapper),
    "sha256": digest,
}
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

FAULT_CORPUS="$FAULT_DIR/corpus"
mkdir -p -- "$FAULT_CORPUS"
cp -- "$FIXTURES/tensor-chunked.h5" "$FAULT_CORPUS/fault.h5"
: >"$FAULT_OBSERVED"
: >"$FAULT_TRANSCRIPT"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$FAULT_PROFILE" --validation-run hdf06-fault-run \
  run --target hdf5-weights --backend local-harness --corpus-dir "$FAULT_CORPUS" \
  --workers 1 --timeout-sec 30 --restart-limit 0 \
  >"$WORK/fault-run.log" 2>&1
fault_run_rc=$?
FAULT_STATUS="$(sed -n 's/^status: //p' "$WORK/fault-run.log" | tail -n 1)"
FAULT_RUN_DIR="$(dirname -- "$FAULT_STATUS")"
FAULT_INPUT="$(find "$FAULT_RUN_DIR/crash-inputs" -maxdepth 1 -type f -name '*.h5' -print 2>/dev/null | head -n 1)"
if [[ "$fault_run_rc" -eq 0 && -f "$FAULT_STATUS" && -f "$FAULT_INPUT" ]] \
  && grep -Fq 'HDF5_ACCESS_OK datasets=1 attributes=0 h5dread_calls=1' "$FAULT_TRANSCRIPT" \
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
assert hashlib.sha256((status_path.parent / "inputs" / "fault.h5").read_bytes()).hexdigest() == expected
PY
then
  ok "a post-H5Dread fault preserves the exact HDF5 input"
else
  bad "HDF5 fault propagation bypassed the loader or lost the input"
  sed -n '1,64p' "$WORK/fault-run.log" >&2
  stop_after_failure
fi

: >"$FAULT_OBSERVED"
: >"$FAULT_TRANSCRIPT"
"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  --target-profile "$FAULT_PROFILE" --validation-run hdf06-triage \
  triage --target hdf5-weights --input "$FAULT_INPUT" --repro-retries 3 --timeout-sec 30 \
  >"$WORK/triage.log" 2>&1
triage_rc=$?
TRIAGE_SUMMARY="$(sed -n 's/^summary: //p' "$WORK/triage.log" | tail -n 1)"
TRIAGE_ID="$(basename -- "$(dirname -- "$TRIAGE_SUMMARY")")"
if [[ "$triage_rc" -eq 0 && -f "$TRIAGE_SUMMARY" ]] \
  && [[ "$(grep -Fc 'HDF5_ACCESS_OK datasets=1 attributes=0 h5dread_calls=1' "$FAULT_TRANSCRIPT")" -eq 4 ]] \
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
assert summary["target"] == "hdf5-weights"
assert summary["verdict"] == "reproduced"
assert summary["crashed_count"] == 3
assert summary["signature_consistent"] is True
assert all(attempt["signal"] == "SIGSEGV" for attempt in summary["attempts"])
assert len(observed) == 4 and set(observed) == {expected}, observed
assert len(manifest["files"]) == 1 and manifest["files"][0]["sha256"] == expected
assert hashlib.sha256(pathlib.Path(summary["input"]).read_bytes()).hexdigest() == expected
PY
then
  ok "generic triage repeats the same HDF5 input before every fault"
else
  bad "generic HDF5 triage changed the input, target, or verdict"
  sed -n '1,80p' "$WORK/triage.log" >&2
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
assert shown["target_id"] == "hdf5-weights"
assert shown["profiled"] is True
assert shown["primary"]["verdict"] == "reproduced"
assert meta["target"] == "hdf5-weights"
assert meta["input_sha256"] == expected
assert meta["poc_collected"] is True and meta["poc_sha256"] == expected
assert "keras" not in json.dumps(shown).lower()
assert "keras" not in json.dumps(meta).lower()
PY
then
  ok "strict show and frozen report retain HDF5 identity without a Keras claim"
else
  bad "show/report lost HDF5 identity or widened it to Keras"
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
  && python3 -B - "$EXPECTED_SHA" "$WORK/dashboard.html" \
    "$RUN_EXPORT" "$TRIAGE_EXPORT" "$REPORT_EXPORT" <<'PY'
import json
import pathlib
import re
import sys

expected, dashboard_text, *roots = sys.argv[1:]
dashboard = pathlib.Path(dashboard_text).read_text(encoding="utf-8")
options = re.findall(r'<option value="([^"]+)"', dashboard)
assert "hdf5-weights" not in options
assert not any("keras" in option.lower() for option in options)
assert "hdf5-weights" in dashboard
assert "keras-v3" not in dashboard.lower()

for root_text in roots:
    root = pathlib.Path(root_text)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    hdf_rows = [row for row in manifest["files"] if row["path"].endswith(".h5")]
    assert hdf_rows, sorted(row["path"] for row in manifest["files"])
    assert any(row["sha256"] == expected for row in hdf_rows)
    assert "keras" not in json.dumps(manifest).lower()
PY
then
  ok "run/triage/report exports and UI agree on HDF5 evidence without support promotion"
else
  bad "strict export or UI lost HDF5 evidence or advertised Keras support"
  sed -n '1,32p' "$WORK/export-run.log" >&2
  sed -n '1,32p' "$WORK/export-triage.log" >&2
  sed -n '1,32p' "$WORK/export-report.log" >&2
  stop_after_failure
fi

sha256sum "${PRESERVED[@]}" >"$WORK/preserved-after.sha256"
if cmp -s "$WORK/preserved-before.sha256" "$WORK/preserved-after.sha256"; then
  ok "pre-existing HDF-01 and HDF-05 evidence stayed byte-identical"
else
  bad "the HDF-06 integration run changed preserved HDF evidence"
  stop_after_failure
fi

summary
[[ "$FAIL" -eq 0 ]]
