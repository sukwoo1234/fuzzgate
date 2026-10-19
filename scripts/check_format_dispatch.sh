#!/usr/bin/env bash
# FND-04 target-registry, profiled-result, and unclassified-diagnostic contract.
# Every write stays below one private temporary directory.
set -euo pipefail
ulimit -c 0 || true

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/format-dispatch-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*" >&2; }

if [[ ! -x "$TOOL_BIN" ]]; then
  printf '[format-dispatch] fail: tool binary not executable: %s\n' "$TOOL_BIN" >&2
  printf '[format-dispatch] this gate cannot run without the tool binary\n' >&2
  exit 1
fi

DATA="$WORK/data"
SEEDS="$WORK/seeds"
mkdir -p "$DATA/runs/run-profiled/inputs" "$SEEDS/onnx" "$WORK/profile"
printf 'profiled-input' >"$DATA/runs/run-profiled/inputs/sample.onnx"

cat >"$WORK/profile/replay" <<'REPLAY'
#!/usr/bin/env bash
printf 'Traceback (most recent call last):\n' >&2
printf '  File "fixture/loader.py", line 7, in parse\n' >&2
printf 'UnexpectedFixtureError: fnd04-unclassified\n' >&2
exit 11
REPLAY
chmod +x "$WORK/profile/replay"

python3 -B - "$WORK/profile" "$DATA/runs/run-profiled" <<'PY'
import hashlib
import json
import os
import sys

profile_root, result_root = sys.argv[1:]
replay = os.path.join(profile_root, "replay")
binary_hash = hashlib.sha256(open(replay, "rb").read()).hexdigest()
profile = {
    "schema_version": "1",
    "target_id": "onnx",
    "format_revision": "onnx-ir-v10",
    "loader_id": "fnd04-fixture",
    "loader_version": "1",
    "source_artifacts": [{
        "url": "https://github.com/microsoft/onnxruntime/archive/refs/tags/v1.23.2.tar.gz",
        "tag": "v1.23.2",
        "resolved_commit": "0123456789abcdef0123456789abcdef01234567",
        "sha256": binary_hash,
        "size_bytes": os.path.getsize(replay),
    }],
    "patches": [],
    "toolchain": {
        "compiler": {"version": "1", "path": replay, "sha256": binary_hash},
        "linker": {"version": "1", "path": replay, "sha256": binary_hash},
        "engine": {"version": "1", "path": replay, "sha256": binary_hash},
        "python": None,
        "rust": {"version": "1", "path": replay, "sha256": binary_hash},
        "environment": {"PATH": "/usr/bin:/bin"},
    },
    "sanitizer_policy": {
        "compile_flags": ["-fsanitize=address"],
        "recovery": "abort",
        "runtime_env": {"ASAN_OPTIONS": "abort_on_error=1"},
        "rust_panic": "abort",
    },
    "binaries": [{
        "role": "replay",
        "path": replay,
        "sha256": binary_hash,
        "argv": ["{input}"],
        "linked_libraries": [],
    }],
    "input_kind": {"kind": "single", "extensions": ["onnx"], "subformats": []},
    "depth": "session",
    "engine_capabilities": [{
        "backend": "local-harness",
        "binary_role": "replay",
        "required_mode": "native",
        "instrumentation_scope": "fixture",
    }],
    "limits": {
        "max_input_bytes": 1048576,
        "memory_bytes": 1073741824,
        "input_timeout_ms": 5000,
        "block_timeout_ms": 30000,
        "threads": 1,
        "workers": 1,
    },
    "coverage_scope": {
        "unit": "source-line",
        "include_sources": ["fixture"],
        "exclude_sources": [],
    },
}
profile_path = os.path.join(profile_root, "profile.json")
with open(profile_path, "w", encoding="utf-8") as stream:
    json.dump(profile, stream, indent=2, sort_keys=True)
    stream.write("\n")
profile_hash = hashlib.sha256(open(profile_path, "rb").read()).hexdigest()
result_profile_path = os.path.join(result_root, "profile.json")
open(result_profile_path, "wb").write(open(profile_path, "rb").read())
input_path = os.path.join(result_root, "inputs", "sample.onnx")
input_bytes = open(input_path, "rb").read()
input_hash = hashlib.sha256(input_bytes).hexdigest()
input_manifest = {
    "schema_version": "1",
    "files": [{
        "path": "inputs/sample.onnx",
        "size_bytes": len(input_bytes),
        "sha256": input_hash,
    }],
}
input_manifest_path = os.path.join(result_root, "input-manifest.json")
with open(input_manifest_path, "w", encoding="utf-8") as stream:
    json.dump(input_manifest, stream, indent=2)
    stream.write("\n")
input_manifest_hash = hashlib.sha256(open(input_manifest_path, "rb").read()).hexdigest()
corpus_row = f"sample.onnx\0{len(input_bytes)}\0{input_hash}\n".encode()
corpus_hash = hashlib.sha256(corpus_row).hexdigest()
status = {
    "schema_version": "1.0",
    "run_id": "profiled",
    "target": "onnx",
    "backend": "local-harness",
    "total": 1,
    "success": 1,
    "failed": 0,
    "timeout": 0,
    "rejected": 0,
    "unclassified": 0,
    "profiled_result": True,
    "profile_sha256": profile_hash,
}
with open(os.path.join(result_root, "status.json"), "w", encoding="utf-8") as stream:
    json.dump(status, stream, sort_keys=True)
    stream.write("\n")
qualification = {
    "schema_version": "1",
    "profile_sha256": profile_hash,
    "status": "verified",
    "gate_evidence": [
        {"requirement_id": f"Q{number:02}", "evidence_sha256": profile_hash}
        for number in range(1, 13)
    ],
}
qualification_path = os.path.join(profile_root, "qualification.json")
with open(qualification_path, "w", encoding="utf-8") as stream:
    json.dump(qualification, stream, indent=2, sort_keys=True)
    stream.write("\n")
qualification_hash = hashlib.sha256(open(qualification_path, "rb").read()).hexdigest()
result_qualification_path = os.path.join(result_root, "qualification.json")
open(result_qualification_path, "wb").write(open(qualification_path, "rb").read())
execution = {
    "schema_version": "1",
    "profile_path": result_profile_path,
    "profile_sha256": profile_hash,
    "authorization": "qualified",
    "qualification_path": result_qualification_path,
    "qualification_sha256": qualification_hash,
    "validation_run": None,
    "target_id": "onnx",
    "format_revision": "onnx-ir-v10",
    "loader_id": "fnd04-fixture",
    "loader_version": "1",
    "backend": "local-harness",
    "depth": "session",
    "argv": ["tool", "run"],
    "allowed_env": {},
    "corpus_snapshot_sha256": corpus_hash,
    "input_manifest_sha256": input_manifest_hash,
    "tool_commit": None,
    "tool_dirty": None,
    "started_unix_ms": 1,
    "ended_unix_ms": 2,
    "elapsed_ms": 1,
    "outcome": "unclassified",
    "profile_unchanged_after_execution": True,
    "identity_error": None,
}
with open(os.path.join(result_root, "execution.json"), "w", encoding="utf-8") as stream:
    json.dump(execution, stream, indent=2, sort_keys=True)
    stream.write("\n")
marker = {
    "schema_version": "1",
    "target_id": "onnx",
    "profile_sha256": profile_hash,
    "authorization": "qualified",
}
with open(os.path.join(result_root, "profiled-result.json"), "w", encoding="utf-8") as stream:
    json.dump(marker, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

BASE=("$TOOL_BIN" --data-dir "$DATA" --seeds-dir "$SEEDS")

run_ok() { # run_ok LABEL NEEDLE COMMAND...
  local label="$1" needle="$2" log="$WORK/${PASS}-${FAIL}.log"
  shift 2
  if "$@" >"$log" 2>&1 && grep -Fq -- "$needle" "$log"; then
    ok "$label"
  else
    bad "$label"
    sed -n '1,12p' "$log" | sed 's/^/       /' >&2
  fi
}

run_fail() { # run_fail LABEL NEEDLE COMMAND...
  local label="$1" needle="$2" log="$WORK/${PASS}-${FAIL}.log" rc=0
  shift 2
  "$@" >"$log" 2>&1 || rc=$?
  if [[ "$rc" -ne 0 ]] && grep -Fq -- "$needle" "$log"; then
    ok "$label"
  else
    bad "$label (rc=$rc, expected text: $needle)"
    sed -n '1,12p' "$log" | sed 's/^/       /' >&2
  fi
}

rebind_result_identity() { # rebind_result_identity RESULT_DIRECTORY
  python3 -B - "$1" <<'PY'
import json
import os
import sys

root = os.path.abspath(sys.argv[1])
path = os.path.join(root, "execution.json")
execution = json.load(open(path, encoding="utf-8"))
execution["profile_path"] = os.path.join(root, "profile.json")
if execution.get("qualification_path") is not None:
    execution["qualification_path"] = os.path.join(root, "qualification.json")
open(path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
PY
}

clone_profiled_run() { # clone_profiled_run DESTINATION
  local destination="$1"
  cp -a "$DATA/runs/run-profiled" "$destination"
  rebind_result_identity "$destination"
}

run_ok "resolved target spec is available to every dispatcher" '"target_id":"onnx"' \
  "${BASE[@]}" target-spec --target onnx --format json

clone_profiled_run "$DATA/runs/run-external-identity"
rm -f "$DATA/runs/run-external-identity/profile.json" \
  "$DATA/runs/run-external-identity/qualification.json"
python3 -B - "$DATA/runs/run-external-identity" "$WORK/profile" <<'PY'
import json
import os
import sys

root, external = sys.argv[1:]
status_path = os.path.join(root, "status.json")
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "external-identity"
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
execution_path = os.path.join(root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["profile_path"] = os.path.join(external, "profile.json")
execution["qualification_path"] = os.path.join(external, "qualification.json")
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
PY
run_fail "profiled result refuses external identity files" \
  "result-local profile.json" \
  "${BASE[@]}" export run-external-identity

run_ok "show reads an actual result instead of a success stub" '"kind":"run"' \
  "${BASE[@]}" show run-profiled
mkdir -p "$DATA/coverage/coverage-fnd04"
printf '{"schema_version":"2.0","run_id":"fnd04","target":"onnx","coverage_kind":"proxy"}\n' \
  >"$DATA/coverage/coverage-fnd04/summary.json"
run_ok "show accepts the real coverage schema-2 run_id contract" '"kind":"coverage"' \
  "${BASE[@]}" show coverage-fnd04
run_fail "result IDs cannot be interpreted as paths" "invalid result id" \
  "${BASE[@]}" show ../run-profiled

mkdir -p "$WORK/symlink-data" "$WORK/symlink-output-data/runs" "$WORK/outside-exports"
ln -s "$DATA/runs" "$WORK/symlink-data/runs"
run_fail "result resolution rejects a symlinked collection root" \
  "result collection root contains a symlink component" \
  "$TOOL_BIN" --data-dir "$WORK/symlink-data" --seeds-dir "$SEEDS" show run-profiled
clone_profiled_run "$WORK/symlink-output-data/runs/run-profiled"
ln -s "$WORK/outside-exports" "$WORK/symlink-output-data/exports"
run_fail "export refuses a symlinked output root" "export root contains a symlink component" \
  "$TOOL_BIN" --data-dir "$WORK/symlink-output-data" --seeds-dir "$SEEDS" export run-profiled

set +e
"${BASE[@]}" --target-profile "$WORK/profile/profile.json" --validation-run FND04-missing-input \
  harness --target onnx --input "$WORK/input/does-not-exist.onnx" \
  >"$WORK/missing-input.log" 2>&1
MISSING_INPUT_RC=$?
set -e
if [[ "$MISSING_INPUT_RC" -eq 9 ]]; then
  ok "profiled harness preserves the legacy missing-input exit code"
else
  bad "profiled harness preserves the legacy missing-input exit code (rc=$MISSING_INPUT_RC)"
fi

run_ok "export writes a complete manifest" '[export] done' \
  "${BASE[@]}" export run-profiled
EXPORT_PATH="$(find "$DATA/exports" -mindepth 1 -maxdepth 1 -type d -name 'export-run-profiled-*' 2>/dev/null | sort | tail -n1 || true)"
if [[ -n "$EXPORT_PATH" ]] && python3 -B - "$EXPORT_PATH" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
manifest = json.load(open(os.path.join(root, "manifest.json"), encoding="utf-8"))
assert manifest["complete"] is True
assert manifest["result_id"] == "run-profiled"
paths = {entry["path"]: entry for entry in manifest["files"]}
required = {
    "result/status.json",
    "result/execution.json",
    "result/input-manifest.json",
    "result/inputs/sample.onnx",
    "identity/profile.json",
    "identity/qualification.json",
}
assert required <= paths.keys(), sorted(paths)
for path, entry in paths.items():
    payload = open(os.path.join(root, path), "rb").read()
    assert len(payload) == entry["size_bytes"]
    assert hashlib.sha256(payload).hexdigest() == entry["sha256"]
PY
then
  ok "export includes result, whole input, profile, and qualification bytes"
else
  bad "export includes result, whole input, profile, and qualification bytes"
fi

clone_profiled_run "$DATA/runs/run-smoke-qualified"
python3 -B - "$DATA/runs/run-smoke-qualified" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
status_path = os.path.join(root, "status.json")
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "smoke-qualified"
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
qualification_path = os.path.join(root, "qualification.json")
qualification = json.load(open(qualification_path, encoding="utf-8"))
qualification["status"] = "smoke_passed"
open(qualification_path, "w", encoding="utf-8").write(
    json.dumps(qualification, sort_keys=True) + "\n"
)
qualification_hash = hashlib.sha256(open(qualification_path, "rb").read()).hexdigest()
execution_path = os.path.join(root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["qualification_sha256"] = qualification_hash
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
PY
run_fail "smoke-passed qualification cannot authorize a verified export" \
  "qualified result requires qualification status verified" \
  "${BASE[@]}" export run-smoke-qualified

clone_profiled_run "$DATA/runs/run-unqualified"
python3 -B - "$DATA/runs/run-unqualified/status.json" "$DATA/runs/run-unqualified/execution.json" "$DATA/runs/run-unqualified/profiled-result.json" <<'PY'
import json, sys
status_path, execution_path, marker_path = sys.argv[1:]
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "unqualified"
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["authorization"] = "unqualified_validation"
execution["qualification_path"] = None
execution["qualification_sha256"] = None
execution["validation_run"] = "FND04-unqualified"
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
marker = json.load(open(marker_path, encoding="utf-8"))
marker["authorization"] = "unqualified_validation"
open(marker_path, "w", encoding="utf-8").write(json.dumps(marker) + "\n")
PY
cp "$WORK/profile/qualification.json" "$DATA/runs/run-unqualified/qualification.json"
run_fail "unqualified result refuses a qualification sidecar" \
  "unqualified result must not contain qualification.json" \
  "${BASE[@]}" export run-unqualified
rm "$DATA/runs/run-unqualified/qualification.json"
run_ok "unqualified validation export remains explicit and complete" '[export] done' \
  "${BASE[@]}" export run-unqualified
UNQUALIFIED_EXPORT="$(find "$DATA/exports" -mindepth 1 -maxdepth 1 -type d -name 'export-run-unqualified-*' 2>/dev/null | sort | tail -n1 || true)"
if [[ -n "$UNQUALIFIED_EXPORT" ]] && python3 -B - "$UNQUALIFIED_EXPORT/manifest.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["qualification_status"] == "unqualified"
assert value["missing_reasons"]
assert all(entry["path"] != "identity/qualification.json" for entry in value["files"])
PY
then
  ok "unqualified export cannot be mistaken for verified"
else
  bad "unqualified export cannot be mistaken for verified"
fi

clone_profiled_run "$DATA/runs/run-missing-input"
rm -rf "$DATA/runs/run-missing-input/inputs"
python3 -B - "$DATA/runs/run-missing-input/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "missing-input"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "profiled export refuses a missing original input" "input manifest" \
  "${BASE[@]}" export run-missing-input

clone_profiled_run "$DATA/runs/run-input-tampered"
printf 'different-profiled-input' >"$DATA/runs/run-input-tampered/inputs/sample.onnx"
python3 -B - "$DATA/runs/run-input-tampered/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "input-tampered"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "profiled export binds preserved input bytes to its manifest" \
  "input manifest" \
  "${BASE[@]}" export run-input-tampered

clone_profiled_run "$DATA/runs/run-missing-execution"
rm "$DATA/runs/run-missing-execution/execution.json"
python3 -B - "$DATA/runs/run-missing-execution/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "missing-execution"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "profile marker cannot be downgraded by deleting execution.json" \
  "profiled result is missing execution.json" \
  "${BASE[@]}" export run-missing-execution

clone_profiled_run "$DATA/runs/run-missing-profile-contract"
rm "$DATA/runs/run-missing-profile-contract/execution.json" \
  "$DATA/runs/run-missing-profile-contract/profiled-result.json"
python3 -B - "$DATA/runs/run-missing-profile-contract/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "missing-profile-contract"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "profile identity cannot be downgraded by deleting marker and execution" \
  "profiled result is missing execution.json" \
  "${BASE[@]}" export run-missing-profile-contract

clone_profiled_run "$DATA/runs/run-identity-sidecar-downgrade"
rm "$DATA/runs/run-identity-sidecar-downgrade/execution.json" \
  "$DATA/runs/run-identity-sidecar-downgrade/profiled-result.json" \
  "$DATA/runs/run-identity-sidecar-downgrade/input-manifest.json"
python3 -B - "$DATA/runs/run-identity-sidecar-downgrade/status.json" <<'PY'
import json
import sys

path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "identity-sidecar-downgrade"
value.pop("profiled_result", None)
value.pop("profile_sha256", None)
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "identity sidecars cannot be downgraded to a legacy result" \
  "identity sidecar without execution.json" \
  "${BASE[@]}" export run-identity-sidecar-downgrade

clone_profiled_run "$DATA/runs/run-running"
python3 -B - "$DATA/runs/run-running/status.json" "$DATA/runs/run-running/execution.json" <<'PY'
import json, sys
status_path, execution_path = sys.argv[1:]
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "running"
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["outcome"] = "running"
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
PY
run_fail "profiled export refuses a nonterminal execution" "execution outcome is not terminal" \
  "${BASE[@]}" export run-running

clone_profiled_run "$DATA/runs/run-identity-drift"
python3 -B - "$DATA/runs/run-identity-drift/status.json" "$DATA/runs/run-identity-drift/execution.json" <<'PY'
import json, sys
status_path, execution_path = sys.argv[1:]
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "identity-drift"
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["outcome"] = "identity_drift"
execution["profile_unchanged_after_execution"] = False
execution["identity_error"] = "fixture drift"
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
PY
run_fail "profiled export refuses an identity-drift execution" \
  "execution outcome is not terminal" \
  "${BASE[@]}" export run-identity-drift

clone_profiled_run "$DATA/runs/run-private-file"
python3 -B - "$DATA/runs/run-private-file/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "private-file"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
printf 'do-not-export' >"$DATA/runs/run-private-file/private.env"
run_fail "profiled export rejects files outside the result allowlist" "not allowed" \
  "${BASE[@]}" export run-private-file

clone_profiled_run "$DATA/runs/run-unclassified-type"
python3 -B - "$DATA/runs/run-unclassified-type/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "unclassified-type"
value["unclassified"] = "1"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "unclassified count cannot bypass evidence validation with a string" \
  "unclassified must be an unsigned integer" \
  "${BASE[@]}" export run-unclassified-type

clone_profiled_run "$DATA/runs/run-fzb"
rm "$DATA/runs/run-fzb/inputs/sample.onnx"
printf 'FZB1\0whole-bundle\0tail' >"$DATA/runs/run-fzb/inputs/sample.fzb"
mkdir -p "$WORK/fzb-profile"
python3 -B - "$DATA/runs/run-fzb" "$WORK/profile/profile.json" "$WORK/fzb-profile" <<'PY'
import hashlib
import json
import os
import sys

result_root, source_profile, _profile_root = sys.argv[1:]
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
profile = json.load(open(source_profile, encoding="utf-8"))
profile["input_kind"] = {"kind": "fzb1", "extensions": ["fzb"], "subformats": []}
profile_path = os.path.join(result_root, "profile.json")
open(profile_path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
profile_hash = sha(profile_path)
qualification = {
    "schema_version": "1",
    "profile_sha256": profile_hash,
    "status": "verified",
    "gate_evidence": [
        {"requirement_id": f"Q{number:02}", "evidence_sha256": profile_hash}
        for number in range(1, 13)
    ],
}
qualification_path = os.path.join(result_root, "qualification.json")
open(qualification_path, "w", encoding="utf-8").write(json.dumps(qualification, sort_keys=True) + "\n")
execution_path = os.path.join(result_root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["profile_path"] = profile_path
execution["profile_sha256"] = profile_hash
execution["qualification_path"] = qualification_path
execution["qualification_sha256"] = sha(qualification_path)
input_path = os.path.join(result_root, "inputs", "sample.fzb")
input_bytes = open(input_path, "rb").read()
input_hash = hashlib.sha256(input_bytes).hexdigest()
manifest = {
    "schema_version": "1",
    "files": [{
        "path": "inputs/sample.fzb",
        "size_bytes": len(input_bytes),
        "sha256": input_hash,
    }],
}
manifest_path = os.path.join(result_root, "input-manifest.json")
with open(manifest_path, "w", encoding="utf-8") as stream:
    json.dump(manifest, stream, indent=2)
    stream.write("\n")
execution["input_manifest_sha256"] = sha(manifest_path)
corpus_row = f"sample.fzb\0{len(input_bytes)}\0{input_hash}\n".encode()
execution["corpus_snapshot_sha256"] = hashlib.sha256(corpus_row).hexdigest()
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution, sort_keys=True) + "\n")
status_path = os.path.join(result_root, "status.json")
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "fzb"
status["profile_sha256"] = profile_hash
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
marker_path = os.path.join(result_root, "profiled-result.json")
marker = json.load(open(marker_path, encoding="utf-8"))
marker["profile_sha256"] = profile_hash
open(marker_path, "w", encoding="utf-8").write(json.dumps(marker) + "\n")
PY
run_ok "FZB1 profiled export accepts the complete original bundle" '[export] done' \
  "${BASE[@]}" export run-fzb
cp -a "$DATA/runs/run-fzb" "$DATA/runs/run-fzb-missing"
rebind_result_identity "$DATA/runs/run-fzb-missing"
rm "$DATA/runs/run-fzb-missing/inputs/sample.fzb"
printf 'placeholder' >"$DATA/runs/run-fzb-missing/inputs/placeholder.txt"
python3 -B - "$DATA/runs/run-fzb-missing/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "fzb-missing"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "FZB1 export refuses a partial or substituted input" "input manifest" \
  "${BASE[@]}" export run-fzb-missing

clone_profiled_run "$DATA/runs/run-symlink"
python3 -B - "$DATA/runs/run-symlink/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "symlink"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
ln -s /etc/passwd "$DATA/runs/run-symlink/inputs/outside"
run_fail "export never follows a result symlink" "result contains a symlink" \
  "${BASE[@]}" export run-symlink

clone_profiled_run "$DATA/runs/run-id-mismatch"
run_fail "primary result ID must match its directory" "result id mismatch" \
  "${BASE[@]}" export run-id-mismatch

clone_profiled_run "$DATA/runs/run-primary-schema"
python3 -B - "$DATA/runs/run-primary-schema/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "primary-schema"
value["schema_version"] = "999"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "unsupported primary schema leaves no complete export" \
  "unsupported run primary schema_version" \
  "${BASE[@]}" export run-primary-schema

clone_profiled_run "$DATA/runs/run-bad-schema"
python3 -B - "$DATA/runs/run-bad-schema/status.json" "$DATA/runs/run-bad-schema/execution.json" <<'PY'
import json, sys
status_path, path = sys.argv[1:]
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "bad-schema"
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
value = json.load(open(path, encoding="utf-8"))
value["schema_version"] = "999"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "unsupported execution schema leaves no complete export" "unsupported execution schema_version" \
  "${BASE[@]}" export run-bad-schema

clone_profiled_run "$DATA/runs/run-marker-extra-field"
python3 -B - "$DATA/runs/run-marker-extra-field/status.json" \
  "$DATA/runs/run-marker-extra-field/profiled-result.json" <<'PY'
import json, sys
status_path, marker_path = sys.argv[1:]
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "marker-extra-field"
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
marker = json.load(open(marker_path, encoding="utf-8"))
marker["unexpected_authority"] = True
open(marker_path, "w", encoding="utf-8").write(json.dumps(marker) + "\n")
PY
run_fail "profiled marker rejects unknown authority fields" "unknown field" \
  "${BASE[@]}" export run-marker-extra-field

clone_profiled_run "$DATA/runs/run-bad-profile-hash"
python3 -B - "$DATA/runs/run-bad-profile-hash/status.json" "$DATA/runs/run-bad-profile-hash/execution.json" <<'PY'
import json, sys
status_path, path = sys.argv[1:]
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "bad-profile-hash"
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
value = json.load(open(path, encoding="utf-8"))
value["profile_sha256"] = "0" * 64
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "profile hash mismatch leaves no complete export" "profile sha256 mismatch" \
  "${BASE[@]}" export run-bad-profile-hash

clone_profiled_run "$DATA/runs/run-wrong-target"
python3 -B - "$DATA/runs/run-wrong-target/status.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["run_id"] = "wrong-target"
value["target"] = "gguf"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
run_fail "target and profile mismatch is rejected before export" "target mismatch" \
  "${BASE[@]}" export run-wrong-target
if ! find "$DATA/exports" -mindepth 1 -maxdepth 1 -name 'export-run-wrong-target-*' 2>/dev/null | grep -q .; then
  ok "failed export leaves no completed output"
else
  bad "failed export leaves no completed output"
fi

mkdir -p "$WORK/input"
printf 'fixture' >"$WORK/input/model.onnx"
set +e
"${BASE[@]}" --target-profile "$WORK/profile/profile.json" --validation-run FND04-exit11 \
  harness --target onnx --input "$WORK/input/model.onnx" >"$WORK/exit11.log" 2>&1
EXIT11_RC=$?
set -e
if [[ "$EXIT11_RC" -eq 11 ]]; then
  ok "profiled exit 11 remains exit 11"
else
  bad "profiled exit 11 remains exit 11 (rc=$EXIT11_RC)"
fi
DIAGNOSTIC_PATH="$(find "$DATA/diagnostics" -mindepth 1 -maxdepth 1 -type d -name 'diagnostic-*' 2>/dev/null | sort | tail -n1 || true)"
if [[ -n "$DIAGNOSTIC_PATH" ]] && python3 -B - "$DIAGNOSTIC_PATH" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
record = json.load(open(os.path.join(root, "diagnostic.json"), encoding="utf-8"))
assert record["classification"] == "unclassified"
for relative in ["input/model.onnx", "profile.json", "execution.json", "traceback.txt"]:
    assert os.path.isfile(os.path.join(root, relative)), relative
assert hashlib.sha256(open(os.path.join(root, "input/model.onnx"), "rb").read()).hexdigest() == record["input_sha256"]
PY
then
  ok "exit 11 preserves an unclassified diagnostic bundle"
else
  bad "exit 11 preserves an unclassified diagnostic bundle"
fi

SIGNAL_PATH=""
if [[ -n "$DIAGNOSTIC_PATH" ]]; then
  DIAGNOSTIC_ID="$(basename "$DIAGNOSTIC_PATH")"
  run_ok "diagnostic show uses the same exact-ID resolver" '"kind":"diagnostic"' \
    "${BASE[@]}" show "$DIAGNOSTIC_ID"
  run_ok "diagnostic IDs are discoverable through list" "$DIAGNOSTIC_ID" \
    "${BASE[@]}" list --kind diagnostics --limit 5
  run_ok "list all includes the diagnostic collection" '[diagnostics]' \
    "${BASE[@]}" list --kind all --limit 1
  run_ok "diagnostic replay records repeated unclassified results" 'result: reproduced' \
    "${BASE[@]}" replay-diagnostic "$DIAGNOSTIC_ID" --attempts 2
  run_fail "diagnostic replay refuses a single observation" '2..=100' \
    "${BASE[@]}" replay-diagnostic "$DIAGNOSTIC_ID" --attempts 1

  OVERSIZE_ID="diagnostic-oversize-replay"
  OVERSIZE_PATH="$DATA/diagnostics/$OVERSIZE_ID"
  cp -a "$DIAGNOSTIC_PATH" "$OVERSIZE_PATH"
  rm -rf "$OVERSIZE_PATH/replays"
  cat >"$WORK/profile/replay-oversize" <<'REPLAY_OVERSIZE'
#!/usr/bin/env bash
head -c 8388300 /dev/zero | tr '\0' x >&2
printf '\nTraceback (most recent call last):\n' >&2
printf '  File "fixture/loader.py", line 7, in parse\n' >&2
printf 'UnexpectedFixtureError: oversized-replay\n' >&2
exit 11
REPLAY_OVERSIZE
  chmod +x "$WORK/profile/replay-oversize"
  python3 -B - "$OVERSIZE_PATH" "$OVERSIZE_ID" "$WORK/profile/replay-oversize" <<'PY'
import hashlib
import json
import os
import sys

root, diagnostic_id, replay = sys.argv[1:]
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
replay_hash = sha(replay)
profile_path = os.path.join(root, "profile.json")
profile = json.load(open(profile_path, encoding="utf-8"))
for artifact in profile["source_artifacts"]:
    artifact["sha256"] = replay_hash
    artifact["size_bytes"] = os.path.getsize(replay)
for key in ["compiler", "linker", "engine", "rust"]:
    profile["toolchain"][key]["path"] = replay
    profile["toolchain"][key]["sha256"] = replay_hash
for binary in profile["binaries"]:
    binary["path"] = replay
    binary["sha256"] = replay_hash
open(profile_path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
profile_hash = sha(profile_path)
execution_path = os.path.join(root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["profile_path"] = profile_path
execution["profile_sha256"] = profile_hash
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution, sort_keys=True) + "\n")
marker_path = os.path.join(root, "profiled-result.json")
marker = json.load(open(marker_path, encoding="utf-8"))
marker["profile_sha256"] = profile_hash
open(marker_path, "w", encoding="utf-8").write(json.dumps(marker, sort_keys=True) + "\n")
record_path = os.path.join(root, "diagnostic.json")
record = json.load(open(record_path, encoding="utf-8"))
record["diagnostic_id"] = diagnostic_id
record["profile_sha256"] = profile_hash
record["execution_sha256"] = sha(execution_path)
open(record_path, "w", encoding="utf-8").write(json.dumps(record, sort_keys=True) + "\n")
PY
  run_fail "diagnostic replay refuses a record larger than its readable JSON limit" \
    "diagnostic replay record exceeds 16777216 bytes" \
    "${BASE[@]}" replay-diagnostic "$OVERSIZE_ID" --attempts 2
  if ! find "$OVERSIZE_PATH/replays" -maxdepth 1 -type f -name 'replay-*.json' \
    -print -quit 2>/dev/null | grep -q .; then
    ok "oversized diagnostic replay leaves no unreadable record"
  else
    bad "oversized diagnostic replay leaves no unreadable record"
  fi
  rm -rf "$OVERSIZE_PATH"

  run_ok "diagnostic export includes its complete evidence" '[export] done' \
    "${BASE[@]}" export "$DIAGNOSTIC_ID"
  python3 -B - "$DIAGNOSTIC_PATH/diagnostic.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["unexpected_authority"] = True
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
  run_fail "diagnostic record rejects unknown authority fields" "unknown field" \
    "${BASE[@]}" export "$DIAGNOSTIC_ID"
  python3 -B - "$DIAGNOSTIC_PATH/diagnostic.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value.pop("unexpected_authority")
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
  REPLAY_RECORD="$(find "$DIAGNOSTIC_PATH/replays" -maxdepth 1 -type f \
    -name 'replay-*.json' -print | sort | head -n1)"
  cp "$REPLAY_RECORD" "$WORK/replay-record.backup"
  python3 -B - "$REPLAY_RECORD" <<'PY'
import hashlib
import json
import sys

path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
for observation in value["observations"]:
    observation["outcome"] = "success"
    observation["detail"] = ""
    observation["detail_sha256"] = hashlib.sha256(b"").hexdigest()
    observation["fingerprint"] = None
value["same_exception_fingerprint"] = True
value["result"] = "reproduced"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
  run_fail "diagnostic replay verdict is derived from its observations" \
    "observations" \
    "${BASE[@]}" export "$DIAGNOSTIC_ID"
  cp "$WORK/replay-record.backup" "$REPLAY_RECORD"
  python3 -B - "$REPLAY_RECORD" <<'PY'
import json
import sys

path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
forged = {
    "exception_type": "ForgedReplayError",
    "target_frames": ["fixture/forged.py::forged"],
}
value["original_fingerprint"] = forged
for observation in value["observations"]:
    assert observation["outcome"] == "unclassified", observation
    observation["fingerprint"] = forged
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
  run_fail "diagnostic replay fingerprints are derived from traceback evidence" \
    "fingerprint" \
    "${BASE[@]}" export "$DIAGNOSTIC_ID"
  cp "$WORK/replay-record.backup" "$REPLAY_RECORD"
  python3 -B - "$REPLAY_RECORD" <<'PY'
import json
import sys

path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value.pop("validation_run", None)
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
  run_fail "diagnostic replay records a fresh validation identity" \
    "validation_run" \
    "${BASE[@]}" export "$DIAGNOSTIC_ID"
  cp "$WORK/replay-record.backup" "$REPLAY_RECORD"
  printf 'must-not-leave-the-result\n' >"$DIAGNOSTIC_PATH/replays/private.env"
  run_fail "diagnostic export rejects non-replay files below replays" \
    "not allowed" \
    "${BASE[@]}" export "$DIAGNOSTIC_ID"
  rm "$DIAGNOSTIC_PATH/replays/private.env"
  printf '{}\n' >"$DIAGNOSTIC_PATH/replays/replay-malformed.json"
  run_fail "diagnostic export validates replay record structure" \
    "diagnostic replay record" \
    "${BASE[@]}" export "$DIAGNOSTIC_ID"
  rm "$DIAGNOSTIC_PATH/replays/replay-malformed.json"

  INVALID_EXECUTION_ID="diagnostic-invalid-execution"
  INVALID_EXECUTION_PATH="$DATA/diagnostics/$INVALID_EXECUTION_ID"
  cp -a "$DIAGNOSTIC_PATH" "$INVALID_EXECUTION_PATH"
  rm -rf "$INVALID_EXECUTION_PATH/replays"
  python3 -B - "$INVALID_EXECUTION_PATH" "$INVALID_EXECUTION_ID" <<'PY'
import hashlib
import json
import os
import sys

root, diagnostic_id = sys.argv[1:]
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
execution_path = os.path.join(root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["schema_version"] = "999"
execution["profile_path"] = os.path.join(root, "profile.json")
if execution.get("qualification_path"):
    execution["qualification_path"] = os.path.join(root, "qualification.json")
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
record_path = os.path.join(root, "diagnostic.json")
record = json.load(open(record_path, encoding="utf-8"))
record["diagnostic_id"] = diagnostic_id
record["execution_sha256"] = sha(execution_path)
open(record_path, "w", encoding="utf-8").write(json.dumps(record) + "\n")
PY
  run_fail "diagnostic replay validates the complete execution contract" \
    "unsupported execution schema_version" \
    "${BASE[@]}" replay-diagnostic "$INVALID_EXECUTION_ID" --attempts 2

  DIFFERENT_ID="diagnostic-different"
  DIFFERENT_PATH="$DATA/diagnostics/$DIFFERENT_ID"
  cp -a "$DIAGNOSTIC_PATH" "$DIFFERENT_PATH"
  rm -rf "$DIFFERENT_PATH/replays"
  cat >"$WORK/profile/replay-different" <<'REPLAY_DIFFERENT'
#!/usr/bin/env bash
printf 'Traceback (most recent call last):\n' >&2
printf '  File "fixture/loader.py", line 99, in parse\n' >&2
printf 'DifferentFixtureError: stable-but-different\n' >&2
exit 11
REPLAY_DIFFERENT
  chmod +x "$WORK/profile/replay-different"
  python3 -B - "$DIFFERENT_PATH" "$DIFFERENT_ID" "$WORK/profile/replay-different" <<'PY'
import hashlib
import json
import os
import sys

root, diagnostic_id, replay = sys.argv[1:]
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
replay_hash = sha(replay)
profile_path = os.path.join(root, "profile.json")
profile = json.load(open(profile_path, encoding="utf-8"))
for artifact in profile["source_artifacts"]:
    artifact["sha256"] = replay_hash
    artifact["size_bytes"] = os.path.getsize(replay)
for key in ["compiler", "linker", "engine", "rust"]:
    profile["toolchain"][key]["path"] = replay
    profile["toolchain"][key]["sha256"] = replay_hash
for binary in profile["binaries"]:
    binary["path"] = replay
    binary["sha256"] = replay_hash
open(profile_path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
profile_hash = sha(profile_path)

qualification_path = os.path.join(root, "qualification.json")
qualification_hash = None
if os.path.isfile(qualification_path):
    qualification = json.load(open(qualification_path, encoding="utf-8"))
    qualification["profile_sha256"] = profile_hash
    for evidence in qualification["gate_evidence"]:
        evidence["evidence_sha256"] = profile_hash
    open(qualification_path, "w", encoding="utf-8").write(json.dumps(qualification, sort_keys=True) + "\n")
    qualification_hash = sha(qualification_path)

execution_path = os.path.join(root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["profile_path"] = profile_path
execution["profile_sha256"] = profile_hash
execution["qualification_path"] = qualification_path if qualification_hash else None
execution["qualification_sha256"] = qualification_hash
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution, sort_keys=True) + "\n")

marker_path = os.path.join(root, "profiled-result.json")
marker = json.load(open(marker_path, encoding="utf-8"))
marker["profile_sha256"] = profile_hash
open(marker_path, "w", encoding="utf-8").write(json.dumps(marker, sort_keys=True) + "\n")

record_path = os.path.join(root, "diagnostic.json")
record = json.load(open(record_path, encoding="utf-8"))
record["diagnostic_id"] = diagnostic_id
record["profile_sha256"] = profile_hash
record["qualification_path"] = "qualification.json" if qualification_hash else None
record["qualification_sha256"] = qualification_hash
record["execution_sha256"] = sha(execution_path)
open(record_path, "w", encoding="utf-8").write(json.dumps(record, sort_keys=True) + "\n")
PY
  run_ok "replay requires the original exception fingerprint, not just stable repeats" \
    'result: not_reproduced' \
    "${BASE[@]}" replay-diagnostic "$DIFFERENT_ID" --attempts 2

  MUTATING_ID="diagnostic-mutating-input"
  MUTATING_PATH="$DATA/diagnostics/$MUTATING_ID"
  cp -a "$DIAGNOSTIC_PATH" "$MUTATING_PATH"
  rm -rf "$MUTATING_PATH/replays"
  cat >"$WORK/profile/replay-mutating" <<'REPLAY_MUTATING'
#!/usr/bin/env bash
if grep -Fqx 'fixture' "$1"; then
  printf 'mutated-between-attempts\n' >"$1"
  printf 'Traceback (most recent call last):\n' >&2
  printf '  File "fixture/loader.py", line 7, in parse\n' >&2
  printf 'UnexpectedFixtureError: fnd04-unclassified\n' >&2
else
  printf 'Traceback (most recent call last):\n' >&2
  printf '  File "fixture/loader.py", line 99, in parse\n' >&2
  printf 'DifferentFixtureError: input-was-reused\n' >&2
fi
exit 11
REPLAY_MUTATING
  chmod +x "$WORK/profile/replay-mutating"
  python3 -B - "$MUTATING_PATH" "$MUTATING_ID" "$WORK/profile/replay-mutating" <<'PY'
import hashlib
import json
import os
import sys

root, diagnostic_id, replay = sys.argv[1:]
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
replay_hash = sha(replay)
profile_path = os.path.join(root, "profile.json")
profile = json.load(open(profile_path, encoding="utf-8"))
for artifact in profile["source_artifacts"]:
    artifact["sha256"] = replay_hash
    artifact["size_bytes"] = os.path.getsize(replay)
for key in ["compiler", "linker", "engine", "rust"]:
    profile["toolchain"][key]["path"] = replay
    profile["toolchain"][key]["sha256"] = replay_hash
for binary in profile["binaries"]:
    binary["path"] = replay
    binary["sha256"] = replay_hash
open(profile_path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
profile_hash = sha(profile_path)
qualification_path = os.path.join(root, "qualification.json")
qualification_hash = None
if os.path.isfile(qualification_path):
    qualification = json.load(open(qualification_path, encoding="utf-8"))
    qualification["profile_sha256"] = profile_hash
    for evidence in qualification["gate_evidence"]:
        evidence["evidence_sha256"] = profile_hash
    open(qualification_path, "w", encoding="utf-8").write(json.dumps(qualification, sort_keys=True) + "\n")
    qualification_hash = sha(qualification_path)
execution_path = os.path.join(root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["profile_path"] = profile_path
execution["profile_sha256"] = profile_hash
execution["qualification_path"] = qualification_path if qualification_hash else None
execution["qualification_sha256"] = qualification_hash
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution, sort_keys=True) + "\n")
marker_path = os.path.join(root, "profiled-result.json")
marker = json.load(open(marker_path, encoding="utf-8"))
marker["profile_sha256"] = profile_hash
open(marker_path, "w", encoding="utf-8").write(json.dumps(marker, sort_keys=True) + "\n")
record_path = os.path.join(root, "diagnostic.json")
record = json.load(open(record_path, encoding="utf-8"))
record["diagnostic_id"] = diagnostic_id
record["profile_sha256"] = profile_hash
record["qualification_path"] = "qualification.json" if qualification_hash else None
record["qualification_sha256"] = qualification_hash
record["execution_sha256"] = sha(execution_path)
open(record_path, "w", encoding="utf-8").write(json.dumps(record, sort_keys=True) + "\n")
PY
  run_ok "diagnostic replay stages pristine input bytes for every attempt" \
    'result: reproduced' \
    "${BASE[@]}" replay-diagnostic "$MUTATING_ID" --attempts 2

  DIRECT_DIAGNOSTICS_BEFORE="$(find "$DATA/diagnostics" -mindepth 1 -maxdepth 1 \
    -type d -name 'diagnostic-[0-9]*' -printf '%f\n' 2>/dev/null | sort)"
  set +e
  "${BASE[@]}" --target-profile "$MUTATING_PATH/profile.json" \
    --validation-run FND04-mutating-direct \
    harness --target onnx --input "$WORK/input/model.onnx" \
    >"$WORK/mutating-direct.log" 2>&1
  MUTATING_DIRECT_RC=$?
  set -e
  DIRECT_DIAGNOSTICS_AFTER="$(find "$DATA/diagnostics" -mindepth 1 -maxdepth 1 \
    -type d -name 'diagnostic-[0-9]*' -printf '%f\n' 2>/dev/null | sort)"
  MUTATING_DIRECT_ID="$(comm -13 \
    <(printf '%s\n' "$DIRECT_DIAGNOSTICS_BEFORE") \
    <(printf '%s\n' "$DIRECT_DIAGNOSTICS_AFTER") | tail -n1)"
  if [[ "$MUTATING_DIRECT_RC" -eq 11 ]] \
    && [[ -n "$MUTATING_DIRECT_ID" ]] \
    && cmp -s "$WORK/input/model.onnx" \
      "$DATA/diagnostics/$MUTATING_DIRECT_ID/input/model.onnx"; then
    ok "direct profiled harness preserves pre-execution input bytes"
  else
    bad "direct profiled harness preserves pre-execution input bytes (rc=$MUTATING_DIRECT_RC)"
  fi

  SIGNAL_ID="diagnostic-signal"
  SIGNAL_PATH="$DATA/diagnostics/$SIGNAL_ID"
  cp -a "$DIFFERENT_PATH" "$SIGNAL_PATH"
  rm -rf "$SIGNAL_PATH/replays"
  cat >"$WORK/profile/replay-signal" <<'REPLAY_SIGNAL'
#!/usr/bin/env bash
printf 'AddressSanitizer: heap-use-after-free\n#0 parser_frame\n' >&2
kill -SEGV "$$"
REPLAY_SIGNAL
  chmod +x "$WORK/profile/replay-signal"
  python3 -B - "$SIGNAL_PATH" "$SIGNAL_ID" "$WORK/profile/replay-signal" <<'PY'
import hashlib
import json
import os
import sys

root, diagnostic_id, replay = sys.argv[1:]
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
replay_hash = sha(replay)
profile_path = os.path.join(root, "profile.json")
profile = json.load(open(profile_path, encoding="utf-8"))
for artifact in profile["source_artifacts"]:
    artifact["sha256"] = replay_hash
    artifact["size_bytes"] = os.path.getsize(replay)
for key in ["compiler", "linker", "engine", "rust"]:
    profile["toolchain"][key]["path"] = replay
    profile["toolchain"][key]["sha256"] = replay_hash
for binary in profile["binaries"]:
    binary["path"] = replay
    binary["sha256"] = replay_hash
open(profile_path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
profile_hash = sha(profile_path)
execution_path = os.path.join(root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["profile_path"] = profile_path
execution["profile_sha256"] = profile_hash
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution, sort_keys=True) + "\n")
marker_path = os.path.join(root, "profiled-result.json")
marker = json.load(open(marker_path, encoding="utf-8"))
marker["profile_sha256"] = profile_hash
open(marker_path, "w", encoding="utf-8").write(json.dumps(marker, sort_keys=True) + "\n")
record_path = os.path.join(root, "diagnostic.json")
record = json.load(open(record_path, encoding="utf-8"))
record["diagnostic_id"] = diagnostic_id
record["profile_sha256"] = profile_hash
record["execution_sha256"] = sha(execution_path)
open(record_path, "w", encoding="utf-8").write(json.dumps(record, sort_keys=True) + "\n")
PY
  mkdir -p "$DATA/triage"
  TRIAGE_COUNT_BEFORE_SIGNAL="$(find "$DATA/triage" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
  run_ok "signal replay remains incomplete and invokes the existing crash triage" \
    'result: incomplete' \
    "${BASE[@]}" replay-diagnostic "$SIGNAL_ID" --attempts 2
  TRIAGE_COUNT_AFTER_SIGNAL="$(find "$DATA/triage" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
  SIGNAL_REPLAY="$(find "$SIGNAL_PATH/replays" -maxdepth 1 -type f -name 'replay-*.json' -print 2>/dev/null | sort | tail -n1 || true)"
  if [[ "$TRIAGE_COUNT_AFTER_SIGNAL" -eq $((TRIAGE_COUNT_BEFORE_SIGNAL + 1)) ]] \
    && [[ -n "$SIGNAL_REPLAY" ]] \
    && python3 -B - "$SIGNAL_REPLAY" <<'PY'
import json, os, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
link = record["linked_triage"]
assert link["status"] == "created", link
assert os.path.isfile(link["summary_path"]), link
for observation in record["observations"]:
    assert observation["outcome"] == "library_crash", observation
    assert "signal: 11" in observation["detail"], observation
    assert "AddressSanitizer: heap-use-after-free\n#0 parser_frame" in observation["detail"], observation
PY
  then
    ok "signal replay links the generated triage evidence"
  else
    bad "signal replay links the generated triage evidence"
  fi
  if [[ -n "$SIGNAL_REPLAY" ]]; then
    cp "$SIGNAL_REPLAY" "$WORK/signal-replay.backup"
    python3 -B - "$SIGNAL_REPLAY" <<'PY'
import json
import sys

path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["linked_triage"]["unexpected_authority"] = True
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
    run_fail "linked triage rejects unknown authority fields" "unknown field" \
      "${BASE[@]}" export "$SIGNAL_ID"
    cp "$WORK/signal-replay.backup" "$SIGNAL_REPLAY"
    python3 -B - "$SIGNAL_REPLAY" <<'PY'
import json
import sys

path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["linked_triage"]["summary_path"] = "/etc/passwd"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
    run_fail "linked triage cannot name an external summary path" \
      "linked triage summary_path does not match its result-local triage ID" \
      "${BASE[@]}" export "$SIGNAL_ID"
    cp "$WORK/signal-replay.backup" "$SIGNAL_REPLAY"
    python3 -B - "$SIGNAL_REPLAY" <<'PY'
import json
import sys

path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["linked_triage"]["triage_id"] = "triage-forged"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
    run_fail "linked triage ID must match its result-local summary path" \
      "linked triage summary_path does not match its result-local triage ID" \
      "${BASE[@]}" export "$SIGNAL_ID"
    cp "$WORK/signal-replay.backup" "$SIGNAL_REPLAY"
    python3 -B - "$SIGNAL_REPLAY" "$DATA" <<'PY'
import json
import os
import sys

path, data = sys.argv[1:]
value = json.load(open(path, encoding="utf-8"))
value["linked_triage"]["triage_id"] = "triage-missing"
value["linked_triage"]["summary_path"] = os.path.join(
    data, "triage", "triage-missing", "summary.json"
)
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
    run_fail "linked triage must resolve to an existing local triage result" \
      "linked triage result does not exist" \
      "${BASE[@]}" export "$SIGNAL_ID"
    cp "$WORK/signal-replay.backup" "$SIGNAL_REPLAY"

    printf 'different-linked-triage-input\n' >"$WORK/signal-linked-other.onnx"
    SIGNAL_REPLAY_VALIDATION="$(python3 -B - "$SIGNAL_REPLAY" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))["validation_run"])
PY
)"
    set +e
    "${BASE[@]}" --target-profile "$SIGNAL_PATH/profile.json" \
      --validation-run "$SIGNAL_REPLAY_VALIDATION" \
      triage --target onnx --input "$WORK/signal-linked-other.onnx" \
      --repro-retries 2 --timeout-sec 2 >"$WORK/signal-linked-other.log" 2>&1
    SIGNAL_OTHER_RC=$?
    set -e
    SIGNAL_OTHER_SUMMARY="$(sed -n 's/^summary: //p' \
      "$WORK/signal-linked-other.log" | tail -n1)"
    if [[ "$SIGNAL_OTHER_RC" -eq 0 ]] && [[ -f "$SIGNAL_OTHER_SUMMARY" ]]; then
      python3 -B - "$SIGNAL_REPLAY" "$SIGNAL_OTHER_SUMMARY" <<'PY'
import json
import os
import sys

path, summary = sys.argv[1:]
value = json.load(open(path, encoding="utf-8"))
value["linked_triage"]["triage_id"] = os.path.basename(os.path.dirname(summary))
value["linked_triage"]["summary_path"] = summary
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
      run_fail "linked triage must match the diagnostic input evidence" \
        "linked triage input does not match its diagnostic" \
        "${BASE[@]}" export "$SIGNAL_ID"
      cp "$WORK/signal-replay.backup" "$SIGNAL_REPLAY"
    else
      bad "linked triage must match the diagnostic input evidence"
      sed -n '1,12p' "$WORK/signal-linked-other.log" | sed 's/^/       /' >&2
    fi
  else
    bad "linked triage rejects unknown authority fields"
    bad "linked triage cannot name an external summary path"
    bad "linked triage ID must match its result-local summary path"
    bad "linked triage must resolve to an existing local triage result"
    bad "linked triage must match the diagnostic input evidence"
  fi

  TAMPERED_ID="diagnostic-tampered"
  cp -a "$DIAGNOSTIC_PATH" "$DATA/diagnostics/$TAMPERED_ID"
  rm -rf "$DATA/diagnostics/$TAMPERED_ID/replays"
  python3 -B - "$DATA/diagnostics/$TAMPERED_ID" "$TAMPERED_ID" <<'PY'
import json, os, sys
root, diagnostic_id = sys.argv[1:]
record_path = os.path.join(root, "diagnostic.json")
record = json.load(open(record_path, encoding="utf-8"))
record["diagnostic_id"] = diagnostic_id
open(record_path, "w", encoding="utf-8").write(json.dumps(record) + "\n")
execution_path = os.path.join(root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
execution["elapsed_ms"] = 999
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
PY
  run_fail "diagnostic execution hash is verified before use" "execution sha256 mismatch" \
    "${BASE[@]}" show "$TAMPERED_ID"

  rm -rf "$DIAGNOSTIC_PATH/replays"
  mkdir -p "$WORK/outside-replays"
  ln -s "$WORK/outside-replays" "$DIAGNOSTIC_PATH/replays"
  run_fail "diagnostic replay never writes through a replays symlink" \
    "result contains a symlink" \
    "${BASE[@]}" replay-diagnostic "$DIAGNOSTIC_ID" --attempts 2
  rm "$DIAGNOSTIC_PATH/replays"

  cp "$DIAGNOSTIC_PATH/input/model.onnx" "$WORK/outside-input.onnx"
  rm "$DIAGNOSTIC_PATH/input/model.onnx"
  ln -s "$WORK/outside-input.onnx" "$DIAGNOSTIC_PATH/input/model.onnx"
  run_fail "diagnostic replay never reads an input symlink" "result contains a symlink" \
    "${BASE[@]}" replay-diagnostic "$DIAGNOSTIC_ID" --attempts 2
else
  bad "diagnostic show uses the same exact-ID resolver"
  bad "diagnostic replay records repeated unclassified results"
  bad "diagnostic export includes its complete evidence"
  bad "diagnostic execution hash is verified before use"
fi

mkdir -p "$DATA/triage" "$DATA/diagnostics"
TRIAGE_DIRS_BEFORE="$(find "$DATA/triage" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
DIAGNOSTICS_BEFORE_TRIAGE="$(find "$DATA/diagnostics" -mindepth 1 -maxdepth 1 -type d -name 'diagnostic-*' 2>/dev/null | wc -l)"
set +e
"${BASE[@]}" --target-profile "$WORK/profile/profile.json" --validation-run FND04-triage11 \
  triage --target onnx --input "$WORK/input/model.onnx" --repro-retries 2 --timeout-sec 2 \
  >"$WORK/triage11.log" 2>&1
TRIAGE11_RC=$?
set -e
TRIAGE_DIRS_AFTER="$(find "$DATA/triage" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
DIAGNOSTICS_AFTER_TRIAGE="$(find "$DATA/diagnostics" -mindepth 1 -maxdepth 1 -type d -name 'diagnostic-*' 2>/dev/null | wc -l)"
if [[ "$TRIAGE11_RC" -ne 0 ]] \
  && grep -Fq 'stopped at unclassified replay; diagnostic_id:' "$WORK/triage11.log" \
  && ! grep -Fq 'verdict:' "$WORK/triage11.log" \
  && [[ "$TRIAGE_DIRS_AFTER" -eq "$TRIAGE_DIRS_BEFORE" ]] \
  && [[ "$DIAGNOSTICS_AFTER_TRIAGE" -eq $((DIAGNOSTICS_BEFORE_TRIAGE + 1)) ]]; then
  ok "profiled triage preserves exit 11 without creating a crash verdict"
else
  bad "profiled triage preserves exit 11 without creating a crash verdict (rc=$TRIAGE11_RC)"
fi

mkdir -p "$WORK/corpus"
cp "$WORK/input/model.onnx" "$WORK/corpus/model.onnx"
DEFAULT_DIAGNOSTICS_BEFORE="$(find "$PROJECT_ROOT/data/diagnostics" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort || true)"
RUN_DIAGNOSTICS_BEFORE="$(find "$DATA/diagnostics" -mindepth 1 -maxdepth 1 -type d -name 'diagnostic-*' 2>/dev/null | wc -l)"
set +e
"${BASE[@]}" --target-profile "$WORK/profile/profile.json" --validation-run FND04-run11 \
  run --target onnx --backend local-harness --corpus-dir "$WORK/corpus" \
  --workers 1 --timeout-sec 2 --restart-limit 0 >"$WORK/run11.log" 2>&1
RUN11_RC=$?
set -e
DEFAULT_DIAGNOSTICS_AFTER="$(find "$PROJECT_ROOT/data/diagnostics" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort || true)"
RUN_DIAGNOSTICS_AFTER="$(find "$DATA/diagnostics" -mindepth 1 -maxdepth 1 -type d -name 'diagnostic-*' 2>/dev/null | wc -l)"
if [[ "$DEFAULT_DIAGNOSTICS_AFTER" == "$DEFAULT_DIAGNOSTICS_BEFORE" ]] \
  && [[ "$RUN_DIAGNOSTICS_AFTER" -eq $((RUN_DIAGNOSTICS_BEFORE + 1)) ]]; then
  ok "run child preserves diagnostics only below the requested data directory"
else
  bad "run child preserves diagnostics only below the requested data directory"
fi
RUN11_STATUS="$(sed -n 's/^status: //p' "$WORK/run11.log" | tail -n1)"
if [[ "$RUN11_RC" -ne 0 ]] && [[ -n "$RUN11_STATUS" ]] && python3 -B - "$RUN11_STATUS" <<'PY'
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["unclassified"] == 1
assert record["failed"] == 0
PY
then
  ok "run preserves exit 11 without auto-confirming a crash"
else
  bad "run preserves exit 11 without auto-confirming a crash"
fi
if [[ -n "$RUN11_STATUS" ]]; then
  RUN11_ID="$(basename "$(dirname "$RUN11_STATUS")")"
  run_ok "unclassified run export retains the exact triggering input" '[export] done' \
    "${BASE[@]}" export "$RUN11_ID"
  RUN11_EXPORT="$(find "$DATA/exports" -mindepth 1 -maxdepth 1 -type d -name "export-$RUN11_ID-*" 2>/dev/null | sort | tail -n1 || true)"
  RUN11_INPUT=""
  if [[ -n "$RUN11_EXPORT" ]]; then
    RUN11_INPUT="$(find "$RUN11_EXPORT/result/diagnostics" -type f -path '*/input/model.onnx' -print -quit 2>/dev/null || true)"
  fi
  if [[ -n "$RUN11_INPUT" ]] && cmp -s "$RUN11_INPUT" "$WORK/corpus/model.onnx"; then
    ok "unclassified run export preserves the triggering bytes"
  else
    bad "unclassified run export preserves the triggering bytes"
  fi

  RUN11_DIAGNOSTIC_PATH="$(find "$(dirname "$RUN11_STATUS")/diagnostics" \
    -mindepth 1 -maxdepth 1 -type d -name 'diagnostic-*' -print -quit 2>/dev/null || true)"
  if [[ -n "$RUN11_DIAGNOSTIC_PATH" ]] && [[ -f "$WORK/replay-record.backup" ]]; then
    mkdir -p "$RUN11_DIAGNOSTIC_PATH/replays"
    RUN11_FORGED_REPLAY="$RUN11_DIAGNOSTIC_PATH/replays/replay-forged-fingerprint.json"
    cp "$WORK/replay-record.backup" "$RUN11_FORGED_REPLAY"
    python3 -B - "$RUN11_FORGED_REPLAY" "$(basename "$RUN11_DIAGNOSTIC_PATH")" <<'PY'
import json
import sys

path, diagnostic_id = sys.argv[1:]
value = json.load(open(path, encoding="utf-8"))
forged = {
    "exception_type": "ForgedNestedReplayError",
    "target_frames": ["fixture/forged_nested.py::forged"],
}
value["diagnostic_id"] = diagnostic_id
value["validation_run"] += "-nested"
value["original_fingerprint"] = forged
for observation in value["observations"]:
    assert observation["outcome"] == "unclassified", observation
    observation["fingerprint"] = forged
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
    run_fail "run-attached replay fingerprints are derived from traceback evidence" \
      "fingerprint" \
      "${BASE[@]}" export "$RUN11_ID"
    rm "$RUN11_FORGED_REPLAY"
  else
    bad "run-attached replay fingerprints are derived from traceback evidence"
  fi

  if [[ -z "$SIGNAL_PATH" || ! -f "$SIGNAL_PATH/profile.json" ]]; then
    bad "unclassified run rejects a diagnostic from another profile"
  else
  WRONG_DIAGNOSTIC_RUN="$DATA/runs/run-wrong-diagnostic"
  cp -a "$(dirname "$RUN11_STATUS")" "$WRONG_DIAGNOSTIC_RUN"
  rebind_result_identity "$WRONG_DIAGNOSTIC_RUN"
  python3 -B - "$WRONG_DIAGNOSTIC_RUN" "$SIGNAL_PATH/profile.json" <<'PY'
import hashlib
import json
import os
import sys

root, replacement_profile = sys.argv[1:]
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
status_path = os.path.join(root, "status.json")
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "wrong-diagnostic"
execution_path = os.path.join(root, "execution.json")
execution = json.load(open(execution_path, encoding="utf-8"))
local_profile = os.path.join(root, "profile.json")
open(local_profile, "wb").write(open(replacement_profile, "rb").read())
execution["profile_path"] = local_profile
execution["profile_sha256"] = sha(local_profile)
status["profile_sha256"] = execution["profile_sha256"]
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
marker_path = os.path.join(root, "profiled-result.json")
marker = json.load(open(marker_path, encoding="utf-8"))
marker["profile_sha256"] = execution["profile_sha256"]
open(marker_path, "w", encoding="utf-8").write(json.dumps(marker) + "\n")
diagnostics = os.path.join(root, "diagnostics")
for diagnostic_id in os.listdir(diagnostics):
    nested = os.path.join(diagnostics, diagnostic_id)
    nested_execution_path = os.path.join(nested, "execution.json")
    nested_execution = json.load(open(nested_execution_path, encoding="utf-8"))
    nested_execution["profile_path"] = os.path.join(nested, "profile.json")
    if nested_execution.get("qualification_path"):
        nested_execution["qualification_path"] = os.path.join(nested, "qualification.json")
    open(nested_execution_path, "w", encoding="utf-8").write(json.dumps(nested_execution) + "\n")
    record_path = os.path.join(nested, "diagnostic.json")
    record = json.load(open(record_path, encoding="utf-8"))
    record["execution_sha256"] = sha(nested_execution_path)
    open(record_path, "w", encoding="utf-8").write(json.dumps(record) + "\n")
PY
  run_fail "unclassified run rejects a diagnostic from another profile" \
    "does not match the parent execution identity" \
    "${BASE[@]}" export run-wrong-diagnostic

  WRONG_INPUT_RUN="$DATA/runs/run-wrong-diagnostic-input"
  cp -a "$(dirname "$RUN11_STATUS")" "$WRONG_INPUT_RUN"
  rebind_result_identity "$WRONG_INPUT_RUN"
  python3 -B - "$WRONG_INPUT_RUN" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
sha_bytes = lambda value: hashlib.sha256(value).hexdigest()
sha_file = lambda path: sha_bytes(open(path, "rb").read())
status_path = os.path.join(root, "status.json")
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "wrong-diagnostic-input"
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
diagnostics = os.path.join(root, "diagnostics")
for diagnostic_id in os.listdir(diagnostics):
    nested = os.path.join(diagnostics, diagnostic_id)
    record_path = os.path.join(nested, "diagnostic.json")
    record = json.load(open(record_path, encoding="utf-8"))
    input_path = os.path.join(nested, *record["input_path"].split("/"))
    replacement = b"same-profile-but-different-input"
    open(input_path, "wb").write(replacement)
    input_hash = sha_bytes(replacement)
    manifest_path = os.path.join(nested, "input-manifest.json")
    manifest = json.load(open(manifest_path, encoding="utf-8"))
    manifest["files"][0]["size_bytes"] = len(replacement)
    manifest["files"][0]["sha256"] = input_hash
    with open(manifest_path, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")
    execution_path = os.path.join(nested, "execution.json")
    execution = json.load(open(execution_path, encoding="utf-8"))
    execution["profile_path"] = os.path.join(nested, "profile.json")
    if execution.get("qualification_path"):
        execution["qualification_path"] = os.path.join(nested, "qualification.json")
    execution["input_manifest_sha256"] = sha_file(manifest_path)
    open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
    record["input_sha256"] = input_hash
    record["execution_sha256"] = sha_file(execution_path)
    if "parent_result_id" in record:
        record["parent_result_id"] = "run-wrong-diagnostic-input"
    if "parent_input_sha256" in record:
        record["parent_input_sha256"] = input_hash
    open(record_path, "w", encoding="utf-8").write(json.dumps(record) + "\n")
PY
  run_fail "unclassified run binds each diagnostic to its parent input" \
    "parent input" \
    "${BASE[@]}" export run-wrong-diagnostic-input

  ZERO_COUNT_RUN="$DATA/runs/run-zero-unclassified-with-diagnostic"
  cp -a "$(dirname "$RUN11_STATUS")" "$ZERO_COUNT_RUN"
  rebind_result_identity "$ZERO_COUNT_RUN"
  python3 -B - "$ZERO_COUNT_RUN" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
status_path = os.path.join(root, "status.json")
status = json.load(open(status_path, encoding="utf-8"))
status["run_id"] = "zero-unclassified-with-diagnostic"
status["unclassified"] = 0
open(status_path, "w", encoding="utf-8").write(json.dumps(status) + "\n")
for diagnostic_id in os.listdir(os.path.join(root, "diagnostics")):
    nested = os.path.join(root, "diagnostics", diagnostic_id)
    execution_path = os.path.join(nested, "execution.json")
    execution = json.load(open(execution_path, encoding="utf-8"))
    execution["profile_path"] = os.path.join(nested, "profile.json")
    if execution.get("qualification_path"):
        execution["qualification_path"] = os.path.join(nested, "qualification.json")
    open(execution_path, "w", encoding="utf-8").write(json.dumps(execution) + "\n")
    record_path = os.path.join(nested, "diagnostic.json")
    record = json.load(open(record_path, encoding="utf-8"))
    record["execution_sha256"] = sha(execution_path)
    if "parent_result_id" in record:
        record["parent_result_id"] = "run-zero-unclassified-with-diagnostic"
    open(record_path, "w", encoding="utf-8").write(json.dumps(record) + "\n")
PY
  run_fail "run cannot hide diagnostic evidence behind a zero count" \
    "diagnostic evidence" \
    "${BASE[@]}" export run-zero-unclassified-with-diagnostic
  fi
else
  bad "unclassified run export retains the exact triggering input"
  bad "unclassified run export preserves the triggering bytes"
  bad "unclassified run rejects a diagnostic from another profile"
fi

run_ok "profiled campaign dry-run does not synthesize legacy engine overrides" \
  '"backend":"local-harness"' \
  "${BASE[@]}" --target-profile "$WORK/profile/profile.json" --validation-run FND04-campaign \
  campaign --mode serial --target onnx --duration-seconds 1 --campaign-id fnd04 \
  --backends local-harness --corpus-dir "$WORK/corpus" --workers 1 --timeout-sec 2 \
  --restart-limit 0 --dry-run
run_fail "profiled campaign refuses a backend absent from the verified profile" \
  "profile does not authorize backend 'aflpp'" \
  "${BASE[@]}" --target-profile "$WORK/profile/profile.json" --validation-run FND04-campaign-afl \
  campaign --mode serial --target onnx --duration-seconds 1 --campaign-id fnd04-afl \
  --backends aflpp --corpus-dir "$WORK/corpus" --workers 1 --timeout-sec 2 \
  --restart-limit 0 --dry-run

SUCCESS_PROFILE="$WORK/success-profile"
SUCCESS_CORPUS="$WORK/success-corpus"
cp -a "$WORK/profile" "$SUCCESS_PROFILE"
mkdir -p "$SUCCESS_CORPUS"
printf 'successful-profiled-input\n' >"$SUCCESS_CORPUS/success.onnx"
cp "$SUCCESS_CORPUS/success.onnx" "$WORK/success-expected.onnx"
cat >"$SUCCESS_PROFILE/replay" <<'SUCCESS_REPLAY'
#!/usr/bin/env bash
test -f "$1"
SUCCESS_REPLAY
chmod +x "$SUCCESS_PROFILE/replay"
python3 -B - "$SUCCESS_PROFILE" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
replay = os.path.join(root, "replay")
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
replay_hash = sha(replay)
profile_path = os.path.join(root, "profile.json")
profile = json.load(open(profile_path, encoding="utf-8"))
for artifact in profile["source_artifacts"]:
    artifact["sha256"] = replay_hash
    artifact["size_bytes"] = os.path.getsize(replay)
for key in ["compiler", "linker", "engine", "rust"]:
    profile["toolchain"][key]["path"] = replay
    profile["toolchain"][key]["sha256"] = replay_hash
for binary in profile["binaries"]:
    binary["path"] = replay
    binary["sha256"] = replay_hash
open(profile_path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
PY
set +e
"${BASE[@]}" --target-profile "$SUCCESS_PROFILE/profile.json" \
  --validation-run FND04-success-snapshot \
  run --target onnx --backend local-harness --corpus-dir "$SUCCESS_CORPUS" \
  --workers 1 --timeout-sec 2 --restart-limit 0 >"$WORK/success-run.log" 2>&1
SUCCESS_RUN_RC=$?
set -e
SUCCESS_STATUS="$(sed -n 's/^status: //p' "$WORK/success-run.log" | tail -n1)"
SUCCESS_RUN_ID=""
if [[ -n "$SUCCESS_STATUS" ]]; then
  SUCCESS_RUN_ID="$(basename "$(dirname "$SUCCESS_STATUS")")"
fi
printf 'source-mutated-after-success\n' >"$SUCCESS_CORPUS/success.onnx"
if [[ "$SUCCESS_RUN_RC" -eq 0 ]] && [[ -n "$SUCCESS_RUN_ID" ]] \
  && "${BASE[@]}" export "$SUCCESS_RUN_ID" >"$WORK/success-export.log" 2>&1 \
  && SUCCESS_EXPORT="$(find "$DATA/exports" -mindepth 1 -maxdepth 1 -type d \
       -name "export-$SUCCESS_RUN_ID-*" -print 2>/dev/null | sort | tail -n1)" \
  && [[ -n "$SUCCESS_EXPORT" ]] \
  && cmp -s "$WORK/success-expected.onnx" \
       "$SUCCESS_EXPORT/result/inputs/success.onnx"; then
  ok "successful profiled run preserves and exports its original input"
else
  bad "successful profiled run preserves and exports its original input (run_rc=$SUCCESS_RUN_RC)"
fi
if [[ -n "$SUCCESS_RUN_ID" ]]; then
  mv "$SUCCESS_PROFILE/profile.json" "$SUCCESS_PROFILE/profile.json.hidden"
  set +e
  "${BASE[@]}" export "$SUCCESS_RUN_ID" >"$WORK/snapshot-export.log" 2>&1
  SNAPSHOT_EXPORT_RC=$?
  set -e
  mv "$SUCCESS_PROFILE/profile.json.hidden" "$SUCCESS_PROFILE/profile.json"
  SNAPSHOT_EXPORT="$(find "$DATA/exports" -mindepth 1 -maxdepth 1 -type d \
    -name "export-$SUCCESS_RUN_ID-*" -print 2>/dev/null | sort | tail -n1)"
  if [[ "$SNAPSHOT_EXPORT_RC" -eq 0 ]] && [[ -n "$SNAPSHOT_EXPORT" ]] \
    && [[ -f "$DATA/runs/$SUCCESS_RUN_ID/profile.json" ]] \
    && [[ -f "$SNAPSHOT_EXPORT/result/profile.json" ]] \
    && [[ -f "$SNAPSHOT_EXPORT/identity/profile.json" ]]; then
    ok "profiled run export survives removal of the source profile path"
  else
    bad "profiled run export survives removal of the source profile path (rc=$SNAPSHOT_EXPORT_RC)"
    sed -n '1,12p' "$WORK/snapshot-export.log" | sed 's/^/       /' >&2
  fi
else
  bad "profiled run export survives removal of the source profile path"
fi

set +e
"${BASE[@]}" --target-profile "$SUCCESS_PROFILE/profile.json" \
  --validation-run FND04-triage-profile-marker \
  triage --target onnx --input "$WORK/success-expected.onnx" \
  --repro-retries 1 --timeout-sec 2 >"$WORK/profiled-triage.log" 2>&1
PROFILED_TRIAGE_RC=$?
set -e
PROFILED_TRIAGE_SUMMARY="$(sed -n 's/^summary: //p' "$WORK/profiled-triage.log" | tail -n1)"
PROFILED_TRIAGE_ID=""
if [[ -n "$PROFILED_TRIAGE_SUMMARY" ]]; then
  PROFILED_TRIAGE_ID="$(basename "$(dirname "$PROFILED_TRIAGE_SUMMARY")")"
fi
PROFILED_TRIAGE_FIELDS_RC=1
if [[ -n "$PROFILED_TRIAGE_SUMMARY" ]]; then
  set +e
  python3 -B - "$PROFILED_TRIAGE_SUMMARY" <<'PY'
import json
import sys

summary = json.load(open(sys.argv[1], encoding="utf-8"))
assert summary["profiled_result"] is True
assert len(summary["profile_sha256"]) == 64
PY
  PROFILED_TRIAGE_FIELDS_RC=$?
  set -e
fi
if [[ "$PROFILED_TRIAGE_RC" -eq 0 ]] && [[ -n "$PROFILED_TRIAGE_ID" ]] \
  && [[ "$PROFILED_TRIAGE_FIELDS_RC" -eq 0 ]] \
  && "${BASE[@]}" export "$PROFILED_TRIAGE_ID" \
    >"$WORK/profiled-triage-export.log" 2>&1; then
  ok "profiled triage keeps intrinsic profile identity and exports"
else
  bad "profiled triage keeps intrinsic profile identity and exports (rc=$PROFILED_TRIAGE_RC)"
  sed -n '1,12p' "$WORK/profiled-triage.log" | sed 's/^/       /' >&2
fi
if [[ -n "$PROFILED_TRIAGE_ID" ]]; then
  rm -f "$(dirname "$PROFILED_TRIAGE_SUMMARY")/execution.json" \
    "$(dirname "$PROFILED_TRIAGE_SUMMARY")/profiled-result.json"
  run_fail "profiled triage cannot be downgraded by deleting its sidecars" \
    "profiled result is missing execution.json" \
    "${BASE[@]}" export "$PROFILED_TRIAGE_ID"
else
  bad "profiled triage cannot be downgraded by deleting its sidecars"
fi

ENGINE_PROFILE="$WORK/engine-profile"
ENGINE_CORPUS="$WORK/engine-corpus"
cp -a "$WORK/profile" "$ENGINE_PROFILE"
mkdir -p "$ENGINE_CORPUS"
printf 'profiled-engine-input\n' >"$ENGINE_CORPUS/engine.onnx"
printf 'profiled-engine-extra\n' >"$ENGINE_CORPUS/extra.onnx"
cp "$ENGINE_CORPUS/engine.onnx" "$WORK/engine-expected.onnx"
cat >"$ENGINE_PROFILE/engine" <<'ENGINE_FIXTURE'
#!/usr/bin/env bash
set -eu
corpus_dir="$1"
artifact_dir="$2"
mkdir -p "$artifact_dir"
find "$corpus_dir" -maxdepth 1 -type f -name '*.onnx' -printf '.\n' \
  | wc -l | tr -d '[:space:]' >"$artifact_dir/input-count"
if [ -f "$corpus_dir/generated.onnx" ]; then
  cp "$corpus_dir/generated.onnx" "$artifact_dir/carried-forward.onnx"
fi
cp "$corpus_dir/engine.onnx" "$artifact_dir/observed.onnx"
printf 'engine-mutated-input\n' >"$corpus_dir/engine.onnx"
printf 'engine-generated-input\n' >"$corpus_dir/generated.onnx"
ENGINE_FIXTURE
chmod +x "$ENGINE_PROFILE/engine"
python3 -B - "$ENGINE_PROFILE" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
engine = os.path.join(root, "engine")
engine_hash = hashlib.sha256(open(engine, "rb").read()).hexdigest()
profile_path = os.path.join(root, "profile.json")
profile = json.load(open(profile_path, encoding="utf-8"))
profile["binaries"].append({
    "role": "engine-fixture",
    "path": engine,
    "sha256": engine_hash,
    "argv": ["{corpus_dir}", "{artifact_dir}"],
    "linked_libraries": [],
})
profile["engine_capabilities"].append({
    "backend": "libfuzzer",
    "binary_role": "engine-fixture",
    "required_mode": "native",
    "instrumentation_scope": "fixture",
})
open(profile_path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
PY
set +e
"${BASE[@]}" --target-profile "$ENGINE_PROFILE/profile.json" \
  --validation-run FND04-engine-working-copy \
  run --target onnx --backend libfuzzer --corpus-dir "$ENGINE_CORPUS" \
  --workers 1 --timeout-sec 2 --restart-limit 0 --max-jobs 1 \
  >"$WORK/engine-run.log" 2>&1
ENGINE_RUN_RC=$?
set -e
ENGINE_STATUS="$(sed -n 's/^status: //p' "$WORK/engine-run.log" | tail -n1)"
ENGINE_RUN_ID=""
if [[ -n "$ENGINE_STATUS" ]]; then
  ENGINE_RUN_ID="$(basename "$(dirname "$ENGINE_STATUS")")"
fi
if [[ "$ENGINE_RUN_RC" -eq 0 ]] && [[ -n "$ENGINE_RUN_ID" ]] \
  && "${BASE[@]}" export "$ENGINE_RUN_ID" >"$WORK/engine-export.log" 2>&1 \
  && ENGINE_EXPORT="$(find "$DATA/exports" -mindepth 1 -maxdepth 1 -type d \
       -name "export-$ENGINE_RUN_ID-*" -print 2>/dev/null | sort | tail -n1)" \
  && [[ -n "$ENGINE_EXPORT" ]] \
  && [[ ! -e "$DATA/runs/$ENGINE_RUN_ID/backend-artifacts/corpus" ]] \
  && ENGINE_PERSISTED="$(find "$DATA/engine-corpus" -type f \
       -name generated.onnx -print -quit 2>/dev/null)" \
  && [[ -n "$ENGINE_PERSISTED" ]] \
  && cmp -s "$WORK/engine-expected.onnx" \
       "$ENGINE_EXPORT/result/inputs/engine.onnx"; then
  ok "profiled engine mutates only a working corpus, not input evidence"
else
  bad "profiled engine mutates only a working corpus, not input evidence (run_rc=$ENGINE_RUN_RC)"
  sed -n '1,12p' "$WORK/engine-export.log" 2>/dev/null | sed 's/^/       /' >&2 || true
fi
if [[ -n "$ENGINE_STATUS" ]] \
  && [[ "$(cat "$(dirname "$ENGINE_STATUS")/backend-artifacts/w1/input-count" 2>/dev/null)" = 1 ]]; then
  ok "profiled engine honors max-jobs when selecting its execution corpus"
else
  bad "profiled engine honors max-jobs when selecting its execution corpus"
fi

ENGINE_SELECTION_PROFILE="$WORK/engine-selection-profile"
ENGINE_SELECTION_CORPUS="$WORK/engine-selection-corpus"
cp -a "$ENGINE_PROFILE" "$ENGINE_SELECTION_PROFILE"
mkdir -p "$ENGINE_SELECTION_CORPUS"
printf 'ok\n' >"$ENGINE_SELECTION_CORPUS/a-valid.onnx"
printf 'this-input-is-over-the-profile-limit\n' \
  >"$ENGINE_SELECTION_CORPUS/z-oversized.onnx"
cat >"$ENGINE_SELECTION_PROFILE/engine-selection" <<'ENGINE_SELECTION'
#!/usr/bin/env bash
set -eu
corpus_dir="$1"
artifact_dir="$2"
mkdir -p "$artifact_dir"
find "$corpus_dir" -maxdepth 1 -type f -name '*.onnx' -printf '%f\n' \
  | sort >"$artifact_dir/selected-inputs"
printf 'reached\n' >"$artifact_dir/engine-reached"
ENGINE_SELECTION
chmod +x "$ENGINE_SELECTION_PROFILE/engine-selection"
python3 -B - "$ENGINE_SELECTION_PROFILE" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
engine = os.path.join(root, "engine-selection")
path = os.path.join(root, "profile.json")
profile = json.load(open(path, encoding="utf-8"))
profile["limits"]["max_input_bytes"] = 8
for binary in profile["binaries"]:
    if binary["role"] == "engine-fixture":
        binary["path"] = engine
        binary["sha256"] = hashlib.sha256(open(engine, "rb").read()).hexdigest()
open(path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
PY
set +e
"${BASE[@]}" --target-profile "$ENGINE_SELECTION_PROFILE/profile.json" \
  --validation-run FND04-engine-select-before-validate \
  run --target onnx --backend libfuzzer --corpus-dir "$ENGINE_SELECTION_CORPUS" \
  --workers 1 --timeout-sec 2 --restart-limit 0 --max-jobs 1 \
  >"$WORK/engine-selection.log" 2>&1
ENGINE_SELECTION_RC=$?
set -e
ENGINE_SELECTION_STATUS="$(sed -n 's/^status: //p' \
  "$WORK/engine-selection.log" | tail -n1)"
if [[ "$ENGINE_SELECTION_RC" -eq 0 ]] && [[ -n "$ENGINE_SELECTION_STATUS" ]] \
  && [[ -f "$(dirname "$ENGINE_SELECTION_STATUS")/backend-artifacts/w1/engine-reached" ]] \
  && [[ "$(cat "$(dirname "$ENGINE_SELECTION_STATUS")/backend-artifacts/w1/selected-inputs")" = a-valid.onnx ]]; then
  ok "profiled engine applies max-jobs before validating excluded inputs"
else
  bad "profiled engine applies max-jobs before validating excluded inputs (rc=$ENGINE_SELECTION_RC)"
  sed -n '1,12p' "$WORK/engine-selection.log" | sed 's/^/       /' >&2
fi

set +e
"${BASE[@]}" --target-profile "$ENGINE_PROFILE/profile.json" \
  --validation-run FND04-engine-corpus-reuse \
  run --target onnx --backend libfuzzer --corpus-dir "$ENGINE_CORPUS" \
  --workers 1 --timeout-sec 2 --restart-limit 0 >"$WORK/engine-reuse.log" 2>&1
ENGINE_REUSE_RC=$?
set -e
ENGINE_REUSE_STATUS="$(sed -n 's/^status: //p' "$WORK/engine-reuse.log" | tail -n1)"
if [[ "$ENGINE_REUSE_RC" -eq 0 ]] && [[ -n "$ENGINE_REUSE_STATUS" ]] \
  && [[ -f "$(dirname "$ENGINE_REUSE_STATUS")/backend-artifacts/w1/carried-forward.onnx" ]]; then
  ok "profiled engine carries generated corpus inputs into the next run"
else
  bad "profiled engine carries generated corpus inputs into the next run (rc=$ENGINE_REUSE_RC)"
  sed -n '1,12p' "$WORK/engine-reuse.log" | sed 's/^/       /' >&2
fi

ENGINE_LIMIT_PROFILE="$WORK/engine-limit-profile"
ENGINE_LIMIT_CORPUS="$WORK/engine-limit-corpus"
cp -a "$ENGINE_PROFILE" "$ENGINE_LIMIT_PROFILE"
mkdir -p "$ENGINE_LIMIT_CORPUS"
printf 'too-large\n' >"$ENGINE_LIMIT_CORPUS/engine.onnx"
python3 -B - "$ENGINE_LIMIT_PROFILE/profile.json" <<'PY'
import json
import sys

path = sys.argv[1]
profile = json.load(open(path, encoding="utf-8"))
profile["limits"]["max_input_bytes"] = 4
open(path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
PY
run_fail "profiled engine enforces profile max_input_bytes before launch" \
  "exceeds max_input_bytes 4" \
  "${BASE[@]}" --target-profile "$ENGINE_LIMIT_PROFILE/profile.json" \
  --validation-run FND04-engine-input-limit \
  run --target onnx --backend libfuzzer --corpus-dir "$ENGINE_LIMIT_CORPUS" \
  --workers 1 --timeout-sec 2 --restart-limit 0

ENGINE_EXT_PROFILE="$WORK/engine-extension-profile"
cp -a "$ENGINE_PROFILE" "$ENGINE_EXT_PROFILE"
python3 -B - "$ENGINE_EXT_PROFILE/profile.json" <<'PY'
import json
import sys

path = sys.argv[1]
profile = json.load(open(path, encoding="utf-8"))
profile["input_kind"]["extensions"] = ["ort"]
open(path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
PY
run_fail "profiled engine enforces the profile extension allowlist before launch" \
  "extension 'onnx' is not allowed" \
  "${BASE[@]}" --target-profile "$ENGINE_EXT_PROFILE/profile.json" \
  --validation-run FND04-engine-extension-limit \
  run --target onnx --backend libfuzzer --corpus-dir "$ENGINE_CORPUS" \
  --workers 1 --timeout-sec 2 --restart-limit 0 --max-jobs 1

ENGINE_TIMEOUT_PROFILE="$WORK/engine-timeout-profile"
ENGINE_TIMEOUT_CORPUS="$WORK/engine-timeout-corpus"
cp -a "$ENGINE_PROFILE" "$ENGINE_TIMEOUT_PROFILE"
mkdir -p "$ENGINE_TIMEOUT_CORPUS"
printf 'timeout-input\n' >"$ENGINE_TIMEOUT_CORPUS/engine.onnx"
cat >"$ENGINE_TIMEOUT_PROFILE/engine-timeout" <<'ENGINE_TIMEOUT'
#!/usr/bin/env bash
sleep 4
ENGINE_TIMEOUT
chmod +x "$ENGINE_TIMEOUT_PROFILE/engine-timeout"
python3 -B - "$ENGINE_TIMEOUT_PROFILE" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
program = os.path.join(root, "engine-timeout")
program_hash = hashlib.sha256(open(program, "rb").read()).hexdigest()
path = os.path.join(root, "profile.json")
profile = json.load(open(path, encoding="utf-8"))
profile["limits"]["input_timeout_ms"] = 1000
profile["limits"]["block_timeout_ms"] = 1000
for binary in profile["binaries"]:
    if binary["role"] == "engine-fixture":
        binary["path"] = program
        binary["sha256"] = program_hash
        binary["argv"] = ["{run_dir}"]
open(path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
PY
ENGINE_TIMEOUT_START="$(date +%s)"
set +e
"${BASE[@]}" --target-profile "$ENGINE_TIMEOUT_PROFILE/profile.json" \
  --validation-run FND04-engine-block-timeout \
  run --target onnx --backend libfuzzer --corpus-dir "$ENGINE_TIMEOUT_CORPUS" \
  --workers 1 --timeout-sec 1 --restart-limit 0 \
  >"$WORK/engine-timeout.log" 2>&1
ENGINE_TIMEOUT_RC=$?
set -e
ENGINE_TIMEOUT_ELAPSED=$(( $(date +%s) - ENGINE_TIMEOUT_START ))
if [[ "$ENGINE_TIMEOUT_RC" -ne 0 ]] && [[ "$ENGINE_TIMEOUT_ELAPSED" -lt 4 ]] \
  && grep -Fq 'timeout=1' "$WORK/engine-timeout.log"; then
  ok "profiled engine enforces block_timeout_ms"
else
  bad "profiled engine enforces block_timeout_ms (rc=$ENGINE_TIMEOUT_RC elapsed=$ENGINE_TIMEOUT_ELAPSED)"
  sed -n '1,12p' "$WORK/engine-timeout.log" | sed 's/^/       /' >&2
fi

ENGINE_DRIFT_PROFILE="$WORK/engine-drift-profile"
ENGINE_DRIFT_CORPUS="$WORK/engine-drift-corpus"
cp -a "$ENGINE_PROFILE" "$ENGINE_DRIFT_PROFILE"
mkdir -p "$ENGINE_DRIFT_CORPUS"
printf 'drift-input\n' >"$ENGINE_DRIFT_CORPUS/engine.onnx"
cat >"$ENGINE_DRIFT_PROFILE/engine-drift" <<'ENGINE_DRIFT'
#!/usr/bin/env bash
set -eu
corpus_dir="$1"
script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
printf 'must-not-persist\n' >"$corpus_dir/tainted.onnx"
printf '\n' >>"$script_dir/profile.json"
ENGINE_DRIFT
chmod +x "$ENGINE_DRIFT_PROFILE/engine-drift"
python3 -B - "$ENGINE_DRIFT_PROFILE" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
program = os.path.join(root, "engine-drift")
program_hash = hashlib.sha256(open(program, "rb").read()).hexdigest()
path = os.path.join(root, "profile.json")
profile = json.load(open(path, encoding="utf-8"))
for binary in profile["binaries"]:
    if binary["role"] == "engine-fixture":
        binary["path"] = program
        binary["sha256"] = program_hash
        binary["argv"] = ["{corpus_dir}"]
open(path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
PY
set +e
"${BASE[@]}" --target-profile "$ENGINE_DRIFT_PROFILE/profile.json" \
  --validation-run FND04-engine-identity-drift \
  run --target onnx --backend libfuzzer --corpus-dir "$ENGINE_DRIFT_CORPUS" \
  --workers 1 --timeout-sec 2 --restart-limit 0 \
  >"$WORK/engine-drift.log" 2>&1
ENGINE_DRIFT_RC=$?
set -e
ENGINE_TAINTED="$(find "$DATA/engine-corpus" -type f -name tainted.onnx -print -quit 2>/dev/null || true)"
if [[ "$ENGINE_DRIFT_RC" -ne 0 ]] && [[ -z "$ENGINE_TAINTED" ]] \
  && grep -Fq 'changed after loading' "$WORK/engine-drift.log"; then
  ok "profile identity drift cannot contaminate the persistent engine corpus"
else
  bad "profile identity drift cannot contaminate the persistent engine corpus (rc=$ENGINE_DRIFT_RC tainted=${ENGINE_TAINTED:-none})"
  sed -n '1,12p' "$WORK/engine-drift.log" | sed 's/^/       /' >&2
fi

RACE_PROFILE="$WORK/race-profile"
RACE_READY="$RACE_PROFILE/race-ready"
cp -a "$WORK/profile" "$RACE_PROFILE"
cat >"$RACE_PROFILE/replay" <<'RACE_REPLAY'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
printf 'ready\n' >"$SCRIPT_DIR/race-ready"
sleep 1
exit 1
RACE_REPLAY
chmod +x "$RACE_PROFILE/replay"
python3 -B - "$RACE_PROFILE" <<'PY'
import hashlib
import json
import os
import sys

root = sys.argv[1]
replay = os.path.join(root, "replay")
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
replay_hash = sha(replay)
profile_path = os.path.join(root, "profile.json")
profile = json.load(open(profile_path, encoding="utf-8"))
for artifact in profile["source_artifacts"]:
    artifact["sha256"] = replay_hash
    artifact["size_bytes"] = os.path.getsize(replay)
for key in ["compiler", "linker", "engine", "rust"]:
    profile["toolchain"][key]["path"] = replay
    profile["toolchain"][key]["sha256"] = replay_hash
for binary in profile["binaries"]:
    binary["path"] = replay
    binary["sha256"] = replay_hash
open(profile_path, "w", encoding="utf-8").write(json.dumps(profile, sort_keys=True) + "\n")
profile_hash = sha(profile_path)
qualification_path = os.path.join(root, "qualification.json")
qualification = json.load(open(qualification_path, encoding="utf-8"))
qualification["profile_sha256"] = profile_hash
for evidence in qualification["gate_evidence"]:
    evidence["evidence_sha256"] = profile_hash
open(qualification_path, "w", encoding="utf-8").write(
    json.dumps(qualification, sort_keys=True) + "\n"
)
PY
RACE_DATA="$WORK/race-data"
RACE_SEEDS="$WORK/race-seeds"
RACE_CORPUS="$WORK/race-corpus"
mkdir -p "$RACE_DATA" "$RACE_SEEDS/onnx" "$RACE_CORPUS"
printf 'bytes-seen-by-harness' >"$RACE_CORPUS/race.onnx"
printf 'bytes-seen-by-harness' >"$WORK/race-expected"
set +e
"$TOOL_BIN" --data-dir "$RACE_DATA" --seeds-dir "$RACE_SEEDS" \
  --target-profile "$RACE_PROFILE/profile.json" --validation-run FND04-input-snapshot \
  run --target onnx --backend local-harness --corpus-dir "$RACE_CORPUS" \
  --workers 1 --timeout-sec 3 --restart-limit 0 >"$WORK/race-run.log" 2>&1 &
RACE_PID=$!
set -e
for _ in $(seq 1 50); do
  [[ -f "$RACE_READY" ]] && break
  kill -0 "$RACE_PID" 2>/dev/null || break
  sleep 0.1
done
if [[ -f "$RACE_READY" ]]; then
  printf 'bytes-written-after-harness-started' >"$RACE_CORPUS/race.onnx"
fi
set +e
wait "$RACE_PID"
RACE_RC=$?
set -e
RACE_STATUS="$(sed -n 's/^status: //p' "$WORK/race-run.log" | tail -n1)"
RACE_SAVED=""
if [[ -n "$RACE_STATUS" ]]; then
  RACE_SAVED="$(find "$(dirname "$RACE_STATUS")/crash-inputs" -maxdepth 1 -type f \
    -name '*race.onnx' -print -quit 2>/dev/null || true)"
fi
if [[ "$RACE_RC" -eq 0 ]] && [[ -n "$RACE_SAVED" ]] \
  && cmp -s "$RACE_SAVED" "$WORK/race-expected"; then
  ok "profiled crash evidence preserves the exact bytes observed by the harness"
else
  bad "profiled crash evidence preserves the exact bytes observed by the harness (rc=$RACE_RC)"
fi

rm "$WORK/profile/replay"
run_ok "show uses result-local profile evidence after the runtime is removed" \
  '"kind":"run"' "${BASE[@]}" show run-profiled
run_ok "export uses result-local profile evidence after the runtime is removed" \
  '[export] done' "${BASE[@]}" export run-profiled
if [[ -n "$SIGNAL_PATH" ]] && [[ -n "${SIGNAL_ID:-}" ]]; then
  rm "$WORK/profile/replay-signal"
  run_ok "diagnostic export remains readable after its replay runtime is removed" \
    '[export] done' "${BASE[@]}" export "$SIGNAL_ID"
  run_fail "diagnostic replay still verifies runtime files immediately before execution" \
    "not a readable regular file" \
    "${BASE[@]}" replay-diagnostic "$SIGNAL_ID" --attempts 2
else
  bad "diagnostic export remains readable after its replay runtime is removed"
  bad "diagnostic replay still verifies runtime files immediately before execution"
fi

printf '[format-dispatch] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
