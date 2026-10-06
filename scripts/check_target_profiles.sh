#!/usr/bin/env bash
# FND-01 black-box contract for typed target profiles and isolated execution contexts.
# Writes only below a private mktemp directory.
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/target-profiles-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

if [[ ! -x "$TOOL_BIN" ]]; then
  printf '[target-profiles] fail: tool binary not executable: %s\n' "$TOOL_BIN" >&2
  printf '[target-profiles] build it with `cargo build` or point TOOL_BIN at one; this gate cannot run\n' >&2
  exit 1
fi

mkdir -p "$WORK/data" "$WORK/seeds" "$WORK/input"
printf 'fixture' >"$WORK/input/model.onnx"

make_profile() { # make_profile <dir> <label> <qualification: yes|no|cycle>
  local dir="$1" label="$2" qualification="$3"
  mkdir -p "$dir"
  cat >"$dir/replay" <<'REPLAY'
#!/usr/bin/env bash
printf 'PROFILE_NAME=%s\n' "${RUST_BACKTRACE:-missing}"
printf 'REPLAY_INPUT=%s\n' "${2:-missing}"
exit 0
REPLAY
  chmod +x "$dir/replay"
  python3 -B - "$dir" "$label" "$qualification" <<'PY'
import hashlib
import json
import os
import sys

root, label, qualification = sys.argv[1:]
binary = os.path.join(root, "replay")
with open(binary, "rb") as fh:
    binary_hash = hashlib.sha256(fh.read()).hexdigest()
profile = {
    "schema_version": "1",
    "target_id": "onnx",
    "format_revision": "onnx-ir-v10",
    "loader_id": "onnxruntime",
    "loader_version": label,
    "source_artifacts": [{
        "url": "https://github.com/microsoft/onnxruntime/archive/refs/tags/v1.23.2.tar.gz",
        "tag": "v1.23.2",
        "resolved_commit": "0123456789abcdef0123456789abcdef01234567",
        "sha256": binary_hash,
        "size_bytes": os.path.getsize(binary),
    }],
    "patches": [],
    "toolchain": {
        "compiler": {"version": "1", "path": binary, "sha256": binary_hash},
        "linker": {"version": "1", "path": binary, "sha256": binary_hash},
        "engine": {"version": "1", "path": binary, "sha256": binary_hash},
        "python": None,
        "rust": {"version": "1", "path": binary, "sha256": binary_hash},
        "environment": {"PATH": "/usr/bin:/bin", "RUST_BACKTRACE": label},
    },
    "sanitizer_policy": {
        "compile_flags": ["-fsanitize=address"],
        "recovery": "abort",
        "runtime_env": {"ASAN_OPTIONS": "abort_on_error=1"},
        "rust_panic": "abort",
    },
    "binaries": [{
        "role": "replay",
        "path": binary,
        "sha256": binary_hash,
        "argv": ["--profiled", "{input}"],
        "linked_libraries": [],
    }],
    "input_kind": {"kind": "single", "extensions": ["onnx"], "subformats": []},
    "depth": "session",
    "engine_capabilities": [{
        "backend": "local-harness",
        "binary_role": "replay",
        "required_mode": "native",
        "instrumentation_scope": "onnxruntime",
    }],
    "limits": {
        "max_input_bytes": 1048576,
        "memory_bytes": 1073741824,
        "input_timeout_ms": 5000,
        "block_timeout_ms": 30000,
        "threads": 1,
        "workers": 2,
    },
    "coverage_scope": {
        "unit": "source-line",
        "include_sources": ["onnxruntime/core"],
        "exclude_sources": [],
    },
}
profile_path = os.path.join(root, "profile.json")
with open(profile_path, "w", encoding="utf-8") as fh:
    json.dump(profile, fh, indent=2, sort_keys=True)
    fh.write("\n")
with open(profile_path, "rb") as fh:
    profile_hash = hashlib.sha256(fh.read()).hexdigest()
if qualification != "no":
    record = {
        "schema_version": "1",
        "profile_sha256": profile_hash,
        "status": "verified",
        "gate_evidence": [
            {"requirement_id": f"Q{number:02}", "evidence_sha256": profile_hash}
            for number in range(1, 13)
        ],
    }
    if qualification == "cycle":
        record["qualification_sha256"] = "b" * 64
    with open(os.path.join(root, "qualification.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
        fh.write("\n")
PY
}

make_profile "$WORK/a" profile-a yes
make_profile "$WORK/b" profile-b yes
make_profile "$WORK/unqualified" profile-unqualified no
make_profile "$WORK/cycle" profile-cycle cycle
make_profile "$WORK/changed" profile-changed no

BASE=("$TOOL_BIN" --data-dir "$WORK/data" --seeds-dir "$WORK/seeds")
INPUT="$WORK/input/model.onnx"

run_ok() { # run_ok <label> <needle> <command...>
  local label="$1" needle="$2" log="$WORK/${PASS}-${FAIL}.log"
  shift 2
  if env -u RUST_BACKTRACE -u ASAN_OPTIONS "$@" >"$log" 2>&1 && grep -Fq -- "$needle" "$log"; then
    ok "$label"
  else
    bad "$label"
    sed -n '1,8p' "$log" | sed 's/^/       /'
  fi
}

run_fail() { # run_fail <label> <needle> <command...>
  local label="$1" needle="$2" log="$WORK/${PASS}-${FAIL}.log" rc=0
  shift 2
  env -u RUST_BACKTRACE -u ASAN_OPTIONS "$@" >"$log" 2>&1 || rc=$?
  if [[ "$rc" -ne 0 ]] && grep -Fq -- "$needle" "$log"; then
    ok "$label"
  else
    bad "$label (rc=$rc, expected text: $needle)"
    sed -n '1,8p' "$log" | sed 's/^/       /'
  fi
}

run_ok "qualified general execution" "PROFILE_NAME=profile-a" \
  "${BASE[@]}" --target-profile "$WORK/a/profile.json" \
  harness --target onnx --input "$INPUT"
run_ok "explicit unqualified validation execution" "PROFILE_NAME=profile-unqualified" \
  "${BASE[@]}" --target-profile "$WORK/unqualified/profile.json" --validation-run FND01-gate \
  harness --target onnx --input "$INPUT"
run_fail "unqualified general execution is refused" "qualification" \
  "${BASE[@]}" --target-profile "$WORK/unqualified/profile.json" \
  harness --target onnx --input "$INPUT"

python3 -B - "$WORK/a/profile.json" "$WORK/duplicate.json" "$WORK/schema.json" \
  "$WORK/empty-hash.json" "$WORK/target-mismatch.json" <<'PY'
import json
import sys

source, duplicate, schema, empty_hash, mismatch = sys.argv[1:]
text = open(source, encoding="utf-8").read()
open(duplicate, "w", encoding="utf-8").write(text.replace('"schema_version": "1"', '"schema_version": "1",\n  "schema_version": "1"', 1))
value = json.loads(text)
for path, mutate in [
    (schema, lambda v: v.__setitem__("schema_version", "2")),
    (empty_hash, lambda v: v["binaries"][0].__setitem__("sha256", "")),
    (mismatch, lambda v: v.__setitem__("target_id", "gguf")),
]:
    copy = json.loads(text)
    mutate(copy)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(copy, fh)
PY

for case in "duplicate.json:duplicate key" "schema.json:unsupported schema_version" \
            "empty-hash.json:binaries[0].sha256" "target-mismatch.json:target mismatch"; do
  file="${case%%:*}"; needle="${case#*:}"
  run_fail "$file is refused" "$needle" \
    "${BASE[@]}" --target-profile "$WORK/$file" --validation-run FND01-negative \
    harness --target onnx --input "$INPUT"
done

printf '\nchanged\n' >>"$WORK/changed/replay"
run_fail "changed binary is refused before execution" "sha256 mismatch" \
  "${BASE[@]}" --target-profile "$WORK/changed/profile.json" --validation-run FND01-changed \
  harness --target onnx --input "$INPUT"
run_fail "CLI and environment profile conflict is refused" "CLI/environment profile conflict" \
  env TOOL_TARGET_PROFILE="$WORK/b/profile.json" \
  "${BASE[@]}" --target-profile "$WORK/a/profile.json" --validation-run FND01-conflict \
  harness --target onnx --input "$INPUT"
run_fail "validation execution rejects inherited qualification state" "cannot inherit qualification" \
  env TOOL_PROFILE_QUALIFICATION="$WORK/a/qualification.json" \
  "${BASE[@]}" --target-profile "$WORK/a/profile.json" --validation-run FND01-mixed-auth \
  harness --target onnx --input "$INPUT"
run_fail "qualified child rejects a forged qualification hash" \
  "TOOL_PROFILE_QUALIFICATION_SHA256 mismatch" \
  env TOOL_PROFILE_QUALIFICATION="$WORK/a/qualification.json" \
      TOOL_PROFILE_QUALIFICATION_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  "${BASE[@]}" --target-profile "$WORK/a/profile.json" \
  harness --target onnx --input "$INPUT"
run_fail "legacy command pollution is refused" "legacy environment override" \
  env TOOL_ONNX_HARNESS_CMD=/tmp/untrusted \
  "${BASE[@]}" --target-profile "$WORK/a/profile.json" --validation-run FND01-legacy \
  harness --target onnx --input "$INPUT"
run_fail "qualification self-hash cycle is refused" "unknown field" \
  "${BASE[@]}" --target-profile "$WORK/cycle/profile.json" \
  harness --target onnx --input "$INPUT"

env -u RUST_BACKTRACE -u ASAN_OPTIONS \
  "${BASE[@]}" --target-profile "$WORK/a/profile.json" --validation-run FND01-parallel-a \
  harness --target onnx --input "$INPUT" >"$WORK/parallel-a.log" 2>&1 &
pid_a=$!
env -u RUST_BACKTRACE -u ASAN_OPTIONS \
  "${BASE[@]}" --target-profile "$WORK/b/profile.json" --validation-run FND01-parallel-b \
  harness --target onnx --input "$INPUT" >"$WORK/parallel-b.log" 2>&1 &
pid_b=$!
parallel_rc=0
wait "$pid_a" || parallel_rc=1
wait "$pid_b" || parallel_rc=1
if [[ "$parallel_rc" -eq 0 ]] \
   && grep -Fq 'PROFILE_NAME=profile-a' "$WORK/parallel-a.log" \
   && ! grep -Fq 'PROFILE_NAME=profile-b' "$WORK/parallel-a.log" \
   && grep -Fq 'PROFILE_NAME=profile-b' "$WORK/parallel-b.log" \
   && ! grep -Fq 'PROFILE_NAME=profile-a' "$WORK/parallel-b.log"; then
  ok "parallel profiles keep isolated child environments"
else
  bad "parallel profiles keep isolated child environments"
fi

run_ok "profiled triage terminates without child recursion" "verdict: not_reproduced" \
  "${BASE[@]}" --target-profile "$WORK/a/profile.json" --validation-run FND01-triage \
  triage --target onnx --input "$INPUT" --repro-retries 1 --timeout-sec 2

mkdir -p "$WORK/corpus"
cp "$INPUT" "$WORK/corpus/model.onnx"
run_ok "profiled local run uses the isolated harness child" "success: 1" \
  "${BASE[@]}" --target-profile "$WORK/a/profile.json" --validation-run FND01-run \
  run --target onnx --backend local-harness --corpus-dir "$WORK/corpus" \
  --workers 1 --timeout-sec 2 --restart-limit 0
record="$(find "$WORK/data/runs" -mindepth 2 -maxdepth 2 -name execution.json -type f | sort | tail -n1)"
if [[ -n "$record" ]] && python3 -B - "$record" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["authorization"] == "unqualified_validation"
assert record["backend"] == "local-harness"
assert record["outcome"] == "success"
assert len(record["profile_sha256"]) == 64
assert len(record["corpus_snapshot_sha256"]) == 64
assert record["profile_unchanged_after_execution"] is True
PY
then
  ok "profiled run writes a stable execution sidecar"
else
  bad "profiled run writes a stable execution sidecar"
fi

printf '[target-profiles] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
