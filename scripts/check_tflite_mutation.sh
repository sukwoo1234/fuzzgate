#!/usr/bin/env bash
set -u

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TARGET_ROOT="${TFLITE_TARGET_ROOT:-$PROJECT_ROOT/data/targets/tflite/v2.20.0}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
GENERATOR="${TFLITE_GENERATOR:-$PROJECT_ROOT/scripts/gen_tflite_fixtures.py}"
REPLAY="${TFLITE_REPLAY:-$PROJECT_ROOT/harnesses/tflite/tflite_loader_replay}"
MUTATOR="${TFLITE_MUTATOR:-$PROJECT_ROOT/harnesses/tflite/tflite_structural_mutator}"
FLATC="${TFLITE_FLATC:-$TARGET_ROOT/build/cmake/flatbuffers-flatc/bin/flatc}"
SOURCE_ROOT="${TFLITE_SOURCE_DIR:-$TARGET_ROOT/build/source}"
IDENTITY="${TFLITE_BUILD_IDENTITY:-$TARGET_ROOT/build-identity.json}"

if [[ ! -x "$TOOL_BIN" ]]; then
  printf '[tflite-mutation] refusal: tool binary is not executable: %s; this gate cannot run\n' \
    "$TOOL_BIN" >&2
  exit 1
fi

PASS=0
FAIL=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tool-tflite-mutation-check.XXXXXX")" || exit 2
trap 'rm -rf -- "$WORK"' EXIT

ok() {
  PASS=$((PASS + 1))
  printf '[tflite-mutation] ok: %s\n' "$1"
}

bad() {
  FAIL=$((FAIL + 1))
  printf '[tflite-mutation] fail: %s\n' "$1" >&2
}

run_capture() {
  local log="$1"
  shift
  "$@" >"$log" 2>&1
}

ready=1
for pair in \
  "tool:$TOOL_BIN" \
  "generator:$GENERATOR" \
  "replay:$REPLAY" \
  "flatc:$FLATC" \
  "build identity:$IDENTITY"
do
  label="${pair%%:*}"
  path="${pair#*:}"
  if [[ ! -f "$path" ]]; then
    bad "$label is not a regular file: $path"
    ready=0
  fi
done
if [[ "$ready" -eq 1 ]]; then
  "$GENERATOR" --source-root "$SOURCE_ROOT" --flatc "$FLATC" \
    --build-identity "$IDENTITY" --output "$WORK/fixtures" \
    >"$WORK/generator.log" 2>&1
  generator_rc=$?
  if [[ "$generator_rc" -ne 0 ]]; then
    bad "fixture generator failed (rc=$generator_rc)"
    sed -n '1,30p' "$WORK/generator.log" >&2
    ready=0
  fi
fi

run_capture "$WORK/target-spec.log" "$TOOL_BIN" target-spec --target tflite --format shell
target_spec_rc=$?
if [[ "$target_spec_rc" -eq 0 ]] \
    && grep -Fqx 'mutation_supported=1' "$WORK/target-spec.log"; then
  ok "target registry exposes TFLite structural mutation"
else
  bad "target registry does not expose TFLite structural mutation (rc=$target_spec_rc)"
fi

if [[ -x "$MUTATOR" && -f "$IDENTITY" ]] && python3 -B - "$IDENTITY" "$MUTATOR" <<'PY'
import hashlib
import json
import pathlib
import sys

identity_path, mutator_path = map(pathlib.Path, sys.argv[1:])
identity = json.loads(identity_path.read_text(encoding="utf-8"))
digest = hashlib.sha256(mutator_path.read_bytes()).hexdigest()
if identity.get("structural_mutator_sha256") != digest:
    raise SystemExit("mutator sha256 does not match build identity")
if identity.get("structural_mutator_path") != str(mutator_path):
    raise SystemExit("mutator path does not match build identity")
PY
then
  ok "native schema mutator is pinned by build identity"
else
  bad "native schema mutator is missing or not pinned by build identity"
fi

if [[ "$ready" -eq 1 && -x "$MUTATOR" ]]; then
  printf '%s\n' \
    '{' \
    '  "version": 3,' \
    '  "operator_codes": [{"builtin_code": "ADD", "version": 1}],' \
    '  "subgraphs": [{' \
    '    "tensors": [' \
    '      {"shape": [1], "type": "FLOAT32", "buffer": 0, "name": "input"},' \
    '      {"shape": [2147483647], "type": "FLOAT32", "buffer": 1, "name": "weight"},' \
    '      {"shape": [1], "type": "FLOAT32", "buffer": 0, "name": "output"}' \
    '    ],' \
    '    "inputs": [0], "outputs": [2],' \
    '    "operators": [{' \
    '      "opcode_index": 0, "inputs": [0, 1], "outputs": [2],' \
    '      "builtin_options_type": "AddOptions",' \
    '      "builtin_options": {"fused_activation_function": "NONE"}' \
    '    }],' \
    '    "name": "max_shape"' \
    '  }],' \
    '  "description": "signed shape boundary fixture",' \
    '  "buffers": [{}, {"data": [0, 0, 192, 63]}]' \
    '}' >"$WORK/max_shape.json"
  "$FLATC" --binary --strict-json --filename-ext tflite \
    -o "$WORK" "$SOURCE_ROOT/tensorflow/compiler/mlir/lite/schema/schema.fbs" \
    "$WORK/max_shape.json" >"$WORK/max-shape-flatc.log" 2>&1
  max_flatc_rc=$?
  run_capture "$WORK/max-shape-mutation.log" "$MUTATOR" \
    --input "$WORK/max_shape.tflite" --output "$WORK/max-shape-mutated.tflite" \
    --operator tensor_shape_reject --seed 0
  max_mutation_rc=$?
  if [[ "$max_flatc_rc" -eq 0 && "$max_mutation_rc" -eq 0 \
        && -s "$WORK/max-shape-mutated.tflite" ]] \
      && grep -Fq 'before=shape=2147483647;buffer_bytes=4 after=shape=-2;buffer_bytes=4' \
        "$WORK/max-shape-mutation.log"; then
    ok "shape rejection handles the signed int32 boundary without overflow"
  else
    bad "shape rejection did not handle the signed int32 boundary safely"
    sed -n '1,20p' "$WORK/max-shape-flatc.log" >&2
    sed -n '1,20p' "$WORK/max-shape-mutation.log" >&2
  fi
else
  bad "signed shape boundary behavior did not run because TFLite prerequisites are unavailable"
fi

validate_manifest() {
  local manifest="$1"
  local output="$2"
  local operator="$3"
  local mode="$4"
  local field="$5"
  local expected_loader="$6"
  local parse_preserving="$7"
  python3 -B - "$manifest" "$output" "$operator" "$mode" "$field" \
    "$expected_loader" "$parse_preserving" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest_path, output_path = map(pathlib.Path, sys.argv[1:3])
operator, mode, field, expected_loader, parse_preserving = sys.argv[3:]
document = json.loads(manifest_path.read_text(encoding="utf-8"))
if document.get("target") != "tflite" or document.get("generated") != 1:
    raise SystemExit("manifest target/generated mismatch")
entries = document.get("entries")
if not isinstance(entries, list) or len(entries) != 1:
    raise SystemExit("manifest must have one entry")
entry = entries[0]
if entry.get("operator") != operator:
    raise SystemExit("operator mismatch")
if entry.get("parse_preserving") != parse_preserving:
    raise SystemExit("parse-preserving mismatch")
params = entry.get("operator_params")
if not isinstance(params, dict):
    raise SystemExit("operator params missing")
for key, expected in {
    "mode": mode,
    "field": field,
    "expected_loader": expected_loader,
}.items():
    if params.get(key) != expected:
        raise SystemExit(f"{key} mismatch")
digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
if entry.get("output_hash") != digest:
    raise SystemExit("output hash mismatch")
before = params.get("before")
after = params.get("after")
if not isinstance(before, str) or not before or not isinstance(after, str) or not after or before == after:
    raise SystemExit("before/after evidence is missing or a no-op")
PY
}

check_operator() {
  local operator="$1"
  local mode="$2"
  local field="$3"
  local expected_loader="$4"
  local parse_preserving="$5"
  local input="$WORK/fixtures/add_constant_float.tflite"
  local out_a="$WORK/${operator}.a.tflite"
  local out_b="$WORK/${operator}.b.tflite"

  run_capture "$WORK/${operator}.mutate-a.log" "$TOOL_BIN" mutate --target tflite \
    --input "$input" --out "$out_a" --seed 4242 --operator "$operator"
  local mutate_a_rc=$?
  run_capture "$WORK/${operator}.mutate-b.log" "$TOOL_BIN" mutate --target tflite \
    --input "$input" --out "$out_b" --seed 4242 --operator "$operator"
  local mutate_b_rc=$?
  if [[ "$mutate_a_rc" -ne 0 || "$mutate_b_rc" -ne 0 \
        || ! -s "$out_a" || ! -s "$out_b" \
        || ! -f "$out_a.manifest.json" \
        || ! -f "$out_b.manifest.json" ]] \
      || ! cmp -s -- "$out_a" "$out_b" \
      || cmp -s -- "$input" "$out_a" \
      || ! validate_manifest "$out_a.manifest.json" "$out_a" "$operator" \
        "$mode" "$field" "$expected_loader" "$parse_preserving"; then
    bad "$operator did not produce a deterministic non-no-op mutation with complete evidence"
    sed -n '1,16p' "$WORK/${operator}.mutate-a.log" >&2
    return
  fi

  run_capture "$WORK/${operator}.replay.log" "$REPLAY" "$out_a"
  local replay_rc=$?
  if [[ "$expected_loader" == accept ]]; then
    if [[ "$replay_rc" -eq 0 ]] \
        && grep -Fq 'TFLITE_LOAD_OK stage=allocate_tensors' "$WORK/${operator}.replay.log" \
        && grep -Fq 'TFLITE_ACCESS_OK' "$WORK/${operator}.replay.log"; then
      ok "$operator is deterministic, fixup-complete, and accepted by the actual loader"
    else
      bad "$operator was not accepted by the actual loader (rc=$replay_rc)"
      sed -n '1,30p' "$WORK/${operator}.replay.log" >&2
    fi
  elif [[ "$replay_rc" -eq 9 ]] \
      && grep -Fq 'TFLITE_LOAD_REJECT' "$WORK/${operator}.replay.log" \
      && ! grep -Eq 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|Segmentation fault' \
        "$WORK/${operator}.replay.log"; then
    ok "$operator is deterministic and cleanly rejected by the actual loader"
  else
    bad "$operator was not cleanly rejected by the actual loader (rc=$replay_rc)"
    sed -n '1,30p' "$WORK/${operator}.replay.log" >&2
  fi
}

if [[ "$ready" -eq 1 && -x "$TOOL_BIN" && -x "$REPLAY" ]]; then
  check_operator tensor_shape structural tensor.shape accept yes
  check_operator tensor_shape_reject reject tensor.shape_buffer reject yes
  check_operator dtype_quantization structural tensor.dtype_quantization accept yes
  check_operator dtype_quantization_reject reject tensor.dtype_quantization reject yes
  check_operator buffer_payload structural buffer.data accept yes
  check_operator buffer_payload_reject reject buffer.data reject no
  check_operator operator_options structural operator.builtin_options accept yes
  check_operator operator_options_reject reject operator.opcode_options reject yes
  check_operator graph_references structural graph.tensor_indices accept yes
  check_operator graph_references_reject reject graph.tensor_indices reject yes
  check_operator names_metadata structural model.names_metadata accept yes
  check_operator names_metadata_reject reject model.names_metadata reject no

  run_capture "$WORK/no-applicable.log" "$TOOL_BIN" mutate --target tflite \
    --input "$WORK/fixtures/identity_float.tflite" \
    --out "$WORK/no-applicable.tflite" --seed 7 --operator operator_options
  no_applicable_rc=$?
  if [[ "$no_applicable_rc" -eq 2 ]] \
      && grep -Fiq 'no applicable' "$WORK/no-applicable.log" \
      && [[ ! -e "$WORK/no-applicable.tflite" ]]; then
    ok "an inapplicable operator fails explicitly without publishing output"
  else
    bad "an inapplicable operator was silent or published output (rc=$no_applicable_rc)"
  fi

  run_capture "$WORK/nested-output.log" "$TOOL_BIN" mutate --target tflite \
    --input "$WORK/fixtures/add_constant_float.tflite" \
    --out "$WORK/new/parent/nested.tflite" --seed 17 --operator names_metadata
  nested_rc=$?
  if [[ "$nested_rc" -eq 0 && -s "$WORK/new/parent/nested.tflite" \
        && -f "$WORK/new/parent/nested.tflite.manifest.json" ]]; then
    ok "single mutation creates a missing output parent safely"
  else
    bad "single mutation cannot create a missing output parent (rc=$nested_rc)"
    sed -n '1,20p' "$WORK/nested-output.log" >&2
  fi

  mkdir "$WORK/corpus"
  cp -- "$WORK/fixtures/add_constant_float.tflite" "$WORK/corpus/seed.tflite"
  run_capture "$WORK/batch.log" "$TOOL_BIN" mutate --target tflite \
    --input-dir "$WORK/corpus" --out-dir "$WORK/batch" --count 3 --seed 99 \
    --operator names_metadata
  batch_rc=$?
  if [[ "$batch_rc" -eq 0 ]] && python3 -B - "$WORK/batch/manifest.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if document.get("target") != "tflite" or document.get("requested") != 3 or document.get("generated") != 3:
    raise SystemExit("batch counts mismatch")
entries = document.get("entries")
if not isinstance(entries, list) or len(entries) != 3:
    raise SystemExit("batch entries mismatch")
if any(row.get("operator") != "names_metadata" for row in entries):
    raise SystemExit("batch operator mismatch")
if len({row.get("output_hash") for row in entries}) != 3:
    raise SystemExit("batch seeds produced duplicate outputs")
PY
  then
    ok "batch mutation records all deterministic TFLite outputs"
  else
    bad "batch mutation did not record three distinct TFLite outputs (rc=$batch_rc)"
    sed -n '1,24p' "$WORK/batch.log" >&2
  fi
else
  for operator in \
    tensor_shape tensor_shape_reject \
    dtype_quantization dtype_quantization_reject \
    buffer_payload buffer_payload_reject \
    operator_options operator_options_reject \
    graph_references graph_references_reject \
    names_metadata names_metadata_reject
  do
    bad "$operator did not run because TFLite prerequisites are unavailable"
  done
  bad "no-applicable behavior did not run because TFLite prerequisites are unavailable"
  bad "nested output behavior did not run because TFLite prerequisites are unavailable"
  bad "batch mutation did not run because TFLite prerequisites are unavailable"
fi

printf '[tflite-mutation] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
