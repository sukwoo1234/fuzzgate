#!/usr/bin/env bash
set -u

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TARGET_ROOT="${TFLITE_TARGET_ROOT:-$PROJECT_ROOT/data/targets/tflite/v2.20.0}"
GENERATOR="${TFLITE_GENERATOR:-$PROJECT_ROOT/scripts/gen_tflite_fixtures.py}"
REPLAY="${TFLITE_REPLAY:-$PROJECT_ROOT/harnesses/tflite/tflite_loader_replay}"
FLATC="${TFLITE_FLATC:-$TARGET_ROOT/build/cmake/flatbuffers-flatc/bin/flatc}"
SOURCE_ROOT="${TFLITE_SOURCE_DIR:-$TARGET_ROOT/build/source}"
IDENTITY="${TFLITE_BUILD_IDENTITY:-$TARGET_ROOT/build-identity.json}"

PASS=0
FAIL=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tool-tflite-fixtures-check.XXXXXX")" || exit 2
trap 'rm -rf -- "$WORK"' EXIT

ok() {
  PASS=$((PASS + 1))
  printf '[tflite-fixtures] ok: %s\n' "$1"
}

bad() {
  FAIL=$((FAIL + 1))
  printf '[tflite-fixtures] fail: %s\n' "$1" >&2
}

can_run=1
for pair in \
  "generator:$GENERATOR" \
  "replay:$REPLAY" \
  "flatc:$FLATC" \
  "build identity:$IDENTITY" \
  "schema:$SOURCE_ROOT/tensorflow/compiler/mlir/lite/schema/schema.fbs"
do
  label="${pair%%:*}"
  path="${pair#*:}"
  if [[ ! -f "$path" ]]; then
    bad "$label is not a regular file: $path; this gate cannot run"
    can_run=0
  fi
done
if [[ -f "$GENERATOR" && ! -x "$GENERATOR" ]]; then
  bad "generator is not executable: $GENERATOR; this gate cannot run"
  can_run=0
fi
if [[ -f "$REPLAY" && ! -x "$REPLAY" ]]; then
  bad "replay is not executable: $REPLAY; this gate cannot run"
  can_run=0
fi
if [[ -f "$FLATC" && ! -x "$FLATC" ]]; then
  bad "flatc is not executable: $FLATC; this gate cannot run"
  can_run=0
fi

generate() {
  "$GENERATOR" \
    --source-root "$SOURCE_ROOT" \
    --flatc "$FLATC" \
    --build-identity "$IDENTITY" \
    --output "$1"
}

validate_manifest() {
  python3 -B - "$1" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
if manifest.get("schema_version") != "1" or manifest.get("generator_version") != "tflite-fixtures-v1":
    raise SystemExit("manifest schema/generator version mismatch")
if manifest.get("seed") != 0:
    raise SystemExit("fixture seed must be exactly zero")
expected_names = [
    "identity_float.tflite",
    "add_float.tflite",
    "add_int8.tflite",
    "add_constant_float.tflite",
    "multi_add_float.tflite",
]
fixtures = manifest.get("fixtures")
if not isinstance(fixtures, list) or [row.get("name") for row in fixtures] != expected_names:
    raise SystemExit("fixture set/order mismatch")
for row in fixtures:
    if not isinstance(row.get("sha256"), str) or len(row["sha256"]) != 64:
        raise SystemExit(f"{row.get('name')}: missing sha256")
    if not isinstance(row.get("size_bytes"), int) or row["size_bytes"] < 8:
        raise SystemExit(f"{row.get('name')}: invalid size")
    if not isinstance(row.get("expected_lines"), list) or not row["expected_lines"]:
        raise SystemExit(f"{row.get('name')}: missing API oracle")
constant = next(row for row in fixtures if row["name"] == "add_constant_float.tflite")
if constant.get("constant_values") != [{
    "tensor_index": 1,
    "dtype": "float32",
    "shape": [1],
    "values": [1.5],
    "payload_hex": "0000c03f",
}]:
    raise SystemExit("constant tensor value oracle mismatch")
for row in fixtures:
    if row["name"] != "add_constant_float.tflite" and row.get("constant_values") != []:
        raise SystemExit(f"{row['name']}: unexpected constant value oracle")
PY
}

validate_output() {
  python3 -B - "$1" "$2" "$3" <<'PY'
import json
import sys

manifest_path, fixture_name, log_path = sys.argv[1:]
manifest = json.load(open(manifest_path, encoding="utf-8"))
fixture = next(row for row in manifest["fixtures"] if row["name"] == fixture_name)
lines = set(open(log_path, encoding="utf-8", errors="replace").read().splitlines())
if not any(line.startswith("TFLITE_ACCESS_OK ") for line in lines):
    raise SystemExit("tensor API access evidence is missing")
for expected in fixture["expected_lines"]:
    if expected not in lines:
        raise SystemExit(f"missing expected tensor observation: {expected}")
PY
}

if [[ "$can_run" -eq 1 ]]; then
  if generate "$WORK/a" >"$WORK/generate-a.log" 2>&1 \
      && generate "$WORK/b" >"$WORK/generate-b.log" 2>&1; then
    if diff -ru -- "$WORK/a" "$WORK/b" >"$WORK/determinism.diff"; then
      ok "fixture generation is byte-for-byte deterministic"
    else
      bad "two fixture generations differ"
      sed -n '1,40p' "$WORK/determinism.diff" >&2
    fi
  else
    bad "fixture generator failed"
    sed -n '1,30p' "$WORK/generate-a.log" >&2
    sed -n '1,30p' "$WORK/generate-b.log" >&2
    can_run=0
  fi
fi

if [[ "$can_run" -eq 1 ]]; then
  manifest="$WORK/a/manifest.json"
  if validate_manifest "$manifest"; then
    ok "fixture manifest carries the fixed tensor and value oracles"
  else
    bad "fixture manifest contract is invalid"
  fi

  printf '%s\n' \
    'TFLITE_LOAD_OK stage=allocate_tensors inputs=1 outputs=1 tensors=1 threads=1' \
    >"$WORK/allocation-only.log"
  if validate_output "$manifest" identity_float.tflite "$WORK/allocation-only.log" \
      >"$WORK/allocation-only-error.log" 2>&1; then
    bad "allocation-only output passed without tensor API access"
  else
    ok "allocation-only output is rejected without tensor API access"
  fi

  while IFS= read -r fixture; do
    "$REPLAY" "$WORK/a/$fixture" >"$WORK/$fixture.log" 2>&1
    rc=$?
    if [[ "$rc" -eq 0 ]] \
        && validate_output "$manifest" "$fixture" "$WORK/$fixture.log"; then
      ok "$fixture matches its tensor API oracle"
    else
      bad "$fixture failed its tensor API oracle (rc=$rc)"
      sed -n '1,30p' "$WORK/$fixture.log" >&2
    fi
  done <<'EOF'
identity_float.tflite
add_float.tflite
add_int8.tflite
add_constant_float.tflite
multi_add_float.tflite
EOF
fi

printf '[tflite-fixtures] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
