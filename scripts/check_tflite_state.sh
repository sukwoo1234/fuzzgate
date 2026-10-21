#!/usr/bin/env bash
set -u

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TARGET_ROOT="${TFLITE_TARGET_ROOT:-$PROJECT_ROOT/data/targets/tflite/v2.20.0}"
GENERATOR="${TFLITE_GENERATOR:-$PROJECT_ROOT/scripts/gen_tflite_fixtures.py}"
BUILD_SCRIPT="${TFLITE_BUILD_SCRIPT:-$PROJECT_ROOT/scripts/build_tflite_profiles.sh}"
REPLAY="${TFLITE_REPLAY:-$PROJECT_ROOT/harnesses/tflite/tflite_loader_replay}"
FUZZER="${TFLITE_FUZZER:-$PROJECT_ROOT/harnesses/tflite/tflite_loader_fuzzer}"
FLATC="${TFLITE_FLATC:-$TARGET_ROOT/build/cmake/flatbuffers-flatc/bin/flatc}"
SOURCE_ROOT="${TFLITE_SOURCE_DIR:-$TARGET_ROOT/build/source}"
IDENTITY="${TFLITE_BUILD_IDENTITY:-$TARGET_ROOT/build-identity.json}"
NM="${NM:-$(command -v llvm-nm || command -v nm || true)}"

PASS=0
FAIL=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tool-tflite-state-check.XXXXXX")" || exit 2
trap 'rm -rf -- "$WORK"' EXIT

ok() {
  PASS=$((PASS + 1))
  printf '[tflite-state] ok: %s\n' "$1"
}

bad() {
  FAIL=$((FAIL + 1))
  printf '[tflite-state] fail: %s\n' "$1" >&2
}

if [[ ! -f "$BUILD_SCRIPT" ]]; then
  bad "build script is not a regular file: $BUILD_SCRIPT; collision check cannot run"
else
  collision_out="$WORK/colliding-output"
  env \
    TFLITE_TARGET_ROOT="$WORK/missing-target" \
    TFLITE_REPLAY="$collision_out" \
    TFLITE_FUZZER="$collision_out" \
    bash "$BUILD_SCRIPT" >"$WORK/output-collision.log" 2>&1
  collision_rc=$?
  if [[ "$collision_rc" -ne 0 ]] \
      && grep -Fq 'replay and fuzzer outputs must differ' "$WORK/output-collision.log"; then
    ok "build refuses colliding replay and fuzzer outputs before configuration"
  else
    bad "build did not reject colliding replay and fuzzer outputs (rc=$collision_rc)"
    sed -n '1,20p' "$WORK/output-collision.log" >&2
  fi

  replay_mutator_out="$WORK/colliding-replay-mutator"
  env \
    TFLITE_TARGET_ROOT="$WORK/missing-target" \
    TFLITE_REPLAY="$replay_mutator_out" \
    TFLITE_FUZZER="$WORK/separate-fuzzer" \
    TFLITE_MUTATOR="$replay_mutator_out" \
    bash "$BUILD_SCRIPT" >"$WORK/replay-mutator-collision.log" 2>&1
  replay_mutator_rc=$?
  if [[ "$replay_mutator_rc" -ne 0 ]] \
      && grep -Fq 'replay and mutator outputs must differ' "$WORK/replay-mutator-collision.log"; then
    ok "build refuses colliding replay and mutator outputs before configuration"
  else
    bad "build did not reject colliding replay and mutator outputs (rc=$replay_mutator_rc)"
    sed -n '1,20p' "$WORK/replay-mutator-collision.log" >&2
  fi

  fuzzer_mutator_out="$WORK/colliding-fuzzer-mutator"
  env \
    TFLITE_TARGET_ROOT="$WORK/missing-target" \
    TFLITE_REPLAY="$WORK/separate-replay" \
    TFLITE_FUZZER="$fuzzer_mutator_out" \
    TFLITE_MUTATOR="$fuzzer_mutator_out" \
    bash "$BUILD_SCRIPT" >"$WORK/fuzzer-mutator-collision.log" 2>&1
  fuzzer_mutator_rc=$?
  if [[ "$fuzzer_mutator_rc" -ne 0 ]] \
      && grep -Fq 'fuzzer and mutator outputs must differ' "$WORK/fuzzer-mutator-collision.log"; then
    ok "build refuses colliding fuzzer and mutator outputs before configuration"
  else
    bad "build did not reject colliding fuzzer and mutator outputs (rc=$fuzzer_mutator_rc)"
    sed -n '1,20p' "$WORK/fuzzer-mutator-collision.log" >&2
  fi
fi

fixtures_ready=1
for pair in "generator:$GENERATOR" "replay:$REPLAY" "flatc:$FLATC" "build identity:$IDENTITY"; do
  label="${pair%%:*}"
  path="${pair#*:}"
  if [[ ! -f "$path" ]]; then
    bad "$label is not a regular file: $path; this gate cannot run"
    fixtures_ready=0
  fi
done
if [[ "$fixtures_ready" -eq 1 ]]; then
  "$GENERATOR" --source-root "$SOURCE_ROOT" --flatc "$FLATC" \
    --build-identity "$IDENTITY" --output "$WORK/fixtures" \
    >"$WORK/generator.log" 2>&1
  generator_rc=$?
  if [[ "$generator_rc" -ne 0 ]]; then
    bad "fixture generator failed (rc=$generator_rc); this gate cannot run"
    sed -n '1,30p' "$WORK/generator.log" >&2
    fixtures_ready=0
  fi
fi

if [[ "$fixtures_ready" -eq 1 && -x "$REPLAY" ]]; then
  python3 -B - "$WORK/fixtures/add_constant_float.tflite" "$WORK/truncated.tflite" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_bytes()
pathlib.Path(sys.argv[2]).write_bytes(source[:12])
PY
  "$REPLAY" "$WORK/truncated.tflite" >"$WORK/truncated.log" 2>&1
  truncated_rc=$?
  if [[ "$truncated_rc" -eq 9 ]] \
      && grep -Fq 'TFLITE_LOAD_REJECT' "$WORK/truncated.log" \
      && ! grep -Eq 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|Segmentation fault' "$WORK/truncated.log"; then
    ok "truncated FlatBuffer is a clean input rejection"
  else
    bad "truncated FlatBuffer is not a clean input rejection (rc=$truncated_rc)"
    sed -n '1,30p' "$WORK/truncated.log" >&2
  fi

  "$REPLAY" "$WORK/fixtures/add_constant_float.tflite" >"$WORK/payload.log" 2>&1
  payload_rc=$?
  if [[ "$payload_rc" -eq 0 ]] \
      && grep -Fq 'role=constant name_hex=776569676874 dtype=float32 shape=1 bytes=4 payload_hex=0000c03f' "$WORK/payload.log" \
      && grep -Fq 'TFLITE_ACCESS_OK tensors=3 constants=1 constant_bytes=4' "$WORK/payload.log"; then
    ok "normal constant payload is confirmed after allocation"
  else
    bad "normal constant payload confirmation failed (rc=$payload_rc)"
    sed -n '1,30p' "$WORK/payload.log" >&2
  fi

  "$REPLAY" \
    "$WORK/fixtures/add_constant_float.tflite" \
    "$WORK/fixtures/add_int8.tflite" \
    "$WORK/fixtures/add_constant_float.tflite" \
    >"$WORK/aba.log" 2>&1
  aba_rc=$?
  if [[ "$aba_rc" -eq 0 ]] && python3 -B - "$WORK/aba.log" <<'PY'
import sys

lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
groups = []
current = None
for line in lines:
    if line.startswith("TFLITE_CASE_BEGIN ordinal="):
        if current is not None:
            raise SystemExit("nested case marker")
        current = []
    elif line.startswith("TFLITE_CASE_END ordinal="):
        if current is None:
            raise SystemExit("orphan case end")
        groups.append(current)
        current = None
    elif current is not None:
        current.append(line)
if current is not None or len(groups) != 3:
    raise SystemExit("expected exactly three completed cases")
if groups[0] != groups[2]:
    raise SystemExit("A observations differ after B")
if groups[0] == groups[1]:
    raise SystemExit("A and B unexpectedly have identical observations")
if not any("payload_hex=0000c03f" in line for line in groups[0]):
    raise SystemExit("A payload evidence is missing")
PY
  then
    ok "A-B-A in one process reproduces identical A observations"
  else
    bad "A-B-A same-process state check failed (rc=$aba_rc)"
    sed -n '1,60p' "$WORK/aba.log" >&2
  fi
elif [[ -f "$REPLAY" ]]; then
  bad "replay is not executable: $REPLAY; state checks cannot run"
fi

if [[ ! -x "$FUZZER" ]]; then
  bad "fuzzer is not executable: $FUZZER; engine checks cannot run"
elif [[ ! -x "$NM" ]]; then
  bad "nm is unavailable; shared loader symbol check cannot run"
else
  "$NM" -C "$FUZZER" >"$WORK/fuzzer-nm.log" 2>&1
  nm_rc=$?
  if [[ "$nm_rc" -eq 0 ]] \
      && grep -Fq 'tool::tflite_loader::LoadAndAllocate(' "$WORK/fuzzer-nm.log" \
      && python3 -B - "$IDENTITY" "$FUZZER" <<'PY'
import hashlib
import json
import sys

identity_path, fuzzer_path = sys.argv[1:]
identity = json.load(open(identity_path, encoding="utf-8"))
digest = hashlib.sha256(open(fuzzer_path, "rb").read()).hexdigest()
if identity.get("fuzzer_sha256") != digest:
    raise SystemExit("fuzzer bytes do not match the pinned build identity")
if not isinstance(identity.get("fuzzer_link_command_sha256"), str):
    raise SystemExit("fuzzer link command identity is missing")
PY
  then
    ok "engine binary and build identity use the same LoadAndAllocate function"
  else
    bad "engine binary does not carry the pinned shared loader function"
  fi

  if [[ "$fixtures_ready" -eq 1 ]]; then
    mkdir "$WORK/corpus"
    cp -- "$WORK/fixtures/"*.tflite "$WORK/corpus/"
    "$FUZZER" -runs=1 -max_len=16777216 "$WORK/corpus" >"$WORK/fuzzer.log" 2>&1
    fuzzer_rc=$?
    if [[ "$fuzzer_rc" -eq 0 ]] \
        && ! grep -Eq 'ERROR: AddressSanitizer|runtime error:|deadly signal' "$WORK/fuzzer.log"; then
      ok "libFuzzer engine executes the shared loader corpus cleanly"
    else
      bad "libFuzzer engine smoke failed (rc=$fuzzer_rc)"
      tail -n 40 "$WORK/fuzzer.log" >&2
    fi
  fi
fi

printf '[tflite-state] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
