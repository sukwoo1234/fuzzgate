#!/usr/bin/env bash
set -u

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
TARGET_ROOT="${TFLITE_TARGET_ROOT:-$PROJECT_ROOT/data/targets/tflite/v2.20.0}"
ARCHIVE="${TFLITE_ARCHIVE:-$TARGET_ROOT/source/v2.20.0.tar.gz}"
META="${TFLITE_META:-$TARGET_ROOT/meta.json}"
PROFILE="${TFLITE_PROFILE:-$TARGET_ROOT/profile.json}"
IDENTITY="${TFLITE_BUILD_IDENTITY:-$TARGET_ROOT/build-identity.json}"
ADD_MODEL="${TFLITE_ADD_MODEL:-$TARGET_ROOT/fixtures/add.tflite}"

PASS=0
FAIL=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tool-tflite-loader-check.XXXXXX")" || exit 2
trap 'rm -rf -- "$WORK"' EXIT

ok() {
  PASS=$((PASS + 1))
  printf '[tflite-loader] ok: %s\n' "$1"
}

bad() {
  FAIL=$((FAIL + 1))
  printf '[tflite-loader] fail: %s\n' "$1" >&2
}

run_capture() {
  local log="$1"
  shift
  "$@" >"$log" 2>&1
}

if [[ ! -x "$TOOL_BIN" ]]; then
  bad "tool binary is not executable: $TOOL_BIN; this gate cannot run"
else
  if run_capture "$WORK/target-spec.log" "$TOOL_BIN" target-spec --target tflite --format json \
      && python3 -B - "$WORK/target-spec.log" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
expected = {
    "target_id": "tflite",
    "seed_subdir": "tflite",
    "input_ext": "tflite",
    "storage_name": "tensorflow-lite",
    "coverage_env_key": "TOOL_COVERAGE_TFLITE_CMD",
    "coverage_runner": "scripts/run_coverage_tflite.sh",
    "external_harness_env": "TOOL_TFLITE_HARNESS_CMD",
    "mutation_supported": True,
    "campaign_supported": False,
    "ui_supported": False,
}
for key, value in expected.items():
    if document.get(key) != value:
        raise SystemExit(f"{key}: expected {value!r}, observed {document.get(key)!r}")
PY
  then
    ok "registry exposes loader, structural mutation, and source coverage"
  else
    bad "registry does not expose the TFLite capability boundary"
    sed -n '1,12p' "$WORK/target-spec.log" >&2
  fi
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
stale = [line for line in lines if "tflite" not in line]
if stale:
    raise SystemExit(f"{len(stale)} target help declarations omit tflite")
PY
then
  ok "every CLI target help declaration names tflite"
else
  bad "CLI target help is stale after registering tflite"
fi

missing=0
for pair in \
  "source archive:$ARCHIVE" \
  "target metadata:$META" \
  "profile:$PROFILE" \
  "build identity:$IDENTITY" \
  "ADD model:$ADD_MODEL"
do
  label="${pair%%:*}"
  path="${pair#*:}"
  if [[ ! -f "$path" ]]; then
    bad "$label is not a regular file: $path; this gate cannot run"
    missing=1
  fi
done

validate_identity() {
  python3 -B - "$1" "$META" "$PROFILE" "$ADD_MODEL" "$ARCHIVE" <<'PY'
import hashlib
import json
import os
import sys

identity_path, meta_path, profile_path, model_path, archive_path = sys.argv[1:]
identity = json.load(open(identity_path, encoding="utf-8"))
meta = json.load(open(meta_path, encoding="utf-8"))
profile = json.load(open(profile_path, encoding="utf-8"))

def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

expected_source = {
    "url": "https://github.com/tensorflow/tensorflow/archive/refs/tags/v2.20.0.tar.gz",
    "tag": "v2.20.0",
    "resolved_commit": "72fbba3d20f4616d7312b5e2b7f79daf6e82f2fa",
    "sha256": "a640d1f97be316a09301dfc9347e3d929ad4d9a2336e3ca23c32c93b0ff7e5d0",
    "size_bytes": 84813578,
}
expected_meta = {
    "schema_version": "1.0",
    "target": "tflite",
    "version": "v2.20.0",
    "source_url": expected_source["url"],
    "source_kind": "official_release",
    "downloaded_file": archive_path,
    "downloaded_sha256": expected_source["sha256"],
    "downloaded_size_bytes": expected_source["size_bytes"],
}
expected_dependencies = {
    "abseil-cpp": "d9e4955c65cd4367dd6bf46f4ccb8cd3d100540b",
    "cpuinfo": "de0ce7c7251372892e53ce9bc891750d2c9a4fd8",
    "eigen": "4c38131a16803130b66266a912029504f2cf23cd",
    "farmhash": "0d859a811870d10f53a594927d0d0b97573ad06d",
    "fft2d": "v1.0",
    "flatbuffers": "e6463926479bd6b330cbcf673f7e917803fd5831",
    "fp16_headers": "0a92994d729ff76a58f692d3028ca1b64b145d91",
    "gemmlowp": "16e8662c34917be0065110bfcd9cc27d30f52fdf",
    "ml_dtypes": "00d98cd92ade342fef589c0470379abb27baebe9",
    "neon2sse": "a15b489e1222b2087007546b4912e21293ea86ff",
    "protobuf": "90b73ac3f0b10320315c2ca0d03a5a9b095d2f66",
    "ruy": "3286a34cc8de6149ac6844107dfdffac91531e72",
}
expected_options = {
    "BUILD_SHARED_LIBS": "OFF",
    "TFLITE_ENABLE_EXTERNAL_DELEGATE": "OFF",
    "TFLITE_ENABLE_GPU": "OFF",
    "TFLITE_ENABLE_METAL": "OFF",
    "TFLITE_ENABLE_NNAPI": "OFF",
    "TFLITE_ENABLE_RUY": "OFF",
    "TFLITE_ENABLE_XNNPACK": "OFF",
    "TFLITE_KERNEL_TEST": "OFF",
}

if meta != expected_meta:
    raise SystemExit("target metadata does not match the pinned official release")
if digest(archive_path) != meta["downloaded_sha256"]:
    raise SystemExit("source archive sha256 does not match target metadata")
if os.path.getsize(archive_path) != meta["downloaded_size_bytes"]:
    raise SystemExit("source archive size does not match target metadata")
if identity.get("schema_version") != "1" or identity.get("target_id") != "tflite":
    raise SystemExit("build identity schema/target mismatch")
if identity.get("source") != expected_source:
    raise SystemExit("build identity source pin mismatch")
if identity.get("cmake_options") != expected_options:
    raise SystemExit("build identity CMake option set mismatch")
expected_compile_flags = [
    "-O1",
    "-g",
    "-DNDEBUG",
    "-DTF_MAJOR_VERSION=2",
    "-DTF_MINOR_VERSION=20",
    "-DTF_PATCH_VERSION=0",
    "-DTF_VERSION_SUFFIX=''",
]
if identity.get("compile_flags") != expected_compile_flags:
    raise SystemExit("build identity compile flag set mismatch")
for tool_name in ("compiler", "cmake", "flatc"):
    tool = identity.get(tool_name, {})
    path = tool.get("path")
    if not isinstance(path, str) or not os.path.isfile(path):
        raise SystemExit(f"{tool_name} path is not a file")
    if digest(path) != tool.get("sha256"):
        raise SystemExit(f"{tool_name} sha256 mismatch")
    if not isinstance(tool.get("version"), str) or not tool["version"]:
        raise SystemExit(f"{tool_name} version is missing")
compiler_invocation = identity["compiler"].get("invocation_path")
if not isinstance(compiler_invocation, str) or os.path.realpath(compiler_invocation) != identity["compiler"]["path"]:
    raise SystemExit("compiler invocation does not resolve to the pinned compiler bytes")
if not os.path.basename(compiler_invocation).endswith("clang++"):
    raise SystemExit("C++ link driver invocation is not clang++")

dependencies = identity.get("dependencies")
if not isinstance(dependencies, list):
    raise SystemExit("dependencies must be a list")
observed = {}
for row in dependencies:
    name = row.get("name")
    if name in observed:
        raise SystemExit(f"duplicate dependency {name}")
    if not isinstance(row.get("tree_sha256"), str) or len(row["tree_sha256"]) != 64:
        raise SystemExit(f"dependency {name} has no tree sha256")
    if not isinstance(row.get("size_bytes"), int) or row["size_bytes"] < 1:
        raise SystemExit(f"dependency {name} has no measured size")
    observed[name] = row.get("resolved_commit")
if observed != expected_dependencies:
    raise SystemExit(f"dependency pin set mismatch: {observed!r}")

if profile.get("schema_version") != "1" or profile.get("target_id") != "tflite":
    raise SystemExit("profile schema/target mismatch")
if profile.get("format_revision") != "3" or profile.get("loader_id") != "tensorflow-lite":
    raise SystemExit("profile format/loader mismatch")
if profile.get("loader_version") != "v2.20.0" or profile.get("depth") != "load-allocate-access":
    raise SystemExit("profile version/depth mismatch")
patches = profile.get("patches")
if not isinstance(patches, list) or len(patches) != 1 or patches[0].get("order") != 1:
    raise SystemExit("profile must pin the v2.20.0 XNNPACK-off CMake patch")
if not os.path.isfile(patches[0].get("path", "")) or digest(patches[0]["path"]) != patches[0].get("sha256"):
    raise SystemExit("profile patch file/hash mismatch")
if profile.get("source_artifacts", [None])[0] != expected_source:
    raise SystemExit("profile primary source pin mismatch")
profile_dependencies = profile.get("source_artifacts", [])[1:]
if len(profile_dependencies) != len(dependencies):
    raise SystemExit("profile dependency source count mismatch")
for profile_row, identity_row in zip(profile_dependencies, dependencies):
    if profile_row != {
        "url": identity_row["url"],
        "tag": identity_row["resolved_commit"],
        "resolved_commit": identity_row["resolved_commit"],
        "sha256": identity_row["tree_sha256"],
        "size_bytes": identity_row["size_bytes"],
    }:
        raise SystemExit(f"profile dependency source mismatch for {identity_row['name']}")
if profile.get("input_kind") != {"kind": "single", "extensions": ["tflite"], "subformats": []}:
    raise SystemExit("profile input kind mismatch")
limits = profile.get("limits", {})
if limits.get("max_input_bytes") != 16 * 1024 * 1024 or limits.get("threads") != 1 or limits.get("workers") != 1:
    raise SystemExit("profile limits mismatch")
capabilities = profile.get("engine_capabilities")
if capabilities != [{
    "backend": "local-harness",
    "binary_role": "replay",
    "required_mode": "native",
    "instrumentation_scope": "tensorflow/lite",
}]:
    raise SystemExit("profile exposes an unbuilt engine capability")
if profile.get("sanitizer_policy", {}).get("compile_flags") != expected_compile_flags:
    raise SystemExit("profile compile flag set mismatch")
replay = next((row for row in profile.get("binaries", []) if row.get("role") == "replay"), None)
if replay is None or replay.get("argv") != ["{input}"]:
    raise SystemExit("profile replay identity mismatch")
if not os.path.isfile(replay["path"]) or digest(replay["path"]) != replay.get("sha256"):
    raise SystemExit("profile replay file/hash mismatch")
if replay.get("sha256") != identity.get("replay_sha256"):
    raise SystemExit("build identity replay sha256 mismatch")
if not os.path.isfile(model_path) or digest(model_path) != identity.get("add_model_sha256"):
    raise SystemExit("ADD model file/hash mismatch")
PY
}

if [[ "$missing" -eq 0 ]]; then
  if validate_identity "$IDENTITY"; then
    ok "official source, dependencies, compiler/CMake options, replay, and ADD model are pinned"
  else
    bad "pinned build/profile identity is invalid"
  fi

  python3 -B - "$IDENTITY" "$WORK/wrong-identity.json" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
document["source"]["sha256"] = "f" * 64
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(document, stream, sort_keys=True)
    stream.write("\n")
PY
  if validate_identity "$WORK/wrong-identity.json" >"$WORK/wrong-pin.log" 2>&1; then
    bad "wrong TensorFlow source pin was accepted"
  else
    ok "wrong TensorFlow source pin is rejected"
  fi
fi

if [[ -x "$TOOL_BIN" ]]; then
  printf '\0\0\0\0TFL3' >"$WORK/minimal-header.tflite"
  run_capture "$WORK/missing-library.log" env \
    TOOL_TFLITE_NATIVE_BIN="$WORK/does-not-exist" \
    TOOL_REQUIRE_LIBRARY_CONNECT=1 \
    "$TOOL_BIN" harness --target tflite --input "$WORK/minimal-header.tflite"
  missing_rc=$?
  if [[ "$missing_rc" -eq 10 ]] \
      && grep -Fq 'library connect required but unavailable' "$WORK/missing-library.log"; then
    ok "missing TFLite loader is unavailable, not a finding"
  else
    bad "missing TFLite loader did not return unavailable (rc=$missing_rc)"
    sed -n '1,12p' "$WORK/missing-library.log" >&2
  fi
fi

if [[ "$missing" -eq 0 && -x "$TOOL_BIN" ]]; then
  run_capture "$WORK/add.log" "$TOOL_BIN" \
    --target-profile "$PROFILE" --validation-run TFL-01 \
    harness --target tflite --input "$ADD_MODEL"
  add_rc=$?
  if [[ "$add_rc" -eq 0 ]] \
      && grep -Eq '^TFLITE_LOAD_OK stage=allocate_tensors .*threads=1$' "$WORK/add.log" \
      && grep -Fq 'library_outcome: session_ok' "$WORK/add.log"; then
    ok "official ADD model reaches AllocateTensors through the typed profile"
  else
    bad "official ADD model did not reach AllocateTensors (rc=$add_rc)"
    sed -n '1,20p' "$WORK/add.log" >&2
  fi
fi

printf '[tflite-loader] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
