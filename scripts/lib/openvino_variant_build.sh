#!/usr/bin/env bash
# OVI-05: rebuild the pinned Core and IR frontend in isolated guided or
# source-coverage object trees. The OVI-03 loader remains the only parser path.
set -euo pipefail

MODE="${1:-}"
if [[ "$MODE" != guided && "$MODE" != coverage ]]; then
  printf 'usage: %s guided|coverage\n' "$0" >&2
  exit 64
fi
shift
[[ $# -eq 0 ]] || {
  printf '[openvino-%s-build] unexpected arguments\n' "$MODE" >&2
  exit 64
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/../.." && pwd -P)}"
TARGET_ROOT_INPUT="${OPENVINO_TARGET_ROOT:-$PROJECT_ROOT/data/targets/openvino-ir/2026.4.1}"
while [[ "$TARGET_ROOT_INPUT" != / && "$TARGET_ROOT_INPUT" == */ ]]; do
  TARGET_ROOT_INPUT="${TARGET_ROOT_INPUT%/}"
done
[[ "$TARGET_ROOT_INPUT" = /* ]] || {
  printf '[openvino-%s-build] fail: OPENVINO_TARGET_ROOT must be absolute\n' "$MODE" >&2
  exit 1
}
[[ ! -L "$TARGET_ROOT_INPUT" ]] || {
  printf '[openvino-%s-build] fail: OPENVINO_TARGET_ROOT must not be a symlink\n' "$MODE" >&2
  exit 1
}
TARGET_ROOT="$(realpath -m -- "$TARGET_ROOT_INPUT")"
case "$TARGET_ROOT" in
  ""|/|"$PROJECT_ROOT"|"${HOME:-__unset_home__}")
    printf '[openvino-%s-build] fail: unsafe target root: %s\n' "$MODE" "$TARGET_ROOT" >&2
    exit 1
    ;;
esac

SOURCE_DIR="$TARGET_ROOT/build/source"
ARCHIVE="$TARGET_ROOT/source/2026.4.1.tar.gz"
PROFILE="$TARGET_ROOT/build-profile.json"
FIXTURES="$TARGET_ROOT/instrumentation-fixtures"
BUILD_DIR="$TARGET_ROOT/build/$MODE-cmake"
INSTALL_DIR="$TARGET_ROOT/install-$MODE"
HARNESS_DIR="$TARGET_ROOT/build/$MODE-harness"
MANIFEST="$TARGET_ROOT/$MODE-instrumentation.json"
JOBS="${JOBS:-4}"

log() { printf '[openvino-%s-build] %s\n' "$MODE" "$*"; }
fail() { printf '[openvino-%s-build] fail: %s\n' "$MODE" "$*" >&2; exit 1; }
blocked() { printf '[openvino-%s-build] blocked: %s\n' "$MODE" "$*" >&2; exit 2; }

[[ -f "$PROFILE" && ! -L "$PROFILE" ]] || blocked "normal build profile is unavailable: $PROFILE"
[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] || blocked "pinned source archive is unavailable: $ARCHIVE"
[[ "$(sha256sum "$ARCHIVE" | awk '{print $1}')" == \
   1ee85264556025486a4745a2d452ea823c578b3d162768bfef590366d2e6c539 ]] \
  || fail 'pinned source archive sha256 mismatch'
[[ "$(stat -c '%s' "$ARCHIVE")" == 71349787 ]] || fail 'pinned source archive size mismatch'
[[ -f "$SOURCE_DIR/.tool-source-contract" && ! -L "$SOURCE_DIR/.tool-source-contract" ]] \
  || blocked 'prepared pinned source tree is unavailable; run build_openvino_profiles.sh first'
expected_contract='1ee85264556025486a4745a2d452ea823c578b3d162768bfef590366d2e6c539:51c102d4187fac99daa38af281b0772c5e6c586f65004cdc63f8f2e011a21492:3d80df7150abaa2103a0c50bbc3e2a100fd7866b3c90e9608783c0a5c785bbe8:0dbc5e40a01ff142e7e68c03e85247a4dcede2f592d12d3677dee3664d17975a'
[[ "$(cat "$SOURCE_DIR/.tool-source-contract")" == "$expected_contract" ]] \
  || fail 'prepared source tree identity mismatch'
for required in \
  "$SOURCE_DIR/CMakeLists.txt" \
  "$SOURCE_DIR/src/frontends/ir/src/frontend.cpp" \
  "$SOURCE_DIR/src/frontends/ir/src/input_model.cpp" \
  "$SOURCE_DIR/src/core/src/model.cpp" \
  "$SOURCE_DIR/src/core/src/op/constant.cpp"
do
  [[ -f "$required" && ! -L "$required" ]] || fail "required pinned source missing: $required"
done

mapfile -t profile_tools < <(python3 -B - "$PROFILE" <<'PY'
import json
import pathlib
import sys

profile = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
toolchain = profile["toolchain"]
print(toolchain["cmake"]["path"])
print(pathlib.Path(toolchain["compiler"]["path"]).with_name("clang"))
print(pathlib.Path(toolchain["compiler"]["path"]).with_name("clang++"))
print(toolchain["ninja"]["path"])
PY
)
[[ ${#profile_tools[@]} -eq 4 ]] || fail 'normal build profile toolchain is incomplete'
CMAKE="${CMAKE:-${profile_tools[0]}}"
CLANG="${CLANG:-${profile_tools[1]}}"
CLANGXX="${CLANGXX:-${profile_tools[2]}}"
NINJA="${NINJA:-${profile_tools[3]}}"
LLVM_NM="${LLVM_NM:-$(dirname -- "$CLANGXX")/llvm-nm}"
LLVM_OBJDUMP="${LLVM_OBJDUMP:-$(dirname -- "$CLANGXX")/llvm-objdump}"
for spec in \
  "cmake:$CMAKE" \
  "clang:$CLANG" \
  "clang++:$CLANGXX" \
  "ninja:$NINJA" \
  "llvm-nm:$LLVM_NM" \
  "llvm-objdump:$LLVM_OBJDUMP"
do
  label="${spec%%:*}"
  path="${spec#*:}"
  [[ -x "$path" ]] || blocked "$label is unavailable: $path"
done
CMAKE="$(readlink -f -- "$CMAKE")"
NINJA="$(readlink -f -- "$NINJA")"
LLVM_NM="$(readlink -f -- "$LLVM_NM")"
LLVM_OBJDUMP="$(readlink -f -- "$LLVM_OBJDUMP")"
[[ "$(basename -- "$CLANGXX")" == clang++ ]] \
  || fail "C++ compiler invocation must retain the clang++ driver name: $CLANGXX"

for fresh in "$BUILD_DIR" "$INSTALL_DIR" "$HARNESS_DIR" "$MANIFEST"; do
  [[ ! -e "$fresh" && ! -L "$fresh" ]] || fail "fresh variant path already exists: $fresh"
done

if [[ "$MODE" == guided ]]; then
  COMPILE_FLAGS='-O1 -g -DNDEBUG -fsanitize=fuzzer-no-link'
  SHARED_LINK_FLAGS=''
  HARNESS_LINK_FLAGS='-fsanitize=fuzzer'
  HARNESS_TARGET=openvino_ir_loader_fuzzer
  DRIVER="$HARNESS_DIR/openvino_ir_loader_fuzzer"
else
  COMPILE_FLAGS='-O1 -g -DNDEBUG -fprofile-instr-generate -fcoverage-mapping'
  SHARED_LINK_FLAGS='-fprofile-instr-generate'
  HARNESS_LINK_FLAGS='-fprofile-instr-generate'
  HARNESS_TARGET=openvino_ir_loader_replay
  DRIVER="$HARNESS_DIR/openvino_ir_loader_replay"
fi

mkdir -p -- "$BUILD_DIR" "$INSTALL_DIR" "$HARNESS_DIR"
log "configuring isolated OpenVINO target objects"
"$CMAKE" -G Ninja \
  -S "$SOURCE_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CLANG" \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="$COMPILE_FLAGS" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="$COMPILE_FLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO="$SHARED_LINK_FLAGS" \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DBUILD_SHARED_LIBS=ON \
  -DENABLE_AUTO=OFF \
  -DENABLE_AUTO_BATCH=OFF \
  -DENABLE_DOCS=OFF \
  -DENABLE_HETERO=OFF \
  -DENABLE_INTEL_CPU=OFF \
  -DENABLE_INTEL_GPU=OFF \
  -DENABLE_INTEL_NPU=OFF \
  -DENABLE_IO_URING=OFF \
  -DENABLE_JS=OFF \
  -DENABLE_LTO=OFF \
  -DENABLE_MULTI=OFF \
  -DENABLE_OV_GGUF_FRONTEND=OFF \
  -DENABLE_OV_IR_FRONTEND=ON \
  -DENABLE_OV_JAX_FRONTEND=OFF \
  -DENABLE_OV_ONNX_FRONTEND=OFF \
  -DENABLE_OV_PADDLE_FRONTEND=OFF \
  -DENABLE_OV_PYTORCH_FRONTEND=OFF \
  -DENABLE_OV_TF_FRONTEND=OFF \
  -DENABLE_OV_TF_LITE_FRONTEND=OFF \
  -DENABLE_PKGCONFIG_GEN=OFF \
  -DENABLE_PLUGINS_XML=OFF \
  -DENABLE_PROFILING_ITT=OFF \
  -DENABLE_PROXY=OFF \
  -DENABLE_PYTHON=OFF \
  -DENABLE_SAMPLES=OFF \
  -DENABLE_SYSTEM_PUGIXML=OFF \
  -DENABLE_TEMPLATE=OFF \
  -DENABLE_TESTS=OFF \
  -DTHREADING=SEQ \
  >"$TARGET_ROOT/$MODE-configure.log" 2>&1 \
  || fail "OpenVINO configure failed; see $TARGET_ROOT/$MODE-configure.log"

log "building Core + IR frontend target objects (jobs=$JOBS)"
"$CMAKE" --build "$BUILD_DIR" --target openvino openvino_c openvino_ir_frontend -j"$JOBS" \
  >"$TARGET_ROOT/$MODE-build.log" 2>&1 \
  || fail "OpenVINO build failed; see $TARGET_ROOT/$MODE-build.log"
"$CMAKE" --install "$BUILD_DIR" >"$TARGET_ROOT/$MODE-install.log" 2>&1 \
  || fail "OpenVINO install failed; see $TARGET_ROOT/$MODE-install.log"

OPENVINO_CONFIG="$(find "$INSTALL_DIR" -type f -name OpenVINOConfig.cmake -print -quit)"
[[ -n "$OPENVINO_CONFIG" ]] || fail 'instrumented OpenVINOConfig.cmake not found'
OPENVINO_CMAKE_DIR="$(dirname -- "$OPENVINO_CONFIG")"

log "building the OVI-03 common loader wrapper against instrumented targets"
"$CMAKE" -G Ninja \
  -S "$PROJECT_ROOT/harnesses/openvino" \
  -B "$HARNESS_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="$COMPILE_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO="$HARNESS_LINK_FLAGS" \
  -DOpenVINO_DIR="$OPENVINO_CMAKE_DIR" \
  -DOPENVINO_BUILD_LOADER=ON \
  >"$TARGET_ROOT/$MODE-harness-configure.log" 2>&1 \
  || fail "loader configure failed; see $TARGET_ROOT/$MODE-harness-configure.log"
"$CMAKE" --build "$HARNESS_DIR" --target "$HARNESS_TARGET" -j"$JOBS" \
  >"$TARGET_ROOT/$MODE-harness-build.log" 2>&1 \
  || fail "loader build failed; see $TARGET_ROOT/$MODE-harness-build.log"
[[ -x "$DRIVER" ]] || fail "instrumented loader driver missing: $DRIVER"

CORE_LIBRARY="$(find "$INSTALL_DIR" -type f -name 'libopenvino.so.*' -print | sort | head -1)"
IR_LIBRARY="$(find "$INSTALL_DIR" -type f -name 'libopenvino_ir_frontend.so.*' -print | sort | head -1)"
[[ -f "$CORE_LIBRARY" && ! -L "$CORE_LIBRARY" ]] || fail 'instrumented Core library missing'
[[ -f "$IR_LIBRARY" && ! -L "$IR_LIBRARY" ]] || fail 'instrumented IR frontend library missing'
LLVM_READELF="$(dirname -- "$LLVM_NM")/llvm-readelf"
[[ -x "$LLVM_READELF" ]] || blocked "llvm-readelf is unavailable: $LLVM_READELF"
for library in "$CORE_LIBRARY" "$IR_LIBRARY"; do
  "$LLVM_READELF" -d "$library" | grep -Fq 'Shared library: [libstdc++.so.6]' \
    || fail "instrumented C++ library lost its libstdc++ dependency: $library"
done

if [[ ! -e "$FIXTURES" && ! -L "$FIXTURES" ]]; then
  python3 -B "$PROJECT_ROOT/scripts/gen_openvino_fixtures.py" \
    --build-profile "$PROFILE" generate --output "$FIXTURES" \
    >"$TARGET_ROOT/instrumentation-fixtures.log" 2>&1 \
    || fail "FZB1 pair generation failed; see $TARGET_ROOT/instrumentation-fixtures.log"
else
  python3 -B "$PROJECT_ROOT/scripts/gen_openvino_fixtures.py" \
    --build-profile "$PROFILE" verify --output "$FIXTURES" \
    >"$TARGET_ROOT/instrumentation-fixtures-$MODE-verify.log" 2>&1 \
    || fail "existing FZB1 pair verification failed"
fi
FIXTURE="$FIXTURES/constant-one.fzb"
[[ -f "$FIXTURE" && ! -L "$FIXTURE" ]] || fail 'constant-one FZB1 fixture missing'

NORMAL_CONTROL=''
NORMAL_CONTROL_LOG=''
GUIDED_LOG=''
NORMAL_COUNTERS=''
GUIDED_COUNTERS=''
PROBE_ROOT=''
if [[ "$MODE" == guided ]]; then
  NORMAL_CONTROL_DIR="$TARGET_ROOT/build/guided-normal-control"
  [[ ! -e "$NORMAL_CONTROL_DIR" && ! -L "$NORMAL_CONTROL_DIR" ]] \
    || fail "fresh normal-control path already exists: $NORMAL_CONTROL_DIR"
  NORMAL_OPENVINO_DIR="$TARGET_ROOT/install/runtime/cmake"
  [[ -f "$NORMAL_OPENVINO_DIR/OpenVINOConfig.cmake" ]] \
    || blocked 'normal OpenVINO install is unavailable for wrapper-only control'
  "$CMAKE" -G Ninja \
    -S "$PROJECT_ROOT/harnesses/openvino" \
    -B "$NORMAL_CONTROL_DIR" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_CXX_COMPILER="$CLANGXX" \
    -DOpenVINO_DIR="$NORMAL_OPENVINO_DIR" \
    -DOPENVINO_BUILD_LOADER=ON \
    >"$TARGET_ROOT/guided-normal-control-configure.log" 2>&1 \
    || fail 'normal wrapper-only control configure failed'
  "$CMAKE" --build "$NORMAL_CONTROL_DIR" --target openvino_ir_loader_fuzzer -j"$JOBS" \
    >"$TARGET_ROOT/guided-normal-control-build.log" 2>&1 \
    || fail 'normal wrapper-only control build failed'
  NORMAL_CONTROL="$NORMAL_CONTROL_DIR/openvino_ir_loader_fuzzer"
  NORMAL_CONTROL_LOG="$TARGET_ROOT/guided-normal-control-smoke.log"
  GUIDED_LOG="$TARGET_ROOT/guided-smoke.log"
  "$NORMAL_CONTROL" -runs=1 "$FIXTURE" >"$NORMAL_CONTROL_LOG" 2>&1 \
    || fail 'wrapper-only fuzzer control failed'
  "$DRIVER" -runs=1 "$FIXTURE" >"$GUIDED_LOG" 2>&1 \
    || fail 'guided target fuzzer smoke failed'
  NORMAL_COUNTERS="$(python3 -B - "$NORMAL_CONTROL_LOG" <<'PY'
import pathlib
import re
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
print(sum(map(int, re.findall(r"\(([0-9]+) inline 8-bit counters\)", text))))
PY
)"
  GUIDED_COUNTERS="$(python3 -B - "$GUIDED_LOG" <<'PY'
import pathlib
import re
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
print(sum(map(int, re.findall(r"\(([0-9]+) inline 8-bit counters\)", text))))
PY
)"
  [[ "$NORMAL_COUNTERS" =~ ^[0-9]+$ && "$NORMAL_COUNTERS" -gt 0 ]] \
    || fail 'wrapper-only control exposed no inline counter record'
  [[ "$GUIDED_COUNTERS" =~ ^[0-9]+$ && "$GUIDED_COUNTERS" -gt "$NORMAL_COUNTERS" ]] \
    || fail "guided counters do not exceed wrapper-only control: $GUIDED_COUNTERS <= $NORMAL_COUNTERS"
else
  PROBE_ROOT="$TARGET_ROOT/coverage-build-probe"
  [[ ! -e "$PROBE_ROOT" && ! -L "$PROBE_ROOT" ]] || fail 'coverage build probe path is not fresh'
  mkdir -p -- "$PROBE_ROOT"
  LLVM_PROFILE_FILE="$PROBE_ROOT/probe-%m-%p.profraw" "$DRIVER" "$FIXTURE" \
    >"$TARGET_ROOT/coverage-smoke.log" 2>&1 \
    || fail 'coverage replay smoke failed'
  shopt -s nullglob
  probe_profiles=("$PROBE_ROOT"/*.profraw)
  shopt -u nullglob
  [[ ${#probe_profiles[@]} -gt 0 ]] || fail 'coverage replay emitted no raw profile'
  for probe_profile in "${probe_profiles[@]}"; do
    [[ -s "$probe_profile" ]] || fail "coverage replay emitted an empty raw profile: $probe_profile"
  done
fi

manifest_tmp="$(mktemp "$TARGET_ROOT/.${MODE}-instrumentation.XXXXXX")" \
  || fail 'could not create manifest staging file'
python3 -B - \
  "$manifest_tmp" "$MODE" "$TARGET_ROOT" "$SOURCE_DIR" "$ARCHIVE" "$PROFILE" \
  "$BUILD_DIR/compile_commands.json" "$CORE_LIBRARY" "$IR_LIBRARY" "$DRIVER" \
  "$CLANGXX" "$LLVM_NM" "$LLVM_OBJDUMP" "$COMPILE_FLAGS" \
  "$NORMAL_CONTROL" "$NORMAL_CONTROL_LOG" "$GUIDED_LOG" \
  "$NORMAL_COUNTERS" "$GUIDED_COUNTERS" "$FIXTURE" "$PROBE_ROOT" <<'PY'
import hashlib
import json
import os
import pathlib
import subprocess
import sys

(
    output, mode, target_root_text, source_root_text, archive_text, profile_text,
    commands_text, core_text, ir_text, driver_text, compiler_text, nm_text,
    objdump_text, flags, normal_driver_text, normal_log_text, guided_log_text,
    normal_counters, guided_counters, fixture_text, probe_root_text,
) = sys.argv[1:]
target_root = pathlib.Path(target_root_text).resolve()
source_root = pathlib.Path(source_root_text).resolve()
commands_path = pathlib.Path(commands_text).resolve()

def sha(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def sha_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def identity(path):
    resolved = pathlib.Path(path).resolve()
    resolved.relative_to(target_root)
    return {"path": str(resolved), "sha256": sha(resolved)}

def tool_output(command):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)

def symbol_count(path, marker, undefined=False):
    command = [nm_text, "-A"]
    if undefined:
        command.append("--undefined-only")
    command.append(str(path))
    return sum(marker in line for line in tool_output(command).splitlines())

def section_count(path, marker):
    return sum(marker in line for line in tool_output([objdump_text, "-h", str(path)]).splitlines())

rows = json.loads(commands_path.read_text(encoding="utf-8"))
required = {
    "ir_reader_frontend": "src/frontends/ir/src/frontend.cpp",
    "ir_reader_model_conversion": "src/frontends/ir/src/input_model.cpp",
    "validation_type_inference": "src/core/src/model.cpp",
    "constant_access": "src/core/src/op/constant.cpp",
}
objects = []
object_paths = {}
for role, suffix in required.items():
    source = (source_root / suffix).resolve()
    matches = [row for row in rows if pathlib.Path(row["file"]).resolve() == source]
    if len(matches) != 1:
        raise SystemExit(f"expected one compile record for {suffix}, found {len(matches)}")
    row = matches[0]
    obj = (pathlib.Path(row["directory"]) / row["output"]).resolve()
    obj.relative_to(target_root)
    if not obj.is_file() or obj.is_symlink():
        raise SystemExit(f"required target object missing: {obj}")
    object_paths[role] = obj
    objects.append({
        "role": role,
        "source": suffix,
        "object": identity(obj),
        "compile_command_sha256": sha_text(row["command"]),
    })

components = {
    "core": pathlib.Path(core_text).resolve(),
    "ir_frontend": pathlib.Path(ir_text).resolve(),
    "driver": pathlib.Path(driver_text).resolve(),
}
document = {
    "schema_version": "openvino-ir-instrumentation-v1",
    "target": "openvino-ir",
    "target_version": "2026.4.1",
    "mode": mode,
    "source_archive_sha256": sha(archive_text),
    "normal_build_profile": identity(profile_text),
    "compiler": {
        "path": str(pathlib.Path(compiler_text).resolve()),
        "invocation_path": compiler_text,
        "sha256": sha(pathlib.Path(compiler_text).resolve()),
        "version": tool_output([compiler_text, "--version"]).splitlines()[0],
    },
    "compile_flags": flags.split(),
    "compile_commands": identity(commands_path),
    "components": {role: identity(path) for role, path in components.items()},
    "required_objects": objects,
}
if mode == "guided":
    document["instrumentation"] = {
        "kind": "sanitizer-coverage",
        "component_symbol_counts": {
            role: symbol_count(components[role], "__sanitizer_cov_", True)
            for role in ("core", "ir_frontend")
        },
        "object_symbol_counts": {
            role: symbol_count(path, "__sanitizer_cov_", True)
            for role, path in object_paths.items()
        },
    }
    document["runtime"] = {
        "normal_control": {
            "binary": identity(normal_driver_text),
            "log": identity(normal_log_text),
            "fixture": identity(fixture_text),
            "loaded_inline_counters": int(normal_counters),
        },
        "guided": {
            "binary": identity(driver_text),
            "log": identity(guided_log_text),
            "fixture": identity(fixture_text),
            "loaded_inline_counters": int(guided_counters),
        },
    }
else:
    document["instrumentation"] = {
        "kind": "llvm-source-cov",
        "component_symbol_counts": {
            role: symbol_count(components[role], "__profc_", False)
            for role in ("core", "ir_frontend")
        },
        "object_symbol_counts": {
            role: symbol_count(path, "__profc_", False)
            for role, path in object_paths.items()
        },
        "object_covmap_sections": {
            role: section_count(path, "__llvm_covmap")
            for role, path in object_paths.items()
        },
    }
    probe_root = pathlib.Path(probe_root_text).resolve()
    document["build_probe_profiles"] = [
        identity(path) for path in sorted(probe_root.glob("*.profraw"))
    ]

pathlib.Path(output).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
mv -- "$manifest_tmp" "$MANIFEST"
log "wrote verified target-object manifest $MANIFEST"
printf 'mode=%s\nmanifest=%s\ncore=%s\nir_frontend=%s\ndriver=%s\n' \
  "$MODE" "$MANIFEST" "$CORE_LIBRARY" "$IR_LIBRARY" "$DRIVER"
