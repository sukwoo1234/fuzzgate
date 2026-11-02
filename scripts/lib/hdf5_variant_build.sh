#!/usr/bin/env bash
# HDF-05: build the pinned HDF5 reader/dataset/filter objects in isolated
# guided or source-coverage trees. HDF-03 LoadImage remains the parser path.
set -euo pipefail

MODE="${1:-}"
if [[ "$MODE" != guided && "$MODE" != coverage ]]; then
  printf 'usage: %s guided|coverage\n' "$0" >&2
  exit 64
fi
shift
[[ $# -eq 0 ]] || {
  printf '[hdf5-%s-build] unexpected arguments\n' "$MODE" >&2
  exit 64
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/../.." && pwd -P)}"
TARGET_ROOT_INPUT="${HDF5_TARGET_ROOT:-$PROJECT_ROOT/data/targets/hdf5-weights/2.2.0}"
while [[ "$TARGET_ROOT_INPUT" != / && "$TARGET_ROOT_INPUT" == */ ]]; do
  TARGET_ROOT_INPUT="${TARGET_ROOT_INPUT%/}"
done
[[ "$TARGET_ROOT_INPUT" = /* && ! -L "$TARGET_ROOT_INPUT" ]] || {
  printf '[hdf5-%s-build] fail: unsafe HDF5_TARGET_ROOT\n' "$MODE" >&2
  exit 1
}
TARGET_ROOT="$(realpath -m -- "$TARGET_ROOT_INPUT")"
case "$TARGET_ROOT" in
  ""|/|/tmp|/var/tmp|"$PROJECT_ROOT"|"${HOME:-__unset_home__}")
    printf '[hdf5-%s-build] fail: unsafe target root: %s\n' "$MODE" "$TARGET_ROOT" >&2
    exit 1
    ;;
esac

SOURCE_DIR="$TARGET_ROOT/build/source"
ARCHIVE="$TARGET_ROOT/source/2.2.0.tar.gz"
PROFILE="$TARGET_ROOT/build-profile.json"
BUILD_DIR="$TARGET_ROOT/build/$MODE-cmake"
INSTALL_DIR="$TARGET_ROOT/install-$MODE"
HARNESS_DIR="$TARGET_ROOT/build/$MODE-harness"
MANIFEST="$TARGET_ROOT/$MODE-instrumentation.json"
FIXTURE_DIR="$TARGET_ROOT/instrumentation-fixtures"
FIXTURE="$FIXTURE_DIR/shuffle-fletcher32.h5"
JOBS="${JOBS:-4}"

log() { printf '[hdf5-%s-build] %s\n' "$MODE" "$*"; }
fail() { printf '[hdf5-%s-build] fail: %s\n' "$MODE" "$*" >&2; exit 1; }
blocked() { printf '[hdf5-%s-build] blocked: %s\n' "$MODE" "$*" >&2; exit 2; }

[[ -f "$PROFILE" && ! -L "$PROFILE" ]] || blocked "normal build profile unavailable: $PROFILE"
[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] || blocked "pinned source archive unavailable: $ARCHIVE"
[[ "$(sha256sum "$ARCHIVE" | awk '{print $1}')" == 1a1ab8209b35586fbc1aa279ba76d102130b95badcb20ca329587219112d8c16 ]] \
  || fail 'pinned source archive sha256 mismatch'
[[ "$(stat -c '%s' "$ARCHIVE")" == 42131403 ]] || fail 'pinned source archive size mismatch'
for required in \
  "$SOURCE_DIR/CMakeLists.txt" \
  "$SOURCE_DIR/src/H5Fio.c" \
  "$SOURCE_DIR/src/H5Dio.c" \
  "$SOURCE_DIR/src/H5Dchunk.c" \
  "$SOURCE_DIR/src/H5Z.c" \
  "$SOURCE_DIR/src/H5Zshuffle.c" \
  "$SOURCE_DIR/src/H5Zfletcher32.c"
do
  [[ -f "$required" && ! -L "$required" ]] || blocked "pinned source missing: $required"
done
while read -r expected_sha relative_source; do
  [[ "$(sha256sum "$SOURCE_DIR/$relative_source" | awk '{print $1}')" == "$expected_sha" ]] \
    || fail "pinned source identity mismatch: $relative_source"
done <<'EOF'
d58491a293695f84cfedebb3f414d6ad0c5cfd15a15e0a08f8800d040d272ba5 src/H5Fio.c
34cc21c84e88b0c6e066a78548c7a686e9ccce5d77869023fae5825d804a5b04 src/H5Dio.c
6895faf7913775040d51e69e46cdfda0fe209cfac2d612bad356476a9cff34f1 src/H5Dchunk.c
e4958b2a98a62c5942f9b97bd3f26250b7306e7c5c802529b613372030202a65 src/H5Z.c
900d1c2588adbe1e53dfe2499462f534c168495ef656c2f6736dd0266fec4471 src/H5Zshuffle.c
a1a7e28c3c601db8615b95de8f5c0b82e6e00b187982928511f8a53413eb45a6 src/H5Zfletcher32.c
EOF

mapfile -t profile_values < <(python3 -B - "$PROFILE" <<'PY'
import json
import pathlib
import sys

profile = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
tools = profile["toolchain"]
print(tools["cmake"]["path"])
print(tools["c_compiler"]["path"])
print(pathlib.Path(tools["cxx_compiler"]["path"]).with_name("clang++"))
print(tools["ninja"]["path"])
print(profile["components"]["core"]["path"])
print(profile["components"]["high_level"]["path"])
PY
)
[[ ${#profile_values[@]} -eq 6 ]] || fail 'normal build profile is incomplete'
CMAKE="${CMAKE:-${profile_values[0]}}"
CLANG="${CLANG:-${profile_values[1]}}"
CLANGXX="${CLANGXX:-${profile_values[2]}}"
NINJA="${NINJA:-${profile_values[3]}}"
NORMAL_CORE="${profile_values[4]}"
NORMAL_HL="${profile_values[5]}"
TOOLCHAIN_DIR="$(dirname -- "$CLANGXX")"
LLVM_NM="${LLVM_NM:-$TOOLCHAIN_DIR/llvm-nm}"
LLVM_OBJDUMP="${LLVM_OBJDUMP:-$TOOLCHAIN_DIR/llvm-objdump}"
if [[ "$(basename -- "$CLANGXX")" != clang++ \
   && -x "$(dirname -- "$CLANGXX")/clang++" \
   && "$(readlink -f -- "$(dirname -- "$CLANGXX")/clang++")" == "$(readlink -f -- "$CLANGXX")" ]]; then
  CLANGXX="$(dirname -- "$CLANGXX")/clang++"
fi
for tool in "$CMAKE" "$CLANG" "$CLANGXX" "$NINJA" "$LLVM_NM" "$LLVM_OBJDUMP"; do
  [[ -x "$tool" ]] || blocked "required tool unavailable: $tool"
done
for component in "$NORMAL_CORE" "$NORMAL_HL"; do
  [[ -f "$component" && ! -L "$component" ]] || blocked "normal component unavailable: $component"
done

for fresh in "$BUILD_DIR" "$INSTALL_DIR" "$HARNESS_DIR" "$MANIFEST"; do
  [[ ! -e "$fresh" && ! -L "$fresh" ]] || fail "fresh variant path already exists: $fresh"
done

NORMAL_CMAKE_DIR="$(find "$TARGET_ROOT/install" -type f -name hdf5-config.cmake -printf '%h\n' | head -1)"
[[ -n "$NORMAL_CMAKE_DIR" ]] || blocked 'normal HDF5 CMake package unavailable'
if [[ ! -e "$FIXTURE" && ! -L "$FIXTURE" ]]; then
  FIXTURE_BUILD="$TARGET_ROOT/build/instrumentation-fixture-harness"
  [[ ! -e "$FIXTURE_BUILD" && ! -L "$FIXTURE_BUILD" ]] \
    || fail "fixture output is missing but fixture build path exists: $FIXTURE_BUILD"
  mkdir -p -- "$FIXTURE_BUILD" "$FIXTURE_DIR"
  "$CMAKE" -G Ninja \
    -S "$PROJECT_ROOT/harnesses/hdf5" \
    -B "$FIXTURE_BUILD" \
    -DCMAKE_MAKE_PROGRAM="$NINJA" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_CXX_COMPILER="$CLANGXX" \
    -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld \
    -DHDF5_DIR="$NORMAL_CMAKE_DIR" \
    -DHDF5_BUILD_INSTRUMENTATION_FIXTURE_TOOL=ON \
    >"$TARGET_ROOT/instrumentation-fixture-configure.log" 2>&1 \
    || fail 'instrumentation fixture configure failed'
  "$CMAKE" --build "$FIXTURE_BUILD" --target hdf5_instrumentation_fixture_tool -j"$JOBS" \
    >"$TARGET_ROOT/instrumentation-fixture-build.log" 2>&1 \
    || fail 'instrumentation fixture build failed'
  LD_LIBRARY_PATH="$(dirname -- "$NORMAL_CORE")" HDF5_PLUGIN_PATH= \
    "$FIXTURE_BUILD/hdf5_instrumentation_fixture_tool" "$FIXTURE" \
    >"$TARGET_ROOT/instrumentation-fixture-generate.log" 2>&1 \
    || fail 'instrumentation fixture generation failed'
fi
[[ -s "$FIXTURE" && ! -L "$FIXTURE" ]] || fail 'filtered instrumentation fixture unavailable'

if [[ "$MODE" == guided ]]; then
  COMPILE_FLAGS='-O1 -g -DNDEBUG -fsanitize=fuzzer-no-link'
  SHARED_LINK_FLAGS='-fuse-ld=lld'
  HARNESS_LINK_FLAGS='-fuse-ld=lld -fsanitize=fuzzer'
  HARNESS_TARGET=hdf5_loader_fuzzer
  DRIVER="$HARNESS_DIR/hdf5_loader_fuzzer"
else
  COMPILE_FLAGS='-O1 -g -DNDEBUG -fprofile-instr-generate -fcoverage-mapping'
  SHARED_LINK_FLAGS='-fuse-ld=lld -fprofile-instr-generate'
  HARNESS_LINK_FLAGS='-fuse-ld=lld -fprofile-instr-generate'
  HARNESS_TARGET=hdf5_loader_replay
  DRIVER="$HARNESS_DIR/hdf5_loader_replay"
fi

mkdir -p -- "$BUILD_DIR" "$INSTALL_DIR" "$HARNESS_DIR"
log 'configuring isolated HDF5 target objects'
"$CMAKE" -G Ninja \
  -S "$SOURCE_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_MAKE_PROGRAM="$NINJA" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CLANG" \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="$COMPILE_FLAGS" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="$COMPILE_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO="$SHARED_LINK_FLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO="$SHARED_LINK_FLAGS" \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DBUILD_SHARED_LIBS=ON \
  -DBUILD_STATIC_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DHDF5_ALLOW_EXTERNAL_SUPPORT=NO \
  -DHDF5_BUILD_CPP_LIB=OFF \
  -DHDF5_BUILD_DOC=OFF \
  -DHDF5_BUILD_EXAMPLES=OFF \
  -DHDF5_BUILD_FORTRAN=OFF \
  -DHDF5_BUILD_HL_LIB=ON \
  -DHDF5_BUILD_JAVA=OFF \
  -DHDF5_BUILD_TOOLS=OFF \
  -DHDF5_ENABLE_CONCURRENCY=OFF \
  -DHDF5_ENABLE_HDFS=OFF \
  -DHDF5_ENABLE_PARALLEL=OFF \
  -DHDF5_ENABLE_PLUGIN_SUPPORT=OFF \
  -DHDF5_ENABLE_SZIP_SUPPORT=OFF \
  -DHDF5_ENABLE_THREADSAFE=OFF \
  -DHDF5_ENABLE_ZLIB_SUPPORT=OFF \
  >"$TARGET_ROOT/$MODE-configure.log" 2>&1 \
  || fail "HDF5 configure failed; see $TARGET_ROOT/$MODE-configure.log"
"$CMAKE" --build "$BUILD_DIR" --target hdf5-shared hdf5_hl-shared -j"$JOBS" \
  >"$TARGET_ROOT/$MODE-build.log" 2>&1 \
  || fail "HDF5 build failed; see $TARGET_ROOT/$MODE-build.log"
"$CMAKE" --install "$BUILD_DIR" >"$TARGET_ROOT/$MODE-install.log" 2>&1 \
  || fail "HDF5 install failed; see $TARGET_ROOT/$MODE-install.log"

HDF5_CMAKE_DIR="$(find "$INSTALL_DIR" -type f -name hdf5-config.cmake -printf '%h\n' | head -1)"
[[ -n "$HDF5_CMAKE_DIR" ]] || fail 'instrumented HDF5 CMake package unavailable'
log 'building the HDF-03 common loader against instrumented HDF5'
"$CMAKE" -G Ninja \
  -S "$PROJECT_ROOT/harnesses/hdf5" \
  -B "$HARNESS_DIR" \
  -DCMAKE_MAKE_PROGRAM="$NINJA" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="$COMPILE_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO="$HARNESS_LINK_FLAGS" \
  -DHDF5_DIR="$HDF5_CMAKE_DIR" \
  -DHDF5_BUILD_LOADER=ON \
  >"$TARGET_ROOT/$MODE-harness-configure.log" 2>&1 \
  || fail 'instrumented loader configure failed'
"$CMAKE" --build "$HARNESS_DIR" --target "$HARNESS_TARGET" -j"$JOBS" \
  >"$TARGET_ROOT/$MODE-harness-build.log" 2>&1 \
  || fail 'instrumented loader build failed'
[[ -x "$DRIVER" ]] || fail "instrumented driver unavailable: $DRIVER"

CORE_LIBRARY="$(find "$INSTALL_DIR" -type f -name 'libhdf5.so.*' ! -type l -print | sort | head -1)"
HL_LIBRARY="$(find "$INSTALL_DIR" -type f -name 'libhdf5_hl.so.*' ! -type l -print | sort | head -1)"
[[ -f "$CORE_LIBRARY" && -f "$HL_LIBRARY" ]] || fail 'instrumented shared libraries unavailable'

NORMAL_CONTROL=''
NORMAL_LOG=''
GUIDED_LOG=''
NORMAL_COUNTERS=0
GUIDED_COUNTERS=0
PROBE_ROOT=''
if [[ "$MODE" == guided ]]; then
  NORMAL_DIR="$TARGET_ROOT/build/guided-normal-control"
  [[ ! -e "$NORMAL_DIR" && ! -L "$NORMAL_DIR" ]] || fail 'normal-control path is not fresh'
  "$CMAKE" -G Ninja \
    -S "$PROJECT_ROOT/harnesses/hdf5" \
    -B "$NORMAL_DIR" \
    -DCMAKE_MAKE_PROGRAM="$NINJA" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_CXX_COMPILER="$CLANGXX" \
    -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld \
    -DHDF5_DIR="$NORMAL_CMAKE_DIR" \
    -DHDF5_BUILD_LOADER=ON \
    >"$TARGET_ROOT/guided-normal-control-configure.log" 2>&1 \
    || fail 'normal wrapper-only control configure failed'
  "$CMAKE" --build "$NORMAL_DIR" --target hdf5_loader_fuzzer -j"$JOBS" \
    >"$TARGET_ROOT/guided-normal-control-build.log" 2>&1 \
    || fail 'normal wrapper-only control build failed'
  NORMAL_CONTROL="$NORMAL_DIR/hdf5_loader_fuzzer"
  NORMAL_LOG="$TARGET_ROOT/guided-normal-control-smoke.log"
  GUIDED_LOG="$TARGET_ROOT/guided-smoke.log"
  LD_LIBRARY_PATH="$(dirname -- "$NORMAL_CORE")" HDF5_PLUGIN_PATH= \
    "$NORMAL_CONTROL" -runs=1 "$FIXTURE" >"$NORMAL_LOG" 2>&1 \
    || fail 'wrapper-only control smoke failed'
  LD_LIBRARY_PATH="$(dirname -- "$CORE_LIBRARY")" HDF5_PLUGIN_PATH= \
    "$DRIVER" -runs=1 "$FIXTURE" >"$GUIDED_LOG" 2>&1 \
    || fail 'guided HDF5 smoke failed'
  NORMAL_COUNTERS="$(grep -Eo '\([0-9]+ inline 8-bit counters\)' "$NORMAL_LOG" | tr -cd '0-9\n' | awk '{s+=$1} END {print s+0}')"
  GUIDED_COUNTERS="$(grep -Eo '\([0-9]+ inline 8-bit counters\)' "$GUIDED_LOG" | tr -cd '0-9\n' | awk '{s+=$1} END {print s+0}')"
  [[ "$NORMAL_COUNTERS" -gt 0 ]] || fail 'wrapper-only control exposed no counters'
  [[ "$GUIDED_COUNTERS" -gt "$NORMAL_COUNTERS" ]] \
    || fail "guided counters do not exceed wrapper-only control: $GUIDED_COUNTERS <= $NORMAL_COUNTERS"
else
  PROBE_ROOT="$TARGET_ROOT/coverage-build-probe"
  [[ ! -e "$PROBE_ROOT" && ! -L "$PROBE_ROOT" ]] || fail 'coverage probe path is not fresh'
  mkdir -p -- "$PROBE_ROOT"
  LD_LIBRARY_PATH="$(dirname -- "$CORE_LIBRARY")" HDF5_PLUGIN_PATH= \
    LLVM_PROFILE_FILE="$PROBE_ROOT/probe-%m-%p.profraw" \
    "$DRIVER" "$FIXTURE" >"$TARGET_ROOT/coverage-smoke.log" 2>&1 \
    || fail 'coverage replay smoke failed'
  shopt -s nullglob
  probe_profiles=("$PROBE_ROOT"/*.profraw)
  shopt -u nullglob
  [[ ${#probe_profiles[@]} -gt 0 ]] || fail 'coverage replay emitted no raw profile'
fi

manifest_tmp="$(mktemp "$TARGET_ROOT/.${MODE}-instrumentation.XXXXXX")"
python3 -B - \
  "$manifest_tmp" "$MODE" "$TARGET_ROOT" "$SOURCE_DIR" "$ARCHIVE" "$PROFILE" \
  "$BUILD_DIR/compile_commands.json" "$CORE_LIBRARY" "$HL_LIBRARY" "$DRIVER" \
  "$CLANGXX" "$LLVM_NM" "$LLVM_OBJDUMP" "$COMPILE_FLAGS" "$FIXTURE" \
  "$NORMAL_CORE" "$NORMAL_HL" "$NORMAL_CONTROL" "$NORMAL_LOG" "$GUIDED_LOG" \
  "$NORMAL_COUNTERS" "$GUIDED_COUNTERS" "$PROBE_ROOT" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    output, mode, target_text, source_text, archive_text, profile_text,
    commands_text, core_text, hl_text, driver_text, compiler_text, nm_text,
    objdump_text, flags, fixture_text, normal_core_text, normal_hl_text,
    normal_driver_text, normal_log_text, guided_log_text, normal_counters,
    guided_counters, probe_root_text,
) = sys.argv[1:]
target = pathlib.Path(target_text).resolve()
source_root = pathlib.Path(source_text).resolve()

def sha(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def identity(path):
    resolved = pathlib.Path(path).resolve()
    resolved.relative_to(target)
    return {"path": str(resolved), "sha256": sha(resolved)}

def external_identity(path):
    resolved = pathlib.Path(path).resolve()
    return {"path": str(resolved), "sha256": sha(resolved)}

def tool_output(command):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)

def symbols(path, marker, undefined=False):
    command = [nm_text, "-A"]
    if undefined:
        command.append("--undefined-only")
    command.append(str(path))
    return sum(marker in line for line in tool_output(command).splitlines())

def sections(path, marker):
    return sum(marker in line for line in tool_output([objdump_text, "-h", str(path)]).splitlines())

commands_path = pathlib.Path(commands_text).resolve()
rows = json.loads(commands_path.read_text(encoding="utf-8"))
required = {
    "reader_io": "src/H5Fio.c",
    "dataset_read": "src/H5Dio.c",
    "chunk_decode": "src/H5Dchunk.c",
    "filter_pipeline": "src/H5Z.c",
    "shuffle_filter": "src/H5Zshuffle.c",
    "fletcher32_filter": "src/H5Zfletcher32.c",
}
objects = []
object_paths = {}
for role, suffix in required.items():
    wanted = (source_root / suffix).resolve()
    matches = [row for row in rows if pathlib.Path(row["file"]).resolve() == wanted]
    if len(matches) != 1:
        raise SystemExit(f"expected one compile record for {suffix}, found {len(matches)}")
    row = matches[0]
    obj = (pathlib.Path(row["directory"]) / row["output"]).resolve()
    obj.relative_to(target)
    if not obj.is_file() or obj.is_symlink():
        raise SystemExit(f"required object unavailable: {obj}")
    object_paths[role] = obj
    objects.append({
        "role": role,
        "source": suffix,
        "source_sha256": sha(wanted),
        "object": identity(obj),
        "compile_command_sha256": hashlib.sha256(row["command"].encode()).hexdigest(),
    })

components = {
    "core": pathlib.Path(core_text).resolve(),
    "high_level": pathlib.Path(hl_text).resolve(),
    "driver": pathlib.Path(driver_text).resolve(),
}
document = {
    "schema_version": "hdf5-weights-instrumentation-v1",
    "target": "hdf5-weights",
    "target_version": "2.2.0",
    "mode": mode,
    "source_archive_sha256": sha(archive_text),
    "normal_build_profile": identity(profile_text),
    "compiler": external_identity(compiler_text),
    "compile_flags": flags.split(),
    "compile_commands": identity(commands_path),
    "components": {role: identity(path) for role, path in components.items()},
    "required_objects": objects,
    "fixture": identity(fixture_text),
    "normal_components": {
        "core": identity(normal_core_text),
        "high_level": identity(normal_hl_text),
    },
}
if mode == "guided":
    document["instrumentation"] = {
        "kind": "sanitizer-coverage",
        "normal_component_hooks": {
            "core": symbols(normal_core_text, "__sanitizer_cov_", True),
            "high_level": symbols(normal_hl_text, "__sanitizer_cov_", True),
        },
        "target_component_hooks": {
            "core": symbols(core_text, "__sanitizer_cov_", True),
            "high_level": symbols(hl_text, "__sanitizer_cov_", True),
        },
        "object_hooks": {
            role: symbols(path, "__sanitizer_cov_", True)
            for role, path in object_paths.items()
        },
    }
    document["runtime"] = {
        "normal_control": {
            "binary": identity(normal_driver_text),
            "log": identity(normal_log_text),
            "loaded_inline_counters": int(normal_counters),
        },
        "guided": {
            "binary": identity(driver_text),
            "log": identity(guided_log_text),
            "loaded_inline_counters": int(guided_counters),
        },
    }
else:
    document["instrumentation"] = {
        "kind": "llvm-source-cov",
        "normal_component_counters": {
            "core": symbols(normal_core_text, "__profc_"),
            "high_level": symbols(normal_hl_text, "__profc_"),
        },
        "target_component_counters": {
            "core": symbols(core_text, "__profc_"),
            "high_level": symbols(hl_text, "__profc_"),
        },
        "object_counters": {
            role: symbols(path, "__profc_") for role, path in object_paths.items()
        },
        "object_covmap_sections": {
            role: sections(path, "__llvm_covmap") for role, path in object_paths.items()
        },
    }
    probe = pathlib.Path(probe_root_text).resolve()
    document["build_probe_profiles"] = [identity(path) for path in sorted(probe.glob("*.profraw"))]

pathlib.Path(output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
mv -- "$manifest_tmp" "$MANIFEST"
log "wrote verified target-object manifest $MANIFEST"
printf 'mode=%s\nmanifest=%s\ncore=%s\nhigh_level=%s\ndriver=%s\nfixture=%s\n' \
  "$MODE" "$MANIFEST" "$CORE_LIBRARY" "$HL_LIBRARY" "$DRIVER" "$FIXTURE"
