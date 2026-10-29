#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
HDF5_VERSION=2.2.0
HDF5_COMMIT=49df1b4e5ca4108d56e80f06321a749da1535268
HDF5_URL=https://github.com/HDFGroup/hdf5/releases/download/2.2.0/hdf5-2.2.0.tar.gz
HDF5_SHA256=1a1ab8209b35586fbc1aa279ba76d102130b95badcb20ca329587219112d8c16
HDF5_SIZE=42131403
EXPECTED_MARKER='HDF5_FILE_IMAGE_OK calls=3 readonly=1 group=1 deflate=0 szip=0 shuffle=1 fletcher32=1 nbit=1 scaleoffset=1 version=2.2.0'

fail() {
  printf '[build-hdf5] fail: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[build-hdf5] %s\n' "$*"
}

TARGET_ROOT_INPUT="${HDF5_TARGET_ROOT:-$PROJECT_ROOT/data/targets/hdf5-weights/$HDF5_VERSION}"
while [[ "$TARGET_ROOT_INPUT" != / && "$TARGET_ROOT_INPUT" == */ ]]; do
  TARGET_ROOT_INPUT="${TARGET_ROOT_INPUT%/}"
done
[[ "$TARGET_ROOT_INPUT" = /* ]] || {
  printf '[build-hdf5] fail: HDF5_TARGET_ROOT must be absolute: %s\n' "$TARGET_ROOT_INPUT" >&2
  exit 1
}
[[ ! -L "$TARGET_ROOT_INPUT" ]] || {
  printf '[build-hdf5] fail: HDF5_TARGET_ROOT must not be a symlink: %s\n' "$TARGET_ROOT_INPUT" >&2
  exit 1
}
path_cursor=
IFS='/' read -r -a path_parts <<<"${TARGET_ROOT_INPUT#/}"
for part in "${path_parts[@]}"; do
  [[ -n "$part" ]] || continue
  [[ "$part" != . && "$part" != .. ]] \
    || fail "HDF5_TARGET_ROOT must not contain dot path components: $TARGET_ROOT_INPUT"
  path_cursor="$path_cursor/$part"
  [[ ! -L "$path_cursor" ]] \
    || fail "HDF5_TARGET_ROOT must not traverse a symlink: $path_cursor"
done
TARGET_ROOT="$(realpath -m -- "$TARGET_ROOT_INPUT")"
case "$TARGET_ROOT" in
  ""|/|/tmp|/var/tmp|"$PROJECT_ROOT"|"${HOME:-__unset_home__}")
    printf '[build-hdf5] fail: unsafe HDF5_TARGET_ROOT: %s\n' "$TARGET_ROOT" >&2
    exit 1
    ;;
esac

ARCHIVE="${HDF5_ARCHIVE:-$TARGET_ROOT/source/$HDF5_VERSION.tar.gz}"
SOURCE_DIR="$TARGET_ROOT/build/source"
BUILD_DIR="$TARGET_ROOT/build/cmake"
INSTALL_DIR="$TARGET_ROOT/install"
PROBE_BUILD_DIR="$TARGET_ROOT/build/probe"
PROBE="$TARGET_ROOT/bin/hdf5_file_image_probe"
META="$TARGET_ROOT/meta.json"
PROFILE="$TARGET_ROOT/build-profile.json"
LINKAGE="$TARGET_ROOT/linkage-manifest.json"
LINK_COMMANDS="$TARGET_ROOT/link-commands.txt"
PROBE_LINK_COMMANDS="$TARGET_ROOT/probe-link-commands.txt"
LINKER_TRACE="$TARGET_ROOT/linker-trace.txt"
JOBS="${JOBS:-4}"

for owned_path in \
  "$TARGET_ROOT/source" "$TARGET_ROOT/build" "$TARGET_ROOT/install" "$TARGET_ROOT/bin" \
  "$META" "$PROFILE" "$LINKAGE" "$LINK_COMMANDS" "$PROBE_LINK_COMMANDS" "$LINKER_TRACE" \
  "$TARGET_ROOT/configure.log" "$TARGET_ROOT/build.log" "$TARGET_ROOT/install.log" \
  "$TARGET_ROOT/probe-configure.log" "$TARGET_ROOT/probe-build.log" "$TARGET_ROOT/check.log"
do
  [[ ! -L "$owned_path" ]] \
    || fail "HDF5 target-owned path must not be a symlink: $owned_path"
done
EXPECTED_TARGET_ROOT="$(realpath -m -- "$PROJECT_ROOT/data/targets/hdf5-weights/$HDF5_VERSION")"
[[ "$TARGET_ROOT" == "$EXPECTED_TARGET_ROOT" ]] \
  || fail "HDF5_TARGET_ROOT must equal the dedicated project target root: $EXPECTED_TARGET_ROOT"

CMAKE="${CMAKE:-$PROJECT_ROOT/.venv/lib/python3.10/site-packages/cmake/data/bin/cmake}"
NINJA="${NINJA:-$(command -v ninja || true)}"
CLANG="${CLANG:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin/clang}"
CLANGXX="${CLANGXX:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin/clang++}"
READELF="${READELF:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin/llvm-readelf}"
for tool in "$CMAKE" "$NINJA" "$CLANG" "$CLANGXX" "$READELF"; do
  [[ -x "$tool" ]] || fail "required executable not found: $tool"
done
CMAKE="$(readlink -f -- "$CMAKE")"
NINJA="$(readlink -f -- "$NINJA")"
CLANG_REAL="$(readlink -f -- "$CLANG")"
CLANGXX_REAL="$(readlink -f -- "$CLANGXX")"
READELF="$(readlink -f -- "$READELF")"

[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] || fail "HDF5 archive is missing or unsafe: $ARCHIVE"
[[ "$(sha256sum "$ARCHIVE" | cut -d' ' -f1)" == "$HDF5_SHA256" ]] \
  || fail "HDF5 archive sha256 mismatch: $ARCHIVE"
[[ "$(stat -c '%s' "$ARCHIVE")" == "$HDF5_SIZE" ]] \
  || fail "HDF5 archive size mismatch: $ARCHIVE"
log "verified official HDF5 $HDF5_VERSION release archive"

log "removing prior HDF5 build outputs for a fresh source/object build"
rm -rf -- "$TARGET_ROOT/build" "$TARGET_ROOT/install" "$TARGET_ROOT/bin"
rm -f -- \
  "$META" "$PROFILE" "$LINKAGE" "$LINK_COMMANDS" "$PROBE_LINK_COMMANDS" "$LINKER_TRACE" \
  "$TARGET_ROOT/configure.log" "$TARGET_ROOT/build.log" "$TARGET_ROOT/install.log" \
  "$TARGET_ROOT/probe-configure.log" "$TARGET_ROOT/probe-build.log" "$TARGET_ROOT/check.log"
mkdir -p -- "$SOURCE_DIR" "$BUILD_DIR" "$INSTALL_DIR" "$PROBE_BUILD_DIR" "$(dirname -- "$PROBE")"
log "extracting the pinned HDF5 source into the fresh build tree"
tar -xzf "$ARCHIVE" -C "$SOURCE_DIR" --strip-components=2
for required in \
  "$SOURCE_DIR/CMakeLists.txt" \
  "$SOURCE_DIR/src/H5F.c" \
  "$SOURCE_DIR/hl/src/H5LT.c" \
  "$SOURCE_DIR/hl/src/H5LTpublic.h"
do
  [[ -f "$required" && ! -L "$required" ]] || fail "required pinned source is missing: $required"
done

log "configuring shared HDF5 core + high-level library without optional filters"
"$CMAKE" -G Ninja \
  -S "$SOURCE_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CLANG" \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO='-O1 -g -DNDEBUG' \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO='-O1 -g -DNDEBUG' \
  -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld \
  -DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=lld \
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
  >"$TARGET_ROOT/configure.log" 2>&1 \
  || fail "HDF5 configure failed; see $TARGET_ROOT/configure.log"
ACTUAL_LINKER="$(sed -n 's/^CMAKE_LINKER:FILEPATH=//p' "$BUILD_DIR/CMakeCache.txt" | head -1)"
[[ -n "$ACTUAL_LINKER" && -x "$ACTUAL_LINKER" ]] \
  || fail "CMake did not select an executable linker: $ACTUAL_LINKER"

log "building HDF5 core + high-level shared libraries (jobs=$JOBS)"
"$CMAKE" --build "$BUILD_DIR" --target hdf5-shared hdf5_hl-shared -j"$JOBS" \
  >"$TARGET_ROOT/build.log" 2>&1 \
  || fail "HDF5 build failed; see $TARGET_ROOT/build.log"
rm -rf -- "$INSTALL_DIR"
mkdir -p -- "$INSTALL_DIR"
"$CMAKE" --install "$BUILD_DIR" >"$TARGET_ROOT/install.log" 2>&1 \
  || fail "HDF5 install failed; see $TARGET_ROOT/install.log"
"$NINJA" -C "$BUILD_DIR" -t commands hdf5-shared hdf5_hl-shared >"$LINK_COMMANDS"

HDF5_CONFIG="$(find "$INSTALL_DIR" -type f -name hdf5-config.cmake -print -quit)"
[[ -n "$HDF5_CONFIG" ]] || fail "installed hdf5-config.cmake not found"
HDF5_CMAKE_DIR="$(dirname -- "$HDF5_CONFIG")"
log "building the H5LT file-image runtime probe"
"$CMAKE" -G Ninja \
  -S "$PROJECT_ROOT/harnesses/hdf5" \
  -B "$PROBE_BUILD_DIR" \
  -DHDF5_DIR="$HDF5_CMAKE_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  >"$TARGET_ROOT/probe-configure.log" 2>&1 \
  || fail "probe configure failed; see $TARGET_ROOT/probe-configure.log"
"$CMAKE" --build "$PROBE_BUILD_DIR" --target hdf5_file_image_probe -j"$JOBS" \
  >"$TARGET_ROOT/probe-build.log" 2>&1 \
  || fail "probe build failed; see $TARGET_ROOT/probe-build.log"
[[ -x "$PROBE_BUILD_DIR/hdf5_file_image_probe" ]] \
  || fail "probe build produced no executable"
"$NINJA" -C "$PROBE_BUILD_DIR" -t commands hdf5_file_image_probe >"$PROBE_LINK_COMMANDS"
CORE_TRACE_OBJECT="$(find "$BUILD_DIR" -type f -name 'H5F.c.o' -print -quit)"
PROBE_TRACE_OBJECT="$(find "$PROBE_BUILD_DIR" -type f -name 'profile_probe.cc.o' -print -quit)"
[[ -f "$CORE_TRACE_OBJECT" && -f "$PROBE_TRACE_OBJECT" ]] \
  || fail "linker trace objects are missing"
{
  "$CLANG" -fuse-ld=lld -### -shared \
    -o "$TARGET_ROOT/.hdf5-linker-trace.so" "$CORE_TRACE_OBJECT"
  "$CLANGXX" -fuse-ld=lld -### \
    -o "$TARGET_ROOT/.probe-linker-trace" "$PROBE_TRACE_OBJECT"
} >"$LINKER_TRACE" 2>&1
[[ -s "$LINKER_TRACE" ]] || fail "linker driver trace is empty"
install -m 0755 "$PROBE_BUILD_DIR/hdf5_file_image_probe" "$PROBE"

CORE_LIBRARY="$(find "$INSTALL_DIR" -type f -name 'libhdf5.so.*' -print | sort | head -1)"
HL_LIBRARY="$(find "$INSTALL_DIR" -type f -name 'libhdf5_hl.so.*' -print | sort | head -1)"
[[ -f "$CORE_LIBRARY" && ! -L "$CORE_LIBRARY" ]] || fail "installed HDF5 core library not found"
[[ -f "$HL_LIBRARY" && ! -L "$HL_LIBRARY" ]] || fail "installed HDF5 high-level library not found"

probe_output="$(LD_LIBRARY_PATH="$(dirname -- "$CORE_LIBRARY")" HDF5_PLUGIN_PATH= "$PROBE" 2>&1)" \
  || fail "H5LT file-image probe failed: $probe_output"
[[ "$probe_output" == "$EXPECTED_MARKER" ]] || fail "unexpected probe output: $probe_output"

python3 -B - \
  "$TARGET_ROOT" "$META" "$PROFILE" "$LINKAGE" "$ARCHIVE" \
  "$CMAKE" "$CLANG_REAL" "$CLANGXX_REAL" "$ACTUAL_LINKER" "$NINJA" "$READELF" \
  "$CORE_LIBRARY" "$HL_LIBRARY" "$PROBE" \
  "$BUILD_DIR/CMakeCache.txt" "$BUILD_DIR/compile_commands.json" \
  "$BUILD_DIR/install_manifest.txt" "$LINK_COMMANDS" \
  "$PROBE_BUILD_DIR/CMakeCache.txt" "$PROBE_BUILD_DIR/compile_commands.json" \
  "$PROBE_LINK_COMMANDS" "$LINKER_TRACE" \
  "$TARGET_ROOT/build.log" "$TARGET_ROOT/probe-build.log" \
  "$HDF5_URL" "$HDF5_COMMIT" \
  "$EXPECTED_MARKER" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

(
    target_root,
    meta_path,
    profile_path,
    linkage_path,
    archive_path,
    cmake_path,
    compiler_path,
    cxx_compiler_path,
    linker_path,
    ninja_path,
    readelf_path,
    core_library,
    high_level_library,
    probe_path,
    cmake_cache,
    compile_commands,
    install_manifest,
    link_commands,
    probe_cmake_cache,
    probe_compile_commands,
    probe_link_commands,
    linker_trace,
    build_log,
    probe_build_log,
    source_url,
    source_commit,
    expected_marker,
) = sys.argv[1:]


def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def first_line(command):
    return subprocess.check_output(command, text=True).splitlines()[0]


def file_identity(path):
    return {"path": os.path.realpath(path), "sha256": sha(path)}


def tool(path, command):
    real = os.path.realpath(path)
    return {"path": real, "sha256": sha(real), "version": first_line(command)}


source = {
    "name": "hdf5",
    "url": source_url,
    "tag": "2.2.0",
    "resolved_commit": source_commit,
    "sha256": sha(archive_path),
    "size_bytes": os.path.getsize(archive_path),
}
options = {
    "BUILD_SHARED_LIBS": "ON",
    "BUILD_STATIC_LIBS": "OFF",
    "BUILD_TESTING": "OFF",
    "CMAKE_BUILD_TYPE": "RelWithDebInfo",
    "CMAKE_EXE_LINKER_FLAGS": "-fuse-ld=lld",
    "CMAKE_SHARED_LINKER_FLAGS": "-fuse-ld=lld",
    "HDF5_ALLOW_EXTERNAL_SUPPORT": "NO",
    "HDF5_BUILD_CPP_LIB": "OFF",
    "HDF5_BUILD_DOC": "OFF",
    "HDF5_BUILD_EXAMPLES": "OFF",
    "HDF5_BUILD_FORTRAN": "OFF",
    "HDF5_BUILD_HL_LIB": "ON",
    "HDF5_BUILD_JAVA": "OFF",
    "HDF5_BUILD_TOOLS": "OFF",
    "HDF5_ENABLE_CONCURRENCY": "OFF",
    "HDF5_ENABLE_HDFS": "OFF",
    "HDF5_ENABLE_PARALLEL": "OFF",
    "HDF5_ENABLE_PLUGIN_SUPPORT": "OFF",
    "HDF5_ENABLE_SZIP_SUPPORT": "OFF",
    "HDF5_ENABLE_THREADSAFE": "OFF",
    "HDF5_ENABLE_ZLIB_SUPPORT": "OFF",
}
filter_contract = {
    "built_in_filters": ["shuffle", "fletcher32", "nbit", "scaleoffset"],
    "deflate": "unsupported-build-disabled",
    "dynamic_plugin_loading": False,
    "external_support": "NO",
    "szip": "unsupported-build-disabled",
}
installed = sorted(
    str(path.resolve())
    for path in pathlib.Path(target_root, "install").rglob("*.so*")
    if path.is_file() and not path.is_symlink()
)
dynamic = subprocess.check_output([readelf_path, "-d", probe_path], text=True)
needed = re.findall(r"Shared library: \[([^]]+)\]", dynamic)
symbols_output = subprocess.check_output(
    [
        readelf_path,
        "--elf-output-style=GNU",
        "--dyn-symbols",
        "--wide",
        probe_path,
    ],
    text=True,
)
symbols = []
for line in symbols_output.splitlines():
    fields = line.split()
    if len(fields) >= 8 and fields[6] == "UND":
        symbols.append(fields[7])

linkage = {
    "schema_version": "hdf5-weights-linkage-v1",
    "libraries": [
        {"role": "core", **file_identity(core_library)},
        {"role": "high_level", **file_identity(high_level_library)},
    ],
    "installed_shared_libraries": installed,
    "probe_dynamic_dependencies": needed,
    "probe_undefined_symbols": symbols,
}
runtime_bindings = []
library_dir = pathlib.Path(core_library).parent
for role, prefix, component in (
    ("core", "libhdf5.so.", pathlib.Path(core_library)),
    ("high_level", "libhdf5_hl.so.", pathlib.Path(high_level_library)),
):
    matches = [name for name in needed if name.startswith(prefix)]
    if len(matches) != 1:
        raise SystemExit(f"expected one DT_NEEDED entry for {role}, observed {matches}")
    needed_name = matches[0]
    loader_path = library_dir / needed_name
    if not loader_path.is_symlink():
        raise SystemExit(f"runtime loader path is not a symlink: {loader_path}")
    resolved_path = loader_path.resolve(strict=True)
    if resolved_path != component.resolve(strict=True):
        raise SystemExit(
            f"runtime loader path for {role} does not resolve to the hashed component"
        )
    runtime_bindings.append(
        {
            "role": role,
            "needed": needed_name,
            "loader_path": str(loader_path),
            "resolved_path": str(resolved_path),
            "sha256": sha(resolved_path),
        }
    )
linkage["runtime_library_bindings"] = runtime_bindings
profile = {
    "schema_version": "hdf5-weights-build-profile-v1",
    "target_id": "hdf5-weights",
    "target_version": "2.2.0",
    "status": "provisioned",
    "source_artifacts": [source],
    "patches": [],
    "toolchain": {
        "cmake": tool(cmake_path, [cmake_path, "--version"]),
        "c_compiler": tool(compiler_path, [compiler_path, "--version"]),
        "cxx_compiler": tool(cxx_compiler_path, [cxx_compiler_path, "--version"]),
        "linker": tool(linker_path, [linker_path, "--version"]),
        "ninja": tool(ninja_path, [ninja_path, "--version"]),
        "readelf": tool(readelf_path, [readelf_path, "--version"]),
    },
    "cmake_options": options,
    "compile_flags": ["-O1", "-g", "-DNDEBUG"],
    "filter_contract": filter_contract,
    "components": {
        "core": file_identity(core_library),
        "high_level": file_identity(high_level_library),
        "probe": file_identity(probe_path),
    },
    "evidence_files": {
        "cmake_cache": file_identity(cmake_cache),
        "compile_commands": file_identity(compile_commands),
        "install_manifest": file_identity(install_manifest),
        "link_commands": file_identity(link_commands),
        "probe_cmake_cache": file_identity(probe_cmake_cache),
        "probe_compile_commands": file_identity(probe_compile_commands),
        "probe_link_commands": file_identity(probe_link_commands),
        "linker_trace": file_identity(linker_trace),
        "build_log": file_identity(build_log),
        "probe_build_log": file_identity(probe_build_log),
    },
    "linkage_manifest": os.path.realpath(linkage_path),
    "probe_contract": {
        "api": "H5LTopen_file_image(buffer, size, 0)",
        "input": "runtime-generated-core-driver-image",
        "expected_marker": expected_marker,
        "required_calls": 3,
    },
    "execution_profile_ready": False,
    "next_card": "HDF-02",
}
meta = {
    "schema_version": "1.0",
    "target": "hdf5-weights",
    "version": "2.2.0",
    "source_kind": "official_release",
    "source_artifacts": [source],
}
for path, document in ((meta_path, meta), (linkage_path, linkage), (profile_path, profile)):
    destination = pathlib.Path(path)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=destination.parent,
        prefix=f".{destination.name}.",
        delete=False,
    ) as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    os.replace(temporary, destination)
PY

python3 -B "$SCRIPT_DIR/check_hdf5_profile.py" --target-root "$TARGET_ROOT" \
  >"$TARGET_ROOT/check.log" 2>&1 \
  || { cat "$TARGET_ROOT/check.log" >&2; fail "generated profile failed validation"; }
cat "$TARGET_ROOT/check.log"
log "done"
printf 'profile=%s\nmeta=%s\nlinkage=%s\nprobe=%s\n' \
  "$PROFILE" "$META" "$LINKAGE" "$PROBE"
