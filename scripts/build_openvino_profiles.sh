#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd -P)}"
OVI_VERSION=2026.4.1
OVI_COMMIT=e213a14725769a6a2bf86fc86650aa78a9c05d3e
OVI_URL=https://github.com/openvinotoolkit/openvino/archive/refs/tags/2026.4.1.tar.gz
OVI_SHA256=1ee85264556025486a4745a2d452ea823c578b3d162768bfef590366d2e6c539
OVI_SIZE=71349787
PUGIXML_COMMIT=ee86beb30e4973f5feffe3ce63bfa4fbadf72f38
PUGIXML_SHA256=51c102d4187fac99daa38af281b0772c5e6c586f65004cdc63f8f2e011a21492
PUGIXML_SIZE=583144
XBYAK_COMMIT=431abd865e70a46d56f5aa0e1f87572decb60169
XBYAK_SHA256=3d80df7150abaa2103a0c50bbc3e2a100fd7866b3c90e9608783c0a5c785bbe8
XBYAK_SIZE=563317
JSON_COMMIT=9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03
JSON_SHA256=0dbc5e40a01ff142e7e68c03e85247a4dcede2f592d12d3677dee3664d17975a
JSON_SIZE=8054631

TARGET_ROOT_INPUT="${OPENVINO_TARGET_ROOT:-$PROJECT_ROOT/data/targets/openvino-ir/$OVI_VERSION}"
while [[ "$TARGET_ROOT_INPUT" != / && "$TARGET_ROOT_INPUT" == */ ]]; do
  TARGET_ROOT_INPUT="${TARGET_ROOT_INPUT%/}"
done
[[ "$TARGET_ROOT_INPUT" = /* ]] || {
  printf '[build-openvino] fail: OPENVINO_TARGET_ROOT must be absolute: %s\n' "$TARGET_ROOT_INPUT" >&2
  exit 1
}
[[ ! -L "$TARGET_ROOT_INPUT" ]] || {
  printf '[build-openvino] fail: OPENVINO_TARGET_ROOT must not be a symlink: %s\n' "$TARGET_ROOT_INPUT" >&2
  exit 1
}
TARGET_ROOT="$(realpath -m -- "$TARGET_ROOT_INPUT")"
case "$TARGET_ROOT" in
  ""|/|"$PROJECT_ROOT"|"${HOME:-__unset_home__}")
    printf '[build-openvino] fail: unsafe OPENVINO_TARGET_ROOT: %s\n' "$TARGET_ROOT" >&2
    exit 1
    ;;
esac
ARCHIVE="${OPENVINO_ARCHIVE:-$TARGET_ROOT/source/$OVI_VERSION.tar.gz}"
DEPENDENCY_ROOT="$TARGET_ROOT/source/dependencies"
PUGIXML_ARCHIVE="$DEPENDENCY_ROOT/pugixml-$PUGIXML_COMMIT.tar.gz"
XBYAK_ARCHIVE="$DEPENDENCY_ROOT/xbyak-$XBYAK_COMMIT.tar.gz"
JSON_ARCHIVE="$DEPENDENCY_ROOT/nlohmann-json-$JSON_COMMIT.tar.gz"
SOURCE_DIR="$TARGET_ROOT/build/source"
BUILD_DIR="$TARGET_ROOT/build/cmake"
INSTALL_DIR="$TARGET_ROOT/install"
PROBE_BUILD_DIR="$TARGET_ROOT/build/probe"
PROBE="$TARGET_ROOT/bin/openvino_ir_frontend_probe"
META="$TARGET_ROOT/meta.json"
PROFILE="$TARGET_ROOT/build-profile.json"
LINKAGE="$TARGET_ROOT/linkage-manifest.json"
LINK_COMMANDS="$TARGET_ROOT/link-commands.txt"
JOBS="${JOBS:-4}"

fail() {
  printf '[build-openvino] fail: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[build-openvino] %s\n' "$*"
}

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

verify_archive() {
  local label="$1"
  local path="$2"
  local expected_sha="$3"
  local expected_size="$4"
  [[ -f "$path" && ! -L "$path" ]] || fail "$label archive is missing or unsafe: $path"
  [[ "$(sha256sum "$path" | cut -d' ' -f1)" == "$expected_sha" ]] \
    || fail "$label archive sha256 mismatch: $path"
  [[ "$(stat -c '%s' "$path")" == "$expected_size" ]] \
    || fail "$label archive size mismatch: $path"
}

verify_archive openvino "$ARCHIVE" "$OVI_SHA256" "$OVI_SIZE"
verify_archive pugixml "$PUGIXML_ARCHIVE" "$PUGIXML_SHA256" "$PUGIXML_SIZE"
verify_archive xbyak "$XBYAK_ARCHIVE" "$XBYAK_SHA256" "$XBYAK_SIZE"
verify_archive nlohmann-json "$JSON_ARCHIVE" "$JSON_SHA256" "$JSON_SIZE"
log "verified official release and exact dependency archives"

source_contract="$OVI_SHA256:$PUGIXML_SHA256:$XBYAK_SHA256:$JSON_SHA256"
source_stamp="$SOURCE_DIR/.tool-source-contract"
if [[ ! -f "$source_stamp" ]] || [[ "$(cat "$source_stamp")" != "$source_contract" ]]; then
  log "extracting pinned OpenVINO source and required gitlink archives"
  rm -rf -- "$SOURCE_DIR"
  mkdir -p -- "$SOURCE_DIR"
  tar -xzf "$ARCHIVE" -C "$SOURCE_DIR" --strip-components=1
  for spec in \
    "$PUGIXML_ARCHIVE:thirdparty/pugixml" \
    "$XBYAK_ARCHIVE:thirdparty/xbyak" \
    "$JSON_ARCHIVE:thirdparty/json/nlohmann_json"
  do
    dependency_archive="${spec%%:*}"
    dependency_dir="$SOURCE_DIR/${spec#*:}"
    mkdir -p -- "$dependency_dir"
    tar -xzf "$dependency_archive" -C "$dependency_dir" --strip-components=1
  done
  printf '%s\n' "$source_contract" >"$source_stamp"
fi
for required in \
  "$SOURCE_DIR/CMakeLists.txt" \
  "$SOURCE_DIR/src/frontends/ir/src/frontend.cpp" \
  "$SOURCE_DIR/thirdparty/pugixml/CMakeLists.txt" \
  "$SOURCE_DIR/thirdparty/xbyak/CMakeLists.txt" \
  "$SOURCE_DIR/thirdparty/json/nlohmann_json/CMakeLists.txt"
do
  [[ -f "$required" && ! -L "$required" ]] || fail "required pinned source is missing: $required"
done

mkdir -p -- "$BUILD_DIR" "$INSTALL_DIR" "$PROBE_BUILD_DIR" "$(dirname -- "$PROBE")"
log "configuring Core + IR frontend only"
"$CMAKE" -G Ninja \
  -S "$SOURCE_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CLANG" \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO='-O1 -g -DNDEBUG' \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO='-O1 -g -DNDEBUG' \
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
  >"$TARGET_ROOT/configure.log" 2>&1 \
  || fail "OpenVINO configure failed; see $TARGET_ROOT/configure.log"

log "building OpenVINO Core + required C export + IR frontend (jobs=$JOBS)"
"$CMAKE" --build "$BUILD_DIR" --target openvino openvino_c openvino_ir_frontend -j"$JOBS" \
  >"$TARGET_ROOT/build.log" 2>&1 \
  || fail "OpenVINO build failed; see $TARGET_ROOT/build.log"
rm -rf -- "$INSTALL_DIR"
mkdir -p -- "$INSTALL_DIR"
"$CMAKE" --install "$BUILD_DIR" >"$TARGET_ROOT/install.log" 2>&1 \
  || fail "OpenVINO install failed; see $TARGET_ROOT/install.log"
"$NINJA" -C "$BUILD_DIR" -t commands openvino openvino_c openvino_ir_frontend >"$LINK_COMMANDS"

OPENVINO_CONFIG="$(find "$INSTALL_DIR" -type f -name OpenVINOConfig.cmake -print -quit)"
[[ -n "$OPENVINO_CONFIG" ]] || fail "installed OpenVINOConfig.cmake not found"
OPENVINO_CMAKE_DIR="$(dirname -- "$OPENVINO_CONFIG")"
log "building the in-memory IR frontend probe"
"$CMAKE" -G Ninja \
  -S "$PROJECT_ROOT/harnesses/openvino" \
  -B "$PROBE_BUILD_DIR" \
  -DOpenVINO_DIR="$OPENVINO_CMAKE_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  >"$TARGET_ROOT/probe-configure.log" 2>&1 \
  || fail "probe configure failed; see $TARGET_ROOT/probe-configure.log"
"$CMAKE" --build "$PROBE_BUILD_DIR" --target openvino_ir_frontend_probe -j"$JOBS" \
  >"$TARGET_ROOT/probe-build.log" 2>&1 \
  || fail "probe build failed; see $TARGET_ROOT/probe-build.log"
[[ -x "$PROBE_BUILD_DIR/openvino_ir_frontend_probe" ]] \
  || fail "probe build produced no executable"
install -m 0755 "$PROBE_BUILD_DIR/openvino_ir_frontend_probe" "$PROBE"

probe_output="$($PROBE 2>&1)" || fail "in-memory IR frontend probe failed: $probe_output"
[[ "$probe_output" == 'OPENVINO_IR_FRONTEND_OK nodes=2 parameters=1 results=1' ]] \
  || fail "unexpected probe output: $probe_output"

CORE_LIBRARY="$(find "$INSTALL_DIR" -type f -name 'libopenvino.so.*' -print | sort | head -1)"
IR_LIBRARY="$(find "$INSTALL_DIR" -type f -name 'libopenvino_ir_frontend.so.*' -print | sort | head -1)"
[[ -f "$CORE_LIBRARY" && ! -L "$CORE_LIBRARY" ]] || fail "installed Core library not found"
[[ -f "$IR_LIBRARY" && ! -L "$IR_LIBRARY" ]] || fail "installed IR frontend library not found"

python3 -B - \
  "$TARGET_ROOT" "$META" "$PROFILE" "$LINKAGE" "$ARCHIVE" \
  "$PUGIXML_ARCHIVE" "$XBYAK_ARCHIVE" "$JSON_ARCHIVE" \
  "$CMAKE" "$CLANG_REAL" "$CLANGXX_REAL" "$NINJA" \
  "$CORE_LIBRARY" "$IR_LIBRARY" "$PROBE" "$READELF" \
  "$BUILD_DIR/CMakeCache.txt" "$BUILD_DIR/compile_commands.json" \
  "$BUILD_DIR/install_manifest.txt" "$LINK_COMMANDS" \
  "$PROBE_BUILD_DIR/compile_commands.json" "$OVI_URL" "$OVI_COMMIT" <<'PY'
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
    pugixml_archive,
    xbyak_archive,
    json_archive,
    cmake_path,
    compiler_path,
    linker_path,
    ninja_path,
    core_library,
    ir_library,
    probe_path,
    readelf_path,
    cmake_cache,
    compile_commands,
    install_manifest,
    link_commands,
    probe_compile_commands,
    source_url,
    source_commit,
) = sys.argv[1:]

def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def first_line(command):
    return subprocess.check_output(command, text=True).splitlines()[0]

source_specs = [
    {
        "name": "openvino",
        "url": source_url,
        "tag": "2026.4.1",
        "resolved_commit": source_commit,
        "sha256": sha(archive_path),
        "size_bytes": os.path.getsize(archive_path),
    },
    {
        "name": "pugixml",
        "url": "https://github.com/zeux/pugixml/archive/ee86beb30e4973f5feffe3ce63bfa4fbadf72f38.tar.gz",
        "tag": "ee86beb30e4973f5feffe3ce63bfa4fbadf72f38",
        "resolved_commit": "ee86beb30e4973f5feffe3ce63bfa4fbadf72f38",
        "sha256": sha(pugixml_archive),
        "size_bytes": os.path.getsize(pugixml_archive),
    },
    {
        "name": "xbyak",
        "url": "https://github.com/herumi/xbyak/archive/431abd865e70a46d56f5aa0e1f87572decb60169.tar.gz",
        "tag": "431abd865e70a46d56f5aa0e1f87572decb60169",
        "resolved_commit": "431abd865e70a46d56f5aa0e1f87572decb60169",
        "sha256": sha(xbyak_archive),
        "size_bytes": os.path.getsize(xbyak_archive),
    },
    {
        "name": "nlohmann-json",
        "url": "https://github.com/nlohmann/json/archive/9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03.tar.gz",
        "tag": "9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03",
        "resolved_commit": "9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03",
        "sha256": sha(json_archive),
        "size_bytes": os.path.getsize(json_archive),
    },
]
options = {
    "BUILD_SHARED_LIBS": "ON",
    "CMAKE_BUILD_TYPE": "RelWithDebInfo",
    "ENABLE_AUTO": "OFF",
    "ENABLE_AUTO_BATCH": "OFF",
    "ENABLE_DOCS": "OFF",
    "ENABLE_HETERO": "OFF",
    "ENABLE_INTEL_CPU": "OFF",
    "ENABLE_INTEL_GPU": "OFF",
    "ENABLE_INTEL_NPU": "OFF",
    "ENABLE_IO_URING": "OFF",
    "ENABLE_JS": "OFF",
    "ENABLE_LTO": "OFF",
    "ENABLE_MULTI": "OFF",
    "ENABLE_OV_GGUF_FRONTEND": "OFF",
    "ENABLE_OV_IR_FRONTEND": "ON",
    "ENABLE_OV_JAX_FRONTEND": "OFF",
    "ENABLE_OV_ONNX_FRONTEND": "OFF",
    "ENABLE_OV_PADDLE_FRONTEND": "OFF",
    "ENABLE_OV_PYTORCH_FRONTEND": "OFF",
    "ENABLE_OV_TF_FRONTEND": "OFF",
    "ENABLE_OV_TF_LITE_FRONTEND": "OFF",
    "ENABLE_PKGCONFIG_GEN": "OFF",
    "ENABLE_PLUGINS_XML": "OFF",
    "ENABLE_PROFILING_ITT": "OFF",
    "ENABLE_PROXY": "OFF",
    "ENABLE_PYTHON": "OFF",
    "ENABLE_SAMPLES": "OFF",
    "ENABLE_SYSTEM_PUGIXML": "OFF",
    "ENABLE_TEMPLATE": "OFF",
    "ENABLE_TESTS": "OFF",
    "THREADING": "SEQ",
}

installed = sorted(
    str(path.resolve())
    for path in pathlib.Path(target_root, "install").rglob("*.so*")
    if path.is_file() and not path.is_symlink()
)
dynamic = subprocess.check_output([readelf_path, "-d", probe_path], text=True)
needed = re.findall(r"Shared library: \[([^]]+)\]", dynamic)
linkage = {
    "schema_version": "openvino-ir-linkage-v1",
    "libraries": [
        {"role": "core", "path": os.path.realpath(core_library), "sha256": sha(core_library)},
        {"role": "ir_frontend", "path": os.path.realpath(ir_library), "sha256": sha(ir_library)},
    ],
    "installed_shared_libraries": installed,
    "probe_dynamic_dependencies": needed,
}

def tool(path, command):
    return {
        "path": os.path.realpath(path),
        "sha256": sha(os.path.realpath(path)),
        "version": first_line(command),
    }

def file_identity(path):
    return {"path": os.path.realpath(path), "sha256": sha(path)}

profile = {
    "schema_version": "openvino-ir-build-profile-v1",
    "target_id": "openvino-ir",
    "target_version": "2026.4.1",
    "status": "provisioned",
    "source_artifacts": source_specs,
    "patches": [],
    "toolchain": {
        "cmake": tool(cmake_path, [cmake_path, "--version"]),
        "compiler": tool(compiler_path, [compiler_path, "--version"]),
        "linker": tool(linker_path, [linker_path, "--version"]),
        "ninja": tool(ninja_path, [ninja_path, "--version"]),
        "readelf": tool(readelf_path, [readelf_path, "--version"]),
    },
    "cmake_options": options,
    "compile_flags": ["-O1", "-g", "-DNDEBUG"],
    "components": {
        "core": file_identity(core_library),
        "ir_frontend": file_identity(ir_library),
        "probe": file_identity(probe_path),
    },
    "evidence_files": {
        "cmake_cache": file_identity(cmake_cache),
        "compile_commands": file_identity(compile_commands),
        "install_manifest": file_identity(install_manifest),
        "link_commands": file_identity(link_commands),
        "probe_compile_commands": file_identity(probe_compile_commands),
    },
    "linkage_manifest": os.path.realpath(linkage_path),
    "probe_contract": {
        "api": "ov::Core::read_model(model_text, weights)",
        "input": "embedded-memory-ir-v11",
        "expected_marker": "OPENVINO_IR_FRONTEND_OK nodes=2 parameters=1 results=1",
    },
    "execution_profile_ready": False,
    "next_card": "OVI-02",
}
meta = {
    "schema_version": "1.0",
    "target": "openvino-ir",
    "version": "2026.4.1",
    "source_kind": "official_release",
    "source_artifacts": source_specs,
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

python3 -B "$SCRIPT_DIR/check_openvino_profile.py" --target-root "$TARGET_ROOT" \
  >"$TARGET_ROOT/check.log" 2>&1 \
  || { cat "$TARGET_ROOT/check.log" >&2; fail "generated profile failed validation"; }
cat "$TARGET_ROOT/check.log"
log "done"
printf 'profile=%s\nmeta=%s\nlinkage=%s\nprobe=%s\n' \
  "$PROFILE" "$META" "$LINKAGE" "$PROBE"
