#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd -P)}"
TFLITE_VERSION="v2.20.0"
TFLITE_COMMIT="72fbba3d20f4616d7312b5e2b7f79daf6e82f2fa"
TFLITE_URL="https://github.com/tensorflow/tensorflow/archive/refs/tags/v2.20.0.tar.gz"
TFLITE_SHA256="a640d1f97be316a09301dfc9347e3d929ad4d9a2336e3ca23c32c93b0ff7e5d0"
TFLITE_SIZE=84813578
PATCH="$PROJECT_ROOT/patches/tflite_v2.20.0_xnnpack_off.cmake.patch"

TARGET_ROOT="${TFLITE_TARGET_ROOT:-$PROJECT_ROOT/data/targets/tflite/$TFLITE_VERSION}"
ARCHIVE="${TFLITE_ARCHIVE:-$TARGET_ROOT/source/$TFLITE_VERSION.tar.gz}"
SOURCE_DIR="$TARGET_ROOT/build/source"
BUILD_DIR="$TARGET_ROOT/build/cmake"
FIXTURE_DIR="$TARGET_ROOT/fixtures"
OUT_REPLAY="${TFLITE_REPLAY:-$PROJECT_ROOT/harnesses/tflite/tflite_loader_replay}"
OUT_FUZZER="${TFLITE_FUZZER:-$PROJECT_ROOT/harnesses/tflite/tflite_loader_fuzzer}"
OUT_MUTATOR="${TFLITE_MUTATOR:-$PROJECT_ROOT/harnesses/tflite/tflite_structural_mutator}"
PROFILE="$TARGET_ROOT/profile.json"
IDENTITY="$TARGET_ROOT/build-identity.json"
META="$TARGET_ROOT/meta.json"
JOBS="${JOBS:-4}"

fail() {
  printf '[build-tflite] fail: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[build-tflite] %s\n' "$*"
}

case "$TARGET_ROOT" in
  ""|/|"$PROJECT_ROOT"|"${HOME:-__unset_home__}")
    fail "unsafe TFLITE_TARGET_ROOT: $TARGET_ROOT"
    ;;
esac
[[ "$OUT_REPLAY" != "$OUT_FUZZER" ]] \
  || fail "replay and fuzzer outputs must differ: $OUT_REPLAY"
[[ "$OUT_REPLAY" != "$OUT_MUTATOR" ]] \
  || fail "replay and mutator outputs must differ: $OUT_REPLAY"
[[ "$OUT_FUZZER" != "$OUT_MUTATOR" ]] \
  || fail "fuzzer and mutator outputs must differ: $OUT_FUZZER"

CMAKE="${CMAKE:-$(command -v cmake || true)}"
NINJA="${NINJA:-$(command -v ninja || true)}"
CLANGXX="${CLANGXX:-$(command -v clang++ || true)}"
CLANG="${CLANG:-$(command -v clang || true)}"
[[ -x "$CMAKE" ]] || fail "cmake not found"
[[ -x "$NINJA" ]] || fail "ninja not found"
[[ -x "$CLANGXX" ]] || fail "clang++ not found"
[[ -x "$CLANG" ]] || fail "clang not found"
[[ -f "$PATCH" ]] || fail "required v2.20.0 CMake patch not found: $PATCH"
CLANGXX_INVOKE="$CLANGXX"
CLANG_INVOKE="$CLANG"
CLANGXX="$(readlink -f -- "$CLANGXX")"
CLANG="$(readlink -f -- "$CLANG")"
CMAKE="$(readlink -f -- "$CMAKE")"
NINJA="$(readlink -f -- "$NINJA")"
TF_RELEASE_FLAGS="-DTF_MAJOR_VERSION=2 -DTF_MINOR_VERSION=20 -DTF_PATCH_VERSION=0 -DTF_VERSION_SUFFIX=''"

[[ -f "$ARCHIVE" ]] || fail "pinned source archive not found: $ARCHIVE"
actual_sha="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
actual_size="$(stat -c '%s' "$ARCHIVE")"
[[ "$actual_sha" == "$TFLITE_SHA256" ]] \
  || fail "source archive sha256 mismatch: expected $TFLITE_SHA256 observed $actual_sha"
[[ "$actual_size" == "$TFLITE_SIZE" ]] \
  || fail "source archive size mismatch: expected $TFLITE_SIZE observed $actual_size"
log "source pin verified: $TFLITE_VERSION $TFLITE_COMMIT"

source_stamp="$SOURCE_DIR/.tool-source-sha256"
patch_stamp="$SOURCE_DIR/.tool-patch-sha256"
patch_sha="$(sha256sum "$PATCH" | cut -d' ' -f1)"
if [[ ! -f "$source_stamp" \
      || "$(cat "$source_stamp")" != "$TFLITE_SHA256" \
      || ! -f "$patch_stamp" \
      || "$(cat "$patch_stamp")" != "$patch_sha" ]]; then
  log "extracting pinned TensorFlow source"
  rm -rf -- "$SOURCE_DIR"
  mkdir -p -- "$SOURCE_DIR"
  tar -xzf "$ARCHIVE" -C "$SOURCE_DIR" --strip-components=1
  printf '%s\n' "$TFLITE_SHA256" >"$source_stamp"
  patch --batch --forward --fuzz=0 -p1 -d "$SOURCE_DIR" <"$PATCH" \
    >"$TARGET_ROOT/patch.log" 2>&1 \
    || fail "v2.20.0 CMake patch failed; see $TARGET_ROOT/patch.log"
  printf '%s\n' "$patch_sha" >"$patch_stamp"
fi

[[ -f "$SOURCE_DIR/tensorflow/lite/CMakeLists.txt" ]] \
  || fail "extracted source has no tensorflow/lite/CMakeLists.txt"
[[ -f "$SOURCE_DIR/tensorflow/lite/testdata/add.bin" ]] \
  || fail "extracted source has no official ADD model"

# These are the dependencies reached by the delegate-free v2.20.0 CMake graph.
# Checking the official module text before configure makes a changed or locally
# patched pin fail closed instead of silently fetching a different source.
declare -A DEP_PIN_FILES=(
  [abseil-cpp]="abseil-cpp.cmake:d9e4955c65cd4367dd6bf46f4ccb8cd3d100540b"
  [cpuinfo]="cpuinfo.cmake:de0ce7c7251372892e53ce9bc891750d2c9a4fd8"
  [eigen]="eigen.cmake:4c38131a16803130b66266a912029504f2cf23cd"
  [farmhash]="farmhash.cmake:0d859a811870d10f53a594927d0d0b97573ad06d"
  [fft2d]="fft2d.cmake:5f4dabc2ae21e1f537425d58a49cdca1c49ea11db0d6271e2a4b27e9697548eb"
  [flatbuffers]="flatbuffers.cmake:e6463926479bd6b330cbcf673f7e917803fd5831"
  [fp16_headers]="fp16_headers.cmake:0a92994d729ff76a58f692d3028ca1b64b145d91"
  [gemmlowp]="gemmlowp.cmake:16e8662c34917be0065110bfcd9cc27d30f52fdf"
  [ml_dtypes]="ml_dtypes.cmake:00d98cd92ade342fef589c0470379abb27baebe9"
  [neon2sse]="neon2sse.cmake:019fbc7ec25860070a1d90e12686fc160cfb33e22aa063c80f52b363f1361e9d"
  [protobuf]="protobuf.cmake:90b73ac3f0b10320315c2ca0d03a5a9b095d2f66"
  [ruy]="ruy.cmake:3286a34cc8de6149ac6844107dfdffac91531e72"
)
module_root="$SOURCE_DIR/tensorflow/lite/tools/cmake/modules"
for name in "${!DEP_PIN_FILES[@]}"; do
  value="${DEP_PIN_FILES[$name]}"
  module="${value%%:*}"
  pin="${value#*:}"
  grep -Fq -- "$pin" "$module_root/$module" \
    || fail "official dependency pin missing for $name ($pin)"
done

mkdir -p -- "$BUILD_DIR"
log "configuring delegate-free CPU loader"
"$CMAKE" -G Ninja \
  -S "$PROJECT_ROOT/harnesses/tflite" \
  -B "$BUILD_DIR" \
  -DTENSORFLOW_SOURCE_DIR="$SOURCE_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CLANG_INVOKE" \
  -DCMAKE_CXX_COMPILER="$CLANGXX_INVOKE" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O1 -g -DNDEBUG $TF_RELEASE_FLAGS" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O1 -g -DNDEBUG $TF_RELEASE_FLAGS" \
  -DBUILD_SHARED_LIBS=OFF \
  -DTFLITE_ENABLE_EXTERNAL_DELEGATE=OFF \
  -DTFLITE_ENABLE_GPU=OFF \
  -DTFLITE_ENABLE_METAL=OFF \
  -DTFLITE_ENABLE_NNAPI=OFF \
  -DTFLITE_ENABLE_RUY=OFF \
  -DTFLITE_ENABLE_XNNPACK=OFF \
  -DTFLITE_KERNEL_TEST=OFF \
  >"$TARGET_ROOT/configure.log" 2>&1 \
  || fail "CMake configure failed; see $TARGET_ROOT/configure.log"

for setting in \
  'BUILD_SHARED_LIBS:UNINITIALIZED=OFF' \
  'TFLITE_ENABLE_EXTERNAL_DELEGATE:BOOL=OFF' \
  'TFLITE_ENABLE_GPU:BOOL=OFF' \
  'TFLITE_ENABLE_METAL:BOOL=OFF' \
  'TFLITE_ENABLE_NNAPI:BOOL=OFF' \
  'TFLITE_ENABLE_RUY:BOOL=OFF' \
  'TFLITE_ENABLE_XNNPACK:BOOL=OFF' \
  'TFLITE_KERNEL_TEST:BOOL=OFF'
do
  grep -Fqx -- "$setting" "$BUILD_DIR/CMakeCache.txt" \
    || fail "configured cache does not contain $setting"
done

declare -A GIT_DEP_COMMITS=(
  [abseil-cpp]="d9e4955c65cd4367dd6bf46f4ccb8cd3d100540b"
  [cpuinfo]="de0ce7c7251372892e53ce9bc891750d2c9a4fd8"
  [eigen]="4c38131a16803130b66266a912029504f2cf23cd"
  [farmhash]="0d859a811870d10f53a594927d0d0b97573ad06d"
  [flatbuffers]="e6463926479bd6b330cbcf673f7e917803fd5831"
  [fp16_headers]="0a92994d729ff76a58f692d3028ca1b64b145d91"
  [gemmlowp]="16e8662c34917be0065110bfcd9cc27d30f52fdf"
  [ml_dtypes]="00d98cd92ade342fef589c0470379abb27baebe9"
  [protobuf]="90b73ac3f0b10320315c2ca0d03a5a9b095d2f66"
  [ruy]="3286a34cc8de6149ac6844107dfdffac91531e72"
)
for name in "${!GIT_DEP_COMMITS[@]}"; do
  dep_dir="$BUILD_DIR/$name"
  [[ -d "$dep_dir/.git" ]] || fail "configured dependency is not a Git checkout: $dep_dir"
  observed="$(git -C "$dep_dir" rev-parse HEAD)"
  [[ "$observed" == "${GIT_DEP_COMMITS[$name]}" ]] \
    || fail "$name commit mismatch: expected ${GIT_DEP_COMMITS[$name]} observed $observed"
done
[[ -d "$BUILD_DIR/fft2d" ]] || fail "configured fft2d source is missing"
[[ -d "$BUILD_DIR/neon2sse" ]] || fail "configured neon2sse source is missing"

log "building pinned flatc, replay, shared-loader fuzzer, and schema mutator (jobs=$JOBS)"
"$CMAKE" --build "$BUILD_DIR" --target flatbuffers-flatc tflite_loader_replay tflite_loader_fuzzer tflite_structural_mutator -j"$JOBS" \
  >"$TARGET_ROOT/build.log" 2>&1 \
  || fail "loader build failed; see $TARGET_ROOT/build.log"
built_replay="$BUILD_DIR/tflite_loader_replay"
built_fuzzer="$BUILD_DIR/tflite_loader_fuzzer"
built_mutator="$BUILD_DIR/tflite_structural_mutator"
flatc_binary="$BUILD_DIR/flatbuffers-flatc/bin/flatc"
[[ -x "$built_replay" ]] || fail "build produced no replay executable: $built_replay"
[[ -x "$built_fuzzer" ]] || fail "build produced no fuzzer executable: $built_fuzzer"
[[ -x "$built_mutator" ]] || fail "build produced no structural mutator executable: $built_mutator"
[[ -x "$flatc_binary" ]] || fail "build produced no pinned flatc executable: $flatc_binary"

# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT_REPLAY || exit 1
staged_target OUT_FUZZER || exit 1
staged_target OUT_MUTATOR || exit 1
[[ "$OUT_REPLAY" != "$OUT_FUZZER" ]] \
  || fail "replay and fuzzer outputs must differ after symlink resolution: $OUT_REPLAY"
[[ "$OUT_REPLAY" != "$OUT_MUTATOR" ]] \
  || fail "replay and mutator outputs must differ after symlink resolution: $OUT_REPLAY"
[[ "$OUT_FUZZER" != "$OUT_MUTATOR" ]] \
  || fail "fuzzer and mutator outputs must differ after symlink resolution: $OUT_FUZZER"
trap staged_cleanup EXIT
staged_new "$OUT_REPLAY" STAGED_REPLAY || exit 1
staged_new "$OUT_FUZZER" STAGED_FUZZER || exit 1
staged_new "$OUT_MUTATOR" STAGED_MUTATOR || exit 1
cp -- "$built_replay" "$STAGED_REPLAY"
cp -- "$built_fuzzer" "$STAGED_FUZZER"
cp -- "$built_mutator" "$STAGED_MUTATOR"
staged_commit "$STAGED_REPLAY" "$OUT_REPLAY" || exit 1
staged_commit "$STAGED_FUZZER" "$OUT_FUZZER" || exit 1
staged_commit "$STAGED_MUTATOR" "$OUT_MUTATOR" || exit 1
trap - EXIT

mkdir -p -- "$FIXTURE_DIR"
cp -- "$SOURCE_DIR/tensorflow/lite/testdata/add.bin" "$FIXTURE_DIR/add.tflite"

"$NINJA" -C "$BUILD_DIR" -t commands tflite_loader_replay tflite_loader_fuzzer tflite_structural_mutator \
  >"$TARGET_ROOT/link-commands.txt"

python3 -B - \
  "$IDENTITY" "$PROFILE" "$META" "$ARCHIVE" "$SOURCE_DIR" "$BUILD_DIR" \
  "$OUT_REPLAY" "$OUT_FUZZER" "$OUT_MUTATOR" "$FIXTURE_DIR/add.tflite" "$CLANGXX" "$CLANGXX_INVOKE" "$CMAKE" "$PATCH" "$flatc_binary" \
  "$TARGET_ROOT/link-commands.txt" "$TFLITE_URL" "$TFLITE_COMMIT" <<'PY'
import hashlib
import json
import os
import pathlib
import subprocess
import sys

(
    identity_path,
    profile_path,
    meta_path,
    archive_path,
    source_root,
    build_root,
    replay_path,
    fuzzer_path,
    mutator_path,
    add_model_path,
    compiler_path,
    compiler_invocation_path,
    cmake_path,
    patch_path,
    flatc_path,
    link_commands_path,
    source_url,
    source_commit,
) = sys.argv[1:]

def file_sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def tree_identity(path):
    root = pathlib.Path(path)
    digest = hashlib.sha256()
    total = 0
    for item in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        relative = item.relative_to(root)
        if ".git" in relative.parts or item.is_dir():
            continue
        encoded = relative.as_posix().encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        if item.is_symlink():
            content = os.readlink(item).encode("utf-8")
        else:
            content = item.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        total += len(content)
    return digest.hexdigest(), total

def first_line(command):
    return subprocess.check_output(command, text=True).splitlines()[0]

dependency_specs = [
    ("abseil-cpp", "https://github.com/abseil/abseil-cpp", "d9e4955c65cd4367dd6bf46f4ccb8cd3d100540b", None),
    ("cpuinfo", "https://github.com/pytorch/cpuinfo", "de0ce7c7251372892e53ce9bc891750d2c9a4fd8", None),
    ("eigen", "https://gitlab.com/libeigen/eigen", "4c38131a16803130b66266a912029504f2cf23cd", None),
    ("farmhash", "https://github.com/google/farmhash", "0d859a811870d10f53a594927d0d0b97573ad06d", None),
    ("fft2d", "https://storage.googleapis.com/mirror.tensorflow.org/github.com/petewarden/OouraFFT/archive/v1.0.tar.gz", "v1.0", "5f4dabc2ae21e1f537425d58a49cdca1c49ea11db0d6271e2a4b27e9697548eb"),
    ("flatbuffers", "https://github.com/google/flatbuffers", "e6463926479bd6b330cbcf673f7e917803fd5831", None),
    ("fp16_headers", "https://github.com/Maratyszcza/FP16", "0a92994d729ff76a58f692d3028ca1b64b145d91", None),
    ("gemmlowp", "https://github.com/google/gemmlowp", "16e8662c34917be0065110bfcd9cc27d30f52fdf", None),
    ("ml_dtypes", "https://github.com/jax-ml/ml_dtypes", "00d98cd92ade342fef589c0470379abb27baebe9", None),
    ("neon2sse", "https://storage.googleapis.com/mirror.tensorflow.org/github.com/intel/ARM_NEON_2_x86_SSE/archive/a15b489e1222b2087007546b4912e21293ea86ff.tar.gz", "a15b489e1222b2087007546b4912e21293ea86ff", "019fbc7ec25860070a1d90e12686fc160cfb33e22aa063c80f52b363f1361e9d"),
    ("protobuf", "https://github.com/protocolbuffers/protobuf", "90b73ac3f0b10320315c2ca0d03a5a9b095d2f66", None),
    ("ruy", "https://github.com/google/ruy", "3286a34cc8de6149ac6844107dfdffac91531e72", None),
]
dependencies = []
source_artifacts = [{
    "url": source_url,
    "tag": "v2.20.0",
    "resolved_commit": source_commit,
    "sha256": file_sha(archive_path),
    "size_bytes": os.path.getsize(archive_path),
}]
target_meta = {
    "schema_version": "1.0",
    "target": "tflite",
    "version": "v2.20.0",
    "source_url": source_url,
    "source_kind": "official_release",
    "downloaded_file": archive_path,
    "downloaded_sha256": source_artifacts[0]["sha256"],
    "downloaded_size_bytes": source_artifacts[0]["size_bytes"],
}
for name, url, commit, archive_sha in dependency_specs:
    tree_sha, tree_size = tree_identity(os.path.join(build_root, name))
    row = {
        "name": name,
        "url": url,
        "resolved_commit": commit,
        "tree_sha256": tree_sha,
        "size_bytes": tree_size,
    }
    if archive_sha is not None:
        row["source_archive_sha256"] = archive_sha
    dependencies.append(row)
    source_artifacts.append({
        "url": url,
        "tag": commit,
        "resolved_commit": commit,
        "sha256": tree_sha,
        "size_bytes": tree_size,
    })

link_lines = [line for line in pathlib.Path(link_commands_path).read_text().splitlines() if line.strip()]
link_command = next((line for line in reversed(link_lines) if " -o tflite_loader_replay" in line), None)
if link_command is None:
    raise SystemExit("could not identify replay link command")
link_command_sha = hashlib.sha256((link_command + "\n").encode()).hexdigest()
fuzzer_link_command = next((line for line in reversed(link_lines) if " -o tflite_loader_fuzzer" in line), None)
if fuzzer_link_command is None:
    raise SystemExit("could not identify fuzzer link command")
fuzzer_link_command_sha = hashlib.sha256((fuzzer_link_command + "\n").encode()).hexdigest()
mutator_link_command = next((line for line in reversed(link_lines) if " -o tflite_structural_mutator" in line), None)
if mutator_link_command is None:
    raise SystemExit("could not identify structural mutator link command")
mutator_link_command_sha = hashlib.sha256((mutator_link_command + "\n").encode()).hexdigest()

critical_options = {
    "BUILD_SHARED_LIBS": "OFF",
    "TFLITE_ENABLE_EXTERNAL_DELEGATE": "OFF",
    "TFLITE_ENABLE_GPU": "OFF",
    "TFLITE_ENABLE_METAL": "OFF",
    "TFLITE_ENABLE_NNAPI": "OFF",
    "TFLITE_ENABLE_RUY": "OFF",
    "TFLITE_ENABLE_XNNPACK": "OFF",
    "TFLITE_KERNEL_TEST": "OFF",
}
compile_flags = [
    "-O1",
    "-g",
    "-DNDEBUG",
    "-DTF_MAJOR_VERSION=2",
    "-DTF_MINOR_VERSION=20",
    "-DTF_PATCH_VERSION=0",
    "-DTF_VERSION_SUFFIX=''",
]
compiler_sha = file_sha(compiler_path)
replay_sha = file_sha(replay_path)
fuzzer_sha = file_sha(fuzzer_path)
mutator_sha = file_sha(mutator_path)
main_library = os.path.join(build_root, "tensorflow-lite", "libtensorflow-lite.a")
loader_library = os.path.join(build_root, "libtool_tflite_loader.a")

identity = {
    "schema_version": "1",
    "target_id": "tflite",
    "source": source_artifacts[0],
    "dependencies": dependencies,
    "compiler": {
        "path": compiler_path,
        "invocation_path": compiler_invocation_path,
        "version": first_line([compiler_invocation_path, "--version"]),
        "sha256": compiler_sha,
    },
    "cmake": {
        "path": cmake_path,
        "version": first_line([cmake_path, "--version"]),
        "sha256": file_sha(cmake_path),
    },
    "flatc": {
        "path": flatc_path,
        "version": first_line([flatc_path, "--version"]),
        "sha256": file_sha(flatc_path),
    },
    "cmake_options": critical_options,
    "compile_flags": compile_flags,
    "link_command_sha256": link_command_sha,
    "fuzzer_link_command_sha256": fuzzer_link_command_sha,
    "structural_mutator_link_command_sha256": mutator_link_command_sha,
    "replay_sha256": replay_sha,
    "fuzzer_sha256": fuzzer_sha,
    "structural_mutator_path": mutator_path,
    "structural_mutator_sha256": mutator_sha,
    "add_model_sha256": file_sha(add_model_path),
}

profile = {
    "schema_version": "1",
    "target_id": "tflite",
    "format_revision": "3",
    "loader_id": "tensorflow-lite",
    "loader_version": "v2.20.0",
    "source_artifacts": source_artifacts,
    "patches": [{"order": 1, "path": patch_path, "sha256": file_sha(patch_path)}],
    "toolchain": {
        "compiler": {"version": identity["compiler"]["version"], "path": compiler_path, "sha256": compiler_sha},
        "linker": {"version": identity["compiler"]["version"], "path": compiler_path, "sha256": compiler_sha},
        "engine": {"version": "tflite-replay-v2.20.0", "path": replay_path, "sha256": replay_sha},
        "python": None,
        "rust": None,
        "environment": {},
    },
    "sanitizer_policy": {
        "compile_flags": compile_flags,
        "recovery": "abort",
        "runtime_env": {"LC_ALL": "C", "OMP_NUM_THREADS": "1"},
        "rust_panic": "abort",
    },
    "binaries": [
        {
            "role": "replay",
            "path": replay_path,
            "sha256": replay_sha,
            "argv": ["{input}"],
            "linked_libraries": [
                {"path": main_library, "sha256": file_sha(main_library)},
                {"path": loader_library, "sha256": file_sha(loader_library)},
            ],
        },
        {
            "role": "fuzzer",
            "path": fuzzer_path,
            "sha256": fuzzer_sha,
            "argv": ["{corpus_dir}"],
            "linked_libraries": [
                {"path": main_library, "sha256": file_sha(main_library)},
                {"path": loader_library, "sha256": file_sha(loader_library)},
            ],
        },
    ],
    "input_kind": {"kind": "single", "extensions": ["tflite"], "subformats": []},
    "depth": "load-allocate-access",
    "engine_capabilities": [{
        "backend": "local-harness",
        "binary_role": "replay",
        "required_mode": "native",
        "instrumentation_scope": "tensorflow/lite",
    }],
    "limits": {
        "max_input_bytes": 16 * 1024 * 1024,
        "memory_bytes": 1024 * 1024 * 1024,
        "input_timeout_ms": 5000,
        "block_timeout_ms": 10000,
        "threads": 1,
        "workers": 1,
    },
    "coverage_scope": {
        "unit": "source-line",
        "include_sources": ["tensorflow/lite/**"],
        "exclude_sources": ["**/*_test.cc"],
    },
}

for path, document in [
    (meta_path, target_meta),
    (identity_path, identity),
    (profile_path, profile),
]:
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
PY

log "done"
printf 'replay=%s\nfuzzer=%s\nmutator=%s\nprofile=%s\nidentity=%s\nmeta=%s\n' \
  "$OUT_REPLAY" "$OUT_FUZZER" "$OUT_MUTATOR" "$PROFILE" "$IDENTITY" "$META"
