#!/usr/bin/env bash
# Build the HDF-03 replay and deterministic HDF-02 corpus needed by HDF-06.
# This publishes an unqualified FND-01 profile only; HDF-07 owns qualification.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd -P)}"
TARGET_ROOT_INPUT="${HDF5_TARGET_ROOT:-$PROJECT_ROOT/data/targets/hdf5-weights/2.2.0}"
while [[ "$TARGET_ROOT_INPUT" != / && "$TARGET_ROOT_INPUT" == */ ]]; do
  TARGET_ROOT_INPUT="${TARGET_ROOT_INPUT%/}"
done

fail() { printf '[build-hdf5-execution] fail: %s\n' "$*" >&2; exit 1; }
blocked() { printf '[build-hdf5-execution] blocked: %s\n' "$*" >&2; exit 2; }

[[ "$TARGET_ROOT_INPUT" = /* ]] \
  || fail "HDF5_TARGET_ROOT must be absolute: $TARGET_ROOT_INPUT"
[[ ! -L "$TARGET_ROOT_INPUT" ]] \
  || fail "HDF5_TARGET_ROOT must not be a symlink: $TARGET_ROOT_INPUT"
TARGET_ROOT="$(realpath -m -- "$TARGET_ROOT_INPUT")"
case "$TARGET_ROOT" in
  ""|/|"$PROJECT_ROOT"|"${HOME:-__unset_home__}")
    fail "unsafe HDF5_TARGET_ROOT: $TARGET_ROOT"
    ;;
esac

BUILD_PROFILE="$TARGET_ROOT/build-profile.json"
LINKAGE="$TARGET_ROOT/linkage-manifest.json"
META="$TARGET_ROOT/meta.json"
BUILD_DIR="$TARGET_ROOT/build/execution-harness"
FIXTURES="$TARGET_ROOT/execution-fixtures"
PROFILE="$TARGET_ROOT/profile.json"
JOBS="${JOBS:-4}"

for tool in python3 sha256sum realpath find; do
  command -v "$tool" >/dev/null 2>&1 || blocked "required command missing: $tool"
done
for path in "$BUILD_PROFILE" "$LINKAGE" "$META"; do
  [[ -f "$path" && ! -L "$path" ]] || blocked "verified target evidence missing: $path"
done
[[ ! -L "$BUILD_DIR" ]] || fail "execution build directory must not be a symlink: $BUILD_DIR"
[[ ! -L "$FIXTURES" ]] || fail "execution fixture directory must not be a symlink: $FIXTURES"
[[ ! -e "$PROFILE" && ! -L "$PROFILE" ]] \
  || fail "execution profile already exists: $PROFILE"

python3 -B "$SCRIPT_DIR/check_hdf5_profile.py" --target-root "$TARGET_ROOT" \
  >"$TARGET_ROOT/execution-profile-precheck.log" 2>&1 \
  || {
    sed -n '1,80p' "$TARGET_ROOT/execution-profile-precheck.log" >&2
    fail "pinned HDF5 build profile no longer validates"
  }

tool_file="$(mktemp "$TARGET_ROOT/.execution-tools.XXXXXX")"
trap 'rm -f -- "$tool_file"' EXIT
python3 -B - "$BUILD_PROFILE" >"$tool_file" <<'PY'
import json
import pathlib
import sys

profile = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for key in ("cmake", "ninja", "cxx_compiler", "linker"):
    print(profile["toolchain"][key]["path"])
PY
mapfile -t profile_tools <"$tool_file"
[[ ${#profile_tools[@]} -eq 4 ]] || fail "build profile toolchain is incomplete"
CMAKE="${CMAKE:-${profile_tools[0]}}"
NINJA="${NINJA:-${profile_tools[1]}}"
PROFILE_CXX="${profile_tools[2]}"
PINNED_LINKER="${profile_tools[3]}"
CLANGXX="${CLANGXX:-$(dirname -- "$PROFILE_CXX")/clang++}"
for tool in "$CMAKE" "$NINJA" "$CLANGXX" "$PINNED_LINKER"; do
  [[ -x "$tool" ]] || blocked "pinned build executable unavailable: $tool"
done
[[ "$(realpath -e -- "$CLANGXX")" == "$(realpath -e -- "$PROFILE_CXX")" ]] \
  || fail "C++ compiler invocation differs from the pinned compiler identity"

HDF5_CMAKE_DIR="$(find "$TARGET_ROOT/install" -type f -name hdf5-config.cmake -printf '%h\n' | head -1)"
[[ -n "$HDF5_CMAKE_DIR" ]] || blocked "installed HDF5 CMake package is unavailable"

"$CMAKE" -G Ninja \
  -S "$PROJECT_ROOT/harnesses/hdf5" \
  -B "$BUILD_DIR" \
  -DHDF5_DIR="$HDF5_CMAKE_DIR" \
  -DHDF5_BUILD_LOADER=ON \
  -DHDF5_BUILD_FIXTURE_TOOL=ON \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_MAKE_PROGRAM="$NINJA" \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  >"$TARGET_ROOT/execution-profile-configure.log" 2>&1 \
  || fail "HDF-03 replay configure failed; see $TARGET_ROOT/execution-profile-configure.log"
"$CMAKE" --build "$BUILD_DIR" --target hdf5_loader_replay hdf5_fixture_tool -j"$JOBS" \
  >"$TARGET_ROOT/execution-profile-build.log" 2>&1 \
  || fail "HDF-03 replay build failed; see $TARGET_ROOT/execution-profile-build.log"

REPLAY="$BUILD_DIR/hdf5_loader_replay"
FIXTURE_TOOL="$BUILD_DIR/hdf5_fixture_tool"
LOADER_LIBRARY="$BUILD_DIR/libtool_hdf5_loader.a"
for path in "$REPLAY" "$FIXTURE_TOOL" "$LOADER_LIBRARY"; do
  [[ -f "$path" && ! -L "$path" ]] || fail "execution build output missing: $path"
done
[[ -x "$REPLAY" && -x "$FIXTURE_TOOL" ]] || fail "execution tools are not executable"

fixture_action=generate
[[ ! -e "$FIXTURES" ]] || fixture_action=verify
python3 -B "$SCRIPT_DIR/gen_hdf5_fixtures.py" \
  --build-profile "$BUILD_PROFILE" \
  --fixture-tool "$FIXTURE_TOOL" \
  "$fixture_action" --output "$FIXTURES" \
  >"$TARGET_ROOT/execution-fixtures.log" 2>&1 \
  || fail "HDF-02 execution fixtures failed; see $TARGET_ROOT/execution-fixtures.log"

normal_output="$("$REPLAY" "$FIXTURES/tensor-chunked.h5" 2>&1)" \
  || fail "HDF-03 replay rejected the normal execution fixture: $normal_output"
grep -Fq 'HDF5_ACCESS_OK datasets=1' <<<"$normal_output" \
  || fail "normal execution fixture did not reach H5Dread"

python3 -B - \
  "$BUILD_PROFILE" "$PROFILE" "$REPLAY" "$LOADER_LIBRARY" "$CLANGXX" \
  "$PINNED_LINKER" <<'PY'
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

(
    build_profile_text,
    destination_text,
    replay_text,
    loader_library_text,
    compiler_invocation,
    linker_text,
) = sys.argv[1:]
build = json.loads(pathlib.Path(build_profile_text).read_text(encoding="utf-8"))
destination = pathlib.Path(destination_text)
replay = pathlib.Path(replay_text).resolve()
loader_library = pathlib.Path(loader_library_text).resolve()
compiler = pathlib.Path(compiler_invocation).resolve()
linker = pathlib.Path(linker_text).resolve()


def sha(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def first_line(command):
    return subprocess.check_output(command, text=True).splitlines()[0]


def source_identity(row):
    return {
        "url": row["url"],
        "tag": row["tag"],
        "resolved_commit": row["resolved_commit"],
        "sha256": row["sha256"],
        "size_bytes": row["size_bytes"],
    }


core = pathlib.Path(build["components"]["core"]["path"]).resolve()
high_level = pathlib.Path(build["components"]["high_level"]["path"]).resolve()
replay_sha = sha(replay)
profile = {
    "schema_version": "1",
    "target_id": "hdf5-weights",
    "format_revision": "hdf5-2.2.0-numeric-datasets-v1",
    "loader_id": "hdf5-file-image-numeric-dataset",
    "loader_version": "2.2.0",
    "source_artifacts": [source_identity(row) for row in build["source_artifacts"]],
    "patches": [],
    "toolchain": {
        "compiler": {
            "version": first_line([compiler_invocation, "--version"]),
            "path": str(compiler),
            "sha256": sha(compiler),
        },
        "linker": {
            "version": build["toolchain"]["linker"]["version"],
            "path": str(linker),
            "sha256": sha(linker),
        },
        "engine": {
            "version": "hdf5-file-image-replay-2.2.0",
            "path": str(replay),
            "sha256": replay_sha,
        },
        "python": None,
        "rust": None,
        "environment": {},
    },
    "sanitizer_policy": {
        "compile_flags": ["-O1", "-g", "-DNDEBUG"],
        "recovery": "abort",
        "runtime_env": {"LC_ALL": "C"},
        "rust_panic": "abort",
    },
    "binaries": [{
        "role": "replay",
        "path": str(replay),
        "sha256": replay_sha,
        "argv": ["{input}"],
        "linked_libraries": [
            {"path": str(core), "sha256": sha(core)},
            {"path": str(high_level), "sha256": sha(high_level)},
            {"path": str(loader_library), "sha256": sha(loader_library)},
        ],
    }],
    "input_kind": {
        "kind": "single",
        "extensions": ["h5"],
        "subformats": ["numeric-dataset"],
    },
    "depth": "read-numeric-datasets",
    "engine_capabilities": [{
        "backend": "local-harness",
        "binary_role": "replay",
        "required_mode": "native",
        "instrumentation_scope": "hdf5-core+high-level-file-image",
    }],
    "limits": {
        "max_input_bytes": 32 * 1024 * 1024,
        "memory_bytes": 1024 * 1024 * 1024,
        "input_timeout_ms": 30000,
        "block_timeout_ms": 60000,
        "threads": 1,
        "workers": 1,
    },
    "coverage_scope": {
        "unit": "source-line",
        "include_sources": [
            "src/H5Fio.c",
            "src/H5Dio.c",
            "src/H5Dchunk.c",
            "src/H5Z.c",
            "src/H5Zshuffle.c",
            "src/H5Zfletcher32.c",
        ],
        "exclude_sources": [],
    },
}

destination.parent.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile(
    mode="w",
    encoding="utf-8",
    dir=destination.parent,
    prefix=f".{destination.name}.",
    delete=False,
) as stream:
    json.dump(profile, stream, indent=2, sort_keys=True)
    stream.write("\n")
    temporary = pathlib.Path(stream.name)
os.replace(temporary, destination)
print(f"profile_sha256={sha(destination)}")
print(f"replay_sha256={replay_sha}")
PY

rm -f -- "$tool_file"
trap - EXIT
printf '[build-hdf5-execution] done\n'
printf 'profile=%s\nreplay=%s\nfixtures=%s\n' "$PROFILE" "$REPLAY" "$FIXTURES"
