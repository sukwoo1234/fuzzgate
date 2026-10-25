#!/usr/bin/env bash
# Build the OVI-03 common-loader replay against an already verified OVI-01
# target root and publish only the unqualified FND-01 execution profile needed
# by OVI-06. Qualification and campaign binaries belong to OVI-07.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd -P)}"
OVI_VERSION=2026.4.1
TARGET_ROOT_INPUT="${OPENVINO_TARGET_ROOT:-$PROJECT_ROOT/data/targets/openvino-ir/$OVI_VERSION}"
while [[ "$TARGET_ROOT_INPUT" != / && "$TARGET_ROOT_INPUT" == */ ]]; do
  TARGET_ROOT_INPUT="${TARGET_ROOT_INPUT%/}"
done

fail() {
  printf '[build-openvino-execution] fail: %s\n' "$*" >&2
  exit 1
}

blocked() {
  printf '[build-openvino-execution] blocked: %s\n' "$*" >&2
  exit 2
}

[[ "$TARGET_ROOT_INPUT" = /* ]] \
  || fail "OPENVINO_TARGET_ROOT must be absolute: $TARGET_ROOT_INPUT"
[[ ! -L "$TARGET_ROOT_INPUT" ]] \
  || fail "OPENVINO_TARGET_ROOT must not be a symlink: $TARGET_ROOT_INPUT"
TARGET_ROOT="$(realpath -m -- "$TARGET_ROOT_INPUT")"
case "$TARGET_ROOT" in
  ""|/|"$PROJECT_ROOT"|"${HOME:-__unset_home__}")
    fail "unsafe OPENVINO_TARGET_ROOT: $TARGET_ROOT"
    ;;
esac

BUILD_PROFILE="$TARGET_ROOT/build-profile.json"
LINKAGE="$TARGET_ROOT/linkage-manifest.json"
META="$TARGET_ROOT/meta.json"
BUILD_DIR="$TARGET_ROOT/build/execution-harness"
PROFILE="$TARGET_ROOT/profile.json"
JOBS="${JOBS:-4}"

for tool in python3 sha256sum realpath find; do
  command -v "$tool" >/dev/null 2>&1 || blocked "required command missing: $tool"
done
for path in "$BUILD_PROFILE" "$LINKAGE" "$META"; do
  [[ -f "$path" && ! -L "$path" ]] || blocked "verified target evidence missing: $path"
done

python3 -B "$SCRIPT_DIR/check_openvino_profile.py" --target-root "$TARGET_ROOT" \
  >"$TARGET_ROOT/execution-profile-precheck.log" 2>&1 \
  || {
    sed -n '1,80p' "$TARGET_ROOT/execution-profile-precheck.log" >&2
    fail "pinned OpenVINO build profile no longer validates"
  }

mapfile -t profile_tools < <(python3 -B - "$BUILD_PROFILE" <<'PY'
import json
import pathlib
import sys

profile = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for key in ("cmake", "ninja", "linker"):
    print(profile["toolchain"][key]["path"])
PY
)
[[ ${#profile_tools[@]} -eq 3 ]] || fail "build profile toolchain is incomplete"
CMAKE="${profile_tools[0]}"
NINJA="${profile_tools[1]}"
PINNED_LINKER="${profile_tools[2]}"
CLANGXX="${CLANGXX:-$PROJECT_ROOT/data/toolchains/clang+llvm-17.0.6-x86_64-linux-gnu-ubuntu-22.04/bin/clang++}"
for tool in "$CMAKE" "$NINJA" "$CLANGXX"; do
  [[ -x "$tool" ]] || blocked "pinned build executable unavailable: $tool"
done
[[ "$(sha256sum "$CLANGXX" | awk '{print $1}')" == \
   "$(sha256sum "$PINNED_LINKER" | awk '{print $1}')" ]] \
  || fail "C++ compiler invocation does not match the pinned linker identity"

OPENVINO_CONFIG="$(find "$TARGET_ROOT/install" -type f -name OpenVINOConfig.cmake -print -quit)"
[[ -n "$OPENVINO_CONFIG" ]] || blocked "installed OpenVINOConfig.cmake is unavailable"
OPENVINO_CMAKE_DIR="$(dirname -- "$OPENVINO_CONFIG")"

mkdir -p -- "$BUILD_DIR"
"$CMAKE" -G Ninja \
  -S "$PROJECT_ROOT/harnesses/openvino" \
  -B "$BUILD_DIR" \
  -DOpenVINO_DIR="$OPENVINO_CMAKE_DIR" \
  -DOPENVINO_BUILD_LOADER=ON \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CLANGXX" \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  >"$TARGET_ROOT/execution-profile-configure.log" 2>&1 \
  || fail "OVI-03 replay configure failed; see $TARGET_ROOT/execution-profile-configure.log"
"$CMAKE" --build "$BUILD_DIR" --target openvino_ir_loader_replay -j"$JOBS" \
  >"$TARGET_ROOT/execution-profile-build.log" 2>&1 \
  || fail "OVI-03 replay build failed; see $TARGET_ROOT/execution-profile-build.log"

REPLAY="$BUILD_DIR/openvino_ir_loader_replay"
LOADER_LIBRARY="$BUILD_DIR/libtool_openvino_loader.a"
for path in "$REPLAY" "$LOADER_LIBRARY"; do
  [[ -f "$path" && ! -L "$path" ]] || fail "execution build output missing: $path"
done
[[ -x "$REPLAY" ]] || fail "execution replay is not executable: $REPLAY"

python3 -B - \
  "$BUILD_PROFILE" "$PROFILE" "$REPLAY" "$LOADER_LIBRARY" "$CLANGXX" <<'PY'
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

build_profile_path, destination_text, replay_text, loader_library_text, compiler_invocation = sys.argv[1:]
build = json.loads(pathlib.Path(build_profile_path).read_text(encoding="utf-8"))
destination = pathlib.Path(destination_text)
replay = pathlib.Path(replay_text).resolve()
loader_library = pathlib.Path(loader_library_text).resolve()

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
frontend = pathlib.Path(build["components"]["ir_frontend"]["path"]).resolve()
compiler = pathlib.Path(build["toolchain"]["compiler"]["path"]).resolve()
linker = pathlib.Path(build["toolchain"]["linker"]["path"]).resolve()
replay_sha = sha(replay)
profile = {
    "schema_version": "1",
    "target_id": "openvino-ir",
    "format_revision": "ir-v11",
    "loader_id": "openvino-ir-frontend",
    "loader_version": "2026.4.1",
    "source_artifacts": [source_identity(row) for row in build["source_artifacts"]],
    "patches": [],
    "toolchain": {
        "compiler": {
            "version": build["toolchain"]["compiler"]["version"],
            "path": str(compiler),
            "sha256": sha(compiler),
        },
        "linker": {
            "version": build["toolchain"]["linker"]["version"],
            "path": str(linker),
            "sha256": sha(linker),
        },
        "engine": {
            "version": "openvino-ir-replay-2026.4.1",
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
        "runtime_env": {"LC_ALL": "C", "OMP_NUM_THREADS": "1"},
        "rust_panic": "abort",
    },
    "binaries": [{
        "role": "replay",
        "path": str(replay),
        "sha256": replay_sha,
        "argv": ["{input}"],
        "linked_libraries": [
            {"path": str(core), "sha256": sha(core)},
            {"path": str(frontend), "sha256": sha(frontend)},
            {"path": str(loader_library), "sha256": sha(loader_library)},
        ],
    }],
    "input_kind": {
        "kind": "fzb1",
        "extensions": ["fzb"],
        "subformats": ["model.bin", "model.xml"],
    },
    "depth": "read-validate-constants",
    "engine_capabilities": [{
        "backend": "local-harness",
        "binary_role": "replay",
        "required_mode": "native",
        "instrumentation_scope": "openvino-core+ir-frontend",
    }],
    "limits": {
        "max_input_bytes": 64 * 1024 * 1024,
        "memory_bytes": 2 * 1024 * 1024 * 1024,
        "input_timeout_ms": 30000,
        "block_timeout_ms": 60000,
        "threads": 1,
        "workers": 1,
    },
    "coverage_scope": {
        "unit": "source-line",
        "include_sources": ["src/core", "src/frontends/ir"],
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
print(f"compiler_invocation={compiler_invocation}")
PY

printf '[build-openvino-execution] done\n'
printf 'profile=%s\nreplay=%s\n' "$PROFILE" "$REPLAY"
