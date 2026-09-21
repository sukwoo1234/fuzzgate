#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${1:-}"
TARGET="${2:-}"
VERSION="${3:-}"

if [[ -z "$DATA_DIR" || -z "$TARGET" ]]; then
  echo "[target-build] usage: build_prepared_target.sh <data_dir> <target> [version]" >&2
  exit 2
fi

case "$TARGET" in
  gguf)
    TARGET_NAME="llama.cpp"
    ;;
  onnx)
    TARGET_NAME="onnxruntime"
    ;;
  safetensors)
    TARGET_NAME="safetensors"
    ;;
  *)
    echo "[target-build] unsupported target: $TARGET" >&2
    exit 2
    ;;
esac

TARGET_ROOT="$DATA_DIR/targets/$TARGET_NAME"
if [[ ! -d "$TARGET_ROOT" ]]; then
  echo "[target-build] prepared target not found: $TARGET_ROOT" >&2
  exit 3
fi

if [[ -z "$VERSION" ]]; then
  VERSION="$(find "$TARGET_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | tail -n 1)"
fi

if [[ -z "$VERSION" ]]; then
  echo "[target-build] no prepared version found for $TARGET" >&2
  exit 3
fi

VERSION_ROOT="$TARGET_ROOT/$VERSION"
SOURCE_DIR="$VERSION_ROOT/source"
ARCHIVE_PATH="$(find "$SOURCE_DIR" -maxdepth 1 -type f | sort | head -n 1)"

if [[ -z "$ARCHIVE_PATH" || ! -f "$ARCHIVE_PATH" ]]; then
  echo "[target-build] source archive not found in $SOURCE_DIR" >&2
  exit 4
fi

# A prepared archive is trusted only after it matches the recorded download.
# Check before removing or creating the extract tree: a corrupt archive must not
# change a prior build or leave partially extracted source behind.
META_PATH="$VERSION_ROOT/meta.json"
if [[ ! -f "$META_PATH" ]]; then
  echo "[target-build] target metadata not found: $META_PATH" >&2
  exit 4
fi
if ! EXPECTED_SHA="$(python3 - "$META_PATH" "$TARGET_NAME" "$VERSION" <<'PY'
import json
import re
import sys

path, target, version = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as stream:
        meta = json.load(stream)
    digest = meta["downloaded_sha256"]
    if meta.get("target") != target or meta.get("version") != version:
        raise ValueError("target or version does not match the prepared directory")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise ValueError("downloaded_sha256 is not a SHA-256 digest")
    print(digest.lower())
except (OSError, ValueError, KeyError, TypeError) as exc:
    print(f"[target-build] invalid target metadata: {exc}", file=sys.stderr)
    sys.exit(1)
PY
)"; then
  exit 4
fi
ACTUAL_SHA="$(sha256sum "$ARCHIVE_PATH" | cut -d' ' -f1)" || exit 4
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
  echo "[target-build] sha256 mismatch: $ARCHIVE_PATH expected=$EXPECTED_SHA actual=$ACTUAL_SHA" >&2
  exit 4
fi

EXTRACT_DIR="$VERSION_ROOT/build-src"
BUILD_DIR="$VERSION_ROOT/build-out"
# gguf gets built from the same version more than once - this plain reference build,
# the ASan+sancov one from build_libfuzzer_gguf_native.sh, the AFL++ one - and this
# script rm -rf's its extract dir. Keep the build kind in the directory name so the
# builds cannot overwrite each other.
if [[ "$TARGET" == gguf ]]; then
  EXTRACT_DIR="$VERSION_ROOT/build-src-plain"
  BUILD_DIR="$VERSION_ROOT/build-out-plain"
fi
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"

echo "[target-build] target: $TARGET"
echo "[target-build] version: $VERSION"
echo "[target-build] archive: $ARCHIVE_PATH"

tar -xf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"
SRC_ROOT="$(find "$EXTRACT_DIR" -mindepth 1 -maxdepth 1 -type d | sort | head -n 1)"

if [[ -z "$SRC_ROOT" || ! -d "$SRC_ROOT" ]]; then
  echo "[target-build] extracted source directory not found" >&2
  exit 5
fi

case "$TARGET" in
  gguf)
    # Build what the fuzz harness links - the ggml-base archive holding gguf.cpp -
    # not llama-cli. (The legacy llama-gguf-hash probe still comes from the separate
    # tools/llama.cpp checkout; it was never taken from here.)
    cmake -S "$SRC_ROOT" -B "$BUILD_DIR" \
      -DBUILD_SHARED_LIBS=OFF \
      -DLLAMA_BUILD_TESTS=OFF \
      -DLLAMA_BUILD_EXAMPLES=OFF \
      -DLLAMA_BUILD_TOOLS=OFF \
      -DLLAMA_BUILD_SERVER=OFF
    cmake --build "$BUILD_DIR" --target ggml-base -j2
    ARTIFACT="$BUILD_DIR/ggml/src/libggml-base.a"
    if [[ ! -f "$ARTIFACT" ]]; then
      echo "[target-build] expected artifact missing: $ARTIFACT" >&2
      exit 6
    fi
    # The archive is produced even if gguf.cpp drops out of the target, so its
    # existence proves nothing. Check for the parser's own symbol (C++-mangled,
    # hence the substring). The listing goes to a file, not a pipe: grep -q would
    # close the pipe on its first match and pipefail would read the resulting
    # SIGPIPE as a missing symbol.
    NM_BIN="${LLVM_NM:-}"
    if [[ -z "$NM_BIN" ]]; then
      NM_BIN="$(command -v llvm-nm || command -v nm || true)"
    fi
    if [[ -z "$NM_BIN" ]]; then
      echo "[target-build] no llvm-nm/nm to verify $ARTIFACT" >&2
      exit 6
    fi
    if ! "$NM_BIN" "$ARTIFACT" >"$BUILD_DIR/nm-ggml-base.txt" 2>/dev/null; then
      echo "[target-build] could not read symbols from $ARTIFACT" >&2
      exit 6
    fi
    if ! grep -q 'gguf_init_from_file_impl' "$BUILD_DIR/nm-ggml-base.txt"; then
      echo "[target-build] gguf.cpp is not in $ARTIFACT (no gguf_init_from_file_impl)" >&2
      exit 6
    fi
    ;;
  onnx)
    pushd "$SRC_ROOT" >/dev/null
    bash ./build.sh --config Release --parallel 2 --build_shared_lib --skip_tests
    popd >/dev/null
    BUILD_DIR="$SRC_ROOT/build/Linux/Release"
    ARTIFACT="$(find "$SRC_ROOT/build/Linux" -type f -name 'libonnxruntime.so' | sort | head -n 1)"
    if [[ -z "$ARTIFACT" || ! -f "$ARTIFACT" ]]; then
      echo "[target-build] expected artifact missing: libonnxruntime.so" >&2
      exit 6
    fi
    ;;
  safetensors)
    BUILD_DIR="$SRC_ROOT/safetensors/target/release"
    cargo build --release --manifest-path "$SRC_ROOT/safetensors/Cargo.toml"
    ARTIFACT="$(find "$SRC_ROOT/safetensors/target/release" -type f \( -name 'libsafetensors*.rlib' -o -name 'libsafetensors*.rmeta' \) | sort | head -n 1)"
    if [[ -z "$ARTIFACT" || ! -f "$ARTIFACT" ]]; then
      echo "[target-build] expected artifact missing: libsafetensors artifact" >&2
      exit 6
    fi
    ;;
esac

echo "[target-build] done"
echo "build_dir: $BUILD_DIR"
echo "artifact: $ARTIFACT"
