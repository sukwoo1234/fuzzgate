#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/seed_collect.sh
. "$SCRIPT_DIR/lib/seed_collect.sh"

WORKDIR="${WORKDIR:-$PWD}"
TOOL_BIN="${TOOL_BIN:-$WORKDIR/target/debug/tool}"

usage() {
  cat <<'EOF'
usage: seed_fetch.sh --target <registered-target> --url <https_url> [--sha256 <hex>] [--out-dir <dir>] [--tmp-dir <dir>] [--no-sync]

examples:
  bash scripts/seed_fetch.sh \
    --target gguf \
    --url https://huggingface.co/ggml-org/models/resolve/main/.../model.gguf \
    --sha256 <expected_sha256>

  bash scripts/seed_fetch.sh \
    --target onnx \
    --url https://github.com/onnx/models/archive/refs/heads/main.tar.gz \
    --out-dir seeds/onnx
EOF
}

TARGET=""
URL=""
SHA256=""
OUT_DIR=""
TMP_DIR=""
SYNC=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:-}"; shift 2 ;;
    --url) URL="${2:-}"; shift 2 ;;
    --sha256) SHA256="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --tmp-dir) TMP_DIR="${2:-}"; shift 2 ;;
    --no-sync) SYNC=0; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[seed-fetch] unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$TARGET" || -z "$URL" ]]; then
  echo "[seed-fetch] --target and --url are required" >&2
  usage
  exit 2
fi

if [[ ! -x "$TOOL_BIN" ]]; then
  echo "[seed-fetch] tool binary missing or not executable: $TOOL_BIN" >&2
  exit 2
fi
TARGET_SPEC="$("$TOOL_BIN" target-spec --target "$TARGET" --format shell 2>/dev/null)" || {
  echo "[seed-fetch] unsupported target: $TARGET" >&2
  exit 2
}
TARGET_ID="$(sed -n 's/^target_id=//p' <<<"$TARGET_SPEC")"
SEED_SUBDIR="$(sed -n 's/^seed_subdir=//p' <<<"$TARGET_SPEC")"
EXT="$(sed -n 's/^input_ext=//p' <<<"$TARGET_SPEC")"
if [[ "$TARGET_ID" != "$TARGET" \
  || ! "$TARGET_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "[seed-fetch] registered target has an invalid or mismatched target_id: $TARGET" >&2
  exit 2
fi
if [[ ! "$SEED_SUBDIR" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "[seed-fetch] registered target has an invalid seed_subdir: $TARGET" >&2
  exit 2
fi
if [[ ! "$EXT" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
  echo "[seed-fetch] registered target has an invalid input_ext: $TARGET" >&2
  exit 2
fi
TARGET="$TARGET_ID"

if [[ "$URL" != https://* ]]; then
  echo "[seed-fetch] only https URLs are allowed" >&2
  exit 2
fi

# Minimal allowlist guard (official/public channels used in this project)
case "$URL" in
  https://github.com/*|https://raw.githubusercontent.com/*|https://objects.githubusercontent.com/*|https://huggingface.co/*)
    ;;
  *)
    echo "[seed-fetch] URL host is not in allowlist: $URL" >&2
    echo "[seed-fetch] allowed: github.com, raw.githubusercontent.com, objects.githubusercontent.com, huggingface.co" >&2
    exit 2
    ;;
esac

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$WORKDIR/seeds/${SEED_SUBDIR}"
fi
if [[ -z "$TMP_DIR" ]]; then
  TMP_DIR="$(mktemp -d /tmp/seed-fetch-${TARGET}-XXXXXX)"
fi

mkdir -p "$OUT_DIR"
mkdir -p "$TMP_DIR"

ARCHIVE_PATH="$TMP_DIR/download.bin"
echo "[seed-fetch] target: $TARGET"
echo "[seed-fetch] url: $URL"
echo "[seed-fetch] tmp_dir: $TMP_DIR"
echo "[seed-fetch] out_dir: $OUT_DIR"

if command -v curl >/dev/null 2>&1; then
  curl -fL "$URL" -o "$ARCHIVE_PATH"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$ARCHIVE_PATH" "$URL"
else
  echo "[seed-fetch] curl/wget not found" >&2
  exit 2
fi

if [[ -n "$SHA256" ]]; then
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA256="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"
  else
    ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
  fi
  if [[ "$ACTUAL_SHA256" != "$SHA256" ]]; then
    echo "[seed-fetch] sha256 mismatch expected=$SHA256 actual=$ACTUAL_SHA256" >&2
    exit 2
  fi
  echo "[seed-fetch] sha256 verified: $ACTUAL_SHA256"
fi

STAGE_DIR="$TMP_DIR/stage"
mkdir -p "$STAGE_DIR"

case "$URL" in
  *.tar.gz|*.tgz)
    tar -xzf "$ARCHIVE_PATH" -C "$STAGE_DIR"
    ;;
  *.tar)
    tar -xf "$ARCHIVE_PATH" -C "$STAGE_DIR"
    ;;
  *.zip)
    if ! command -v unzip >/dev/null 2>&1; then
      echo "[seed-fetch] unzip not found for zip archive" >&2
      exit 2
    fi
    unzip -q "$ARCHIVE_PATH" -d "$STAGE_DIR"
    ;;
  *)
    # Non-archive single file fallback
    cp "$ARCHIVE_PATH" "$STAGE_DIR/from_url.${EXT}"
    ;;
esac

RAW_DIR="$TMP_DIR/raw"
collect_seed_files "$STAGE_DIR" "$RAW_DIR" "$EXT"

RAW_COUNT="$(find "$RAW_DIR" -maxdepth 1 -type f -name "*.${EXT}" | wc -l | tr -d ' ')"
echo "[seed-fetch] collected raw ${EXT} files: $RAW_COUNT"
if [[ "$RAW_COUNT" -eq 0 ]]; then
  echo "[seed-fetch] no *.${EXT} files found from URL payload" >&2
  exit 2
fi

if [[ "$SYNC" -eq 1 ]]; then
  echo "[seed-fetch] running harness-filter sync"
  "$TOOL_BIN" seed sync --target "$TARGET" --from "$RAW_DIR" --to "$OUT_DIR" --harness-filter
  "$TOOL_BIN" seed stats --target "$TARGET" --dir "$OUT_DIR"
else
  echo "[seed-fetch] sync disabled (--no-sync). raw files remain at: $RAW_DIR"
fi

echo "[seed-fetch] done"
echo "[seed-fetch] tmp_dir: $TMP_DIR"
