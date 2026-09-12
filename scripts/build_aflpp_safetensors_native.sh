#!/usr/bin/env bash
# Build the native AFL++ safetensors replay with Rust code instrumented.
#
# Rust cannot be instrumented by the C++-only afl-clang-fast++ route used by the ONNX
# and GGUF arms. This arm therefore uses cargo-afl, which injects AFL++'s LLVM runtime
# and sanitizer-coverage instrumentation while cargo compiles the replay and its pinned
# safetensors dependency. The resulting argv-based replay is still driven by the shared
# AFL++ Docker loop, so the campaign host does not need to run Rust inside the container.
#
# One-time online provisioning on the fuzzing computer (pinned tool, no repo mutation):
#   cargo install cargo-afl --version 0.18.2 --locked
#   cargo +nightly afl config --build
# After that this build is offline and uses the vendored fuzz crate dependencies.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
ST_VER="${ST_VER:-v0.7.0}"
ST_CRATE_VER="${ST_CRATE_VER:-0.7.0}"
TARGET_DIR="${TARGET_DIR:-$PROJECT_ROOT/data/targets/safetensors/$ST_VER}"
META="${META:-$TARGET_DIR/meta.json}"
ARCHIVE="${ARCHIVE:-$TARGET_DIR/source/$ST_VER.tar.gz}"
FUZZ_DIR="${FUZZ_DIR:-$PROJECT_ROOT/fuzz}"
AFLPP_TARGET_DIR="${AFLPP_TARGET_DIR:-$FUZZ_DIR/target-aflpp}"
OUT="${OUT:-$PROJECT_ROOT/harnesses/aflpp/safetensors_loader_replay}"
CARGO="${CARGO:-cargo}"
CARGO_AFL_TOOLCHAIN="${CARGO_AFL_TOOLCHAIN:-nightly}"

log() { echo "[st-build-aflpp] $*"; }
fail() { echo "[st-build-aflpp] fail: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
usage: build_aflpp_safetensors_native.sh

Builds harnesses/aflpp/safetensors_loader_replay with Rust AFL++ instrumentation
through cargo-afl. The parser is statically linked and must be classified as
instrumentation_scope=library by scripts/lib/engine_mode.sh.

The cargo-afl tool is provisioned once, online, outside this script:
  cargo install cargo-afl --version 0.18.2 --locked
  cargo +nightly afl config --build
This build itself is offline and uses the vendored fuzz dependencies.

Environment: PROJECT_ROOT ST_VER ST_CRATE_VER TARGET_DIR META ARCHIVE FUZZ_DIR
             AFLPP_TARGET_DIR OUT CARGO CARGO_AFL_TOOLCHAIN
             ALLOW_UNINSTRUMENTED=1  accept a deliberate no-instrumentation baseline
             ALLOW_DRIVER_ONLY=1      accept a deliberate driver-only baseline
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
[[ $# -eq 0 ]] || { echo "[st-build-aflpp] unknown argument: $1" >&2; usage >&2; exit 2; }

command -v "$CARGO" >/dev/null 2>&1 || fail "cargo not found: $CARGO"
command -v cargo-afl >/dev/null 2>&1 \
  || fail "cargo-afl missing; provision once with: cargo install cargo-afl --version 0.18.2 --locked"

if [[ -n "$CARGO_AFL_TOOLCHAIN" ]]; then
  command -v rustup >/dev/null 2>&1 || fail "rustup missing; required for cargo +$CARGO_AFL_TOOLCHAIN afl"
  rustup toolchain list 2>/dev/null | grep -qE "^${CARGO_AFL_TOOLCHAIN}([[:space:]-]|$)" \
    || fail "Rust toolchain not installed: $CARGO_AFL_TOOLCHAIN"
fi

CARGO_AFL_CMD=("$CARGO")
if [[ -n "$CARGO_AFL_TOOLCHAIN" ]]; then
  CARGO_AFL_CMD+=("+$CARGO_AFL_TOOLCHAIN")
fi
CARGO_AFL_CMD+=(afl)

# Fail early with a useful message when cargo-afl was installed but its per-toolchain
# AFL++ runtime was not built. The actual build below also checks this, but this probe
# avoids hiding the provisioning fix behind a long dependency compile.
if ! "${CARGO_AFL_CMD[@]}" --version >/dev/null 2>&1; then
  fail "cargo-afl is not usable for toolchain ${CARGO_AFL_TOOLCHAIN:-default}; run '${CARGO_AFL_CMD[*]} config --build' once"
fi

[[ -f "$META" ]] || fail "meta.json not found: $META"
[[ -f "$ARCHIVE" ]] || fail "archive not found: $ARCHIVE"
[[ -f "$FUZZ_DIR/Cargo.lock" ]] || fail "fuzz/Cargo.lock missing"

want_sha="$(grep -oE '"downloaded_sha256"[[:space:]]*:[[:space:]]*"[0-9a-f]{64}"' "$META" | grep -oE '[0-9a-f]{64}')"
got_sha="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
[[ -n "$want_sha" ]] || fail "no downloaded_sha256 in $META"
[[ "$want_sha" == "$got_sha" ]] || fail "archive sha mismatch (want $want_sha got $got_sha)"
log "provenance ok: $ST_VER tarball sha256 matches meta.json"

awk -v want="$ST_CRATE_VER" '
  $0 == "name = \"safetensors\"" { seen = 1; next }
  seen && $0 ~ /^version = / { if ($0 == "version = \"" want "\"") ok = 1; seen = 0 }
  END { exit(ok ? 0 : 1) }
' "$FUZZ_DIR/Cargo.lock" \
  || fail "fuzz/Cargo.lock does not pin safetensors $ST_CRATE_VER"
log "crate pin ok: safetensors $ST_CRATE_VER in fuzz/Cargo.lock"

# R46: stage the new replay beside $OUT and only move it into place once the build and
# the instrumentation-scope check have both passed. This script used to `rm -f "$OUT"`
# here, before cargo ran. check_safetensors_native_engines.sh calls it on every cargo-afl
# run whether or not the replay already exists, so any build failure - offline
# resolution, toolchain, RAM - destroyed a replay that is the only copy on the fuzzing
# computer. The staging file is a sibling, so the mv is a same-filesystem rename.
# R49/R55: the staging discipline R46 introduced here now lives in one place, so this
# build also gets the properties it was missing - 0755 instead of 0711, no 0-byte
# install, symlink and directory handling. See scripts/lib/staged_install.sh.
# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT || exit 1
trap staged_cleanup EXIT
staged_new "$OUT" STAGED || exit 1

BUILD_RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C panic=abort"
log "building AFL++ Rust replay with ${CARGO_AFL_CMD[*]} (offline)"
CARGO_NET_OFFLINE=true RUSTFLAGS="$BUILD_RUSTFLAGS" \
  "${CARGO_AFL_CMD[@]}" build --release \
    --manifest-path "$FUZZ_DIR/Cargo.toml" \
    --bin safetensors_loader_replay \
    --target-dir "$AFLPP_TARGET_DIR"

REPLAY_BIN="$(find "$AFLPP_TARGET_DIR" -type f \
  -path '*/release/safetensors_loader_replay' ! -path '*/build/*' \
  -print -quit)"
[[ -n "$REPLAY_BIN" ]] || fail "could not locate cargo-afl replay under $AFLPP_TARGET_DIR"
cp "$REPLAY_BIN" "$STAGED"

# shellcheck source=lib/engine_mode.sh
. "$PROJECT_ROOT/scripts/lib/engine_mode.sh"
SCOPE="$(instrumentation_scope "$STAGED")"
case "$SCOPE" in
  library)
    log "instrumentation_scope=library (safetensors parser is statically linked and classified)"
    ;;
  driver_only)
    if [[ "${ALLOW_DRIVER_ONLY:-0}" == "1" ]]; then
      log "WARN: instrumentation_scope=driver_only (ALLOW_DRIVER_ONLY=1)"
    else
      fail "the freshly built replay is instrumented but safetensors parser symbols were not found; refusing a driver-only arm ($OUT left unchanged)"
    fi
    ;;
  none)
    if [[ "${ALLOW_UNINSTRUMENTED:-0}" == "1" ]]; then
      log "WARN: $OUT has no AFL++ instrumentation (ALLOW_UNINSTRUMENTED=1)"
    else
      fail "the freshly built replay has no AFL++ instrumentation; cargo-afl runtime was not linked ($OUT left unchanged)"
    fi
    ;;
  *)
    fail "unexpected instrumentation scope: $SCOPE"
    ;;
esac

staged_commit "$STAGED" "$OUT" || exit 1
trap - EXIT

log "done"
echo "out: $OUT"
echo "instrumentation_scope: $SCOPE"
