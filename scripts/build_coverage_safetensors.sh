#!/usr/bin/env bash
# Build a source-instrumented (rustc -Cinstrument-coverage) safetensors replay so a
# coverage run counts real edges of the safetensors crate parser, not harness-only.
# Rust's own coverage flag replaces the clang -fprofile-instr-generate path the ONNX
# build uses; the crate is Rust, so there is no .so / .cc / cmake here. Fully offline
# (vendored deps).
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
FUZZ_DIR="${FUZZ_DIR:-$PROJECT_ROOT/fuzz}"
# Distinct output dir so the instrumented binary never collides with the panic=abort
# fuzzing replay under fuzz/target/release.
COV_TARGET_DIR="${COV_TARGET_DIR:-$FUZZ_DIR/target-cov}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
OUT_BIN="${OUT_BIN:-$COV_TARGET_DIR/safetensors_loader_replay_cov}"

log() { echo "[st-cov-build] $*"; }
fail() { echo "[st-cov-build] fail: $*" >&2; exit 1; }

command -v rustc >/dev/null || fail "rustc missing"
rustup toolchain list 2>/dev/null | grep -q nightly || fail "nightly toolchain missing (run S0)"

log "building instrumented replay (rustc -Cinstrument-coverage, offline)"
mkdir -p "$COV_TARGET_DIR"
# -Cinstrument-coverage also instruments proc-macros and build scripts that RUN during
# the build; without a contained LLVM_PROFILE_FILE they drop default_*.profraw into the
# CWD and the vendored crate dirs (which are committed). Pin their output into the
# gitignored target-cov dir so the tree stays clean.
LLVM_PROFILE_FILE="$COV_TARGET_DIR/build-%p.profraw" \
RUSTFLAGS="-Cinstrument-coverage" CARGO_NET_OFFLINE=true \
  cargo +nightly build --release \
    --bin safetensors_loader_replay \
    --manifest-path "$FUZZ_DIR/Cargo.toml" \
    --target-dir "$COV_TARGET_DIR"

# R55: same staging discipline as the native builds. These outputs are rebuildable, but
# a link or copy that fails part-way still leaves a truncated binary where a working
# one was, and the coverage runners would then measure it.
# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT_BIN || exit 1
trap staged_cleanup EXIT
staged_new "$OUT_BIN" STAGED_BIN || exit 1

BUILT="$(find "$COV_TARGET_DIR" -type f -path '*/release/safetensors_loader_replay' ! -path '*/build/*' | head -1)"
[[ -n "$BUILT" ]] || fail "could not locate instrumented replay binary"
cp "$BUILT" "$STAGED_BIN"
staged_commit "$STAGED_BIN" "$OUT_BIN" || exit 1
trap - EXIT
log "instrumented replay -> $OUT_BIN"
echo "$OUT_BIN"
