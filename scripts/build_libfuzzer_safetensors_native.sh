#!/usr/bin/env bash
# Build the native safetensors harness (in-process libFuzzer target + standalone
# replay) from the PINNED safetensors crate. Unlike the gguf/onnx builds there is no
# clang/cmake/patch step: the loader IS a Rust crate, so this is cargo-fuzz + a plain
# release build. Deps are vendored (vendor/), so this runs fully offline.
#
#   1. verify the target-of-record tarball against meta.json's sha256 (provenance)
#   2. verify the crate actually built is safetensors 0.7.0 (fuzz/Cargo.lock)
#   3. cargo-fuzz build the in-process target
#   4. build the standalone replay with -C panic=abort so a panic aborts (a finding)
#   5. self-test the replay's exit-code contract
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
ST_VER="${ST_VER:-v0.7.0}"
ST_CRATE_VER="${ST_CRATE_VER:-0.7.0}"
TARGET_DIR="${TARGET_DIR:-$PROJECT_ROOT/data/targets/safetensors/$ST_VER}"
META="${META:-$TARGET_DIR/meta.json}"
ARCHIVE="${ARCHIVE:-$TARGET_DIR/source/$ST_VER.tar.gz}"
FUZZ_DIR="${FUZZ_DIR:-$PROJECT_ROOT/fuzz}"
OUT_FUZZER="${OUT_FUZZER:-$PROJECT_ROOT/harnesses/libfuzzer/safetensors_loader_fuzzer}"
OUT_REPLAY="${OUT_REPLAY:-$PROJECT_ROOT/harnesses/libfuzzer/safetensors_loader_replay}"

log() { echo "[st-build] $*"; }
fail() { echo "[st-build] fail: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
usage: build_libfuzzer_safetensors_native.sh

Builds harnesses/libfuzzer/safetensors_loader_fuzzer (in-process libFuzzer) and
harnesses/libfuzzer/safetensors_loader_replay (standalone probe) from the pinned
safetensors crate, fully offline (vendored deps). Requires the S0 toolchain:
nightly + cargo-fuzz + a vendored crate tree.

Environment: PROJECT_ROOT ST_VER ST_CRATE_VER TARGET_DIR META ARCHIVE FUZZ_DIR
             OUT_FUZZER OUT_REPLAY
EOF
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }

# 1. provenance: tarball sha256 must match meta.json (the target of record)
[[ -f "$META" ]] || fail "meta.json not found: $META"
[[ -f "$ARCHIVE" ]] || fail "archive not found: $ARCHIVE"
want_sha="$(grep -oE '"downloaded_sha256":[[:space:]]*"[0-9a-f]{64}"' "$META" | grep -oE '[0-9a-f]{64}')"
got_sha="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
[[ -n "$want_sha" ]] || fail "no downloaded_sha256 in $META"
[[ "$want_sha" == "$got_sha" ]] || fail "archive sha mismatch (want $want_sha got $got_sha)"
log "provenance ok: $ST_VER tarball sha256 matches meta.json"

# 2. the crate actually compiled must be the pinned version
[[ -f "$FUZZ_DIR/Cargo.lock" ]] || fail "fuzz/Cargo.lock missing (run S0 vendor first)"
grep -qE "name = \"safetensors\"" "$FUZZ_DIR/Cargo.lock" \
  && grep -qE "version = \"$ST_CRATE_VER\"" "$FUZZ_DIR/Cargo.lock" \
  || fail "fuzz/Cargo.lock does not pin safetensors $ST_CRATE_VER"
log "crate pin ok: safetensors $ST_CRATE_VER in fuzz/Cargo.lock"

# toolchain presence (S0)
command -v cargo-fuzz >/dev/null || fail "cargo-fuzz missing (run S0 provisioning)"
rustup toolchain list 2>/dev/null | grep -q nightly || fail "nightly toolchain missing (run S0)"

# R55: cp opens its destination O_WRONLY|O_TRUNC, so an interrupted copy leaves a
# truncated file where the binary was - these two are the largest in the tree (19MB/6MB),
# the widest window of any build here.
# shellcheck source=lib/staged_install.sh
. "$SCRIPT_DIR/lib/staged_install.sh"
staged_target OUT_FUZZER || exit 1
staged_target OUT_REPLAY || exit 1
# Armed before the first staged_new: if the SECOND one fails, the first staging file is
# already on disk and nothing else would remove it.
trap staged_cleanup EXIT
staged_new "$OUT_FUZZER" STAGED_FUZZER || exit 1
staged_new "$OUT_REPLAY" STAGED_REPLAY || exit 1

# 3. in-process libFuzzer target (ASan on by default under cargo-fuzz)
log "building libFuzzer target (cargo-fuzz, offline)"
( cd "$PROJECT_ROOT" && CARGO_NET_OFFLINE=true cargo +nightly fuzz build safetensors_deserialize )
FUZZER_BIN="$(find "$FUZZ_DIR/target" -type f -path '*/release/safetensors_deserialize' ! -path '*/build/*' | head -1)"
[[ -n "$FUZZER_BIN" ]] || fail "could not locate built safetensors_deserialize binary"
cp "$FUZZER_BIN" "$STAGED_FUZZER"

# 4. standalone replay: -C panic=abort so a Rust panic becomes SIGABRT (a finding),
#    while a clean SafeTensorError still exits 9 (rejected).
log "building standalone replay (panic=abort, offline)"
( cd "$PROJECT_ROOT" && RUSTFLAGS="-C panic=abort" CARGO_NET_OFFLINE=true \
    cargo +nightly build --release --bin safetensors_loader_replay --manifest-path "$FUZZ_DIR/Cargo.toml" )
REPLAY_BIN="$(find "$FUZZ_DIR/target" -type f -path '*/release/safetensors_loader_replay' ! -path '*/build/*' | head -1)"
[[ -n "$REPLAY_BIN" ]] || fail "could not locate built safetensors_loader_replay binary"
cp "$REPLAY_BIN" "$STAGED_REPLAY"

# 5. self-test the exit-code contract of the replay we just produced
# Self-test the staged binary BEFORE it replaces the operational one: a replay that
# fails its own exit-code contract must not be installed.
"$STAGED_REPLAY" --selftest | grep -q "exit_codes: ok=0 rejected=9 unavailable=10" \
  || fail "replay --selftest did not print the expected exit-code contract ($OUT_REPLAY left unchanged)"

staged_commit "$STAGED_FUZZER" "$OUT_FUZZER" || exit 1
staged_commit "$STAGED_REPLAY" "$OUT_REPLAY" || exit 1
trap - EXIT
log "fuzzer -> $OUT_FUZZER"
log "replay -> $OUT_REPLAY"
log "replay selftest ok"

log "done"
echo "fuzzer: $OUT_FUZZER"
echo "replay: $OUT_REPLAY"
