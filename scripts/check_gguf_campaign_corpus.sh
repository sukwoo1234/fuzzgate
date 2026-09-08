#!/usr/bin/env bash
# R26: run_long's default GGUF libFuzzer corpus must be a writable copy, not a fixture.
set -euo pipefail

# This script is copied into a temporary WORKDIR as a deliberately writing backend.
# Exercise run_long's actual environment handoff without native binaries or a timer.
if [[ "${BASH_SOURCE[0]##*/}" == run_backend_loop.sh ]]; then
  printf '%s\n' "$CORPUS_DIR" > "$CORPUS_PROBE"
  printf 'discovered unit\n' > "$CORPUS_DIR/fuzzer-discovery"
  if [[ "${MUTATE_SEED:-0}" == 1 ]]; then
    printf 'fuzzer-modified seed\n' > "$CORPUS_DIR/mutable.gguf"
  fi
  exit 0
fi

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export HOOK_FILE="$WORK/no-discord-hook" DISCORD_WEBHOOK="" GGUF_LIBFUZZER_CORPUS_CAP=1048576

fail() { echo "[gguf-campaign-corpus] fail: $*" >&2; exit 1; }
log() { echo "[gguf-campaign-corpus] $*"; }

new_root() {
  ROOT="$WORK/$1"
  ORIGINAL="$ROOT/seeds/gguf"
  DERIVED="$ROOT/data/corpus/gguf-libfuzzer"
  CORPUS="$ROOT/data/corpus/libfuzzer/gguf"
  mkdir -p "$ROOT/scripts" "$ORIGINAL"
  cp "${BASH_SOURCE[0]}" "$ROOT/scripts/run_backend_loop.sh"
  printf 'original seed\n' > "$ORIGINAL/seed.gguf"
  printf 'original mutable seed\n' > "$ORIGINAL/mutable.gguf"
}

make_derived() {
  mkdir -p "$DERIVED"
  printf 'reduced seed\n' > "$DERIVED/seed.gguf"
  printf 'reduced mutable seed\n' > "$DERIVED/mutable.gguf"
}

snapshot() {
  if [[ ! -d "$1" ]]; then
    printf 'missing directory\n'
    return
  fi
  (cd "$1" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum)
}

run_long() {
  local expected="$1"
  shift
  local before_original before_derived
  before_original="$(snapshot "$ORIGINAL")"
  before_derived="$(snapshot "$DERIVED")"
  env -u TOOL_LIBFUZZER_CMD -u TOOL_LIBFUZZER_MODE -u LIBFUZZER_DRIVER \
    REQUIRE_NATIVE=0 REQUIRE_INSTRUMENTED=0 \
    WORKDIR="$ROOT" DATA_DIR="$ROOT/output" CORPUS_PROBE="$ROOT/probe" \
    bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend libfuzzer \
      --duration-seconds 1 --tag corpus-check "$@" > "$ROOT/run.log" 2>&1 \
    || { cat "$ROOT/run.log" >&2; fail 'run_long failed'; }
  [[ "$(cat "$ROOT/probe")" == "$expected" ]] \
    || fail "backend received $(cat "$ROOT/probe"), expected $expected"
  [[ "$(snapshot "$ORIGINAL")" == "$before_original" ]] || fail 'original fixture changed'
  [[ "$(snapshot "$DERIVED")" == "$before_derived" ]] || fail 'derived fixture changed'
  [[ -f "$expected/fuzzer-discovery" ]] || fail 'writing backend did not run'
}

log 'fresh default: copy derived fixture, isolate backend writes, ignore DATA_DIR override'
new_root fresh
make_derived
MUTATE_SEED=1 run_long "$CORPUS"
cmp -s "$DERIVED/seed.gguf" "$CORPUS/seed.gguf" || fail 'derived seed was not copied'
[[ "$(cat "$CORPUS/mutable.gguf")" == 'fuzzer-modified seed' ]] || fail 'seed was not mutated'
[[ "$(cat "$CORPUS.seeded-from")" == "$DERIVED" ]] || fail 'wrong seed marker'
grep -Fq "seed_fixture=$DERIVED" "$ROOT/run.log" || fail 'seed fixture is not logged'
[[ ! -e "$ROOT/output/corpus" ]] || fail 'DATA_DIR changed the default corpus location'

log 'repeated default: preserve discoveries and locally modified seeds'
printf 'older discovery\n' > "$CORPUS/older-discovery"
run_long "$CORPUS"
[[ "$(cat "$CORPUS/older-discovery")" == 'older discovery' ]] || fail 'discovery lost'
[[ "$(cat "$CORPUS/mutable.gguf")" == 'fuzzer-modified seed' ]] || fail 'modified seed replaced'

log 'missing derived: copy originals, then safely replace identical seeds on transition'
new_root transition
MUTATE_SEED=1 run_long "$CORPUS"
cmp -s "$ORIGINAL/seed.gguf" "$CORPUS/seed.gguf" || fail 'fallback seed was not copied'
[[ "$(cat "$CORPUS.seeded-from")" == "$ORIGINAL" ]] || fail 'wrong fallback marker'
printf 'older discovery\n' > "$CORPUS/older-discovery"
make_derived
run_long "$CORPUS"
cmp -s "$DERIVED/seed.gguf" "$CORPUS/seed.gguf" || fail 'old identical seed was not replaced'
[[ "$(cat "$CORPUS/older-discovery")" == 'older discovery' ]] || fail 'transition lost discovery'
[[ "$(cat "$CORPUS/mutable.gguf")" == 'fuzzer-modified seed' ]] || fail 'transition replaced modified seed'
[[ "$(cat "$CORPUS.seeded-from")" == "$DERIVED" ]] || fail 'transition did not update marker'

log 'incomplete and over-cap derivatives: use isolated original copies'
new_root incomplete
mkdir -p "$DERIVED"
printf 'partial seed\n' > "$DERIVED/seed.gguf"
run_long "$CORPUS"
cmp -s "$ORIGINAL/seed.gguf" "$CORPUS/seed.gguf" || fail 'partial derivative accepted'
new_root over_cap
make_derived
truncate -s 1048576 "$DERIVED/seed.gguf"
run_long "$CORPUS"
cmp -s "$ORIGINAL/seed.gguf" "$CORPUS/seed.gguf" || fail 'over-cap derivative accepted'

log 'explicit corpus (including campaign arm copies): no default seeding'
new_root explicit
make_derived
EXPLICIT="$ROOT/campaign/gguf/libfuzzer/corpus"
mkdir -p "$EXPLICIT"
printf 'caller seed\n' > "$EXPLICIT/caller.gguf"
run_long "$EXPLICIT" --corpus-dir "$EXPLICIT"
[[ ! -e "$CORPUS" && ! -e "$EXPLICIT.seeded-from" && ! -e "$EXPLICIT/seed.gguf" ]] \
  || fail 'explicit corpus was automatically seeded'
[[ "$(cat "$EXPLICIT/caller.gguf")" == 'caller seed' ]] || fail 'caller seed changed'

log 'missing source fixture: retain exit 2 and do not create an empty working corpus'
ROOT="$WORK/missing"
mkdir -p "$ROOT"
rc=0
env -u TOOL_LIBFUZZER_CMD WORKDIR="$ROOT" \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target gguf --backend libfuzzer \
    --duration-seconds 1 --tag corpus-check > "$ROOT/run.log" 2>&1 || rc=$?
[[ "$rc" -eq 2 ]] || fail "missing fixture returned $rc, expected 2"
grep -Fq 'corpus dir not found:' "$ROOT/run.log" || fail 'missing fixture error was lost'
[[ ! -e "$ROOT/data/corpus/libfuzzer/gguf" ]] || fail 'missing fixture created an empty corpus'

log 'PASS: default isolation, seed transition, fallback, preservation and explicit overrides'
