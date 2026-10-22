#!/usr/bin/env bash
# FND-04: every launcher must resolve the target registry before it trusts an
# explicit corpus, and must reject registry rows it cannot safely dispatch.
# Fixture-only: fake target-spec/tool, one-iteration loops, no fuzzing or network.
set -uo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/target-registry-consumers-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*" >&2; }

mkdir -p "$WORK/bin" "$WORK/net-bin" "$WORK/corpus" "$WORK/seeds/fixture" \
  "$WORK/long-root/scripts" "$WORK/long-root/harnesses/libfuzzer" \
  "$WORK/export-data/runs/run-fixture"
printf 'seed' >"$WORK/corpus/seed.blob"
printf 'seed' >"$WORK/seeds/fixture/seed.blob"
printf '[package]\nname="fixture"\nversion="0.0.0"\n' >"$WORK/Cargo.toml"
printf '{"total":1,"success":1,"failed":0,"timeout":0,"retries":0,"rejected":0,"engine_mode":"fixture"}\n' \
  >"$WORK/export-data/runs/run-fixture/status.json"
printf '{"metrics":{}}\n' >"$WORK/export-data/metrics.json"

cat >"$WORK/bin/tool" <<'TOOL'
#!/usr/bin/env bash
set -u
printf '%s\n' "$*" >>"${SPEC_LOG:?}"
if [[ "${1:-}" == target-spec ]]; then
  printf 'target_id=%s\n' "${SPEC_TARGET_ID:-demo}"
  printf 'seed_subdir=%s\n' "${SPEC_SEED_SUBDIR:-fixture}"
  printf 'input_ext=%s\n' "${SPEC_INPUT_EXT:-blob}"
  printf 'mutation_supported=%s\n' "${SPEC_MUTATION_SUPPORTED:-1}"
  printf 'campaign_supported=%s\n' "${SPEC_CAMPAIGN_SUPPORTED:-1}"
  exit 0
fi
if [[ "${1:-}" == run ]]; then
  printf '%s\n' "${TOOL_LIBFUZZER_CMD:-}" >>"${ENGINE_ENV_LOG:?}"
fi
exit 0
TOOL
chmod +x "$WORK/bin/tool"

# The host preflight checks that Cargo is discoverable, but this suite only
# verifies registry routing.  Supply a fixture command so the result does not
# depend on whether the acceptance runner's deliberately minimal PATH happens
# to contain the host's Cargo installation.
cat >"$WORK/bin/cargo" <<'CARGO'
#!/usr/bin/env bash
exit 0
CARGO
chmod +x "$WORK/bin/cargo"

cat >"$WORK/net-bin/curl" <<'CURL'
#!/usr/bin/env bash
set -eu
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="${2:?}"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$out" ]]
printf 'fixture-download\n' >"$out"
CURL
chmod +x "$WORK/net-bin/curl"

cat >"$WORK/long-root/scripts/run_backend_loop.sh" <<'LOOP'
#!/usr/bin/env bash
set -eu
printf '%s\n' "${TOOL_LIBFUZZER_CMD:-}" >"${LONG_ENV_LOG:?}"
LOOP
chmod +x "$WORK/long-root/scripts/run_backend_loop.sh"

run_refusal() { # run_refusal <label> <log> <command...>
  local label="$1" log="$2" rc=0
  shift 2
  "$@" >"$log" 2>&1 || rc=$?
  if [[ "$rc" -eq 2 ]]; then
    ok "$label"
  else
    bad "$label (rc=$rc, expected=2)"
    sed -n '1,5p' "$log" | sed 's/^/       /' >&2
  fi
}

run_success() { # run_success <label> <needle> <log> <command...>
  local label="$1" needle="$2" log="$3" rc=0
  shift 3
  "$@" >"$log" 2>&1 || rc=$?
  if [[ "$rc" -eq 0 ]] && grep -Fq -- "$needle" "$log"; then
    ok "$label"
  else
    bad "$label (rc=$rc, expected text: $needle)"
    sed -n '1,8p' "$log" | sed 's/^/       /' >&2
  fi
}

base_env=(
  SPEC_LOG="$WORK/spec.log"
  ENGINE_ENV_LOG="$WORK/engine-env.log"
  TOOL_BIN="$WORK/bin/tool"
  TARGET=demo
  HOME="$WORK"
  HOOK_FILE="$WORK/no-hook"
  DISCORD_WEBHOOK=
  SPEC_TARGET_ID=demo
  SPEC_INPUT_EXT=blob
)

# An explicit corpus is data, not authority to bypass registry capability checks.
: >"$WORK/spec.log"
run_refusal "backend loop rejects campaign-disabled target with explicit corpus" \
  "$WORK/backend-unsupported.log" env "${base_env[@]}" \
  SPEC_SEED_SUBDIR=fixture SPEC_MUTATION_SUPPORTED=1 SPEC_CAMPAIGN_SUPPORTED=0 \
  WORKDIR="$WORK" DATA_DIR="$WORK/backend-data" CORPUS_DIR="$WORK/corpus" \
  DURATION_SECONDS=0 bash "$PROJECT_ROOT/scripts/run_backend_loop.sh"

run_refusal "campaign rejects campaign-disabled target with explicit corpus" \
  "$WORK/campaign-unsupported.log" env "${base_env[@]}" \
  SPEC_SEED_SUBDIR=fixture SPEC_MUTATION_SUPPORTED=1 SPEC_CAMPAIGN_SUPPORTED=0 \
  WORKDIR="$WORK" bash "$PROJECT_ROOT/scripts/run_campaign.sh" \
  --mode serial --target demo --duration-seconds 1 --campaign-id fixture \
  --corpus-dir "$WORK/corpus" --dry-run

run_refusal "run-long rejects campaign-disabled target with explicit corpus" \
  "$WORK/long-unsupported.log" env "${base_env[@]}" \
  SPEC_SEED_SUBDIR=fixture SPEC_MUTATION_SUPPORTED=1 SPEC_CAMPAIGN_SUPPORTED=0 \
  WORKDIR="$WORK/long-root" bash "$PROJECT_ROOT/scripts/run_long.sh" \
  --target demo --backend local-harness --duration-seconds 1 --tag fixture \
  --corpus-dir "$WORK/corpus"

run_refusal "mutation loop rejects mutation-disabled target with explicit seed dir" \
  "$WORK/mutate-unsupported.log" env "${base_env[@]}" \
  SPEC_SEED_SUBDIR=fixture SPEC_MUTATION_SUPPORTED=0 SPEC_CAMPAIGN_SUPPORTED=1 \
  PROJECT_ROOT="$WORK" SEED_DIR="$WORK/seeds/fixture" \
  FUZZ_LOOP_MAX_ITERATIONS=1 ITERATION_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/ops/scripts/fuzz-loop.sh"

run_refusal "libFuzzer loop rejects campaign-disabled target with explicit corpus" \
  "$WORK/libfuzzer-unsupported.log" env "${base_env[@]}" \
  SPEC_SEED_SUBDIR=fixture SPEC_MUTATION_SUPPORTED=1 SPEC_CAMPAIGN_SUPPORTED=0 \
  PROJECT_ROOT="$WORK" TARGET=demo CORPUS_DIR="$WORK/seeds/fixture" \
  FUZZ_LOOP_MAX_ITERATIONS=1 ITERATION_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/ops/scripts/fuzz-loop-libfuzzer.sh"

run_refusal "AFL++ loop rejects campaign-disabled target with explicit corpus" \
  "$WORK/aflpp-unsupported.log" env "${base_env[@]}" \
  SPEC_SEED_SUBDIR=fixture SPEC_MUTATION_SUPPORTED=1 SPEC_CAMPAIGN_SUPPORTED=0 \
  PROJECT_ROOT="$WORK" TARGET=demo CORPUS_DIR="$WORK/corpus" \
  RUNS_ROOT="$WORK/runs" AFLPP_RUN_SUMMARY_ROOT="$WORK/archive" \
  FUZZ_LOOP_MAX_ITERATIONS=1 ITERATION_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/ops/scripts/fuzz-loop-aflpp.sh"

if [[ "$(grep -c '^target-spec ' "$WORK/spec.log")" -eq 6 ]]; then
  ok "all six launchers resolve target-spec even with explicit corpus paths"
else
  bad "not every launcher resolved target-spec with an explicit corpus"
fi

# A registry path component is rejected even when the caller supplied a corpus,
# because the same row is used by other paths and must be safe as a whole.
for launcher in backend campaign long mutate libfuzzer aflpp; do
  case "$launcher" in
    backend)
      command=(env "${base_env[@]}" SPEC_SEED_SUBDIR=. SPEC_MUTATION_SUPPORTED=1 \
        SPEC_CAMPAIGN_SUPPORTED=1 WORKDIR="$WORK" DATA_DIR="$WORK/invalid-backend" \
        CORPUS_DIR="$WORK/corpus" DURATION_SECONDS=0 \
        bash "$PROJECT_ROOT/scripts/run_backend_loop.sh")
      ;;
    campaign)
      command=(env "${base_env[@]}" SPEC_SEED_SUBDIR=. SPEC_MUTATION_SUPPORTED=1 \
        SPEC_CAMPAIGN_SUPPORTED=1 WORKDIR="$WORK" \
        bash "$PROJECT_ROOT/scripts/run_campaign.sh" --mode serial --target demo \
        --duration-seconds 1 --campaign-id invalid-seed --corpus-dir "$WORK/corpus" --dry-run)
      ;;
    long)
      command=(env "${base_env[@]}" SPEC_SEED_SUBDIR=. SPEC_MUTATION_SUPPORTED=1 \
        SPEC_CAMPAIGN_SUPPORTED=1 WORKDIR="$WORK/long-root" \
        bash "$PROJECT_ROOT/scripts/run_long.sh" --target demo --backend local-harness \
        --duration-seconds 1 --tag invalid-seed --corpus-dir "$WORK/corpus")
      ;;
    mutate)
      command=(env "${base_env[@]}" SPEC_SEED_SUBDIR=. SPEC_MUTATION_SUPPORTED=1 \
        SPEC_CAMPAIGN_SUPPORTED=1 PROJECT_ROOT="$WORK" SEED_DIR="$WORK/seeds/fixture" \
        FUZZ_LOOP_MAX_ITERATIONS=1 ITERATION_SLEEP_SEC=0 \
        bash "$PROJECT_ROOT/ops/scripts/fuzz-loop.sh")
      ;;
    libfuzzer)
      command=(env "${base_env[@]}" SPEC_SEED_SUBDIR=. SPEC_MUTATION_SUPPORTED=1 \
        SPEC_CAMPAIGN_SUPPORTED=1 PROJECT_ROOT="$WORK" TARGET=demo \
        CORPUS_DIR="$WORK/seeds/fixture" FUZZ_LOOP_MAX_ITERATIONS=1 ITERATION_SLEEP_SEC=0 \
        bash "$PROJECT_ROOT/ops/scripts/fuzz-loop-libfuzzer.sh")
      ;;
    aflpp)
      command=(env "${base_env[@]}" SPEC_SEED_SUBDIR=. SPEC_MUTATION_SUPPORTED=1 \
        SPEC_CAMPAIGN_SUPPORTED=1 PROJECT_ROOT="$WORK" TARGET=demo CORPUS_DIR="$WORK/corpus" \
        RUNS_ROOT="$WORK/runs" AFLPP_RUN_SUMMARY_ROOT="$WORK/archive" \
        FUZZ_LOOP_MAX_ITERATIONS=1 ITERATION_SLEEP_SEC=0 \
        bash "$PROJECT_ROOT/ops/scripts/fuzz-loop-aflpp.sh")
      ;;
  esac
  run_refusal "$launcher rejects unsafe seed_subdir" "$WORK/$launcher-invalid-seed.log" \
    "${command[@]}"
done

# The input extension is an independent registry field; a target id is not an
# acceptable substitute in black-box libFuzzer commands.
: >"$WORK/engine-env.log"
env "${base_env[@]}" SPEC_SEED_SUBDIR=fixture SPEC_MUTATION_SUPPORTED=1 \
  SPEC_CAMPAIGN_SUPPORTED=1 PROJECT_ROOT="$WORK" TARGET=demo \
  CORPUS_DIR="$WORK/seeds/fixture" FUZZ_LOOP_MAX_ITERATIONS=1 ITERATION_SLEEP_SEC=0 \
  bash "$PROJECT_ROOT/ops/scripts/fuzz-loop-libfuzzer.sh" \
  >"$WORK/libfuzzer-ext.log" 2>&1
if grep -Fq 'TOOL_HARNESS_EXT=blob' "$WORK/engine-env.log"; then
  ok "libFuzzer loop uses registry input_ext"
else
  bad "libFuzzer loop substituted target id for registry input_ext"
fi

LONG_ENV_LOG="$WORK/long-env.log" env "${base_env[@]}" \
  SPEC_SEED_SUBDIR=fixture SPEC_MUTATION_SUPPORTED=1 SPEC_CAMPAIGN_SUPPORTED=1 \
  LONG_ENV_LOG="$WORK/long-env.log" WORKDIR="$WORK/long-root" \
  bash "$PROJECT_ROOT/scripts/run_long.sh" --target demo --backend libfuzzer \
  --duration-seconds 1 --tag ext --corpus-dir "$WORK/corpus" \
  >"$WORK/long-ext.log" 2>&1
if grep -Fq 'TOOL_HARNESS_EXT=blob' "$WORK/long-env.log"; then
  ok "run-long uses registry input_ext"
else
  bad "run-long substituted target id for registry input_ext"
fi

# The remaining operator entrypoints must consume the same registry row too.
# These fixtures use a registry target whose id, seed directory and extension are
# deliberately different, so substituting TARGET for either metadata field fails.
: >"$WORK/spec-extra.log"
extra_env=(
  SPEC_LOG="$WORK/spec-extra.log"
  ENGINE_ENV_LOG="$WORK/engine-env.log"
  TOOL_BIN="$WORK/bin/tool"
  SPEC_TARGET_ID=demo
  SPEC_SEED_SUBDIR=fixture
  SPEC_INPUT_EXT=blob
  SPEC_MUTATION_SUPPORTED=1
  SPEC_CAMPAIGN_SUPPORTED=1
  HOME="$WORK"
  PATH="$WORK/bin:$PATH"
)

run_success "host preflight resolves registry seed_subdir and input_ext" \
  "seeds: $WORK/seeds/fixture (1 files)" "$WORK/preflight.log" \
  env "${extra_env[@]}" WORKDIR="$WORK" \
  bash "$PROJECT_ROOT/scripts/fuzz_host_preflight.sh" --target demo \
  --backends local-harness --data-dir "$WORK/preflight-data" \
  --seeds-dir "$WORK/seeds" --min-free-gb 0

run_success "smoke launcher accepts a campaign-capable registry target" \
  "[smoke] target=demo" "$WORK/smoke.log" \
  env "${extra_env[@]}" WORKDIR="$WORK" \
  bash "$PROJECT_ROOT/scripts/fuzz_smoke.sh" --target demo \
  --backend local-harness --seconds 1 --id registry-smoke --dry-run

run_success "seed fetch uses registry input_ext without network" \
  "collected raw blob files: 1" "$WORK/seed-fetch.log" \
  env "${extra_env[@]}" WORKDIR="$WORK" PATH="$WORK/net-bin:$PATH" \
  bash "$PROJECT_ROOT/scripts/seed_fetch.sh" --target demo \
  --url https://github.com/example/model.bin --tmp-dir "$WORK/seed-fetch-tmp"
if grep -Fq "seed sync --target demo --from $WORK/seed-fetch-tmp/raw --to $WORK/seeds/fixture --harness-filter" \
    "$WORK/spec-extra.log" \
  && grep -Fq "seed stats --target demo --dir $WORK/seeds/fixture" \
    "$WORK/spec-extra.log"; then
  ok "seed fetch uses TOOL_BIN and registry default seed_subdir for sync"
else
  bad "seed fetch bypassed TOOL_BIN or registry seed_subdir during sync"
fi

run_success "experiment export resolves registry metadata" \
  "[export-experiment] done" "$WORK/export.log" \
  env "${extra_env[@]}" WORKDIR="$WORK" \
  bash "$PROJECT_ROOT/scripts/export_experiment_summary.sh" \
  --experiment-id registry-export --machine-label fixture --target demo \
  --backend local-harness --duration-hours 1 \
  --data-dir "$WORK/export-data" --metrics-file "$WORK/export-data/metrics.json" \
  --run-status-file "$WORK/export-data/runs/run-fixture/status.json" \
  --out-dir "$WORK/export-out"
if [[ -f "$WORK/export-out/manifest.json" ]] \
  && [[ "$(jq -r '.seed_count' "$WORK/export-out/manifest.json")" == 1 ]] \
  && [[ "$(jq -r '.corpus_dir' "$WORK/export-out/manifest.json")" == "$WORK/seeds/fixture" ]]; then
  ok "experiment export uses registry seed_subdir and input_ext"
else
  bad "experiment export substituted target id for registry corpus metadata"
fi

if [[ "$(grep -c '^target-spec ' "$WORK/spec-extra.log")" -eq 4 ]]; then
  ok "all four remaining entrypoints resolve target-spec"
else
  bad "not every remaining entrypoint resolved target-spec"
fi

for launcher in preflight smoke seed-fetch export; do
  case "$launcher" in
    preflight)
      command=(env "${extra_env[@]}" SPEC_INPUT_EXT=. WORKDIR="$WORK" \
        bash "$PROJECT_ROOT/scripts/fuzz_host_preflight.sh" --target demo \
        --backends local-harness --data-dir "$WORK/preflight-invalid" \
        --seeds-dir "$WORK/seeds" --min-free-gb 0)
      ;;
    smoke)
      command=(env "${extra_env[@]}" SPEC_INPUT_EXT=. WORKDIR="$WORK" \
        bash "$PROJECT_ROOT/scripts/fuzz_smoke.sh" --target demo \
        --backend local-harness --seconds 1 --id invalid-ext --dry-run)
      ;;
    seed-fetch)
      command=(env "${extra_env[@]}" SPEC_INPUT_EXT=. WORKDIR="$WORK" \
        PATH="$WORK/net-bin:$PATH" bash "$PROJECT_ROOT/scripts/seed_fetch.sh" \
        --target demo --url https://github.com/example/model.bin --no-sync)
      ;;
    export)
      command=(env "${extra_env[@]}" SPEC_INPUT_EXT=. WORKDIR="$WORK" \
        bash "$PROJECT_ROOT/scripts/export_experiment_summary.sh" \
        --experiment-id invalid-ext --machine-label fixture --target demo \
        --backend local-harness --duration-hours 1 \
        --data-dir "$WORK/export-data" --metrics-file "$WORK/export-data/metrics.json" \
        --run-status-file "$WORK/export-data/runs/run-fixture/status.json" \
        --out-dir "$WORK/export-invalid")
      ;;
  esac
  run_refusal "$launcher rejects unsafe registry input_ext" \
    "$WORK/$launcher-invalid-ext.log" "${command[@]}"
done

run_refusal "host preflight rejects campaign-disabled registry target" \
  "$WORK/preflight-disabled.log" env "${extra_env[@]}" \
  SPEC_CAMPAIGN_SUPPORTED=0 WORKDIR="$WORK" \
  bash "$PROJECT_ROOT/scripts/fuzz_host_preflight.sh" --target demo \
  --backends local-harness --data-dir "$WORK/preflight-disabled-data" \
  --seeds-dir "$WORK/seeds" --min-free-gb 0
run_refusal "smoke launcher rejects campaign-disabled registry target" \
  "$WORK/smoke-disabled.log" env "${extra_env[@]}" \
  SPEC_CAMPAIGN_SUPPORTED=0 WORKDIR="$WORK" \
  bash "$PROJECT_ROOT/scripts/fuzz_smoke.sh" --target demo \
  --backend local-harness --seconds 1 --id disabled --dry-run

printf '[target-registry-consumers] pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
