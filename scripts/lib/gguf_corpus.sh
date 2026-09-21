# shellcheck shell=bash
# C3: which directory seeds a gguf libFuzzer run. Sourced by
# ops/scripts/fuzz-loop-libfuzzer.sh and scripts/run_long.sh so both entry points agree;
# verified by scripts/check_engine_mode_labels.sh.
#
# libFuzzer never generates an input longer than -max_len, and our loops do not set it,
# so it derives one from the corpus and never goes above 1 MB. 15 of the 19 gguf seeds
# are larger than that (1.16 MB - 10.9 MB): they are read, but no input it generates
# ever reaches their size, so the deep structure they were chosen for is never
# reproduced. scripts/build_gguf_libfuzzer_corpus.sh derives an under-cap corpus that
# keeps every metadata key.
#
# ONLY the libFuzzer arm wants this. AFL++ has no such cap, and the gguf AFL++ unit
# deliberately keeps reading seeds/gguf so its inputs stay the full-size originals - the
# two arms therefore run on deliberately different corpora, which is recorded in the
# runbook and must be stated whenever the arms are compared.

GGUF_LIBFUZZER_CORPUS_CAP="${GGUF_LIBFUZZER_CORPUS_CAP:-1048576}"

# Echoes the directory a gguf libFuzzer run should seed from, and returns 1 when it had
# to fall back (so the caller can WARN). Never silently prefers a corpus it cannot vouch
# for: a half-written build directory would quietly shrink the seed set instead.
gguf_libfuzzer_seed_fixture() {
    local project_root="$1"
    local original="${project_root}/seeds/gguf"
    local reduced="${project_root}/data/corpus/gguf-libfuzzer"

    if [ ! -d "${reduced}" ] || [ -z "$(ls -A "${reduced}" 2>/dev/null)" ]; then
        printf '%s' "${original}"
        return 1
    fi
    if [ -d "${original}" ] && ! gguf_reduced_corpus_covers "${reduced}" "${original}"; then
        printf '%s' "${original}"
        return 1
    fi
    printf '%s' "${reduced}"
    return 0
}

# True when the derived corpus covers exactly the seed set and every file is under the
# cap it exists to satisfy.
gguf_reduced_corpus_covers() {
    local reduced="$1" original="$2"
    local a b
    a="$(cd "${reduced}" && ls -1 ./*.gguf 2>/dev/null | sort)"
    b="$(cd "${original}" && ls -1 ./*.gguf 2>/dev/null | sort)"
    [ "${a}" = "${b}" ] || return 1
    ! find "${reduced}" -maxdepth 1 -name '*.gguf' -size +"$((GGUF_LIBFUZZER_CORPUS_CAP - 1))"c \
        -print -quit 2>/dev/null | grep -q .
}

# Seed a private working corpus from a fixture, evicting whatever a DIFFERENT fixture
# put there on an earlier run. Without the eviction `cp -n` keeps the old units under
# the same names, so building the under-cap corpus changed nothing on any machine that
# had already run the arm - while the loop logged the new fixture as if it were in use.
# Only units byte-identical to the old fixture's are removed, so anything libFuzzer
# itself discovered survives.
gguf_seed_working_corpus() {
    local corpus_dir="${1%/}" fixture="$2"
    local marker="${corpus_dir}.seeded-from"
    local previous=""
    local fixture_root previous_root=""

    [ -f "${marker}" ] && previous="$(cat "${marker}" 2>/dev/null || true)"
    if [ ! -d "${fixture}" ]; then
        printf '[gguf-corpus] seed fixture not found: %s\n' "${fixture}" >&2
        return 1
    fi
    fixture_root="$(realpath -e -- "${fixture}")" || return 1
    if [ -n "${previous}" ]; then
        # Without the previous fixture's bytes, the helper cannot distinguish its
        # old seed copies from discoveries. Refuse rather than label stale units as
        # if they came from the new fixture.
        if [ ! -d "${previous}" ]; then
            printf '[gguf-corpus] previous seed fixture not found: %s\n' "${previous}" >&2
            return 1
        fi
        previous_root="$(realpath -e -- "${previous}")" || return 1
    fi
    mkdir -p "${corpus_dir}"

    local evicted=0
    if [ -n "${previous_root}" ] && [ "${previous_root}" != "${fixture_root}" ]; then
        local old victim
        for old in "${previous_root}"/*; do
            [ -f "${old}" ] || continue
            victim="${corpus_dir}/$(basename "${old}")"
            if [ -f "${victim}" ] && cmp -s "${old}" "${victim}"; then
                rm -f "${victim}"
                evicted=$((evicted + 1))
            fi
        done
    fi
    cp -n "${fixture_root}"/* "${corpus_dir}/" 2>/dev/null || true
    printf '%s\n' "${fixture_root}" > "${marker}"
    printf '%s' "${evicted}"
}
