use super::{align_up, parse_gguf, write_u64, GgufValueType, ALIGNMENT_KEY};
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "kv_insert";

/// Keys worth adding to a file that does not already have them. `general.alignment` is
/// the one that pays: ggml reads it back as a u32 with no type check
/// (gguf.cpp:478 -> :183) and none of the gguf seeds carries the key at all, so no
/// amount of in-place byte mutation can reach that path.
const INSERT_KEYS: &[&str] = &[
    ALIGNMENT_KEY,
    "general.architecture",
    "general.name",
    "split.no",
];

/// Scalar values small enough that a u32 `general.alignment` cannot inflate the
/// realignment padding to gigabytes. The powers of two get past ggml's power-of-2
/// check (gguf.cpp:481) and on to the code that uses the value; the rest exercise the
/// check itself.
const SCALAR_VALUES: &[u64] = &[0, 1, 2, 3, 16, 32, 64, 255, 1024, 4096];

const STRING_VALUES: &[&str] = &["", "x", "32", "llama"];

/// Element types an inserted array may carry. Nested arrays are left out on purpose:
/// the depth limit already has its own coverage, and a flat array is what reaches the
/// arity assert (gguf.cpp:864).
const SCALAR_TYPES: &[GgufValueType] = &[
    GgufValueType::U8,
    GgufValueType::I8,
    GgufValueType::U16,
    GgufValueType::I16,
    GgufValueType::U32,
    GgufValueType::I32,
    GgufValueType::F32,
    GgufValueType::Bool,
    GgufValueType::U64,
    GgufValueType::I64,
    GgufValueType::F64,
];

const ARRAY_COUNTS: &[usize] = &[0, 1, 2, 3];

const VALUE_TYPE_COUNT: usize = 13;

/// An insert shifts the metadata, so the alignment padding in front of the tensor data
/// has to be rebuilt. A file may declare an alignment far larger than the file itself -
/// our parser does not require the bytes to actually reach the data section - so
/// without a ceiling a declared 4 GB alignment would make the mutator the thing that
/// runs out of memory. The ceiling is relative to the input: padding a file to a
/// multiple of its own alignment is affordable, inflating a 60-byte file to gigabytes
/// is not.
pub(crate) const PADDING_HEADROOM: usize = 64 * 1024;

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;

    let existing: Vec<&[u8]> = layout
        .kvs
        .iter()
        .map(|kv| &bytes[kv.key_str_start..kv.key_str_end])
        .collect();
    let key = pick_key(&existing, rng).ok_or(OperatorError::NoApplicableField)?;

    let value_type = GgufValueType::from_u32(rng.index(VALUE_TYPE_COUNT) as u32)
        .ok_or(OperatorError::NoApplicableField)?;
    let payload = build_payload(value_type, rng);

    let mut entry = Vec::with_capacity(8 + key.len() + 4 + payload.len());
    entry.extend_from_slice(&(key.len() as u64).to_le_bytes());
    entry.extend_from_slice(key.as_bytes());
    entry.extend_from_slice(&(value_type as u32).to_le_bytes());
    entry.extend_from_slice(&payload);

    // The KV section ends where the tensor info begins; a file with no KVs has both at
    // the end of the 24-byte header.
    let kv_end = layout.kvs.last().map(|kv| kv.entry_end).unwrap_or(24);
    let tensor_info_end = layout.tensors.last().map(|t| t.entry_end).unwrap_or(kv_end);

    let mut out = Vec::with_capacity(bytes.len() + entry.len() + 64);
    out.extend_from_slice(&bytes[..kv_end]);
    out.extend_from_slice(&entry);
    out.extend_from_slice(&bytes[kv_end..tensor_info_end]);
    write_u64(&mut out, 16, layout.kv_count.saturating_add(1));

    // Re-read the alignment from the file we just built: an inserted
    // `general.alignment` changes where the data section has to start, and the
    // tensor offsets are relative to that start, so they need no rewriting.
    let data_start = layout.tensor_data_start.min(bytes.len());
    let data = &bytes[data_start..];
    let (padding, alignment_used) =
        padding_for(&out, data, layout.alignment, bytes.len() + PADDING_HEADROOM)
            .ok_or(OperatorError::NoApplicableField)?;
    out.resize(out.len() + padding, 0);
    out.extend_from_slice(data);

    let parse_preserving = if parse_gguf(&out).is_ok() {
        "yes"
    } else {
        "no"
    };
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("inserted_key", key),
            ("value_type", (value_type as u32).to_string()),
            ("insert_offset", kv_end.to_string()),
            (
                "new_kv_count",
                layout.kv_count.saturating_add(1).to_string(),
            ),
            ("alignment_used", alignment_used.to_string()),
            ("padding_bytes", padding.to_string()),
        ],
        parse_preserving,
    })
}

/// A key the file does not already carry. ggml rejects a duplicate key outright
/// (gguf.cpp:431) before it ever looks at a value, so a colliding insert would only
/// buy an early rejection.
fn pick_key(existing: &[&[u8]], rng: &mut DeterministicRng) -> Option<String> {
    let free: Vec<&str> = INSERT_KEYS
        .iter()
        .copied()
        .filter(|k| !existing.contains(&k.as_bytes()))
        .collect();
    if !free.is_empty() {
        return Some(free[rng.index(free.len())].to_string());
    }
    // Every interesting key is taken. Fall back to a name of our own so the operator
    // still applies instead of dropping the mutation on the floor.
    let start = rng.index(1024);
    (0..1024)
        .map(|i| format!("fuzz.kv.{}", (start + i) % 1024))
        .find(|k| !existing.contains(&k.as_bytes()))
}

fn build_payload(value_type: GgufValueType, rng: &mut DeterministicRng) -> Vec<u8> {
    match value_type {
        GgufValueType::String => {
            let s = STRING_VALUES[rng.index(STRING_VALUES.len())];
            let mut v = Vec::with_capacity(8 + s.len());
            v.extend_from_slice(&(s.len() as u64).to_le_bytes());
            v.extend_from_slice(s.as_bytes());
            v
        }
        GgufValueType::Array => {
            let elem = SCALAR_TYPES[rng.index(SCALAR_TYPES.len())];
            let width = elem.scalar_size().unwrap_or(1);
            let count = ARRAY_COUNTS[rng.index(ARRAY_COUNTS.len())];
            let mut v = Vec::with_capacity(12 + count * width);
            v.extend_from_slice(&(elem as u32).to_le_bytes());
            v.extend_from_slice(&(count as u64).to_le_bytes());
            for _ in 0..count {
                v.extend_from_slice(&scalar_bytes(width, rng));
            }
            v
        }
        scalar => {
            let width = scalar.scalar_size().unwrap_or(1);
            scalar_bytes(width, rng)
        }
    }
}

fn scalar_bytes(width: usize, rng: &mut DeterministicRng) -> Vec<u8> {
    let value = SCALAR_VALUES[rng.index(SCALAR_VALUES.len())];
    value.to_le_bytes()[..width].to_vec()
}

/// How many padding bytes put the tensor data back on an aligned boundary, and which
/// alignment that answer used. `meta` is the header plus metadata plus tensor info of
/// the file being built - everything before the padding.
///
/// Returns None when the file cannot be produced honestly: padding to the alignment the
/// file itself declares would cost more than `ceiling`. Emitting it unpadded instead
/// was the wrong answer - ggml re-derives the data offset with GGML_PAD (gguf.cpp:621)
/// and then reads past the end of a file whose blob never moved, so the mutant is
/// rejected at a depth where the seed it came from loads.
pub(crate) fn padding_for(
    meta: &[u8],
    data: &[u8],
    fallback_alignment: u64,
    ceiling: usize,
) -> Option<(usize, u64)> {
    let alignment = parse_gguf(meta)
        .map(|l| l.alignment)
        .unwrap_or(fallback_alignment);
    // No data section, nothing to align: ggml seeks to the padded offset and then reads
    // zero bytes, so the padding is not part of the contract for a tensorless file.
    if data.is_empty() {
        return Some((0, alignment));
    }
    let pad = align_up(meta.len(), alignment as usize) - meta.len();
    if pad > ceiling {
        return None;
    }
    Some((pad, alignment))
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::{build_gguf_without_alignment_key, build_minimal_gguf};
    use super::super::ALIGNMENT_KEY;
    use super::*;

    fn key_of<'a>(bytes: &'a [u8], kv: &super::super::KvEntry) -> &'a [u8] {
        &bytes[kv.key_str_start..kv.key_str_end]
    }

    #[test]
    fn inserting_a_kv_raises_the_header_count_and_keeps_the_file_parsable_up_to_that_key() {
        let seed = build_gguf_without_alignment_key();
        let mut rng = DeterministicRng::new(7);
        let out = apply(&seed, &mut rng).expect("kv_insert applies");
        let before = parse_gguf(&seed).expect("seed parses");
        let after = parse_gguf(&out.bytes).expect("mutant parses");
        assert_eq!(after.kvs.len(), before.kvs.len() + 1);
        assert_eq!(after.kv_count, before.kv_count + 1);
    }

    #[test]
    fn kv_insert_can_produce_a_wrongly_typed_alignment_key() {
        // Why this operator exists: reach the general.alignment type confusion
        // (gguf.cpp:478 -> :183) without a hand-made seed. None of the 18 real gguf
        // seeds carries the key at all, so the fixture here has none either.
        let seed = build_gguf_without_alignment_key();
        let mut found = false;
        for s in 0..512u64 {
            let mut rng = DeterministicRng::new(s);
            if let Ok(out) = apply(&seed, &mut rng) {
                let layout = parse_gguf(&out.bytes).expect("mutant parses");
                if layout.kvs.iter().any(|kv| {
                    key_of(&out.bytes, kv) == ALIGNMENT_KEY.as_bytes()
                        && kv.value_type != GgufValueType::U32
                }) {
                    found = true;
                    break;
                }
            }
        }
        assert!(
            found,
            "kv_insert never produced a mistyped general.alignment in 512 seeds"
        );
    }

    #[test]
    fn kv_insert_never_duplicates_a_key_the_seed_already_has() {
        // ggml rejects a duplicate key outright (gguf.cpp:431) BEFORE it ever looks at
        // the alignment value, so an insert that collides with an existing key buys
        // nothing: the file dies in the kv loop. build_minimal_gguf already carries
        // general.name and general.alignment.
        let seed = build_minimal_gguf();
        let mut applied = 0usize;
        for s in 0..512u64 {
            let mut rng = DeterministicRng::new(s);
            let Ok(out) = apply(&seed, &mut rng) else {
                continue;
            };
            applied += 1;
            let layout = parse_gguf(&out.bytes).expect("mutant parses");
            let mut keys: Vec<&[u8]> = layout.kvs.iter().map(|kv| key_of(&out.bytes, kv)).collect();
            let total = keys.len();
            keys.sort_unstable();
            keys.dedup();
            assert_eq!(
                keys.len(),
                total,
                "seed {s} produced a duplicate key, which ggml rejects at gguf.cpp:431"
            );
        }
        // Without this the test also passes when apply() never succeeds at all.
        assert!(applied > 0, "apply() never produced a mutant to check");
    }

    #[test]
    fn the_tensor_data_stays_aligned_and_intact_after_an_insert() {
        // Inserting into the metadata shifts everything after it. Tensor offsets are
        // relative to the data start, so they can stay put - but the alignment padding
        // in front of the data has to be recomputed or the blob lands unaligned.
        let seed = build_gguf_without_alignment_key();
        let mut applied = 0usize;
        for s in 0..128u64 {
            let mut rng = DeterministicRng::new(s);
            let Ok(out) = apply(&seed, &mut rng) else {
                continue;
            };
            applied += 1;
            let before = parse_gguf(&seed).expect("seed parses");
            let after = parse_gguf(&out.bytes).expect("mutant parses");
            assert_eq!(
                after.tensor_data_start % after.alignment as usize,
                0,
                "seed {s}: data start is not aligned"
            );
            assert!(
                out.bytes.len() >= after.tensor_data_start,
                "seed {s}: the file ends before its own data section"
            );
            let data_before = &seed[before.tensor_data_start..];
            let data_after = &out.bytes[after.tensor_data_start..];
            assert_eq!(
                data_after, data_before,
                "seed {s}: the tensor data blob was not carried over intact"
            );
        }
        assert!(applied > 0, "apply() never produced a mutant to check");
    }

    // The padding ceiling used to give up and emit the file with NO alignment padding
    // at all. ggml re-derives the data offset with GGML_PAD (gguf.cpp:621) and then
    // reads past the end, so such a mutant is rejected at a depth where its own seed
    // loads. A file whose alignment is affordable must still be padded correctly.
    #[test]
    fn a_large_but_affordable_alignment_is_still_padded_correctly() {
        let seed = super::super::test_fixtures::build_gguf_with_large_alignment();
        let mut applied = 0usize;
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let Ok(out) = apply(&seed, &mut rng) else {
                continue;
            };
            applied += 1;
            let after = parse_gguf(&out.bytes).expect("mutant parses");
            assert_eq!(
                after.tensor_data_start % after.alignment as usize,
                0,
                "seed {s}: data start not aligned"
            );
            assert!(
                out.bytes.len() >= after.tensor_data_start,
                "seed {s}: the file ends before the data section it declares"
            );
            let before = parse_gguf(&seed).expect("seed parses");
            assert_eq!(
                &out.bytes[after.tensor_data_start..],
                &seed[before.tensor_data_start..],
                "seed {s}: blob not carried over intact"
            );
        }
        assert!(applied > 0, "apply() never produced a mutant to check");
    }

    // ...and one it cannot afford must be declined, not emitted unpadded.
    #[test]
    fn an_unaffordable_alignment_declines_instead_of_emitting_a_short_file() {
        let seed = super::super::test_fixtures::build_gguf_with_absurd_alignment();
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            match apply(&seed, &mut rng) {
                Err(OperatorError::NoApplicableField) => {}
                Ok(out) => {
                    let after = parse_gguf(&out.bytes).expect("mutant parses");
                    assert!(
                        out.bytes.len() >= after.tensor_data_start,
                        "seed {s}: emitted a file shorter than the data offset it declares"
                    );
                }
            }
        }
    }

    // Every key in the table is already present, so the operator has to fall back to a
    // name of its own instead of dropping the mutation.
    #[test]
    fn a_file_holding_every_table_key_still_gets_an_insert() {
        let seed = super::super::test_fixtures::build_gguf_with_every_insert_key();
        let before = parse_gguf(&seed).expect("seed parses");
        let mut applied = 0usize;
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out = apply(&seed, &mut rng).expect("the synthetic-key fallback applies");
            applied += 1;
            let after = parse_gguf(&out.bytes).expect("mutant parses");
            assert_eq!(after.kvs.len(), before.kvs.len() + 1);
            let inserted = out
                .operator_params
                .iter()
                .find(|(k, _)| *k == "inserted_key")
                .map(|(_, v)| v.clone())
                .expect("inserted_key recorded");
            assert!(
                inserted.starts_with("fuzz.kv."),
                "seed {s}: expected the synthetic fallback, got {inserted}"
            );
        }
        assert!(applied > 0);
    }
}
