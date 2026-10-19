//! GGUF metadata is mostly arrays - a tokenizer's vocab and merges, per-layer scales -
//! and every in-place operator before this one skipped arrays outright
//! (metadata_value.rs:22). Both array-shaped defects lived out of reach as a result: the
//! array arity assert (V2, gguf.cpp:864) and the pre-read allocation on a declared
//! element count (V4, gguf.cpp:231, `dst.resize(n)`). This operator mutates the arrays
//! themselves, one behaviour per call:
//!   - `count_amplify` enlarges the declared count and leaves the payload put, so the
//!     file declares more elements than it carries. That is the V4 trigger; our own
//!     parser rejects the short file, so the mutant is only meaningful fed to the native
//!     harness - it is honestly labelled parse_preserving="no".
//!   - `force_arity` rewrites a scalar KV as a two-element array of the same type,
//!     re-laying-out the section behind it (the kv_insert padding logic). That reaches
//!     the arity getter (V2) with a file that still parses at our depth.
//!   - `mutate_element` retypes an array's elements to a same-width alternative, or
//!     drives one element to a byte boundary - both layout-preserving.

use super::kv_insert::{padding_for, PADDING_HEADROOM};
use super::metadata_type::same_width_alternatives;
use super::{parse_gguf, read_u32, read_u64, write_u32, write_u64, GgufValueType};
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "array_mutate";

/// Declared element counts far larger than any payload a mutated seed carries. The point
/// is the mismatch, not the exact number: ggml reads the count and pre-allocates before
/// it has validated a single element.
const COUNT_AMPLIFY_VALUES: &[u64] = &[
    0x1_0000,
    0x0100_0000,
    0x1_0000_0000,
    0x0100_0000_0000,
    u64::MAX,
];

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    // Pick a behaviour, then fall through to the others so a file that has arrays but no
    // scalars (or the reverse) still gets mutated instead of declined.
    let start = rng.index(3);
    for k in 0..3 {
        let result = match (start + k) % 3 {
            0 => count_amplify(bytes, rng),
            1 => force_arity(bytes, rng),
            _ => mutate_element(bytes, rng),
        };
        if let Ok(out) = result {
            return Ok(out);
        }
    }
    Err(OperatorError::NoApplicableField)
}

/// Enlarge one array's declared element count without touching its payload, so the file
/// claims more elements than follow. This is the exact shape of the V4 allocation DoS.
fn count_amplify(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    let candidates: Vec<usize> = (0..layout.kvs.len())
        .filter(|&i| layout.kvs[i].value_type == GgufValueType::Array)
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let kv = &layout.kvs[candidates[rng.index(candidates.len())]];
    // an array payload is [elem_type: u32][count: u64][elements...].
    let count_off = kv.value_payload_start + 4;
    let old_count = read_u64(bytes, count_off).map_err(|_| OperatorError::NoApplicableField)?;
    let pick = COUNT_AMPLIFY_VALUES[rng.index(COUNT_AMPLIFY_VALUES.len())];
    let new_count = if pick > old_count {
        pick
    } else {
        old_count.saturating_add(0x1_0000)
    };

    let mut out = bytes.to_vec();
    write_u64(&mut out, count_off, new_count);
    let parse_preserving = if parse_gguf(&out).is_ok() {
        "yes"
    } else {
        "no"
    };
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("behaviour", "count_amplify".to_string()),
            ("declared_count", new_count.to_string()),
            ("actual_count", old_count.to_string()),
        ],
        parse_preserving,
    })
}

/// Rewrite a scalar KV as a two-element array of the same scalar type, then rebuild the
/// alignment padding in front of the tensor data - the section behind the KV moved.
fn force_arity(bytes: &[u8], rng: &mut DeterministicRng) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    let candidates: Vec<usize> = (0..layout.kvs.len())
        .filter(|&i| layout.kvs[i].value_type.scalar_size().is_some())
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let kv_idx = candidates[rng.index(candidates.len())];
    let kv = &layout.kvs[kv_idx];
    let elem_type = kv.value_type;
    let width = elem_type
        .scalar_size()
        .ok_or(OperatorError::NoApplicableField)?;
    let key = &bytes[kv.key_str_start..kv.key_str_end];
    let scalar_payload = &bytes[kv.value_payload_start..kv.value_payload_end];

    let mut entry = Vec::with_capacity(8 + key.len() + 4 + 4 + 8 + 2 * width);
    entry.extend_from_slice(&(key.len() as u64).to_le_bytes());
    entry.extend_from_slice(key);
    entry.extend_from_slice(&(GgufValueType::Array as u32).to_le_bytes());
    entry.extend_from_slice(&(elem_type as u32).to_le_bytes());
    entry.extend_from_slice(&2u64.to_le_bytes());
    entry.extend_from_slice(scalar_payload);
    entry.extend_from_slice(scalar_payload);

    // Everything from the end of the KV section through the tensor info moves with the
    // insert; the tensor data blob is carried over intact and re-padded.
    let tensor_info_end = layout
        .tensors
        .last()
        .map(|t| t.entry_end)
        .unwrap_or_else(|| layout.kvs.last().map(|k| k.entry_end).unwrap_or(24));
    let data_start = layout.tensor_data_start.min(bytes.len());
    let data = &bytes[data_start..];

    let mut meta = Vec::with_capacity(bytes.len() + entry.len());
    meta.extend_from_slice(&bytes[..kv.entry_start]);
    meta.extend_from_slice(&entry);
    meta.extend_from_slice(&bytes[kv.entry_end..tensor_info_end]);

    let (padding, alignment_used) = padding_for(
        &meta,
        data,
        layout.alignment,
        bytes.len() + PADDING_HEADROOM,
    )
    .ok_or(OperatorError::NoApplicableField)?;
    let mut out = meta;
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
            ("behaviour", "force_arity".to_string()),
            ("kv_index", kv_idx.to_string()),
            ("elem_type", (elem_type as u32).to_string()),
            ("forced_ne", "2".to_string()),
            ("alignment_used", alignment_used.to_string()),
            ("padding_bytes", padding.to_string()),
        ],
        parse_preserving,
    })
}

/// Retype an array's scalar elements to a same-width alternative, or drive one element to
/// an all-ones (or all-zero) boundary. Both keep the byte layout, so the file still
/// parses and the parser reaches the code that reads the value.
fn mutate_element(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    let candidates: Vec<usize> = (0..layout.kvs.len())
        .filter(|&i| {
            let kv = &layout.kvs[i];
            if kv.value_type != GgufValueType::Array {
                return false;
            }
            read_u32(bytes, kv.value_payload_start)
                .ok()
                .and_then(GgufValueType::from_u32)
                .and_then(|t| t.scalar_size())
                .is_some()
        })
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let kv = &layout.kvs[candidates[rng.index(candidates.len())]];
    let elem_type_raw =
        read_u32(bytes, kv.value_payload_start).map_err(|_| OperatorError::NoApplicableField)?;
    let elem_type =
        GgufValueType::from_u32(elem_type_raw).ok_or(OperatorError::NoApplicableField)?;
    let width = elem_type
        .scalar_size()
        .ok_or(OperatorError::NoApplicableField)?;
    let count = read_u64(bytes, kv.value_payload_start + 4)
        .map_err(|_| OperatorError::NoApplicableField)? as usize;
    let elems_start = kv.value_payload_start + 12;
    let alternatives = same_width_alternatives(elem_type);

    let mut out = bytes.to_vec();
    let kind = if (rng.index(2) == 0 && !alternatives.is_empty()) || count == 0 {
        if alternatives.is_empty() {
            return Err(OperatorError::NoApplicableField);
        }
        let new_type = alternatives[rng.index(alternatives.len())];
        write_u32(&mut out, kv.value_payload_start, new_type as u32);
        "retype"
    } else {
        let idx = rng.index(count);
        let off = elems_start + idx * width;
        let all_ones = out[off..off + width].iter().all(|&b| b == 0xff);
        let fill = if all_ones { 0x00 } else { 0xff };
        for b in out[off..off + width].iter_mut() {
            *b = fill;
        }
        "boundary"
    };

    let parse_preserving = if parse_gguf(&out).is_ok() {
        "yes"
    } else {
        "no"
    };
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("behaviour", "mutate_element".to_string()),
            ("kind", kind.to_string()),
            ("elem_type", elem_type_raw.to_string()),
        ],
        parse_preserving,
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::{build_gguf_with_scalar_array, build_minimal_gguf};
    use super::super::{parse_gguf, read_u64, GgufValueType};
    use super::*;

    fn key_of<'a>(bytes: &'a [u8], kv: &super::super::KvEntry) -> &'a [u8] {
        &bytes[kv.key_str_start..kv.key_str_end]
    }

    // count_amplify only enlarges the declared element count (a u64) and leaves the
    // payload where it is, so the file declares more elements than it carries. That is
    // the exact V4 trigger: ggml pre-allocates dst.resize(n) (gguf.cpp:231) for the
    // attacker-controlled n before it has read a single element. Our own parser, like
    // ggml's structural walk, must reject the short file - so this is a parse_preserving
    // "no" mutant whose value is only visible to the native harness.
    #[test]
    fn count_amplify_makes_declared_exceed_actual() {
        let bytes = build_gguf_with_scalar_array();
        let before = parse_gguf(&bytes).expect("fixture parses");
        let arr = before
            .kvs
            .iter()
            .find(|kv| kv.value_type == GgufValueType::Array)
            .expect("fixture carries an array kv");
        // an array payload is [elem_type: u32][count: u64][elements...]; the count sits
        // right after the 4-byte element type.
        let count_off = arr.value_payload_start + 4;
        let actual_count = read_u64(&bytes, count_off).expect("array count is readable");

        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out = count_amplify(&bytes, &mut rng)
                .expect("count_amplify applies to a file that carries an array");
            assert_eq!(
                out.bytes.len(),
                bytes.len(),
                "seed {s}: count amplification must not add or move payload"
            );
            let new_count = read_u64(&out.bytes, count_off).expect("count still readable");
            assert!(
                new_count > actual_count,
                "seed {s}: the declared count must exceed the {actual_count} elements actually present"
            );
            assert_eq!(
                &out.bytes[..count_off],
                &bytes[..count_off],
                "seed {s}: nothing before the count field may change"
            );
            assert_eq!(
                &out.bytes[count_off + 8..],
                &bytes[count_off + 8..],
                "seed {s}: nothing after the count field may change"
            );
            assert_eq!(
                out.parse_preserving, "no",
                "seed {s}: a file whose array runs off the end does not parse"
            );
        }
    }

    // Forcing a key ggml reads with a single-value getter (general.alignment) into a
    // two-element array is the arity mismatch it asserts on (gguf.cpp:864). The rewrite
    // grows the KV, so the section after it and the alignment padding have to be rebuilt,
    // and the file must still parse - the crash is at ggml's depth, not ours.
    #[test]
    fn arity_two_reaches_the_scalar_getter() {
        let bytes = build_gguf_with_scalar_array();
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out = force_arity(&bytes, &mut rng)
                .expect("force_arity applies to a file that carries a scalar kv");
            let after = parse_gguf(&out.bytes).expect("the rewritten file still parses");
            let align = after
                .kvs
                .iter()
                .find(|kv| key_of(&out.bytes, kv) == b"general.alignment")
                .expect("the alignment key survives the rewrite");
            assert_eq!(
                align.value_type,
                GgufValueType::Array,
                "seed {s}: the scalar key was rewritten as an array"
            );
            let ne = read_u64(&out.bytes, align.value_payload_start + 4).expect("array count");
            assert_eq!(ne, 2, "seed {s}: the forced arity is 2");
            assert_eq!(
                out.parse_preserving, "yes",
                "seed {s}: a well-formed array parses"
            );
        }
    }

    // Re-laying-out after the KV grows also has to keep a tensor blob aligned and intact:
    // general.alignment is the only scalar in build_minimal_gguf, and turning it into an
    // array shifts the data section behind it.
    #[test]
    fn force_arity_keeps_the_tensor_blob_aligned_and_intact() {
        let bytes = build_minimal_gguf();
        let before = parse_gguf(&bytes).expect("fixture parses");
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out = force_arity(&bytes, &mut rng).expect("force_arity applies");
            let after = parse_gguf(&out.bytes).expect("mutant parses");
            assert_eq!(
                after.tensor_data_start % after.alignment as usize,
                0,
                "seed {s}: data start is not aligned"
            );
            assert_eq!(
                &out.bytes[after.tensor_data_start..],
                &bytes[before.tensor_data_start..],
                "seed {s}: the tensor blob was not carried over intact"
            );
        }
    }

    // The third behaviour retypes an array's elements or drives one to a boundary; either
    // way the byte layout is untouched, so the file stays the same size and still parses.
    #[test]
    fn mutating_an_element_preserves_the_layout() {
        let bytes = build_gguf_with_scalar_array();
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out = mutate_element(&bytes, &mut rng)
                .expect("mutate_element applies to a file that carries an array");
            assert_eq!(
                out.bytes.len(),
                bytes.len(),
                "seed {s}: an element mutation never resizes the file"
            );
            assert_ne!(out.bytes, bytes, "seed {s}: something must actually change");
            assert!(
                parse_gguf(&out.bytes).is_ok(),
                "seed {s}: a same-width element edit still parses"
            );
            assert_eq!(out.parse_preserving, "yes", "seed {s}");
        }
    }

    // The public entry point has to reach every behaviour across seeds, and always
    // produce a different file from one that carries an array.
    #[test]
    fn apply_always_mutates_a_file_with_arrays() {
        let bytes = build_gguf_with_scalar_array();
        let mut applied = 0usize;
        for s in 0..128u64 {
            let mut rng = DeterministicRng::new(s);
            let out = apply(&bytes, &mut rng).expect("apply reaches some behaviour");
            assert_ne!(out.bytes, bytes, "seed {s}: apply must change the file");
            applied += 1;
        }
        assert!(applied > 0);
    }
}
