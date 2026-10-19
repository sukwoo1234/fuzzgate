//! Overwrite a scalar metadata value with a same-width boundary. The layout is left
//! intact - the number is the only thing that moves - so the parser walks the KV section
//! unchanged and reaches the code that actually uses the value, which is where a boundary
//! feeds ggml's integer arithmetic (a block_count or n_dims that overflows a multiply).
//! metadata_value only ever flips one bit; this drives the value to the edges of its
//! type on purpose.

use super::parse_gguf;
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "scalar_boundary";

/// The edges of a `width`-byte value, little-endian: {0, 1, type-max, signed-min /
/// high-bit-set, type-max - 1}. Each is the low `width` bytes of the corresponding u64,
/// so `sign_min` is `1 << (width*8 - 1)` and `max` is every byte 0xff.
fn boundary_patterns(width: usize) -> Vec<(&'static str, Vec<u8>)> {
    let truncate = |v: u64| v.to_le_bytes()[..width].to_vec();
    let sign_min = 1u64 << (width * 8 - 1);
    vec![
        ("zero", truncate(0)),
        ("one", truncate(1)),
        ("max", truncate(u64::MAX)),
        ("sign_min", truncate(sign_min)),
        ("max_minus_one", truncate(u64::MAX - 1)),
    ]
}

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    let candidates: Vec<usize> = (0..layout.kvs.len())
        .filter(|&i| layout.kvs[i].value_type.scalar_size().is_some())
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let kv_idx = candidates[rng.index(candidates.len())];
    let kv = &layout.kvs[kv_idx];
    let width = kv
        .value_type
        .scalar_size()
        .ok_or(OperatorError::NoApplicableField)?;
    let off = kv.value_payload_start;
    let current = &bytes[off..off + width];

    // Only boundaries the value is not already sitting on, so the write always moves it.
    let choices: Vec<(&'static str, Vec<u8>)> = boundary_patterns(width)
        .into_iter()
        .filter(|(_, p)| p.as_slice() != current)
        .collect();
    if choices.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let choice = &choices[rng.index(choices.len())];
    let kind = choice.0;
    let pattern = &choice.1;

    let mut out = bytes.to_vec();
    out[off..off + width].copy_from_slice(pattern);
    let parse_preserving = if parse_gguf(&out).is_ok() {
        "yes"
    } else {
        "no"
    };
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("kv_index", kv_idx.to_string()),
            ("value_type", (kv.value_type as u32).to_string()),
            ("width", width.to_string()),
            ("boundary_kind", kind.to_string()),
        ],
        parse_preserving,
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::build_gguf_with_three_same_width_values;
    use super::super::{parse_gguf, GgufValueType};
    use super::*;

    // The whole point of a boundary sweep is that it does not resize the value: it
    // overwrites a fixed-width scalar with an extreme of the same width, so the parser
    // walks past the KV section unchanged and on to the code that reads the number
    // (ggml's block_count/n_dims arithmetic). A resize would break the layout and the
    // parser would never get there.
    #[test]
    fn boundary_write_preserves_length() {
        let bytes = build_gguf_with_three_same_width_values();
        for s in 0..128u64 {
            let mut rng = DeterministicRng::new(s);
            let out = apply(&bytes, &mut rng)
                .expect("scalar_boundary applies to a file with scalar values");
            assert_eq!(
                out.bytes.len(),
                bytes.len(),
                "seed {s}: a boundary write never resizes the file"
            );
            assert_ne!(out.bytes, bytes, "seed {s}: the value must actually move");
            assert!(
                parse_gguf(&out.bytes).is_ok(),
                "seed {s}: a same-width write leaves the file parseable"
            );
            assert_eq!(out.parse_preserving, "yes", "seed {s}");
        }
    }

    // The type maximum (every byte 0xff) is the boundary most likely to overflow a
    // downstream multiply, so the operator has to be able to reach it, not just wobble
    // the low bits.
    #[test]
    fn hits_type_max() {
        let bytes = build_gguf_with_three_same_width_values();
        let reached_max = (0..512u64).any(|s| {
            let mut rng = DeterministicRng::new(s);
            apply(&bytes, &mut rng)
                .ok()
                .and_then(|out| {
                    out.operator_params
                        .iter()
                        .find(|(k, _)| *k == "boundary_kind")
                        .map(|(_, v)| v == "max")
                })
                .unwrap_or(false)
        });
        assert!(reached_max, "no seed drove a scalar to its type maximum");
    }

    // Every scalar KV must be a candidate over enough seeds, not just the first one.
    #[test]
    fn every_scalar_value_is_reachable() {
        let bytes = build_gguf_with_three_same_width_values();
        let before = parse_gguf(&bytes).expect("fixture parses");
        let scalar_kvs: Vec<usize> = (0..before.kvs.len())
            .filter(|&i| before.kvs[i].value_type.scalar_size().is_some())
            .collect();
        assert_eq!(
            scalar_kvs.len(),
            3,
            "fixture should carry three scalar values"
        );
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..512u64 {
            let mut rng = DeterministicRng::new(s);
            let out = apply(&bytes, &mut rng).expect("applies");
            let idx: usize = out
                .operator_params
                .iter()
                .find(|(k, _)| *k == "kv_index")
                .map(|(_, v)| v.parse().unwrap())
                .expect("kv_index recorded");
            seen.insert(idx);
        }
        for i in scalar_kvs {
            assert!(seen.contains(&i), "scalar kv {i} was never chosen");
        }
    }

    // A file whose values are all variable-width (string, array) has no same-width
    // boundary to write, so the operator declines instead of corrupting the layout.
    #[test]
    fn declines_a_file_with_no_scalar_values() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"GGUF");
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        let key = b"general.name";
        buf.extend_from_slice(&(key.len() as u64).to_le_bytes());
        buf.extend_from_slice(key);
        buf.extend_from_slice(&(GgufValueType::String as u32).to_le_bytes());
        let val = b"test";
        buf.extend_from_slice(&(val.len() as u64).to_le_bytes());
        buf.extend_from_slice(val);
        let mut rng = DeterministicRng::new(1);
        assert!(matches!(
            apply(&buf, &mut rng),
            Err(OperatorError::NoApplicableField)
        ));
    }
}
