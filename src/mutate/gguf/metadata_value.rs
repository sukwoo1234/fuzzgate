use super::{parse_gguf, pick_different_ascii_byte, GgufValueType};
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "metadata_value";

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;

    let candidates: Vec<usize> = (0..layout.kvs.len())
        .filter(|&i| {
            let kv = &layout.kvs[i];
            // A string's payload is a u64 length plus its bytes, so an empty string
            // has 8 bytes of payload and nothing to mutate. Counting it as a
            // candidate and then failing on it took the whole operator down with it.
            let has_payload = match kv.value_type {
                GgufValueType::String => kv.value_payload_end > kv.value_payload_start + 8,
                _ => kv.value_payload_end > kv.value_payload_start,
            };
            let suitable = !matches!(kv.value_type, GgufValueType::Array);
            has_payload && suitable
        })
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let kv_idx = candidates[rng.index(candidates.len())];
    let kv = &layout.kvs[kv_idx];

    let mut out = bytes.to_vec();
    let (byte_offset, original_byte, mutated_byte, kind_label) = match kv.value_type {
        GgufValueType::String => {
            let str_start = kv.value_payload_start + 8;
            let str_end = kv.value_payload_end;
            if str_end <= str_start {
                return Err(OperatorError::NoApplicableField);
            }
            let span = str_end - str_start;
            let pick = str_start + rng.index(span);
            let cur = out[pick];
            let new_b = pick_different_ascii_byte(rng, cur);
            out[pick] = new_b;
            (pick, cur, new_b, "string")
        }
        _ => {
            let pl_start = kv.value_payload_start;
            let pl_end = kv.value_payload_end;
            if pl_end <= pl_start {
                return Err(OperatorError::NoApplicableField);
            }
            let span = pl_end - pl_start;
            let pick = pl_start + rng.index(span);
            let cur = out[pick];
            let bit = rng.index(8) as u32;
            let new_b = cur ^ (1u8 << bit);
            out[pick] = new_b;
            (pick, cur, new_b, "scalar")
        }
    };

    let parse_preserving = parse_preserving_label(&out);
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("kv_index", kv_idx.to_string()),
            ("value_kind", kind_label.to_string()),
            ("byte_offset", byte_offset.to_string()),
            ("original_byte", format!("0x{:02x}", original_byte)),
            ("mutated_byte", format!("0x{:02x}", mutated_byte)),
        ],
        parse_preserving,
    })
}

/// Whether the mutated bytes still parse.
///
/// A17/A18: these operators substitute an arbitrary printable byte into a string,
/// which can be a quote or backslash in a safetensors JSON header, or the middle
/// of a multi-byte UTF-8 sequence in GGUF. The output was labelled
/// parse_preserving="yes" regardless, so the manifest asserted something the file
/// no longer satisfied. The mutation itself is worth keeping - a parser's handling
/// of its own delimiters is exactly what wants exercising - so the label is
/// derived instead of claimed.
fn parse_preserving_label(bytes: &[u8]) -> &'static str {
    if parse_gguf(bytes).is_ok() {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::build_gguf_with_empty_string_value;
    use super::*;

    // A GGUF string value is a u64 length followed by that many bytes, so an empty
    // string still has an 8-byte payload and passed the "has a payload" filter.
    // Picking it then failed the whole operator instead of choosing another key -
    // and real models carry empty metadata strings.
    #[test]
    fn an_empty_string_value_does_not_fail_the_operator() {
        let bytes = build_gguf_with_empty_string_value();
        for seed in 0..50u64 {
            let mut rng = DeterministicRng::new(seed);
            let result = apply(&bytes, &mut rng)
                .unwrap_or_else(|e| panic!("seed {seed} found nothing to mutate: {e:?}"));
            assert_ne!(result.bytes, bytes);
            assert_eq!(result.bytes.len(), bytes.len());
        }
    }

    // ... and the filter must not become string-only while fixing that.
    #[test]
    fn scalar_values_are_still_candidates() {
        let bytes = build_gguf_with_empty_string_value();
        let mut rng = DeterministicRng::new(7);
        let result = apply(&bytes, &mut rng).expect("the u32 alignment value is mutable");
        assert_ne!(result.bytes, bytes);
    }
}
