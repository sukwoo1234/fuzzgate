use super::{parse_gguf, pick_different_ascii_byte, truncate_param_str};
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "tensor_name";

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    let candidates: Vec<usize> = (0..layout.tensors.len())
        .filter(|&i| layout.tensors[i].name_str_end > layout.tensors[i].name_str_start)
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let t_idx = candidates[rng.index(candidates.len())];
    let t = &layout.tensors[t_idx];

    let original_name = std::str::from_utf8(&bytes[t.name_str_start..t.name_str_end])
        .unwrap_or("not_available")
        .to_string();

    let mut out = bytes.to_vec();
    let span = t.name_str_end - t.name_str_start;
    let pick = t.name_str_start + rng.index(span);
    let cur = out[pick];
    let new_b = pick_different_ascii_byte(rng, cur);
    out[pick] = new_b;

    let parse_preserving = parse_preserving_label(&out);
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("tensor_index", t_idx.to_string()),
            ("original_name", truncate_param_str(&original_name, 64)),
            ("byte_offset", pick.to_string()),
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
mod label_tests {
    use super::super::test_fixtures::build_gguf_with_multibyte_tensor_name;
    use super::*;

    // A17/A18: the operator substitutes an arbitrary printable byte into a string,
    // which can be a JSON delimiter in a safetensors header or the middle of a
    // multi-byte UTF-8 sequence in GGUF. The manifest claimed parse_preserving="yes"
    // either way. The mutation is worth keeping; the label has to be true.
    #[test]
    fn the_parse_preserving_label_matches_what_the_output_does() {
        let bytes = build_gguf_with_multibyte_tensor_name();
        let mut saw_broken = false;
        for seed in 0..400u64 {
            let mut rng = DeterministicRng::new(seed);
            let Ok(result) = apply(&bytes, &mut rng) else {
                continue;
            };
            let parses = parse_gguf(&result.bytes).is_ok();
            assert_eq!(
                result.parse_preserving,
                if parses { "yes" } else { "no" },
                "seed {seed}: label disagrees with the parser"
            );
            saw_broken |= !parses;
        }
        assert!(
            saw_broken,
            "the operator should be able to break the container; the fixture never showed it"
        );
    }
}
