use super::{parse_preserving_label, parse_safetensors, pick_different_ascii_byte};
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "tensor_name";

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_safetensors(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    let candidates: Vec<usize> = (0..layout.tensors.len())
        .filter(|&i| layout.tensors[i].name.inner_len() > 0)
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let t_idx = candidates[rng.index(candidates.len())];
    let span = &layout.tensors[t_idx].name;
    let pick = span.inner_start + rng.index(span.inner_len());

    let mut out = bytes.to_vec();
    let original_byte = out[pick];
    let mutated_byte = pick_different_ascii_byte(rng, original_byte);
    out[pick] = mutated_byte;

    let parse_preserving = parse_preserving_label(&out);
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("tensor_index", t_idx.to_string()),
            ("byte_offset", pick.to_string()),
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
#[cfg(test)]
mod label_tests {
    use super::super::test_fixtures::build_minimal_safetensors;
    use super::*;

    // A17/A18: the operator substitutes an arbitrary printable byte into a string,
    // which can be a JSON delimiter in a safetensors header or the middle of a
    // multi-byte UTF-8 sequence in GGUF. The manifest claimed parse_preserving="yes"
    // either way. The mutation is worth keeping; the label has to be true.
    #[test]
    fn the_parse_preserving_label_matches_what_the_output_does() {
        let bytes = build_minimal_safetensors();
        let mut saw_broken = false;
        for seed in 0..400u64 {
            let mut rng = DeterministicRng::new(seed);
            let Ok(result) = apply(&bytes, &mut rng) else {
                continue;
            };
            let parses = parse_safetensors(&result.bytes).is_ok();
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
