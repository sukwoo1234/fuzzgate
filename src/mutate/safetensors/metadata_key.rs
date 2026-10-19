use super::{parse_preserving_label, parse_safetensors, pick_different_ascii_byte};
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "metadata_key";

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_safetensors(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    let metadata = layout
        .metadata
        .as_ref()
        .ok_or(OperatorError::NoApplicableField)?;

    let candidates: Vec<usize> = (0..metadata.kvs.len())
        .filter(|&i| metadata.kvs[i].key.inner_len() > 0)
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let kv_idx = candidates[rng.index(candidates.len())];
    let kv = &metadata.kvs[kv_idx];
    let span_len = kv.key.inner_len();
    let pick = kv.key.inner_start + rng.index(span_len);

    let mut out = bytes.to_vec();
    let original_byte = out[pick];
    let mutated_byte = pick_different_ascii_byte(rng, original_byte);
    out[pick] = mutated_byte;

    let parse_preserving = parse_preserving_label(&out);
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("kv_index", kv_idx.to_string()),
            ("byte_offset", pick.to_string()),
            ("original_byte", format!("0x{:02x}", original_byte)),
            ("mutated_byte", format!("0x{:02x}", mutated_byte)),
        ],
        parse_preserving,
    })
}
