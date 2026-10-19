use super::{digit_count_u64, parse_safetensors, NATURAL_ALIGNMENT_LARGE, NATURAL_ALIGNMENT_SMALL};
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "tensor_data_offsets";

fn parse_number_bytes(slice: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(slice).ok()?;
    s.parse::<u64>().ok()
}

fn detect_alignment(start: u64, end: u64) -> u64 {
    if start % NATURAL_ALIGNMENT_LARGE == 0 && end % NATURAL_ALIGNMENT_LARGE == 0 {
        NATURAL_ALIGNMENT_LARGE
    } else if start % NATURAL_ALIGNMENT_SMALL == 0 && end % NATURAL_ALIGNMENT_SMALL == 0 {
        NATURAL_ALIGNMENT_SMALL
    } else {
        0
    }
}

#[derive(Clone, Copy)]
enum Slot {
    Start,
    End,
}

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_safetensors(bytes).map_err(|_| OperatorError::NoApplicableField)?;

    let mut candidates: Vec<(usize, Slot, u64, u64, u64)> = Vec::new();
    for (t_idx, tensor) in layout.tensors.iter().enumerate() {
        if tensor.data_offsets.elements.len() != 2 {
            continue;
        }
        let start_elem = &tensor.data_offsets.elements[0];
        let end_elem = &tensor.data_offsets.elements[1];
        let start_raw = &bytes[start_elem.start..start_elem.end];
        let end_raw = &bytes[end_elem.start..end_elem.end];
        let (start_val, end_val) =
            match (parse_number_bytes(start_raw), parse_number_bytes(end_raw)) {
                (Some(s), Some(e)) => (s, e),
                _ => continue,
            };
        let alignment = detect_alignment(start_val, end_val);
        if alignment == 0 {
            continue;
        }

        for (slot, current, original_len, paired) in [
            (Slot::Start, start_val, start_elem.len(), end_val),
            (Slot::End, end_val, end_elem.len(), start_val),
        ] {
            for direction in [true, false] {
                let candidate = if direction {
                    current.checked_add(alignment)
                } else if current >= alignment {
                    Some(current - alignment)
                } else {
                    None
                };
                let Some(candidate) = candidate else { continue };
                let new_str = candidate.to_string();
                if new_str.len() != original_len {
                    continue;
                }
                if digit_count_u64(candidate) != digit_count_u64(current) {
                    continue;
                }
                let pair_ok = match slot {
                    Slot::Start => candidate < paired,
                    Slot::End => candidate > paired,
                };
                if !pair_ok {
                    continue;
                }
                candidates.push((t_idx, slot, current, candidate, alignment));
            }
        }
    }
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let pick_idx = rng.index(candidates.len());
    let (t_idx, slot, original, mutated, alignment) = candidates[pick_idx];
    let elements = &layout.tensors[t_idx].data_offsets.elements;
    let span = match slot {
        Slot::Start => &elements[0],
        Slot::End => &elements[1],
    };
    let slot_label = match slot {
        Slot::Start => "start",
        Slot::End => "end",
    };

    let mut out = bytes.to_vec();
    let new_str = mutated.to_string();
    out[span.start..span.end].copy_from_slice(new_str.as_bytes());

    let parse_preserving = super::parse_preserving_label(&out);
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("tensor_index", t_idx.to_string()),
            ("slot", slot_label.to_string()),
            ("alignment", alignment.to_string()),
            ("byte_offset", span.start.to_string()),
            ("original", original.to_string()),
            ("mutated", mutated.to_string()),
        ],
        parse_preserving,
    })
}
