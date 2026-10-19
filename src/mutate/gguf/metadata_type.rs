use super::{parse_gguf, write_u32, GgufValueType};
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "metadata_type";

const VALUE_TYPE_COUNT: u32 = 13;

/// Every scalar type, grouped by the width of the value it describes. A retype inside a
/// group leaves the byte layout untouched, so the parser walks past the KV section and
/// on to the code that actually reads the value - which is where the type is trusted
/// without a check (gguf.cpp:478 -> :183). A retype across groups moves every byte
/// after the value, and the parse dies near the header instead.
const WIDTH_GROUPS: &[&[GgufValueType]] = &[
    &[GgufValueType::U8, GgufValueType::I8, GgufValueType::Bool],
    &[GgufValueType::U16, GgufValueType::I16],
    &[GgufValueType::U32, GgufValueType::I32, GgufValueType::F32],
    &[GgufValueType::U64, GgufValueType::I64, GgufValueType::F64],
];

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    // Mix the two: the same-width retype reaches deeper, but the width-changing one is
    // what exercises the parser's own bounds handling, and a file whose values are all
    // strings or arrays has no same-width move available at all.
    if rng.index(2) == 0 {
        if let Ok(out) = apply_same_width(bytes, rng) {
            return Ok(out);
        }
    }
    apply_any_width(bytes, rng)
}

/// Retype one metadata value to a different type of the SAME width.
pub(crate) fn apply_same_width(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    let candidates: Vec<usize> = (0..layout.kvs.len())
        .filter(|&i| !same_width_alternatives(layout.kvs[i].value_type).is_empty())
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let kv_idx = candidates[rng.index(candidates.len())];
    let kv = &layout.kvs[kv_idx];
    let alternatives = same_width_alternatives(kv.value_type);
    let new_type = alternatives[rng.index(alternatives.len())];
    Ok(rewrite_type(
        bytes,
        kv.value_type_start,
        kv_idx,
        kv.value_type as u32,
        new_type as u32,
    ))
}

/// Retype one metadata value to any other type, width included.
fn apply_any_width(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    if layout.kvs.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let kv_idx = rng.index(layout.kvs.len());
    let kv = &layout.kvs[kv_idx];

    let current = kv.value_type as u32;
    let new_type = loop {
        let candidate = rng.index(VALUE_TYPE_COUNT as usize) as u32;
        if candidate != current {
            break candidate;
        }
    };
    Ok(rewrite_type(
        bytes,
        kv.value_type_start,
        kv_idx,
        current,
        new_type,
    ))
}

pub(crate) fn same_width_alternatives(value_type: GgufValueType) -> Vec<GgufValueType> {
    WIDTH_GROUPS
        .iter()
        .find(|group| group.contains(&value_type))
        .map(|group| group.iter().copied().filter(|t| *t != value_type).collect())
        .unwrap_or_default()
}

fn rewrite_type(
    bytes: &[u8],
    value_type_start: usize,
    kv_idx: usize,
    current: u32,
    new_type: u32,
) -> MutationOutput {
    // Derived, not asserted: the any-width branch picks from all 13 types and lands on
    // a same-width one about one time in four, so a hard-coded "no" mislabelled those
    // rows - including mutants that go on to abort the library.
    let width_of = |t: u32| GgufValueType::from_u32(t).and_then(|t| t.scalar_size());
    let width_preserved = if width_of(current).is_some() && width_of(current) == width_of(new_type)
    {
        "yes"
    } else {
        "no"
    };
    let mut out = bytes.to_vec();
    write_u32(&mut out, value_type_start, new_type);
    // A17/A18: derive the label instead of claiming one. A same-width retype leaves a
    // file that still parses; a width-changing one usually does not, but "usually" is
    // not something the manifest gets to assert.
    let parse_preserving = if parse_gguf(&out).is_ok() {
        "yes"
    } else {
        "no"
    };
    MutationOutput {
        bytes: out,
        operator_params: vec![
            ("kv_index", kv_idx.to_string()),
            ("original_type", current.to_string()),
            ("mutated_type", new_type.to_string()),
            ("width_preserved", width_preserved.to_string()),
        ],
        parse_preserving,
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::build_minimal_gguf;
    use super::super::{parse_gguf, GgufValueType};
    use super::*;

    // A retype that changes the value's WIDTH shifts every byte after it, so the parser
    // gives up near the header and never reaches the code that reads the value. Staying
    // inside a width group keeps the layout intact, which is exactly the shape of V1
    // (general.alignment as UINT32 -> INT32/FLOAT32, gguf.cpp:478 -> :183).
    #[test]
    fn same_width_retype_keeps_the_rest_of_the_file_aligned() {
        let seed = build_minimal_gguf();
        let mut rng = DeterministicRng::new(3);
        let out = apply_same_width(&seed, &mut rng).expect("applies");
        assert_eq!(out.bytes.len(), seed.len());
        assert!(parse_gguf(&out.bytes).is_ok());
    }

    #[test]
    fn same_width_retype_changes_the_type_but_not_its_width() {
        let seed = build_minimal_gguf();
        let before = parse_gguf(&seed).expect("seed parses");
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out = apply_same_width(&seed, &mut rng).expect("applies");
            let after = parse_gguf(&out.bytes).expect("mutant parses");
            let changed: Vec<usize> = (0..before.kvs.len())
                .filter(|&i| before.kvs[i].value_type != after.kvs[i].value_type)
                .collect();
            assert_eq!(
                changed.len(),
                1,
                "seed {s}: exactly one kv should be retyped"
            );
            let i = changed[0];
            assert_eq!(
                before.kvs[i].value_type.scalar_size(),
                after.kvs[i].value_type.scalar_size(),
                "seed {s}: width group must be preserved"
            );
        }
    }

    // A string or array value has no width group to stay inside, so the operator has to
    // say so instead of retyping it and claiming the layout survived.
    #[test]
    fn same_width_retype_declines_a_file_whose_values_are_all_variable_width() {
        let seed = build_gguf_with_only_string_values();
        let mut rng = DeterministicRng::new(5);
        assert!(matches!(
            apply_same_width(&seed, &mut rng),
            Err(OperatorError::NoApplicableField)
        ));
    }

    fn build_gguf_with_only_string_values() -> Vec<u8> {
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
        buf
    }
}
