//! Change the length of a variable-width value - a string's byte count or an array's
//! element count - to a still-valid new length, rebuild the payload to match, and
//! re-lay-out everything behind it. GGUF has no length-prefix chain the way ONNX's
//! protobuf does, so the "re-encode what follows" step here is the alignment padding in
//! front of the tensor data (the same recomputation kv_insert does). Tensor offsets are
//! relative to the data start, so they need no rewriting. A valid resize leaves a file
//! that still parses - asserted, not assumed.

use super::kv_insert::{padding_for, PADDING_HEADROOM};
use super::{parse_gguf, read_u32, read_u64, GgufValueType};
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "value_resize";

/// How many bytes (string) or elements (array) a single resize adds or drops.
const MAX_DELTA: usize = 16;

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    let layout = parse_gguf(bytes).map_err(|_| OperatorError::NoApplicableField)?;
    // Resizable = a string, or an array whose elements are fixed-width scalars (so the
    // payload can be rebuilt by adding or dropping whole elements).
    let candidates: Vec<usize> = (0..layout.kvs.len())
        .filter(|&i| {
            let kv = &layout.kvs[i];
            match kv.value_type {
                GgufValueType::String => true,
                GgufValueType::Array => read_u32(bytes, kv.value_payload_start)
                    .ok()
                    .and_then(GgufValueType::from_u32)
                    .and_then(|t| t.scalar_size())
                    .is_some(),
                _ => false,
            }
        })
        .collect();
    if candidates.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let kv_idx = candidates[rng.index(candidates.len())];
    let kv = &layout.kvs[kv_idx];

    let (new_payload, kind, direction, old_size, new_size): (Vec<u8>, &str, &str, usize, usize) =
        match kv.value_type {
            GgufValueType::String => {
                let str_start = kv.value_payload_start + 8;
                let old_str = &bytes[str_start..kv.value_payload_end];
                let old_len = old_str.len();
                let (new_str, direction) = if old_len == 0 || rng.index(2) == 0 {
                    let add = 1 + rng.index(MAX_DELTA);
                    let mut v = old_str.to_vec();
                    v.extend(std::iter::repeat_n(b'x', add));
                    (v, "grow")
                } else {
                    let sub = (1 + rng.index(MAX_DELTA)).min(old_len);
                    (old_str[..old_len - sub].to_vec(), "shrink")
                };
                let new_len = new_str.len();
                let mut payload = Vec::with_capacity(8 + new_len);
                payload.extend_from_slice(&(new_len as u64).to_le_bytes());
                payload.extend_from_slice(&new_str);
                (payload, "string", direction, old_len, new_len)
            }
            GgufValueType::Array => {
                let elem_type_raw = read_u32(bytes, kv.value_payload_start)
                    .map_err(|_| OperatorError::NoApplicableField)?;
                let width = GgufValueType::from_u32(elem_type_raw)
                    .and_then(|t| t.scalar_size())
                    .ok_or(OperatorError::NoApplicableField)?;
                let old_count = read_u64(bytes, kv.value_payload_start + 4)
                    .map_err(|_| OperatorError::NoApplicableField)?
                    as usize;
                let elems_start = kv.value_payload_start + 12;
                let old_elems = &bytes[elems_start..kv.value_payload_end];
                let (new_elems, new_count, direction) = if old_count == 0 || rng.index(2) == 0 {
                    let add = 1 + rng.index(MAX_DELTA);
                    let mut v = old_elems.to_vec();
                    v.extend(std::iter::repeat_n(0u8, add * width));
                    (v, old_count + add, "grow")
                } else {
                    let sub = (1 + rng.index(MAX_DELTA)).min(old_count);
                    let keep = old_count - sub;
                    (old_elems[..keep * width].to_vec(), keep, "shrink")
                };
                let mut payload = Vec::with_capacity(12 + new_elems.len());
                payload.extend_from_slice(&elem_type_raw.to_le_bytes());
                payload.extend_from_slice(&(new_count as u64).to_le_bytes());
                payload.extend_from_slice(&new_elems);
                (payload, "array", direction, old_count, new_count)
            }
            _ => return Err(OperatorError::NoApplicableField),
        };

    // The new entry is the key and value-type header (unchanged) followed by the resized
    // payload; splice it in and rebuild the padding in front of the unmoved data blob.
    let mut entry =
        Vec::with_capacity((kv.value_payload_start - kv.entry_start) + new_payload.len());
    entry.extend_from_slice(&bytes[kv.entry_start..kv.value_payload_start]);
    entry.extend_from_slice(&new_payload);

    let tensor_info_end = layout
        .tensors
        .last()
        .map(|t| t.entry_end)
        .unwrap_or_else(|| layout.kvs.last().map(|k| k.entry_end).unwrap_or(24));
    let data_start = layout.tensor_data_start.min(bytes.len());
    let data = &bytes[data_start..];

    let mut meta = Vec::with_capacity(bytes.len() + new_payload.len());
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
            ("kv_index", kv_idx.to_string()),
            ("kind", kind.to_string()),
            ("direction", direction.to_string()),
            ("old_size", old_size.to_string()),
            ("new_size", new_size.to_string()),
            ("alignment_used", alignment_used.to_string()),
            ("padding_bytes", padding.to_string()),
        ],
        parse_preserving,
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::{build_gguf_with_scalar_array, build_minimal_gguf};
    use super::super::{parse_gguf, read_u64, GgufValueType};
    use super::*;

    fn param<'a>(out: &'a MutationOutput, k: &str) -> Option<&'a str> {
        out.operator_params
            .iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| v.as_str())
    }

    // A valid resize lengthens the value and rebuilds everything behind it, so the file
    // still parses cleanly - the point of this operator, unlike a blind length edit, is
    // that it stays well-formed all the way down. String bytes stay ASCII so the UTF-8
    // check ggml and our parser both run still passes.
    #[test]
    fn grow_string_keeps_file_parseable() {
        let bytes = build_minimal_gguf();
        let before = parse_gguf(&bytes).expect("fixture parses");
        let name = before
            .kvs
            .iter()
            .find(|kv| kv.value_type == GgufValueType::String)
            .expect("fixture carries a string value");
        let old_len = read_u64(&bytes, name.value_payload_start).expect("string length");

        let mut grew = false;
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out =
                apply(&bytes, &mut rng).expect("value_resize applies to a file with a string");
            let after = parse_gguf(&out.bytes).expect("the resized file still parses");
            assert_eq!(
                out.parse_preserving, "yes",
                "seed {s}: a valid resize stays parseable"
            );
            let name_after = after
                .kvs
                .iter()
                .find(|kv| kv.value_type == GgufValueType::String)
                .expect("the string survives the resize");
            let new_len = read_u64(&out.bytes, name_after.value_payload_start).expect("length");
            if new_len > old_len {
                grew = true;
            }
        }
        assert!(grew, "no seed ever grew the string");
    }

    // Resizing the metadata shifts everything after it, so the alignment padding in front
    // of the tensor blob has to be recomputed - or the data lands off its boundary - and
    // the blob itself has to be carried over unchanged.
    #[test]
    fn data_stays_aligned() {
        let bytes = build_minimal_gguf();
        let before = parse_gguf(&bytes).expect("fixture parses");
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out = apply(&bytes, &mut rng).expect("applies");
            let after = parse_gguf(&out.bytes).expect("mutant parses");
            assert_eq!(
                after.tensor_data_start % after.alignment as usize,
                0,
                "seed {s}: the data section is not aligned after the resize"
            );
            assert_eq!(
                &out.bytes[after.tensor_data_start..],
                &bytes[before.tensor_data_start..],
                "seed {s}: the tensor blob was not carried over intact"
            );
        }
    }

    // Shrinking is a valid resize too, down to an empty value, and must stay parseable.
    #[test]
    fn shrink_is_valid_too() {
        let bytes = build_minimal_gguf();
        let mut shrank = false;
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out = apply(&bytes, &mut rng).expect("applies");
            assert!(
                parse_gguf(&out.bytes).is_ok(),
                "seed {s}: shrunk file still parses"
            );
            if param(&out, "direction") == Some("shrink") {
                shrank = true;
            }
        }
        assert!(shrank, "no seed ever shrank the value");
    }

    // The array count is the other length this operator can change, and the elements have
    // to be rebuilt to match so the file still parses.
    #[test]
    fn array_resize_keeps_file_parseable() {
        let bytes = build_gguf_with_scalar_array();
        let before = parse_gguf(&bytes).expect("fixture parses");
        let arr = before
            .kvs
            .iter()
            .find(|kv| kv.value_type == GgufValueType::Array)
            .expect("fixture carries an array");
        let old_count = read_u64(&bytes, arr.value_payload_start + 4).expect("array count");

        let mut changed = false;
        for s in 0..64u64 {
            let mut rng = DeterministicRng::new(s);
            let out = apply(&bytes, &mut rng).expect("applies");
            let after = parse_gguf(&out.bytes).expect("resized array still parses");
            assert_eq!(out.parse_preserving, "yes", "seed {s}");
            let arr_after = after
                .kvs
                .iter()
                .find(|kv| kv.value_type == GgufValueType::Array)
                .expect("the array survives");
            let new_count = read_u64(&out.bytes, arr_after.value_payload_start + 4).expect("count");
            if new_count != old_count {
                changed = true;
            }
        }
        assert!(changed, "no seed ever changed the array count");
    }

    // A file whose values are all fixed-width scalars has nothing to resize.
    #[test]
    fn declines_a_file_with_no_resizable_values() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"GGUF");
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        let key = b"general.alignment";
        buf.extend_from_slice(&(key.len() as u64).to_le_bytes());
        buf.extend_from_slice(key);
        buf.extend_from_slice(&(GgufValueType::U32 as u32).to_le_bytes());
        buf.extend_from_slice(&32u32.to_le_bytes());
        for s in 0..8u64 {
            let mut rng = DeterministicRng::new(s);
            assert!(matches!(
                apply(&buf, &mut rng),
                Err(OperatorError::NoApplicableField)
            ));
        }
    }
}
