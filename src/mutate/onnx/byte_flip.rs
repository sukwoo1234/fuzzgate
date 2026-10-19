use super::{flip_value_byte, DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "byte_flip";

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    if bytes.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let mut out = bytes.to_vec();
    let len = out.len();
    let offset = flip_value_byte(&mut out, 0, len, rng).ok_or(OperatorError::NoApplicableField)?;
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![("byte_offset", offset.to_string())],
        parse_preserving: "no",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutates_some_byte() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let mut rng = DeterministicRng::new(7);
        let result = apply(&bytes, &mut rng).expect("non-empty");
        assert_eq!(result.parse_preserving, "no");
        assert_ne!(result.bytes, bytes);
        assert_eq!(result.bytes.len(), bytes.len());
    }

    #[test]
    fn errors_on_empty_bytes() {
        let bytes: Vec<u8> = Vec::new();
        let mut rng = DeterministicRng::new(1);
        assert!(matches!(
            apply(&bytes, &mut rng),
            Err(OperatorError::NoApplicableField)
        ));
    }
}
