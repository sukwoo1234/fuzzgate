use super::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "havoc";

// Multi-byte havoc operator = the STRONG byte baseline (B1) for coverage comparisons.
// Unlike byte_flip (B0, a single-bit flip), havoc applies a fixed mix of multi-byte edits
// {overwrite, insert, delete, block_copy} until a cumulative perturbed-byte budget is
// reached.
//
// FAIRNESS (frozen): the byte budget is read from ONNX_HAVOC_BYTE_BUDGET so the
// experiment can pin it to S's measured median byte-edit distance (byte-budget parity)
// rather than tuning B1's strength post-hoc. Edit-type weights and the per-edit size
// distribution are frozen constants. RNG is the shared DeterministicRng so B1 uses the
// same seed schedule as the structural arm.
const DEFAULT_BYTE_BUDGET: usize = 16;
const PER_EDIT_MIN: usize = 1;
const PER_EDIT_MAX: usize = 16; // size ~ uniform[PER_EDIT_MIN, PER_EDIT_MAX]
const MAX_EDITS: usize = 4096; // runaway guard (e.g. when every edit size rounds tiny)

fn byte_budget() -> usize {
    std::env::var("ONNX_HAVOC_BYTE_BUDGET")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(DEFAULT_BYTE_BUDGET)
}

fn rand_byte(rng: &mut DeterministicRng) -> u8 {
    (rng.next_u64() & 0xff) as u8
}

// uniform[PER_EDIT_MIN, PER_EDIT_MAX]
fn edit_size(rng: &mut DeterministicRng) -> usize {
    PER_EDIT_MIN + rng.index(PER_EDIT_MAX - PER_EDIT_MIN + 1)
}

fn overwrite(out: &mut [u8], size: usize, rng: &mut DeterministicRng) -> usize {
    let len = out.len();
    if len == 0 {
        return 0;
    }
    let start = rng.index(len);
    let n = size.min(len - start);
    for b in out.iter_mut().skip(start).take(n) {
        *b = rand_byte(rng);
    }
    n
}

fn insert(out: &mut Vec<u8>, size: usize, rng: &mut DeterministicRng) -> usize {
    let pos = rng.index(out.len() + 1); // may insert at end
    let mut chunk = Vec::with_capacity(size);
    for _ in 0..size {
        chunk.push(rand_byte(rng));
    }
    out.splice(pos..pos, chunk);
    size
}

fn delete(out: &mut Vec<u8>, size: usize, rng: &mut DeterministicRng) -> usize {
    let len = out.len();
    if len <= 1 {
        return 0; // keep at least 1 byte (avoid degenerate empty output)
    }
    let start = rng.index(len);
    let n = size.min(len - start).min(len - 1); // never drop the last remaining byte
    if n == 0 {
        return 0;
    }
    out.drain(start..start + n);
    n
}

fn block_copy(out: &mut [u8], size: usize, rng: &mut DeterministicRng) -> usize {
    let len = out.len();
    if len == 0 {
        return 0;
    }
    let src = rng.index(len);
    let dst = rng.index(len);
    let n = size.min(len - src).min(len - dst);
    if n == 0 {
        return 0;
    }
    let chunk: Vec<u8> = out[src..src + n].to_vec(); // snapshot for overlap-safe copy
    out[dst..dst + n].copy_from_slice(&chunk);
    n
}

pub(crate) fn apply(
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    if bytes.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let budget = byte_budget();
    let mut out = bytes.to_vec();
    let mut spent = 0usize;
    let mut edits = 0usize;

    while spent < budget && edits < MAX_EDITS {
        let size = edit_size(rng);
        // frozen weights: overwrite 0.40, insert 0.20, delete 0.20, block_copy 0.20
        let n = match rng.index(10) {
            0 | 1 | 2 | 3 => overwrite(&mut out, size, rng),
            4 | 5 => insert(&mut out, size, rng),
            6 | 7 => delete(&mut out, size, rng),
            _ => block_copy(&mut out, size, rng),
        };
        spent += n.max(1); // always make progress so the loop terminates
        edits += 1;
    }

    // Guarantee the output differs from the input (e.g. all edits were no-ops on a
    // 1-byte seed). Flip one byte deterministically.
    if out == bytes {
        let idx = rng.index(out.len());
        out[idx] ^= 0x01;
    }

    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("byte_budget", budget.to_string()),
            ("edits", edits.to_string()),
        ],
        parse_preserving: "no",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutates_and_marks_not_parse_preserving() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let mut rng = DeterministicRng::new(7);
        let r = apply(&bytes, &mut rng).expect("non-empty");
        assert_eq!(r.parse_preserving, "no");
        assert_ne!(r.bytes, bytes, "havoc must change the bytes");
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

    #[test]
    fn deterministic_for_same_seed() {
        let bytes = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut a = DeterministicRng::new(42);
        let mut b = DeterministicRng::new(42);
        let ra = apply(&bytes, &mut a).expect("ok");
        let rb = apply(&bytes, &mut b).expect("ok");
        assert_eq!(ra.bytes, rb.bytes, "same seed must give identical output");
    }

    #[test]
    fn handles_tiny_input_without_emptying() {
        let bytes = vec![0xAA, 0xBB];
        let mut rng = DeterministicRng::new(123);
        let r = apply(&bytes, &mut rng).expect("ok");
        assert!(!r.bytes.is_empty(), "must never produce an empty output");
        assert_ne!(r.bytes, bytes);
    }

    #[test]
    fn respects_byte_budget_env() {
        // A large explicit budget should drive more edits than the default on a big seed.
        let bytes: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
        std::env::set_var("ONNX_HAVOC_BYTE_BUDGET", "256");
        let mut rng = DeterministicRng::new(9);
        let r = apply(&bytes, &mut rng).expect("ok");
        std::env::remove_var("ONNX_HAVOC_BYTE_BUDGET");
        let edits: usize = r
            .operator_params
            .iter()
            .find(|(k, _)| *k == "edits")
            .map(|(_, v)| v.parse().unwrap())
            .unwrap();
        assert!(edits >= 1);
        assert_ne!(r.bytes, bytes);
    }
}
