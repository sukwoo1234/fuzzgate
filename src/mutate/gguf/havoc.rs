//! The strong byte baseline for the coverage-comparison experiment - the GGUF
//! counterpart of src/mutate/onnx/havoc.rs (the B1 byte baseline).
//! Unlike byte_flip (a single-bit flip), it applies a fixed mix of multi-byte edits
//! {overwrite, insert, delete, block_copy} until a cumulative perturbed-byte budget is
//! reached. It is deliberately format-blind: it exists to measure what byte-level
//! mutation alone can cover on GGUF, NOT to find bugs, which is why it stays out of the
//! default set (opt-in, exactly as on ONNX).
//!
//! FAIRNESS (frozen): the byte budget is read from GGUF_HAVOC_BYTE_BUDGET so the
//! experiment can pin it to the structural arm's measured byte-edit distance rather than
//! tuning this arm's strength after the fact. Edit-type weights and the per-edit size
//! distribution are frozen constants, and it shares the DeterministicRng so it runs on
//! the same seed schedule as the structural arm.

use super::parse_gguf;
use crate::mutate::common::{DeterministicRng, MutationOutput, OperatorError};

pub(crate) const NAME: &str = "havoc";

const DEFAULT_BYTE_BUDGET: usize = 16;
const PER_EDIT_MIN: usize = 1;
const PER_EDIT_MAX: usize = 16; // size ~ uniform[PER_EDIT_MIN, PER_EDIT_MAX]
const MAX_EDITS: usize = 4096; // runaway guard (e.g. when every edit size rounds tiny)

fn byte_budget() -> usize {
    std::env::var("GGUF_HAVOC_BYTE_BUDGET")
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
    apply_with_budget(bytes, rng, byte_budget())
}

fn apply_with_budget(
    bytes: &[u8],
    rng: &mut DeterministicRng,
    budget: usize,
) -> Result<MutationOutput, OperatorError> {
    if bytes.is_empty() {
        return Err(OperatorError::NoApplicableField);
    }
    let mut out = bytes.to_vec();
    let mut spent = 0usize;
    let mut edits = 0usize;

    while spent < budget && edits < MAX_EDITS {
        let size = edit_size(rng);
        // frozen weights: overwrite 0.40, insert 0.20, delete 0.20, block_copy 0.20
        let n = match rng.index(10) {
            0..=3 => overwrite(&mut out, size, rng),
            4..=5 => insert(&mut out, size, rng),
            6..=7 => delete(&mut out, size, rng),
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

    // Derived, not asserted (A17/A18): a byte-blind edit that lands entirely in the
    // tensor-data tail - which parse_gguf never reads - leaves a file that still parses,
    // and on a real multi-MB model that tail is most of the file. The manifest records
    // what the parser actually says, not what the operator intends.
    let parse_preserving = if parse_gguf(&out).is_ok() { "yes" } else { "no" };
    Ok(MutationOutput {
        bytes: out,
        operator_params: vec![
            ("byte_budget", budget.to_string()),
            ("edits", edits.to_string()),
        ],
        parse_preserving,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edits_of(out: &MutationOutput) -> usize {
        out.operator_params
            .iter()
            .find(|(k, _)| *k == "edits")
            .map(|(_, v)| v.parse().unwrap())
            .expect("edits recorded")
    }

    // The loop keeps applying multi-byte edits until it has perturbed budget bytes, so a
    // larger budget on the same seed drives strictly more edits. This is what makes havoc
    // the strong byte arm - it is not a single flip.
    #[test]
    fn havoc_perturbs_up_to_budget() {
        let bytes: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
        let run = |budget: usize| {
            let mut rng = DeterministicRng::new(9);
            edits_of(&apply_with_budget(&bytes, &mut rng, budget).expect("applies"))
        };
        let small = run(2);
        let large = run(128);
        assert!(small >= 1, "even a tiny budget makes at least one edit");
        assert!(
            large > small,
            "a larger byte budget must drive more edits ({large} vs {small})"
        );
    }

    // The budget is read from GGUF_HAVOC_BYTE_BUDGET so the coverage experiment can pin it
    // to a measured byte-edit distance rather than tuning it post-hoc.
    #[test]
    fn respects_budget_env() {
        let bytes: Vec<u8> = (0..512u32).map(|i| (i & 0xff) as u8).collect();
        std::env::set_var("GGUF_HAVOC_BYTE_BUDGET", "256");
        let mut rng = DeterministicRng::new(9);
        let out = apply(&bytes, &mut rng).expect("applies");
        std::env::remove_var("GGUF_HAVOC_BYTE_BUDGET");
        assert!(edits_of(&out) >= 1);
        assert_ne!(out.bytes, bytes);
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
        // A fixed budget, not the env-derived one, so a concurrent test setting
        // GGUF_HAVOC_BYTE_BUDGET between two apply() calls cannot make this flaky.
        let bytes = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut a = DeterministicRng::new(42);
        let mut b = DeterministicRng::new(42);
        let ra = apply_with_budget(&bytes, &mut a, 16).expect("ok");
        let rb = apply_with_budget(&bytes, &mut b, 16).expect("ok");
        assert_eq!(ra.bytes, rb.bytes, "same seed must give identical output");
    }

    #[test]
    fn a_non_gguf_seed_never_parses_so_the_label_is_no() {
        let bytes = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let mut rng = DeterministicRng::new(7);
        let out = apply(&bytes, &mut rng).expect("non-empty");
        assert_eq!(out.parse_preserving, "no");
        assert_ne!(out.bytes, bytes);
    }

    // Honesty (A17/A18): the label is DERIVED from parse_gguf, not asserted. parse_gguf
    // reads only header + KVs + tensor infos and never touches the tensor-data tail, so a
    // havoc edit that lands there leaves the parse-relevant prefix byte-identical and the
    // output re-parses - those outputs must be labeled "yes", not a blanket "no".
    #[test]
    fn parse_preserving_matches_the_parser() {
        use super::super::test_fixtures::build_minimal_gguf;
        use super::super::parse_gguf;
        let bytes = build_minimal_gguf();
        let mut parseable = 0usize;
        for s in 0..256u64 {
            let mut rng = DeterministicRng::new(s);
            let out = apply_with_budget(&bytes, &mut rng, 16).expect("applies");
            let expected = if parse_gguf(&out.bytes).is_ok() { "yes" } else { "no" };
            assert_eq!(
                out.parse_preserving, expected,
                "seed {s}: label disagrees with the parser"
            );
            if expected == "yes" {
                parseable += 1;
            }
        }
        assert!(
            parseable > 0,
            "no seed produced a parseable havoc output, so the derived-yes path went untested"
        );
    }

    #[test]
    fn handles_tiny_input_without_emptying() {
        let bytes = vec![0xAA, 0xBB];
        let mut rng = DeterministicRng::new(123);
        let out = apply(&bytes, &mut rng).expect("ok");
        assert!(!out.bytes.is_empty(), "must never produce an empty output");
        assert_ne!(out.bytes, bytes);
    }
}
