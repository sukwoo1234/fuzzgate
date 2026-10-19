pub(crate) mod common;
mod gguf;
mod onnx;
mod safetensors;

use std::path::Path;

use crate::target::{target_spec, TargetKind};

pub(crate) fn run_mutate_pipeline(
    target: &TargetKind,
    input: Option<&Path>,
    out: Option<&Path>,
    input_dir: Option<&Path>,
    out_dir: Option<&Path>,
    count: usize,
    seed: u64,
    operators: &[String],
) -> Result<(), String> {
    if !target_spec(target).mutation_supported {
        return Err(format!(
            "target '{}' is registered but structural mutation is not implemented",
            target_spec(target).target_id
        ));
    }
    match target {
        TargetKind::Onnx => {
            let resolved = onnx::validate_operators(operators)?;
            onnx::run(
                target, input, out, input_dir, out_dir, count, seed, &resolved,
            )
        }
        TargetKind::Gguf => {
            let resolved = gguf::validate_operators(operators)?;
            gguf::run(
                target, input, out, input_dir, out_dir, count, seed, &resolved,
            )
        }
        TargetKind::Safetensors => {
            let resolved = safetensors::validate_operators(operators)?;
            safetensors::run(
                target, input, out, input_dir, out_dir, count, seed, &resolved,
            )
        }
        TargetKind::Tflite => Err(
            "target 'tflite' is registered but structural mutation is not implemented".to_string(),
        ),
    }
}
