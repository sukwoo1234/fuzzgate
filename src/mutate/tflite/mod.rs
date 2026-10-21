use std::{
    fs,
    io::ErrorKind,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    common::sha256_file,
    mutate::common::{
        operator_set, print_batch_mutation_report, print_mutation_report, select_operator,
        single_manifest_path, unproductive_inputs, write_mutation_manifest, write_output,
        BatchMutationReport, DeterministicRng, MutationManifestEntry, MutationOutput,
        MutationReport,
    },
    target::TargetKind,
};

pub(crate) const DEFAULT_OPERATORS: &[&str] = &[
    "tensor_shape",
    "tensor_shape_reject",
    "dtype_quantization",
    "dtype_quantization_reject",
    "buffer_payload",
    "buffer_payload_reject",
    "operator_options",
    "operator_options_reject",
    "graph_references",
    "graph_references_reject",
    "names_metadata",
    "names_metadata_reject",
];

pub(crate) const KNOWN_OPERATORS: &[&str] = DEFAULT_OPERATORS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperatorContract {
    mode: &'static str,
    field: &'static str,
    expected_loader: &'static str,
    parse_preserving: &'static str,
    mutation_level: u32,
}

#[derive(Debug, Eq, PartialEq)]
enum DispatchError {
    NoApplicableField,
    MutationFailed(String),
}

fn contract(operator: &str) -> Option<OperatorContract> {
    let value = match operator {
        "tensor_shape" => OperatorContract {
            mode: "structural",
            field: "tensor.shape",
            expected_loader: "accept",
            parse_preserving: "yes",
            mutation_level: 2,
        },
        "tensor_shape_reject" => OperatorContract {
            mode: "reject",
            field: "tensor.shape_buffer",
            expected_loader: "reject",
            parse_preserving: "yes",
            mutation_level: 2,
        },
        "dtype_quantization" => OperatorContract {
            mode: "structural",
            field: "tensor.dtype_quantization",
            expected_loader: "accept",
            parse_preserving: "yes",
            mutation_level: 2,
        },
        "dtype_quantization_reject" => OperatorContract {
            mode: "reject",
            field: "tensor.dtype_quantization",
            expected_loader: "reject",
            parse_preserving: "yes",
            mutation_level: 2,
        },
        "buffer_payload" => OperatorContract {
            mode: "structural",
            field: "buffer.data",
            expected_loader: "accept",
            parse_preserving: "yes",
            mutation_level: 3,
        },
        "buffer_payload_reject" => OperatorContract {
            mode: "reject",
            field: "buffer.data",
            expected_loader: "reject",
            parse_preserving: "no",
            mutation_level: 3,
        },
        "operator_options" => OperatorContract {
            mode: "structural",
            field: "operator.builtin_options",
            expected_loader: "accept",
            parse_preserving: "yes",
            mutation_level: 2,
        },
        "operator_options_reject" => OperatorContract {
            mode: "reject",
            field: "operator.opcode_options",
            expected_loader: "reject",
            parse_preserving: "yes",
            mutation_level: 2,
        },
        "graph_references" => OperatorContract {
            mode: "structural",
            field: "graph.tensor_indices",
            expected_loader: "accept",
            parse_preserving: "yes",
            mutation_level: 3,
        },
        "graph_references_reject" => OperatorContract {
            mode: "reject",
            field: "graph.tensor_indices",
            expected_loader: "reject",
            parse_preserving: "yes",
            mutation_level: 3,
        },
        "names_metadata" => OperatorContract {
            mode: "structural",
            field: "model.names_metadata",
            expected_loader: "accept",
            parse_preserving: "yes",
            mutation_level: 2,
        },
        "names_metadata_reject" => OperatorContract {
            mode: "reject",
            field: "model.names_metadata",
            expected_loader: "reject",
            parse_preserving: "no",
            mutation_level: 2,
        },
        _ => return None,
    };
    Some(value)
}

pub(crate) fn validate_operators(requested: &[String]) -> Result<Vec<&'static str>, String> {
    let mut resolved = Vec::with_capacity(requested.len());
    for name in requested {
        let matched = KNOWN_OPERATORS
            .iter()
            .copied()
            .find(|known| *known == name.as_str())
            .ok_or_else(|| {
                format!(
                    "unknown operator '{}'; known operators: {}",
                    name,
                    KNOWN_OPERATORS.join(", ")
                )
            })?;
        resolved.push(matched);
    }
    Ok(resolved)
}

fn mutator_binary() -> PathBuf {
    std::env::var_os("TOOL_TFLITE_MUTATOR_BIN")
        .or_else(|| std::env::var_os("TFLITE_MUTATOR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("harnesses/tflite/tflite_structural_mutator"))
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TemporaryOutput {
    path: PathBuf,
    dir: PathBuf,
}

impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.dir);
    }
}

fn temporary_output(out: &Path, seed: u64) -> Result<TemporaryOutput, DispatchError> {
    let name = out
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("mutation.tflite");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for _ in 0..128 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tool-tflite-native.{}.{}.{}.{}",
            std::process::id(),
            seed,
            timestamp,
            counter
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&dir) {
            Ok(()) => {
                return Ok(TemporaryOutput {
                    path: dir.join(name),
                    dir,
                });
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(DispatchError::MutationFailed(format!(
                    "failed to create private native mutation directory '{}': {error}",
                    dir.display()
                )));
            }
        }
    }
    Err(DispatchError::MutationFailed(
        "failed to allocate a private native mutation directory".to_string(),
    ))
}

fn parse_evidence(
    stdout: &str,
    operator: &'static str,
    expected: OperatorContract,
) -> Result<Vec<(&'static str, String)>, DispatchError> {
    let line = stdout
        .lines()
        .find(|line| line.starts_with("TFLITE_MUTATION_OK "))
        .ok_or_else(|| {
            DispatchError::MutationFailed("native mutator emitted no result marker".into())
        })?;
    let mut reported_operator = None;
    let mut mode = None;
    let mut field = None;
    let mut before = None;
    let mut after = None;
    let mut expected_loader = None;
    for token in line.split_whitespace().skip(1) {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "operator" => reported_operator = Some(value),
            "mode" => mode = Some(value),
            "field" => field = Some(value),
            "before" => before = Some(value),
            "after" => after = Some(value),
            "expected_loader" => expected_loader = Some(value),
            _ => {}
        }
    }
    if reported_operator != Some(operator)
        || mode != Some(expected.mode)
        || field != Some(expected.field)
        || expected_loader != Some(expected.expected_loader)
        || before.is_none()
        || after.is_none()
        || before == after
    {
        return Err(DispatchError::MutationFailed(format!(
            "native evidence violates the '{}' operator contract",
            operator
        )));
    }
    Ok(vec![
        ("mode", expected.mode.to_string()),
        ("field", expected.field.to_string()),
        ("before", before.unwrap_or_default().to_string()),
        ("after", after.unwrap_or_default().to_string()),
        ("expected_loader", expected.expected_loader.to_string()),
        ("schema", "tensorflow-v2.20.0".to_string()),
    ])
}

fn dispatch(
    operator: &'static str,
    input: &Path,
    out_hint: &Path,
    input_bytes: &[u8],
    seed: u64,
) -> Result<MutationOutput, DispatchError> {
    let expected = contract(operator).ok_or(DispatchError::NoApplicableField)?;
    let binary = mutator_binary();
    if !binary.is_file() {
        return Err(DispatchError::MutationFailed(format!(
            "native TFLite mutator is unavailable: {}",
            binary.display()
        )));
    }
    let temp = temporary_output(out_hint, seed)?;
    let output = Command::new(&binary)
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(&temp.path)
        .arg("--operator")
        .arg(operator)
        .arg("--seed")
        .arg(seed.to_string())
        .output()
        .map_err(|error| {
            DispatchError::MutationFailed(format!(
                "failed to execute native TFLite mutator '{}': {error}",
                binary.display()
            ))
        })?;
    if output.status.code() == Some(3) {
        return Err(DispatchError::NoApplicableField);
    }
    if !output.status.success() {
        return Err(DispatchError::MutationFailed(format!(
            "native mutator failed (status={}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let read_result = fs::read(&temp.path);
    let bytes = read_result.map_err(|error| {
        DispatchError::MutationFailed(format!(
            "failed to read native mutation '{}': {error}",
            temp.path.display()
        ))
    })?;
    if bytes.is_empty() || bytes == input_bytes {
        return Err(DispatchError::MutationFailed(
            "native mutator produced an empty output or a no-op".to_string(),
        ));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|_| {
        DispatchError::MutationFailed("native mutator output was not UTF-8".to_string())
    })?;
    let operator_params = parse_evidence(&stdout, operator, expected)?;
    Ok(MutationOutput {
        bytes,
        operator_params,
        parse_preserving: expected.parse_preserving,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    target: &TargetKind,
    input: Option<&Path>,
    out: Option<&Path>,
    input_dir: Option<&Path>,
    out_dir: Option<&Path>,
    count: usize,
    seed: u64,
    operators: &[&'static str],
) -> Result<(), String> {
    match (input, out, input_dir, out_dir) {
        (Some(input), Some(out), None, None) => {
            run_single_mutation(target, input, out, seed, operators)
        }
        (None, None, Some(input_dir), Some(out_dir)) => {
            run_batch_mutation(target, input_dir, out_dir, count, seed, operators)
        }
        _ => Err(
            "choose exactly one mode: --input <file> --out <file> or --input-dir <dir> --out-dir <dir>"
                .to_string(),
        ),
    }
}

fn format_operator_error(operator: &str, error: DispatchError) -> String {
    match error {
        DispatchError::NoApplicableField => {
            format!("operator '{operator}' failed: no applicable field")
        }
        DispatchError::MutationFailed(message) => {
            format!("operator '{operator}' failed: {message}")
        }
    }
}

fn run_single_mutation(
    target: &TargetKind,
    input: &Path,
    out: &Path,
    seed: u64,
    operators: &[&'static str],
) -> Result<(), String> {
    if !input.exists() || !input.is_file() {
        return Err(format!("input is invalid: {}", input.display()));
    }
    let bytes = fs::read(input)
        .map_err(|error| format!("failed to read input '{}': {error}", input.display()))?;
    if bytes.is_empty() {
        return Err("input is empty".to_string());
    }

    let mut rng = DeterministicRng::new(seed);
    let set = operator_set(operators, DEFAULT_OPERATORS);
    let chosen = select_operator(set, &mut rng);
    let result = dispatch(chosen, input, out, &bytes, seed)
        .map_err(|error| format_operator_error(chosen, error))?;
    write_output(out, &result.bytes)?;

    let output_size = result.bytes.len();
    let source_hash = sha256_file(input).unwrap_or_else(|_| "not_available".to_string());
    let output_hash = sha256_file(out).unwrap_or_else(|_| "not_available".to_string());
    let entry = MutationManifestEntry {
        index: 1,
        source_seed: input.display().to_string(),
        source_hash,
        output_path: out.display().to_string(),
        output_hash,
        operator: chosen,
        operator_params: result.operator_params,
        mutation_level: contract(chosen).map_or(1, |value| value.mutation_level),
        parse_preserving: result.parse_preserving,
        validation_status: "skipped",
        seed,
        input_size: bytes.len(),
        output_size,
    };
    let manifest_path = single_manifest_path(out);
    let batch_id = out
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("single")
        .to_string();
    let out_dir = out
        .parent()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| ".".to_string());
    write_mutation_manifest(
        &manifest_path,
        target,
        "single",
        &input.display().to_string(),
        &format!("seed:{}", input.display()),
        &out_dir,
        &batch_id,
        1,
        seed,
        operators,
        "tool/mutate/tflite",
        &[entry],
    )?;
    print_mutation_report(
        target,
        input,
        out,
        seed,
        &MutationReport {
            strategy: chosen,
            input_size: bytes.len(),
            output_size,
        },
    );
    println!("manifest: {}", manifest_path.display());
    Ok(())
}

fn run_batch_mutation(
    target: &TargetKind,
    input_dir: &Path,
    out_dir: &Path,
    count: usize,
    seed: u64,
    operators: &[&'static str],
) -> Result<(), String> {
    if count == 0 {
        return Err("count must be >= 1".to_string());
    }
    if !input_dir.exists() || !input_dir.is_dir() {
        return Err(format!("input_dir is invalid: {}", input_dir.display()));
    }
    let inputs = collect_tflite_inputs(input_dir)?;
    if inputs.is_empty() {
        return Err(format!(
            "no .tflite input files found in {}",
            input_dir.display()
        ));
    }
    fs::create_dir_all(out_dir)
        .map_err(|error| format!("failed to create out_dir '{}': {error}", out_dir.display()))?;

    let set = operator_set(operators, DEFAULT_OPERATORS);
    let mut entries = Vec::new();
    let mut attempts = std::collections::BTreeMap::<PathBuf, usize>::new();
    for index in 0..count {
        let input = &inputs[index % inputs.len()];
        let bytes = fs::read(input)
            .map_err(|error| format!("failed to read input '{}': {error}", input.display()))?;
        attempts.entry(input.clone()).or_insert(0);
        if bytes.is_empty() {
            continue;
        }
        let entry_seed = seed.wrapping_add(index as u64);
        let mut rng = DeterministicRng::new(entry_seed);
        let chosen = select_operator(set, &mut rng);
        let out = out_dir.join(format!("mut-tflite-{:06}.tflite", index + 1));
        let result = match dispatch(chosen, input, &out, &bytes, entry_seed) {
            Ok(result) => result,
            Err(DispatchError::NoApplicableField) => continue,
            Err(DispatchError::MutationFailed(message)) => {
                return Err(format!("operator '{chosen}' failed: {message}"));
            }
        };
        write_output(&out, &result.bytes)?;
        *attempts.entry(input.clone()).or_insert(0) += 1;
        let output_size = result.bytes.len();
        entries.push(MutationManifestEntry {
            index: index + 1,
            source_seed: input.display().to_string(),
            source_hash: sha256_file(input).unwrap_or_else(|_| "not_available".to_string()),
            output_path: out.display().to_string(),
            output_hash: sha256_file(&out).unwrap_or_else(|_| "not_available".to_string()),
            operator: chosen,
            operator_params: result.operator_params,
            mutation_level: contract(chosen).map_or(1, |value| value.mutation_level),
            parse_preserving: result.parse_preserving,
            validation_status: "skipped",
            seed: entry_seed,
            input_size: bytes.len(),
            output_size,
        });
    }

    let batch_id = out_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("not_available")
        .to_string();
    let manifest_path = out_dir.join("manifest.json");
    write_mutation_manifest(
        &manifest_path,
        target,
        "batch",
        &input_dir.display().to_string(),
        &format!("seed_corpus:{}", input_dir.display()),
        &out_dir.display().to_string(),
        &batch_id,
        count,
        seed,
        operators,
        "tool/mutate/tflite",
        &entries,
    )?;
    print_batch_mutation_report(
        target,
        input_dir,
        seed,
        &BatchMutationReport {
            generated: entries.len(),
            requested: count,
            input_count: inputs.len(),
            out_dir: out_dir.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            unproductive_inputs: unproductive_inputs(&attempts),
        },
    );
    Ok(())
}

fn collect_tflite_inputs(input_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut inputs = Vec::new();
    for entry in fs::read_dir(input_dir).map_err(|error| {
        format!(
            "failed to read input_dir '{}': {error}",
            input_dir.display()
        )
    })? {
        let path = entry
            .map_err(|error| format!("failed to read input_dir entry: {error}"))?
            .path();
        if path.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("tflite"))
        {
            inputs.push(path);
        }
    }
    inputs.sort();
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn native_output_is_staged_inside_a_private_directory() {
        let output = temporary_output(Path::new("result.tflite"), 987_654_321).unwrap();
        let parent = output.path.parent().unwrap();
        assert_ne!(parent, std::env::temp_dir());
        assert_eq!(
            fs::metadata(parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!output.path.exists());
    }

    #[test]
    fn t4_contract_exposes_six_structural_and_six_reject_operators() {
        assert_eq!(KNOWN_OPERATORS.len(), 12);
        assert_eq!(
            KNOWN_OPERATORS
                .iter()
                .filter(|operator| contract(operator).unwrap().mode == "structural")
                .count(),
            6
        );
        assert_eq!(
            KNOWN_OPERATORS
                .iter()
                .filter(|operator| contract(operator).unwrap().mode == "reject")
                .count(),
            6
        );
    }

    #[test]
    fn only_byte_corruption_claims_not_parse_preserving() {
        let non_preserving = KNOWN_OPERATORS
            .iter()
            .copied()
            .filter(|operator| contract(operator).unwrap().parse_preserving == "no")
            .collect::<Vec<_>>();
        assert_eq!(
            non_preserving,
            vec!["buffer_payload_reject", "names_metadata_reject"]
        );
    }

    #[test]
    fn evidence_parser_rejects_noop_or_wrong_contract() {
        let expected = contract("tensor_shape").unwrap();
        let noop = "TFLITE_MUTATION_OK operator=tensor_shape mode=structural field=tensor.shape before=x after=x expected_loader=accept";
        assert!(parse_evidence(noop, "tensor_shape", expected).is_err());
        let wrong = "TFLITE_MUTATION_OK operator=tensor_shape mode=reject field=tensor.shape before=x after=y expected_loader=accept";
        assert!(parse_evidence(wrong, "tensor_shape", expected).is_err());
    }
}
