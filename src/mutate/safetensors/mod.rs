use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::mutate::common::{
    operator_set, print_batch_mutation_report, print_mutation_report, select_operator,
    single_manifest_path, unproductive_inputs, write_mutation_manifest, write_output,
    BatchMutationReport, DeterministicRng, MutationManifestEntry, MutationOutput, MutationReport,
    OperatorError,
};
use crate::{common::sha256_file, target::TargetKind};

pub(crate) mod byte_flip;
pub(crate) mod header_length;
pub(crate) mod metadata_key;
pub(crate) mod metadata_value;
pub(crate) mod tensor_data_offsets;
pub(crate) mod tensor_dtype;
pub(crate) mod tensor_name;
pub(crate) mod tensor_shape;

pub(crate) const HEADER_LEN_BYTES: usize = 8;
pub(crate) const NATURAL_ALIGNMENT_SMALL: u64 = 8;
pub(crate) const NATURAL_ALIGNMENT_LARGE: u64 = 64;

pub(crate) const DEFAULT_OPERATORS: &[&str] = &[
    header_length::NAME,
    metadata_value::NAME,
    metadata_key::NAME,
    tensor_name::NAME,
    tensor_dtype::NAME,
    tensor_shape::NAME,
    tensor_data_offsets::NAME,
];

pub(crate) const KNOWN_OPERATORS: &[&str] = &[
    header_length::NAME,
    metadata_value::NAME,
    metadata_key::NAME,
    tensor_name::NAME,
    tensor_dtype::NAME,
    tensor_shape::NAME,
    tensor_data_offsets::NAME,
    byte_flip::NAME,
];

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

fn dispatch(
    operator: &'static str,
    bytes: &[u8],
    rng: &mut DeterministicRng,
) -> Result<MutationOutput, OperatorError> {
    match operator {
        "header_length" => header_length::apply(bytes, rng),
        "metadata_value" => metadata_value::apply(bytes, rng),
        "metadata_key" => metadata_key::apply(bytes, rng),
        "tensor_name" => tensor_name::apply(bytes, rng),
        "tensor_dtype" => tensor_dtype::apply(bytes, rng),
        "tensor_shape" => tensor_shape::apply(bytes, rng),
        "tensor_data_offsets" => tensor_data_offsets::apply(bytes, rng),
        "byte_flip" => byte_flip::apply(bytes, rng),
        _ => Err(OperatorError::NoApplicableField),
    }
}

/// The mutation level recorded in the manifest, mirroring gguf/onnx: the structural
/// header-length and data-offset rewrites that reach the offset/length validation
/// defects are level 3, the length-valid shape/dtype edits are level 2, and the
/// string/byte edits are level 1.
fn mutation_level_for_operator(operator: &str) -> u32 {
    match operator {
        "header_length" | "tensor_data_offsets" => 3,
        "tensor_shape" | "tensor_dtype" => 2,
        _ => 1,
    }
}

/// One meaning of parse_preserving for every operator: does the mutated container still
/// parse? Derived by re-parsing, never hardcoded — A17/A18 established this for the
/// metadata/name operators, and the dtype/shape/offset operators now share it (they
/// used to hardcode "no" even though their length-valid edits still parse).
pub(super) fn parse_preserving_label(bytes: &[u8]) -> &'static str {
    if parse_safetensors(bytes).is_ok() {
        "yes"
    } else {
        "no"
    }
}

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

    let bytes =
        fs::read(input).map_err(|e| format!("failed to read input '{}': {e}", input.display()))?;
    if bytes.is_empty() {
        return Err("input is empty".to_string());
    }

    let mut rng = DeterministicRng::new(seed);
    let set = operator_set(operators, DEFAULT_OPERATORS);
    let chosen = select_operator(set, &mut rng);
    let result = dispatch(chosen, &bytes, &mut rng)
        .map_err(|e| format!("operator '{}' failed: {:?}", chosen, e))?;
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
        mutation_level: mutation_level_for_operator(chosen),
        parse_preserving: result.parse_preserving,
        validation_status: "skipped",
        seed,
        input_size: bytes.len(),
        output_size,
    };

    let manifest_path_buf = single_manifest_path(out);
    let batch_id = out
        .file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or("single")
        .to_string();
    let out_dir_str = out
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| ".".to_string());
    write_mutation_manifest(
        &manifest_path_buf,
        target,
        "single",
        &input.display().to_string(),
        &format!("seed:{}", input.display()),
        &out_dir_str,
        &batch_id,
        1,
        seed,
        operators,
        "tool/mutate/safetensors",
        &[entry],
    )?;

    let report = MutationReport {
        strategy: chosen,
        input_size: bytes.len(),
        output_size,
    };
    print_mutation_report(target, input, out, seed, &report);
    println!("manifest: {}", manifest_path_buf.display());
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

    let inputs = collect_safetensors_inputs(input_dir)?;
    if inputs.is_empty() {
        return Err(format!(
            "no .safetensors input files found in {}",
            input_dir.display()
        ));
    }
    fs::create_dir_all(out_dir)
        .map_err(|e| format!("failed to create out_dir '{}': {e}", out_dir.display()))?;

    let set = operator_set(operators, DEFAULT_OPERATORS);
    let mut entries = Vec::new();
    let mut attempts: std::collections::BTreeMap<PathBuf, usize> =
        std::collections::BTreeMap::new();
    for idx in 0..count {
        let input = &inputs[idx % inputs.len()];
        let bytes = fs::read(input)
            .map_err(|e| format!("failed to read input '{}': {e}", input.display()))?;
        attempts.entry(input.clone()).or_insert(0);
        if bytes.is_empty() {
            continue;
        }

        let mut rng = DeterministicRng::new(seed.wrapping_add(idx as u64));
        let entry_seed = seed.wrapping_add(idx as u64);
        let chosen = select_operator(set, &mut rng);
        let result = match dispatch(chosen, &bytes, &mut rng) {
            Ok(r) => r,
            Err(_) => continue,
        };
        *attempts.entry(input.clone()).or_insert(0) += 1;
        let output_size = result.bytes.len();
        let out = out_dir.join(format!("mut-safetensors-{:06}.safetensors", idx + 1));
        fs::write(&out, &result.bytes)
            .map_err(|e| format!("failed to write output '{}': {e}", out.display()))?;
        let output_hash = sha256_file(&out).unwrap_or_else(|_| "not_available".to_string());
        let source_hash = sha256_file(input).unwrap_or_else(|_| "not_available".to_string());
        entries.push(MutationManifestEntry {
            index: idx + 1,
            source_seed: input.display().to_string(),
            source_hash,
            output_path: out.display().to_string(),
            output_hash,
            operator: chosen,
            operator_params: result.operator_params,
            mutation_level: mutation_level_for_operator(chosen),
            parse_preserving: result.parse_preserving,
            validation_status: "skipped",
            seed: entry_seed,
            input_size: bytes.len(),
            output_size,
        });
    }

    let batch_id = out_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("not_available")
        .to_string();
    let manifest_path_buf = out_dir.join("manifest.json");
    write_mutation_manifest(
        &manifest_path_buf,
        target,
        "batch",
        &input_dir.display().to_string(),
        &format!("seed_corpus:{}", input_dir.display()),
        &out_dir.display().to_string(),
        &batch_id,
        count,
        seed,
        operators,
        "tool/mutate/safetensors",
        &entries,
    )?;

    let report = BatchMutationReport {
        generated: entries.len(),
        requested: count,
        input_count: inputs.len(),
        out_dir: out_dir.display().to_string(),
        manifest_path: manifest_path_buf.display().to_string(),
        unproductive_inputs: unproductive_inputs(&attempts),
    };
    print_batch_mutation_report(target, input_dir, seed, &report);
    Ok(())
}

fn collect_safetensors_inputs(input_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut inputs = Vec::new();
    for entry in fs::read_dir(input_dir)
        .map_err(|e| format!("failed to read input_dir '{}': {e}", input_dir.display()))?
    {
        let entry = entry.map_err(|e| format!("failed to read input_dir entry: {e}"))?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("safetensors"))
                .unwrap_or(false)
        {
            inputs.push(path);
        }
    }
    inputs.sort();
    Ok(inputs)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    TooSmall,
    HeaderLenZero,
    HeaderLenOverflow,
    HeaderOutOfRange,
    InvalidUtf8,
    JsonUnexpectedEof,
    JsonExpected(u8),
    JsonExpectedNumber,
    JsonExpectedString,
    JsonBadEscape,
    JsonRootNotObject,
    TensorMissingField(&'static str),
    DataOffsetsNotPair,
    ShapeNotArray,
    JsonNestingTooDeep,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall => write!(f, "safetensors smaller than 8-byte header prefix"),
            Self::HeaderLenZero => write!(f, "safetensors header length is zero"),
            Self::HeaderLenOverflow => write!(f, "safetensors header length overflow"),
            Self::HeaderOutOfRange => write!(f, "safetensors header out of range"),
            Self::InvalidUtf8 => write!(f, "safetensors header is not utf-8"),
            Self::JsonUnexpectedEof => write!(f, "safetensors json truncated"),
            Self::JsonExpected(b) => {
                write!(f, "safetensors json expected '{}'", *b as char)
            }
            Self::JsonExpectedNumber => write!(f, "safetensors json expected number"),
            Self::JsonExpectedString => write!(f, "safetensors json expected string"),
            Self::JsonBadEscape => write!(f, "safetensors json bad escape sequence"),
            Self::JsonRootNotObject => write!(f, "safetensors json root is not object"),
            Self::TensorMissingField(name) => {
                write!(f, "safetensors tensor missing field '{}'", name)
            }
            Self::DataOffsetsNotPair => {
                write!(f, "safetensors data_offsets is not a 2-element array")
            }
            Self::ShapeNotArray => write!(f, "safetensors shape is not an array"),
            Self::JsonNestingTooDeep => write!(f, "safetensors json nesting exceeds depth limit"),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct StringSpan {
    pub(crate) outer_start: usize,
    pub(crate) outer_end: usize,
    pub(crate) inner_start: usize,
    pub(crate) inner_end: usize,
}

impl StringSpan {
    pub(crate) fn inner_len(&self) -> usize {
        self.inner_end - self.inner_start
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NumberSpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl NumberSpan {
    pub(crate) fn len(&self) -> usize {
        self.end - self.start
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct ArraySpan {
    pub(crate) open: usize,
    pub(crate) close: usize,
    pub(crate) elements: Vec<NumberSpan>,
}

#[derive(Debug, Clone)]
pub(crate) struct TensorEntry {
    pub(crate) name: StringSpan,
    pub(crate) dtype: StringSpan,
    pub(crate) shape: ArraySpan,
    pub(crate) data_offsets: ArraySpan,
}

#[derive(Debug, Clone)]
pub(crate) struct MetadataKv {
    pub(crate) key: StringSpan,
    pub(crate) value: StringSpan,
}

#[derive(Debug, Clone)]
pub(crate) struct MetadataSection {
    pub(crate) kvs: Vec<MetadataKv>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct SafetensorsLayout {
    pub(crate) header_len: u64,
    pub(crate) json_start: usize,
    pub(crate) json_end: usize,
    pub(crate) header_end: usize,
    pub(crate) tensors: Vec<TensorEntry>,
    pub(crate) metadata: Option<MetadataSection>,
}

pub(crate) fn parse_safetensors(bytes: &[u8]) -> Result<SafetensorsLayout, ParseError> {
    if bytes.len() < HEADER_LEN_BYTES {
        return Err(ParseError::TooSmall);
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[0..HEADER_LEN_BYTES]);
    let header_len = u64::from_le_bytes(arr);
    if header_len == 0 {
        return Err(ParseError::HeaderLenZero);
    }
    let header_len_usize =
        usize::try_from(header_len).map_err(|_| ParseError::HeaderLenOverflow)?;
    let json_start = HEADER_LEN_BYTES;
    let json_end = HEADER_LEN_BYTES
        .checked_add(header_len_usize)
        .ok_or(ParseError::HeaderLenOverflow)?;
    if json_end > bytes.len() {
        return Err(ParseError::HeaderOutOfRange);
    }
    let json_slice =
        std::str::from_utf8(&bytes[json_start..json_end]).map_err(|_| ParseError::InvalidUtf8)?;

    let mut walker = JsonWalker::new(json_slice, json_start);
    walker.skip_whitespace();
    if walker.peek() != Some(b'{') {
        return Err(ParseError::JsonRootNotObject);
    }
    walker.cursor += 1;

    let mut tensors = Vec::new();
    let mut metadata: Option<MetadataSection> = None;
    let mut first = true;

    loop {
        walker.skip_whitespace();
        match walker.peek() {
            Some(b'}') => break,
            None => return Err(ParseError::JsonUnexpectedEof),
            _ => {}
        }
        if !first {
            walker.expect(b',')?;
            walker.skip_whitespace();
        }
        first = false;

        let key_span = walker.parse_string()?;
        let key_str = walker.slice_inner(&key_span).to_string();
        walker.skip_whitespace();
        walker.expect(b':')?;
        walker.skip_whitespace();

        if key_str == "__metadata__" {
            let section = walker.parse_metadata_object()?;
            metadata = Some(section);
        } else if walker.peek() == Some(b'{') {
            let entry = walker.parse_tensor_object(key_span)?;
            tensors.push(entry);
        } else {
            walker.skip_value()?;
        }
    }

    let header_end = json_end;

    Ok(SafetensorsLayout {
        header_len,
        json_start,
        json_end,
        header_end,
        tensors,
        metadata,
    })
}

const MAX_JSON_NESTING_DEPTH: usize = 64;

struct JsonWalker<'a> {
    src: &'a str,
    bytes: &'a [u8],
    cursor: usize,
    base: usize,
}

impl<'a> JsonWalker<'a> {
    fn new(src: &'a str, base: usize) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            cursor: 0,
            base,
        }
    }

    fn abs(&self, relative: usize) -> usize {
        self.base + relative
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.cursor).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.cursor += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, ch: u8) -> Result<(), ParseError> {
        match self.peek() {
            Some(b) if b == ch => {
                self.cursor += 1;
                Ok(())
            }
            Some(_) => Err(ParseError::JsonExpected(ch)),
            None => Err(ParseError::JsonUnexpectedEof),
        }
    }

    fn slice_inner(&self, span: &StringSpan) -> &str {
        let s = span.inner_start - self.base;
        let e = span.inner_end - self.base;
        &self.src[s..e]
    }

    fn parse_string(&mut self) -> Result<StringSpan, ParseError> {
        if self.peek() != Some(b'"') {
            return Err(ParseError::JsonExpectedString);
        }
        let outer_start = self.cursor;
        self.cursor += 1;
        let inner_start = self.cursor;
        while let Some(b) = self.peek() {
            match b {
                b'\\' => {
                    self.cursor += 1;
                    if self.peek().is_none() {
                        return Err(ParseError::JsonBadEscape);
                    }
                    self.cursor += 1;
                }
                b'"' => {
                    let inner_end = self.cursor;
                    self.cursor += 1;
                    return Ok(StringSpan {
                        outer_start: self.abs(outer_start),
                        outer_end: self.abs(self.cursor),
                        inner_start: self.abs(inner_start),
                        inner_end: self.abs(inner_end),
                    });
                }
                _ => self.cursor += 1,
            }
        }
        Err(ParseError::JsonUnexpectedEof)
    }

    fn parse_number(&mut self) -> Result<NumberSpan, ParseError> {
        let start = self.cursor;
        if matches!(self.peek(), Some(b'-')) {
            self.cursor += 1;
        }
        let digits_start = self.cursor;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.cursor += 1;
            } else {
                break;
            }
        }
        if self.cursor == digits_start {
            return Err(ParseError::JsonExpectedNumber);
        }
        if matches!(self.peek(), Some(b'.')) {
            self.cursor += 1;
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() {
                    self.cursor += 1;
                } else {
                    break;
                }
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.cursor += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.cursor += 1;
            }
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() {
                    self.cursor += 1;
                } else {
                    break;
                }
            }
        }
        Ok(NumberSpan {
            start: self.abs(start),
            end: self.abs(self.cursor),
        })
    }

    fn parse_number_array(&mut self) -> Result<ArraySpan, ParseError> {
        self.expect(b'[')?;
        let open = self.abs(self.cursor - 1);
        let mut elements = Vec::new();
        self.skip_whitespace();
        let mut first = true;
        loop {
            self.skip_whitespace();
            if self.peek() == Some(b']') {
                self.cursor += 1;
                let close = self.abs(self.cursor);
                return Ok(ArraySpan {
                    open,
                    close,
                    elements,
                });
            }
            if !first {
                self.expect(b',')?;
                self.skip_whitespace();
            }
            first = false;
            let num = self.parse_number()?;
            elements.push(num);
        }
    }

    fn parse_tensor_object(&mut self, name: StringSpan) -> Result<TensorEntry, ParseError> {
        self.expect(b'{')?;
        let mut dtype: Option<StringSpan> = None;
        let mut shape: Option<ArraySpan> = None;
        let mut data_offsets: Option<ArraySpan> = None;
        let mut first = true;
        loop {
            self.skip_whitespace();
            if self.peek() == Some(b'}') {
                self.cursor += 1;
                break;
            }
            if !first {
                self.expect(b',')?;
                self.skip_whitespace();
            }
            first = false;
            let field_key = self.parse_string()?;
            let key_str = self.slice_inner(&field_key).to_string();
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            match key_str.as_str() {
                "dtype" => {
                    let span = self.parse_string()?;
                    dtype = Some(span);
                }
                "shape" => {
                    if self.peek() != Some(b'[') {
                        return Err(ParseError::ShapeNotArray);
                    }
                    let arr = self.parse_number_array()?;
                    shape = Some(arr);
                }
                "data_offsets" => {
                    if self.peek() != Some(b'[') {
                        return Err(ParseError::DataOffsetsNotPair);
                    }
                    let arr = self.parse_number_array()?;
                    data_offsets = Some(arr);
                }
                _ => {
                    self.skip_value()?;
                }
            }
        }
        let dtype = dtype.ok_or(ParseError::TensorMissingField("dtype"))?;
        let shape = shape.ok_or(ParseError::TensorMissingField("shape"))?;
        let data_offsets = data_offsets.ok_or(ParseError::TensorMissingField("data_offsets"))?;
        if data_offsets.elements.len() != 2 {
            return Err(ParseError::DataOffsetsNotPair);
        }
        Ok(TensorEntry {
            name,
            dtype,
            shape,
            data_offsets,
        })
    }

    fn parse_metadata_object(&mut self) -> Result<MetadataSection, ParseError> {
        self.expect(b'{')?;
        let mut kvs = Vec::new();
        let mut first = true;
        loop {
            self.skip_whitespace();
            if self.peek() == Some(b'}') {
                self.cursor += 1;
                break;
            }
            if !first {
                self.expect(b',')?;
                self.skip_whitespace();
            }
            first = false;
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            if self.peek() == Some(b'"') {
                let value = self.parse_string()?;
                kvs.push(MetadataKv { key, value });
            } else {
                self.skip_value()?;
            }
        }
        Ok(MetadataSection { kvs })
    }

    fn skip_value(&mut self) -> Result<(), ParseError> {
        self.skip_value_depth(0)
    }

    fn skip_value_depth(&mut self, depth: usize) -> Result<(), ParseError> {
        // safetensors headers are flat (tensor objects one level deep); a small cap
        // stops crafted deeply-nested '['/'{' from exhausting the stack (A6).
        if depth > MAX_JSON_NESTING_DEPTH {
            return Err(ParseError::JsonNestingTooDeep);
        }
        self.skip_whitespace();
        match self.peek() {
            Some(b'"') => {
                self.parse_string()?;
                Ok(())
            }
            Some(b'{') => {
                self.cursor += 1;
                let mut first = true;
                loop {
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        self.cursor += 1;
                        return Ok(());
                    }
                    if !first {
                        self.expect(b',')?;
                        self.skip_whitespace();
                    }
                    first = false;
                    let _ = self.parse_string()?;
                    self.skip_whitespace();
                    self.expect(b':')?;
                    self.skip_value_depth(depth + 1)?;
                }
            }
            Some(b'[') => {
                self.cursor += 1;
                let mut first = true;
                loop {
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        self.cursor += 1;
                        return Ok(());
                    }
                    if !first {
                        self.expect(b',')?;
                        self.skip_whitespace();
                    }
                    first = false;
                    self.skip_value_depth(depth + 1)?;
                }
            }
            Some(b't') | Some(b'f') | Some(b'n') => {
                while let Some(b) = self.peek() {
                    if b.is_ascii_alphabetic() {
                        self.cursor += 1;
                    } else {
                        break;
                    }
                }
                Ok(())
            }
            Some(_) => {
                self.parse_number()?;
                Ok(())
            }
            None => Err(ParseError::JsonUnexpectedEof),
        }
    }
}

pub(crate) fn pick_different_ascii_byte(rng: &mut DeterministicRng, current: u8) -> u8 {
    let range = (0x7eu8 - 0x21u8 + 1) as usize;
    loop {
        let candidate = 0x21u8 + (rng.index(range) as u8);
        if candidate != current {
            return candidate;
        }
    }
}

pub(crate) fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, ParseError> {
    let end = offset.checked_add(8).ok_or(ParseError::HeaderLenOverflow)?;
    if end > bytes.len() {
        return Err(ParseError::TooSmall);
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[offset..end]);
    Ok(u64::from_le_bytes(arr))
}

pub(crate) fn write_u64_le(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn digit_count_u64(value: u64) -> usize {
    let mut n = value;
    if n == 0 {
        return 1;
    }
    let mut c = 0;
    while n > 0 {
        c += 1;
        n /= 10;
    }
    c
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    pub(crate) fn build_minimal_safetensors() -> Vec<u8> {
        let header =
            br#"{"tensor_a":{"dtype":"F32","shape":[2,3],"data_offsets":[0,24]}}"#.to_vec();
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&[0u8; 24]);
        bytes
    }

    pub(crate) fn build_safetensors_with_metadata() -> Vec<u8> {
        let header =
            br#"{"__metadata__":{"format":"pt"},"t":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#.to_vec();
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&[0u8; 4]);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::{build_minimal_safetensors, build_safetensors_with_metadata};
    use super::*;

    // Grade operators by mutation level like gguf/onnx, instead of a flat 1: the
    // structural header-length/data-offset rewrites (the offset/length validation
    // defects) are 3, the length-valid shape/dtype edits are 2, the rest are 1.
    // A same-length dtype swap keeps the container valid, so parse_preserving must be
    // DERIVED ("yes"), not hardcoded "no". This unifies the label meaning across all
    // operators to "the container still parses".
    #[test]
    fn tensor_dtype_label_reflects_that_the_output_still_parses() {
        let bytes = build_minimal_safetensors();
        let mut rng = DeterministicRng::new(7);
        let out = tensor_dtype::apply(&bytes, &mut rng).expect("dtype applies to F32 fixture");
        assert!(
            parse_safetensors(&out.bytes).is_ok(),
            "a same-length dtype swap should still parse"
        );
        assert_eq!(out.parse_preserving, "yes");
    }

    #[test]
    fn safetensors_operators_are_graded_by_mutation_level() {
        assert_eq!(mutation_level_for_operator(header_length::NAME), 3);
        assert_eq!(mutation_level_for_operator(tensor_data_offsets::NAME), 3);
        assert_eq!(mutation_level_for_operator(tensor_shape::NAME), 2);
        assert_eq!(mutation_level_for_operator(tensor_dtype::NAME), 2);
        assert_eq!(mutation_level_for_operator(byte_flip::NAME), 1);
        assert_eq!(mutation_level_for_operator(metadata_key::NAME), 1);
        assert_eq!(mutation_level_for_operator(metadata_value::NAME), 1);
        assert_eq!(mutation_level_for_operator(tensor_name::NAME), 1);
    }

    #[test]
    fn skip_value_rejects_deeply_nested_json() {
        // A6 regression: unbounded recursion on nested '['/'{' lets a crafted header
        // overflow the stack (SIGABRT) before any bounds check. Must be a clean error.
        let depth = 500usize;
        let json = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let mut walker = JsonWalker::new(&json, 0);
        let result = walker.skip_value();
        assert!(
            matches!(result, Err(ParseError::JsonNestingTooDeep)),
            "deeply nested json must be rejected with JsonNestingTooDeep"
        );
    }

    #[test]
    fn parse_minimal_safetensors_succeeds() {
        let bytes = build_minimal_safetensors();
        let layout = parse_safetensors(&bytes).expect("parse minimal");
        assert_eq!(layout.header_len, 64);
        assert_eq!(layout.tensors.len(), 1);
        let t = &layout.tensors[0];
        assert_eq!(&bytes[t.name.inner_start..t.name.inner_end], b"tensor_a");
        assert_eq!(&bytes[t.dtype.inner_start..t.dtype.inner_end], b"F32");
        assert_eq!(t.shape.elements.len(), 2);
        assert_eq!(t.data_offsets.elements.len(), 2);
    }

    #[test]
    fn parse_rejects_too_small() {
        assert!(matches!(
            parse_safetensors(&[0u8; 4]),
            Err(ParseError::TooSmall)
        ));
    }

    #[test]
    fn parse_rejects_zero_header_len() {
        assert!(matches!(
            parse_safetensors(&[0u8; 16]),
            Err(ParseError::HeaderLenZero)
        ));
    }

    #[test]
    fn parse_rejects_header_out_of_range() {
        let mut bytes = 999u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        assert!(matches!(
            parse_safetensors(&bytes),
            Err(ParseError::HeaderOutOfRange)
        ));
    }

    #[test]
    fn parse_extracts_metadata_section() {
        let bytes = build_safetensors_with_metadata();
        let layout = parse_safetensors(&bytes).expect("parse with metadata");
        let m = layout.metadata.as_ref().expect("metadata section");
        assert_eq!(m.kvs.len(), 1);
        assert_eq!(
            &bytes[m.kvs[0].key.inner_start..m.kvs[0].key.inner_end],
            b"format"
        );
        assert_eq!(
            &bytes[m.kvs[0].value.inner_start..m.kvs[0].value.inner_end],
            b"pt"
        );
        assert_eq!(layout.tensors.len(), 1);
    }

    #[test]
    fn validate_operators_accepts_known() {
        let req = vec!["metadata_value".to_string(), "byte_flip".to_string()];
        let resolved = validate_operators(&req).expect("known operators accepted");
        assert_eq!(resolved, vec!["metadata_value", "byte_flip"]);
    }

    #[test]
    fn validate_operators_rejects_unknown() {
        let req = vec!["nonexistent".to_string()];
        assert!(validate_operators(&req).is_err());
    }

    #[test]
    fn default_operators_excludes_opt_in() {
        assert!(!DEFAULT_OPERATORS.contains(&byte_flip::NAME));
        assert!(KNOWN_OPERATORS.contains(&byte_flip::NAME));
        assert_eq!(DEFAULT_OPERATORS.len(), 7);
        assert_eq!(KNOWN_OPERATORS.len(), 8);
    }

    #[test]
    fn header_length_mutates_u64() {
        let bytes = build_minimal_safetensors();
        let mut rng = DeterministicRng::new(1);
        let r = header_length::apply(&bytes, &mut rng).expect("apply");
        assert_ne!(r.bytes[0..8], bytes[0..8]);
        let old_v = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let new_v = u64::from_le_bytes(r.bytes[0..8].try_into().unwrap());
        assert!(new_v == old_v + 1 || new_v == old_v.saturating_sub(1));
        // The label is DERIVED now (was hardcoded "no"): for this seed the ±1 header
        // length still parses, so the label must be "yes" and must match the parser.
        let parses = parse_safetensors(&r.bytes).is_ok();
        assert_eq!(
            r.parse_preserving == "yes",
            parses,
            "label must match the parser"
        );
        assert_eq!(r.parse_preserving, "yes");
    }

    #[test]
    fn metadata_value_preserves_length() {
        let bytes = build_safetensors_with_metadata();
        let mut rng = DeterministicRng::new(2);
        let r = metadata_value::apply(&bytes, &mut rng).expect("apply");
        assert_ne!(r.bytes, bytes);
        assert_eq!(r.bytes.len(), bytes.len());
        assert_eq!(r.parse_preserving, "yes");
    }

    #[test]
    fn metadata_key_preserves_length() {
        let bytes = build_safetensors_with_metadata();
        let mut rng = DeterministicRng::new(3);
        let r = metadata_key::apply(&bytes, &mut rng).expect("apply");
        assert_ne!(r.bytes, bytes);
        assert_eq!(r.bytes.len(), bytes.len());
        assert_eq!(r.parse_preserving, "yes");
    }

    #[test]
    fn metadata_operators_no_applicable_without_metadata() {
        let bytes = build_minimal_safetensors();
        let mut rng = DeterministicRng::new(5);
        assert!(matches!(
            metadata_value::apply(&bytes, &mut rng),
            Err(OperatorError::NoApplicableField)
        ));
        let mut rng = DeterministicRng::new(7);
        assert!(matches!(
            metadata_key::apply(&bytes, &mut rng),
            Err(OperatorError::NoApplicableField)
        ));
    }

    #[test]
    fn tensor_name_preserves_length() {
        let bytes = build_minimal_safetensors();
        let mut rng = DeterministicRng::new(11);
        let r = tensor_name::apply(&bytes, &mut rng).expect("apply");
        assert_ne!(r.bytes, bytes);
        assert_eq!(r.bytes.len(), bytes.len());
        assert_eq!(r.parse_preserving, "yes");
    }

    #[test]
    fn tensor_dtype_swaps_in_same_length_group() {
        let bytes = build_minimal_safetensors();
        let mut rng = DeterministicRng::new(13);
        let r = tensor_dtype::apply(&bytes, &mut rng).expect("apply");
        assert_ne!(r.bytes, bytes);
        assert_eq!(r.bytes.len(), bytes.len());
        let layout = parse_safetensors(&r.bytes).expect("parse after");
        let dtype =
            &r.bytes[layout.tensors[0].dtype.inner_start..layout.tensors[0].dtype.inner_end];
        assert_eq!(dtype.len(), 3);
        assert_ne!(dtype, b"F32");
        assert_eq!(r.parse_preserving, "yes");
    }

    #[test]
    fn tensor_shape_preserves_digit_count() {
        let bytes = build_minimal_safetensors();
        let mut rng = DeterministicRng::new(17);
        let r = tensor_shape::apply(&bytes, &mut rng).expect("apply");
        assert_ne!(r.bytes, bytes);
        assert_eq!(r.bytes.len(), bytes.len());
        assert_eq!(r.parse_preserving, "yes");
    }

    #[test]
    fn tensor_data_offsets_preserves_alignment() {
        let bytes = build_minimal_safetensors();
        let mut rng = DeterministicRng::new(19);
        let r = tensor_data_offsets::apply(&bytes, &mut rng).expect("apply");
        assert_ne!(r.bytes, bytes);
        assert_eq!(r.bytes.len(), bytes.len());
        let layout = parse_safetensors(&r.bytes).expect("parse after");
        let elements = &layout.tensors[0].data_offsets.elements;
        let start: u64 = std::str::from_utf8(&r.bytes[elements[0].start..elements[0].end])
            .unwrap()
            .parse()
            .unwrap();
        let end: u64 = std::str::from_utf8(&r.bytes[elements[1].start..elements[1].end])
            .unwrap()
            .parse()
            .unwrap();
        assert!(start < end);
        assert_eq!(start % NATURAL_ALIGNMENT_SMALL, 0);
        assert_eq!(end % NATURAL_ALIGNMENT_SMALL, 0);
        assert_eq!(r.parse_preserving, "yes");
    }

    #[test]
    fn byte_flip_targets_header_region() {
        let bytes = build_minimal_safetensors();
        let mut rng = DeterministicRng::new(23);
        let r = byte_flip::apply(&bytes, &mut rng).expect("apply");
        assert_ne!(r.bytes, bytes);
        let layout = parse_safetensors(&bytes).expect("parse");
        let diff_idx = (0..bytes.len())
            .find(|&i| bytes[i] != r.bytes[i])
            .expect("difference exists");
        assert!(diff_idx < layout.header_end);
        assert_eq!(r.parse_preserving, "no");
    }
}
