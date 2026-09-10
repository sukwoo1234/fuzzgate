use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
};

use crate::common::{
    command_with_core_dump_off, download_file, download_file_name, first_line, has_ext,
    is_core_dump_wrapper_exec_failure, sha256_file, validate_official_source, AppPaths,
};
use crate::json_utils::json_escape;

#[derive(clap::ValueEnum, Clone, Debug)]
pub(crate) enum TargetKind {
    #[value(name = "gguf")]
    Gguf,
    #[value(name = "onnx")]
    Onnx,
    #[value(name = "safetensors")]
    Safetensors,
}

#[derive(Clone, Copy)]
pub(crate) struct TargetPreset {
    pub(crate) name: &'static str,
    pub(crate) default_version: &'static str,
    pub(crate) default_url: &'static str,
    pub(crate) official_owner: &'static str,
    pub(crate) official_repo: &'static str,
}

pub(crate) struct TargetMeta {
    pub(crate) schema_version: &'static str,
    pub(crate) target: String,
    pub(crate) version: String,
    pub(crate) source_url: String,
    pub(crate) source_kind: &'static str,
    pub(crate) downloaded_file: String,
    pub(crate) downloaded_sha256: String,
    pub(crate) downloaded_size_bytes: u64,
}

pub(crate) struct HarnessReport {
    pub(crate) target: &'static str,
    pub(crate) input: String,
    pub(crate) parser_step: String,
    pub(crate) core_path_step: String,
    pub(crate) library_step: String,
    pub(crate) library_outcome: &'static str,
    pub(crate) external_step: String,
}

pub(crate) struct LibraryConnectResult {
    pub(crate) step: String,
    pub(crate) outcome: LibraryConnectOutcome,
}

#[derive(Clone, Copy)]
pub(crate) enum LibraryConnectOutcome {
    SessionOk,
    Invoked,
    Crashed,
    Unavailable,
}

impl LibraryConnectOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            LibraryConnectOutcome::SessionOk => "session_ok",
            LibraryConnectOutcome::Invoked => "invoked",
            LibraryConnectOutcome::Crashed => "crashed",
            LibraryConnectOutcome::Unavailable => "unavailable",
        }
    }
}

pub(crate) struct TargetAdapter {
    pub(crate) target_label: &'static str,
    pub(crate) seed_subdir: &'static str,
    pub(crate) input_ext: &'static str,
}

pub(crate) fn target_label(target: &TargetKind) -> &'static str {
    match target {
        TargetKind::Gguf => "gguf",
        TargetKind::Onnx => "onnx",
        TargetKind::Safetensors => "safetensors",
    }
}

pub(crate) fn seed_ext(target: &TargetKind) -> &'static str {
    match target {
        TargetKind::Gguf => "gguf",
        TargetKind::Onnx => "onnx",
        TargetKind::Safetensors => "safetensors",
    }
}

pub(crate) fn preset_for_target(target: &TargetKind) -> TargetPreset {
    match target {
        TargetKind::Gguf => TargetPreset {
            name: "llama.cpp",
            default_version: "b7921",
            default_url: "https://github.com/ggml-org/llama.cpp/archive/refs/tags/b7921.tar.gz",
            official_owner: "ggml-org",
            official_repo: "llama.cpp",
        },
        TargetKind::Onnx => TargetPreset {
            name: "onnxruntime",
            default_version: "v1.23.2",
            default_url:
                "https://github.com/microsoft/onnxruntime/archive/refs/tags/v1.23.2.tar.gz",
            official_owner: "microsoft",
            official_repo: "onnxruntime",
        },
        TargetKind::Safetensors => TargetPreset {
            name: "safetensors",
            default_version: "v0.7.0",
            default_url:
                "https://github.com/huggingface/safetensors/archive/refs/tags/v0.7.0.tar.gz",
            official_owner: "huggingface",
            official_repo: "safetensors",
        },
    }
}

pub(crate) fn resolve_target_adapter(target: &TargetKind) -> TargetAdapter {
    TargetAdapter {
        target_label: target_label(target),
        seed_subdir: target_label(target),
        input_ext: seed_ext(target),
    }
}

pub(crate) fn default_seed_dir(app_paths: &AppPaths, target: &TargetKind) -> PathBuf {
    let adapter = resolve_target_adapter(target);
    app_paths.seeds_dir.join(adapter.seed_subdir)
}

pub(crate) fn collect_corpus_inputs(
    corpus_dir: &Path,
    target: &TargetKind,
) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(corpus_dir)
        .map_err(|e| format!("failed to read corpus dir '{}': {e}", corpus_dir.display()))?
    {
        let entry = entry.map_err(|e| format!("failed to read dir entry: {e}"))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let keep = match target {
            TargetKind::Gguf => has_ext(&path, "gguf"),
            TargetKind::Onnx => has_ext(&path, "onnx"),
            TargetKind::Safetensors => has_ext(&path, "safetensors"),
        };
        if keep {
            files.push(path);
        }
    }

    files.sort();
    Ok(files)
}

pub(crate) fn prepare_target(
    app_paths: &AppPaths,
    target: &TargetKind,
    version_override: Option<String>,
    source_url_override: Option<String>,
) -> Result<(), String> {
    let preset = preset_for_target(target);
    let version = version_override.unwrap_or_else(|| preset.default_version.to_string());
    let source_url = source_url_override.unwrap_or_else(|| preset.default_url.to_string());

    validate_official_source(&source_url, preset.official_owner, preset.official_repo)?;

    let file_name = download_file_name(&source_url);

    let target_root = app_paths
        .data_dir
        .join("targets")
        .join(preset.name)
        .join(&version);
    let source_dir = target_root.join("source");
    fs::create_dir_all(&source_dir)
        .map_err(|e| format!("failed to create '{}': {e}", source_dir.display()))?;

    let file_path = source_dir.join(&file_name);
    download_file(&source_url, &file_path)?;
    let sha256 = sha256_file(&file_path)?;
    let size_bytes = fs::metadata(&file_path)
        .map_err(|e| format!("failed to read metadata '{}': {e}", file_path.display()))?
        .len();

    let meta = TargetMeta {
        schema_version: "1.0",
        target: preset.name.to_string(),
        version: version.clone(),
        source_url,
        source_kind: "official_release",
        downloaded_file: file_path.display().to_string(),
        downloaded_sha256: sha256,
        downloaded_size_bytes: size_bytes,
    };

    let meta_path = target_root.join("meta.json");
    let meta_json = render_meta_json(&meta);
    fs::write(&meta_path, meta_json)
        .map_err(|e| format!("failed to write '{}': {e}", meta_path.display()))?;

    println!("[prepare-target] done");
    println!("target: {}", preset.name);
    println!("version: {version}");
    println!("file: {}", file_path.display());
    println!("sha256: {}", meta.downloaded_sha256);
    println!("meta: {}", meta_path.display());

    Ok(())
}

/// G3: why a harness invocation failed. Only a real library crash is the finding we
/// fuzz for; an input the harness rejected before the library ran, and a harness that
/// could not run at all, are not. Each exits with its own code so `run`/`triage` and
/// the engine drivers can tell a finding from a rejected input from a broken host.
#[derive(Debug)]
pub(crate) enum HarnessError {
    LibraryCrash(String),
    InputRejected(String),
    Unavailable(String),
}

impl HarnessError {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            HarnessError::LibraryCrash(_) => crate::EXIT_HARNESS_LIBRARY_CRASH,
            HarnessError::InputRejected(_) => crate::EXIT_HARNESS_INPUT_REJECTED,
            HarnessError::Unavailable(_) => crate::EXIT_HARNESS_UNAVAILABLE,
        }
    }
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HarnessError::LibraryCrash(msg)
            | HarnessError::InputRejected(msg)
            | HarnessError::Unavailable(msg) => write!(f, "{msg}"),
        }
    }
}

pub(crate) fn run_harness(target: &TargetKind, input: &Path) -> Result<(), HarnessError> {
    if !input.exists() {
        return Err(HarnessError::InputRejected(format!(
            "input not found: {}",
            input.display()
        )));
    }
    if !input.is_file() {
        return Err(HarnessError::InputRejected(format!(
            "input is not a file: {}",
            input.display()
        )));
    }

    let bytes = fs::read(input).map_err(|e| {
        HarnessError::InputRejected(format!("failed to read input '{}': {e}", input.display()))
    })?;

    let parser_step = match target {
        TargetKind::Gguf => gguf_precheck(&bytes).map_err(HarnessError::InputRejected)?,
        TargetKind::Onnx => onnx_precheck(&bytes).map_err(HarnessError::InputRejected)?,
        TargetKind::Safetensors => {
            safetensors_precheck(&bytes).map_err(HarnessError::InputRejected)?
        }
    };

    let core_path_step = match target {
        TargetKind::Gguf => "header->llama.cpp parser".to_string(),
        TargetKind::Onnx => "protobuf->onnxruntime session loader".to_string(),
        TargetKind::Safetensors => "header_json->safetensors deserialize".to_string(),
    };
    let library_connect = match target {
        TargetKind::Gguf => gguf_library_connect(input),
        TargetKind::Onnx => onnx_library_connect(input),
        TargetKind::Safetensors => safetensors_library_connect(input),
    };
    let strict_connect = std::env::var("TOOL_REQUIRE_LIBRARY_CONNECT")
        .map(|v| v == "1")
        .unwrap_or(false);
    if strict_connect && matches!(library_connect.outcome, LibraryConnectOutcome::Unavailable) {
        // Environment problem, not a finding: the library never ran.
        return Err(HarnessError::Unavailable(format!(
            "library connect required but unavailable: {}",
            library_connect.step
        )));
    }

    let library_crashed = matches!(library_connect.outcome, LibraryConnectOutcome::Crashed);
    let library_crash_step = library_connect.step.clone();
    let external_step = if library_crashed {
        "skipped because library_connect crashed".to_string()
    } else {
        maybe_run_external_harness(target, input)?
    };
    let report = HarnessReport {
        target: target_label(target),
        input: input.display().to_string(),
        parser_step,
        core_path_step,
        library_step: library_connect.step,
        library_outcome: library_connect.outcome.as_str(),
        external_step,
    };
    print_harness_report(&report);
    if library_crashed {
        return Err(HarnessError::LibraryCrash(format!(
            "library connect crashed: {library_crash_step}"
        )));
    }
    Ok(())
}

fn print_harness_report(report: &HarnessReport) {
    println!("[harness] done");
    println!("target: {}", report.target);
    println!("input: {}", report.input);
    println!("parser_step: {}", report.parser_step);
    println!("core_path_step: {}", report.core_path_step);
    println!("library_step: {}", report.library_step);
    println!("library_outcome: {}", report.library_outcome);
    println!("external_step: {}", report.external_step);
}

fn render_meta_json(meta: &TargetMeta) -> String {
    format!(
        "{{\n  \"schema_version\": \"{}\",\n  \"target\": \"{}\",\n  \"version\": \"{}\",\n  \"source_url\": \"{}\",\n  \"source_kind\": \"{}\",\n  \"downloaded_file\": \"{}\",\n  \"downloaded_sha256\": \"{}\",\n  \"downloaded_size_bytes\": {}\n}}\n",
        json_escape(meta.schema_version),
        json_escape(&meta.target),
        json_escape(&meta.version),
        json_escape(&meta.source_url),
        json_escape(meta.source_kind),
        json_escape(&meta.downloaded_file),
        json_escape(&meta.downloaded_sha256),
        meta.downloaded_size_bytes
    )
}

/// Split a configured command line the way a shell would.
///
/// A33: `split_whitespace()` cut a quoted program path in half at its space, so a
/// correctly configured harness looked permanently unavailable - and when the
/// mangled prefix still resolved to something, its non-zero exit was filed as a
/// library crash. Handles single quotes (literal), double quotes (`\"` and `\\`
/// escapes) and a bare backslash; an unbalanced quote is an error rather than a
/// silently different command.
fn split_command_line(line: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut chars = line.chars();

    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if started {
                    parts.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            '\'' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => current.push(c),
                        None => return Err("unbalanced single quote".to_string()),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(escaped @ ('"' | '\\')) => current.push(escaped),
                            Some(other) => {
                                current.push('\\');
                                current.push(other);
                            }
                            None => return Err("unbalanced double quote".to_string()),
                        },
                        Some(c) => current.push(c),
                        None => return Err("unbalanced double quote".to_string()),
                    }
                }
            }
            '\\' => match chars.next() {
                Some(escaped) => {
                    current.push(escaped);
                    started = true;
                }
                None => return Err("trailing backslash".to_string()),
            },
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        parts.push(current);
    }
    Ok(parts)
}

fn maybe_run_external_harness(target: &TargetKind, input: &Path) -> Result<String, HarnessError> {
    let env_key = match target {
        TargetKind::Gguf => "TOOL_GGUF_HARNESS_CMD",
        TargetKind::Onnx => "TOOL_ONNX_HARNESS_CMD",
        TargetKind::Safetensors => "TOOL_SAFETENSORS_HARNESS_CMD",
    };

    let Ok(command_line) = std::env::var(env_key) else {
        return Ok(format!("{env_key} not set (external harness skipped)"));
    };
    if command_line.trim().is_empty() {
        return Ok(format!("{env_key} empty (external harness skipped)"));
    }

    let mut parts = split_command_line(&command_line).map_err(|e| {
        HarnessError::Unavailable(format!("{env_key} is not a valid command line: {e}"))
    })?;
    if parts.is_empty() {
        return Ok(format!("{env_key} invalid (external harness skipped)"));
    }

    let cmd = parts.remove(0);
    // A35: the input path is passed as an OsStr. display().to_string() replaces a
    // non-UTF-8 byte with U+FFFD, so the child opened a path that does not exist
    // and reported the seed as not a model file.
    let mut args = parts.into_iter().map(OsString::from).collect::<Vec<_>>();
    args.push(input.as_os_str().to_os_string());

    let output = command_with_core_dump_off(&cmd)
        .args(&args)
        .output()
        .map_err(|e| HarnessError::Unavailable(format!("{env_key} could not be executed: {e}")))?;

    if output.status.success() {
        return Ok(format!("{env_key} executed successfully"));
    }

    // A13-class: the harness binary itself could not be executed (prlimit reports that as
    // a plain 126/127), which is a broken configuration rather than a library crash.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_core_dump_wrapper_exec_failure(output.status.code(), &stderr) {
        return Err(HarnessError::Unavailable(format!(
            "{env_key} could not be executed ({})",
            first_line(&stderr)
        )));
    }

    // Anything else stays a crash: sanitizers report findings through a plain non-zero
    // exit (ASAN exitcode=1), so downgrading here would lose crashes.
    Err(HarnessError::LibraryCrash(format!(
        "{env_key} executed but failed with status {} ({})",
        output.status,
        first_evidence_line(&stderr)
    )))
}

// --- Format-specific prechecks ---

fn gguf_precheck(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() < 24 {
        return Err("GGUF too small: need at least 24 bytes".to_string());
    }
    if &bytes[0..4] != b"GGUF" {
        return Err("GGUF magic mismatch".to_string());
    }

    let version = read_le_u32(&bytes[4..8])?;
    let tensor_count = read_le_u64(&bytes[8..16])?;
    let kv_count = read_le_u64(&bytes[16..24])?;
    Ok(format!(
        "GGUF ok (version={version}, kv_count={kv_count}, tensor_count={tensor_count})"
    ))
}

fn onnx_precheck(bytes: &[u8]) -> Result<String, String> {
    // ONNX는 protobuf 포맷이라 magic bytes가 없고, protobuf 스펙상 field 순서도
    // 보장되지 않는다 (specs.md §13.3: "protobuf 디코드 + 그래프/노드 순회").
    // 엄격한 첫 field 검증은 정상 모델을 거절할 위험이 있어 비운다.
    // 실제 구조 검증은 onnxruntime 라이브러리의 library_connect 단계에 위임.
    if bytes.is_empty() {
        return Err("ONNX input is empty".to_string());
    }
    Ok(format!("ONNX input accepted (size={} bytes)", bytes.len()))
}

fn safetensors_precheck(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() < 8 {
        return Err("safetensors too small: need at least 8 bytes".to_string());
    }

    let header_len = read_le_u64(&bytes[0..8])? as usize;
    if header_len == 0 {
        return Err("safetensors header length is zero".to_string());
    }
    let end = 8usize
        .checked_add(header_len)
        .ok_or_else(|| "safetensors header length overflow".to_string())?;
    if end > bytes.len() {
        return Err("safetensors header out of range".to_string());
    }

    let header = std::str::from_utf8(&bytes[8..end])
        .map_err(|e| format!("safetensors header utf8 error: {e}"))?;
    let trimmed = header.trim();
    if !(trimmed.starts_with('{') && trimmed.ends_with('}')) {
        return Err("safetensors header is not JSON-like object".to_string());
    }
    if !trimmed.contains(':') {
        return Err("safetensors header has no key/value entry".to_string());
    }

    Ok(format!(
        "safetensors header probe ok (header_bytes={header_len})"
    ))
}

fn read_le_u32(bytes: &[u8]) -> Result<u32, String> {
    if bytes.len() != 4 {
        return Err("read_le_u32 requires 4 bytes".to_string());
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(arr))
}

fn read_le_u64(bytes: &[u8]) -> Result<u64, String> {
    if bytes.len() != 8 {
        return Err("read_le_u64 requires 8 bytes".to_string());
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(arr))
}

// --- Library connect probes ---

/// Where `cmd` would actually run from, or None if nothing executable answers to it.
///
/// A34: deciding "this candidate does not exist" from the spawn error meant a file
/// that exists but is not executable ended the search, and a candidate missing on a
/// non-English host was reported as an invocation instead of skipped. Checking
/// first makes both cases the same: not a candidate.
#[cfg(unix)]
fn resolve_executable(cmd: &std::ffi::OsStr) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let is_executable = |path: &Path| {
        path.metadata()
            .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };

    let candidate = Path::new(cmd);
    if cmd.as_bytes().contains(&b'/') {
        return is_executable(candidate).then(|| candidate.to_path_buf());
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .map(|dir| dir.join(candidate))
        .find(|path| is_executable(path))
}

#[cfg(not(unix))]
fn resolve_executable(cmd: &std::ffi::OsStr) -> Option<PathBuf> {
    let candidate = PathBuf::from(cmd);
    candidate.is_file().then_some(candidate)
}

/// Which probe answers `library_connect` for GGUF.
///
/// `native` is the harness built by scripts/build_libfuzzer_gguf_native.sh: it checks
/// what gguf_init_from_file actually returned, so a file the parser rejects comes back
/// as a rejection instead of a crash. `legacy_hash` is llama-gguf-hash, kept selectable
/// because measuring how often it fakes a crash needs it to still be runnable.
#[derive(Debug)]
enum GgufProbeKind {
    Native,
    LegacyHash,
}

fn resolve_gguf_probe_kind(raw: Option<&str>) -> Result<GgufProbeKind, String> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("native") => Ok(GgufProbeKind::Native),
        Some("legacy_hash") => Ok(GgufProbeKind::LegacyHash),
        // Falling back to a default here would hand a typo'd campaign back to the
        // legacy probe and quietly restore its false crashes.
        Some(other) => Err(format!(
            "gguf probe unavailable (unknown {GGUF_PROBE_KIND}={other}; expected native or legacy_hash)"
        )),
    }
}

fn gguf_library_connect(input: &Path) -> LibraryConnectResult {
    let selector = std::env::var(GGUF_PROBE_KIND).ok();
    match resolve_gguf_probe_kind(selector.as_deref()) {
        Ok(GgufProbeKind::Native) => gguf_native_connect(input),
        Ok(GgufProbeKind::LegacyHash) => gguf_legacy_hash_connect(input),
        Err(step) => LibraryConnectResult {
            step,
            outcome: LibraryConnectOutcome::Unavailable,
        },
    }
}

fn gguf_native_connect(input: &Path) -> LibraryConnectResult {
    if let Some(custom) = std::env::var_os(GGUF_NATIVE_BIN).filter(|value| !value.is_empty()) {
        return gguf_native_connect_with_bin(&custom, input);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let bin = gguf_native_bin_from(std::env::current_exe().ok().as_deref(), &cwd);
    gguf_native_connect_with_bin(&bin, input)
}

/// A36 again, for the gguf harness: GGUF_NATIVE_DEFAULT_BIN is a relative path, so a
/// `tool` invoked from anywhere but the project root - a systemd unit, a campaign
/// script, triage re-executing from a run directory - looked beside the wrong cwd and
/// reported the harness missing. Look next to the binary too, but only under a
/// directory that actually looks like this project, so an unrelated tree cannot bind
/// the probe to a harness that is not ours.
fn gguf_native_bin_from(exe: Option<&Path>, cwd: &Path) -> OsString {
    if let Some(found) = native_replay_under(cwd) {
        return found.into_os_string();
    }
    if let Some(exe) = exe {
        for root in exe.ancestors().skip(1).take(3) {
            if !is_project_root(root) {
                continue;
            }
            if let Some(found) = native_replay_under(root) {
                return found.into_os_string();
            }
        }
    }
    OsString::from(GGUF_NATIVE_DEFAULT_BIN)
}

fn native_replay_under(root: &Path) -> Option<PathBuf> {
    let candidate = root.join(GGUF_NATIVE_DEFAULT_BIN);
    candidate.is_file().then_some(candidate)
}

/// The replay harness answers with the same exit-code vocabulary the tool uses
/// (src/main.rs:45-47): 0 parsed, 9 the parser rejected the input, 10 the harness
/// itself could not run. Anything else is the target really dying.
fn gguf_native_connect_with_bin(bin: &std::ffi::OsStr, input: &Path) -> LibraryConnectResult {
    // The binary is a build artifact, so it is absent on a fresh checkout and on the
    // fuzzing host until someone builds it. Name the path that was tried and the
    // script that produces it; under TOOL_REQUIRE_LIBRARY_CONNECT=1 the existing gate
    // turns this into exit 10 rather than a campaign that finds nothing and looks fine.
    if resolve_executable(bin).is_none() {
        return LibraryConnectResult {
            step: format!(
                "gguf native harness unavailable (not executable: {}; build it with \
                 scripts/build_libfuzzer_gguf_native.sh)",
                bin.to_string_lossy()
            ),
            outcome: LibraryConnectOutcome::Unavailable,
        };
    }

    let output = match command_with_core_dump_off(bin).arg(input).output() {
        Ok(output) => output,
        Err(e) => {
            return LibraryConnectResult {
                step: format!(
                    "gguf native harness unavailable ({}: {e})",
                    bin.to_string_lossy()
                ),
                outcome: LibraryConnectOutcome::Unavailable,
            }
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        // A clean parse is normally silent, and first_line() turns silence into the
        // literal words "no output"; only quote the harness when it said something.
        let step = if stdout.trim().is_empty() {
            "gguf parser connected (native: parsed)".to_string()
        } else {
            format!("gguf parser connected (native: parsed; {})", first_line(&stdout))
        };
        return LibraryConnectResult {
            step,
            outcome: LibraryConnectOutcome::SessionOk,
        };
    }

    // A13: prlimit reporting its own exec failure as 126/127 means the harness never
    // ran. Reading that as a crash is exactly the fake-crash bug we removed once.
    if is_core_dump_wrapper_exec_failure(output.status.code(), &stderr) {
        return LibraryConnectResult {
            step: format!("gguf native harness unavailable ({})", first_line(&stderr)),
            outcome: LibraryConnectOutcome::Unavailable,
        };
    }

    match output.status.code() {
        Some(code) if code == i32::from(crate::EXIT_HARNESS_INPUT_REJECTED) => {
            LibraryConnectResult {
                step: format!(
                    "gguf parser rejected the file (native: {})",
                    first_line(&stderr)
                ),
                outcome: LibraryConnectOutcome::Invoked,
            }
        }
        Some(code) if code == i32::from(crate::EXIT_HARNESS_UNAVAILABLE) => LibraryConnectResult {
            step: format!("gguf native harness unavailable ({})", first_line(&stderr)),
            outcome: LibraryConnectOutcome::Unavailable,
        },
        _ => {
            if let Some(result) = crashed_connect_result("gguf parser", "native harness", &output) {
                return result;
            }
            // Off the contract entirely: 0/9/10 and a signal are the whole vocabulary.
            // Anything else means this is not the harness we think it is - a stale
            // binary, a wrapper script, a shell error - and calling it "invoked" would
            // report every crashing input as clean while keeping the strict connect
            // gate quiet. Unavailable is what makes that gate fire.
            LibraryConnectResult {
                step: format!(
                    "gguf native harness unavailable (off-contract exit {}: {})",
                    output
                        .status
                        .code()
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    first_evidence_line(&stderr)
                ),
                outcome: LibraryConnectOutcome::Unavailable,
            }
        }
    }
}

fn gguf_legacy_hash_connect(input: &Path) -> LibraryConnectResult {
    let mut candidates = Vec::new();
    if let Some(custom) = std::env::var_os("TOOL_LLAMA_CLI_BIN") {
        if !custom.is_empty() {
            let custom_path = PathBuf::from(custom);
            if let Some(bin_dir) = custom_path.parent() {
                candidates.push(bin_dir.join("llama-gguf-hash").into_os_string());
            }
        }
    }
    candidates.push(OsString::from("llama-gguf-hash"));
    candidates.push(OsString::from("tools/llama.cpp/build/bin/llama-gguf-hash"));
    candidates.push(OsString::from("./tools/llama.cpp/build/bin/llama-gguf-hash"));

    let mut last_error = String::new();
    for cmd in candidates {
        if resolve_executable(&cmd).is_none() {
            continue;
        }
        let result = command_with_core_dump_off(&cmd)
            .arg("--sha256")
            .arg(input)
            .output();

        match result {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return LibraryConnectResult {
                    step: format!(
                        "llama.cpp parser connected ({}: {})",
                        cmd.to_string_lossy(),
                        first_line(&stdout)
                    ),
                    outcome: LibraryConnectOutcome::SessionOk,
                };
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // A13: prlimit reports its own exec failure (127/126) instead of
                // Err(NotFound); either way this candidate did not run, so try the next.
                if is_core_dump_wrapper_exec_failure(output.status.code(), &stderr) {
                    last_error = first_line(&stderr).to_string();
                    continue;
                }
                if is_gguf_parser_rejection(&output.status, &stderr) {
                    return LibraryConnectResult {
                        step: format!(
                            "llama.cpp parser rejected the file, crash suppressed by {} ({})",
                            GGUF_SUPPRESS_REJECTION_CRASHES,
                            first_line(&stderr)
                        ),
                        outcome: LibraryConnectOutcome::Invoked,
                    };
                }
                if let Some(result) =
                    crashed_connect_result("llama.cpp parser", "invocation", &output)
                {
                    return result;
                }
                return LibraryConnectResult {
                    step: format!(
                        "llama.cpp parser invoked (non-zero exit: {})",
                        first_line(&stderr)
                    ),
                    outcome: LibraryConnectOutcome::Invoked,
                };
            }
            // A candidate that cannot be spawned is not a verdict on the probe:
            // remember why and let the remaining candidates answer.
            Err(e) => {
                last_error = e.to_string();
                continue;
            }
        }
    }

    let step = if last_error.is_empty() {
        "llama.cpp parser unavailable (llama-gguf-hash not installed)".to_string()
    } else {
        format!("llama.cpp parser unavailable (last error: {last_error})")
    };
    LibraryConnectResult {
        step,
        outcome: LibraryConnectOutcome::Unavailable,
    }
}

fn onnx_library_connect(input: &Path) -> LibraryConnectResult {
    let code = r#"
import sys
try:
    import onnxruntime as ort
except Exception as e:
    print(f"missing_module:{e}")
    sys.exit(3)
path = sys.argv[1]
try:
    sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
    print(f"session_ok:inputs={len(sess.get_inputs())},outputs={len(sess.get_outputs())}")
except Exception as e:
    print(f"load_fail:{e}")
    sys.exit(2)
"#;
    let python_bin = detect_python_bin();
    match command_with_core_dump_off(&python_bin)
        .arg("-c")
        .arg(code)
        .arg(input)
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            LibraryConnectResult {
                step: format!("onnxruntime connected ({})", first_line(&stdout)),
                outcome: LibraryConnectOutcome::SessionOk,
            }
        }
        Ok(output) => {
            if let Some(result) = crashed_connect_result("onnxruntime", "loader", &output) {
                return result;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            // A13: the interpreter never ran (prlimit could not exec it), so this is an
            // unavailable probe, not an invoked loader.
            if is_core_dump_wrapper_exec_failure(output.status.code(), &stderr) {
                return LibraryConnectResult {
                    step: format!("onnxruntime unavailable ({})", first_line(&stderr)),
                    outcome: LibraryConnectOutcome::Unavailable,
                };
            }
            if output.status.code() == Some(3) {
                LibraryConnectResult {
                    step: format!("onnxruntime unavailable ({})", first_line(&stdout)),
                    outcome: LibraryConnectOutcome::Unavailable,
                }
            } else {
                LibraryConnectResult {
                    step: format!("onnxruntime loader invoked ({})", first_line(&stdout)),
                    outcome: LibraryConnectOutcome::Invoked,
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LibraryConnectResult {
            step: format!(
                "onnxruntime unavailable ({} not installed)",
                python_bin.to_string_lossy()
            ),
            outcome: LibraryConnectOutcome::Unavailable,
        },
        Err(e) => LibraryConnectResult {
            step: format!("onnxruntime probe error ({e})"),
            outcome: LibraryConnectOutcome::Unavailable,
        },
    }
}

// --- safetensors native probe ---
//
// Mirrors the gguf design decision D1: the native replay (the real Rust safetensors
// crate) is the default probe, and the legacy python safe_open probe stays selectable
// (TOOL_SAFETENSORS_PROBE=python) so the same corpus can measure native-vs-python.
// The native replay speaks the tool's 0/9/10 exit vocabulary, so a file the parser
// rejects (SafeTensorError) comes back Invoked, not Crashed.
pub(crate) const SAFETENSORS_PROBE_KIND: &str = "TOOL_SAFETENSORS_PROBE";
pub(crate) const SAFETENSORS_NATIVE_BIN: &str = "TOOL_SAFETENSORS_NATIVE_BIN";
const SAFETENSORS_NATIVE_DEFAULT_BIN: &str = "harnesses/libfuzzer/safetensors_loader_replay";

#[derive(Debug)]
enum SafetensorsProbeKind {
    Native,
    Python,
}

fn resolve_safetensors_probe_kind(raw: Option<&str>) -> Result<SafetensorsProbeKind, String> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("native") => Ok(SafetensorsProbeKind::Native),
        Some("python") => Ok(SafetensorsProbeKind::Python),
        // A typo must not silently fall back to a different probe and quietly change
        // what the campaign is measuring.
        Some(other) => Err(format!(
            "safetensors probe unavailable (unknown {SAFETENSORS_PROBE_KIND}={other}; expected native or python)"
        )),
    }
}

fn safetensors_library_connect(input: &Path) -> LibraryConnectResult {
    let selector = std::env::var(SAFETENSORS_PROBE_KIND).ok();
    match resolve_safetensors_probe_kind(selector.as_deref()) {
        Ok(SafetensorsProbeKind::Native) => safetensors_native_connect(input),
        Ok(SafetensorsProbeKind::Python) => safetensors_python_connect(input),
        Err(step) => LibraryConnectResult {
            step,
            outcome: LibraryConnectOutcome::Unavailable,
        },
    }
}

fn safetensors_native_connect(input: &Path) -> LibraryConnectResult {
    if let Some(custom) = std::env::var_os(SAFETENSORS_NATIVE_BIN).filter(|value| !value.is_empty())
    {
        return safetensors_native_connect_with_bin(&custom, input);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let bin = safetensors_native_bin_from(std::env::current_exe().ok().as_deref(), &cwd);
    safetensors_native_connect_with_bin(&bin, input)
}

// A36 again, for the safetensors replay: the default path is relative, so a `tool`
// invoked from anywhere but the project root looked beside the wrong cwd. Look next to
// the binary too, but only under a directory that looks like this project.
fn safetensors_native_bin_from(exe: Option<&Path>, cwd: &Path) -> OsString {
    if let Some(found) = safetensors_native_replay_under(cwd) {
        return found.into_os_string();
    }
    if let Some(exe) = exe {
        for root in exe.ancestors().skip(1).take(3) {
            if !is_project_root(root) {
                continue;
            }
            if let Some(found) = safetensors_native_replay_under(root) {
                return found.into_os_string();
            }
        }
    }
    OsString::from(SAFETENSORS_NATIVE_DEFAULT_BIN)
}

fn safetensors_native_replay_under(root: &Path) -> Option<PathBuf> {
    let candidate = root.join(SAFETENSORS_NATIVE_DEFAULT_BIN);
    candidate.is_file().then_some(candidate)
}

/// The replay answers with the tool's exit vocabulary (0 parsed, 9 the parser rejected
/// the input, 10 the harness could not run). A `SafeTensorError` is exit 9, never a
/// crash; only a panic or memory fault aborts by signal. Same shape as
/// gguf_native_connect_with_bin.
fn safetensors_native_connect_with_bin(
    bin: &std::ffi::OsStr,
    input: &Path,
) -> LibraryConnectResult {
    if resolve_executable(bin).is_none() {
        return LibraryConnectResult {
            step: format!(
                "safetensors native harness unavailable (not executable: {}; build it with \
                 scripts/build_libfuzzer_safetensors_native.sh)",
                bin.to_string_lossy()
            ),
            outcome: LibraryConnectOutcome::Unavailable,
        };
    }

    let output = match command_with_core_dump_off(bin).arg(input).output() {
        Ok(output) => output,
        Err(e) => {
            return LibraryConnectResult {
                step: format!(
                    "safetensors native harness unavailable ({}: {e})",
                    bin.to_string_lossy()
                ),
                outcome: LibraryConnectOutcome::Unavailable,
            }
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        let step = if stdout.trim().is_empty() {
            "safetensors parser connected (native: parsed)".to_string()
        } else {
            format!(
                "safetensors parser connected (native: parsed; {})",
                first_line(&stdout)
            )
        };
        return LibraryConnectResult {
            step,
            outcome: LibraryConnectOutcome::SessionOk,
        };
    }

    if is_core_dump_wrapper_exec_failure(output.status.code(), &stderr) {
        return LibraryConnectResult {
            step: format!(
                "safetensors native harness unavailable ({})",
                first_line(&stderr)
            ),
            outcome: LibraryConnectOutcome::Unavailable,
        };
    }

    match output.status.code() {
        Some(code) if code == i32::from(crate::EXIT_HARNESS_INPUT_REJECTED) => {
            LibraryConnectResult {
                step: format!(
                    "safetensors parser rejected the file (native: {})",
                    first_line(&stderr)
                ),
                outcome: LibraryConnectOutcome::Invoked,
            }
        }
        Some(code) if code == i32::from(crate::EXIT_HARNESS_UNAVAILABLE) => LibraryConnectResult {
            step: format!(
                "safetensors native harness unavailable ({})",
                first_line(&stderr)
            ),
            outcome: LibraryConnectOutcome::Unavailable,
        },
        _ => {
            if let Some(result) =
                crashed_connect_result("safetensors parser", "native harness", &output)
            {
                return result;
            }
            // Off the contract entirely (0/9/10 and a signal are the whole vocabulary):
            // a stale or wrong binary. Calling it invoked would report crashes as clean;
            // Unavailable is what makes the strict connect gate fire.
            LibraryConnectResult {
                step: format!(
                    "safetensors native harness unavailable (off-contract exit {}: {})",
                    output
                        .status
                        .code()
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    first_evidence_line(&stderr)
                ),
                outcome: LibraryConnectOutcome::Unavailable,
            }
        }
    }
}

fn safetensors_python_connect(input: &Path) -> LibraryConnectResult {
    let code = r#"
import sys
try:
    from safetensors import safe_open
except Exception as e:
    print(f"missing_module:{e}")
    sys.exit(3)
path = sys.argv[1]
try:
    with safe_open(path, framework="pt", device="cpu") as f:
        keys = list(f.keys())
        print(f"safe_open_ok:tensors={len(keys)}")
except Exception as e:
    print(f"load_fail:{e}")
    sys.exit(2)
"#;
    let python_bin = detect_python_bin();
    match command_with_core_dump_off(&python_bin)
        .arg("-c")
        .arg(code)
        .arg(input)
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            LibraryConnectResult {
                step: format!("safetensors connected ({})", first_line(&stdout)),
                outcome: LibraryConnectOutcome::SessionOk,
            }
        }
        Ok(output) => {
            if let Some(result) = crashed_connect_result("safetensors", "loader", &output) {
                return result;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            // A13: see onnx_library_connect - a wrapper exec failure means no probe ran.
            if is_core_dump_wrapper_exec_failure(output.status.code(), &stderr) {
                return LibraryConnectResult {
                    step: format!("safetensors unavailable ({})", first_line(&stderr)),
                    outcome: LibraryConnectOutcome::Unavailable,
                };
            }
            if output.status.code() == Some(3) {
                LibraryConnectResult {
                    step: format!("safetensors unavailable ({})", first_line(&stdout)),
                    outcome: LibraryConnectOutcome::Unavailable,
                }
            } else {
                LibraryConnectResult {
                    step: format!("safetensors loader invoked ({})", first_line(&stdout)),
                    outcome: LibraryConnectOutcome::Invoked,
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LibraryConnectResult {
            step: format!(
                "safetensors unavailable ({} not installed)",
                python_bin.to_string_lossy()
            ),
            outcome: LibraryConnectOutcome::Unavailable,
        },
        Err(e) => LibraryConnectResult {
            step: format!("safetensors probe error ({e})"),
            outcome: LibraryConnectOutcome::Unavailable,
        },
    }
}

fn detect_python_bin() -> OsString {
    if let Some(custom) = std::env::var_os("TOOL_PYTHON_BIN") {
        if !custom.is_empty() {
            return custom;
        }
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    detect_python_bin_from(std::env::current_exe().ok().as_deref(), &cwd)
}

/// A36: the probe only ever looked for `.venv/bin/python3` relative to the process
/// working directory, so a `tool` invoked from anywhere else - a systemd unit, a
/// campaign script, a triage re-exec from a run directory - silently fell back to
/// the system python3, which has no onnxruntime. Under the strict connect gate
/// that turns every input into a harness-unavailable exit.
fn detect_python_bin_from(exe: Option<&Path>, cwd: &Path) -> OsString {
    if let Some(python) = venv_python_under(cwd) {
        return python.into_os_string();
    }
    if let Some(exe) = exe {
        // Only a directory that actually looks like this project: adopting any
        // .venv above the binary could bind the probe to an unrelated environment.
        for root in exe.ancestors().skip(1).take(3) {
            if !is_project_root(root) {
                continue;
            }
            if let Some(python) = venv_python_under(root) {
                return python.into_os_string();
            }
        }
    }
    OsString::from("python3")
}

fn venv_python_under(root: &Path) -> Option<PathBuf> {
    let candidate = root.join(".venv").join("bin").join("python3");
    candidate.exists().then_some(candidate)
}

fn is_project_root(root: &Path) -> bool {
    root.join("Cargo.toml").is_file() || root.join("seeds").is_dir()
}

/// Env switch for the carve-out below. Unset means "report every crash".
pub(crate) const GGUF_SUPPRESS_REJECTION_CRASHES: &str = "TOOL_GGUF_SUPPRESS_REJECTION_CRASHES";
pub(crate) const GGUF_PROBE_KIND: &str = "TOOL_GGUF_PROBE";
pub(crate) const GGUF_NATIVE_BIN: &str = "TOOL_GGUF_NATIVE_BIN";
const GGUF_NATIVE_DEFAULT_BIN: &str = "harnesses/libfuzzer/gguf_loader_replay";

/// Whether the probe died because llama.cpp's parser cleanly refused the file.
///
/// The probe binary is llama.cpp's gguf-hash example, which does not NULL-check
/// gguf_init_from_file (tools/llama.cpp/examples/gguf-hash/gguf-hash.cpp:329). The
/// parser returns NULL on every rejection path and the example then dereferences
/// it, so a structurally broken file - which is most of what the mutator produces -
/// segfaults and is reported as a library crash. The GGUF crash oracle is a
/// false-positive factory, and a GGUF campaign's crashes need re-reading with that
/// in mind.
///
/// **This is OFF unless the operator sets the env switch, and that is deliberate.**
/// llama.cpp logs the rejection and only then frees attacker-controlled structures,
/// so a fault in that cleanup is exactly the memory-safety bug this project hunts -
/// and it produces the same observable shape as the benign null deref: SIGSEGV,
/// marker present, nothing else. The markers below can only separate them on a
/// sanitizer build, and the probe binary this repo builds is not one, so on the
/// real host the predicate reduces to "SIGSEGV after a rejection message". Suppressing
/// by default would trade a loud false positive for a silent false negative, and a
/// lost crash is the worse outcome.
///
/// The durable fix is a native GGUF harness that checks the return value itself and
/// crashes only when the parser really faults; it is the first Phase 2 item.
fn is_gguf_parser_rejection(status: &ExitStatus, stderr: &str) -> bool {
    const REJECTION_MARKER: &str = "gguf_init_from_file_impl: ";
    // Anything that says "a memory-safety tool noticed something" outranks the marker.
    const CRASH_MARKERS: &[&str] = &[
        "AddressSanitizer",
        "UndefinedBehaviorSanitizer",
        "LeakSanitizer",
        "MemorySanitizer",
        "ThreadSanitizer",
        "runtime error:",
        "SUMMARY:",
        "GGML_ASSERT",
        "GGML_ABORT",
    ];

    if std::env::var_os(GGUF_SUPPRESS_REJECTION_CRASHES).is_none() {
        return false;
    }
    if exit_signal(status) != Some(SIGSEGV) {
        return false;
    }
    if !stderr.contains(REJECTION_MARKER) {
        return false;
    }
    !CRASH_MARKERS.iter().any(|marker| stderr.contains(marker))
}

const SIGSEGV: i32 = 11;

/// The first line of a sanitizer report is a rule of '=' characters, so first_line()
/// reduces the whole report to punctuation and the evidence that reaches triage says
/// nothing at all. Skip blank lines and rules made only of '=' or '-', and fall back
/// to first_line() when the text holds nothing else.
fn first_evidence_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.chars().all(|c| c == '=' || c == '-'))
        .map(str::to_string)
        .unwrap_or_else(|| first_line(text))
}

fn crashed_connect_result(
    component: &str,
    action: &str,
    output: &Output,
) -> Option<LibraryConnectResult> {
    let detail = crash_status_detail(&output.status)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Some(LibraryConnectResult {
        step: format!(
            "{component} {action} crashed ({detail}; stdout: {}; stderr: {})",
            first_evidence_line(&stdout),
            first_evidence_line(&stderr)
        ),
        outcome: LibraryConnectOutcome::Crashed,
    })
}

fn crash_status_detail(status: &ExitStatus) -> Option<String> {
    if let Some(signal_number) = exit_signal(status) {
        return Some(format!(
            "{} (signal: {signal_number})",
            signal_name(signal_number)
        ));
    }

    let exit_code = status.code()?;
    exit_code_signal_name(exit_code).map(|signal| format!("{signal} (exit_code: {exit_code})"))
}

fn exit_code_signal_name(exit_code: i32) -> Option<&'static str> {
    match exit_code {
        132 => Some("SIGILL"),
        134 => Some("SIGABRT"),
        135 => Some("SIGBUS"),
        136 => Some("SIGFPE"),
        137 => Some("SIGKILL"),
        139 => Some("SIGSEGV"),
        143 => Some("SIGTERM"),
        _ => None,
    }
}

fn signal_name(signal_number: i32) -> &'static str {
    match signal_number {
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        15 => "SIGTERM",
        _ => "unknown",
    }
}

#[cfg(unix)]
fn exit_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &ExitStatus) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    fn gguf_probe_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tool-{label}-{}-{}",
            std::process::id(),
            crate::common::now_unix_millis()
        ))
    }

    // Install a stub llama-gguf-hash and run the gguf probe against a 24-byte input
    // that passes gguf_precheck. `body` is the stub's shell body.
    #[cfg(unix)]
    fn gguf_probe_with_stub(label: &str, body: &str) -> super::LibraryConnectResult {
        use std::os::unix::fs::PermissionsExt;

        let dir = gguf_probe_dir(label);
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).expect("create bin dir");
        let stub = bin.join("llama-gguf-hash");
        std::fs::write(&stub, format!("#!/bin/sh\n{body}\n")).expect("write stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let mut gguf = Vec::new();
        gguf.extend_from_slice(b"GGUF");
        gguf.extend_from_slice(&3u32.to_le_bytes());
        gguf.extend_from_slice(&1u64.to_le_bytes());
        gguf.extend_from_slice(&0u64.to_le_bytes());
        let input = dir.join("sample.gguf");
        std::fs::write(&input, &gguf).expect("write input");

        // The default probe is the native harness now, so a test about the old
        // llama-gguf-hash behaviour has to ask for it by name.
        std::env::set_var(super::GGUF_PROBE_KIND, "legacy_hash");
        std::env::set_var("TOOL_LLAMA_CLI_BIN", bin.join("llama-cli"));
        let result = super::gguf_library_connect(&input);
        std::env::remove_var("TOOL_LLAMA_CLI_BIN");
        std::env::remove_var(super::GGUF_PROBE_KIND);
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    // The native harness reports its verdict as an exit code, so its stub is a
    // different file under a different env var. TOOL_GGUF_PROBE is cleared rather
    // than set: these tests are also what pins `native` as the default.
    #[cfg(unix)]
    fn gguf_probe_with_native_stub(label: &str, body: &str) -> super::LibraryConnectResult {
        use std::os::unix::fs::PermissionsExt;

        let dir = gguf_probe_dir(label);
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).expect("create bin dir");
        let stub = bin.join("gguf_loader_replay");
        std::fs::write(&stub, format!("#!/bin/sh\n{body}\n")).expect("write stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let mut gguf = Vec::new();
        gguf.extend_from_slice(b"GGUF");
        gguf.extend_from_slice(&3u32.to_le_bytes());
        gguf.extend_from_slice(&1u64.to_le_bytes());
        gguf.extend_from_slice(&0u64.to_le_bytes());
        let input = dir.join("sample.gguf");
        std::fs::write(&input, &gguf).expect("write input");

        std::env::remove_var(super::GGUF_PROBE_KIND);
        std::env::set_var(super::GGUF_NATIVE_BIN, &stub);
        let result = super::gguf_library_connect(&input);
        std::env::remove_var(super::GGUF_NATIVE_BIN);
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    // --- safetensors native probe (mirrors the gguf native-connect tests) ---
    // The replay reports its verdict as an exit code, so the stub is a fixed-exit
    // shell script under TOOL_SAFETENSORS_NATIVE_BIN. TOOL_SAFETENSORS_PROBE is
    // cleared, so these tests also pin `native` as the default.
    #[cfg(unix)]
    fn safetensors_probe_with_native_stub(label: &str, body: &str) -> super::LibraryConnectResult {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "st-probe-{label}-{}",
            crate::common::now_unix_millis()
        ));
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).expect("create bin dir");
        let stub = bin.join("safetensors_loader_replay");
        std::fs::write(&stub, format!("#!/bin/sh\n{body}\n")).expect("write stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let header = br#"{"x":1}"#;
        let mut st = (header.len() as u64).to_le_bytes().to_vec();
        st.extend_from_slice(header);
        let input = dir.join("sample.safetensors");
        std::fs::write(&input, &st).expect("write input");

        std::env::remove_var(super::SAFETENSORS_PROBE_KIND);
        std::env::set_var(super::SAFETENSORS_NATIVE_BIN, &stub);
        let result = super::safetensors_library_connect(&input);
        std::env::remove_var(super::SAFETENSORS_NATIVE_BIN);
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    // Exit 9 is why the native probe exists: deserialize returning Err is a clean
    // rejection, not a crash. 0 -> SessionOk, 10 -> Unavailable, off-contract (3) ->
    // Unavailable so the strict-connect gate fires rather than trusting a wrong binary.
    #[cfg(unix)]
    #[test]
    fn safetensors_native_maps_exit_codes() {
        let _guard = env_lock();
        assert!(matches!(
            safetensors_probe_with_native_stub("ok", "exit 0").outcome,
            super::LibraryConnectOutcome::SessionOk
        ));
        let rej = safetensors_probe_with_native_stub("rej", "exit 9");
        assert!(
            matches!(rej.outcome, super::LibraryConnectOutcome::Invoked),
            "step: {}",
            rej.step
        );
        assert!(matches!(
            safetensors_probe_with_native_stub("un", "exit 10").outcome,
            super::LibraryConnectOutcome::Unavailable
        ));
        assert!(matches!(
            safetensors_probe_with_native_stub("off", "exit 3").outcome,
            super::LibraryConnectOutcome::Unavailable
        ));
    }

    // A missing native binary is Unavailable, not a silent clean pass: under the strict
    // connect gate that becomes exit 10 instead of a campaign that finds nothing.
    #[cfg(unix)]
    #[test]
    fn safetensors_native_missing_binary_is_unavailable() {
        let _guard = env_lock();
        let dir = std::env::temp_dir().join(format!(
            "st-missing-{}",
            crate::common::now_unix_millis()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let input = dir.join("in.safetensors");
        std::fs::write(&input, b"whatever").expect("write");
        std::env::remove_var(super::SAFETENSORS_PROBE_KIND);
        std::env::set_var(super::SAFETENSORS_NATIVE_BIN, dir.join("nope"));
        let result = super::safetensors_library_connect(&input);
        std::env::remove_var(super::SAFETENSORS_NATIVE_BIN);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(
            result.outcome,
            super::LibraryConnectOutcome::Unavailable
        ));
    }

    // The native crash oracle: a signal-killed native replay must be Crashed (which
    // run_harness turns into the library-crash exit code), never Invoked or clean.
    #[cfg(unix)]
    #[test]
    fn a_signal_killed_native_safetensors_probe_is_crashed() {
        let _guard = env_lock();
        let r = safetensors_probe_with_native_stub("segv", "kill -SEGV \"$$\"");
        assert!(
            matches!(r.outcome, super::LibraryConnectOutcome::Crashed),
            "step: {}",
            r.step
        );
    }

    #[test]
    fn safetensors_probe_kind_defaults_native_and_switches() {
        assert!(matches!(
            super::resolve_safetensors_probe_kind(None),
            Ok(super::SafetensorsProbeKind::Native)
        ));
        assert!(matches!(
            super::resolve_safetensors_probe_kind(Some("native")),
            Ok(super::SafetensorsProbeKind::Native)
        ));
        assert!(matches!(
            super::resolve_safetensors_probe_kind(Some("python")),
            Ok(super::SafetensorsProbeKind::Python)
        ));
        assert!(super::resolve_safetensors_probe_kind(Some("bogus")).is_err());
    }

    // Exit 9 is the whole reason this harness exists: the parser turned the file
    // down on purpose. The legacy probe turned the same answer into a SIGSEGV.
    #[cfg(unix)]
    #[test]
    fn the_native_gguf_probe_reports_a_rejected_file_as_invoked_not_crashed() {
        let _guard = env_lock();
        let result = gguf_probe_with_native_stub("gguf-native-reject", "exit 9");
        assert!(
            matches!(result.outcome, super::LibraryConnectOutcome::Invoked),
            "outcome was {} / {}",
            result.outcome.as_str(),
            result.step
        );
        assert!(result.step.contains("rejected"), "step was: {}", result.step);
    }

    #[cfg(unix)]
    #[test]
    fn a_clean_native_gguf_parse_does_not_report_empty_output_as_a_detail() {
        let _guard = env_lock();
        let result = gguf_probe_with_native_stub("gguf-native-ok", "exit 0");
        assert!(
            matches!(result.outcome, super::LibraryConnectOutcome::SessionOk),
            "outcome was {} / {}",
            result.outcome.as_str(),
            result.step
        );
        assert_eq!(result.step, "gguf parser connected (native: parsed)");
    }

    #[cfg(unix)]
    #[test]
    fn the_native_gguf_probe_reports_a_signal_death_as_a_crash() {
        let _guard = env_lock();
        let result = gguf_probe_with_native_stub("gguf-native-abort", "kill -ABRT \"$$\"");
        assert!(
            matches!(result.outcome, super::LibraryConnectOutcome::Crashed),
            "outcome was {} / {}",
            result.outcome.as_str(),
            result.step
        );
    }

    // Exit 10 means the harness could not run at all. That says nothing about the
    // input, so it must not be counted as a finding or as a clean parse.
    #[cfg(unix)]
    #[test]
    fn the_native_gguf_probe_reports_its_own_unavailability_as_unavailable() {
        let _guard = env_lock();
        let result = gguf_probe_with_native_stub("gguf-native-unavail", "exit 10");
        assert!(
            matches!(result.outcome, super::LibraryConnectOutcome::Unavailable),
            "outcome was {} / {}",
            result.outcome.as_str(),
            result.step
        );
    }

    // A typo in the selector must not quietly hand the campaign back to the old
    // probe, which would put the false crashes back without anyone noticing.
    #[test]
    fn an_unknown_gguf_probe_selector_is_an_error_not_a_silent_default() {
        let err = super::resolve_gguf_probe_kind(Some("nativ")).unwrap_err();
        assert!(err.contains(super::GGUF_PROBE_KIND), "err was: {err}");
    }

    // An exit code outside the contract means the harness is not the program we
    // think it is - a stale binary, a wrapper script, a shell error. Reading that as
    // "invoked, nothing wrong" makes every crashing input look clean AND keeps the
    // strict connect gate from firing, which is the quiet-zero-findings failure.
    #[cfg(unix)]
    #[test]
    fn an_off_contract_exit_from_the_native_gguf_harness_is_unavailable_not_invoked() {
        let _guard = env_lock();
        let result = gguf_probe_with_native_stub("gguf-native-offcontract", "exit 3");
        assert!(
            matches!(result.outcome, super::LibraryConnectOutcome::Unavailable),
            "outcome was {} / {}",
            result.outcome.as_str(),
            result.step
        );
        assert!(result.step.contains('3'), "step must name the exit: {}", result.step);
    }

    // A36 again, for the gguf harness: the default path is relative, so `tool` run
    // from a systemd unit, a campaign script, or a run directory looked for the
    // harness beside the wrong cwd and called it missing.
    #[cfg(unix)]
    #[test]
    fn the_native_gguf_harness_is_found_from_the_executable_not_only_the_cwd() {
        use std::os::unix::fs::PermissionsExt;

        let root = gguf_probe_dir("gguf-native-cwd");
        let project = root.join("proj");
        let harness_dir = project.join("harnesses").join("libfuzzer");
        let exe_dir = project.join("target").join("debug");
        std::fs::create_dir_all(&harness_dir).expect("create harness dir");
        std::fs::create_dir_all(&exe_dir).expect("create exe dir");
        std::fs::write(project.join("Cargo.toml"), "[package]").expect("write marker");
        let replay = harness_dir.join("gguf_loader_replay");
        std::fs::write(&replay, "#!/bin/sh\nexit 0\n").expect("write replay");
        std::fs::set_permissions(&replay, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let exe = exe_dir.join("tool");
        std::fs::write(&exe, "").expect("write exe");

        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("create elsewhere");

        assert_eq!(
            super::gguf_native_bin_from(Some(&exe), &elsewhere),
            replay.into_os_string(),
            "the harness next to the binary was not found"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // The harness binary is gitignored, so a fresh checkout and the fuzzing host
    // both start without it. If that read as "nothing to report", a campaign would
    // run to completion with zero findings and look perfectly healthy.
    #[cfg(unix)]
    #[test]
    fn a_missing_native_gguf_harness_is_reported_not_silently_skipped() {
        let input = gguf_probe_dir("gguf-native-missing").join("sample.gguf");
        let result = super::gguf_native_connect_with_bin(
            std::ffi::OsStr::new("/nonexistent/harnesses/libfuzzer/gguf_loader_replay"),
            &input,
        );
        assert!(
            matches!(result.outcome, super::LibraryConnectOutcome::Unavailable),
            "outcome was {} / {}",
            result.outcome.as_str(),
            result.step
        );
        assert!(
            result.step.contains("gguf_loader_replay"),
            "step must name the path it looked at: {}",
            result.step
        );
        assert!(
            result.step.contains("build_libfuzzer_gguf_native.sh"),
            "step must say how to fix it: {}",
            result.step
        );
    }

    // The probe binary is llama.cpp's gguf-hash example, which does not NULL-check
    // gguf_init_from_file (gguf-hash.cpp:329). Every file the parser rejects makes
    // the example null-deref, so a structurally broken mutant - which is most of
    // what the mutator produces - was reported as a library crash. The crash oracle
    // for GGUF was a false-positive factory.
    // The suppression is opt-in: on the real host the markers below cannot separate
    // llama.cpp's benign null deref from a fault in its own cleanup, so the default
    // must keep reporting the crash. This pins the default.
    #[cfg(unix)]
    #[test]
    fn a_rejection_marker_alone_is_still_a_library_crash_by_default() {
        use super::LibraryConnectOutcome;

        let _guard = env_lock();
        std::env::remove_var(super::GGUF_SUPPRESS_REJECTION_CRASHES);
        let result = gguf_probe_with_stub(
            "gguf-reject-default",
            "echo 'gguf_init_from_file_impl: failed to read tensor info' >&2\nkill -SEGV \"$$\"",
        );

        assert!(
            matches!(result.outcome, LibraryConnectOutcome::Crashed),
            "the default must not suppress a crash: {} / {}",
            result.outcome.as_str(),
            result.step
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_gguf_file_the_parser_cleanly_rejects_is_not_a_library_crash() {
        use super::LibraryConnectOutcome;

        let _guard = env_lock();
        std::env::set_var(super::GGUF_SUPPRESS_REJECTION_CRASHES, "1");
        let result = gguf_probe_with_stub(
            "gguf-reject",
            "echo 'gguf_init_from_file_impl: failed to read tensor info' >&2\nkill -SEGV \"$$\"",
        );

        assert!(
            matches!(result.outcome, LibraryConnectOutcome::Invoked),
            "a clean parser rejection was reported as {}: {}",
            result.outcome.as_str(),
            result.step
        );
        assert!(
            result.step.contains("rejected"),
            "step should say the parser rejected the file: {}",
            result.step
        );
        std::env::remove_var(super::GGUF_SUPPRESS_REJECTION_CRASHES);
    }

    // The carve-out must not widen. A signal death with no rejection marker is the
    // finding this project exists to catch.
    #[cfg(unix)]
    #[test]
    fn a_gguf_signal_death_without_a_rejection_marker_is_still_a_library_crash() {
        use super::LibraryConnectOutcome;

        let _guard = env_lock();
        let result = gguf_probe_with_stub("gguf-crash", "kill -SEGV \"$$\"");

        assert!(
            matches!(result.outcome, LibraryConnectOutcome::Crashed),
            "a real crash was downgraded to {}: {}",
            result.outcome.as_str(),
            result.step
        );
    }

    // llama.cpp logs the rejection and then frees attacker-controlled structures.
    // A fault in that cleanup is a real memory-safety bug, and a sanitizer report
    // or an abort says so even though the rejection marker is present.
    #[cfg(unix)]
    #[test]
    fn a_sanitizer_report_after_a_rejection_marker_is_still_a_library_crash() {
        use super::LibraryConnectOutcome;

        let _guard = env_lock();
        std::env::set_var(super::GGUF_SUPPRESS_REJECTION_CRASHES, "1");
        let result = gguf_probe_with_stub(
            "gguf-asan",
            "echo 'gguf_init_from_file_impl: failed to read tensor info' >&2\n\
             echo '==1==ERROR: AddressSanitizer: heap-use-after-free' >&2\nkill -SEGV \"$$\"",
        );

        assert!(
            matches!(result.outcome, LibraryConnectOutcome::Crashed),
            "a sanitizer report was swallowed as {}: {}",
            result.outcome.as_str(),
            result.step
        );
        std::env::remove_var(super::GGUF_SUPPRESS_REJECTION_CRASHES);
    }

    #[cfg(unix)]
    #[test]
    fn a_gguf_abort_after_a_rejection_marker_is_still_a_library_crash() {
        use super::LibraryConnectOutcome;

        let _guard = env_lock();
        std::env::set_var(super::GGUF_SUPPRESS_REJECTION_CRASHES, "1");
        let result = gguf_probe_with_stub(
            "gguf-abort",
            "echo 'gguf_init_from_file_impl: failed to read tensor info' >&2\nkill -ABRT \"$$\"",
        );

        assert!(
            matches!(result.outcome, LibraryConnectOutcome::Crashed),
            "an abort was swallowed as {}: {}",
            result.outcome.as_str(),
            result.step
        );
        std::env::remove_var(super::GGUF_SUPPRESS_REJECTION_CRASHES);
    }

    // G6: the crash-propagation fix was only ever proven on ONNX. Everything below
    // run_harness is format-independent, so what actually needs proving per format
    // is that a signal-killed probe reaches HarnessError::LibraryCrash.
    #[cfg(unix)]
    #[test]
    fn a_gguf_signal_killed_probe_reaches_the_library_crash_exit_code() {
        use super::{run_harness, TargetKind};
        use std::os::unix::fs::PermissionsExt;

        let _guard = env_lock();
        let dir = gguf_probe_dir("g6-gguf");
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).expect("create bin dir");
        let stub = bin.join("llama-gguf-hash");
        std::fs::write(&stub, "#!/bin/sh\nkill -SEGV \"$$\"\n").expect("write stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let mut gguf = Vec::new();
        gguf.extend_from_slice(b"GGUF");
        gguf.extend_from_slice(&3u32.to_le_bytes());
        gguf.extend_from_slice(&1u64.to_le_bytes());
        gguf.extend_from_slice(&0u64.to_le_bytes());
        let input = dir.join("sample.gguf");
        std::fs::write(&input, &gguf).expect("write input");

        std::env::set_var(super::GGUF_PROBE_KIND, "legacy_hash");
        std::env::set_var("TOOL_LLAMA_CLI_BIN", bin.join("llama-cli"));
        std::env::remove_var("TOOL_GGUF_HARNESS_CMD");
        let result = run_harness(&TargetKind::Gguf, &input);
        std::env::remove_var("TOOL_LLAMA_CLI_BIN");
        std::env::remove_var(super::GGUF_PROBE_KIND);
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err("a signal-killed gguf probe must not be Ok");
        assert!(
            matches!(err, super::HarnessError::LibraryCrash(_)),
            "err was: {err:?}"
        );
        assert_eq!(err.exit_code(), crate::EXIT_HARNESS_LIBRARY_CRASH);
    }

    #[cfg(unix)]
    #[test]
    fn a_safetensors_signal_killed_probe_reaches_the_library_crash_exit_code() {
        use super::{run_harness, TargetKind};
        use std::os::unix::fs::PermissionsExt;

        let _guard = env_lock();
        let dir = gguf_probe_dir("g6-safetensors");
        std::fs::create_dir_all(&dir).expect("create dir");
        let stub = dir.join("segv_python.sh");
        std::fs::write(&stub, "#!/bin/sh\nkill -SEGV \"$$\"\n").expect("write stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let header = br#"{"a":1}"#;
        let mut body = (header.len() as u64).to_le_bytes().to_vec();
        body.extend_from_slice(header);
        let input = dir.join("sample.safetensors");
        std::fs::write(&input, &body).expect("write input");

        // The python safe_open probe is now behind a switch (native is the default),
        // so this test about the python probe crashing has to ask for it by name.
        std::env::set_var("TOOL_SAFETENSORS_PROBE", "python");
        std::env::set_var("TOOL_PYTHON_BIN", &stub);
        std::env::remove_var("TOOL_SAFETENSORS_HARNESS_CMD");
        let result = run_harness(&TargetKind::Safetensors, &input);
        std::env::remove_var("TOOL_PYTHON_BIN");
        std::env::remove_var("TOOL_SAFETENSORS_PROBE");
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err("a signal-killed safetensors probe must not be Ok");
        assert!(
            matches!(err, super::HarnessError::LibraryCrash(_)),
            "err was: {err:?}"
        );
        assert_eq!(err.exit_code(), crate::EXIT_HARNESS_LIBRARY_CRASH);
    }

    // A36: the probe looked for .venv/bin/python3 relative to the process working
    // directory, so running the tool from anywhere but the project root silently
    // fell back to the system python3 - which has no onnxruntime. With the strict
    // connect gate on, that turns every input into a harness-unavailable exit.
    #[test]
    fn the_venv_interpreter_is_found_from_the_executable_not_only_the_cwd() {
        use super::detect_python_bin_from;

        let root = std::env::temp_dir().join(format!(
            "tool-a36-{}-{}",
            std::process::id(),
            crate::common::now_unix_millis()
        ));
        let project = root.join("proj");
        let venv = project.join(".venv").join("bin");
        let exe_dir = project.join("target").join("release");
        std::fs::create_dir_all(&venv).expect("create venv");
        std::fs::create_dir_all(&exe_dir).expect("create exe dir");
        std::fs::write(project.join("Cargo.toml"), "[package]").expect("write marker");
        std::fs::write(venv.join("python3"), "#!/bin/sh\n").expect("write python");
        let exe = exe_dir.join("tool");
        std::fs::write(&exe, "").expect("write exe");

        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("create elsewhere");

        assert_eq!(
            detect_python_bin_from(Some(&exe), &elsewhere),
            venv.join("python3").into_os_string(),
            "the interpreter next to the binary was not found"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unrelated_venv_in_a_parent_directory_is_not_used() {
        use super::detect_python_bin_from;

        let root = std::env::temp_dir().join(format!(
            "tool-a36-unrelated-{}-{}",
            std::process::id(),
            crate::common::now_unix_millis()
        ));
        // A .venv with no project marker beside it: someone else's environment.
        let venv = root.join("home").join(".venv").join("bin");
        let exe_dir = root.join("home").join("bin");
        std::fs::create_dir_all(&venv).expect("create venv");
        std::fs::create_dir_all(&exe_dir).expect("create exe dir");
        std::fs::write(venv.join("python3"), "#!/bin/sh\n").expect("write python");
        let exe = exe_dir.join("tool");
        std::fs::write(&exe, "").expect("write exe");

        assert_eq!(
            detect_python_bin_from(Some(&exe), &root),
            std::ffi::OsString::from("python3"),
            "an unrelated virtualenv must not be adopted"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_venv_in_the_working_directory_still_wins() {
        use super::detect_python_bin_from;

        let root = std::env::temp_dir().join(format!(
            "tool-a36-cwd-{}-{}",
            std::process::id(),
            crate::common::now_unix_millis()
        ));
        let venv = root.join(".venv").join("bin");
        std::fs::create_dir_all(&venv).expect("create venv");
        std::fs::write(venv.join("python3"), "#!/bin/sh\n").expect("write python");

        assert_eq!(
            detect_python_bin_from(None, &root),
            venv.join("python3").into_os_string()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // A34: a candidate that exists but cannot be executed returned Unavailable for
    // the whole probe, so a stale TOOL_LLAMA_CLI_BIN hid a perfectly good
    // llama-gguf-hash further down the list. The strict gate then fails every GGUF
    // input on a host where the parser is in fact installed.
    #[cfg(unix)]
    #[test]
    fn a_gguf_candidate_that_cannot_be_executed_falls_through_to_the_next() {
        use super::{gguf_library_connect, LibraryConnectOutcome};
        use std::os::unix::fs::PermissionsExt;

        const CHILD_INPUT: &str = "TOOL_TEST_GGUF_FALLBACK_INPUT";
        if let Some(input) = std::env::var_os(CHILD_INPUT) {
            let result = gguf_library_connect(std::path::Path::new(&input));
            assert!(
                matches!(result.outcome, LibraryConnectOutcome::SessionOk),
                "the working candidate was never reached: {} / {}",
                result.step,
                result.outcome.as_str()
            );
            assert!(result.step.contains("sha256: dead"), "{}", result.step);
            return;
        }

        let _guard = env_lock();
        let root = std::env::temp_dir().join(format!(
            "tool-a34-{}-{}",
            std::process::id(),
            crate::common::now_unix_millis()
        ));
        let dir_a = root.join("a");
        let dir_b = root.join("b");
        std::fs::create_dir_all(&dir_a).expect("create dir a");
        std::fs::create_dir_all(&dir_b).expect("create dir b");

        // Present but not executable: the candidate the stale override points at.
        std::fs::write(dir_a.join("llama-gguf-hash"), "#!/bin/sh\nexit 0\n").expect("write a");
        std::fs::set_permissions(
            dir_a.join("llama-gguf-hash"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod a");

        let good = dir_b.join("llama-gguf-hash");
        std::fs::write(
            &good,
            "#!/bin/sh\nroot=${2%/*}\n: > \"$root/probe-ready\"\n\
             tries=0\nwhile [ ! -f \"$root/hash-done\" ]; do\n\
             tries=$((tries + 1))\n[ \"$tries\" -lt 500 ] || exit 1\n\
             /bin/sleep 0.01\ndone\necho 'sha256: dead'\n",
        )
        .expect("write b");
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o755)).expect("chmod b");

        let input = root.join("model.gguf");
        std::fs::write(&input, b"gguf").expect("write input");

        // A prlimit stand-in that just execs what it was asked to run. Its exec
        // failure message is not the sentinel the A13 carve-out recognises, which is
        // also what a non-English host looks like - so this covers both the
        // "no util-linux" and the "unrecognised wrapper message" cases.
        let prlimit = dir_b.join("prlimit");
        std::fs::write(&prlimit, "#!/bin/sh\nshift 2\nexec \"$@\"\n").expect("write prlimit");
        std::fs::set_permissions(&prlimit, std::fs::Permissions::from_mode(0o755))
            .expect("chmod prlimit");

        // R30: hash while the fallback probe is active, as a concurrent report
        // test would. The fixture handshake guarantees overlap without relying
        // on the test runner's scheduling to reproduce the PATH race.
        let expected_hash = crate::common::sha256_file(&input).expect("baseline hash");
        let observer_root = root.clone();
        let observer_input = input.clone();
        let observer = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !observer_root.join("probe-ready").exists() {
                if std::time::Instant::now() >= deadline {
                    return Err("fallback probe never became ready".to_string());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let hash = crate::common::sha256_file(&observer_input);
            std::fs::write(observer_root.join("hash-done"), b"done").expect("release probe");
            hash
        });

        // Only this exact test runs in the child. Its restricted PATH and probe
        // overrides must never affect the parent test runner's other threads.
        let previous_path = std::env::var_os("PATH");
        let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"));
        child
            .arg("--exact")
            .arg("target::tests::a_gguf_candidate_that_cannot_be_executed_falls_through_to_the_next")
            .arg("--nocapture")
            .env(CHILD_INPUT, &input)
            .env("PATH", &dir_b)
            .env(super::GGUF_PROBE_KIND, "legacy_hash")
            .env("TOOL_LLAMA_CLI_BIN", dir_a.join("llama-cli"));
        let result = crate::common::output_with_deadline(child, 10);
        let concurrent_hash = observer.join().expect("hash observer");
        let _ = std::fs::remove_dir_all(&root);

        let (output, timed_out) = result.expect("run isolated fallback test");
        assert!(!timed_out, "isolated fallback test timed out");
        assert!(
            output.status.success(),
            "isolated fallback test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::env::var_os("PATH"), previous_path);
        assert_eq!(
            concurrent_hash,
            Ok(expected_hash),
            "the fallback probe test disrupted hashing in another thread"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_executable_refuses_a_file_without_the_execute_bit() {
        use super::resolve_executable;
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "tool-resolve-exec-{}-{}",
            std::process::id(),
            crate::common::now_unix_millis()
        ));
        std::fs::create_dir_all(&root).expect("create root");
        let plain = root.join("plain");
        std::fs::write(&plain, "x").expect("write");
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(resolve_executable(plain.as_os_str()).is_none());

        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(resolve_executable(plain.as_os_str()), Some(plain.clone()));

        assert!(resolve_executable(root.join("missing").as_os_str()).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    // A35: a non-UTF-8 input path was handed to child processes through
    // display().to_string(), which substitutes U+FFFD. The child then opened a
    // path that does not exist and reported "not a model file", so a real seed was
    // silently classified as rejected instead of being tested.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_input_path_reaches_the_probe_unmangled() {
        use super::{onnx_library_connect, LibraryConnectOutcome};
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        let _guard = env_lock();
        let dir = std::env::temp_dir().join(format!(
            "tool-a35-{}-{}",
            std::process::id(),
            crate::common::now_unix_millis()
        ));
        std::fs::create_dir_all(&dir).expect("create dir");

        let input = dir.join(OsStr::from_bytes(b"seed\xffx.onnx"));
        std::fs::write(&input, b"not really onnx").expect("write input");

        let stub = dir.join("python-stub.sh");
        std::fs::write(
            &stub,
            "#!/usr/bin/env bash\n[ -e \"$3\" ] && echo 'session_ok:inputs=1' || exit 2\n",
        )
        .expect("write stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        std::env::set_var("TOOL_PYTHON_BIN", &stub);
        let result = onnx_library_connect(&input);
        std::env::remove_var("TOOL_PYTHON_BIN");

        assert!(
            matches!(result.outcome, LibraryConnectOutcome::SessionOk),
            "the probe did not see the file: {} / {:?}",
            result.step,
            result.outcome.as_str()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // A33: the external harness command line was tokenized with split_whitespace(),
    // so a quoted program path containing a space was cut in half. The harness then
    // looked permanently unavailable, and when the mangled prefix happened to
    // resolve, its non-zero exit was filed as a library crash.
    #[test]
    fn harness_command_line_is_split_like_a_shell() {
        use super::split_command_line;

        assert_eq!(
            split_command_line("\"/tmp/my dir/replay\" --flag 'a b'").expect("split"),
            vec!["/tmp/my dir/replay", "--flag", "a b"]
        );
        assert_eq!(
            split_command_line("/usr/bin/env python3 x.py").expect("split"),
            vec!["/usr/bin/env", "python3", "x.py"]
        );
        assert_eq!(
            split_command_line("/tmp/my\\ dir/replay").expect("split"),
            vec!["/tmp/my dir/replay"]
        );
        assert_eq!(
            split_command_line("  spaced   out  ").expect("split"),
            vec!["spaced", "out"]
        );
        assert!(split_command_line("\"unterminated").is_err());
        assert!(split_command_line("'unterminated").is_err());
        assert!(split_command_line("").expect("split").is_empty());
    }

    use super::{crash_status_detail, exit_code_signal_name};

    // cargo runs #[test]s in parallel threads and TOOL_PYTHON_BIN /
    // TOOL_REQUIRE_LIBRARY_CONNECT are process-global, so the probe tests that
    // mutate them must not overlap.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // A sanitizer report opens with a rule of '=' characters, so reducing it with
    // first_line() hands triage a line of punctuation and nothing else.
    #[test]
    fn an_asan_report_keeps_its_error_line_instead_of_the_banner() {
        let text = "=================================================================\n\
                    ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff0\n";
        assert_eq!(
            super::first_evidence_line(text),
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff0"
        );
        // Nothing but rules and blanks: behave exactly like first_line().
        assert_eq!(super::first_evidence_line("=====\n\n"), "=====");
        assert_eq!(super::first_evidence_line(""), "no output");
    }

    #[test]
    fn detects_128_plus_signal_exit_codes() {
        assert_eq!(exit_code_signal_name(136), Some("SIGFPE"));
        assert_eq!(exit_code_signal_name(139), Some("SIGSEGV"));
        assert_eq!(exit_code_signal_name(2), None);
    }

    #[cfg(unix)]
    #[test]
    fn detects_unix_signal_status() {
        use std::os::unix::process::ExitStatusExt;

        let status = std::process::ExitStatus::from_raw(11);
        assert_eq!(
            crash_status_detail(&status).as_deref(),
            Some("SIGSEGV (signal: 11)")
        );
    }

    // G1 regression: protect the crash-propagation fix (commit 0a0b475). A library
    // subprocess killed by a signal must be classified as a crash, and run_harness
    // must surface it as Err rather than a silent clean EXIT:0. Both tests are
    // self-contained: no private PoC and no real onnxruntime.
    #[cfg(unix)]
    #[test]
    fn signal_killed_library_output_is_classified_as_crashed() {
        use super::{crashed_connect_result, LibraryConnectOutcome};
        use std::os::unix::process::ExitStatusExt;

        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(11), // WIFSIGNALED, SIGSEGV
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        let result = crashed_connect_result("onnxruntime", "loader", &output)
            .expect("a signal-killed library subprocess must be classified as a crash");
        assert!(matches!(result.outcome, LibraryConnectOutcome::Crashed));
        assert!(result.step.contains("SIGSEGV"), "step was: {}", result.step);
    }

    #[cfg(unix)]
    #[test]
    fn run_harness_returns_err_when_library_subprocess_is_signal_killed() {
        use super::{run_harness, TargetKind};
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let _guard = env_lock();
        let dir = std::env::temp_dir().join(format!("tool-g1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Stand-in for the onnxruntime probe: dies by SIGSEGV instead of loading.
        let script = dir.join("segv_python.sh");
        {
            let mut f = std::fs::File::create(&script).unwrap();
            writeln!(f, "#!/bin/sh\nkill -SEGV \"$$\"").unwrap();
        }
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let input = dir.join("sample.onnx");
        std::fs::write(&input, b"not-a-real-onnx-but-non-empty").unwrap();

        std::env::set_var("TOOL_PYTHON_BIN", &script);
        std::env::remove_var("TOOL_ONNX_HARNESS_CMD");
        let result = run_harness(&TargetKind::Onnx, &input);
        std::env::remove_var("TOOL_PYTHON_BIN");
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err(
            "a signal-killed library subprocess must make run_harness return Err, not Ok",
        );
        assert!(
            matches!(err, super::HarnessError::LibraryCrash(_)),
            "err was: {err:?}"
        );
        assert_eq!(err.exit_code(), crate::EXIT_HARNESS_LIBRARY_CRASH);
        assert!(err.to_string().contains("crash"), "err was: {err}");
    }

    // G3: exit code 4 must mean "the library really crashed". Benign harness-side
    // rejections (missing input, precheck reject) exit with a different code so
    // triage does not count them as crashes.
    #[test]
    fn missing_input_is_a_benign_harness_error() {
        use super::{run_harness, HarnessError, TargetKind};

        let missing = std::env::temp_dir().join(format!(
            "tool-g3-missing-{}-{}.onnx",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&missing);

        let err = run_harness(&TargetKind::Onnx, &missing)
            .expect_err("a missing input must make run_harness return Err");
        assert!(
            matches!(err, HarnessError::InputRejected(_)),
            "err was: {err:?}"
        );
        assert_eq!(err.exit_code(), crate::EXIT_HARNESS_INPUT_REJECTED);
    }

    #[test]
    fn precheck_rejection_is_a_benign_harness_error() {
        use super::{run_harness, HarnessError, TargetKind};

        let dir = std::env::temp_dir().join(format!("tool-g3-precheck-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("tiny.safetensors");
        // shorter than the 8-byte header length prefix -> rejected before any library call
        std::fs::write(&input, b"abc").unwrap();

        let err = run_harness(&TargetKind::Safetensors, &input)
            .expect_err("a precheck-rejected input must make run_harness return Err");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            matches!(err, HarnessError::InputRejected(_)),
            "err was: {err:?}"
        );
        assert_eq!(err.exit_code(), crate::EXIT_HARNESS_INPUT_REJECTED);
    }

    // A13: with prlimit in front of the interpreter, a missing/non-executable
    // interpreter comes back as a plain exit 127 instead of Err(NotFound), so the
    // probe used to report "loader invoked" even though nothing ever ran.
    #[cfg(unix)]
    #[test]
    fn missing_python_interpreter_is_unavailable_not_invoked() {
        use super::{onnx_library_connect, safetensors_library_connect, LibraryConnectOutcome};

        let _guard = env_lock();
        let dir = std::env::temp_dir().join(format!("tool-a13-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("sample.onnx");
        std::fs::write(&input, b"bytes").unwrap();

        // This A13 invariant is about the python interpreter being missing, so select
        // the python probe explicitly (native is the default now).
        std::env::set_var("TOOL_SAFETENSORS_PROBE", "python");
        std::env::set_var("TOOL_PYTHON_BIN", "/nonexistent/tool-a13-python3");
        let onnx = onnx_library_connect(&input);
        let safetensors = safetensors_library_connect(&input);
        std::env::remove_var("TOOL_PYTHON_BIN");
        std::env::remove_var("TOOL_SAFETENSORS_PROBE");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            matches!(onnx.outcome, LibraryConnectOutcome::Unavailable),
            "onnx step was: {}",
            onnx.step
        );
        assert!(
            matches!(safetensors.outcome, LibraryConnectOutcome::Unavailable),
            "safetensors step was: {}",
            safetensors.step
        );
    }

    // Review follow-up: an external harness that cannot be executed is an environment
    // problem, not a crash; reporting it as a library crash files a finding for a typo.
    #[cfg(unix)]
    #[test]
    fn unrunnable_external_harness_is_unavailable_not_a_crash() {
        use super::{run_harness, HarnessError, TargetKind};

        let _guard = env_lock();
        let dir = std::env::temp_dir().join(format!("tool-ext-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("sample.onnx");
        std::fs::write(&input, b"bytes").unwrap();

        std::env::set_var("TOOL_ONNX_HARNESS_CMD", "/nonexistent/tool-external-harness");
        std::env::remove_var("TOOL_REQUIRE_LIBRARY_CONNECT");
        let result = run_harness(&TargetKind::Onnx, &input);
        std::env::remove_var("TOOL_ONNX_HARNESS_CMD");
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err("an unrunnable external harness must fail the harness run");
        assert!(
            matches!(err, HarnessError::Unavailable(_)),
            "err was: {err:?}"
        );
        assert_eq!(err.exit_code(), crate::EXIT_HARNESS_UNAVAILABLE);
    }

    #[cfg(unix)]
    #[test]
    fn strict_library_connect_gate_fails_when_interpreter_is_missing() {
        use super::{run_harness, HarnessError, TargetKind};

        let _guard = env_lock();
        let dir = std::env::temp_dir().join(format!("tool-a13-strict-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("sample.onnx");
        std::fs::write(&input, b"bytes").unwrap();

        std::env::set_var("TOOL_PYTHON_BIN", "/nonexistent/tool-a13-python3");
        std::env::set_var("TOOL_REQUIRE_LIBRARY_CONNECT", "1");
        std::env::remove_var("TOOL_ONNX_HARNESS_CMD");
        let result = run_harness(&TargetKind::Onnx, &input);
        std::env::remove_var("TOOL_REQUIRE_LIBRARY_CONNECT");
        std::env::remove_var("TOOL_PYTHON_BIN");
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err(
            "the strict library-connect gate must fail when the probe never ran",
        );
        assert!(
            matches!(err, HarnessError::Unavailable(_)),
            "err was: {err:?}"
        );
        assert_eq!(err.exit_code(), crate::EXIT_HARNESS_UNAVAILABLE);
        assert!(
            err.to_string().contains("unavailable"),
            "err was: {err}"
        );
    }
}
