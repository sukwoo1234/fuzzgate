use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fmt, fs,
    io::Write,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use serde::{Deserialize, Serialize};

use crate::{
    common::{artifact_contract, now_unix_millis, AppPaths},
    execution_context::{self, ExecutionContext},
    target::{parse_target_id, target_label, HarnessError, TargetKind},
    target_profiles::{
        load_profile_snapshot, load_qualification_snapshot_for_profile, sha256_bytes, LoadedProfile,
    },
};

const MAX_RESULT_ID_BYTES: usize = 200;
const MAX_RESULT_FILES: usize = 10_000;
const MAX_RESULT_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RESULT_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TRACEBACK_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const DIAGNOSTIC_SUPERVISOR_ENV: &str = "TOOL_DIAGNOSTIC_SUPERVISOR";

static NEXT_ARTIFACT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResultKind {
    Run,
    Triage,
    Report,
    Coverage,
    Diagnostic,
}

impl ResultKind {
    fn label(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Triage => "triage",
            Self::Report => "report",
            Self::Coverage => "coverage",
            Self::Diagnostic => "diagnostic",
        }
    }

    fn primary_file(self) -> &'static str {
        match self {
            Self::Run => "status.json",
            Self::Triage => "summary.json",
            Self::Report => "meta.json",
            Self::Coverage => "summary.json",
            Self::Diagnostic => "diagnostic.json",
        }
    }
}

struct ResolvedResult {
    id: String,
    kind: ResultKind,
    path: PathBuf,
}

struct IdentityBundle {
    target_id: Option<String>,
    authorization: Option<String>,
    profile_sha256: Option<String>,
    input_kind: Option<String>,
    input_extensions: Vec<String>,
    profile: Option<IdentityFile>,
    qualification: Option<IdentityFile>,
    missing_reasons: Vec<String>,
}

struct IdentityFile {
    source: PathBuf,
    bytes: Vec<u8>,
    sha256: String,
    destination: &'static str,
}

#[derive(Clone, Debug)]
struct ResultFile {
    relative: PathBuf,
    bytes: Arc<[u8]>,
    sha256: String,
}

#[derive(Debug)]
pub(crate) struct DiagnosticLocation {
    pub(crate) id: String,
    pub(crate) path: PathBuf,
}

pub(crate) struct StagedInput {
    root: PathBuf,
    path: PathBuf,
    evidence_path: PathBuf,
}

#[derive(Debug)]
pub(crate) enum StageInputError {
    Rejected(String),
    Unavailable(String),
}

impl StageInputError {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Rejected(_) => crate::EXIT_HARNESS_INPUT_REJECTED,
            Self::Unavailable(_) => crate::EXIT_HARNESS_UNAVAILABLE,
        }
    }
}

impl fmt::Display for StageInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(message) | Self::Unavailable(message) => formatter.write_str(message),
        }
    }
}

impl StagedInput {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn evidence_path(&self) -> &Path {
        &self.evidence_path
    }
}

impl Drop for StagedInput {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionReferences {
    schema_version: String,
    profile_path: PathBuf,
    profile_sha256: String,
    authorization: String,
    qualification_path: Option<PathBuf>,
    qualification_sha256: Option<String>,
    validation_run: Option<String>,
    target_id: String,
    format_revision: String,
    loader_id: String,
    loader_version: String,
    backend: String,
    depth: String,
    argv: Vec<String>,
    allowed_env: serde_json::Map<String, serde_json::Value>,
    corpus_snapshot_sha256: Option<String>,
    input_manifest_sha256: Option<String>,
    tool_commit: Option<String>,
    tool_dirty: Option<bool>,
    started_unix_ms: u128,
    ended_unix_ms: u128,
    elapsed_ms: u128,
    outcome: String,
    profile_unchanged_after_execution: bool,
    identity_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfiledResultMarker {
    schema_version: String,
    target_id: String,
    profile_sha256: String,
    authorization: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticRecord {
    schema_version: String,
    diagnostic_id: String,
    target_id: String,
    classification: String,
    input_path: String,
    input_sha256: String,
    profile_path: String,
    profile_sha256: String,
    authorization: String,
    qualification_path: Option<String>,
    qualification_sha256: Option<String>,
    execution_path: String,
    execution_sha256: String,
    traceback_path: String,
    traceback_sha256: String,
    created_unix_ms: u128,
    parent_result_id: Option<String>,
    parent_job_id: Option<u64>,
    parent_input_path: Option<String>,
    parent_input_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TracebackFingerprint {
    exception_type: String,
    target_frames: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticReplayRecord {
    schema_version: String,
    diagnostic_id: String,
    validation_run: String,
    profile_sha256: String,
    profile_unchanged_after_execution: bool,
    identity_error: Option<String>,
    attempts: u32,
    result: String,
    same_exception_fingerprint: bool,
    original_fingerprint: Option<TracebackFingerprint>,
    linked_triage: Option<DiagnosticReplayLinkedTriage>,
    next_action: String,
    observations: Vec<DiagnosticReplayObservation>,
}

#[derive(Deserialize)]
#[serde(tag = "status")]
enum DiagnosticReplayLinkedTriage {
    #[serde(rename = "created")]
    Created(DiagnosticReplayCreatedTriage),
    #[serde(rename = "failed")]
    Failed(DiagnosticReplayFailedTriage),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticReplayCreatedTriage {
    triage_id: String,
    summary_path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticReplayFailedTriage {
    error: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticReplayObservation {
    attempt: u32,
    outcome: String,
    detail_sha256: String,
    detail: String,
    fingerprint: Option<TracebackFingerprint>,
}

#[derive(serde::Serialize)]
struct ManifestEntry {
    path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputManifest {
    schema_version: String,
    files: Vec<InputManifestEntry>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputManifestEntry {
    path: String,
    size_bytes: u64,
    sha256: String,
}

pub(crate) struct InputSnapshot {
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) sha256: Vec<String>,
    pub(crate) manifest_sha256: String,
}

pub(crate) fn show_result(app_paths: &AppPaths, id: &str) -> Result<(), String> {
    let resolved = resolve_result(app_paths, id)?;
    let files = collect_result_files(&resolved.path)?;
    let primary: serde_json::Value =
        read_result_json(&files, Path::new(resolved.kind.primary_file()))?;
    let identity = validate_result(&resolved, &primary, &files)?;
    let value = serde_json::json!({
        "schema_version": "1",
        "id": resolved.id,
        "kind": resolved.kind.label(),
        "target_id": identity.target_id,
        "profiled": identity.profile.is_some(),
        "profile_sha256": identity.profile_sha256,
        "authorization": identity.authorization,
        "missing_reasons": identity.missing_reasons,
        "file_count": files.len(),
        "primary": primary,
    });
    println!(
        "{}",
        serde_json::to_string(&value).map_err(|e| format!("failed to render result: {e}"))?
    );
    Ok(())
}

pub(crate) fn export_result(app_paths: &AppPaths, id: &str) -> Result<PathBuf, String> {
    let resolved = resolve_result(app_paths, id)?;
    let result_files = collect_result_files(&resolved.path)?;
    let primary: serde_json::Value =
        read_result_json(&result_files, Path::new(resolved.kind.primary_file()))?;
    let identity = validate_result(&resolved, &primary, &result_files)?;
    validate_export_original_input(&resolved, &identity, &result_files)?;

    let artifact = artifact_contract(app_paths);
    fs::create_dir_all(&artifact.exports_root).map_err(|e| {
        format!(
            "failed to create export root '{}': {e}",
            artifact.exports_root.display()
        )
    })?;
    ensure_no_symlink_components(&artifact.exports_root, "export root")?;
    let suffix = unique_suffix();
    let export_id = format!("export-{}-{suffix}", resolved.id);
    let final_path = artifact.exports_root.join(&export_id);
    let temp_path = artifact.exports_root.join(format!(".{export_id}.tmp"));
    fs::create_dir(&temp_path).map_err(|e| {
        format!(
            "failed to create export staging '{}': {e}",
            temp_path.display()
        )
    })?;

    let result = (|| -> Result<Vec<ManifestEntry>, String> {
        let mut manifest_files = Vec::new();
        for file in &result_files {
            let destination = Path::new("result").join(&file.relative);
            manifest_files.push(copy_snapshot_file(file, &temp_path, &destination)?);
        }
        if let Some(profile) = &identity.profile {
            manifest_files.push(copy_identity_file(
                profile,
                &temp_path,
                Path::new(profile.destination),
            )?);
        }
        if let Some(qualification) = &identity.qualification {
            manifest_files.push(copy_identity_file(
                qualification,
                &temp_path,
                Path::new(qualification.destination),
            )?);
        }
        manifest_files.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(manifest_files)
    })();

    let manifest_files = match result {
        Ok(files) => files,
        Err(error) => {
            let _ = fs::remove_dir_all(&temp_path);
            return Err(error);
        }
    };
    let manifest = serde_json::json!({
        "schema_version": "1",
        "export_id": export_id,
        "result_id": resolved.id,
        "result_kind": resolved.kind.label(),
        "target_id": identity.target_id,
        "profile_sha256": identity.profile_sha256,
        "authorization": identity.authorization,
        "qualification_status": if identity.qualification.is_some() { "verified" } else { "unqualified" },
        "missing_reasons": identity.missing_reasons,
        "complete": true,
        "files": manifest_files,
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("failed to serialize export manifest: {e}"))?;
    if let Err(error) = write_new_file(&temp_path.join("manifest.json"), &manifest_bytes) {
        let _ = fs::remove_dir_all(&temp_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, &final_path) {
        let _ = fs::remove_dir_all(&temp_path);
        return Err(format!(
            "failed to publish export '{}' as '{}': {error}",
            temp_path.display(),
            final_path.display()
        ));
    }
    println!("[export] done");
    println!("id: {}", resolved.id);
    println!("export_id: {export_id}");
    println!("path: {}", final_path.display());
    Ok(final_path)
}

pub(crate) fn preserve_unclassified(
    app_paths: &AppPaths,
    context: &ExecutionContext,
    target: &TargetKind,
    input: &Path,
    traceback: &str,
) -> Result<DiagnosticLocation, String> {
    context.ensure_unchanged()?;
    if traceback.len() > MAX_TRACEBACK_BYTES {
        return Err(format!(
            "unclassified traceback exceeds {MAX_TRACEBACK_BYTES} bytes"
        ));
    }
    let traceback_bytes = traceback.as_bytes();
    let traceback_sha256 = sha256_bytes(traceback_bytes)?;

    let artifact = artifact_contract(app_paths);
    fs::create_dir_all(&artifact.diagnostics_root).map_err(|e| {
        format!(
            "failed to create diagnostics root '{}': {e}",
            artifact.diagnostics_root.display()
        )
    })?;
    ensure_no_symlink_components(&artifact.diagnostics_root, "diagnostics root")?;
    let id = format!("diagnostic-{}", unique_suffix());
    let final_path = artifact.diagnostics_root.join(&id);
    let temp_path = artifact.diagnostics_root.join(format!(".{id}.tmp"));
    fs::create_dir(&temp_path).map_err(|e| {
        format!(
            "failed to create diagnostic staging '{}': {e}",
            temp_path.display()
        )
    })?;

    let result = (|| -> Result<(), String> {
        let file_name = input
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "diagnostic input has no file name".to_string())?;
        let relative_input = Path::new("input").join(file_name);
        let input_snapshot = snapshot_inputs(&temp_path, &[input.to_path_buf()], "input")?;
        if input_snapshot.paths.first() != Some(&temp_path.join(&relative_input)) {
            return Err("diagnostic input snapshot path mismatch".to_string());
        }
        let input_sha256 = input_snapshot
            .sha256
            .first()
            .ok_or_else(|| "diagnostic input snapshot hash is missing".to_string())?;
        write_new_file(
            &temp_path.join("profile.json"),
            &context.profile.loaded.bytes,
        )?;
        if let Some((_path, expected_hash, bytes)) = context.qualification_snapshot() {
            let observed = sha256_bytes(bytes)?;
            if !observed.eq_ignore_ascii_case(expected_hash) {
                return Err(
                    "qualification bytes changed before diagnostic preservation".to_string()
                );
            }
            write_new_file(&temp_path.join("qualification.json"), bytes)?;
        }
        write_new_file(&temp_path.join("traceback.txt"), traceback_bytes)?;

        let started = now_unix_millis();
        let argv = std::env::args_os()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        context.write_execution_record(
            &temp_path,
            "diagnostic",
            None,
            Some(&input_snapshot.manifest_sha256),
            started,
            0,
            "unclassified",
            &argv,
        )?;
        let execution_path = temp_path.join("execution.json");
        let mut execution: serde_json::Value = read_json(&execution_path)?;
        execution["profile_path"] = serde_json::Value::String(
            absolute_path(&final_path.join("profile.json"))?
                .display()
                .to_string(),
        );
        if context.qualification_snapshot().is_some() {
            execution["qualification_path"] = serde_json::Value::String(
                absolute_path(&final_path.join("qualification.json"))?
                    .display()
                    .to_string(),
            );
        }
        let execution_bytes = serde_json::to_vec_pretty(&execution)
            .map_err(|e| format!("failed to serialize diagnostic execution: {e}"))?;
        replace_file(&execution_path, &execution_bytes)?;
        let execution_sha256 = sha256_bytes(&read_regular_file(
            &execution_path,
            MAX_JSON_BYTES,
            "diagnostic execution",
        )?)?;
        let qualification_sha256 = context
            .qualification_snapshot()
            .map(|(_, hash, _)| hash.to_string());
        let record = serde_json::json!({
            "schema_version": "1",
            "diagnostic_id": id,
            "target_id": target_label(target),
            "classification": "unclassified",
            "input_path": relative_path_text(&relative_input)?,
            "input_sha256": input_sha256,
            "profile_path": "profile.json",
            "profile_sha256": context.profile.loaded.sha256,
            "authorization": context.mode_label(),
            "qualification_path": qualification_sha256.as_ref().map(|_| "qualification.json"),
            "qualification_sha256": qualification_sha256,
            "execution_path": "execution.json",
            "execution_sha256": execution_sha256,
            "traceback_path": "traceback.txt",
            "traceback_sha256": traceback_sha256,
            "created_unix_ms": started,
        });
        let bytes = serde_json::to_vec_pretty(&record)
            .map_err(|e| format!("failed to serialize diagnostic record: {e}"))?;
        write_new_file(&temp_path.join("diagnostic.json"), &bytes)
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temp_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp_path, &final_path) {
        let _ = fs::remove_dir_all(&temp_path);
        return Err(format!(
            "failed to publish diagnostic '{}' as '{}': {error}",
            temp_path.display(),
            final_path.display()
        ));
    }
    Ok(DiagnosticLocation {
        id,
        path: final_path,
    })
}

pub(crate) fn stage_input(input: &Path) -> Result<StagedInput, StageInputError> {
    let bytes = read_regular_file(input, MAX_RESULT_FILE_BYTES, "profile input")
        .map_err(StageInputError::Rejected)?;
    let name = input
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| StageInputError::Rejected("profile input has no file name".to_string()))?;
    stage_input_bytes(name, &bytes)
}

pub(crate) fn snapshot_inputs(
    result_root: &Path,
    inputs: &[PathBuf],
    directory_name: &str,
) -> Result<InputSnapshot, String> {
    if inputs.is_empty() {
        return Err("cannot snapshot an empty profiled input set".to_string());
    }
    validate_relative_path(Path::new(directory_name))?;
    let input_root = result_root.join(directory_name);
    fs::create_dir(&input_root).map_err(|e| {
        format!(
            "failed to create profiled input snapshot '{}': {e}",
            input_root.display()
        )
    })?;
    let manifest_path = result_root.join("input-manifest.json");
    let result = (|| -> Result<InputSnapshot, String> {
        let mut sources = inputs
            .iter()
            .map(|source| {
                let name = source
                    .file_name()
                    .and_then(OsStr::to_str)
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| {
                        format!(
                            "profiled input has no UTF-8 file name: {}",
                            source.display()
                        )
                    })?;
                Ok((name.to_string(), source))
            })
            .collect::<Result<Vec<_>, String>>()?;
        sources.sort_by(|left, right| left.0.cmp(&right.0));
        let mut previous_name: Option<String> = None;
        let mut paths = Vec::with_capacity(sources.len());
        let mut hashes = Vec::with_capacity(sources.len());
        let mut entries = Vec::with_capacity(sources.len());
        for (name, source) in sources {
            if previous_name.as_deref() == Some(name.as_str()) {
                return Err(format!("duplicate profiled input file name: {name}"));
            }
            previous_name = Some(name.clone());
            let bytes = read_regular_file(source, MAX_RESULT_FILE_BYTES, "profiled input")?;
            let relative = Path::new(directory_name).join(&name);
            validate_relative_path(&relative)?;
            let destination = result_root.join(&relative);
            write_new_file(&destination, &bytes)?;
            let sha256 = sha256_bytes(&bytes)?;
            entries.push(InputManifestEntry {
                path: relative_path_text(&relative)?,
                size_bytes: bytes.len() as u64,
                sha256: sha256.clone(),
            });
            paths.push(destination);
            hashes.push(sha256);
        }
        let manifest = InputManifest {
            schema_version: "1".to_string(),
            files: entries,
        };
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| format!("failed to serialize input manifest: {e}"))?;
        manifest_bytes.push(b'\n');
        let manifest_sha256 = sha256_bytes(&manifest_bytes)?;
        write_new_file(&manifest_path, &manifest_bytes)?;
        Ok(InputSnapshot {
            paths,
            sha256: hashes,
            manifest_sha256,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&manifest_path);
        let _ = fs::remove_dir_all(&input_root);
    }
    result
}

fn stage_input_bytes(name: &OsStr, bytes: &[u8]) -> Result<StagedInput, StageInputError> {
    if name.is_empty() {
        return Err(StageInputError::Rejected(
            "profile input has no file name".to_string(),
        ));
    }
    let root = std::env::temp_dir().join(format!("tool-profile-input-{}", unique_suffix()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(&root).map_err(|e| {
        StageInputError::Unavailable(format!(
            "failed to create private input staging '{}': {e}",
            root.display()
        ))
    })?;
    let path = root.join(name);
    let evidence_root = root.join("evidence");
    let mut evidence_builder = fs::DirBuilder::new();
    #[cfg(unix)]
    evidence_builder.mode(0o700);
    if let Err(error) = evidence_builder.create(&evidence_root) {
        let _ = fs::remove_dir_all(&root);
        return Err(StageInputError::Unavailable(format!(
            "failed to create private input evidence staging '{}': {error}",
            evidence_root.display()
        )));
    }
    let evidence_path = evidence_root.join(name);
    if let Err(error) =
        write_private_file(&path, bytes).and_then(|_| write_private_file(&evidence_path, bytes))
    {
        let _ = fs::remove_dir_all(&root);
        return Err(StageInputError::Unavailable(error));
    }
    Ok(StagedInput {
        root,
        path,
        evidence_path,
    })
}

pub(crate) fn supervised_traceback_line(traceback: &str) -> Result<String, String> {
    serde_json::to_string(traceback)
        .map(|encoded| format!("TOOL_UNCLASSIFIED_JSON={encoded}"))
        .map_err(|e| format!("failed to encode supervised traceback: {e}"))
}

pub(crate) fn extract_supervised_traceback(output: &str) -> Option<String> {
    const MARKER: &str = "TOOL_UNCLASSIFIED_JSON=";
    output.lines().rev().find_map(|line| {
        let encoded = line.strip_prefix(MARKER)?;
        serde_json::from_str::<String>(encoded).ok()
    })
}

pub(crate) fn attach_diagnostic_to_result(
    location: &DiagnosticLocation,
    result_root: &Path,
    parent_job_id: usize,
    parent_input: &Path,
    parent_backend: &str,
) -> Result<PathBuf, String> {
    ensure_no_symlink_components(result_root, "result root")?;
    let parent_result_id = result_root
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "parent run result has no UTF-8 ID".to_string())?;
    validate_result_id(parent_result_id)?;
    if !parent_result_id.starts_with("run-") {
        return Err(format!(
            "attached diagnostic parent is not a run result: {parent_result_id}"
        ));
    }
    let parent_input_relative = parent_input.strip_prefix(result_root).map_err(|_| {
        format!(
            "attached diagnostic parent input '{}' is outside result '{}'",
            parent_input.display(),
            result_root.display()
        )
    })?;
    validate_relative_path(parent_input_relative)?;
    let parent_input_parts = parent_input_relative.components().collect::<Vec<_>>();
    if parent_input_parts.len() != 2
        || parent_input_parts.first() != Some(&Component::Normal(OsStr::new("inputs")))
    {
        return Err(format!(
            "attached diagnostic parent input is not a preserved run input: {}",
            parent_input_relative.display()
        ));
    }
    let parent_input_path = relative_path_text(parent_input_relative)?;
    let parent_input_bytes = read_regular_file(
        parent_input,
        MAX_RESULT_FILE_BYTES,
        "attached diagnostic parent input",
    )?;
    let parent_input_sha256 = sha256_bytes(&parent_input_bytes)?;
    let parent_job_id = u64::try_from(parent_job_id)
        .map_err(|_| "attached diagnostic parent job ID is too large".to_string())?;
    if parent_backend.trim().is_empty() {
        return Err("attached diagnostic parent backend is empty".to_string());
    }
    let diagnostics_root = result_root.join("diagnostics");
    if diagnostics_root.exists() {
        let metadata = fs::symlink_metadata(&diagnostics_root).map_err(|e| {
            format!(
                "failed to inspect result diagnostics root '{}': {e}",
                diagnostics_root.display()
            )
        })?;
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "result diagnostics root is not a real directory: {}",
                diagnostics_root.display()
            ));
        }
    } else {
        fs::create_dir(&diagnostics_root).map_err(|e| {
            format!(
                "failed to create result diagnostics root '{}': {e}",
                diagnostics_root.display()
            )
        })?;
    }
    let final_path = diagnostics_root.join(&location.id);
    let temp_path = diagnostics_root.join(format!(".{}.tmp-{}", location.id, unique_suffix()));
    fs::create_dir(&temp_path).map_err(|e| {
        format!(
            "failed to create attached diagnostic staging '{}': {e}",
            temp_path.display()
        )
    })?;
    let result = (|| -> Result<(), String> {
        for file in collect_result_files(&location.path)? {
            copy_snapshot_file(&file, &temp_path, &file.relative)?;
        }
        let diagnostic_path = temp_path.join("diagnostic.json");
        let standalone_record: DiagnosticRecord = read_json(&diagnostic_path)?;
        if !standalone_record
            .input_sha256
            .eq_ignore_ascii_case(&parent_input_sha256)
        {
            return Err(format!(
                "attached diagnostic input does not match parent input: expected {parent_input_sha256}, observed {}",
                standalone_record.input_sha256
            ));
        }
        if standalone_record.parent_result_id.is_some()
            || standalone_record.parent_job_id.is_some()
            || standalone_record.parent_input_path.is_some()
            || standalone_record.parent_input_sha256.is_some()
        {
            return Err("standalone diagnostic already contains a parent binding".to_string());
        }
        let execution_path = temp_path.join("execution.json");
        let mut execution: serde_json::Value = read_json(&execution_path)?;
        execution["profile_path"] = serde_json::Value::String(
            absolute_path(&final_path.join("profile.json"))?
                .display()
                .to_string(),
        );
        if temp_path.join("qualification.json").is_file() {
            execution["qualification_path"] = serde_json::Value::String(
                absolute_path(&final_path.join("qualification.json"))?
                    .display()
                    .to_string(),
            );
        }
        execution["backend"] = serde_json::Value::String(parent_backend.to_string());
        replace_file(
            &execution_path,
            &serde_json::to_vec_pretty(&execution)
                .map_err(|e| format!("failed to serialize attached execution: {e}"))?,
        )?;
        let execution_hash = sha256_bytes(&read_regular_file(
            &execution_path,
            MAX_JSON_BYTES,
            "attached execution",
        )?)?;
        let mut diagnostic: serde_json::Value = read_json(&diagnostic_path)?;
        diagnostic["execution_sha256"] = serde_json::Value::String(execution_hash);
        diagnostic["parent_result_id"] = serde_json::Value::String(parent_result_id.to_string());
        diagnostic["parent_job_id"] = serde_json::Value::from(parent_job_id);
        diagnostic["parent_input_path"] = serde_json::Value::String(parent_input_path.clone());
        diagnostic["parent_input_sha256"] = serde_json::Value::String(parent_input_sha256.clone());
        replace_file(
            &diagnostic_path,
            &serde_json::to_vec_pretty(&diagnostic)
                .map_err(|e| format!("failed to serialize attached diagnostic: {e}"))?,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temp_path);
        return Err(error);
    }
    fs::rename(&temp_path, &final_path).map_err(|e| {
        let _ = fs::remove_dir_all(&temp_path);
        format!(
            "failed to publish attached diagnostic '{}' as '{}': {e}",
            temp_path.display(),
            final_path.display()
        )
    })?;
    Ok(final_path)
}

pub(crate) fn replay_diagnostic(
    app_paths: &AppPaths,
    id: &str,
    attempts: u32,
) -> Result<(), String> {
    if !(2..=100).contains(&attempts) {
        return Err("attempts must be in 2..=100".to_string());
    }
    let resolved = resolve_result(app_paths, id)?;
    if resolved.kind != ResultKind::Diagnostic {
        return Err(format!("result '{id}' is not a diagnostic"));
    }
    let files = collect_result_files(&resolved.path)?;
    let primary: serde_json::Value =
        read_result_json(&files, Path::new(resolved.kind.primary_file()))?;
    validate_result(&resolved, &primary, &files)?;
    let record: DiagnosticRecord = read_result_json(&files, Path::new("diagnostic.json"))?;
    let target = parse_target_id(&record.target_id)
        .ok_or_else(|| format!("diagnostic target is not registered: {}", record.target_id))?;
    let input_path = confined_relative_path(&resolved.path, &record.input_path)?;
    let input_file = result_file(&files, Path::new(&record.input_path))?;
    let input_name = input_path
        .file_name()
        .ok_or_else(|| "diagnostic input has no file name".to_string())?;
    let profile_file = result_file(&files, Path::new(&record.profile_path))?;
    let staged_profile = stage_input_bytes(OsStr::new("profile.json"), &profile_file.bytes)
        .map_err(|error| error.to_string())?;

    let validation_id = format!("diagnostic-replay-{}", unique_suffix());
    let context = execution_context::resolve_execution_context(
        Some(staged_profile.path()),
        Some(&validation_id),
        &target,
    )?
    .ok_or_else(|| "diagnostic replay did not build an execution context".to_string())?;

    let traceback_file = result_file(&files, Path::new(&record.traceback_path))?;
    let original_traceback = String::from_utf8(traceback_file.bytes.to_vec())
        .map_err(|_| "diagnostic traceback is not UTF-8".to_string())?;
    let include_sources = &context
        .profile
        .loaded
        .profile
        .coverage_scope
        .include_sources;
    let exclude_sources = &context
        .profile
        .loaded
        .profile
        .coverage_scope
        .exclude_sources;
    let original_fingerprint =
        traceback_fingerprint(&original_traceback, include_sources, exclude_sources);

    let mut observations = Vec::new();
    let mut replay_fingerprints = Vec::new();
    let mut incomplete = false;
    let mut saw_library_crash = false;
    for attempt in 1..=attempts {
        let staged_input =
            stage_input_bytes(input_name, &input_file.bytes).map_err(|error| error.to_string())?;
        let (outcome, detail, fingerprint) =
            match execution_context::run_profiled_harness(&context, &target, staged_input.path()) {
                Ok(()) => ("success", String::new(), None),
                Err(HarnessError::InputRejected(message)) => ("rejected", message, None),
                Err(HarnessError::Unclassified(message)) => {
                    let fingerprint =
                        traceback_fingerprint(&message, include_sources, exclude_sources);
                    if fingerprint.is_none() {
                        incomplete = true;
                    }
                    replay_fingerprints.push(fingerprint.clone());
                    ("unclassified", message, fingerprint)
                }
                Err(HarnessError::Unavailable(message)) => {
                    incomplete = true;
                    ("unavailable", message, None)
                }
                Err(HarnessError::LibraryCrash(message)) => {
                    incomplete = true;
                    saw_library_crash = true;
                    ("library_crash", message, None)
                }
            };
        observations.push(serde_json::json!({
            "attempt": attempt,
            "outcome": outcome,
            "detail_sha256": sha256_bytes(detail.as_bytes())?,
            "detail": detail,
            "fingerprint": fingerprint,
        }));
    }
    if original_fingerprint.is_none() {
        incomplete = true;
    }
    let linked_triage = if saw_library_crash {
        let triage_input =
            stage_input_bytes(input_name, &input_file.bytes).map_err(|error| error.to_string())?;
        let timeout_sec = context
            .profile
            .loaded
            .profile
            .limits
            .input_timeout_ms
            .saturating_add(999)
            / 1000;
        match execution_context::run_profiled_triage_with_summary(
            &context,
            app_paths,
            &target,
            triage_input.path(),
            attempts,
            timeout_sec.max(1),
        ) {
            Ok(summary) => {
                let summary = absolute_path(&summary)?;
                let triage_id = summary
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| {
                        format!(
                            "generated triage summary has no valid result ID: {}",
                            summary.display()
                        )
                    })?;
                Some(serde_json::json!({
                    "status": "created",
                    "triage_id": triage_id,
                    "summary_path": summary,
                }))
            }
            Err(error) => Some(serde_json::json!({
                "status": "failed",
                "error": error,
            })),
        }
    } else {
        None
    };
    let identity_error = context.ensure_unchanged().err();
    if identity_error.is_some() {
        incomplete = true;
    }
    let same_unclassified = identity_error.is_none()
        && replay_fingerprints.len() == attempts as usize
        && original_fingerprint.as_ref().is_some_and(|original| {
            replay_fingerprints
                .iter()
                .all(|observed| observed.as_ref() == Some(original))
        });
    let result = if incomplete {
        "incomplete"
    } else if same_unclassified {
        "reproduced"
    } else {
        "not_reproduced"
    };

    let replay_root = resolved.path.join("replays");
    ensure_real_directory(&replay_root, "diagnostic replay root")?;
    let replay_name = format!("replay-{}.json", unique_suffix());
    let replay_path = replay_root.join(&replay_name);
    let replay_temp = replay_root.join(format!(".{replay_name}.tmp"));
    let next_action = match (result, linked_triage.as_ref()) {
        (_, Some(link))
            if link.get("status").and_then(serde_json::Value::as_str) == Some("created") =>
        {
            "review the linked crash triage before classifying the diagnostic"
        }
        ("reproduced", _) => {
            "review whether the exception is an expected rejection or an upstream defect"
        }
        ("not_reproduced", _) => "review the divergent observations before classifying the finding",
        _ => "restore a usable original fingerprint and replay environment, then retry",
    };
    let replay = serde_json::json!({
        "schema_version": "1",
        "diagnostic_id": resolved.id,
        "validation_run": validation_id,
        "profile_sha256": context.profile.loaded.sha256,
        "profile_unchanged_after_execution": identity_error.is_none(),
        "identity_error": identity_error,
        "attempts": attempts,
        "result": result,
        "same_exception_fingerprint": same_unclassified,
        "original_fingerprint": original_fingerprint,
        "linked_triage": linked_triage,
        "next_action": next_action,
        "observations": observations,
    });
    let bytes = serde_json::to_vec_pretty(&replay)
        .map_err(|e| format!("failed to serialize diagnostic replay: {e}"))?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(format!(
            "diagnostic replay record exceeds {MAX_JSON_BYTES} bytes"
        ));
    }
    if let Err(error) = write_new_file(&replay_temp, &bytes).and_then(|_| {
        fs::rename(&replay_temp, &replay_path).map_err(|e| {
            format!(
                "failed to publish diagnostic replay '{}' as '{}': {e}",
                replay_temp.display(),
                replay_path.display()
            )
        })
    }) {
        let _ = fs::remove_file(&replay_temp);
        return Err(error);
    }
    println!("[replay-diagnostic] done");
    println!("diagnostic_id: {}", resolved.id);
    println!("attempts: {attempts}");
    println!("result: {result}");
    println!("record: {}", replay_path.display());
    Ok(())
}

fn traceback_fingerprint(
    traceback: &str,
    include_sources: &[String],
    exclude_sources: &[String],
) -> Option<TracebackFingerprint> {
    let exception_type = traceback.lines().rev().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("TOOL_UNCLASSIFIED_JSON=") {
            return None;
        }
        let candidate = trimmed.split_once(':').map_or(trimmed, |(kind, _)| kind);
        let valid = !candidate.is_empty()
            && !candidate.chars().any(char::is_whitespace)
            && candidate
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.'))
            && candidate
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_');
        valid.then(|| candidate.to_string())
    })?;
    let mut target_frames = Vec::new();
    for line in traceback.lines() {
        let Some(rest) = line.trim().strip_prefix("File \"") else {
            continue;
        };
        let Some((raw_path, rest)) = rest.split_once("\", line ") else {
            continue;
        };
        let Some((_line, function)) = rest.split_once(", in ") else {
            continue;
        };
        let normalized_path = raw_path.replace('\\', "/");
        if exclude_sources
            .iter()
            .any(|source| !source.is_empty() && normalized_path.contains(source))
        {
            continue;
        }
        let Some((offset, _)) = include_sources
            .iter()
            .filter(|source| !source.is_empty())
            .filter_map(|source| normalized_path.find(source).map(|offset| (offset, source)))
            .min_by_key(|(offset, _)| *offset)
        else {
            continue;
        };
        target_frames.push(format!("{}::{function}", &normalized_path[offset..]));
    }
    if target_frames.is_empty() {
        return None;
    }
    Some(TracebackFingerprint {
        exception_type,
        target_frames,
    })
}

fn resolve_result(app_paths: &AppPaths, id: &str) -> Result<ResolvedResult, String> {
    validate_result_id(id)?;
    let artifact = artifact_contract(app_paths);
    let (kind, root) = if id.starts_with("run-") {
        (ResultKind::Run, artifact.runs_root)
    } else if id.starts_with("triage-") {
        (ResultKind::Triage, artifact.triage_root)
    } else if id.starts_with("report-") {
        (ResultKind::Report, artifact.reports_root)
    } else if id.starts_with("coverage-") {
        (ResultKind::Coverage, artifact.coverage_root)
    } else if id.starts_with("diagnostic-") {
        (ResultKind::Diagnostic, artifact.diagnostics_root)
    } else {
        return Err(format!("unknown result id prefix: {id}"));
    };
    let path = root.join(id);
    ensure_no_symlink_components(&app_paths.data_dir, "data root")?;
    ensure_no_symlink_components(&root, "result collection root")?;
    ensure_no_symlink_components(&path, "result path")?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|e| format!("result id '{id}' does not exist: {e}"))?;
    if !metadata.file_type().is_dir() {
        return Err(format!("result id '{id}' is not a real directory"));
    }
    Ok(ResolvedResult {
        id: id.to_string(),
        kind,
        path,
    })
}

fn ensure_no_symlink_components(path: &Path, label: &str) -> Result<(), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to resolve current directory: {e}"))?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new("/")),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(format!(
                    "{label} contains a parent-directory component: {}",
                    path.display()
                ));
            }
            Component::Normal(value) => current.push(value),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|e| {
            format!(
                "failed to inspect {label} component '{}': {e}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{label} contains a symlink component: {}",
                current.display()
            ));
        }
    }
    Ok(())
}

fn validate_result_id(id: &str) -> Result<(), String> {
    let valid = !id.is_empty()
        && id.len() <= MAX_RESULT_ID_BYTES
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid {
        return Err(format!("invalid result id: {id:?}"));
    }
    Ok(())
}

fn validate_result(
    resolved: &ResolvedResult,
    primary: &serde_json::Value,
    files: &[ResultFile],
) -> Result<IdentityBundle, String> {
    validate_primary_identity(resolved, primary, files)?;
    validate_result_file_allowlist(resolved, files)?;
    if resolved.kind == ResultKind::Report {
        result_file(files, Path::new("report.md"))?;
    }

    let primary_target = primary
        .get("target")
        .or_else(|| primary.get("target_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let diagnostic_record = if resolved.kind == ResultKind::Diagnostic {
        let record: DiagnosticRecord = read_result_json(files, Path::new("diagnostic.json"))?;
        validate_diagnostic_record(resolved, &record, Some(files))?;
        Some(record)
    } else {
        None
    };

    let execution_file = result_file_optional(files, Path::new("execution.json"));
    let primary_profiled = primary
        .get("profiled_result")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let marker = if result_file_optional(files, Path::new("profiled-result.json")).is_some() {
        let marker: ProfiledResultMarker =
            read_result_json(files, Path::new("profiled-result.json"))?;
        if marker.schema_version != "1" {
            return Err(format!(
                "unsupported profiled result marker schema_version '{}'",
                marker.schema_version
            ));
        }
        Some(marker)
    } else {
        None
    };
    if execution_file.is_none() {
        if marker.is_some()
            || primary_profiled
            || result_file_optional(files, Path::new("input-manifest.json")).is_some()
        {
            return Err("profiled result is missing execution.json".to_string());
        }
        if result_file_optional(files, Path::new("profile.json")).is_some()
            || result_file_optional(files, Path::new("qualification.json")).is_some()
        {
            return Err("result contains an identity sidecar without execution.json".to_string());
        }
        validate_unclassified_evidence(resolved, primary, files, None, None)?;
        return Ok(IdentityBundle {
            target_id: primary_target,
            authorization: None,
            profile_sha256: None,
            input_kind: None,
            input_extensions: Vec::new(),
            profile: None,
            qualification: None,
            missing_reasons: Vec::new(),
        });
    }
    let execution: ExecutionReferences = read_result_json(files, Path::new("execution.json"))?;
    validate_execution_structure(resolved, primary, &execution)?;
    let marker =
        marker.ok_or_else(|| "profiled result is missing profiled-result.json".to_string())?;
    let target = primary_target
        .as_deref()
        .ok_or_else(|| "profiled result primary file is missing a string target".to_string())?;
    if target != execution.target_id {
        return Err(format!(
            "target mismatch: result names '{target}' but execution names '{}'",
            execution.target_id
        ));
    }
    let target = parse_target_id(&execution.target_id).ok_or_else(|| {
        format!(
            "execution target is not registered: {}",
            execution.target_id
        )
    })?;
    let profile_path = absolute_path(&resolved.path.join("profile.json"))?;
    if execution.profile_path != profile_path {
        return Err(format!(
            "profiled {} result must use its result-local profile.json",
            resolved.kind.label()
        ));
    }
    let profile_file = result_file(files, Path::new("profile.json")).map_err(|_| {
        format!(
            "profiled {} result is missing its result-local profile.json",
            resolved.kind.label()
        )
    })?;
    if !profile_file
        .sha256
        .eq_ignore_ascii_case(&execution.profile_sha256)
    {
        return Err(format!(
            "profile sha256 mismatch: expected {}, observed {}",
            execution.profile_sha256, profile_file.sha256
        ));
    }
    let loaded = load_profile_snapshot(&profile_path, &profile_file.bytes, &target)?;
    if !loaded
        .sha256
        .eq_ignore_ascii_case(&execution.profile_sha256)
    {
        return Err(format!(
            "profile sha256 mismatch: expected {}, observed {}",
            execution.profile_sha256, loaded.sha256
        ));
    }
    if marker.target_id != execution.target_id
        || !marker
            .profile_sha256
            .eq_ignore_ascii_case(&execution.profile_sha256)
        || marker.authorization != execution.authorization
    {
        return Err("profiled result marker does not match execution.json".to_string());
    }
    if execution.format_revision != loaded.profile.format_revision
        || execution.loader_id != loaded.profile.loader_id
        || execution.loader_version != loaded.profile.loader_version
        || execution.depth != loaded.profile.depth
    {
        return Err("execution loader identity does not match the verified profile".to_string());
    }
    if let Some(record) = diagnostic_record.as_ref() {
        validate_diagnostic_replay_records(
            resolved,
            files,
            record,
            &loaded.profile.coverage_scope.include_sources,
            &loaded.profile.coverage_scope.exclude_sources,
        )?;
    }
    validate_input_manifest(
        resolved,
        files,
        &execution,
        &loaded,
        diagnostic_record.as_ref(),
    )?;
    validate_unclassified_evidence(resolved, primary, files, Some(&execution), Some(&loaded))?;
    let profile = Some(IdentityFile {
        source: loaded.path.clone(),
        bytes: loaded.bytes.clone(),
        sha256: loaded.sha256.clone(),
        destination: "identity/profile.json",
    });
    let (qualification, missing_reasons) =
        validate_authorization(resolved, files, &execution, &loaded)?;
    Ok(IdentityBundle {
        target_id: Some(execution.target_id),
        authorization: Some(execution.authorization),
        profile_sha256: Some(loaded.sha256.clone()),
        input_kind: Some(loaded.profile.input_kind.kind.clone()),
        input_extensions: loaded.profile.input_kind.extensions.clone(),
        profile,
        qualification,
        missing_reasons,
    })
}

fn validate_execution_structure(
    resolved: &ResolvedResult,
    primary: &serde_json::Value,
    execution: &ExecutionReferences,
) -> Result<(), String> {
    if execution.schema_version != "1" {
        return Err(format!(
            "unsupported execution schema_version '{}'",
            execution.schema_version
        ));
    }
    if !matches!(
        execution.outcome.as_str(),
        "success" | "failed" | "unclassified"
    ) {
        return Err(format!(
            "execution outcome is not terminal: '{}'",
            execution.outcome
        ));
    }
    if !execution.profile_unchanged_after_execution || execution.identity_error.is_some() {
        return Err("execution did not preserve its profile identity".to_string());
    }

    for (label, value) in [
        ("target_id", execution.target_id.as_str()),
        ("format_revision", execution.format_revision.as_str()),
        ("loader_id", execution.loader_id.as_str()),
        ("loader_version", execution.loader_version.as_str()),
        ("backend", execution.backend.as_str()),
        ("depth", execution.depth.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("execution {label} must be present"));
        }
    }
    if execution.profile_path.as_os_str().is_empty() {
        return Err("execution profile_path must be present".to_string());
    }
    validate_sha256_text("execution profile_sha256", &execution.profile_sha256)?;
    if execution.argv.is_empty() || execution.argv.iter().any(|value| value.trim().is_empty()) {
        return Err("execution argv must contain only non-empty arguments".to_string());
    }
    if execution
        .allowed_env
        .iter()
        .any(|(key, value)| key.trim().is_empty() || !matches!(value, serde_json::Value::String(_)))
    {
        return Err("execution allowed_env must map non-empty names to strings".to_string());
    }

    let observed_elapsed = execution
        .ended_unix_ms
        .checked_sub(execution.started_unix_ms)
        .ok_or_else(|| "execution ended before it started".to_string())?;
    if observed_elapsed != execution.elapsed_ms {
        return Err(format!(
            "execution elapsed_ms mismatch: recorded {}, observed {observed_elapsed}",
            execution.elapsed_ms
        ));
    }
    if let Some(hash) = execution.corpus_snapshot_sha256.as_deref() {
        validate_sha256_text("execution corpus_snapshot_sha256", hash)?;
    }
    let input_manifest_sha256 = execution
        .input_manifest_sha256
        .as_deref()
        .ok_or_else(|| "profiled result execution is missing input_manifest_sha256".to_string())?;
    validate_sha256_text("execution input_manifest_sha256", input_manifest_sha256)?;
    if resolved.kind == ResultKind::Run && execution.corpus_snapshot_sha256.is_none() {
        return Err("profiled run execution is missing corpus_snapshot_sha256".to_string());
    }

    match (&execution.tool_commit, execution.tool_dirty) {
        (None, None) => {}
        (Some(commit), Some(_))
            if matches!(commit.len(), 40 | 64)
                && commit.chars().all(|ch| ch.is_ascii_hexdigit()) => {}
        (Some(_), Some(_)) => {
            return Err("execution tool_commit is not a full Git object ID".to_string());
        }
        _ => {
            return Err(
                "execution tool_commit and tool_dirty must either both be present or both be null"
                    .to_string(),
            );
        }
    }

    match execution.authorization.as_str() {
        "qualified" => {
            if execution.qualification_path.is_none()
                || execution.qualification_sha256.is_none()
                || execution.validation_run.is_some()
            {
                return Err(
                    "qualified execution must name one qualification and no validation_run"
                        .to_string(),
                );
            }
        }
        "unqualified_validation" => {
            if execution.qualification_path.is_some()
                || execution.qualification_sha256.is_some()
                || execution
                    .validation_run
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
            {
                return Err(
                    "unqualified validation must name validation_run and no qualification"
                        .to_string(),
                );
            }
        }
        other => return Err(format!("unsupported execution authorization '{other}'")),
    }
    if let Some(hash) = execution.qualification_sha256.as_deref() {
        validate_sha256_text("execution qualification_sha256", hash)?;
    }

    if let Some(primary_backend) = primary.get("backend").and_then(serde_json::Value::as_str) {
        if primary_backend != execution.backend {
            return Err(format!(
                "backend mismatch: result names '{primary_backend}' but execution names '{}'",
                execution.backend
            ));
        }
    }
    if let Some(primary_profile_sha256) = primary
        .get("profile_sha256")
        .and_then(serde_json::Value::as_str)
    {
        if !primary_profile_sha256.eq_ignore_ascii_case(&execution.profile_sha256) {
            return Err("profile sha256 mismatch between primary and execution".to_string());
        }
    }
    Ok(())
}

fn validate_sha256_text(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a 64-digit sha256"));
    }
    Ok(())
}

fn validate_input_manifest(
    resolved: &ResolvedResult,
    files: &[ResultFile],
    execution: &ExecutionReferences,
    loaded: &LoadedProfile,
    diagnostic_record: Option<&DiagnosticRecord>,
) -> Result<(), String> {
    let manifest_file = result_file(files, Path::new("input-manifest.json"))?;
    let expected_manifest_sha256 = execution
        .input_manifest_sha256
        .as_deref()
        .ok_or_else(|| "profiled result execution is missing input_manifest_sha256".to_string())?;
    if !manifest_file
        .sha256
        .eq_ignore_ascii_case(expected_manifest_sha256)
    {
        return Err(format!(
            "input manifest sha256 mismatch: expected {expected_manifest_sha256}, observed {}",
            manifest_file.sha256
        ));
    }
    let manifest: InputManifest = read_result_json(files, Path::new("input-manifest.json"))?;
    if manifest.schema_version != "1" {
        return Err(format!(
            "unsupported input manifest schema_version '{}'",
            manifest.schema_version
        ));
    }
    if manifest.files.is_empty() {
        return Err("profiled input manifest must contain at least one file".to_string());
    }

    let allowed_roots: &[&str] = match resolved.kind {
        ResultKind::Run => &["inputs"],
        ResultKind::Triage => &["input"],
        ResultKind::Report => &["poc", "input"],
        ResultKind::Coverage => &["input", "inputs"],
        ResultKind::Diagnostic => &["input"],
    };
    let mut previous_path: Option<&str> = None;
    let mut listed_paths = BTreeSet::new();
    for entry in &manifest.files {
        if previous_path.is_some_and(|previous| previous >= entry.path.as_str()) {
            return Err(
                "profiled input manifest paths must be strictly sorted and unique".to_string(),
            );
        }
        previous_path = Some(&entry.path);
        validate_sha256_text("input manifest file sha256", &entry.sha256)?;

        let relative = Path::new(&entry.path);
        validate_relative_path(relative)?;
        if relative_path_text(relative)? != entry.path {
            return Err(format!(
                "input manifest path is not canonical: {}",
                entry.path
            ));
        }
        let parts = relative
            .components()
            .map(|component| match component {
                Component::Normal(value) => value
                    .to_str()
                    .ok_or_else(|| format!("input manifest path is not UTF-8: {}", entry.path)),
                _ => Err(format!(
                    "input manifest path is not confined: {}",
                    entry.path
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if parts.len() != 2 || !allowed_roots.contains(&parts[0]) {
            return Err(format!(
                "input manifest path is not allowed for {}: {}",
                resolved.kind.label(),
                entry.path
            ));
        }
        let extension_allowed =
            relative
                .extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| {
                    loaded
                        .profile
                        .input_kind
                        .extensions
                        .iter()
                        .any(|allowed| extension.eq_ignore_ascii_case(allowed))
                });
        if !extension_allowed {
            return Err(format!(
                "input manifest path has an extension not authorized by the profile: {}",
                entry.path
            ));
        }

        let file = result_file(files, relative).map_err(|_| {
            format!(
                "input manifest references a missing preserved input: {}",
                entry.path
            )
        })?;
        if file.bytes.len() as u64 != entry.size_bytes {
            return Err(format!(
                "input manifest size mismatch for '{}': expected {}, observed {}",
                entry.path,
                entry.size_bytes,
                file.bytes.len()
            ));
        }
        if !file.sha256.eq_ignore_ascii_case(&entry.sha256) {
            return Err(format!(
                "input manifest sha256 mismatch for '{}': expected {}, observed {}",
                entry.path, entry.sha256, file.sha256
            ));
        }
        listed_paths.insert(relative.to_path_buf());
    }

    let observed_paths = files
        .iter()
        .filter_map(|file| {
            let first = file.relative.components().next()?;
            let Component::Normal(first) = first else {
                return None;
            };
            let first = first.to_str()?;
            allowed_roots
                .contains(&first)
                .then(|| file.relative.clone())
        })
        .collect::<BTreeSet<_>>();
    if listed_paths != observed_paths {
        return Err(
            "input manifest does not exactly cover the preserved profiled inputs".to_string(),
        );
    }

    if resolved.kind == ResultKind::Run {
        let mut corpus_manifest = Vec::new();
        for entry in &manifest.files {
            let relative = Path::new(&entry.path);
            let name = relative
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or_else(|| format!("input manifest has no file name: {}", entry.path))?;
            let file = result_file(files, relative)?;
            corpus_manifest.extend_from_slice(name.as_bytes());
            corpus_manifest.push(0);
            corpus_manifest.extend_from_slice(file.bytes.len().to_string().as_bytes());
            corpus_manifest.push(0);
            corpus_manifest.extend_from_slice(file.sha256.as_bytes());
            corpus_manifest.push(b'\n');
        }
        let observed = sha256_bytes(&corpus_manifest)?;
        let expected = execution.corpus_snapshot_sha256.as_deref().ok_or_else(|| {
            "profiled run execution is missing corpus_snapshot_sha256".to_string()
        })?;
        if !observed.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "run corpus snapshot sha256 mismatch: expected {expected}, observed {observed}"
            ));
        }
    }

    if resolved.kind == ResultKind::Diagnostic {
        let record = diagnostic_record
            .ok_or_else(|| "profiled diagnostic is missing diagnostic.json".to_string())?;
        if manifest.files.len() != 1 {
            return Err("profiled diagnostic input manifest must contain one file".to_string());
        }
        let entry = &manifest.files[0];
        if entry.path != record.input_path
            || !entry.sha256.eq_ignore_ascii_case(&record.input_sha256)
        {
            return Err(
                "diagnostic input_path/input_sha256 does not match input manifest".to_string(),
            );
        }
    }
    Ok(())
}

fn validate_authorization(
    resolved: &ResolvedResult,
    files: &[ResultFile],
    execution: &ExecutionReferences,
    loaded: &LoadedProfile,
) -> Result<(Option<IdentityFile>, Vec<String>), String> {
    match execution.authorization.as_str() {
        "qualified" => {
            let expected_path = execution
                .qualification_path
                .as_ref()
                .ok_or_else(|| "qualified execution is missing qualification_path".to_string())?;
            let expected_hash = execution
                .qualification_sha256
                .as_ref()
                .ok_or_else(|| "qualified execution is missing qualification_sha256".to_string())?;
            let qualification_path = absolute_path(&resolved.path.join("qualification.json"))?;
            if expected_path != &qualification_path {
                return Err(format!(
                    "qualified {} result must use its result-local qualification.json",
                    resolved.kind.label()
                ));
            }
            let qualification_file =
                result_file(files, Path::new("qualification.json")).map_err(|_| {
                    format!(
                        "qualified {} result is missing its result-local qualification.json",
                        resolved.kind.label()
                    )
                })?;
            if !qualification_file
                .sha256
                .eq_ignore_ascii_case(expected_hash)
            {
                return Err(format!(
                    "qualification sha256 mismatch: expected {expected_hash}, observed {}",
                    qualification_file.sha256
                ));
            }
            let qualification = load_qualification_snapshot_for_profile(
                loaded,
                &qualification_path,
                &qualification_file.bytes,
            )?;
            if !qualification.sha256.eq_ignore_ascii_case(expected_hash) {
                return Err(format!(
                    "qualification sha256 mismatch: expected {expected_hash}, observed {}",
                    qualification.sha256
                ));
            }
            if qualification.qualification.status != "verified" {
                return Err(format!(
                    "qualified result requires qualification status verified, observed '{}'",
                    qualification.qualification.status
                ));
            }
            Ok((
                Some(IdentityFile {
                    source: qualification.path,
                    bytes: qualification.bytes,
                    sha256: qualification.sha256,
                    destination: "identity/qualification.json",
                }),
                Vec::new(),
            ))
        }
        "unqualified_validation" => {
            if execution.qualification_path.is_some() || execution.qualification_sha256.is_some() {
                return Err("unqualified validation cannot reference a qualification".to_string());
            }
            if result_file_optional(files, Path::new("qualification.json")).is_some() {
                return Err("unqualified result must not contain qualification.json".to_string());
            }
            Ok((
                None,
                vec!["qualification was not issued for this explicit validation run".to_string()],
            ))
        }
        other => Err(format!("unsupported execution authorization '{other}'")),
    }
}

fn validate_diagnostic_record(
    resolved: &ResolvedResult,
    record: &DiagnosticRecord,
    files: Option<&[ResultFile]>,
) -> Result<(), String> {
    if record.schema_version != "1" {
        return Err(format!(
            "unsupported diagnostic schema_version '{}'",
            record.schema_version
        ));
    }
    if record.diagnostic_id != resolved.id {
        return Err(format!(
            "diagnostic id mismatch: directory '{}' record '{}'",
            resolved.id, record.diagnostic_id
        ));
    }
    if record.classification != "unclassified" {
        return Err(format!(
            "diagnostic classification must be unclassified, observed '{}'",
            record.classification
        ));
    }
    let parent_field_count = [
        record.parent_result_id.is_some(),
        record.parent_job_id.is_some(),
        record.parent_input_path.is_some(),
        record.parent_input_sha256.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if !matches!(parent_field_count, 0 | 4) {
        return Err(
            "diagnostic parent binding fields must be either all present or all absent".to_string(),
        );
    }
    if let (Some(parent_result_id), Some(parent_input_path), Some(parent_input_sha256)) = (
        record.parent_result_id.as_deref(),
        record.parent_input_path.as_deref(),
        record.parent_input_sha256.as_deref(),
    ) {
        validate_result_id(parent_result_id)?;
        if !parent_result_id.starts_with("run-") {
            return Err("diagnostic parent_result_id must name a run result".to_string());
        }
        let parent_input_path = Path::new(parent_input_path);
        validate_relative_path(parent_input_path)?;
        if relative_path_text(parent_input_path)?
            != record.parent_input_path.as_deref().unwrap_or_default()
        {
            return Err("diagnostic parent_input_path is not canonical".to_string());
        }
        validate_sha256_text("diagnostic parent_input_sha256", parent_input_sha256)?;
    }
    if parse_target_id(&record.target_id).is_none() {
        return Err(format!(
            "diagnostic target is not registered: {}",
            record.target_id
        ));
    }
    for (label, relative, hash) in [
        ("diagnostic input", &record.input_path, &record.input_sha256),
        (
            "diagnostic profile",
            &record.profile_path,
            &record.profile_sha256,
        ),
        (
            "diagnostic execution",
            &record.execution_path,
            &record.execution_sha256,
        ),
        (
            "diagnostic traceback",
            &record.traceback_path,
            &record.traceback_sha256,
        ),
    ] {
        if let Some(files) = files {
            let relative = Path::new(relative);
            validate_relative_path(relative)?;
            let file = result_file(files, relative)?;
            if !file.sha256.eq_ignore_ascii_case(hash) {
                return Err(format!(
                    "{label} sha256 mismatch: expected {hash}, observed {}",
                    file.sha256
                ));
            }
        } else {
            let path = confined_relative_path(&resolved.path, relative)?;
            verify_file_hash(&path, hash, label)?;
        }
    }
    let execution_path = confined_relative_path(&resolved.path, &record.execution_path)?;
    if execution_path != resolved.path.join("execution.json") {
        return Err("diagnostic execution_path must name execution.json".to_string());
    }
    let execution: ExecutionReferences = if let Some(files) = files {
        read_result_json(files, Path::new(&record.execution_path))?
    } else {
        read_json(&execution_path)?
    };
    if record.created_unix_ms != execution.started_unix_ms {
        return Err("diagnostic creation time does not match execution start".to_string());
    }
    if execution.target_id != record.target_id {
        return Err(format!(
            "diagnostic target mismatch: record '{}' execution '{}'",
            record.target_id, execution.target_id
        ));
    }
    if !execution
        .profile_sha256
        .eq_ignore_ascii_case(&record.profile_sha256)
    {
        return Err("diagnostic profile sha256 does not match execution".to_string());
    }
    let local_profile = absolute_path(&confined_relative_path(
        &resolved.path,
        &record.profile_path,
    )?)?;
    if execution.profile_path != local_profile {
        return Err("diagnostic profile path does not match execution".to_string());
    }
    if execution.authorization != record.authorization {
        return Err("diagnostic authorization does not match execution".to_string());
    }
    match record.authorization.as_str() {
        "qualified" => {
            let relative = record
                .qualification_path
                .as_deref()
                .ok_or_else(|| "qualified diagnostic is missing qualification_path".to_string())?;
            let expected_hash = record.qualification_sha256.as_deref().ok_or_else(|| {
                "qualified diagnostic is missing qualification_sha256".to_string()
            })?;
            let local = confined_relative_path(&resolved.path, relative)?;
            if let Some(files) = files {
                let file = result_file(files, Path::new(relative))?;
                if !file.sha256.eq_ignore_ascii_case(expected_hash) {
                    return Err(format!(
                        "diagnostic qualification sha256 mismatch: expected {expected_hash}, observed {}",
                        file.sha256
                    ));
                }
            } else {
                verify_file_hash(&local, expected_hash, "diagnostic qualification")?;
            }
            if execution.qualification_path.as_ref() != Some(&absolute_path(&local)?)
                || execution.qualification_sha256.as_deref() != Some(expected_hash)
            {
                return Err("diagnostic qualification does not match execution".to_string());
            }
        }
        "unqualified_validation" => {
            if record.qualification_path.is_some()
                || record.qualification_sha256.is_some()
                || execution.qualification_path.is_some()
                || execution.qualification_sha256.is_some()
            {
                return Err("unqualified diagnostic cannot reference a qualification".to_string());
            }
            if files.is_some_and(|files| {
                result_file_optional(files, Path::new("qualification.json")).is_some()
            }) {
                return Err(
                    "unqualified diagnostic must not contain qualification.json".to_string()
                );
            }
        }
        other => {
            return Err(format!("unsupported diagnostic authorization '{other}'"));
        }
    }
    Ok(())
}

fn validate_export_original_input(
    resolved: &ResolvedResult,
    identity: &IdentityBundle,
    files: &[ResultFile],
) -> Result<(), String> {
    if identity.profile.is_none() {
        return Ok(());
    }
    let allowed_roots: &[&str] = match resolved.kind {
        ResultKind::Run => &["crash-inputs", "diagnostics", "input", "inputs"],
        ResultKind::Triage => &["input"],
        ResultKind::Report => &["poc", "input"],
        ResultKind::Coverage => &["input", "inputs"],
        ResultKind::Diagnostic => &["input"],
    };
    let has_input = files.iter().any(|file| {
        let relative = &file.relative;
        let in_allowed_root = relative
            .components()
            .next()
            .and_then(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            })
            .map(|value| allowed_roots.contains(&value))
            .unwrap_or(false);
        let extension_allowed = relative
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| {
                identity
                    .input_extensions
                    .iter()
                    .any(|allowed| extension.eq_ignore_ascii_case(allowed))
            });
        in_allowed_root && extension_allowed
    });
    if !has_input {
        if identity.input_kind.as_deref() == Some("fzb1") {
            return Err(format!(
                "profiled {} result is missing its preserved original fzb1 input",
                resolved.kind.label()
            ));
        }
        return Err(format!(
            "profiled {} result is missing its preserved original input",
            resolved.kind.label()
        ));
    }
    Ok(())
}

fn validate_primary_identity(
    resolved: &ResolvedResult,
    primary: &serde_json::Value,
    files: &[ResultFile],
) -> Result<(), String> {
    let (id_field, supported_schemas): (&str, &[&str]) = match resolved.kind {
        ResultKind::Run => ("run_id", &["1.0", "1.1"]),
        ResultKind::Triage => ("triage_id", &["1.0", "1.1"]),
        ResultKind::Report => ("report_id", &["1.0", "1.1", "1.2", "1.3"]),
        ResultKind::Coverage => ("coverage_id", &["1.0", "2.0"]),
        ResultKind::Diagnostic => ("diagnostic_id", &["1"]),
    };
    let observed = primary
        .get(id_field)
        .or_else(|| {
            (resolved.kind == ResultKind::Coverage)
                .then(|| primary.get("run_id"))
                .flatten()
        })
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            if resolved.kind == ResultKind::Coverage {
                "result primary file is missing string coverage_id or run_id".to_string()
            } else {
                format!("result primary file is missing string {id_field}")
            }
        })?;
    let expected_suffix = resolved
        .id
        .split_once('-')
        .map(|(_, suffix)| suffix)
        .unwrap_or(resolved.id.as_str());
    if observed != resolved.id && observed != expected_suffix {
        return Err(format!(
            "result id mismatch: directory '{}' primary '{observed}'",
            resolved.id
        ));
    }
    if let Some(schema) = primary
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
    {
        if !supported_schemas.contains(&schema) {
            return Err(format!(
                "unsupported {} primary schema_version '{schema}'",
                resolved.kind.label()
            ));
        }
    } else if result_file_optional(files, Path::new("execution.json")).is_some() {
        return Err(format!(
            "profiled {} result is missing primary schema_version",
            resolved.kind.label()
        ));
    }
    Ok(())
}

fn validate_unclassified_evidence(
    resolved: &ResolvedResult,
    primary: &serde_json::Value,
    files: &[ResultFile],
    parent_execution: Option<&ExecutionReferences>,
    parent_profile: Option<&LoadedProfile>,
) -> Result<(), String> {
    if resolved.kind != ResultKind::Run {
        return Ok(());
    }
    let count = match primary.get("unclassified") {
        None => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| "run primary unclassified must be an unsigned integer".to_string())?,
    };
    let diagnostics = diagnostic_prefix_views(files)?;
    if count == 0 && diagnostics.is_empty() {
        return Ok(());
    }
    if count == 0 {
        return Err(
            "run contains diagnostic evidence but reports an unclassified count of zero"
                .to_string(),
        );
    }
    if diagnostics.is_empty() {
        return Err("unclassified run is missing diagnostic evidence".to_string());
    }
    if diagnostics.len() as u64 != count {
        return Err(format!(
            "unclassified run has {count} outcomes but {} complete diagnostic records",
            diagnostics.len()
        ));
    }
    let parent = parent_execution.ok_or_else(|| {
        "run diagnostic evidence cannot be validated without a parent execution".to_string()
    })?;
    let parent_profile = parent_profile.ok_or_else(|| {
        "run diagnostic evidence cannot be validated without a verified profile".to_string()
    })?;
    let parent_manifest: InputManifest = read_result_json(files, Path::new("input-manifest.json"))?;
    let mut parent_job_ids = BTreeSet::new();

    for (id, nested_files) in diagnostics {
        let nested = ResolvedResult {
            id: id.clone(),
            kind: ResultKind::Diagnostic,
            path: resolved.path.join("diagnostics").join(&id),
        };
        validate_result_file_allowlist(&nested, &nested_files)?;
        let record: DiagnosticRecord =
            read_result_json(&nested_files, Path::new("diagnostic.json"))?;
        validate_diagnostic_record(&nested, &record, Some(&nested_files))?;
        let nested_execution: ExecutionReferences =
            read_result_json(&nested_files, Path::new("execution.json"))?;
        if record.target_id != parent.target_id
            || !record
                .profile_sha256
                .eq_ignore_ascii_case(&parent.profile_sha256)
            || record.authorization != parent.authorization
            || record.qualification_sha256.as_deref() != parent.qualification_sha256.as_deref()
            || !attached_execution_identity_matches(&nested_execution, parent)
        {
            return Err(format!(
                "run diagnostic '{}' does not match the parent execution identity",
                nested.id
            ));
        }
        validate_diagnostic_replay_records(
            &nested,
            &nested_files,
            &record,
            &parent_profile.profile.coverage_scope.include_sources,
            &parent_profile.profile.coverage_scope.exclude_sources,
        )?;

        let nested_primary: serde_json::Value =
            read_result_json(&nested_files, Path::new("diagnostic.json"))?;
        validate_execution_structure(&nested, &nested_primary, &nested_execution)?;
        let nested_marker: ProfiledResultMarker =
            read_result_json(&nested_files, Path::new("profiled-result.json"))?;
        if nested_marker.schema_version != "1"
            || nested_marker.target_id != nested_execution.target_id
            || !nested_marker
                .profile_sha256
                .eq_ignore_ascii_case(&nested_execution.profile_sha256)
            || nested_marker.authorization != nested_execution.authorization
        {
            return Err(format!(
                "run diagnostic '{}' has an inconsistent profiled result marker",
                nested.id
            ));
        }
        validate_attached_diagnostic_manifest(&nested_files, &record, &nested_execution)?;

        let parent_result_id = record
            .parent_result_id
            .as_deref()
            .ok_or_else(|| format!("run diagnostic '{}' is missing parent_result_id", nested.id))?;
        let parent_job_id = record
            .parent_job_id
            .ok_or_else(|| format!("run diagnostic '{}' is missing parent_job_id", nested.id))?;
        let parent_input_path = record.parent_input_path.as_deref().ok_or_else(|| {
            format!(
                "run diagnostic '{}' is missing parent_input_path",
                nested.id
            )
        })?;
        let parent_input_sha256 = record.parent_input_sha256.as_deref().ok_or_else(|| {
            format!(
                "run diagnostic '{}' is missing parent_input_sha256",
                nested.id
            )
        })?;
        if parent_result_id != resolved.id {
            return Err(format!(
                "run diagnostic '{}' does not match parent result '{}'",
                nested.id, resolved.id
            ));
        }
        if !parent_job_ids.insert(parent_job_id) {
            return Err(format!(
                "run diagnostic evidence repeats parent job ID {parent_job_id}"
            ));
        }
        let parent_job_index = usize::try_from(parent_job_id)
            .map_err(|_| format!("parent job ID is too large: {parent_job_id}"))?;
        let parent_entry = parent_manifest.files.get(parent_job_index).ok_or_else(|| {
            format!(
                "run diagnostic '{}' names unknown parent job ID {parent_job_id}",
                nested.id
            )
        })?;
        if parent_entry.path != parent_input_path {
            return Err(format!(
                "run diagnostic '{}' parent input path does not match parent job {parent_job_id}",
                nested.id
            ));
        }
        let parent_input_file = result_file(files, Path::new(parent_input_path)).map_err(|_| {
            format!(
                "run diagnostic '{}' parent input is missing: {parent_input_path}",
                nested.id
            )
        })?;
        if !parent_entry
            .sha256
            .eq_ignore_ascii_case(parent_input_sha256)
            || !parent_input_file
                .sha256
                .eq_ignore_ascii_case(parent_input_sha256)
            || !record
                .input_sha256
                .eq_ignore_ascii_case(parent_input_sha256)
        {
            return Err(format!(
                "run diagnostic '{}' parent input sha256 does not match the run input manifest",
                nested.id
            ));
        }
        if Path::new(parent_input_path).file_name() != Path::new(&record.input_path).file_name() {
            return Err(format!(
                "run diagnostic '{}' parent input name does not match diagnostic input",
                nested.id
            ));
        }
    }
    Ok(())
}

fn attached_execution_identity_matches(
    nested: &ExecutionReferences,
    parent: &ExecutionReferences,
) -> bool {
    nested.target_id == parent.target_id
        && nested
            .profile_sha256
            .eq_ignore_ascii_case(&parent.profile_sha256)
        && nested.authorization == parent.authorization
        && nested.qualification_sha256 == parent.qualification_sha256
        && nested.validation_run == parent.validation_run
        && nested.format_revision == parent.format_revision
        && nested.loader_id == parent.loader_id
        && nested.loader_version == parent.loader_version
        && nested.backend == parent.backend
        && nested.depth == parent.depth
        && nested.allowed_env == parent.allowed_env
        && nested.tool_commit == parent.tool_commit
        && nested.tool_dirty == parent.tool_dirty
}

fn diagnostic_prefix_views(
    files: &[ResultFile],
) -> Result<BTreeMap<String, Vec<ResultFile>>, String> {
    let mut diagnostics = BTreeMap::<String, Vec<ResultFile>>::new();
    for file in files {
        let Ok(suffix) = file.relative.strip_prefix(Path::new("diagnostics")) else {
            continue;
        };
        let mut components = suffix.components();
        let id = match components.next() {
            Some(Component::Normal(value)) => value
                .to_str()
                .ok_or_else(|| "run diagnostic ID is not UTF-8".to_string())?
                .to_string(),
            _ => {
                return Err(format!(
                    "invalid run diagnostic evidence path: {}",
                    file.relative.display()
                ));
            }
        };
        validate_result_id(&id)?;
        if !id.starts_with("diagnostic-") {
            return Err(format!("unexpected run diagnostic entry: {id}"));
        }
        let mut nested_relative = PathBuf::new();
        for component in components {
            match component {
                Component::Normal(value) => nested_relative.push(value),
                _ => {
                    return Err(format!(
                        "invalid run diagnostic evidence path: {}",
                        file.relative.display()
                    ));
                }
            }
        }
        validate_relative_path(&nested_relative)?;
        let mut nested = file.clone();
        nested.relative = nested_relative;
        diagnostics.entry(id).or_default().push(nested);
    }
    for nested_files in diagnostics.values_mut() {
        nested_files.sort_by(|left, right| left.relative.cmp(&right.relative));
    }
    Ok(diagnostics)
}

fn validate_attached_diagnostic_manifest(
    files: &[ResultFile],
    record: &DiagnosticRecord,
    execution: &ExecutionReferences,
) -> Result<(), String> {
    let manifest_file = result_file(files, Path::new("input-manifest.json"))?;
    let expected_manifest_sha256 = execution.input_manifest_sha256.as_deref().ok_or_else(|| {
        "attached diagnostic execution is missing input_manifest_sha256".to_string()
    })?;
    if !manifest_file
        .sha256
        .eq_ignore_ascii_case(expected_manifest_sha256)
    {
        return Err(format!(
            "attached diagnostic input manifest sha256 mismatch: expected {expected_manifest_sha256}, observed {}",
            manifest_file.sha256
        ));
    }
    let manifest: InputManifest = read_result_json(files, Path::new("input-manifest.json"))?;
    if manifest.schema_version != "1" {
        return Err(format!(
            "unsupported attached diagnostic input manifest schema_version '{}'",
            manifest.schema_version
        ));
    }
    if manifest.files.len() != 1 {
        return Err("attached diagnostic input manifest must contain one file".to_string());
    }
    let entry = &manifest.files[0];
    let relative = Path::new(&entry.path);
    validate_relative_path(relative)?;
    if relative_path_text(relative)? != entry.path {
        return Err("attached diagnostic input manifest path is not canonical".to_string());
    }
    let parts = relative.components().collect::<Vec<_>>();
    if parts.len() != 2 || parts.first() != Some(&Component::Normal(OsStr::new("input"))) {
        return Err(format!(
            "attached diagnostic input manifest path is not allowed: {}",
            entry.path
        ));
    }
    validate_sha256_text("attached diagnostic input sha256", &entry.sha256)?;
    let input = result_file(files, relative)?;
    if input.bytes.len() as u64 != entry.size_bytes
        || !input.sha256.eq_ignore_ascii_case(&entry.sha256)
        || entry.path != record.input_path
        || !entry.sha256.eq_ignore_ascii_case(&record.input_sha256)
    {
        return Err("attached diagnostic input does not match its input manifest".to_string());
    }
    let observed_inputs = files
        .iter()
        .filter(|file| file.relative.starts_with(Path::new("input")))
        .map(|file| file.relative.clone())
        .collect::<BTreeSet<_>>();
    if observed_inputs != BTreeSet::from([relative.to_path_buf()]) {
        return Err(
            "attached diagnostic input manifest does not exactly cover its input snapshot"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_result_file_allowlist(
    resolved: &ResolvedResult,
    files: &[ResultFile],
) -> Result<(), String> {
    for file in files {
        let relative = &file.relative;
        let parts = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            })
            .collect::<Vec<_>>();
        let Some(first) = parts.first().copied() else {
            return Err("result contains an empty relative path".to_string());
        };
        if parts.iter().any(|part| part.starts_with('.')) {
            return Err(format!(
                "result file is not allowed for {}: {}",
                resolved.kind.label(),
                relative.display()
            ));
        }
        let allowed = match resolved.kind {
            ResultKind::Run => {
                (parts.len() == 1
                    && matches!(
                        first,
                        "status.json"
                            | "execution.json"
                            | "profiled-result.json"
                            | "input-manifest.json"
                            | "profile.json"
                            | "qualification.json"
                    ))
                    || matches!(
                        first,
                        "logs"
                            | "crash-inputs"
                            | "diagnostics"
                            | "backend-artifacts"
                            | "backend-crashes"
                            | "afl-out"
                            | "input"
                            | "inputs"
                    )
            }
            ResultKind::Triage => {
                (parts.len() == 1
                    && (matches!(
                        first,
                        "summary.json"
                            | "execution.json"
                            | "profiled-result.json"
                            | "input-manifest.json"
                            | "profile.json"
                            | "qualification.json"
                    ) || (first.starts_with("attempt-") && first.ends_with(".log"))))
                    || first == "input"
            }
            ResultKind::Report => {
                (parts.len() == 1
                    && (matches!(
                        first,
                        "meta.json"
                            | "report.md"
                            | "crash_report.txt"
                            | "repro.sh"
                            | "submission_draft.md"
                            | "manifest.json"
                            | "execution.json"
                            | "profiled-result.json"
                            | "input-manifest.json"
                    ) || (first.starts_with("report-") && first.ends_with("-evidence.zip"))))
                    || matches!(first, "poc" | "input")
            }
            ResultKind::Coverage => {
                (parts.len() == 1
                    && matches!(
                        first,
                        "summary.json"
                            | "execution.json"
                            | "profiled-result.json"
                            | "input-manifest.json"
                            | "coverage.json"
                            | "cov.profdata"
                            | "coverage-runner.sh"
                    ))
                    || matches!(first, "logs" | "raw" | "input" | "inputs")
            }
            ResultKind::Diagnostic => {
                (parts.len() == 1
                    && matches!(
                        first,
                        "diagnostic.json"
                            | "profile.json"
                            | "qualification.json"
                            | "execution.json"
                            | "profiled-result.json"
                            | "input-manifest.json"
                            | "traceback.txt"
                    ))
                    || (parts.len() == 2 && first == "input")
                    || (parts.len() == 2
                        && first == "replays"
                        && parts[1].starts_with("replay-")
                        && parts[1].ends_with(".json"))
            }
        };
        if !allowed {
            return Err(format!(
                "result file is not allowed for {}: {}",
                resolved.kind.label(),
                relative.display()
            ));
        }
    }
    Ok(())
}

fn validate_diagnostic_replay_records(
    resolved: &ResolvedResult,
    files: &[ResultFile],
    diagnostic: &DiagnosticRecord,
    include_sources: &[String],
    exclude_sources: &[String],
) -> Result<(), String> {
    if resolved.kind != ResultKind::Diagnostic {
        return Ok(());
    }
    let replay_files = files
        .iter()
        .filter(|file| file.relative.starts_with(Path::new("replays")))
        .collect::<Vec<_>>();
    if replay_files.is_empty() {
        return Ok(());
    }
    let original_traceback_file = result_file(files, Path::new(&diagnostic.traceback_path))?;
    let original_traceback = std::str::from_utf8(original_traceback_file.bytes.as_ref())
        .map_err(|_| "diagnostic replay source traceback is not UTF-8".to_string())?;
    let expected_original_fingerprint =
        traceback_fingerprint(original_traceback, include_sources, exclude_sources);

    let mut validation_runs = BTreeSet::new();
    for file in replay_files {
        let replay: DiagnosticReplayRecord = serde_json::from_slice(&file.bytes).map_err(|e| {
            format!(
                "failed to parse diagnostic replay record '{}': {e}",
                file.relative.display()
            )
        })?;
        if replay.schema_version != "1" {
            return Err(format!(
                "unsupported diagnostic replay record schema_version '{}'",
                replay.schema_version
            ));
        }
        if replay.diagnostic_id != resolved.id {
            return Err(format!(
                "diagnostic replay record ID mismatch: directory '{}' record '{}'",
                resolved.id, replay.diagnostic_id
            ));
        }
        validate_result_id(&replay.validation_run)?;
        if !replay.validation_run.starts_with("diagnostic-replay-") {
            return Err("diagnostic replay validation_run has an invalid prefix".to_string());
        }
        if !validation_runs.insert(replay.validation_run.clone()) {
            return Err(format!(
                "diagnostic replay validation_run is reused: {}",
                replay.validation_run
            ));
        }
        validate_sha256_text("diagnostic replay profile_sha256", &replay.profile_sha256)?;
        if !replay
            .profile_sha256
            .eq_ignore_ascii_case(&diagnostic.profile_sha256)
        {
            return Err(
                "diagnostic replay profile_sha256 does not match its diagnostic".to_string(),
            );
        }
        match (
            replay.profile_unchanged_after_execution,
            replay.identity_error.as_deref(),
        ) {
            (true, None) => {}
            (false, Some(error)) if !error.trim().is_empty() => {}
            _ => {
                return Err("diagnostic replay profile drift fields are inconsistent".to_string());
            }
        }
        if !(2..=100).contains(&replay.attempts)
            || replay.observations.len() != replay.attempts as usize
        {
            return Err(
                "diagnostic replay record attempts do not match its observations".to_string(),
            );
        }
        if !matches!(
            replay.result.as_str(),
            "reproduced" | "not_reproduced" | "incomplete"
        ) {
            return Err(format!(
                "unsupported diagnostic replay record result '{}'",
                replay.result
            ));
        }
        if replay.next_action.trim().is_empty() {
            return Err("diagnostic replay record next_action must be present".to_string());
        }
        if let Some(fingerprint) = &replay.original_fingerprint {
            validate_traceback_fingerprint(fingerprint)?;
        }
        if replay.original_fingerprint.as_ref() != expected_original_fingerprint.as_ref() {
            return Err(
                "diagnostic replay original fingerprint does not match its traceback evidence"
                    .to_string(),
            );
        }
        if let Some(link) = &replay.linked_triage {
            validate_linked_triage(resolved, diagnostic, &replay.validation_run, link)?;
        }
        let mut incomplete =
            !replay.profile_unchanged_after_execution || replay.original_fingerprint.is_none();
        let mut all_unclassified = true;
        let mut all_fingerprints_match = replay.original_fingerprint.is_some();
        let mut saw_library_crash = false;
        for (index, observation) in replay.observations.iter().enumerate() {
            if observation.attempt != (index + 1) as u32 {
                return Err(
                    "diagnostic replay record observations are not consecutively numbered"
                        .to_string(),
                );
            }
            if !matches!(
                observation.outcome.as_str(),
                "success" | "rejected" | "unclassified" | "unavailable" | "library_crash"
            ) {
                return Err(format!(
                    "unsupported diagnostic replay observation outcome '{}'",
                    observation.outcome
                ));
            }
            validate_sha256_text(
                "diagnostic replay observation detail_sha256",
                &observation.detail_sha256,
            )?;
            let observed_detail_sha256 = sha256_bytes(observation.detail.as_bytes())?;
            if !observed_detail_sha256.eq_ignore_ascii_case(&observation.detail_sha256) {
                return Err(format!(
                    "diagnostic replay observation {} detail sha256 mismatch",
                    observation.attempt
                ));
            }
            if let Some(fingerprint) = &observation.fingerprint {
                validate_traceback_fingerprint(fingerprint)?;
            }
            let expected_observation_fingerprint = if observation.outcome == "unclassified" {
                traceback_fingerprint(&observation.detail, include_sources, exclude_sources)
            } else {
                None
            };
            if observation.fingerprint.as_ref() != expected_observation_fingerprint.as_ref() {
                return Err(format!(
                    "diagnostic replay observation {} fingerprint does not match its detail evidence",
                    observation.attempt
                ));
            }
            match observation.outcome.as_str() {
                "unclassified" => match (
                    replay.original_fingerprint.as_ref(),
                    observation.fingerprint.as_ref(),
                ) {
                    (Some(original), Some(observed)) if observed == original => {}
                    (Some(_), Some(_)) => all_fingerprints_match = false,
                    (_, None) => {
                        incomplete = true;
                        all_fingerprints_match = false;
                    }
                    (None, Some(_)) => all_fingerprints_match = false,
                },
                "unavailable" => {
                    incomplete = true;
                    all_unclassified = false;
                    all_fingerprints_match = false;
                    if observation.fingerprint.is_some() {
                        return Err(
                            "non-unclassified replay observations cannot carry fingerprints"
                                .to_string(),
                        );
                    }
                }
                "library_crash" => {
                    incomplete = true;
                    saw_library_crash = true;
                    all_unclassified = false;
                    all_fingerprints_match = false;
                    if observation.fingerprint.is_some() {
                        return Err(
                            "non-unclassified replay observations cannot carry fingerprints"
                                .to_string(),
                        );
                    }
                }
                "success" | "rejected" => {
                    all_unclassified = false;
                    all_fingerprints_match = false;
                    if observation.fingerprint.is_some() {
                        return Err(
                            "non-unclassified replay observations cannot carry fingerprints"
                                .to_string(),
                        );
                    }
                }
                _ => unreachable!("outcome was validated above"),
            }
        }
        if saw_library_crash != replay.linked_triage.is_some() {
            return Err(
                "diagnostic replay linked_triage does not match its observations".to_string(),
            );
        }
        let expected_same = !incomplete && all_unclassified && all_fingerprints_match;
        let expected_result = if incomplete {
            "incomplete"
        } else if expected_same {
            "reproduced"
        } else {
            "not_reproduced"
        };
        if replay.same_exception_fingerprint != expected_same || replay.result != expected_result {
            return Err("diagnostic replay verdict does not match its observations".to_string());
        }
    }
    Ok(())
}

fn validate_linked_triage(
    diagnostic_result: &ResolvedResult,
    diagnostic: &DiagnosticRecord,
    replay_validation_run: &str,
    link: &DiagnosticReplayLinkedTriage,
) -> Result<(), String> {
    let DiagnosticReplayLinkedTriage::Created(created) = link else {
        let DiagnosticReplayLinkedTriage::Failed(failed) = link else {
            unreachable!("linked triage variants are exhaustive")
        };
        if failed.error.trim().is_empty() {
            return Err("failed diagnostic replay linked_triage must include an error".to_string());
        }
        return Ok(());
    };

    validate_result_id(&created.triage_id)?;
    if !created.triage_id.starts_with("triage-") {
        return Err("linked triage ID must name a triage result".to_string());
    }

    let data_root = if diagnostic.parent_result_id.is_some() {
        diagnostic_result
            .path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .and_then(Path::parent)
    } else {
        diagnostic_result.path.parent().and_then(Path::parent)
    }
    .ok_or_else(|| {
        format!(
            "cannot locate the result data root for linked triage from '{}'",
            diagnostic_result.path.display()
        )
    })?;
    let triage_path = data_root.join("triage").join(&created.triage_id);
    let expected_summary_path = absolute_path(&triage_path.join("summary.json"))?;
    if !created.summary_path.is_absolute() || created.summary_path != expected_summary_path {
        return Err(
            "linked triage summary_path does not match its result-local triage ID".to_string(),
        );
    }

    let triage_metadata = match fs::symlink_metadata(&triage_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "linked triage result does not exist: {}",
                created.triage_id
            ));
        }
        Err(error) => {
            return Err(format!(
                "failed to inspect linked triage result '{}': {error}",
                triage_path.display()
            ));
        }
    };
    if !triage_metadata.file_type().is_dir() {
        return Err(format!(
            "linked triage result does not exist as a real directory: {}",
            created.triage_id
        ));
    }
    ensure_no_symlink_components(data_root, "linked triage data root")?;
    ensure_no_symlink_components(&triage_path, "linked triage result path")?;

    let files = collect_result_files(&triage_path)?;
    let primary: serde_json::Value = read_result_json(&files, Path::new("summary.json"))?;
    let triage_result = ResolvedResult {
        id: created.triage_id.clone(),
        kind: ResultKind::Triage,
        path: triage_path,
    };
    let identity = validate_result(&triage_result, &primary, &files)?;
    if identity.target_id.as_deref() != Some(diagnostic.target_id.as_str()) {
        return Err("linked triage target does not match its diagnostic".to_string());
    }
    if !identity
        .profile_sha256
        .as_deref()
        .is_some_and(|profile| profile.eq_ignore_ascii_case(&diagnostic.profile_sha256))
    {
        return Err("linked triage profile does not match its diagnostic".to_string());
    }
    if identity.authorization.as_deref() != Some("unqualified_validation") {
        return Err(
            "linked triage authorization is not bound to diagnostic replay validation".to_string(),
        );
    }
    let execution: ExecutionReferences = read_result_json(&files, Path::new("execution.json"))?;
    if execution.validation_run.as_deref() != Some(replay_validation_run) {
        return Err(
            "linked triage validation_run does not match its diagnostic replay".to_string(),
        );
    }
    let manifest: InputManifest = read_result_json(&files, Path::new("input-manifest.json"))?;
    if manifest.files.len() != 1
        || !manifest.files[0]
            .sha256
            .eq_ignore_ascii_case(&diagnostic.input_sha256)
    {
        return Err("linked triage input does not match its diagnostic".to_string());
    }
    Ok(())
}

fn validate_traceback_fingerprint(fingerprint: &TracebackFingerprint) -> Result<(), String> {
    if fingerprint.exception_type.trim().is_empty()
        || fingerprint.target_frames.is_empty()
        || fingerprint
            .target_frames
            .iter()
            .any(|frame| frame.trim().is_empty())
    {
        return Err("diagnostic replay record contains an empty fingerprint".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux_result_reader {
    use super::{
        sha256_bytes, validate_relative_path, ResultFile, MAX_RESULT_FILES, MAX_RESULT_FILE_BYTES,
        MAX_RESULT_TOTAL_BYTES,
    };
    use std::{
        ffi::{CString, OsStr, OsString},
        fs::{self, File, Metadata},
        io::{self, Read},
        os::{
            fd::{AsRawFd, FromRawFd},
            raw::{c_char, c_int},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::{Component, Path, PathBuf},
    };

    const O_RDONLY: c_int = 0;
    const O_NONBLOCK: c_int = 0o4000;
    const O_DIRECTORY: c_int = 0o200000;
    const O_NOFOLLOW: c_int = 0o400000;
    const O_CLOEXEC: c_int = 0o2000000;
    const O_PATH: c_int = 0o10000000;
    const S_IFMT: u32 = 0o170000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFREG: u32 = 0o100000;
    const S_IFLNK: u32 = 0o120000;
    const MAX_RESULT_DEPTH: usize = 64;

    unsafe extern "C" {
        fn open(pathname: *const c_char, flags: c_int, ...) -> c_int;
        fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, ...) -> c_int;
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StableMetadata {
        device: u64,
        inode: u64,
        mode: u32,
        len: u64,
        modified_sec: i64,
        modified_nsec: i64,
        changed_sec: i64,
        changed_nsec: i64,
    }

    impl StableMetadata {
        fn from(metadata: &Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                len: metadata.len(),
                modified_sec: metadata.mtime(),
                modified_nsec: metadata.mtime_nsec(),
                changed_sec: metadata.ctime(),
                changed_nsec: metadata.ctime_nsec(),
            }
        }

        fn kind(self) -> u32 {
            self.mode & S_IFMT
        }

        fn is_directory(self) -> bool {
            self.kind() == S_IFDIR
        }

        fn is_regular(self) -> bool {
            self.kind() == S_IFREG
        }

        fn is_symlink(self) -> bool {
            self.kind() == S_IFLNK
        }
    }

    fn c_path(path: &Path) -> Result<CString, String> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("path contains NUL: {}", path.display()))
    }

    fn c_component(name: &OsStr) -> Result<CString, String> {
        CString::new(name.as_bytes()).map_err(|_| format!("path component contains NUL: {name:?}"))
    }

    fn owned_file(fd: c_int, action: &str) -> Result<File, String> {
        if fd < 0 {
            Err(format!("{action}: {}", io::Error::last_os_error()))
        } else {
            // SAFETY: a successful open/openat call returns one new descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn open_path_directory(path: &Path) -> Result<File, String> {
        let path_c = c_path(path)?;
        // SAFETY: path_c is NUL-terminated and remains alive for the call.
        let fd = unsafe {
            open(
                path_c.as_ptr(),
                O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            )
        };
        owned_file(
            fd,
            &format!("failed to open directory '{}'", path.display()),
        )
    }

    fn open_directory_at(parent: &File, name: &OsStr) -> Result<File, String> {
        let name_c = c_component(name)?;
        // SAFETY: parent is open and name_c is NUL-terminated for the call.
        let fd = unsafe {
            openat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            )
        };
        owned_file(fd, &format!("failed to open directory component {name:?}"))
    }

    fn open_directory(path: &Path) -> Result<File, String> {
        let mut directory = if path.is_absolute() {
            open_path_directory(Path::new("/"))?
        } else {
            open_path_directory(Path::new("."))?
        };
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => directory = open_directory_at(&directory, name)?,
                Component::ParentDir => {
                    directory = open_directory_at(&directory, OsStr::new(".."))?
                }
                Component::Prefix(_) => {
                    return Err(format!("unsupported directory path: {}", path.display()));
                }
            }
        }
        Ok(directory)
    }

    fn open_entry_at(parent: &File, name: &OsStr) -> Result<File, String> {
        let name_c = c_component(name)?;
        // SAFETY: parent is open and name_c is NUL-terminated for the call. O_PATH lets us
        // inspect every entry type without blocking on a FIFO or following a symlink.
        let fd = unsafe {
            openat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                O_PATH | O_NOFOLLOW | O_CLOEXEC,
            )
        };
        owned_file(fd, &format!("failed to open result entry {name:?}"))
    }

    fn descriptor_path(file: &File) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
    }

    fn open_readable_descriptor(file: &File, label: &str) -> Result<File, String> {
        let descriptor = descriptor_path(file);
        let descriptor_c = c_path(&descriptor)?;
        // SAFETY: descriptor_c is NUL-terminated and refers to the already-open object. Opening
        // through procfs cannot be redirected by a later pathname rename.
        let fd = unsafe { open(descriptor_c.as_ptr(), O_RDONLY | O_NONBLOCK | O_CLOEXEC) };
        owned_file(
            fd,
            &format!("failed to open {label} through its descriptor"),
        )
    }

    fn descriptor_metadata(file: &File, label: &str) -> Result<StableMetadata, String> {
        file.metadata()
            .map(|metadata| StableMetadata::from(&metadata))
            .map_err(|e| format!("failed to inspect {label} descriptor: {e}"))
    }

    fn ensure_unchanged(
        before: StableMetadata,
        after: StableMetadata,
        label: &str,
    ) -> Result<(), String> {
        if before == after {
            Ok(())
        } else {
            Err(format!("{label} changed while being read"))
        }
    }

    fn validate_entry_kind(metadata: StableMetadata, label: &str) -> Result<(), String> {
        if metadata.is_symlink() {
            Err(format!("result contains a symlink: {label}"))
        } else if metadata.is_regular() || metadata.is_directory() {
            Ok(())
        } else {
            Err(format!("result contains a special file: {label}"))
        }
    }

    fn read_open_regular(
        entry: &File,
        expected: StableMetadata,
        max_bytes: u64,
        label: &str,
    ) -> Result<Vec<u8>, String> {
        if !expected.is_regular() {
            if expected.is_symlink() {
                return Err(format!("{label} is a symlink"));
            }
            return Err(format!("{label} is not a regular file"));
        }
        if expected.len > max_bytes {
            return Err(format!("{label} exceeds {max_bytes} bytes"));
        }
        let mut readable = open_readable_descriptor(entry, label)?;
        let readable_before = descriptor_metadata(&readable, label)?;
        ensure_unchanged(expected, readable_before, label)?;
        let mut bytes =
            Vec::with_capacity(usize::try_from(expected.len.min(max_bytes)).unwrap_or_default());
        readable
            .by_ref()
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| format!("failed to read {label}: {e}"))?;
        if bytes.len() as u64 > max_bytes {
            return Err(format!("{label} exceeds {max_bytes} bytes"));
        }
        let readable_after = descriptor_metadata(&readable, label)?;
        ensure_unchanged(expected, readable_after, label)?;
        let path_after = descriptor_metadata(entry, label)?;
        ensure_unchanged(expected, path_after, label)?;
        if bytes.len() as u64 != expected.len {
            return Err(format!("{label} changed while being read"));
        }
        Ok(bytes)
    }

    fn directory_names(directory: &File, relative: &Path) -> Result<Vec<OsString>, String> {
        let descriptor = descriptor_path(directory);
        let mut names = fs::read_dir(&descriptor)
            .map_err(|e| {
                format!(
                    "failed to read result directory '{}': {e}",
                    relative.display()
                )
            })?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|e| format!("failed to read result entry: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    }

    fn walk_directory<F>(
        directory: &File,
        relative: &Path,
        depth: usize,
        entries_seen: &mut usize,
        files: &mut Vec<ResultFile>,
        total: &mut u64,
        hook: &mut F,
    ) -> Result<(), String>
    where
        F: FnMut(Option<&Path>),
    {
        if depth > MAX_RESULT_DEPTH {
            return Err(format!(
                "result directory depth limit ({MAX_RESULT_DEPTH}) exceeded"
            ));
        }
        let directory_label = if relative.as_os_str().is_empty() {
            "result root".to_string()
        } else {
            format!("result directory '{}'", relative.display())
        };
        let directory_before = descriptor_metadata(directory, &directory_label)?;
        if !directory_before.is_directory() {
            return Err(format!("{directory_label} is not a directory"));
        }
        for name in directory_names(directory, relative)? {
            *entries_seen = entries_seen
                .checked_add(1)
                .ok_or_else(|| "result entry count overflow".to_string())?;
            if *entries_seen > MAX_RESULT_FILES {
                return Err(format!(
                    "result contains more than {MAX_RESULT_FILES} entries"
                ));
            }
            let child_relative = relative.join(&name);
            validate_relative_path(&child_relative)?;
            let child_label = child_relative.display().to_string();
            let child = open_entry_at(directory, &name)?;
            let child_before = descriptor_metadata(&child, &child_label)?;
            hook(Some(&child_relative));
            validate_entry_kind(child_before, &child_label)?;
            if child_before.is_directory() {
                walk_directory(
                    &child,
                    &child_relative,
                    depth + 1,
                    entries_seen,
                    files,
                    total,
                    hook,
                )?;
            } else {
                let bytes = read_open_regular(
                    &child,
                    child_before,
                    MAX_RESULT_FILE_BYTES,
                    &format!("result file '{}'", child_relative.display()),
                )?;
                *total = total
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| "result total size overflow".to_string())?;
                if *total > MAX_RESULT_TOTAL_BYTES {
                    return Err("result files exceed total export size limit".to_string());
                }
                let sha256 = sha256_bytes(&bytes)?;
                files.push(ResultFile {
                    relative: child_relative.clone(),
                    bytes: bytes.into(),
                    sha256,
                });
                if files.len() > MAX_RESULT_FILES {
                    return Err(format!(
                        "result contains more than {MAX_RESULT_FILES} files"
                    ));
                }
            }
            let child_after = descriptor_metadata(&child, &child_label)?;
            ensure_unchanged(child_before, child_after, &child_label)?;
            let current = open_entry_at(directory, &name).map_err(|_| {
                format!(
                    "result entry '{}' changed while being read",
                    child_relative.display()
                )
            })?;
            let current_metadata = descriptor_metadata(&current, &child_label)?;
            ensure_unchanged(child_before, current_metadata, &child_label)?;
        }
        let directory_after = descriptor_metadata(directory, &directory_label)?;
        ensure_unchanged(directory_before, directory_after, &directory_label)
    }

    pub(super) fn collect<F>(root: &Path, mut hook: F) -> Result<Vec<ResultFile>, String>
    where
        F: FnMut(Option<&Path>),
    {
        let root_directory = open_directory(root)?;
        let root_before = descriptor_metadata(&root_directory, "result root")?;
        if !root_before.is_directory() {
            return Err(format!(
                "result root is not a directory: {}",
                root.display()
            ));
        }
        hook(None);
        let mut files = Vec::new();
        let mut total = 0u64;
        let mut entries_seen = 0usize;
        walk_directory(
            &root_directory,
            Path::new(""),
            0,
            &mut entries_seen,
            &mut files,
            &mut total,
            &mut hook,
        )?;
        let root_after = descriptor_metadata(&root_directory, "result root")?;
        ensure_unchanged(root_before, root_after, "result root")?;
        let current_root =
            open_directory(root).map_err(|_| "result root changed while being read".to_string())?;
        let current_root_metadata = descriptor_metadata(&current_root, "current result root")?;
        ensure_unchanged(root_before, current_root_metadata, "result root")?;
        files.sort_by(|left, right| left.relative.cmp(&right.relative));
        Ok(files)
    }

    pub(super) fn read_file<F>(
        path: &Path,
        max_bytes: u64,
        label: &str,
        mut hook: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnMut(),
    {
        let name = path
            .file_name()
            .ok_or_else(|| format!("{label} has no filename: {}", path.display()))?;
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = open_directory(parent_path)
            .map_err(|e| format!("failed to open parent of {label} '{}': {e}", path.display()))?;
        let parent_before = descriptor_metadata(&parent, &format!("{label} parent"))?;
        let entry = open_entry_at(&parent, name)
            .map_err(|e| format!("missing or unreadable {label} '{}': {e}", path.display()))?;
        let entry_before = descriptor_metadata(&entry, label)?;
        hook();
        let bytes = read_open_regular(&entry, entry_before, max_bytes, label)?;
        let current_entry = open_entry_at(&parent, name)
            .map_err(|_| format!("{label} changed while being read: {}", path.display()))?;
        let current_entry_metadata = descriptor_metadata(&current_entry, label)?;
        ensure_unchanged(entry_before, current_entry_metadata, label)?;
        let parent_after = descriptor_metadata(&parent, &format!("{label} parent"))?;
        ensure_unchanged(parent_before, parent_after, &format!("{label} parent"))?;
        let current_parent = open_directory(parent_path)
            .map_err(|_| format!("{label} parent changed while being read"))?;
        let current_parent_metadata =
            descriptor_metadata(&current_parent, &format!("{label} parent"))?;
        ensure_unchanged(
            parent_before,
            current_parent_metadata,
            &format!("{label} parent"),
        )?;
        Ok(bytes)
    }
}

#[cfg(target_os = "linux")]
fn collect_result_files(root: &Path) -> Result<Vec<ResultFile>, String> {
    linux_result_reader::collect(root, |_| {})
}

#[cfg(not(target_os = "linux"))]
fn collect_result_files(_root: &Path) -> Result<Vec<ResultFile>, String> {
    Err("secure result collection requires Linux descriptor semantics".to_string())
}

#[cfg(all(test, target_os = "linux"))]
fn collect_result_files_with_hook<F>(root: &Path, hook: F) -> Result<Vec<ResultFile>, String>
where
    F: FnMut(Option<&Path>),
{
    linux_result_reader::collect(root, hook)
}

#[cfg(all(test, not(target_os = "linux")))]
fn collect_result_files_with_hook<F>(_root: &Path, _hook: F) -> Result<Vec<ResultFile>, String>
where
    F: FnMut(Option<&Path>),
{
    Err("secure result collection requires Linux descriptor semantics".to_string())
}

fn result_file<'a>(files: &'a [ResultFile], relative: &Path) -> Result<&'a ResultFile, String> {
    result_file_optional(files, relative)
        .ok_or_else(|| format!("result is missing required file: {}", relative.display()))
}

fn result_file_optional<'a>(files: &'a [ResultFile], relative: &Path) -> Option<&'a ResultFile> {
    files.iter().find(|file| file.relative == relative)
}

fn read_result_json<T: for<'de> Deserialize<'de>>(
    files: &[ResultFile],
    relative: &Path,
) -> Result<T, String> {
    let file = result_file(files, relative)?;
    if file.bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(format!(
            "result JSON exceeds {MAX_JSON_BYTES} bytes: {}",
            relative.display()
        ));
    }
    serde_json::from_slice(&file.bytes)
        .map_err(|e| format!("failed to parse result JSON '{}': {e}", relative.display()))
}

fn copy_snapshot_file(
    file: &ResultFile,
    export_root: &Path,
    relative: &Path,
) -> Result<ManifestEntry, String> {
    validate_relative_path(relative)?;
    let destination = export_root.join(relative);
    write_new_file(&destination, &file.bytes)?;
    Ok(ManifestEntry {
        path: relative_path_text(relative)?,
        size_bytes: file.bytes.len() as u64,
        sha256: file.sha256.clone(),
    })
}

fn copy_identity_file(
    identity: &IdentityFile,
    export_root: &Path,
    relative: &Path,
) -> Result<ManifestEntry, String> {
    let observed = sha256_bytes(&identity.bytes)?;
    if !observed.eq_ignore_ascii_case(&identity.sha256) {
        return Err(format!(
            "identity snapshot sha256 mismatch for '{}': expected {}, observed {observed}",
            identity.source.display(),
            identity.sha256
        ));
    }
    validate_relative_path(relative)?;
    write_new_file(&export_root.join(relative), &identity.bytes)?;
    Ok(ManifestEntry {
        path: relative_path_text(relative)?,
        size_bytes: identity.bytes.len() as u64,
        sha256: observed,
    })
}

fn confined_relative_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative = Path::new(relative);
    validate_relative_path(relative)?;
    Ok(root.join(relative))
}

fn validate_relative_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "path is not a confined relative path: {}",
            path.display()
        ));
    }
    Ok(())
}

fn relative_path_text(path: &Path) -> Result<String, String> {
    validate_relative_path(path)?;
    path.components()
        .map(|component| match component {
            Component::Normal(value) => value
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| format!("manifest path is not UTF-8: {}", path.display())),
            _ => Err(format!("manifest path is invalid: {}", path.display())),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join("/"))
}

fn ensure_real_directory(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(format!(
            "{label} is not a real directory: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)
            .map_err(|e| format!("failed to create {label} '{}': {e}", path.display())),
        Err(error) => Err(format!(
            "failed to inspect {label} '{}': {error}",
            path.display()
        )),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn read_regular_file(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    linux_result_reader::read_file(path, max_bytes, label, || {})
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_regular_file(
    _path: &Path,
    _max_bytes: u64,
    _label: &str,
) -> Result<Vec<u8>, String> {
    Err("secure regular-file reads require Linux descriptor semantics".to_string())
}

#[cfg(all(test, target_os = "linux"))]
fn read_regular_file_with_open_hook<F>(
    path: &Path,
    max_bytes: u64,
    label: &str,
    hook: F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(),
{
    linux_result_reader::read_file(path, max_bytes, label, hook)
}

#[cfg(all(test, not(target_os = "linux")))]
fn read_regular_file_with_open_hook<F>(
    _path: &Path,
    _max_bytes: u64,
    _label: &str,
    _hook: F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(),
{
    Err("secure regular-file reads require Linux descriptor semantics".to_string())
}

fn verify_file_hash(path: &Path, expected: &str, label: &str) -> Result<(), String> {
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} expected sha256 is invalid"));
    }
    let bytes = read_regular_file(path, MAX_RESULT_FILE_BYTES, label)?;
    let observed = sha256_bytes(&bytes)?;
    if !observed.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "{label} sha256 mismatch: expected {expected}, observed {observed}"
        ));
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes = read_regular_file(path, MAX_JSON_BYTES, "JSON file")?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse JSON '{}': {e}", path.display()))
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| {
        format!(
            "failed to create output directory '{}': {e}",
            parent.display()
        )
    })?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("failed to create output '{}': {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("failed to write output '{}': {e}", path.display()))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|e| format!("failed to create private output '{}': {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("failed to write private output '{}': {e}", path.display()))
}

fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("failed to open output '{}': {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("failed to replace output '{}': {e}", path.display()))
}

fn unique_suffix() -> String {
    format!(
        "{}-{}-{}",
        now_unix_millis(),
        std::process::id(),
        NEXT_ARTIFACT_ID.fetch_add(1, Ordering::Relaxed)
    )
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .map_err(|e| format!("failed to resolve current directory: {e}"))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use super::{
        attached_execution_identity_matches, collect_result_files_with_hook,
        extract_supervised_traceback, read_regular_file_with_open_hook, stage_input, unique_suffix,
        validate_result_id, ExecutionReferences,
    };

    #[test]
    fn result_ids_are_names_not_paths() {
        for valid in ["run-1", "diagnostic-a_b.c-9"] {
            validate_result_id(valid).expect("plain ID should be valid");
        }
        for invalid in ["", ".", "..", "../run-1", "run/1", "run 1", "런-1"] {
            assert!(validate_result_id(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn supervised_traceback_uses_the_last_exact_marker_line() {
        let output = concat!(
            "exception text TOOL_UNCLASSIFIED_JSON=\"embedded\"\n",
            "TOOL_UNCLASSIFIED_JSON=\"forged\"\n",
            "ordinary stderr\n",
            "TOOL_UNCLASSIFIED_JSON=\"trusted traceback\"\n",
        );
        assert_eq!(
            extract_supervised_traceback(output).as_deref(),
            Some("trusted traceback")
        );
    }

    fn execution_identity_fixture() -> ExecutionReferences {
        serde_json::from_value(serde_json::json!({
            "schema_version": "1",
            "profile_path": "/tmp/profile.json",
            "profile_sha256": "a".repeat(64),
            "authorization": "qualified",
            "qualification_path": "/tmp/qualification.json",
            "qualification_sha256": "b".repeat(64),
            "validation_run": null,
            "target_id": "onnx",
            "format_revision": "onnx-ir-v10",
            "loader_id": "fixture",
            "loader_version": "1",
            "backend": "local-harness",
            "depth": "session",
            "argv": ["tool", "run"],
            "allowed_env": {},
            "corpus_snapshot_sha256": "c".repeat(64),
            "input_manifest_sha256": "d".repeat(64),
            "tool_commit": null,
            "tool_dirty": null,
            "started_unix_ms": 1,
            "ended_unix_ms": 2,
            "elapsed_ms": 1,
            "outcome": "failed",
            "profile_unchanged_after_execution": true,
            "identity_error": null
        }))
        .expect("execution fixture")
    }

    #[test]
    fn attached_execution_must_match_parent_loader_and_backend_identity() {
        let parent = execution_identity_fixture();
        assert!(attached_execution_identity_matches(
            &execution_identity_fixture(),
            &parent
        ));

        let mut nested = execution_identity_fixture();
        nested.format_revision = "other-format".to_string();
        assert!(!attached_execution_identity_matches(&nested, &parent));
        let mut nested = execution_identity_fixture();
        nested.loader_id = "other-loader".to_string();
        assert!(!attached_execution_identity_matches(&nested, &parent));
        let mut nested = execution_identity_fixture();
        nested.loader_version = "2".to_string();
        assert!(!attached_execution_identity_matches(&nested, &parent));
        let mut nested = execution_identity_fixture();
        nested.depth = "shallow".to_string();
        assert!(!attached_execution_identity_matches(&nested, &parent));
        let mut nested = execution_identity_fixture();
        nested.backend = "diagnostic".to_string();
        assert!(!attached_execution_identity_matches(&nested, &parent));
    }

    #[cfg(unix)]
    #[test]
    fn staged_profile_input_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let source = PathBuf::from("/tmp").join(format!("tool-profile-source-{}", unique_suffix()));
        fs::write(&source, b"private input").expect("write source");
        let staged = stage_input(&source).expect("stage input");
        let root_mode = fs::metadata(&staged.root)
            .expect("staging root metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(staged.path())
            .expect("staged file metadata")
            .permissions()
            .mode()
            & 0o777;
        let evidence_mode = fs::metadata(staged.evidence_path())
            .expect("staged evidence metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        assert_eq!(evidence_mode, 0o600);
        fs::write(staged.path(), b"mutated working copy").expect("mutate working input");
        assert_eq!(
            fs::read(staged.evidence_path()).expect("read evidence input"),
            b"private input"
        );
        fs::remove_file(source).expect("remove source");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn result_collection_rejects_root_replacement_after_open() {
        let parent =
            PathBuf::from("/tmp").join(format!("tool-result-reader-root-swap-{}", unique_suffix()));
        let root = parent.join("run-test");
        let moved = parent.join("moved");
        fs::create_dir_all(&root).expect("create result root");
        fs::write(root.join("status.json"), b"original").expect("write original");

        let mut swapped = false;
        let result = collect_result_files_with_hook(&root, |relative| {
            if relative.is_none() && !swapped {
                fs::rename(&root, &moved).expect("rename opened root");
                fs::create_dir(&root).expect("create replacement root");
                fs::write(root.join("status.json"), b"replacement").expect("write replacement");
                swapped = true;
            }
        });

        assert!(swapped, "root-open hook did not run");
        assert!(result
            .expect_err("root replacement must fail closed")
            .contains("changed while being read"));
        fs::remove_dir_all(parent).expect("remove test tree");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn result_collection_rejects_entry_rename_swap_after_open() {
        let parent =
            PathBuf::from("/tmp").join(format!("tool-result-reader-file-swap-{}", unique_suffix()));
        let root = parent.join("run-test");
        let moved = root.join("status-original.json");
        fs::create_dir_all(&root).expect("create result root");
        fs::write(root.join("status.json"), b"original").expect("write original");

        let mut swapped = false;
        let result = collect_result_files_with_hook(&root, |relative| {
            if relative == Some(Path::new("status.json")) && !swapped {
                fs::rename(root.join("status.json"), &moved).expect("rename opened file");
                fs::write(root.join("status.json"), b"replacement").expect("write replacement");
                swapped = true;
            }
        });

        assert!(swapped, "entry-open hook did not run");
        assert!(result
            .expect_err("entry replacement must fail closed")
            .contains("changed while being read"));
        fs::remove_dir_all(parent).expect("remove test tree");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn regular_file_read_rejects_path_replacement_after_open() {
        let parent = PathBuf::from("/tmp")
            .join(format!("tool-result-reader-input-swap-{}", unique_suffix()));
        let source = parent.join("input.onnx");
        let moved = parent.join("input-original.onnx");
        fs::create_dir_all(&parent).expect("create input parent");
        fs::write(&source, b"original").expect("write original");

        let result = read_regular_file_with_open_hook(&source, 1024, "test input", || {
            fs::rename(&source, &moved).expect("rename opened input");
            fs::write(&source, b"replacement").expect("write replacement input");
        });

        assert!(result
            .expect_err("input replacement must fail closed")
            .contains("changed while being read"));
        fs::remove_dir_all(parent).expect("remove test tree");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn result_collection_rejects_symlinks_and_special_files() {
        use std::{
            ffi::CString,
            os::{
                raw::c_char,
                unix::{ffi::OsStrExt, fs::symlink},
            },
        };

        unsafe extern "C" {
            fn mkfifo(pathname: *const c_char, mode: u32) -> i32;
        }

        let parent =
            PathBuf::from("/tmp").join(format!("tool-result-reader-types-{}", unique_suffix()));
        let symlink_root = parent.join("run-symlink");
        let special_root = parent.join("run-special");
        fs::create_dir_all(&symlink_root).expect("create symlink result root");
        fs::create_dir_all(&special_root).expect("create special result root");
        fs::write(parent.join("outside"), b"outside").expect("write symlink target");
        symlink(parent.join("outside"), symlink_root.join("status.json"))
            .expect("create result symlink");
        let fifo = special_root.join("status.json");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path has no NUL");
        // SAFETY: fifo_c is NUL-terminated and remains alive for the call.
        assert_eq!(
            unsafe { mkfifo(fifo_c.as_ptr(), 0o600) },
            0,
            "create result FIFO"
        );

        assert!(collect_result_files_with_hook(&symlink_root, |_| {})
            .expect_err("symlink must fail closed")
            .contains("symlink"));
        assert!(collect_result_files_with_hook(&special_root, |_| {})
            .expect_err("special file must fail closed")
            .contains("special file"));
        fs::remove_dir_all(parent).expect("remove test tree");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn result_collection_bounds_empty_directory_depth() {
        let parent =
            PathBuf::from("/tmp").join(format!("tool-result-reader-depth-{}", unique_suffix()));
        let root = parent.join("run-test");
        let mut nested = root.clone();
        for _ in 0..65 {
            nested.push("d");
        }
        fs::create_dir_all(&nested).expect("create deep result tree");

        assert!(collect_result_files_with_hook(&root, |_| {})
            .expect_err("deep result tree must fail closed")
            .contains("depth limit"));
        fs::remove_dir_all(parent).expect("remove test tree");
    }
}
