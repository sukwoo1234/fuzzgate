use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde::{
    de::{DeserializeOwned, Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};

use crate::{
    common::sha256_file,
    target::{target_label, TargetKind},
};

pub(crate) const MAX_PROFILE_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_QUALIFICATION_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetProfile {
    pub(crate) schema_version: String,
    pub(crate) target_id: String,
    pub(crate) format_revision: String,
    pub(crate) loader_id: String,
    pub(crate) loader_version: String,
    pub(crate) source_artifacts: Vec<SourceArtifact>,
    pub(crate) patches: Vec<PatchIdentity>,
    pub(crate) toolchain: Toolchain,
    pub(crate) sanitizer_policy: SanitizerPolicy,
    pub(crate) binaries: Vec<BinaryIdentity>,
    pub(crate) input_kind: InputKind,
    pub(crate) depth: String,
    pub(crate) engine_capabilities: Vec<EngineCapability>,
    pub(crate) limits: ProfileLimits,
    pub(crate) coverage_scope: CoverageScope,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceArtifact {
    pub(crate) url: String,
    pub(crate) tag: String,
    pub(crate) resolved_commit: String,
    pub(crate) sha256: String,
    pub(crate) size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PatchIdentity {
    pub(crate) order: u32,
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Toolchain {
    pub(crate) compiler: ToolIdentity,
    pub(crate) linker: ToolIdentity,
    pub(crate) engine: ToolIdentity,
    pub(crate) python: Option<ToolIdentity>,
    pub(crate) rust: Option<ToolIdentity>,
    #[serde(default)]
    pub(crate) environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolIdentity {
    pub(crate) version: String,
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SanitizerPolicy {
    pub(crate) compile_flags: Vec<String>,
    pub(crate) recovery: String,
    pub(crate) runtime_env: BTreeMap<String, String>,
    pub(crate) rust_panic: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BinaryIdentity {
    pub(crate) role: String,
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
    pub(crate) argv: Vec<String>,
    #[serde(default)]
    pub(crate) linked_libraries: Vec<FileIdentity>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIdentity {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputKind {
    pub(crate) kind: String,
    pub(crate) extensions: Vec<String>,
    #[serde(default)]
    pub(crate) subformats: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineCapability {
    pub(crate) backend: String,
    pub(crate) binary_role: String,
    pub(crate) required_mode: String,
    pub(crate) instrumentation_scope: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileLimits {
    pub(crate) max_input_bytes: u64,
    pub(crate) memory_bytes: u64,
    pub(crate) input_timeout_ms: u64,
    pub(crate) block_timeout_ms: u64,
    pub(crate) threads: u32,
    pub(crate) workers: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoverageScope {
    pub(crate) unit: String,
    pub(crate) include_sources: Vec<String>,
    #[serde(default)]
    pub(crate) exclude_sources: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct LoadedProfile {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) profile: TargetProfile,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedProfile {
    pub(crate) loaded: LoadedProfile,
    verified_files: Vec<VerifiedFile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Qualification {
    pub(crate) schema_version: String,
    pub(crate) profile_sha256: String,
    pub(crate) status: String,
    pub(crate) gate_evidence: Vec<QualificationEvidence>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationEvidence {
    pub(crate) requirement_id: String,
    pub(crate) evidence_sha256: String,
}

#[derive(Clone, Debug)]
pub(crate) struct LoadedQualification {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) qualification: Qualification,
}

#[derive(Clone, Debug)]
struct VerifiedFile {
    label: String,
    path: PathBuf,
    sha256: String,
    executable: bool,
}

pub(crate) fn load_profile(
    path: &Path,
    requested_target: &TargetKind,
) -> Result<LoadedProfile, String> {
    if !path.is_absolute() {
        return Err(format!(
            "target profile path must be absolute: {}",
            path.display()
        ));
    }
    let metadata = regular_file_metadata(path, "target profile")?;
    if metadata.len() > MAX_PROFILE_BYTES {
        return Err(format!(
            "target profile exceeds {} bytes: {}",
            MAX_PROFILE_BYTES,
            path.display()
        ));
    }
    let bytes = fs::read(path)
        .map_err(|e| format!("failed to read target profile '{}': {e}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(format!(
            "target profile changed while being read: {}",
            path.display()
        ));
    }
    if bytes.is_empty() {
        return Err(format!("target profile is empty: {}", path.display()));
    }

    load_profile_snapshot(path, &bytes, requested_target)
}

pub(crate) fn load_profile_snapshot(
    path: &Path,
    bytes: &[u8],
    requested_target: &TargetKind,
) -> Result<LoadedProfile, String> {
    if !path.is_absolute() {
        return Err(format!(
            "target profile path must be absolute: {}",
            path.display()
        ));
    }
    if bytes.len() as u64 > MAX_PROFILE_BYTES {
        return Err(format!(
            "target profile exceeds {} bytes: {}",
            MAX_PROFILE_BYTES,
            path.display()
        ));
    }
    if bytes.is_empty() {
        return Err(format!("target profile is empty: {}", path.display()));
    }

    let profile: TargetProfile = parse_unique_json(bytes, "target profile")?;
    validate_profile(&profile, requested_target)?;
    let sha256 = sha256_bytes(bytes)?;

    Ok(LoadedProfile {
        path: path.to_path_buf(),
        sha256,
        bytes: bytes.to_vec(),
        profile,
    })
}

pub(crate) fn verify_profile_files(loaded: LoadedProfile) -> Result<VerifiedProfile, String> {
    verify_loaded_bytes_unchanged(&loaded)?;

    verify_profile_snapshot_files(loaded)
}

pub(crate) fn verify_profile_snapshot_files(
    loaded: LoadedProfile,
) -> Result<VerifiedProfile, String> {
    let mut files = Vec::new();
    for (label, tool) in [
        ("toolchain.compiler", &loaded.profile.toolchain.compiler),
        ("toolchain.linker", &loaded.profile.toolchain.linker),
        ("toolchain.engine", &loaded.profile.toolchain.engine),
    ] {
        files.push(VerifiedFile {
            label: label.to_string(),
            path: tool.path.clone(),
            sha256: tool.sha256.clone(),
            executable: true,
        });
    }
    if let Some(tool) = &loaded.profile.toolchain.python {
        files.push(VerifiedFile {
            label: "toolchain.python".to_string(),
            path: tool.path.clone(),
            sha256: tool.sha256.clone(),
            executable: true,
        });
    }
    if let Some(tool) = &loaded.profile.toolchain.rust {
        files.push(VerifiedFile {
            label: "toolchain.rust".to_string(),
            path: tool.path.clone(),
            sha256: tool.sha256.clone(),
            executable: true,
        });
    }
    for (index, patch) in loaded.profile.patches.iter().enumerate() {
        files.push(VerifiedFile {
            label: format!("patches[{index}]"),
            path: patch.path.clone(),
            sha256: patch.sha256.clone(),
            executable: false,
        });
    }
    for (index, binary) in loaded.profile.binaries.iter().enumerate() {
        files.push(VerifiedFile {
            label: format!("binaries[{index}]"),
            path: binary.path.clone(),
            sha256: binary.sha256.clone(),
            executable: true,
        });
        for (library_index, library) in binary.linked_libraries.iter().enumerate() {
            files.push(VerifiedFile {
                label: format!("binaries[{index}].linked_libraries[{library_index}]"),
                path: library.path.clone(),
                sha256: library.sha256.clone(),
                executable: false,
            });
        }
    }

    verify_file_identities(&files)?;
    Ok(VerifiedProfile {
        loaded,
        verified_files: files,
    })
}

pub(crate) fn load_qualification(
    verified: &VerifiedProfile,
) -> Result<LoadedQualification, String> {
    let parent = verified
        .loaded
        .path
        .parent()
        .ok_or_else(|| "target profile has no parent directory".to_string())?;
    let path = parent.join("qualification.json");
    let metadata = regular_file_metadata(&path, "profile qualification")?;
    if metadata.len() > MAX_QUALIFICATION_BYTES {
        return Err(format!(
            "profile qualification exceeds {} bytes: {}",
            MAX_QUALIFICATION_BYTES,
            path.display()
        ));
    }
    let bytes = fs::read(&path).map_err(|e| {
        format!(
            "failed to read profile qualification '{}': {e}",
            path.display()
        )
    })?;
    if bytes.len() as u64 != metadata.len() || bytes.is_empty() {
        return Err(format!(
            "profile qualification is empty or changed while being read: {}",
            path.display()
        ));
    }

    load_qualification_snapshot(verified, &path, &bytes)
}

pub(crate) fn load_qualification_snapshot(
    verified: &VerifiedProfile,
    path: &Path,
    bytes: &[u8],
) -> Result<LoadedQualification, String> {
    load_qualification_snapshot_for_profile(&verified.loaded, path, bytes)
}

pub(crate) fn load_qualification_snapshot_for_profile(
    loaded: &LoadedProfile,
    path: &Path,
    bytes: &[u8],
) -> Result<LoadedQualification, String> {
    if !path.is_absolute() {
        return Err(format!(
            "profile qualification path must be absolute: {}",
            path.display()
        ));
    }
    if bytes.len() as u64 > MAX_QUALIFICATION_BYTES {
        return Err(format!(
            "profile qualification exceeds {} bytes: {}",
            MAX_QUALIFICATION_BYTES,
            path.display()
        ));
    }
    if bytes.is_empty() {
        return Err(format!(
            "profile qualification is empty: {}",
            path.display()
        ));
    }
    let qualification: Qualification = parse_unique_json(bytes, "profile qualification")?;
    validate_qualification(&qualification, &loaded.sha256)?;
    let sha256 = sha256_bytes(bytes)?;
    Ok(LoadedQualification {
        path: path.to_path_buf(),
        sha256,
        bytes: bytes.to_vec(),
        qualification,
    })
}

impl VerifiedProfile {
    pub(crate) fn ensure_unchanged(&self) -> Result<(), String> {
        verify_loaded_bytes_unchanged(&self.loaded)?;
        verify_file_identities(&self.verified_files)
    }

    pub(crate) fn binary(&self, role: &str) -> Option<&BinaryIdentity> {
        self.loaded
            .profile
            .binaries
            .iter()
            .find(|binary| binary.role == role)
    }
}

impl LoadedQualification {
    pub(crate) fn ensure_unchanged(&self) -> Result<(), String> {
        let metadata = regular_file_metadata(&self.path, "profile qualification")?;
        if metadata.len() > MAX_QUALIFICATION_BYTES {
            return Err(format!(
                "profile qualification exceeds {} bytes: {}",
                MAX_QUALIFICATION_BYTES,
                self.path.display()
            ));
        }
        let current = fs::read(&self.path).map_err(|e| {
            format!(
                "failed to re-read profile qualification '{}': {e}",
                self.path.display()
            )
        })?;
        let current_hash = sha256_bytes(&current)?;
        if current_hash != self.sha256 || current != self.bytes {
            return Err(format!(
                "profile qualification changed after loading: {}",
                self.path.display()
            ));
        }
        Ok(())
    }
}

fn validate_qualification(
    qualification: &Qualification,
    profile_sha256: &str,
) -> Result<(), String> {
    if qualification.schema_version != "1" {
        return Err(format!(
            "unsupported qualification schema_version '{}'; expected '1'",
            qualification.schema_version
        ));
    }
    validate_hash(
        "qualification.profile_sha256",
        &qualification.profile_sha256,
    )?;
    if !qualification
        .profile_sha256
        .eq_ignore_ascii_case(profile_sha256)
    {
        return Err(format!(
            "qualification profile_sha256 mismatch: expected {profile_sha256}, observed {}",
            qualification.profile_sha256
        ));
    }
    if !matches!(qualification.status.as_str(), "verified" | "smoke_passed") {
        return Err("qualification.status must be verified or smoke_passed".to_string());
    }
    if qualification.gate_evidence.is_empty() {
        return Err("qualification.gate_evidence must not be empty".to_string());
    }
    let mut requirements = BTreeSet::new();
    for (index, evidence) in qualification.gate_evidence.iter().enumerate() {
        if !matches_requirement_id(&evidence.requirement_id) {
            return Err(format!(
                "qualification.gate_evidence[{index}].requirement_id is invalid: {}",
                evidence.requirement_id
            ));
        }
        if !requirements.insert(evidence.requirement_id.as_str()) {
            return Err(format!(
                "qualification contains duplicate requirement_id '{}'",
                evidence.requirement_id
            ));
        }
        validate_hash(
            &format!("qualification.gate_evidence[{index}].evidence_sha256"),
            &evidence.evidence_sha256,
        )?;
    }
    if qualification.status == "verified" {
        let expected = (1..=12)
            .map(|number| format!("Q{number:02}"))
            .collect::<BTreeSet<_>>();
        let observed = requirements
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        if observed != expected {
            return Err(
                "verified qualification must contain each requirement Q01 through Q12 exactly once"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn matches_requirement_id(value: &str) -> bool {
    value.len() == 3
        && value.starts_with('Q')
        && value[1..].bytes().all(|byte| byte.is_ascii_digit())
        && value[1..]
            .parse::<u8>()
            .is_ok_and(|number| (1..=12).contains(&number))
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> Result<String, String> {
    for (program, args) in [("sha256sum", vec!["-"]), ("shasum", vec!["-a", "256", "-"])] {
        let mut child = match Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("failed to start {program}: {e}")),
        };
        child
            .stdin
            .take()
            .ok_or_else(|| format!("failed to open {program} stdin"))?
            .write_all(bytes)
            .map_err(|e| format!("failed to send bytes to {program}: {e}"))?;
        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed to wait for {program}: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "{program} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|_| format!("{program} returned non-UTF-8 output"))?;
        let hash = stdout
            .split_whitespace()
            .next()
            .ok_or_else(|| format!("{program} returned no sha256"))?;
        validate_hash("computed sha256", hash)?;
        return Ok(hash.to_ascii_lowercase());
    }
    Err("sha256 tool not found (sha256sum/shasum)".to_string())
}

fn regular_file_metadata(path: &Path, label: &str) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| {
        format!(
            "{label} is not a readable regular file '{}': {e}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular file, not a symlink or directory: {}",
            path.display()
        ));
    }
    Ok(metadata)
}

fn verify_loaded_bytes_unchanged(loaded: &LoadedProfile) -> Result<(), String> {
    let metadata = regular_file_metadata(&loaded.path, "target profile")?;
    if metadata.len() > MAX_PROFILE_BYTES {
        return Err(format!(
            "target profile exceeds {} bytes: {}",
            MAX_PROFILE_BYTES,
            loaded.path.display()
        ));
    }
    let current = fs::read(&loaded.path).map_err(|e| {
        format!(
            "failed to re-read target profile '{}': {e}",
            loaded.path.display()
        )
    })?;
    let current_hash = sha256_bytes(&current)?;
    if current_hash != loaded.sha256 || current != loaded.bytes {
        return Err(format!(
            "target profile changed after loading: {}",
            loaded.path.display()
        ));
    }
    Ok(())
}

fn verify_file_identities(files: &[VerifiedFile]) -> Result<(), String> {
    let mut measured = BTreeMap::<PathBuf, String>::new();
    for file in files {
        if !file.path.is_absolute() {
            return Err(format!(
                "{} path must be absolute: {}",
                file.label,
                file.path.display()
            ));
        }
        let metadata = regular_file_metadata(&file.path, &file.label)?;
        if file.executable && !is_executable(&metadata) {
            return Err(format!(
                "{} is not executable: {}",
                file.label,
                file.path.display()
            ));
        }
        let actual = if let Some(hash) = measured.get(&file.path) {
            hash.clone()
        } else {
            let hash = sha256_file(&file.path)?;
            measured.insert(file.path.clone(), hash.clone());
            hash
        };
        if !actual.eq_ignore_ascii_case(&file.sha256) {
            return Err(format!(
                "{} sha256 mismatch for '{}': expected {}, observed {}",
                file.label,
                file.path.display(),
                file.sha256,
                actual
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    true
}

fn validate_profile(profile: &TargetProfile, requested_target: &TargetKind) -> Result<(), String> {
    if profile.schema_version != "1" {
        return Err(format!(
            "unsupported schema_version '{}'; expected '1'",
            profile.schema_version
        ));
    }
    if profile.target_id != target_label(requested_target) {
        return Err(format!(
            "target mismatch: requested '{}', profile names '{}'",
            target_label(requested_target),
            profile.target_id
        ));
    }
    validate_id("target_id", &profile.target_id)?;
    validate_text("format_revision", &profile.format_revision)?;
    validate_id("loader_id", &profile.loader_id)?;
    validate_text("loader_version", &profile.loader_version)?;

    if profile.source_artifacts.is_empty() {
        return Err("source_artifacts must not be empty".to_string());
    }
    for (index, source) in profile.source_artifacts.iter().enumerate() {
        if !source.url.starts_with("https://") {
            return Err(format!("source_artifacts[{index}].url must use https"));
        }
        validate_text(&format!("source_artifacts[{index}].tag"), &source.tag)?;
        validate_text(
            &format!("source_artifacts[{index}].resolved_commit"),
            &source.resolved_commit,
        )?;
        validate_hash(&format!("source_artifacts[{index}].sha256"), &source.sha256)?;
        if source.size_bytes == 0 {
            return Err(format!("source_artifacts[{index}].size_bytes must be >= 1"));
        }
    }

    for (index, patch) in profile.patches.iter().enumerate() {
        let expected_order = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if patch.order != expected_order {
            return Err(format!(
                "patches[{index}].order must be {expected_order}, observed {}",
                patch.order
            ));
        }
        validate_absolute_path(&format!("patches[{index}].path"), &patch.path)?;
        validate_hash(&format!("patches[{index}].sha256"), &patch.sha256)?;
    }

    for (label, tool) in [
        ("toolchain.compiler", &profile.toolchain.compiler),
        ("toolchain.linker", &profile.toolchain.linker),
        ("toolchain.engine", &profile.toolchain.engine),
    ] {
        validate_tool(label, tool)?;
    }
    if let Some(tool) = &profile.toolchain.python {
        validate_tool("toolchain.python", tool)?;
    }
    if let Some(tool) = &profile.toolchain.rust {
        validate_tool("toolchain.rust", tool)?;
    }
    validate_environment("toolchain.environment", &profile.toolchain.environment)?;

    if profile.sanitizer_policy.compile_flags.is_empty() {
        return Err("sanitizer_policy.compile_flags must not be empty".to_string());
    }
    for (index, flag) in profile.sanitizer_policy.compile_flags.iter().enumerate() {
        validate_text(&format!("sanitizer_policy.compile_flags[{index}]"), flag)?;
    }
    if !matches!(
        profile.sanitizer_policy.recovery.as_str(),
        "abort" | "recover" | "trap"
    ) {
        return Err("sanitizer_policy.recovery must be abort, recover, or trap".to_string());
    }
    if !matches!(
        profile.sanitizer_policy.rust_panic.as_str(),
        "abort" | "unwind"
    ) {
        return Err("sanitizer_policy.rust_panic must be abort or unwind".to_string());
    }
    if profile.sanitizer_policy.runtime_env.is_empty() {
        return Err("sanitizer_policy.runtime_env must not be empty".to_string());
    }
    validate_environment(
        "sanitizer_policy.runtime_env",
        &profile.sanitizer_policy.runtime_env,
    )?;

    if profile.binaries.is_empty() {
        return Err("binaries must not be empty".to_string());
    }
    let mut roles = BTreeSet::new();
    for (index, binary) in profile.binaries.iter().enumerate() {
        validate_id(&format!("binaries[{index}].role"), &binary.role)?;
        if !roles.insert(binary.role.as_str()) {
            return Err(format!("duplicate binary role '{}'", binary.role));
        }
        validate_absolute_path(&format!("binaries[{index}].path"), &binary.path)?;
        validate_hash(&format!("binaries[{index}].sha256"), &binary.sha256)?;
        validate_argv(&format!("binaries[{index}].argv"), &binary.argv)?;
        for (library_index, library) in binary.linked_libraries.iter().enumerate() {
            validate_absolute_path(
                &format!("binaries[{index}].linked_libraries[{library_index}].path"),
                &library.path,
            )?;
            validate_hash(
                &format!("binaries[{index}].linked_libraries[{library_index}].sha256"),
                &library.sha256,
            )?;
        }
    }
    if !roles.contains("replay") {
        return Err("binaries must contain the replay role".to_string());
    }
    let replay = profile
        .binaries
        .iter()
        .find(|binary| binary.role == "replay")
        .expect("role checked above");
    if replay
        .argv
        .iter()
        .filter(|arg| arg.as_str() == "{input}")
        .count()
        != 1
    {
        return Err("the replay argv must contain {input} exactly once".to_string());
    }

    if !matches!(profile.input_kind.kind.as_str(), "single" | "fzb1") {
        return Err("input_kind.kind must be single or fzb1".to_string());
    }
    if profile.input_kind.extensions.is_empty() {
        return Err("input_kind.extensions must not be empty".to_string());
    }
    validate_unique_labels(
        "input_kind.extensions",
        &profile.input_kind.extensions,
        true,
    )?;
    validate_unique_labels(
        "input_kind.subformats",
        &profile.input_kind.subformats,
        false,
    )?;
    validate_depth(&profile.target_id, &profile.depth)?;

    if profile.engine_capabilities.is_empty() {
        return Err("engine_capabilities must not be empty".to_string());
    }
    let mut backends = BTreeSet::new();
    for (index, capability) in profile.engine_capabilities.iter().enumerate() {
        if !matches!(
            capability.backend.as_str(),
            "local-harness" | "aflpp" | "libfuzzer" | "coverage"
        ) {
            return Err(format!(
                "engine_capabilities[{index}].backend is unsupported: {}",
                capability.backend
            ));
        }
        if !backends.insert(capability.backend.as_str()) {
            return Err(format!(
                "duplicate engine capability backend '{}'",
                capability.backend
            ));
        }
        if !roles.contains(capability.binary_role.as_str()) {
            return Err(format!(
                "engine_capabilities[{index}].binary_role '{}' does not exist",
                capability.binary_role
            ));
        }
        validate_text(
            &format!("engine_capabilities[{index}].required_mode"),
            &capability.required_mode,
        )?;
        validate_text(
            &format!("engine_capabilities[{index}].instrumentation_scope"),
            &capability.instrumentation_scope,
        )?;
    }
    if !backends.contains("local-harness") {
        return Err("engine_capabilities must include local-harness".to_string());
    }

    for (label, value) in [
        ("limits.max_input_bytes", profile.limits.max_input_bytes),
        ("limits.memory_bytes", profile.limits.memory_bytes),
        ("limits.input_timeout_ms", profile.limits.input_timeout_ms),
        ("limits.block_timeout_ms", profile.limits.block_timeout_ms),
        ("limits.threads", u64::from(profile.limits.threads)),
        ("limits.workers", u64::from(profile.limits.workers)),
    ] {
        if value == 0 {
            return Err(format!("{label} must be >= 1"));
        }
    }
    if profile.limits.input_timeout_ms > profile.limits.block_timeout_ms {
        return Err("limits.input_timeout_ms must not exceed block_timeout_ms".to_string());
    }

    validate_id("coverage_scope.unit", &profile.coverage_scope.unit)?;
    if profile.coverage_scope.include_sources.is_empty() {
        return Err("coverage_scope.include_sources must not be empty".to_string());
    }
    validate_unique_labels(
        "coverage_scope.include_sources",
        &profile.coverage_scope.include_sources,
        false,
    )?;
    validate_unique_labels(
        "coverage_scope.exclude_sources",
        &profile.coverage_scope.exclude_sources,
        false,
    )?;
    Ok(())
}

fn validate_tool(label: &str, tool: &ToolIdentity) -> Result<(), String> {
    validate_text(&format!("{label}.version"), &tool.version)?;
    validate_absolute_path(&format!("{label}.path"), &tool.path)?;
    validate_hash(&format!("{label}.sha256"), &tool.sha256)
}

fn validate_text(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > 4096 || value.contains('\0') || value.contains(['\r', '\n']) {
        return Err(format!(
            "{label} contains invalid characters or is too long"
        ));
    }
    Ok(())
}

fn validate_id(label: &str, value: &str) -> Result<(), String> {
    validate_text(label, value)?;
    if value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(format!("{label} is not a safe identifier"));
    }
    Ok(())
}

fn validate_hash(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a non-empty 64-digit sha256"));
    }
    if value.bytes().all(|byte| byte == b'0') {
        return Err(format!("{label} must not be an all-zero placeholder"));
    }
    Ok(())
}

fn validate_absolute_path(label: &str, path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{label} must be absolute: {}", path.display()));
    }
    Ok(())
}

fn validate_environment(label: &str, environment: &BTreeMap<String, String>) -> Result<(), String> {
    const ALLOWED: &[&str] = &[
        "ASAN_OPTIONS",
        "GGUF_FUZZ_DEPTH",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LSAN_OPTIONS",
        "MKL_NUM_THREADS",
        "MSAN_OPTIONS",
        "NUMEXPR_NUM_THREADS",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "PATH",
        "RUST_BACKTRACE",
        "RUST_MIN_STACK",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TSAN_OPTIONS",
        "TZ",
        "UBSAN_OPTIONS",
        "VECLIB_MAXIMUM_THREADS",
    ];
    for (key, value) in environment {
        if !ALLOWED.contains(&key.as_str()) {
            return Err(format!("{label} contains disallowed key '{key}'"));
        }
        validate_text(&format!("{label}.{key}"), value)?;
    }
    Ok(())
}

fn validate_argv(label: &str, argv: &[String]) -> Result<(), String> {
    if argv.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    const PLACEHOLDERS: &[&str] = &[
        "{artifact_dir}",
        "{corpus_dir}",
        "{input}",
        "{restart_limit}",
        "{run_dir}",
        "{timeout_sec}",
        "{worker_id}",
        "{workers}",
    ];
    for (index, arg) in argv.iter().enumerate() {
        validate_text(&format!("{label}[{index}]"), arg)?;
        if (arg.contains('{') || arg.contains('}')) && !PLACEHOLDERS.contains(&arg.as_str()) {
            return Err(format!(
                "{label}[{index}] contains an unsupported placeholder"
            ));
        }
    }
    Ok(())
}

fn validate_unique_labels(label: &str, values: &[String], extension: bool) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        validate_text(&format!("{label}[{index}]"), value)?;
        if extension
            && (value.starts_with('.')
                || value.contains('/')
                || value.contains('\\')
                || !value
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')))
        {
            return Err(format!("{label}[{index}] is not a plain extension"));
        }
        if !seen.insert(value.as_str()) {
            return Err(format!("{label} contains duplicate '{value}'"));
        }
    }
    Ok(())
}

fn validate_depth(target: &str, depth: &str) -> Result<(), String> {
    let accepted = match target {
        "gguf" => matches!(depth, "metadata" | "tensor-info" | "full"),
        "onnx" => depth == "session",
        "safetensors" => depth == "deserialize",
        _ => false,
    };
    if accepted {
        Ok(())
    } else {
        Err(format!("unsupported depth '{depth}' for target '{target}'"))
    }
}

fn parse_unique_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueJson::deserialize(&mut deserializer)
        .map_err(|e| format!("invalid {label} JSON: {e}"))?;
    deserializer
        .end()
        .map_err(|e| format!("invalid {label} JSON: {e}"))?;
    serde_json::from_value(value.0).map_err(|e| format!("invalid {label}: {e}"))
}

struct UniqueJson(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            values.push(value.0);
        }
        Ok(UniqueJson(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate key '{key}'")));
            }
            let value = map.next_value::<UniqueJson>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueJson(serde_json::Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use serde_json::{json, Value};

    use super::{load_profile, verify_profile_files};
    use crate::{common::sha256_file, target::TargetKind};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        profile_path: PathBuf,
        binary_path: PathBuf,
        value: Value,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "tool-target-profile-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("create fixture root");
        root
    }

    fn write_executable(path: &Path, body: &str) {
        fs::write(path, body).expect("write fixture executable");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(path).expect("fixture metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("make fixture executable");
        }
    }

    fn fixture(label: &str) -> Fixture {
        let root = temp_root(label);
        let binary_path = root.join("replay");
        write_executable(&binary_path, "#!/bin/sh\nexit 0\n");
        let hash = sha256_file(&binary_path).expect("hash fixture executable");
        let profile_path = root.join("profile.json");
        let file_identity = || {
            json!({
                "version": "1.0",
                "path": binary_path,
                "sha256": hash,
            })
        };
        let value = json!({
            "schema_version": "1",
            "target_id": "onnx",
            "format_revision": "onnx-ir-v10",
            "loader_id": "onnxruntime",
            "loader_version": "1.23.2",
            "source_artifacts": [{
                "url": "https://github.com/microsoft/onnxruntime/archive/refs/tags/v1.23.2.tar.gz",
                "tag": "v1.23.2",
                "resolved_commit": "0123456789abcdef0123456789abcdef01234567",
                "sha256": hash,
                "size_bytes": 17
            }],
            "patches": [],
            "toolchain": {
                "compiler": file_identity(),
                "linker": file_identity(),
                "engine": file_identity(),
                "python": null,
                "rust": file_identity(),
                "environment": {"PATH": "/usr/bin:/bin"}
            },
            "sanitizer_policy": {
                "compile_flags": ["-fsanitize=address"],
                "recovery": "abort",
                "runtime_env": {"ASAN_OPTIONS": "abort_on_error=1"},
                "rust_panic": "abort"
            },
            "binaries": [{
                "role": "replay",
                "path": binary_path,
                "sha256": hash,
                "argv": ["{input}"],
                "linked_libraries": []
            }],
            "input_kind": {
                "kind": "single",
                "extensions": ["onnx"],
                "subformats": ["modelproto"]
            },
            "depth": "session",
            "engine_capabilities": [{
                "backend": "local-harness",
                "binary_role": "replay",
                "required_mode": "native",
                "instrumentation_scope": "onnxruntime"
            }],
            "limits": {
                "max_input_bytes": 1048576,
                "memory_bytes": 1073741824,
                "input_timeout_ms": 5000,
                "block_timeout_ms": 30000,
                "threads": 1,
                "workers": 2
            },
            "coverage_scope": {
                "unit": "source-line",
                "include_sources": ["onnxruntime/core"],
                "exclude_sources": []
            }
        });
        Fixture {
            root,
            profile_path,
            binary_path,
            value,
        }
    }

    fn write_profile(fixture: &Fixture, value: &Value) {
        fs::write(
            &fixture.profile_path,
            serde_json::to_vec_pretty(value).expect("serialize fixture profile"),
        )
        .expect("write fixture profile");
    }

    fn verified_fixture(label: &str) -> (Fixture, super::VerifiedProfile) {
        let fixture = fixture(label);
        write_profile(&fixture, &fixture.value);
        let loaded = load_profile(&fixture.profile_path, &TargetKind::Onnx).unwrap();
        let verified = verify_profile_files(loaded).unwrap();
        (fixture, verified)
    }

    fn qualification_value(profile_sha256: &str) -> Value {
        let gates = (1..=12)
            .map(|number| {
                json!({
                    "requirement_id": format!("Q{number:02}"),
                    "evidence_sha256": profile_sha256,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schema_version": "1",
            "profile_sha256": profile_sha256,
            "status": "verified",
            "gate_evidence": gates,
        })
    }

    fn load_error(fixture: &Fixture) -> String {
        load_profile(&fixture.profile_path, &TargetKind::Onnx)
            .expect_err("profile must be rejected")
    }

    #[test]
    fn a_valid_typed_profile_loads_and_verifies_its_files() {
        let fixture = fixture("valid");
        write_profile(&fixture, &fixture.value);

        let loaded = load_profile(&fixture.profile_path, &TargetKind::Onnx)
            .expect("valid profile should load");
        assert_eq!(loaded.profile.target_id, "onnx");
        assert_eq!(loaded.bytes, fs::read(&fixture.profile_path).unwrap());
        verify_profile_files(loaded).expect("unchanged profile files should verify");
    }

    #[test]
    fn duplicate_keys_are_rejected_before_typed_deserialization() {
        let fixture = fixture("duplicate");
        let bytes = serde_json::to_vec(&fixture.value).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let duplicate = text.replacen(
            "\"schema_version\":\"1\"",
            "\"schema_version\":\"1\",\"schema_version\":\"1\"",
            1,
        );
        fs::write(&fixture.profile_path, duplicate).unwrap();

        assert!(load_error(&fixture).contains("duplicate key"));
    }

    #[test]
    fn unknown_schema_fields_are_rejected() {
        let mut fixture = fixture("unknown-field");
        fixture.value["qualification"] = json!({"status": "verified"});
        write_profile(&fixture, &fixture.value);

        assert!(load_error(&fixture).contains("unknown field"));
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let mut fixture = fixture("schema");
        fixture.value["schema_version"] = json!("2");
        write_profile(&fixture, &fixture.value);

        assert!(load_error(&fixture).contains("unsupported schema_version"));
    }

    #[test]
    fn empty_identity_hash_is_rejected() {
        let mut fixture = fixture("empty-hash");
        fixture.value["binaries"][0]["sha256"] = json!("");
        write_profile(&fixture, &fixture.value);

        assert!(load_error(&fixture).contains("binaries[0].sha256"));
    }

    #[test]
    fn requested_target_must_match_the_profile() {
        let mut fixture = fixture("target-mismatch");
        fixture.value["target_id"] = json!("gguf");
        write_profile(&fixture, &fixture.value);

        assert!(load_error(&fixture).contains("target mismatch"));
    }

    #[test]
    fn changed_binary_is_rejected_after_the_profile_loads() {
        let fixture = fixture("changed-binary");
        write_profile(&fixture, &fixture.value);
        let loaded = load_profile(&fixture.profile_path, &TargetKind::Onnx)
            .expect("profile should load before file verification");
        write_executable(&fixture.binary_path, "#!/bin/sh\nexit 7\n");

        let err = verify_profile_files(loaded).expect_err("changed binary must fail");
        assert!(err.contains("sha256 mismatch"));
    }

    #[test]
    fn a_profile_path_must_be_absolute_and_regular() {
        let fixture = fixture("absolute");
        write_profile(&fixture, &fixture.value);

        let err = load_profile(Path::new("profile.json"), &TargetKind::Onnx)
            .expect_err("relative profile path must fail");
        assert!(err.contains("absolute"));

        #[cfg(unix)]
        {
            let link = fixture.root.join("profile-link.json");
            std::os::unix::fs::symlink(&fixture.profile_path, &link).unwrap();
            let err =
                load_profile(&link, &TargetKind::Onnx).expect_err("symlinked profile must fail");
            assert!(err.contains("regular file"));
        }
    }

    #[test]
    fn verified_qualification_binds_all_gates_to_the_profile_hash() {
        let (fixture, verified) = verified_fixture("qualification");
        let qualification = qualification_value(&verified.loaded.sha256);
        fs::write(
            fixture.root.join("qualification.json"),
            serde_json::to_vec_pretty(&qualification).unwrap(),
        )
        .unwrap();

        let loaded =
            super::load_qualification(&verified).expect("matching qualification should load");
        assert_eq!(loaded.qualification.gate_evidence.len(), 12);
        assert_eq!(loaded.qualification.status, "verified");
    }

    #[test]
    fn qualification_rejects_a_different_profile_hash() {
        let (fixture, verified) = verified_fixture("qualification-mismatch");
        let other_hash = "a".repeat(64);
        let qualification = qualification_value(&other_hash);
        fs::write(
            fixture.root.join("qualification.json"),
            serde_json::to_vec_pretty(&qualification).unwrap(),
        )
        .unwrap();

        let err = super::load_qualification(&verified)
            .expect_err("qualification for another profile must fail");
        assert!(err.contains("profile_sha256 mismatch"));
    }

    #[test]
    fn qualification_cannot_embed_a_self_hash_cycle() {
        let (fixture, verified) = verified_fixture("qualification-cycle");
        let mut qualification = qualification_value(&verified.loaded.sha256);
        qualification["qualification_sha256"] = json!("b".repeat(64));
        fs::write(
            fixture.root.join("qualification.json"),
            serde_json::to_vec_pretty(&qualification).unwrap(),
        )
        .unwrap();

        let err = super::load_qualification(&verified)
            .expect_err("self-referential qualification identity must fail");
        assert!(err.contains("unknown field"));
    }
}
