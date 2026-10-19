use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use crate::{
    common::{
        command_with_core_dump_off, first_line, now_unix_millis, output_with_deadline,
        output_with_deadline_ms, sha256_file, AppPaths,
    },
    target::{target_label, HarnessError, TargetKind},
    target_profiles::{
        load_profile, load_qualification, verify_profile_files, LoadedQualification,
        VerifiedProfile,
    },
};

pub(crate) const TARGET_PROFILE_ENV: &str = "TOOL_TARGET_PROFILE";
pub(crate) const PROFILE_CHILD_ENV: &str = "TOOL_PROFILE_CHILD";
pub(crate) const PROFILE_SHA256_ENV: &str = "TOOL_PROFILE_SHA256";
pub(crate) const VALIDATION_RUN_ENV: &str = "TOOL_VALIDATION_RUN";
pub(crate) const QUALIFICATION_PATH_ENV: &str = "TOOL_PROFILE_QUALIFICATION";
pub(crate) const QUALIFICATION_SHA256_ENV: &str = "TOOL_PROFILE_QUALIFICATION_SHA256";

#[derive(Clone, Debug)]
enum ProfileAuthorization {
    Qualified(LoadedQualification),
    Validation { evidence_id: String },
}

#[derive(Clone, Debug)]
pub(crate) struct ExecutionContext {
    pub(crate) profile: VerifiedProfile,
    authorization: ProfileAuthorization,
    allowed_env: BTreeMap<OsString, OsString>,
}

#[derive(Clone, Debug)]
pub(crate) struct CommandSpec {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<OsString>,
}

pub(crate) fn resolve_execution_context(
    cli_profile: Option<&Path>,
    validation_run: Option<&str>,
    target: &TargetKind,
) -> Result<Option<ExecutionContext>, String> {
    let env_profile = std::env::var_os(TARGET_PROFILE_ENV).map(PathBuf::from);
    let profile = resolve_profile_selection(cli_profile, env_profile.as_deref(), target)?;

    let env_validation = std::env::var(VALIDATION_RUN_ENV).ok();
    let selected_validation = match (validation_run, env_validation.as_deref()) {
        (Some(cli), Some(env)) if cli != env => {
            return Err(format!(
                "CLI/environment validation-run conflict: CLI '{cli}', environment '{env}'"
            ));
        }
        (Some(cli), _) => Some(cli.to_string()),
        (None, Some(env)) => Some(env.to_string()),
        (None, None) => None,
    };

    let Some(profile) = profile else {
        if selected_validation.is_some() {
            return Err("--validation-run requires a target profile".to_string());
        }
        return Ok(None);
    };

    if let Some(expected) = std::env::var_os(PROFILE_SHA256_ENV) {
        let expected = expected
            .to_str()
            .ok_or_else(|| format!("{PROFILE_SHA256_ENV} must be UTF-8"))?;
        if !expected.eq_ignore_ascii_case(&profile.loaded.sha256) {
            return Err(format!(
                "{PROFILE_SHA256_ENV} mismatch: expected {}, observed {expected}",
                profile.loaded.sha256
            ));
        }
    }
    if let Some(marker) = std::env::var_os(PROFILE_CHILD_ENV) {
        if !profile_child_marker(Some(&marker)) {
            return Err(format!(
                "{PROFILE_CHILD_ENV} must be exactly 1 when present"
            ));
        }
    }

    build_execution_context_with_env(
        profile,
        selected_validation.as_deref(),
        std::env::vars_os().collect(),
    )
    .map(Some)
}

pub(crate) fn is_profile_child() -> bool {
    profile_child_marker(std::env::var_os(PROFILE_CHILD_ENV).as_deref())
}

fn profile_child_marker(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

fn resolve_profile_selection(
    cli_profile: Option<&Path>,
    env_profile: Option<&Path>,
    target: &TargetKind,
) -> Result<Option<VerifiedProfile>, String> {
    let load = |path: &Path| verify_profile_files(load_profile(path, target)?);
    match (cli_profile, env_profile) {
        (None, None) => Ok(None),
        (Some(path), None) | (None, Some(path)) => load(path).map(Some),
        (Some(cli), Some(env)) if cli == env => load(cli).map(Some),
        (Some(cli), Some(env)) => {
            let cli_profile = load(cli)?;
            let env_profile = load(env)?;
            if cli_profile.loaded.sha256 != env_profile.loaded.sha256
                || cli_profile.loaded.bytes != env_profile.loaded.bytes
            {
                return Err(format!(
                    "CLI/environment profile conflict: '{}' and '{}' have different bytes",
                    cli.display(),
                    env.display()
                ));
            }
            Ok(Some(cli_profile))
        }
    }
}

fn build_execution_context_with_env(
    profile: VerifiedProfile,
    validation_run: Option<&str>,
    inherited: Vec<(OsString, OsString)>,
) -> Result<ExecutionContext, String> {
    profile.ensure_unchanged()?;
    if let Some(id) = validation_run {
        validate_evidence_id(id)?;
    }

    const LEGACY_OVERRIDES: &[&str] = &[
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONHOME",
        "PYTHONPATH",
        "TOOL_AFLPP_CMD",
        "TOOL_COVERAGE_GGUF_CMD",
        "TOOL_COVERAGE_ONNX_CMD",
        "TOOL_COVERAGE_SAFETENSORS_CMD",
        "TOOL_EXTERNAL_HARNESS_CMD",
        "TOOL_GGUF_HARNESS_CMD",
        "TOOL_GGUF_PROBE",
        "TOOL_LIBFUZZER_CMD",
        "TOOL_ONNX_HARNESS_CMD",
        "TOOL_ONNX_NATIVE_REPLAY",
        "TOOL_REQUIRE_LIBRARY_CONNECT",
        "TOOL_SAFETENSORS_HARNESS_CMD",
        "TOOL_SAFETENSORS_PROBE",
    ];
    const OS_ALLOWLIST: &[&str] = &[
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "WINDIR",
    ];

    let inherited = inherited.into_iter().collect::<BTreeMap<_, _>>();
    for key in LEGACY_OVERRIDES {
        if inherited.contains_key(OsStr::new(key)) {
            return Err(format!(
                "legacy environment override {key} is forbidden with a target profile"
            ));
        }
    }

    let mut profile_env = BTreeMap::<OsString, OsString>::new();
    for (key, value) in profile
        .loaded
        .profile
        .toolchain
        .environment
        .iter()
        .chain(profile.loaded.profile.sanitizer_policy.runtime_env.iter())
    {
        let key = OsString::from(key);
        let value = OsString::from(value);
        if let Some(existing) = profile_env.insert(key.clone(), value.clone()) {
            if existing != value {
                return Err(format!(
                    "profile environment defines '{}' with conflicting values",
                    key.to_string_lossy()
                ));
            }
        }
    }
    let mut allowed_env = BTreeMap::new();
    for key in OS_ALLOWLIST {
        if let Some(value) = inherited.get(OsStr::new(key)) {
            allowed_env.insert(OsString::from(key), value.clone());
        }
    }
    for (key, value) in profile_env {
        allowed_env.insert(key, value);
    }

    let authorization = if let Some(evidence_id) = validation_run {
        ProfileAuthorization::Validation {
            evidence_id: evidence_id.to_string(),
        }
    } else {
        let qualification = load_qualification(&profile)?;
        if qualification.qualification.status != "verified" {
            return Err(format!(
                "profile qualification status '{}' cannot authorize general execution",
                qualification.qualification.status
            ));
        }
        ProfileAuthorization::Qualified(qualification)
    };
    validate_inherited_authorization(&authorization, &inherited)?;

    Ok(ExecutionContext {
        profile,
        authorization,
        allowed_env,
    })
}

fn validate_inherited_authorization(
    authorization: &ProfileAuthorization,
    inherited: &BTreeMap<OsString, OsString>,
) -> Result<(), String> {
    let inherited_path = inherited.get(OsStr::new(QUALIFICATION_PATH_ENV));
    let inherited_hash = inherited.get(OsStr::new(QUALIFICATION_SHA256_ENV));
    match authorization {
        ProfileAuthorization::Validation { .. } => {
            if inherited_path.is_some() || inherited_hash.is_some() {
                return Err(
                    "validation execution cannot inherit qualification authorization".to_string(),
                );
            }
        }
        ProfileAuthorization::Qualified(qualification) => match (inherited_path, inherited_hash) {
            (None, None) => {}
            (Some(path), Some(hash)) => {
                if path != qualification.path.as_os_str() {
                    return Err(format!(
                        "{QUALIFICATION_PATH_ENV} mismatch: expected '{}', observed '{}'",
                        qualification.path.display(),
                        path.to_string_lossy()
                    ));
                }
                let hash = hash
                    .to_str()
                    .ok_or_else(|| format!("{QUALIFICATION_SHA256_ENV} must be UTF-8"))?;
                if !hash.eq_ignore_ascii_case(&qualification.sha256) {
                    return Err(format!(
                        "{QUALIFICATION_SHA256_ENV} mismatch: expected {}, observed {hash}",
                        qualification.sha256
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "{QUALIFICATION_PATH_ENV} and {QUALIFICATION_SHA256_ENV} must be provided together"
                ));
            }
        },
    }
    Ok(())
}

impl ExecutionContext {
    pub(crate) fn ensure_unchanged(&self) -> Result<(), String> {
        self.profile.ensure_unchanged()?;
        if let ProfileAuthorization::Qualified(qualification) = &self.authorization {
            qualification.ensure_unchanged()?;
        }
        Ok(())
    }

    pub(crate) fn validate_input(&self, input: &Path) -> Result<(), String> {
        self.ensure_unchanged()?;
        let metadata = std::fs::symlink_metadata(input).map_err(|e| {
            format!(
                "profile input is not a readable regular file '{}': {e}",
                input.display()
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "profile input must be a regular file: {}",
                input.display()
            ));
        }
        if metadata.len() > self.profile.loaded.profile.limits.max_input_bytes {
            return Err(format!(
                "profile input exceeds max_input_bytes {}: {}",
                self.profile.loaded.profile.limits.max_input_bytes,
                input.display()
            ));
        }
        let extension = input.extension().and_then(OsStr::to_str).unwrap_or("");
        if !self
            .profile
            .loaded
            .profile
            .input_kind
            .extensions
            .iter()
            .any(|accepted| accepted.eq_ignore_ascii_case(extension))
        {
            return Err(format!(
                "profile input extension '{}' is not allowed for target '{}'",
                extension, self.profile.loaded.profile.target_id
            ));
        }
        Ok(())
    }

    pub(crate) fn replay_command(&self, input: &Path) -> Result<CommandSpec, String> {
        self.validate_input(input)?;
        let replay = self
            .profile
            .binary("replay")
            .ok_or_else(|| "profile has no replay binary".to_string())?;
        let mut args = Vec::with_capacity(replay.argv.len());
        for arg in &replay.argv {
            if arg == "{input}" {
                args.push(input.as_os_str().to_os_string());
            } else if arg.contains('{') || arg.contains('}') {
                return Err(format!(
                    "replay argv contains unresolved placeholder '{arg}'"
                ));
            } else {
                args.push(OsString::from(arg));
            }
        }
        Ok(CommandSpec {
            program: replay.path.clone(),
            args,
        })
    }

    pub(crate) fn engine_command(
        &self,
        backend: &str,
        values: &BTreeMap<&str, OsString>,
    ) -> Result<CommandSpec, String> {
        self.ensure_unchanged()?;
        let capability = self
            .profile
            .loaded
            .profile
            .engine_capabilities
            .iter()
            .find(|capability| capability.backend == backend)
            .ok_or_else(|| format!("profile does not authorize backend '{backend}'"))?;
        let binary = self
            .profile
            .binary(&capability.binary_role)
            .ok_or_else(|| {
                format!(
                    "profile backend '{backend}' names missing binary role '{}'",
                    capability.binary_role
                )
            })?;
        let mut args = Vec::with_capacity(binary.argv.len());
        for arg in &binary.argv {
            if let Some(key) = arg
                .strip_prefix('{')
                .and_then(|rest| rest.strip_suffix('}'))
            {
                let value = values.get(key).ok_or_else(|| {
                    format!("profile backend '{backend}' requires argv value '{key}'")
                })?;
                args.push(value.clone());
            } else {
                args.push(OsString::from(arg));
            }
        }
        Ok(CommandSpec {
            program: binary.path.clone(),
            args,
        })
    }

    pub(crate) fn validate_run_limits(
        &self,
        backend: &str,
        workers: usize,
        timeout_sec: u64,
    ) -> Result<(), String> {
        if !self
            .profile
            .loaded
            .profile
            .engine_capabilities
            .iter()
            .any(|capability| capability.backend == backend)
        {
            return Err(format!("profile does not authorize backend '{backend}'"));
        }
        if workers == 0 || workers > self.profile.loaded.profile.limits.workers as usize {
            return Err(format!(
                "workers {workers} exceeds profile limit {}",
                self.profile.loaded.profile.limits.workers
            ));
        }
        let timeout_ms = timeout_sec
            .checked_mul(1000)
            .ok_or_else(|| "timeout_sec overflows milliseconds".to_string())?;
        if timeout_ms == 0 || timeout_ms > self.profile.loaded.profile.limits.input_timeout_ms {
            return Err(format!(
                "timeout_sec {timeout_sec} exceeds profile input limit {}ms",
                self.profile.loaded.profile.limits.input_timeout_ms
            ));
        }
        Ok(())
    }

    pub(crate) fn required_mode(&self, backend: &str) -> Result<&str, String> {
        self.profile
            .loaded
            .profile
            .engine_capabilities
            .iter()
            .find(|capability| capability.backend == backend)
            .map(|capability| capability.required_mode.as_str())
            .ok_or_else(|| format!("profile does not authorize backend '{backend}'"))
    }

    pub(crate) fn backend_contract_json(&self, backend: &str) -> Result<String, String> {
        self.ensure_unchanged()?;
        let capability = self
            .profile
            .loaded
            .profile
            .engine_capabilities
            .iter()
            .find(|capability| capability.backend == backend)
            .ok_or_else(|| format!("profile does not authorize backend '{backend}'"))?;
        let binary = self
            .profile
            .binary(&capability.binary_role)
            .ok_or_else(|| {
                format!(
                    "profile backend '{backend}' names missing binary role '{}'",
                    capability.binary_role
                )
            })?;
        serde_json::to_string(&serde_json::json!({
            "profile_sha256": self.profile.loaded.sha256,
            "backend": backend,
            "required_mode": capability.required_mode,
            "instrumentation_scope": capability.instrumentation_scope,
            "binary_role": capability.binary_role,
            "program": binary.path,
            "argv_template": binary.argv,
        }))
        .map_err(|e| format!("failed to render backend contract: {e}"))
    }

    pub(crate) fn apply_to_command(
        &self,
        command: &mut Command,
        profile_child: bool,
    ) -> Result<(), String> {
        self.ensure_unchanged()?;
        command.env_clear();
        command.envs(self.allowed_env.iter());
        command.env(TARGET_PROFILE_ENV, &self.profile.loaded.path);
        command.env(PROFILE_SHA256_ENV, &self.profile.loaded.sha256);
        if profile_child {
            command.env(PROFILE_CHILD_ENV, "1");
        }
        match &self.authorization {
            ProfileAuthorization::Qualified(qualification) => {
                command.env(QUALIFICATION_PATH_ENV, &qualification.path);
                command.env(QUALIFICATION_SHA256_ENV, &qualification.sha256);
            }
            ProfileAuthorization::Validation { evidence_id } => {
                command.env(VALIDATION_RUN_ENV, evidence_id);
            }
        }
        Ok(())
    }

    pub(crate) fn mode_label(&self) -> &'static str {
        match self.authorization {
            ProfileAuthorization::Qualified(_) => "qualified",
            ProfileAuthorization::Validation { .. } => "unqualified_validation",
        }
    }

    pub(crate) fn qualification_snapshot(&self) -> Option<(&Path, &str, &[u8])> {
        match &self.authorization {
            ProfileAuthorization::Qualified(qualification) => Some((
                qualification.path.as_path(),
                qualification.sha256.as_str(),
                qualification.bytes.as_slice(),
            )),
            ProfileAuthorization::Validation { .. } => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn write_execution_record(
        &self,
        directory: &Path,
        backend: &str,
        corpus_snapshot_sha256: Option<&str>,
        input_manifest_sha256: Option<&str>,
        started_unix_ms: u128,
        elapsed_ms: u128,
        outcome: &str,
        argv: &[String],
    ) -> Result<PathBuf, String> {
        static NEXT_RECORD: AtomicU64 = AtomicU64::new(0);

        if backend.trim().is_empty() || outcome.trim().is_empty() || argv.is_empty() {
            return Err("execution record backend, outcome, and argv must be present".to_string());
        }
        if let Some(hash) = corpus_snapshot_sha256 {
            validate_sha256_reference("corpus_snapshot_sha256", hash)?;
        }
        if let Some(hash) = input_manifest_sha256 {
            validate_sha256_reference("input_manifest_sha256", hash)?;
        }
        fs::create_dir_all(directory).map_err(|e| {
            format!(
                "failed to create execution record directory '{}': {e}",
                directory.display()
            )
        })?;

        let record_directory = fs::canonicalize(directory).map_err(|e| {
            format!(
                "failed to resolve execution record directory '{}': {e}",
                directory.display()
            )
        })?;
        let profile_path = record_directory.join("profile.json");
        ensure_identity_snapshot(
            &profile_path,
            &self.profile.loaded.bytes,
            "profile snapshot",
        )?;
        let qualification_path = match &self.authorization {
            ProfileAuthorization::Qualified(qualification) => {
                let path = record_directory.join("qualification.json");
                ensure_identity_snapshot(&path, &qualification.bytes, "qualification snapshot")?;
                Some(path)
            }
            ProfileAuthorization::Validation { .. } => None,
        };

        let identity_error = self.ensure_unchanged().err();
        let profile_unchanged = identity_error.is_none();
        let allowed_env = self
            .allowed_env
            .iter()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    serde_json::Value::String(value.to_string_lossy().into_owned()),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let (qualification_sha256, validation_run) = match &self.authorization {
            ProfileAuthorization::Qualified(qualification) => {
                (Some(qualification.sha256.clone()), None)
            }
            ProfileAuthorization::Validation { evidence_id } => (None, Some(evidence_id.clone())),
        };
        ensure_profiled_result_marker(
            directory,
            &self.profile.loaded.profile.target_id,
            &self.profile.loaded.sha256,
            self.mode_label(),
        )?;
        let (tool_commit, tool_dirty) = tool_git_identity();
        let record = serde_json::json!({
            "schema_version": "1",
            "profile_path": profile_path,
            "profile_sha256": self.profile.loaded.sha256,
            "authorization": self.mode_label(),
            "qualification_path": qualification_path,
            "qualification_sha256": qualification_sha256,
            "validation_run": validation_run,
            "target_id": self.profile.loaded.profile.target_id,
            "format_revision": self.profile.loaded.profile.format_revision,
            "loader_id": self.profile.loaded.profile.loader_id,
            "loader_version": self.profile.loaded.profile.loader_version,
            "backend": backend,
            "depth": self.profile.loaded.profile.depth,
            "argv": argv,
            "allowed_env": allowed_env,
            "corpus_snapshot_sha256": corpus_snapshot_sha256,
            "input_manifest_sha256": input_manifest_sha256,
            "tool_commit": tool_commit,
            "tool_dirty": tool_dirty,
            "started_unix_ms": started_unix_ms,
            "ended_unix_ms": started_unix_ms.saturating_add(elapsed_ms),
            "elapsed_ms": elapsed_ms,
            "outcome": if profile_unchanged { outcome } else { "identity_drift" },
            "profile_unchanged_after_execution": profile_unchanged,
            "identity_error": identity_error.as_deref(),
        });
        let bytes = serde_json::to_vec_pretty(&record)
            .map_err(|e| format!("failed to serialize execution record: {e}"))?;
        let path = directory.join("execution.json");
        let temp = directory.join(format!(
            ".execution.json.tmp-{}-{}",
            std::process::id(),
            NEXT_RECORD.fetch_add(1, Ordering::Relaxed)
        ));
        let write_result = (|| -> Result<(), String> {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .map_err(|e| format!("failed to create '{}': {e}", temp.display()))?;
            file.write_all(&bytes)
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all())
                .map_err(|e| format!("failed to write '{}': {e}", temp.display()))?;
            fs::rename(&temp, &path).map_err(|e| {
                format!(
                    "failed to rename '{}' to '{}': {e}",
                    temp.display(),
                    path.display()
                )
            })?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        write_result?;
        if let Some(error) = identity_error {
            return Err(error);
        }
        Ok(path)
    }
}

fn ensure_identity_snapshot(path: &Path, expected: &[u8], label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(format!("{label} is not a regular file: {}", path.display()));
            }
            let observed = fs::read(path)
                .map_err(|e| format!("failed to read {label} '{}': {e}", path.display()))?;
            if observed != expected {
                return Err(format!("{label} changed or belongs to another execution"));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .map_err(|e| format!("failed to create {label} '{}': {e}", path.display()))?;
            file.write_all(expected)
                .and_then(|_| file.sync_all())
                .map_err(|e| format!("failed to write {label} '{}': {e}", path.display()))
        }
        Err(error) => Err(format!(
            "failed to inspect {label} '{}': {error}",
            path.display()
        )),
    }
}

fn ensure_profiled_result_marker(
    directory: &Path,
    target_id: &str,
    profile_sha256: &str,
    authorization: &str,
) -> Result<(), String> {
    let marker = serde_json::json!({
        "schema_version": "1",
        "target_id": target_id,
        "profile_sha256": profile_sha256,
        "authorization": authorization,
    });
    let mut expected = serde_json::to_vec_pretty(&marker)
        .map_err(|e| format!("failed to serialize profiled result marker: {e}"))?;
    expected.push(b'\n');
    let path = directory.join("profiled-result.json");
    match fs::read(&path) {
        Ok(observed) => {
            if observed != expected {
                return Err(format!(
                    "profiled result marker changed or belongs to another profile: {}",
                    path.display()
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .map_err(|e| format!("failed to create '{}': {e}", path.display()))?;
            file.write_all(&expected)
                .and_then(|_| file.sync_all())
                .map_err(|e| format!("failed to write '{}': {e}", path.display()))
        }
        Err(error) => Err(format!(
            "failed to read profiled result marker '{}': {error}",
            path.display()
        )),
    }
}

fn validate_sha256_reference(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a 64-digit sha256"));
    }
    Ok(())
}

fn tool_git_identity() -> (Option<String>, Option<bool>) {
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let dirty = Command::new("git")
        .args(["status", "--porcelain=v1"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| !output.stdout.is_empty());
    (commit, dirty)
}

pub(crate) fn run_profiled_harness(
    context: &ExecutionContext,
    target: &TargetKind,
    input: &Path,
) -> Result<(), HarnessError> {
    if !input.exists() {
        return Err(HarnessError::InputRejected(format!(
            "input not found: {}",
            input.display()
        )));
    }
    let spec = context
        .replay_command(input)
        .map_err(HarnessError::Unavailable)?;
    let mut command = command_with_core_dump_off(&spec.program);
    command.args(&spec.args);
    context
        .apply_to_command(&mut command, false)
        .map_err(HarnessError::Unavailable)?;
    let timeout_ms = context.profile.loaded.profile.limits.input_timeout_ms;
    let (output, timed_out) = output_with_deadline_ms(command, timeout_ms).map_err(|e| {
        HarnessError::Unavailable(format!("profile replay could not be executed: {e}"))
    })?;
    let _ = std::io::stdout().write_all(&output.stdout);
    let _ = std::io::stderr().write_all(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = if stderr.trim().is_empty() {
        first_line(&stdout)
    } else {
        first_line(&stderr)
    };
    if timed_out {
        return Err(HarnessError::Unavailable(format!(
            "profile replay timed out after {}ms",
            context.profile.loaded.profile.limits.input_timeout_ms
        )));
    }
    match output.status.code() {
        Some(0) => {
            println!("[harness] done");
            println!("target: {}", target_label(target));
            println!("input: {}", input.display());
            println!("profile_sha256: {}", context.profile.loaded.sha256);
            println!("library_step: profile replay ({detail})");
            println!("library_outcome: session_ok");
            println!("external_step: profile replay only");
            Ok(())
        }
        Some(code) if code == i32::from(crate::EXIT_HARNESS_INPUT_REJECTED) => Err(
            HarnessError::InputRejected(format!("profile replay rejected input: {detail}")),
        ),
        Some(code)
            if code == i32::from(crate::EXIT_HARNESS_UNAVAILABLE) || code == 126 || code == 127 =>
        {
            Err(HarnessError::Unavailable(format!(
                "profile replay unavailable: {detail}"
            )))
        }
        Some(code) if code == i32::from(crate::EXIT_HARNESS_UNCLASSIFIED) => {
            let traceback = if stderr.trim().is_empty() {
                stdout.into_owned()
            } else {
                stderr.into_owned()
            };
            Err(HarnessError::Unclassified(traceback))
        }
        _ => {
            let (stream, evidence) = if stderr.trim().is_empty() {
                ("stdout", stdout.into_owned())
            } else {
                ("stderr", stderr.into_owned())
            };
            Err(HarnessError::LibraryCrash(format!(
                "profile replay crashed or failed (status {}); {stream}:\n{evidence}",
                output.status
            )))
        }
    }
}

pub(crate) fn run_profiled_triage(
    context: &ExecutionContext,
    app_paths: &AppPaths,
    target: &TargetKind,
    input: &Path,
    repro_retries: u32,
    timeout_sec: u64,
) -> Result<(), String> {
    run_profiled_triage_with_summary(
        context,
        app_paths,
        target,
        input,
        repro_retries,
        timeout_sec,
    )
    .map(|_| ())
}

pub(crate) fn run_profiled_triage_with_summary(
    context: &ExecutionContext,
    app_paths: &AppPaths,
    target: &TargetKind,
    input: &Path,
    repro_retries: u32,
    timeout_sec: u64,
) -> Result<PathBuf, String> {
    context.validate_run_limits("local-harness", 1, timeout_sec)?;
    let staged_input =
        crate::profile_results::stage_input(input).map_err(|error| error.to_string())?;
    match run_profiled_harness(context, target, staged_input.path()) {
        Err(crate::target::HarnessError::Unclassified(traceback)) => {
            let location = crate::profile_results::preserve_unclassified(
                app_paths,
                context,
                target,
                staged_input.evidence_path(),
                &traceback,
            )?;
            return Err(format!(
                "profiled triage stopped at unclassified replay; diagnostic_id: {}",
                location.id
            ));
        }
        Err(crate::target::HarnessError::Unavailable(message)) => {
            return Err(format!("profiled triage preflight unavailable: {message}"));
        }
        Ok(())
        | Err(crate::target::HarnessError::InputRejected(_))
        | Err(crate::target::HarnessError::LibraryCrash(_)) => {}
    }
    let executable = std::env::current_exe()
        .map_err(|e| format!("failed to resolve current executable: {e}"))?;
    let argv = vec![
        executable.display().to_string(),
        "--data-dir".to_string(),
        app_paths.data_dir.display().to_string(),
        "--seeds-dir".to_string(),
        app_paths.seeds_dir.display().to_string(),
        "triage".to_string(),
        "--target".to_string(),
        target_label(target).to_string(),
        "--input".to_string(),
        staged_input.path().display().to_string(),
        "--repro-retries".to_string(),
        repro_retries.to_string(),
        "--timeout-sec".to_string(),
        timeout_sec.to_string(),
    ];
    let mut command = command_with_core_dump_off(&executable);
    command
        .arg("--data-dir")
        .arg(&app_paths.data_dir)
        .arg("--seeds-dir")
        .arg(&app_paths.seeds_dir)
        .arg("triage")
        .arg("--target")
        .arg(target_label(target))
        .arg("--input")
        .arg(staged_input.path())
        .arg("--repro-retries")
        .arg(repro_retries.to_string())
        .arg("--timeout-sec")
        .arg(timeout_sec.to_string());
    context.apply_to_command(&mut command, true)?;
    command.env(crate::profile_results::DIAGNOSTIC_SUPERVISOR_ENV, "triage");

    let started_unix_ms = now_unix_millis();
    let started = Instant::now();
    let total_timeout = timeout_sec
        .checked_mul(u64::from(repro_retries.max(1)))
        .and_then(|value| value.checked_add(5))
        .ok_or_else(|| "triage timeout budget overflow".to_string())?;
    let (output, timed_out) = output_with_deadline(command, total_timeout)
        .map_err(|e| format!("failed to execute profiled triage child: {e}"))?;
    let _ = std::io::stdout().write_all(&output.stdout);
    let _ = std::io::stderr().write_all(&output.stderr);
    if timed_out {
        return Err(format!(
            "profiled triage child exceeded its total {}s budget",
            total_timeout
        ));
    }
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if let Some(traceback) = crate::profile_results::extract_supervised_traceback(&stderr) {
            let location = crate::profile_results::preserve_unclassified(
                app_paths,
                context,
                target,
                staged_input.evidence_path(),
                &traceback,
            )?;
            return Err(format!(
                "profiled triage stopped at unclassified replay; diagnostic_id: {}",
                location.id
            ));
        }
        return Err(format!(
            "profiled triage child exited with status {}",
            output.status
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let summary = stdout
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("summary: "))
        .ok_or_else(|| "profiled triage child produced no summary path".to_string())?;
    let summary_path = PathBuf::from(summary);
    let directory = summary_path
        .parent()
        .ok_or_else(|| "profiled triage summary has no parent directory".to_string())?;
    let input_snapshot = crate::profile_results::snapshot_inputs(
        directory,
        &[staged_input.evidence_path().to_path_buf()],
        "input",
    )?;
    let preserved_input = input_snapshot
        .paths
        .first()
        .ok_or_else(|| "profiled triage input snapshot is empty".to_string())?;
    let mut summary_value: serde_json::Value = serde_json::from_slice(
        &fs::read(&summary_path)
            .map_err(|e| format!("failed to read profiled triage summary: {e}"))?,
    )
    .map_err(|e| format!("failed to parse profiled triage summary: {e}"))?;
    bind_profiled_triage_summary(
        &mut summary_value,
        preserved_input,
        &context.profile.loaded.sha256,
    )?;
    let summary_bytes = serde_json::to_vec_pretty(&summary_value)
        .map_err(|e| format!("failed to serialize profiled triage summary: {e}"))?;
    let summary_temp = directory.join(format!(
        ".summary.json.tmp-{}-{}",
        std::process::id(),
        now_unix_millis()
    ));
    fs::write(&summary_temp, &summary_bytes)
        .map_err(|e| format!("failed to stage profiled triage summary: {e}"))?;
    fs::rename(&summary_temp, &summary_path)
        .map_err(|e| format!("failed to publish profiled triage summary: {e}"))?;
    context.write_execution_record(
        directory,
        "triage",
        None,
        Some(&input_snapshot.manifest_sha256),
        started_unix_ms,
        started.elapsed().as_millis(),
        "success",
        &argv,
    )?;
    Ok(summary_path)
}

fn bind_profiled_triage_summary(
    summary: &mut serde_json::Value,
    preserved_input: &Path,
    profile_sha256: &str,
) -> Result<(), String> {
    let input = if preserved_input.is_absolute() {
        preserved_input.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to resolve profiled triage input: {e}"))?
            .join(preserved_input)
    };
    let object = summary
        .as_object_mut()
        .ok_or_else(|| "profiled triage summary must be a JSON object".to_string())?;
    object.insert(
        "input".to_string(),
        serde_json::Value::String(input.display().to_string()),
    );
    object.insert("profiled_result".to_string(), serde_json::Value::Bool(true));
    object.insert(
        "profile_sha256".to_string(),
        serde_json::Value::String(profile_sha256.to_string()),
    );
    Ok(())
}

pub(crate) fn corpus_snapshot_sha256(inputs: &[PathBuf]) -> Result<String, String> {
    let mut inputs = inputs
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .ok_or_else(|| format!("corpus input has no file name: {}", path.display()))?
                .to_string_lossy()
                .into_owned();
            Ok((name, path))
        })
        .collect::<Result<Vec<_>, String>>()?;
    inputs.sort_by(|left, right| left.0.cmp(&right.0));
    let mut manifest = Vec::new();
    let mut previous_name: Option<String> = None;
    for (name, path) in inputs {
        if previous_name.as_deref() == Some(name.as_str()) {
            return Err(format!("duplicate corpus file name: {name}"));
        }
        previous_name = Some(name.clone());
        let metadata = fs::symlink_metadata(path)
            .map_err(|e| format!("failed to inspect corpus input '{}': {e}", path.display()))?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "corpus input is not a regular file: {}",
                path.display()
            ));
        }
        let hash = sha256_file(path)?;
        manifest.extend_from_slice(name.as_bytes());
        manifest.push(0);
        manifest.extend_from_slice(metadata.len().to_string().as_bytes());
        manifest.push(0);
        manifest.extend_from_slice(hash.as_bytes());
        manifest.push(b'\n');
    }
    crate::target_profiles::sha256_bytes(&manifest)
}

fn validate_evidence_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err("validation-run must be a safe non-empty identifier".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{OsStr, OsString},
        fs,
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use serde_json::{json, Value};

    use super::{
        build_execution_context_with_env, corpus_snapshot_sha256, profile_child_marker,
        resolve_profile_selection, run_profiled_harness,
    };
    use crate::{
        common::sha256_file,
        target::TargetKind,
        target_profiles::{load_profile, verify_profile_files, VerifiedProfile},
    };

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
            "tool-execution-context-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn executable(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).unwrap();
        }
    }

    fn fixture(label: &str) -> Fixture {
        let root = temp_root(label);
        let binary_path = root.join("replay");
        executable(&binary_path, "#!/bin/sh\nexit 0\n");
        let hash = sha256_file(&binary_path).unwrap();
        let profile_path = root.join("profile.json");
        let tool = || json!({"version": "1", "path": binary_path, "sha256": hash});
        let value = json!({
            "schema_version": "1",
            "target_id": "onnx",
            "format_revision": "onnx-ir-v10",
            "loader_id": "onnxruntime",
            "loader_version": label,
            "source_artifacts": [{
                "url": "https://github.com/microsoft/onnxruntime/archive/refs/tags/v1.23.2.tar.gz",
                "tag": "v1.23.2",
                "resolved_commit": "0123456789abcdef0123456789abcdef01234567",
                "sha256": hash,
                "size_bytes": 17
            }],
            "patches": [],
            "toolchain": {
                "compiler": tool(), "linker": tool(), "engine": tool(),
                "python": null, "rust": tool(),
                "environment": {"PATH": "/usr/bin:/bin", "RUST_BACKTRACE": label}
            },
            "sanitizer_policy": {
                "compile_flags": ["-fsanitize=address"],
                "recovery": "abort",
                "runtime_env": {"ASAN_OPTIONS": "abort_on_error=1"},
                "rust_panic": "abort"
            },
            "binaries": [
                {
                    "role": "replay", "path": binary_path, "sha256": hash,
                    "argv": ["--profiled", "{input}"], "linked_libraries": []
                },
                {
                    "role": "aflpp", "path": binary_path, "sha256": hash,
                    "argv": ["--corpus", "{corpus_dir}", "--artifacts", "{artifact_dir}",
                             "--workers", "{workers}"],
                    "linked_libraries": []
                }
            ],
            "input_kind": {"kind": "single", "extensions": ["onnx"], "subformats": []},
            "depth": "session",
            "engine_capabilities": [
                {
                    "backend": "local-harness", "binary_role": "replay",
                    "required_mode": "native", "instrumentation_scope": "onnxruntime"
                },
                {
                    "backend": "aflpp", "binary_role": "aflpp",
                    "required_mode": "instrumented", "instrumentation_scope": "onnxruntime"
                }
            ],
            "limits": {
                "max_input_bytes": 1048576, "memory_bytes": 1073741824,
                "input_timeout_ms": 5000, "block_timeout_ms": 30000,
                "threads": 1, "workers": 2
            },
            "coverage_scope": {
                "unit": "source-line", "include_sources": ["onnxruntime/core"],
                "exclude_sources": []
            }
        });
        fs::write(&profile_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        Fixture {
            root,
            profile_path,
            binary_path,
            value,
        }
    }

    fn verified(fixture: &Fixture) -> VerifiedProfile {
        verify_profile_files(load_profile(&fixture.profile_path, &TargetKind::Onnx).unwrap())
            .unwrap()
    }

    fn rewrite_replay(fixture: &mut Fixture, body: &str) {
        executable(&fixture.binary_path, body);
        let binary_hash = sha256_file(&fixture.binary_path).unwrap();
        for role in ["compiler", "linker", "engine", "rust"] {
            fixture.value["toolchain"][role]["sha256"] = json!(binary_hash);
        }
        for binary in fixture.value["binaries"].as_array_mut().unwrap() {
            binary["sha256"] = json!(binary_hash);
        }
    }

    fn qualification(profile: &VerifiedProfile, status: &str) -> Value {
        json!({
            "schema_version": "1",
            "profile_sha256": profile.loaded.sha256,
            "status": status,
            "gate_evidence": (1..=12).map(|number| json!({
                "requirement_id": format!("Q{number:02}"),
                "evidence_sha256": profile.loaded.sha256,
            })).collect::<Vec<_>>()
        })
    }

    fn validation_context(fixture: &Fixture) -> super::ExecutionContext {
        build_execution_context_with_env(
            verified(fixture),
            Some("FND01-test"),
            vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))],
        )
        .expect("validation context")
    }

    #[test]
    fn general_execution_requires_a_verified_qualification() {
        let fixture = fixture("qualified");
        let profile = verified(&fixture);
        let missing = build_execution_context_with_env(profile.clone(), None, Vec::new())
            .expect_err("missing qualification must fail");
        assert!(missing.contains("qualification"));

        fs::write(
            fixture.root.join("qualification.json"),
            serde_json::to_vec_pretty(&qualification(&profile, "verified")).unwrap(),
        )
        .unwrap();
        let context = build_execution_context_with_env(profile, None, Vec::new())
            .expect("verified qualification should authorize general execution");
        assert_eq!(context.mode_label(), "qualified");
    }

    #[test]
    fn explicit_validation_run_is_unqualified_and_needs_no_qualification_file() {
        let fixture = fixture("validation");
        let context = validation_context(&fixture);
        assert_eq!(context.mode_label(), "unqualified_validation");
    }

    #[test]
    fn validation_and_qualified_authorization_envelopes_cannot_be_mixed() {
        let fixture = fixture("mixed-authorization");
        let err = build_execution_context_with_env(
            verified(&fixture),
            Some("FND01-test"),
            vec![(
                OsString::from("TOOL_PROFILE_QUALIFICATION"),
                fixture.root.join("qualification.json").into_os_string(),
            )],
        )
        .expect_err("validation execution must reject inherited qualification state");
        assert!(err.contains("qualification"));
    }

    #[test]
    fn inherited_qualification_hash_must_match_the_loaded_sidecar() {
        let fixture = fixture("qualification-envelope");
        let profile = verified(&fixture);
        fs::write(
            fixture.root.join("qualification.json"),
            serde_json::to_vec_pretty(&qualification(&profile, "verified")).unwrap(),
        )
        .unwrap();

        let err = build_execution_context_with_env(
            profile,
            None,
            vec![
                (
                    OsString::from("TOOL_PROFILE_QUALIFICATION"),
                    fixture.root.join("qualification.json").into_os_string(),
                ),
                (
                    OsString::from("TOOL_PROFILE_QUALIFICATION_SHA256"),
                    OsString::from("a".repeat(64)),
                ),
            ],
        )
        .expect_err("a forged inherited qualification hash must fail");
        assert!(err.contains("TOOL_PROFILE_QUALIFICATION_SHA256 mismatch"));
    }

    #[test]
    fn cli_and_environment_profiles_must_have_identical_bytes() {
        let first = fixture("first");
        let second = fixture("second");
        let err = resolve_profile_selection(
            Some(&first.profile_path),
            Some(&second.profile_path),
            &TargetKind::Onnx,
        )
        .expect_err("different profile bytes must conflict");
        assert!(err.contains("CLI/environment profile conflict"));
    }

    #[test]
    fn inherited_legacy_command_overrides_are_rejected() {
        let fixture = fixture("legacy-env");
        let err = build_execution_context_with_env(
            verified(&fixture),
            Some("FND01-test"),
            vec![(
                OsString::from("TOOL_ONNX_HARNESS_CMD"),
                OsString::from("/tmp/untrusted"),
            )],
        )
        .expect_err("legacy command must not enter profiled execution");
        assert!(err.contains("legacy environment override"));
    }

    #[test]
    fn two_profiles_build_isolated_child_environments_in_parallel() {
        let first_fixture = fixture("parallel-a");
        let second_fixture = fixture("parallel-b");
        let first = validation_context(&first_fixture);
        let second = validation_context(&second_fixture);

        let run = |context: super::ExecutionContext| {
            let mut command = Command::new("/bin/sh");
            command.arg("-c").arg("printf '%s' \"$RUST_BACKTRACE\"");
            context.apply_to_command(&mut command, true).unwrap();
            String::from_utf8(command.output().unwrap().stdout).unwrap()
        };
        let first_handle = thread::spawn(move || run(first));
        let second_handle = thread::spawn(move || run(second));
        assert_eq!(first_handle.join().unwrap(), "parallel-a");
        assert_eq!(second_handle.join().unwrap(), "parallel-b");
    }

    #[test]
    fn replay_argv_is_built_without_a_shell_string() {
        let fixture = fixture("argv");
        let input = fixture.root.join("case.onnx");
        fs::write(&input, b"model").unwrap();
        let spec = validation_context(&fixture).replay_command(&input).unwrap();
        assert_eq!(spec.program, fixture.binary_path);
        assert_eq!(
            spec.args,
            vec![OsString::from("--profiled"), input.into_os_string()]
        );
    }

    #[test]
    fn engine_argv_replaces_only_whole_token_placeholders() {
        let fixture = fixture("engine-argv");
        let context = validation_context(&fixture);
        let mut values = std::collections::BTreeMap::new();
        values.insert("corpus_dir", OsString::from("/tmp/corpus with spaces"));
        values.insert("artifact_dir", OsString::from("/tmp/artifacts"));
        values.insert("workers", OsString::from("2"));

        let spec = context.engine_command("aflpp", &values).unwrap();
        assert_eq!(spec.program, fixture.binary_path);
        assert_eq!(
            spec.args,
            vec![
                "--corpus",
                "/tmp/corpus with spaces",
                "--artifacts",
                "/tmp/artifacts",
                "--workers",
                "2",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
        );
        context.validate_run_limits("aflpp", 2, 5).unwrap();
        assert!(context.validate_run_limits("aflpp", 3, 5).is_err());
    }

    #[test]
    fn profile_child_marker_accepts_only_the_exact_value_one() {
        assert!(profile_child_marker(Some(OsStr::new("1"))));
        assert!(!profile_child_marker(Some(OsStr::new("true"))));
        assert!(!profile_child_marker(None));
    }

    #[cfg(unix)]
    #[test]
    fn profiled_harness_enforces_the_millisecond_input_deadline() {
        let mut fixture = fixture("millisecond-timeout");
        let marker = fixture.root.join("ran-past-deadline");
        rewrite_replay(
            &mut fixture,
            &format!(
                "#!/bin/sh\nsleep 0.20\nprintf reached > '{}'\n",
                marker.display()
            ),
        );
        fixture.value["limits"]["input_timeout_ms"] = json!(50);
        fs::write(
            &fixture.profile_path,
            serde_json::to_vec_pretty(&fixture.value).unwrap(),
        )
        .unwrap();
        let input = fixture.root.join("case.onnx");
        fs::write(&input, b"model").unwrap();

        let error = run_profiled_harness(&validation_context(&fixture), &TargetKind::Onnx, &input)
            .expect_err("a 50ms profile deadline must stop a 200ms replay");
        assert!(
            matches!(error, crate::target::HarnessError::Unavailable(message)
            if message.contains("timed out after 50ms"))
        );
        thread::sleep(std::time::Duration::from_millis(250));
        assert!(
            !marker.exists(),
            "the replay survived its profile deadline and wrote its marker"
        );
    }

    #[cfg(unix)]
    #[test]
    fn profiled_harness_preserves_full_signal_stderr_for_replay_observations() {
        let mut fixture = fixture("signal-stderr");
        rewrite_replay(
            &mut fixture,
            "#!/bin/sh\nprintf 'AddressSanitizer: heap-use-after-free\\n#0 parser_frame\\n' >&2\nkill -ABRT $$\n",
        );
        fs::write(
            &fixture.profile_path,
            serde_json::to_vec_pretty(&fixture.value).unwrap(),
        )
        .unwrap();
        let input = fixture.root.join("case.onnx");
        fs::write(&input, b"model").unwrap();

        let error = run_profiled_harness(&validation_context(&fixture), &TargetKind::Onnx, &input)
            .expect_err("a signal-terminated replay must be a library crash");
        let crate::target::HarnessError::LibraryCrash(detail) = error else {
            panic!("signal-terminated replay lost its crash identity: {error}");
        };
        assert!(
            detail.contains("signal: 6"),
            "signal identity missing: {detail}"
        );
        assert!(
            detail.contains("AddressSanitizer: heap-use-after-free\n#0 parser_frame"),
            "multi-line sanitizer stderr was truncated: {detail}"
        );
    }

    #[test]
    fn profiled_triage_summary_keeps_intrinsic_profile_identity() {
        let mut summary = json!({"schema_version": "1.0", "triage_id": "fixture"});
        super::bind_profiled_triage_summary(
            &mut summary,
            Path::new("/tmp/preserved-input.onnx"),
            &"a".repeat(64),
        )
        .expect("profiled triage summary binding");

        assert_eq!(summary["profiled_result"], true);
        assert_eq!(summary["profile_sha256"], "a".repeat(64));
        assert_eq!(summary["input"], "/tmp/preserved-input.onnx");
    }

    #[test]
    fn context_rechecks_profile_bytes_before_each_child() {
        let mut fixture = fixture("recheck");
        let context = validation_context(&fixture);
        fixture.value["loader_version"] = json!("changed");
        fs::write(
            &fixture.profile_path,
            serde_json::to_vec_pretty(&fixture.value).unwrap(),
        )
        .unwrap();

        let err = context
            .ensure_unchanged()
            .expect_err("changed profile must fail");
        assert!(err.contains("changed after loading"));
    }

    #[test]
    fn execution_record_snapshots_profile_bytes_without_embedding_them() {
        let fixture = fixture("record");
        let context = validation_context(&fixture);
        let record_dir = fixture.root.join("run");
        fs::create_dir_all(&record_dir).unwrap();

        let path = context
            .write_execution_record(
                &record_dir,
                "local-harness",
                Some(&"c".repeat(64)),
                None,
                10,
                20,
                "success",
                &["tool".to_string(), "run".to_string()],
            )
            .expect("execution record should be written");
        let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(value["profile_sha256"], context.profile.loaded.sha256);
        assert_eq!(value["authorization"], "unqualified_validation");
        assert_eq!(
            value["profile_path"],
            record_dir.join("profile.json").display().to_string()
        );
        assert_eq!(
            fs::read(record_dir.join("profile.json")).unwrap(),
            context.profile.loaded.bytes
        );
        assert!(value.get("profile").is_none());
        assert!(value.get("qualification").is_none());
        assert_eq!(
            sha256_file(&fixture.profile_path).unwrap(),
            context.profile.loaded.sha256,
            "writing the sidecar must not mutate the profile and create a hash cycle"
        );
    }

    #[test]
    fn qualified_execution_record_snapshots_qualification_bytes() {
        let fixture = fixture("qualified-record");
        let profile = verified(&fixture);
        let qualification_path = fixture.root.join("qualification.json");
        fs::write(
            &qualification_path,
            serde_json::to_vec_pretty(&qualification(&profile, "verified")).unwrap(),
        )
        .unwrap();
        let context =
            build_execution_context_with_env(profile, None, Vec::new()).expect("qualified context");
        let record_dir = fixture.root.join("run");

        let execution_path = context
            .write_execution_record(
                &record_dir,
                "local-harness",
                Some(&"c".repeat(64)),
                None,
                10,
                20,
                "success",
                &["tool".to_string(), "run".to_string()],
            )
            .expect("execution record");
        let execution: Value = serde_json::from_slice(&fs::read(execution_path).unwrap()).unwrap();
        assert_eq!(
            execution["qualification_path"],
            record_dir.join("qualification.json").display().to_string()
        );
        assert_eq!(
            fs::read(record_dir.join("qualification.json")).unwrap(),
            fs::read(qualification_path).unwrap()
        );
    }

    #[test]
    fn execution_record_marks_identity_drift_before_returning_an_error() {
        let mut fixture = fixture("record-drift");
        let context = validation_context(&fixture);
        let record_dir = fixture.root.join("run");
        fs::create_dir_all(&record_dir).unwrap();
        fixture.value["loader_version"] = json!("changed-after-start");
        fs::write(
            &fixture.profile_path,
            serde_json::to_vec_pretty(&fixture.value).unwrap(),
        )
        .unwrap();

        let err = context
            .write_execution_record(
                &record_dir,
                "local-harness",
                None,
                None,
                10,
                20,
                "success",
                &["tool".to_string(), "run".to_string()],
            )
            .expect_err("identity drift must fail the execution");
        assert!(err.contains("changed after loading"));
        let value: Value = serde_json::from_slice(
            &fs::read(record_dir.join("execution.json")).expect("drift evidence must be written"),
        )
        .unwrap();
        assert_eq!(value["profile_unchanged_after_execution"], false);
        assert!(value["identity_error"]
            .as_str()
            .unwrap()
            .contains("changed after loading"));
    }

    #[test]
    fn corpus_snapshot_hash_is_independent_of_the_machine_root_path() {
        let first_root = temp_root("corpus-root-a");
        let second_root = temp_root("corpus-root-b");
        let first = first_root.join("case.onnx");
        let second = second_root.join("case.onnx");
        fs::write(&first, b"same corpus member").unwrap();
        fs::write(&second, b"same corpus member").unwrap();

        assert_eq!(
            corpus_snapshot_sha256(&[first]).unwrap(),
            corpus_snapshot_sha256(&[second]).unwrap()
        );
        fs::remove_dir_all(first_root).unwrap();
        fs::remove_dir_all(second_root).unwrap();
    }
}
