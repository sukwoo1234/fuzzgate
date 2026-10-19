use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    sync::OnceLock,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub(crate) struct AppPaths {
    pub(crate) data_dir: PathBuf,
    pub(crate) seeds_dir: PathBuf,
}

impl AppPaths {
    pub(crate) fn prepare(data_dir: &Path, seeds_dir: &Path) -> Result<Self, String> {
        ensure_directory(data_dir)
            .map_err(|e| format!("failed to create data dir '{}': {e}", data_dir.display()))?;
        ensure_data_layout(data_dir).map_err(|e| {
            format!(
                "failed to create data layout in '{}': {e}",
                data_dir.display()
            )
        })?;
        ensure_directory(seeds_dir)
            .map_err(|e| format!("failed to create seeds dir '{}': {e}", seeds_dir.display()))?;

        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            seeds_dir: seeds_dir.to_path_buf(),
        })
    }
}

#[derive(Clone)]
pub(crate) struct ArtifactContract {
    pub(crate) runs_root: PathBuf,
    pub(crate) triage_root: PathBuf,
    pub(crate) reports_root: PathBuf,
    pub(crate) coverage_root: PathBuf,
    pub(crate) metrics_root: PathBuf,
    pub(crate) exports_root: PathBuf,
    pub(crate) diagnostics_root: PathBuf,
    pub(crate) mutated_root: PathBuf,
    pub(crate) legacy_mutated_root: PathBuf,
}

pub(crate) fn artifact_contract(app_paths: &AppPaths) -> ArtifactContract {
    artifact_contract_for_data_dir(&app_paths.data_dir)
}

pub(crate) fn artifact_contract_for_data_dir(data_dir: &Path) -> ArtifactContract {
    ArtifactContract {
        runs_root: data_dir.join("runs"),
        triage_root: data_dir.join("triage"),
        reports_root: data_dir.join("reports"),
        coverage_root: data_dir.join("coverage"),
        metrics_root: data_dir.join("metrics"),
        exports_root: data_dir.join("exports"),
        diagnostics_root: data_dir.join("diagnostics"),
        mutated_root: data_dir.join("corpus").join("mutated"),
        legacy_mutated_root: data_dir.join("mutated"),
    }
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn now_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub(crate) fn command_exists(cmd: &str) -> bool {
    Command::new(cmd).arg("--version").output().is_ok()
}

/// Whether `prlimit` is on this host, looked up once.
///
/// The answer cannot change while the process runs, but this used to spawn
/// `prlimit --version` on every wrapped command - one extra fork/exec per fuzzing
/// job and per triage attempt.
fn prlimit_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        #[cfg(test)]
        PRLIMIT_PROBES.fetch_add(1, Ordering::Relaxed);
        command_exists("prlimit")
    })
}

#[cfg(test)]
static PRLIMIT_PROBES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn prlimit_probe_count() -> usize {
    PRLIMIT_PROBES.load(Ordering::Relaxed)
}

pub(crate) fn command_with_core_dump_off(program: impl AsRef<OsStr>) -> Command {
    let program = program.as_ref();
    let mut cmd = if prlimit_available() {
        let mut c = Command::new("prlimit");
        c.arg("--core=0").arg("--").arg(program);
        c
    } else {
        Command::new(program)
    };
    cmd.env("ASAN_OPTIONS", core_dump_off_env());
    cmd
}

// A13: command_with_core_dump_off runs the real program behind `prlimit`, which
// execs successfully and then reports the failure itself. A missing or
// non-executable program therefore arrives as a normal exit 127/126 instead of
// Err(NotFound), so callers must recognise the wrapper's own failure sentinel.
pub(crate) fn is_core_dump_wrapper_exec_failure(exit_code: Option<i32>, stderr: &str) -> bool {
    matches!(exit_code, Some(126) | Some(127)) && stderr.contains("prlimit: failed to execute")
}

/// A9/A38: enforce `timeout_sec` in-process. The pipeline relied solely on the external
/// `timeout` binary, so on a host without it the child ran unbounded: a hanging input
/// blocked the worker (or triage) forever and the Timeout verdict was unreachable.
///
/// stdout/stderr go to temp files rather than pipes. A child that fills the pipe buffer
/// blocks before it can exit (so a poll loop would never see it finish), and draining the
/// pipes from reader threads instead makes the call block for as long as a surviving
/// grandchild holds the write end - exactly the hang this fix removes. Files have neither
/// problem, and unlinking them afterwards frees the space even if a grandchild keeps
/// writing. Like the `timeout` binary, only the direct child is killed.
pub(crate) fn output_with_deadline(
    cmd: Command,
    timeout_sec: u64,
) -> std::io::Result<(Output, bool)> {
    output_with_deadline_ms(cmd, timeout_sec.saturating_mul(1000))
}

pub(crate) fn output_with_deadline_ms(
    mut cmd: Command,
    timeout_ms: u64,
) -> std::io::Result<(Output, bool)> {
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let deadline = Duration::from_millis(timeout_ms.max(1));
    let unique = format!(
        "tool-exec-{}-{}-{}",
        std::process::id(),
        now_unix_millis(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let stdout_path = std::env::temp_dir().join(format!("{unique}.out"));
    let stderr_path = std::env::temp_dir().join(format!("{unique}.err"));

    let result = run_to_deadline(&mut cmd, deadline, &stdout_path, &stderr_path);

    // always reclaim the capture files, including on an early error return
    let _ = fs::remove_file(&stdout_path);
    let _ = fs::remove_file(&stderr_path);
    result
}

fn run_to_deadline(
    cmd: &mut Command,
    deadline: Duration,
    stdout_path: &Path,
    stderr_path: &Path,
) -> std::io::Result<(Output, bool)> {
    // R1: the deadline used to kill only the direct child, so a probe's own child -
    // the python interpreter an onnx/safetensors probe starts, or llama-gguf-hash -
    // was orphaned and kept running long after the job it belonged to was over. Over
    // a multi-day campaign those accumulate. Leading its own process group lets the
    // whole job be signalled at once.
    //
    // The trade-off, the same one the dashboard's jobs have (README, R7): a child in
    // its own group is no longer in the terminal's foreground group, so Ctrl-C
    // reaches `tool` but not the harness it is waiting on. Campaign runs are under
    // systemd or nohup, where that is not the stop mechanism anyway.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(create_capture_file(stdout_path)?))
        .stderr(Stdio::from(create_capture_file(stderr_path)?))
        .spawn()?;

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= deadline {
            // a child that exited inside the last poll window finished on its own; its
            // real status (a crash, say) must not be relabelled as a timeout
            if let Some(status) = child.try_wait()? {
                break status;
            }
            timed_out = true;
            kill_process_group(child.id());
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(20));
    };

    Ok((
        Output {
            status,
            stdout: fs::read(stdout_path).unwrap_or_default(),
            stderr: fs::read(stderr_path).unwrap_or_default(),
        },
        timed_out,
    ))
}

/// Signal the whole group the timed-out child leads, so its own children go too.
#[cfg(unix)]
fn kill_process_group(pid: u32) {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    // The child was spawned with process_group(0), so its pid is the group id and a
    // negative pid addresses the group. Never signal group 0 - that is our own.
    if pid == 0 {
        return;
    }
    unsafe {
        kill(-(pid as i32), SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: u32) {}

// create_new refuses an existing path, so a pre-planted symlink in a shared /tmp cannot
// redirect the capture into someone else's file.
fn create_capture_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// A29: under GNU coreutils `timeout 0s` means "no limit", so a zero budget silently
/// removed the per-job bound instead of bounding it.
pub(crate) fn validate_timeout_sec(timeout_sec: u64) -> Result<u64, String> {
    if timeout_sec == 0 {
        return Err("timeout_sec must be >= 1 (0 means no time limit)".to_string());
    }
    Ok(timeout_sec)
}

/// A25: `--max-jobs 0` truncated the input list to nothing after the "no inputs"
/// check, so a run that executed nothing still published a status.json, a coverage
/// summary and a metrics event that all read as a clean zero-crash run.
pub(crate) fn validate_max_jobs(max_jobs: Option<usize>) -> Result<Option<usize>, String> {
    if max_jobs == Some(0) {
        return Err("max_jobs must be >= 1 (0 means no work)".to_string());
    }
    Ok(max_jobs)
}

fn core_dump_off_env() -> String {
    let existing = std::env::var("ASAN_OPTIONS").unwrap_or_default();
    if existing.trim().is_empty() {
        "disable_coredump=1".to_string()
    } else if existing.contains("disable_coredump=") {
        existing
    } else {
        format!("{existing}:disable_coredump=1")
    }
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    let file = path.display().to_string();

    if let Some(out) = run_capture("sha256sum", &[&file])? {
        return parse_hash_output(&out);
    }
    if let Some(out) = run_capture("shasum", &["-a", "256", &file])? {
        return parse_hash_output(&out);
    }

    Err("sha256 tool not found (sha256sum/shasum)".to_string())
}

fn parse_hash_output(output: &str) -> Result<String, String> {
    output
        .split_whitespace()
        .next()
        .map(|s| s.to_string())
        .ok_or_else(|| "failed to parse sha256 output".to_string())
}

pub(crate) fn download_file(source_url: &str, output_path: &Path) -> Result<(), String> {
    let output = output_path.display().to_string();

    if try_run(
        "curl",
        &[
            "-fL",
            "--retry",
            "2",
            "--connect-timeout",
            "15",
            "-o",
            &output,
            source_url,
        ],
    )? {
        return Ok(());
    }

    if try_run("wget", &["-O", &output, source_url])? {
        return Ok(());
    }

    Err("download failed: both curl and wget are unavailable or failed".to_string())
}

pub(crate) fn download_file_name(source_url: &str) -> String {
    let without_query = source_url.split('?').next().unwrap_or(source_url);
    let from_path = without_query.rsplit('/').next().filter(|s| !s.is_empty());
    from_path.unwrap_or("target-source.bin").to_string()
}

pub(crate) fn validate_official_source(
    source_url: &str,
    official_owner: &str,
    official_repo: &str,
) -> Result<(), String> {
    if !source_url.starts_with("https://") {
        return Err("source URL must use https".to_string());
    }

    let (host, segments) = parse_url_host_and_path(source_url)
        .ok_or_else(|| format!("source URL parse failed: '{source_url}'"))?;
    if host != "github.com" && host != "codeload.github.com" {
        return Err(format!(
            "unsupported source host '{host}'; only github.com/codeload.github.com are allowed"
        ));
    }
    // Path segment 정확 일치 검사 — query/fragment에 prefix 문자열을 끼워 넣는 우회 방지
    if segments.len() < 2 || segments[0] != official_owner || segments[1] != official_repo {
        return Err(format!(
            "source URL path must begin with '/{official_owner}/{official_repo}/'"
        ));
    }

    Ok(())
}

// `https://<host>/<seg1>/<seg2>/...?query#frag` → (host, [seg1, seg2, ...])
// query/fragment는 제거하고 비어있는 segment는 건너뛴다.
fn parse_url_host_and_path(source_url: &str) -> Option<(&str, Vec<&str>)> {
    let without_scheme = source_url.strip_prefix("https://")?;
    let without_fragment = without_scheme.split('#').next().unwrap_or(without_scheme);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    let mut parts = without_query.splitn(2, '/');
    let host = parts.next()?;
    if host.is_empty() {
        return None;
    }
    let path = parts.next().unwrap_or("");
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    Some((host, segments))
}

pub(crate) fn try_run(cmd: &str, args: &[&str]) -> Result<bool, String> {
    match Command::new(cmd).args(args).status() {
        Ok(status) => Ok(status.success()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{cmd} execution failed: {e}")),
    }
}

pub(crate) fn run_capture(cmd: &str, args: &[&str]) -> Result<Option<String>, String> {
    match Command::new(cmd).args(args).output() {
        Ok(output) => {
            if !output.status.success() {
                return Ok(None);
            }
            let text = String::from_utf8(output.stdout)
                .map_err(|e| format!("{cmd} output decode failed: {e}"))?;
            Ok(Some(text))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{cmd} execution failed: {e}")),
    }
}

pub(crate) fn first_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("no output")
        .trim()
        .to_string()
}

pub(crate) fn has_ext(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

pub(crate) fn shell_escape(path: &Path) -> String {
    let s = path.display().to_string();
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

pub(crate) fn ensure_directory(path: &Path) -> std::io::Result<()> {
    if path.exists() && !path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("path '{}' exists but is not a directory", path.display()),
        ));
    }
    fs::create_dir_all(path)
}

pub(crate) fn ensure_data_layout(data_dir: &Path) -> std::io::Result<()> {
    const REQUIRED_DIRS: &[&str] = &[
        "queue/pending",
        "queue/processing",
        "queue/done",
        "queue/failed",
        "queue/quarantine",
        "queue/quarantine/broken",
        "artifacts",
    ];

    for dir in REQUIRED_DIRS {
        fs::create_dir_all(data_dir.join(dir))?;
    }

    Ok(())
}

pub(crate) enum HarnessExecResult {
    Success(String),
    Failed(String),
    Timeout(String),
    // G3: the harness rejected this input before the library ran. Not a failed job and
    // not a reproducer - keeping it in `failed` inflates the crash-side counters.
    Rejected(String),
    // A profiled loader raised a non-signal exception that still needs independent
    // replay. It is neither a confirmed crash nor a benign input rejection.
    Unclassified(String),
}

#[cfg(test)]
mod tests {
    // Every wrapped spawn probed for prlimit by running `prlimit --version`, so a
    // fuzzing loop paid an extra fork/exec on every single job and every triage
    // attempt just to re-learn something that cannot change while the process runs.
    #[test]
    fn prlimit_is_probed_once_per_process() {
        use super::{command_with_core_dump_off, prlimit_probe_count};

        for _ in 0..50 {
            let _ = command_with_core_dump_off("true");
        }
        assert_eq!(
            prlimit_probe_count(),
            1,
            "prlimit should be looked up once, not once per spawn"
        );
    }

    // R1: the deadline killed only the direct child, so a probe's own child - the
    // python interpreter the harness starts - was left orphaned and kept running
    // after the job it belonged to was over. Over a multi-day campaign those pile up.
    #[cfg(unix)]
    #[test]
    fn the_deadline_kills_the_whole_process_group_not_just_the_child() {
        use super::output_with_deadline;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let dir = std::env::temp_dir().join(format!(
            "tool-r1-{}-{}",
            std::process::id(),
            super::now_unix_millis()
        ));
        std::fs::create_dir_all(&dir).expect("create dir");
        let marker = dir.join("grandchild.pid");

        // The child starts a grandchild that outlives it, exactly like a probe
        // starting python, then hangs so the deadline has to step in.
        let script = dir.join("spawner.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 sh -c 'echo $$ > {marker}; sleep 60' &\n\
                 sleep 60\n",
                marker = marker.display()
            ),
        )
        .expect("write script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let mut cmd = Command::new(&script);
        let (_, timed_out) = output_with_deadline(cmd_ref(&mut cmd), 1).expect("run");
        assert!(timed_out, "the script should have hit the deadline");

        let pid = std::fs::read_to_string(&marker)
            .expect("grandchild pid")
            .trim()
            .to_string();
        // Give the group kill a moment to be reaped.
        std::thread::sleep(std::time::Duration::from_millis(200));
        // /proc rather than kill(1): a missing kill binary would make this test pass
        // without testing anything.
        let proc_entry = std::path::PathBuf::from("/proc").join(&pid);
        assert!(
            proc_entry.parent().is_some_and(|p| p.exists()),
            "this test needs procfs"
        );
        let alive = proc_entry.exists()
            && !std::fs::read_to_string(proc_entry.join("stat"))
                .unwrap_or_default()
                .rsplit(')')
                .next()
                .unwrap_or("")
                .trim_start()
                .starts_with('Z');
        if alive {
            let _ = Command::new("kill").arg("-KILL").arg(&pid).status();
        }
        let _ = std::fs::remove_dir_all(&dir);

        assert!(!alive, "the grandchild outlived the job that started it");
    }

    fn cmd_ref(cmd: &mut std::process::Command) -> std::process::Command {
        let mut fresh = std::process::Command::new(cmd.get_program());
        fresh.args(cmd.get_args());
        fresh
    }

    // A25 / the same hole in `run`: `--max-jobs 0` truncated the input list to
    // nothing AFTER the "no inputs" check, so a run that executed nothing still
    // published a status.json, a coverage summary and a metrics event that read as
    // a clean, successful, zero-crash run.
    #[test]
    fn a_zero_job_budget_is_rejected() {
        use super::validate_max_jobs;

        assert!(
            validate_max_jobs(Some(0)).is_err(),
            "a budget of zero jobs must not be accepted"
        );
        assert_eq!(validate_max_jobs(Some(1)), Ok(Some(1)));
        assert_eq!(validate_max_jobs(None), Ok(None));
    }

    use super::{is_core_dump_wrapper_exec_failure, output_with_deadline, validate_timeout_sec};
    use std::process::Command;
    use std::time::{Duration, Instant};

    // A9/A38: when the `timeout` binary is missing the pipeline ran with no time bound
    // at all, so a hanging input blocked a worker (or triage) forever.
    #[test]
    fn deadline_kills_a_hanging_child_and_reports_timeout() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("sleep 30");

        let started = Instant::now();
        let (output, timed_out) = output_with_deadline(cmd, 1).expect("spawn");

        assert!(
            timed_out,
            "a child past its deadline must be reported as timed out"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the deadline must actually fire: {:?}",
            started.elapsed()
        );
        assert!(!output.status.success());
    }

    #[test]
    fn deadline_returns_full_output_of_a_fast_child() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("printf hello; printf oops >&2; exit 3");

        let (output, timed_out) = output_with_deadline(cmd, 5).expect("spawn");

        assert!(!timed_out);
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(String::from_utf8_lossy(&output.stdout), "hello");
        assert_eq!(String::from_utf8_lossy(&output.stderr), "oops");
    }

    #[test]
    fn deadline_captures_output_larger_than_the_pipe_buffer() {
        // a plain try_wait() poll loop deadlocks here: the child blocks writing into a
        // full pipe and never exits, so the deadline would fire on a healthy run.
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("dd if=/dev/zero bs=1024 count=256 2>/dev/null | tr '\\0' 'a'");

        let (output, timed_out) = output_with_deadline(cmd, 20).expect("spawn");

        assert!(!timed_out, "a healthy child must not hit the deadline");
        assert_eq!(output.stdout.len(), 256 * 1024);
    }

    // A29: `timeout 0s` means "no limit" under GNU coreutils, so accepting 0 silently
    // disabled the per-job bound.
    #[test]
    fn zero_timeout_is_rejected() {
        assert!(validate_timeout_sec(0).is_err());
        assert_eq!(validate_timeout_sec(1).expect("1s is valid"), 1);
        assert_eq!(validate_timeout_sec(30).expect("30s is valid"), 30);
    }

    // A13: prlimit runs fine and reports the failure itself, so a missing or
    // non-executable interpreter arrives as a plain exit 126/127 instead of
    // Err(NotFound). Without this sentinel the probe is reported as "invoked".
    #[test]
    fn detects_prlimit_exec_failure_codes() {
        assert!(is_core_dump_wrapper_exec_failure(
            Some(127),
            "prlimit: failed to execute /nonexistent/python3: No such file or directory\n"
        ));
        assert!(is_core_dump_wrapper_exec_failure(
            Some(126),
            "prlimit: failed to execute /etc/hostname: Permission denied\n"
        ));
    }

    #[test]
    fn ignores_program_own_exit_codes_and_output() {
        // the program itself ran and exited 127/126 on its own
        assert!(!is_core_dump_wrapper_exec_failure(
            Some(127),
            "load_fail: bad model\n"
        ));
        // wrapper message but a normal exit code (never produced by prlimit exec failure)
        assert!(!is_core_dump_wrapper_exec_failure(
            Some(2),
            "prlimit: failed to execute /nonexistent/python3: No such file or directory\n"
        ));
        assert!(!is_core_dump_wrapper_exec_failure(None, ""));
    }
}
