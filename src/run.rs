use std::{
    collections::VecDeque,
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
};

use crate::common::{
    artifact_contract, command_exists, command_with_core_dump_off, first_line, now_unix,
    now_unix_millis, output_with_deadline, shell_escape, validate_max_jobs, validate_timeout_sec,
    AppPaths,
    ArtifactContract, HarnessExecResult,
};
use crate::json_utils::json_escape;
use crate::metrics::{self, MetricEvent};
use crate::target::{
    collect_corpus_inputs, default_seed_dir, resolve_target_adapter, target_label, TargetKind,
};
use crate::triage;

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RunBackend {
    #[value(name = "local-harness")]
    LocalHarness,
    #[value(name = "aflpp")]
    Aflpp,
    #[value(name = "libfuzzer")]
    Libfuzzer,
}

struct EngineAdapter {
    backend_label: &'static str,
    cmd_env: &'static str,
}

#[derive(Clone)]
pub(crate) struct RunJob {
    pub(crate) id: usize,
    pub(crate) input: PathBuf,
}

/// What running one job reports back: the harness outcome, how many retries it
/// took, and whether the library session was reached.
type JobOutcome = (HarnessExecResult, usize, bool);

#[derive(Default)]
struct RunStats {
    total: usize,
    success: usize,
    failed: usize,
    timeout: usize,
    rejected: usize,
    retries: usize,
    library_session_ok: usize,
    // A26: jobs the run never got to execute. Not failures of the library under test,
    // so they stay out of `failed` and out of the metrics denominator.
    job_errors: usize,
}

struct RunStatusCounts {
    total: usize,
    success: usize,
    failed: usize,
    timeout: usize,
    rejected: usize,
    retries: usize,
    job_errors: usize,
    worker_errors: usize,
    backend_crash_artifacts: usize,
    backend_crashes_triaged: usize,
    backend_crash_triage_errors: usize,
    backend_crash_scan_errors: usize,
}

struct EngineWorkerPlan {
    worker_id: usize,
    engine_cmd: String,
    worker_log_path: PathBuf,
}

struct EngineWorkerResult {
    outcome: EngineWorkerOutcome,
}

enum EngineWorkerOutcome {
    Success,
    Failed,
    Timeout,
}

struct BackendCrashArtifact {
    path: PathBuf,
    kind: &'static str,
}

struct BackendCrashIngest {
    discovered: usize,
    triaged: usize,
    errors: usize,
    scan_errors: usize,
    manifest_error: bool,
    manifest_path: Option<PathBuf>,
}

/// What a crash-directory sweep found, plus how many directories or entries it could
/// not read. A28: an unreadable directory used to abort the whole run through `?`,
/// which threw away status.json and the metrics event for jobs that had already
/// finished. Losing a finished block's record is worse than losing one scan.
struct BackendCrashScan {
    artifacts: Vec<BackendCrashArtifact>,
    scan_errors: usize,
}

impl BackendCrashScan {
    fn note_error(&mut self, message: String) {
        eprintln!("[run] warning: {message}");
        self.scan_errors += 1;
    }
}

pub(crate) fn run_fuzz_pipeline(
    app_paths: &AppPaths,
    target: &TargetKind,
    backend: &RunBackend,
    local: bool,
    corpus_dir: Option<&Path>,
    seed_fixture: Option<&Path>,
    workers: usize,
    timeout_sec: u64,
    restart_limit: u32,
    max_jobs: Option<usize>,
) -> Result<(), String> {
    // A29: `timeout 0s` means "no limit", so a zero budget silently unbounded every job.
    let timeout_sec = validate_timeout_sec(timeout_sec)?;
    let max_jobs = validate_max_jobs(max_jobs)?;

    let artifact = artifact_contract(app_paths);
    if *backend != RunBackend::LocalHarness {
        return run_engine_backend(
            app_paths,
            &artifact,
            target,
            backend,
            local,
            corpus_dir,
            seed_fixture,
            workers,
            timeout_sec,
            restart_limit,
        );
    }

    let corpus_dir = match corpus_dir {
        Some(path) => path.to_path_buf(),
        None if local => default_seed_dir(app_paths, target),
        None => app_paths.seeds_dir.clone(),
    };
    if !corpus_dir.exists() || !corpus_dir.is_dir() {
        return Err(format!("corpus_dir is invalid: {}", corpus_dir.display()));
    }

    // corpus reload: v1은 시작 시 코퍼스를 스냅샷으로 고정한다.
    // 재실행 루프 사이 신규 파일 반영은 차기 단계에서 "루프 간 재스캔"으로 확장한다.
    let mut inputs = collect_corpus_inputs(&corpus_dir, target)?;
    if inputs.is_empty() {
        return Err(format!(
            "no input files found for target '{}' in {}",
            target_label(target),
            corpus_dir.display()
        ));
    }
    if let Some(max_jobs) = max_jobs {
        inputs.truncate(max_jobs);
    }

    let run_id = now_unix_millis();
    let run_dir = artifact.runs_root.join(format!("run-{run_id}"));
    let logs_dir = run_dir.join("logs");
    fs::create_dir_all(&logs_dir)
        .map_err(|e| format!("failed to create run log dir '{}': {e}", logs_dir.display()))?;
    // A10: durable home for crashing/hanging reproducers, outside the mutation batch
    // dir that retention prunes. Created lazily on the first failed/timeout job.
    let crash_inputs_dir = run_dir.join("crash-inputs");

    let jobs = inputs
        .into_iter()
        .enumerate()
        .map(|(id, input)| RunJob { id, input })
        .collect::<Vec<_>>();
    let queue = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let stats = Arc::new(Mutex::new(RunStats {
        total: queue.lock().map_err(|_| "queue lock poisoned")?.len(),
        ..RunStats::default()
    }));

    let workers = workers.max(1).min(
        queue
            .lock()
            .map_err(|_| "queue lock poisoned")?
            .len()
            .max(1),
    );
    let timeout_available = command_exists("timeout");
    let engine_mode = engine_mode_label(
        backend,
        engine_mode_env_key(backend).and_then(|key| std::env::var(key).ok()),
    );

    println!("[run] start");
    println!("target: {}", target_label(target));
    println!("backend: {}", run_backend_label(backend));
    println!("local_mode: {}", local);
    println!("corpus_dir: {}", corpus_dir.display());
    println!("workers: {workers}");
    println!("timeout_sec: {}", timeout_sec);
    println!("restart_limit: {}", restart_limit);
    println!("engine_mode: {engine_mode}");
    println!("run_dir: {}", run_dir.display());

    let mut handles = Vec::new();
    for _worker_id in 0..workers {
        let queue = Arc::clone(&queue);
        let stats = Arc::clone(&stats);
        let logs_dir = logs_dir.clone();
        let crash_inputs_dir = crash_inputs_dir.clone();
        let target = target.clone();

        handles.push(thread::spawn(move || {
            let exec = |job: &RunJob| {
                run_job_with_retry(
                    job,
                    &target,
                    timeout_sec,
                    restart_limit,
                    timeout_available,
                    &logs_dir,
                )
            };
            drain_job_queue(&queue, &stats, &crash_inputs_dir, &exec)
        }));
    }

    // Join every worker before deciding: returning early left the remaining workers
    // detached, still writing into the run directory this function was abandoning.
    let mut worker_error = None;
    for handle in handles {
        let outcome = match handle.join() {
            Ok(outcome) => outcome,
            Err(_) => Err("worker thread panicked".to_string()),
        };
        if let Err(e) = outcome {
            if worker_error.is_none() {
                worker_error = Some(e);
            }
        }
    }

    // zombie fencing: 현재 구현은 파일 큐 대신 in-memory pop_front 단일 소유권으로 중복 처리 write를 방지한다.
    // file-queue 전환 시에는 결과 쓰기 전에 processing/<job_id> 존재 확인을 강제한다.
    let s = stats.lock().map_err(|_| "stats lock poisoned")?;
    let status_path = write_run_status(
        &run_dir,
        run_id,
        target,
        backend,
        RunStatusCounts {
            total: s.total,
            success: s.success,
            failed: s.failed,
            timeout: s.timeout,
            rejected: s.rejected,
            retries: s.retries,
            job_errors: s.job_errors,
            worker_errors: 0,
            backend_crash_artifacts: 0,
            backend_crashes_triaged: 0,
            backend_crash_triage_errors: 0,
            backend_crash_scan_errors: 0,
        },
        workers,
        timeout_sec,
        restart_limit,
        &engine_mode,
        &corpus_dir,
        seed_fixture,
    )?;

    println!("[run] done");
    println!("success: {}", s.success);
    println!("failed: {}", s.failed);
    println!("timeout: {}", s.timeout);
    println!("rejected: {}", s.rejected);
    println!("retries: {}", s.retries);
    println!("job_errors: {}", s.job_errors);
    println!("status: {}", status_path.display());

    // status.json is already written; a metrics failure must not turn a finished run
    // into a non-zero exit that a campaign loop reads as a failed block.
    metrics::record_metrics_event_best_effort(
        app_paths,
        MetricEvent {
            ts: now_unix(),
            kind: metrics::KIND_RUN,
            // A job that never ran is not a trial: keeping it in `total` would dilute
            // library_connect_rate_proxy with inputs the library never saw.
            total: s.total.saturating_sub(s.job_errors) as u64,
            errors: (s.failed + s.timeout) as u64,
            successful_runs_proxy: s.success as u64,
            library_session_ok: s.library_session_ok as u64,
            new_crashes: 0,
            valid_crashes: 0,
            total_crashes: 0,
        },
    );

    local_run_verdict(&s, worker_error)
}

/// Whether a finished local-harness run counts as successful.
///
/// A failing or timing-out input is a result, not a broken run - that is what the
/// tool is for. A job the host could not execute is different: nothing was tested,
/// so reporting success would tell the campaign loop that a block ran when it did
/// not. The engine-backend path gates on its own counter the same way.
fn local_run_verdict(stats: &RunStats, worker_error: Option<String>) -> Result<(), String> {
    if let Some(e) = worker_error {
        return Err(e);
    }
    if stats.job_errors > 0 {
        return Err(format!(
            "{} of {} jobs could not be executed (job_errors={})",
            stats.job_errors, stats.total, stats.job_errors
        ));
    }
    Ok(())
}

/// Pull jobs off the shared queue until it is empty, recording each outcome.
///
/// `exec` is built inside each worker thread so it can borrow that thread's own
/// clones of the target and log directory.
fn drain_job_queue(
    queue: &Mutex<VecDeque<RunJob>>,
    stats: &Mutex<RunStats>,
    crash_inputs_dir: &Path,
    exec: &dyn Fn(&RunJob) -> Result<JobOutcome, String>,
) -> Result<(), String> {
    loop {
        let job = {
            let mut guard = queue.lock().map_err(|_| "queue lock poisoned".to_string())?;
            guard.pop_front()
        };

        let Some(job) = job else {
            break;
        };

        // A26: one job the host could not execute - a transient spawn failure, a log
        // that could not be opened - used to abort the whole run and take the record
        // of every finished job with it. Count it and keep draining.
        let (result, retries_used, is_session_ok) = match exec(&job) {
            Ok(outcome) => outcome,
            Err(e) => {
                eprintln!(
                    "[run] warning: job {} ({}) could not be executed: {e}",
                    job.id,
                    job.input.display()
                );
                let mut s = stats.lock().map_err(|_| "stats lock poisoned".to_string())?;
                s.job_errors += 1;
                continue;
            }
        };

        let mut s = stats.lock().map_err(|_| "stats lock poisoned".to_string())?;
        s.retries += retries_used;
        if is_session_ok {
            s.library_session_ok += 1;
        }
        match result {
            HarnessExecResult::Success(_) => s.success += 1,
            HarnessExecResult::Failed(_) => s.failed += 1,
            HarnessExecResult::Timeout(_) => s.timeout += 1,
            HarnessExecResult::Rejected(_) => s.rejected += 1,
        }
        let persist_reproducer = is_reproducer(&result);
        drop(s);
        if persist_reproducer {
            if let Err(e) = persist_crash_input(crash_inputs_dir, job.id, &job.input) {
                eprintln!(
                    "[run] warning: failed to persist reproducer for {}: {e}",
                    job.input.display()
                );
            }
        }
    }
    Ok(())
}

fn run_engine_backend(
    app_paths: &AppPaths,
    artifact: &ArtifactContract,
    target: &TargetKind,
    backend: &RunBackend,
    local: bool,
    corpus_dir: Option<&Path>,
    seed_fixture: Option<&Path>,
    workers: usize,
    timeout_sec: u64,
    restart_limit: u32,
) -> Result<(), String> {
    if workers == 0 {
        return Err("workers must be >= 1".to_string());
    }

    let corpus_dir = match corpus_dir {
        Some(path) => path.to_path_buf(),
        None if local => default_seed_dir(app_paths, target),
        None => app_paths.seeds_dir.clone(),
    };
    if !corpus_dir.exists() || !corpus_dir.is_dir() {
        return Err(format!("corpus_dir is invalid: {}", corpus_dir.display()));
    }

    let run_id = now_unix_millis();
    let run_dir = artifact.runs_root.join(format!("run-{run_id}"));
    let logs_dir = run_dir.join("logs");
    fs::create_dir_all(&logs_dir)
        .map_err(|e| format!("failed to create run dir '{}': {e}", run_dir.display()))?;
    let engine_mode = engine_mode_label(
        backend,
        engine_mode_env_key(backend).and_then(|key| std::env::var(key).ok()),
    );

    println!("[run] start");
    println!("target: {}", target_label(target));
    println!("backend: {}", run_backend_label(backend));
    println!("local_mode: {}", local);
    println!("corpus_dir: {}", corpus_dir.display());
    println!("workers: {}", workers);
    println!("timeout_sec: {}", timeout_sec);
    println!("restart_limit: {}", restart_limit);
    println!("engine_mode: {engine_mode}");
    println!("run_dir: {}", run_dir.display());

    let mut worker_plans = Vec::with_capacity(workers);
    for worker_id in 1..=workers {
        let worker_log_path = logs_dir.join(format!("backend-engine-w{worker_id}.log"));
        let engine_cmd = build_engine_command(
            target,
            backend,
            &corpus_dir,
            &run_dir,
            workers,
            worker_id,
            timeout_sec,
            restart_limit,
            &worker_log_path,
        )?;
        println!("backend_engine_cmd[w{worker_id}]: {engine_cmd}");
        worker_plans.push(EngineWorkerPlan {
            worker_id,
            engine_cmd,
            worker_log_path,
        });
    }

    let mut success = 0usize;
    let mut failed = 0usize;
    let mut timeout = 0usize;

    let handles = worker_plans
        .into_iter()
        .map(|plan| thread::spawn(move || run_engine_worker(plan)))
        .collect::<Vec<_>>();

    // Join every worker before deciding. Returning on the first error skipped crash
    // ingestion, status.json and the metrics event for the whole block, and left the
    // workers still running detached from the run that spawned them.
    let results = handles
        .into_iter()
        .map(|handle| handle.join().map_err(|_| ()))
        .collect::<Vec<_>>();
    let totals = summarize_engine_workers(results);
    success += totals.success;
    failed += totals.failed;
    timeout += totals.timeout;
    let worker_errors = totals.worker_errors;

    let ingest =
        ingest_backend_crash_artifacts(app_paths, &run_dir, run_id, target, backend, timeout_sec);

    let status_path = write_run_status(
        &run_dir,
        run_id,
        target,
        backend,
        RunStatusCounts {
            total: workers,
            success,
            failed,
            timeout,
            rejected: 0,
            retries: 0,
            job_errors: 0,
            worker_errors,
            backend_crash_artifacts: ingest.discovered,
            backend_crashes_triaged: ingest.triaged,
            backend_crash_triage_errors: ingest.errors,
            backend_crash_scan_errors: ingest.scan_errors,
        },
        workers,
        timeout_sec,
        restart_limit,
        &engine_mode,
        &corpus_dir,
        seed_fixture,
    )?;

    println!("[run] done");
    println!("success: {success}");
    println!("failed: {failed}");
    println!("timeout: {timeout}");
    println!("retries: 0");
    println!("backend_crash_artifacts: {}", ingest.discovered);
    println!("backend_crashes_triaged: {}", ingest.triaged);
    println!("backend_crash_triage_errors: {}", ingest.errors);
    println!("worker_errors: {worker_errors}");
    println!("backend_crash_scan_errors: {}", ingest.scan_errors);
    if let Some(manifest_path) = &ingest.manifest_path {
        println!("backend_crash_manifest: {}", manifest_path.display());
    }
    println!("status: {}", status_path.display());

    // status.json is already written; a metrics failure must not turn a finished run
    // into a non-zero exit that a campaign loop reads as a failed block.
    metrics::record_metrics_event_best_effort(
        app_paths,
        MetricEvent {
            ts: now_unix(),
            // A27: one unit here is a worker, not an input. Sharing the local run's
            // kind put worker counts into a per-input denominator.
            kind: metrics::KIND_RUN_BACKEND,
            total: workers as u64,
            errors: (failed + timeout) as u64,
            successful_runs_proxy: success as u64,
            library_session_ok: 0,
            new_crashes: 0,
            valid_crashes: 0,
            total_crashes: 0,
        },
    );

    if failed == 0
        && timeout == 0
        && worker_errors == 0
        && ingest.scan_errors == 0
        && !ingest.manifest_error
    {
        Ok(())
    } else {
        Err(format!(
            "backend '{}' engine command failed (failed={}, timeout={}, worker_errors={}, crash_scan_errors={}, manifest_error={}, run_dir={})",
            run_backend_label(backend),
            failed,
            timeout,
            worker_errors,
            ingest.scan_errors,
            ingest.manifest_error,
            run_dir.display()
        ))
    }
}

struct EngineWorkerTotals {
    success: usize,
    failed: usize,
    timeout: usize,
    worker_errors: usize,
}

/// Fold the joined worker results into block totals.
///
/// A worker that could not be started, or that panicked, is counted separately: it
/// never ran the engine, so calling it a failed run would report a backend failure
/// that did not happen.
fn summarize_engine_workers(
    results: Vec<Result<Result<EngineWorkerResult, String>, ()>>,
) -> EngineWorkerTotals {
    let mut totals = EngineWorkerTotals {
        success: 0,
        failed: 0,
        timeout: 0,
        worker_errors: 0,
    };
    for (index, result) in results.into_iter().enumerate() {
        match result {
            Ok(Ok(worker)) => match worker.outcome {
                EngineWorkerOutcome::Success => totals.success += 1,
                EngineWorkerOutcome::Failed => totals.failed += 1,
                EngineWorkerOutcome::Timeout => totals.timeout += 1,
            },
            Ok(Err(e)) => {
                eprintln!(
                    "[run] warning: backend engine worker {} could not run: {e}",
                    index + 1
                );
                totals.worker_errors += 1;
            }
            Err(()) => {
                eprintln!("[run] warning: backend engine worker {} panicked", index + 1);
                totals.worker_errors += 1;
            }
        }
    }
    totals
}

fn run_engine_worker(plan: EngineWorkerPlan) -> Result<EngineWorkerResult, String> {
    let mut cmd = command_with_core_dump_off("bash");
    cmd.arg("-lc").arg(&plan.engine_cmd);
    let output = cmd.output().map_err(|e| {
        format!(
            "failed to execute backend engine command for worker {}: {e}",
            plan.worker_id
        )
    })?;
    let log_body = format!(
        "worker_id: {}\ncmd: {}\nexit_code: {:?}\n\n[stdout]\n{}\n\n[stderr]\n{}\n",
        plan.worker_id,
        plan.engine_cmd,
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Same reason: the worker has finished and its crash artifacts are already on
    // disk. A log that cannot be written must not turn that into a worker error.
    if let Err(e) = fs::write(&plan.worker_log_path, log_body) {
        eprintln!(
            "[run] warning: failed to write '{}': {e}",
            plan.worker_log_path.display()
        );
    }

    let exit_code = output.status.code().unwrap_or(1);
    let outcome = if output.status.success() {
        EngineWorkerOutcome::Success
    } else if exit_code == 124 {
        EngineWorkerOutcome::Timeout
    } else {
        EngineWorkerOutcome::Failed
    };
    Ok(EngineWorkerResult { outcome })
}

fn ingest_backend_crash_artifacts(
    app_paths: &AppPaths,
    run_dir: &Path,
    run_id: u128,
    target: &TargetKind,
    backend: &RunBackend,
    timeout_sec: u64,
) -> BackendCrashIngest {
    let scan = collect_backend_crash_artifacts(run_dir, backend);
    let artifacts = scan.artifacts;
    if artifacts.is_empty() {
        return BackendCrashIngest {
            discovered: 0,
            triaged: 0,
            errors: 0,
            scan_errors: scan.scan_errors,
            manifest_error: false,
            manifest_path: None,
        };
    }

    let triage_limit = backend_triage_limit();
    let mut triaged = 0usize;
    let mut errors = 0usize;
    let mut entries = Vec::with_capacity(artifacts.len());
    for (idx, artifact) in artifacts.iter().enumerate() {
        let (triage_status, triage_error) = if idx < triage_limit {
            match triage::run_triage_pipeline(app_paths, target, &artifact.path, 1, timeout_sec) {
                Ok(()) => {
                    triaged += 1;
                    ("triaged", String::new())
                }
                Err(err) => {
                    errors += 1;
                    ("triage_failed", err)
                }
            }
        } else {
            ("skipped_limit", String::new())
        };
        entries.push(format!(
            "    {{\"index\": {}, \"kind\": \"{}\", \"path\": \"{}\", \"triage_status\": \"{}\", \"triage_error\": \"{}\"}}",
            idx + 1,
            artifact.kind,
            json_escape(&artifact.path.display().to_string()),
            triage_status,
            json_escape(&triage_error)
        ));
    }

    // The manifest is a convenience index. Triage has already run at this point, so a
    // manifest that cannot be written is reported, not allowed to discard the results.
    let manifest_dir = run_dir.join("backend-crashes");
    let mut manifest_error = false;
    if let Err(e) = fs::create_dir_all(&manifest_dir) {
        eprintln!(
            "[run] warning: failed to create backend crash manifest dir '{}': {e}",
            manifest_dir.display()
        );
        return BackendCrashIngest {
            discovered: artifacts.len(),
            triaged,
            errors,
            scan_errors: scan.scan_errors,
            manifest_error: true,
            manifest_path: None,
        };
    }

    let manifest_path = manifest_dir.join("manifest.json");
    let manifest = format!(
        "{{\n  \"schema_version\": \"1.0\",\n  \"run_id\": \"{}\",\n  \"target\": \"{}\",\n  \"backend\": \"{}\",\n  \"discovered\": {},\n  \"triage_limit\": {},\n  \"triaged\": {},\n  \"errors\": {},\n  \"artifacts\": [\n{}\n  ]\n}}\n",
        run_id,
        target_label(target),
        run_backend_label(backend),
        artifacts.len(),
        triage_limit,
        triaged,
        errors,
        entries.join(",\n")
    );
    let manifest_path = match fs::write(&manifest_path, manifest) {
        Ok(()) => Some(manifest_path),
        Err(e) => {
            eprintln!(
                "[run] warning: failed to write '{}': {e}",
                manifest_path.display()
            );
            manifest_error = true;
            None
        }
    };

    BackendCrashIngest {
        discovered: artifacts.len(),
        triaged,
        errors,
        scan_errors: scan.scan_errors,
        manifest_error,
        manifest_path,
    }
}

fn backend_triage_limit() -> usize {
    std::env::var("TOOL_BACKEND_TRIAGE_MAX_CRASHES")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(32)
}

fn collect_backend_crash_artifacts(run_dir: &Path, backend: &RunBackend) -> BackendCrashScan {
    let mut scan = BackendCrashScan {
        artifacts: Vec::new(),
        scan_errors: 0,
    };
    match backend {
        RunBackend::Aflpp => collect_aflpp_crash_artifacts(run_dir, &mut scan),
        RunBackend::Libfuzzer => collect_libfuzzer_crash_artifacts(run_dir, &mut scan),
        RunBackend::LocalHarness => {}
    }
    scan.artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    scan.artifacts.dedup_by(|a, b| a.path == b.path);
    scan
}

fn collect_aflpp_crash_artifacts(run_dir: &Path, scan: &mut BackendCrashScan) {
    let afl_out = run_dir.join("afl-out");
    if !afl_out.exists() {
        return;
    }
    let entries = match fs::read_dir(&afl_out) {
        Ok(entries) => entries,
        Err(e) => {
            scan.note_error(format!("failed to read '{}': {e}", afl_out.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                scan.note_error(format!("failed to read afl-out entry: {e}"));
                continue;
            }
        };
        let fuzzer_dir = entry.path();
        if !fuzzer_dir.is_dir() {
            continue;
        }
        let crashes_dir = fuzzer_dir.join("crashes");
        collect_files_in_dir(&crashes_dir, "aflpp_crash", scan);
    }
}

fn collect_libfuzzer_crash_artifacts(run_dir: &Path, scan: &mut BackendCrashScan) {
    let artifact_root = run_dir.join("backend-artifacts");
    collect_prefixed_files_recursive(&artifact_root, "libfuzzer_crash", scan);
}

fn collect_prefixed_files_recursive(dir: &Path, kind: &'static str, scan: &mut BackendCrashScan) {
    if !dir.exists() {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            scan.note_error(format!("failed to read '{}': {e}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                scan.note_error(format!("failed to read artifact entry: {e}"));
                continue;
            }
        };
        let path = entry.path();
        if path.is_dir() {
            collect_prefixed_files_recursive(&path, kind, scan);
        } else if is_libfuzzer_artifact_file(&path) {
            scan.artifacts.push(BackendCrashArtifact { path, kind });
        }
    }
}

fn collect_files_in_dir(dir: &Path, kind: &'static str, scan: &mut BackendCrashScan) {
    if !dir.exists() {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            scan.note_error(format!("failed to read '{}': {e}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                scan.note_error(format!("failed to read artifact entry: {e}"));
                continue;
            }
        };
        let path = entry.path();
        let is_file = match dir_entry_is_file(&entry) {
            Ok(is_file) => is_file,
            Err(e) => {
                scan.note_error(format!("failed to stat '{}': {e}", path.display()));
                continue;
            }
        };
        if is_file && !is_aflpp_metadata_file(&path) {
            scan.artifacts.push(BackendCrashArtifact { path, kind });
        }
    }
}

/// Whether a directory entry names a regular file, following a symlink.
///
/// The listing itself carries the entry type, so this still answers when the
/// directory denies search and stat-ing the entry does not. `Path::is_file` alone
/// reports "not a file" for that permission error, which used to drop a real crash
/// artifact without a trace.
fn dir_entry_is_file(entry: &fs::DirEntry) -> std::io::Result<bool> {
    if let Ok(file_type) = entry.file_type() {
        if !file_type.is_symlink() {
            return Ok(file_type.is_file());
        }
    }
    entry.path().metadata().map(|meta| meta.is_file())
}

fn is_aflpp_metadata_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "README.txt" || name.starts_with('.'))
        .unwrap_or(false)
}

fn is_libfuzzer_artifact_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            ["crash-", "oom-", "timeout-", "leak-"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
        .unwrap_or(false)
}

fn build_engine_command(
    target: &TargetKind,
    backend: &RunBackend,
    corpus_dir: &Path,
    run_dir: &Path,
    workers: usize,
    worker_id: usize,
    timeout_sec: u64,
    restart_limit: u32,
    worker_log_path: &Path,
) -> Result<String, String> {
    let engine = resolve_engine_adapter(backend)?;
    let target_adapter = resolve_target_adapter(target);
    let docker_user_flag = current_docker_user_flag();
    let docker_hardening_flags = docker_hardening_flags();
    let docker_readonly_flags = docker_readonly_flags();
    let workdir_abs =
        absolute_path(&std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let corpus_dir_abs = absolute_path(corpus_dir);
    let run_dir_abs = absolute_path(run_dir);
    let artifact_dir = run_dir
        .join("backend-artifacts")
        .join(format!("w{worker_id}"));
    fs::create_dir_all(&artifact_dir).map_err(|e| {
        format!(
            "failed to create backend artifact dir '{}': {e}",
            artifact_dir.display()
        )
    })?;
    let template = std::env::var(engine.cmd_env).map_err(|_| {
        format!(
            "{} is not set; provide backend command template. example: {}='echo run {{target}} {{corpus_dir}}; true'",
            engine.cmd_env, engine.cmd_env
        )
    })?;
    if template.trim().is_empty() {
        return Err(format!("{} is empty", engine.cmd_env));
    }

    let cmd = template
        .replace("{target}", target_adapter.target_label)
        .replace("{backend}", engine.backend_label)
        .replace("{corpus_dir}", &shell_escape(corpus_dir))
        .replace("{workers}", &workers.to_string())
        .replace("{worker_id}", &worker_id.to_string())
        .replace("{timeout_sec}", &timeout_sec.to_string())
        .replace("{restart_limit}", &restart_limit.to_string())
        .replace("{docker_user_flag}", &docker_user_flag)
        .replace("{docker_hardening_flags}", docker_hardening_flags)
        .replace("{docker_readonly_flags}", docker_readonly_flags)
        .replace("{run_dir}", &shell_escape(run_dir))
        .replace("{artifact_dir}", &shell_escape(&artifact_dir))
        .replace("{workdir_abs}", &shell_escape(&workdir_abs))
        .replace("{corpus_dir_abs}", &shell_escape(&corpus_dir_abs))
        .replace("{run_dir_abs}", &shell_escape(&run_dir_abs))
        .replace("{container_workdir}", "/work")
        .replace("{container_corpus_dir}", "/corpus")
        .replace("{container_run_dir}", "/out")
        .replace("{workdir}", &shell_escape(&workdir_abs))
        .replace("{worker_log}", &shell_escape(worker_log_path));

    Ok(cmd)
}

fn current_docker_user_flag() -> String {
    let uid = read_id_output("-u");
    let gid = read_id_output("-g");
    match (uid, gid) {
        (Some(uid), Some(gid)) => format!("--user {uid}:{gid}"),
        _ => String::new(),
    }
}

fn docker_hardening_flags() -> &'static str {
    "--network none --memory 4g --cpus 2 --pids-limit 512"
}

fn docker_readonly_flags() -> &'static str {
    "--read-only --tmpfs /tmp:rw,size=1g --tmpfs /dev/shm:rw,size=1g"
}

fn absolute_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn read_id_output(flag: &str) -> Option<String> {
    let out = Command::new("id").arg(flag).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn resolve_engine_adapter(backend: &RunBackend) -> Result<EngineAdapter, String> {
    match backend {
        RunBackend::Aflpp => Ok(EngineAdapter {
            backend_label: "aflpp",
            cmd_env: "TOOL_AFLPP_CMD",
        }),
        RunBackend::Libfuzzer => Ok(EngineAdapter {
            backend_label: "libfuzzer",
            cmd_env: "TOOL_LIBFUZZER_CMD",
        }),
        RunBackend::LocalHarness => {
            Err("internal error: local-harness should not use engine command".to_string())
        }
    }
}

fn run_job_with_retry(
    job: &RunJob,
    target: &TargetKind,
    timeout_sec: u64,
    restart_limit: u32,
    timeout_available: bool,
    logs_dir: &Path,
) -> Result<JobOutcome, String> {
    let attempts = restart_limit + 1;
    let mut last = HarnessExecResult::Failed("not executed".to_string());
    let mut last_session_ok = false;
    let mut retries_used = 0usize;

    for attempt in 1..=attempts {
        let (result, is_session_ok) =
            execute_harness_subprocess(job, target, timeout_sec, timeout_available)?;
        last_session_ok = is_session_ok;
        // Review follow-up: the harness has already run and its verdict is in hand.
        // Failing here on a full disk or an fd limit threw that verdict away - and
        // for an input that had just crashed the library, the reproducer was never
        // persisted. A log is evidence about a result, not the result.
        if let Err(e) = write_job_log(logs_dir, job, attempt, &result) {
            eprintln!("[run] warning: failed to write the job log: {e}");
        }
        if !should_retry(&result) {
            return Ok((result, retries_used, is_session_ok));
        }
        last = result;
        if attempt < attempts {
            retries_used += 1;
        }
    }

    Ok((last, retries_used, last_session_ok))
}

// A10: local-harness runs record only counters; a crashing/hanging input still lives
// only in the mutation batch dir, which retention prunes. Copy it into the durable
// run dir so the reproducer survives to be triaged/reported.
fn persist_crash_input(
    crash_inputs_dir: &Path,
    job_id: usize,
    input: &Path,
) -> std::io::Result<PathBuf> {
    fs::create_dir_all(crash_inputs_dir)?;
    let name = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("input");
    // job_id keeps the name unique within a run and preserves provenance.
    let dest = crash_inputs_dir.join(format!("job-{job_id:06}-{name}"));
    fs::copy(input, &dest)?;
    Ok(dest)
}

pub(crate) fn execute_harness_subprocess(
    job: &RunJob,
    target: &TargetKind,
    timeout_sec: u64,
    timeout_available: bool,
) -> Result<(HarnessExecResult, bool), String> {
    let exe = std::env::current_exe().map_err(|e| format!("failed to resolve current exe: {e}"))?;
    let target_name = target_label(target).to_string();

    let mut cmd = if timeout_available {
        let mut c = command_with_core_dump_off("timeout");
        c.arg(format!("{}s", timeout_sec));
        c.arg(&exe);
        c
    } else {
        command_with_core_dump_off(&exe)
    };
    cmd.arg("harness")
        .arg("--target")
        .arg(&target_name)
        .arg("--input")
        .arg(&job.input)
        .env("OMP_NUM_THREADS", "1")
        .env("MKL_NUM_THREADS", "1")
        .env("OPENBLAS_NUM_THREADS", "1")
        .env("NUMEXPR_NUM_THREADS", "1")
        .env("VECLIB_MAXIMUM_THREADS", "1");

    // A9: the external `timeout` bounds the run where it exists; where it does not, the
    // child used to run unbounded, so enforce the same budget in-process instead.
    let (out, timed_out) = if timeout_available {
        let out = cmd
            .output()
            .map_err(|e| format!("failed to execute harness subprocess: {e}"))?;
        let timed_out = out.status.code() == Some(124);
        (out, timed_out)
    } else {
        output_with_deadline(cmd, timeout_sec)
            .map_err(|e| format!("failed to execute harness subprocess: {e}"))?
    };
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let is_session_ok = stdout
        .lines()
        .any(|l| l.trim() == "library_outcome: session_ok");
    let summary = format!(
        "stdout: {}\nstderr: {}",
        first_line(&stdout),
        first_line(&stderr)
    );

    Ok((
        harness_exec_result(out.status.success(), out.status.code(), timed_out, summary),
        is_session_ok,
    ))
}

// G3: the run pipeline keys off the same exit-code split as triage and the engine
// drivers. Only the rejected-input code is carved out; an unavailable harness stays a
// failed job (a strict-gate host problem shows up as every job failing), and every other
// non-zero exit and every signal death stays Failed so a real crash is never dropped.
fn harness_exec_result(
    success: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    summary: String,
) -> HarnessExecResult {
    if timed_out {
        return HarnessExecResult::Timeout(summary);
    }
    if success {
        return HarnessExecResult::Success(summary);
    }
    if exit_code == Some(i32::from(crate::EXIT_HARNESS_INPUT_REJECTED)) {
        return HarnessExecResult::Rejected(summary);
    }
    HarnessExecResult::Failed(summary)
}

// Only a crash or a hang can differ between attempts. A success needs no retry and a
// rejected input is deterministic, so retrying it just burns the restart budget.
fn should_retry(result: &HarnessExecResult) -> bool {
    matches!(
        result,
        HarnessExecResult::Failed(_) | HarnessExecResult::Timeout(_)
    )
}

// A10: only a crash or a hang leaves a reproducer worth keeping; an input the harness
// rejected never reached the library, so persisting it just fills the crash dir.
fn is_reproducer(result: &HarnessExecResult) -> bool {
    matches!(
        result,
        HarnessExecResult::Failed(_) | HarnessExecResult::Timeout(_)
    )
}

pub(crate) fn write_job_log(
    logs_dir: &Path,
    job: &RunJob,
    attempt: u32,
    result: &HarnessExecResult,
) -> Result<(), String> {
    let path = logs_dir.join(format!("job-{:05}-attempt-{}.log", job.id, attempt));
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| format!("failed to open '{}': {e}", path.display()))?;
    let (kind, summary) = match result {
        HarnessExecResult::Success(s) => ("success", s.as_str()),
        HarnessExecResult::Failed(s) => ("failed", s.as_str()),
        HarnessExecResult::Timeout(s) => ("timeout", s.as_str()),
        HarnessExecResult::Rejected(s) => ("rejected", s.as_str()),
    };
    let body = format!(
        "job_id: {}\ninput: {}\nattempt: {}\nresult: {}\n{}\n",
        job.id,
        job.input.display(),
        attempt,
        kind,
        summary
    );
    f.write_all(body.as_bytes())
        .map_err(|e| format!("failed to write '{}': {e}", path.display()))
}

// G2/G4: the loop scripts know whether the engine really runs instrumented/native or
// fell back to black-box mode, and they pass that label in through the environment.
// Persisting it in the run status keeps a black-box arm from being reported as native
// later; anything unlabelled or unexpected is recorded as "unlabeled" rather than
// interpolated verbatim into status.json.
fn engine_mode_env_key(backend: &RunBackend) -> Option<&'static str> {
    match backend {
        RunBackend::LocalHarness => None,
        RunBackend::Aflpp => Some("TOOL_AFLPP_MODE"),
        RunBackend::Libfuzzer => Some("TOOL_LIBFUZZER_MODE"),
    }
}

fn engine_mode_label(backend: &RunBackend, raw: Option<String>) -> String {
    if matches!(backend, RunBackend::LocalHarness) {
        return "local_harness".to_string();
    }
    let raw = raw.unwrap_or_default();
    let label = raw.trim();
    let plausible = !label.is_empty()
        && label.len() <= 32
        && label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if plausible {
        label.to_string()
    } else {
        "unlabeled".to_string()
    }
}

fn run_backend_label(backend: &RunBackend) -> &'static str {
    match backend {
        RunBackend::LocalHarness => "local-harness",
        RunBackend::Aflpp => "aflpp",
        RunBackend::Libfuzzer => "libfuzzer",
    }
}

fn write_run_status(
    run_dir: &Path,
    run_id: u128,
    target: &TargetKind,
    backend: &RunBackend,
    counts: RunStatusCounts,
    workers: usize,
    timeout_sec: u64,
    restart_limit: u32,
    engine_mode: &str,
    corpus_dir: &Path,
    seed_fixture: Option<&Path>,
) -> Result<PathBuf, String> {
    let status_path = run_dir.join("status.json");
    // Record the source selected by the caller, never infer it from a mutable
    // corpus or a neighboring marker. This is a path label, not a content hash or
    // a claim that every current corpus input came from that fixture. Preserve
    // caller spelling; relative paths are relative to the run's working directory.
    let seed_fixture_json = seed_fixture
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| format!("\"{}\"", json_escape(&path.display().to_string())))
        .unwrap_or_else(|| "null".to_string());
    let status_json = format!(
        "{{\n  \"run_id\": \"{}\",\n  \"target\": \"{}\",\n  \"backend\": \"{}\",\n  \"total\": {},\n  \"success\": {},\n  \"failed\": {},\n  \"timeout\": {},\n  \"rejected\": {},\n  \"retries\": {},\n  \"job_errors\": {},\n  \"worker_errors\": {},\n  \"workers\": {},\n  \"timeout_sec\": {},\n  \"restart_limit\": {},\n  \"engine_mode\": \"{}\",\n  \"backend_crash_artifacts\": {},\n  \"backend_crashes_triaged\": {},\n  \"backend_crash_triage_errors\": {},\n  \"backend_crash_scan_errors\": {},\n  \"corpus_dir\": \"{}\",\n  \"seed_fixture\": {}\n}}\n",
        run_id,
        target_label(target),
        run_backend_label(backend),
        counts.total,
        counts.success,
        counts.failed,
        counts.timeout,
        counts.rejected,
        counts.retries,
        counts.job_errors,
        counts.worker_errors,
        workers,
        timeout_sec,
        restart_limit,
        json_escape(engine_mode),
        counts.backend_crash_artifacts,
        counts.backend_crashes_triaged,
        counts.backend_crash_triage_errors,
        counts.backend_crash_scan_errors,
        json_escape(&corpus_dir.display().to_string()),
        seed_fixture_json
    );
    fs::write(&status_path, status_json)
        .map_err(|e| format!("failed to write '{}': {e}", status_path.display()))?;
    Ok(status_path)
}

#[cfg(test)]
mod tests {
    use super::{
        collect_backend_crash_artifacts, persist_crash_input, run_fuzz_pipeline, RunBackend,
    };
    use crate::common::AppPaths;
    use crate::target::TargetKind;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    // Review follow-up: the run pipeline must key off the same exit-code split as triage
    // and the engine drivers - a rejected input is not a failed job and has no reproducer.
    #[test]
    fn harness_exec_result_separates_rejected_inputs_from_crashes() {
        use super::harness_exec_result;
        use crate::common::HarnessExecResult;

        let summary = || "stdout: ; stderr: ".to_string();
        assert!(matches!(
            harness_exec_result(true, Some(0), false, summary()),
            HarnessExecResult::Success(_)
        ));
        assert!(matches!(
            harness_exec_result(
                false,
                Some(i32::from(crate::EXIT_HARNESS_LIBRARY_CRASH)),
                false,
                summary()
            ),
            HarnessExecResult::Failed(_)
        ));
        assert!(matches!(
            harness_exec_result(false, None, false, summary()),
            HarnessExecResult::Failed(_)
        ));
        assert!(matches!(
            harness_exec_result(
                false,
                Some(i32::from(crate::EXIT_HARNESS_INPUT_REJECTED)),
                false,
                summary()
            ),
            HarnessExecResult::Rejected(_)
        ));
        assert!(matches!(
            harness_exec_result(false, Some(124), true, summary()),
            HarnessExecResult::Timeout(_)
        ));
    }

    #[test]
    fn rejected_inputs_are_not_retried() {
        use super::should_retry;
        use crate::common::HarnessExecResult;

        assert!(should_retry(&HarnessExecResult::Failed(String::new())));
        assert!(should_retry(&HarnessExecResult::Timeout(String::new())));
        assert!(!should_retry(&HarnessExecResult::Success(String::new())));
        assert!(!should_retry(&HarnessExecResult::Rejected(String::new())));
    }

    #[test]
    fn only_crashes_and_hangs_are_kept_as_reproducers() {
        use super::is_reproducer;
        use crate::common::HarnessExecResult;

        assert!(is_reproducer(&HarnessExecResult::Failed(String::new())));
        assert!(is_reproducer(&HarnessExecResult::Timeout(String::new())));
        assert!(!is_reproducer(&HarnessExecResult::Success(String::new())));
        assert!(!is_reproducer(&HarnessExecResult::Rejected(String::new())));
    }

    // G2/G4: the engine loops decide whether a run is really native/instrumented or a
    // black-box fallback; the run status must carry that label so a black-box arm can
    // never be written up as a native coverage-guided one afterwards.
    #[test]
    fn engine_mode_label_records_the_loop_label_and_rejects_junk() {
        use super::engine_mode_label;

        assert_eq!(
            engine_mode_label(&RunBackend::Aflpp, Some("instrumented".to_string())),
            "instrumented"
        );
        assert_eq!(
            engine_mode_label(&RunBackend::Aflpp, Some(" blackbox_n \n".to_string())),
            "blackbox_n"
        );
        assert_eq!(
            engine_mode_label(&RunBackend::Libfuzzer, Some("native".to_string())),
            "native"
        );
        // an unlabelled backend run must not claim a mode it cannot prove
        assert_eq!(engine_mode_label(&RunBackend::Libfuzzer, None), "unlabeled");
        assert_eq!(
            engine_mode_label(&RunBackend::Libfuzzer, Some(String::new())),
            "unlabeled"
        );
        // never interpolate arbitrary env text into status.json
        assert_eq!(
            engine_mode_label(&RunBackend::Aflpp, Some("native\", \"x\": \"y".to_string())),
            "unlabeled"
        );
        assert_eq!(
            engine_mode_label(&RunBackend::LocalHarness, Some("native".to_string())),
            "local_harness"
        );
    }

    #[test]
    fn run_status_records_the_engine_mode() {
        use super::{write_run_status, RunStatusCounts};

        let run_dir = unique_temp_dir("engine-mode-status");
        fs::create_dir_all(&run_dir).expect("create run dir");
        let status_path = write_run_status(
            &run_dir,
            42,
            &TargetKind::Onnx,
            &RunBackend::Aflpp,
            RunStatusCounts {
                total: 1,
                success: 1,
                failed: 0,
                timeout: 0,
                rejected: 0,
                retries: 0,
                job_errors: 0,
                worker_errors: 0,
                backend_crash_artifacts: 0,
                backend_crashes_triaged: 0,
                backend_crash_triage_errors: 0,
                backend_crash_scan_errors: 0,
            },
            1,
            30,
            1,
            "blackbox_n",
            std::path::Path::new("seeds/onnx"),
            None,
        )
        .expect("write status");

        let status = fs::read_to_string(&status_path).expect("read status");
        assert!(
            status.contains("\"engine_mode\": \"blackbox_n\""),
            "status was: {status}"
        );
        let _ = fs::remove_dir_all(&run_dir);
    }

    // A29: `timeout 0s` means "no limit" under GNU coreutils, so a zero budget used to
    // be accepted and silently unbound every job.
    #[test]
    fn run_pipeline_rejects_a_zero_timeout() {
        let root = unique_temp_dir("a29-run");
        let seeds = root.join("seeds");
        fs::create_dir_all(&seeds).expect("create seeds dir");
        let paths = AppPaths::prepare(&root.join("data"), &seeds).expect("prepare paths");

        let err = run_fuzz_pipeline(
            &paths,
            &TargetKind::Onnx,
            &RunBackend::LocalHarness,
            true,
            None,
            None,
            1,
            0,
            1,
            None,
        )
        .expect_err("timeout_sec=0 must be rejected");

        assert!(err.contains("timeout_sec"), "err was: {err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn persist_crash_input_survives_batch_dir_deletion() {
        // A10: a local-harness crashing input must be copied into run_dir/crash-inputs/
        // so the reproducer survives when mutation-batch retention prunes the batch dir.
        let root = unique_temp_dir("a10-persist");
        let batch = root.join("batch-000");
        fs::create_dir_all(&batch).expect("create batch dir");
        let input = batch.join("crash.onnx");
        fs::write(&input, b"crashing-onnx-bytes").expect("write input");

        let crash_dir = root.join("run-x").join("crash-inputs");
        let dest = persist_crash_input(&crash_dir, 7, &input).expect("persist");

        // simulate mutation-batch retention deleting the whole batch dir
        fs::remove_dir_all(&batch).expect("prune batch");

        assert!(dest.exists(), "reproducer must survive batch deletion");
        assert_eq!(fs::read(&dest).expect("read dest"), b"crashing-onnx-bytes");
        assert!(dest
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains("crash.onnx")));

        let _ = fs::remove_dir_all(&root);
    }

    // A26: one job that could not be executed aborted the whole local-harness run
    // through `?`, so status.json and the metrics event for every job that had
    // already finished were thrown away with it.
    // Review follow-up: the stage made an unrunnable job non-fatal so the finished
    // jobs kept their record - but then never failed the run, so a block in which
    // NOTHING executed exited 0. The campaign loop reads that exit code, so hours of
    // fuzzing could vanish without an alert. The engine path already gates on its
    // own counter; the local path has to match.
    #[test]
    fn a_run_whose_jobs_could_not_execute_does_not_report_success() {
        use super::{local_run_verdict, RunStats};

        let clean = RunStats {
            total: 3,
            success: 3,
            ..RunStats::default()
        };
        assert!(local_run_verdict(&clean, None).is_ok());

        let some_failed = RunStats {
            total: 3,
            success: 2,
            failed: 1,
            ..RunStats::default()
        };
        assert!(
            local_run_verdict(&some_failed, None).is_ok(),
            "a failing input is a result, not a broken run"
        );

        let could_not_run = RunStats {
            total: 3,
            success: 2,
            job_errors: 1,
            ..RunStats::default()
        };
        let err = local_run_verdict(&could_not_run, None)
            .expect_err("a job that never executed must fail the run");
        assert!(err.contains("job_errors=1"), "err was: {err}");

        let poisoned = RunStats {
            total: 1,
            success: 1,
            ..RunStats::default()
        };
        assert_eq!(
            local_run_verdict(&poisoned, Some("worker thread panicked".to_string())),
            Err("worker thread panicked".to_string()),
            "a worker error still wins"
        );
    }

    #[test]
    fn a_job_that_cannot_be_spawned_does_not_discard_the_finished_jobs() {
        use super::{drain_job_queue, RunJob, RunStats};
        use crate::common::HarnessExecResult;
        use std::collections::VecDeque;
        use std::sync::Mutex;

        let jobs: VecDeque<RunJob> = (0..3)
            .map(|id| RunJob {
                id,
                input: PathBuf::from(format!("seed-{id}.onnx")),
            })
            .collect();
        let queue = Mutex::new(jobs);
        let stats = Mutex::new(RunStats {
            total: 3,
            ..RunStats::default()
        });
        let crash_inputs_dir = unique_temp_dir("a26-crash-inputs");

        let exec = |job: &RunJob| {
            if job.id == 1 {
                Err("failed to spawn harness: Too many open files".to_string())
            } else {
                Ok((HarnessExecResult::Success(String::new()), 0, true))
            }
        };

        drain_job_queue(&queue, &stats, &crash_inputs_dir, &exec).expect("drain must not abort");

        assert!(
            queue.lock().expect("queue").is_empty(),
            "the queue must still be drained"
        );
        let s = stats.lock().expect("stats");
        assert_eq!(s.success, 2, "the finished jobs must survive");
        assert_eq!(s.failed, 0, "an unrunnable job is not a failed job");
        assert_eq!(s.job_errors, 1);

        let _ = fs::remove_dir_all(&crash_inputs_dir);
    }

    #[test]
    fn run_status_records_the_jobs_that_could_not_run() {
        use super::{write_run_status, RunStatusCounts};

        let run_dir = unique_temp_dir("a26-job-errors-status");
        fs::create_dir_all(&run_dir).expect("create run dir");
        let status_path = write_run_status(
            &run_dir,
            9,
            &TargetKind::Onnx,
            &RunBackend::LocalHarness,
            RunStatusCounts {
                total: 3,
                success: 2,
                failed: 0,
                timeout: 0,
                rejected: 0,
                retries: 0,
                job_errors: 1,
                worker_errors: 0,
                backend_crash_artifacts: 0,
                backend_crashes_triaged: 0,
                backend_crash_triage_errors: 0,
                backend_crash_scan_errors: 0,
            },
            1,
            30,
            1,
            "local_harness",
            std::path::Path::new("seeds/onnx"),
            None,
        )
        .expect("write status");

        let status = fs::read_to_string(&status_path).expect("read status");
        assert!(
            status.contains("\"job_errors\": 1"),
            "status was: {status}"
        );
        let _ = fs::remove_dir_all(&run_dir);
    }

    // The engine-backend twin of A26: one worker whose bash could not be started
    // returned Err out of the join loop, so ingest, status.json and the metrics event
    // never ran for the block, and the workers still running were left unjoined.
    #[test]
    fn an_engine_worker_that_cannot_start_does_not_discard_the_other_workers() {
        use super::{summarize_engine_workers, EngineWorkerOutcome, EngineWorkerResult};

        let totals = summarize_engine_workers(vec![
            Ok(Ok(EngineWorkerResult {
                outcome: EngineWorkerOutcome::Success,
            })),
            Ok(Err("failed to execute backend engine command for worker 2".to_string())),
            Ok(Ok(EngineWorkerResult {
                outcome: EngineWorkerOutcome::Timeout,
            })),
            Err(()),
        ]);

        assert_eq!(totals.success, 1);
        assert_eq!(totals.timeout, 1);
        assert_eq!(totals.failed, 0, "a worker that never ran is not a failed run");
        assert_eq!(totals.worker_errors, 2, "the error and the panic both count");
    }

    #[test]
    fn run_status_records_engine_worker_errors() {
        use super::{write_run_status, RunStatusCounts};

        let run_dir = unique_temp_dir("engine-worker-errors-status");
        fs::create_dir_all(&run_dir).expect("create run dir");
        let status_path = write_run_status(
            &run_dir,
            11,
            &TargetKind::Onnx,
            &RunBackend::Libfuzzer,
            RunStatusCounts {
                total: 2,
                success: 1,
                failed: 0,
                timeout: 0,
                rejected: 0,
                retries: 0,
                job_errors: 0,
                worker_errors: 1,
                backend_crash_artifacts: 0,
                backend_crashes_triaged: 0,
                backend_crash_triage_errors: 0,
                backend_crash_scan_errors: 0,
            },
            2,
            30,
            1,
            "blackbox",
            std::path::Path::new("seeds/onnx"),
            None,
        )
        .expect("write status");

        let status = fs::read_to_string(&status_path).expect("read status");
        assert!(
            status.contains("\"worker_errors\": 1"),
            "status was: {status}"
        );
        let _ = fs::remove_dir_all(&run_dir);
    }

    #[test]
    fn collects_aflpp_crash_files_without_readme() {
        let run_dir = unique_temp_dir("aflpp-crash-collect");
        let crashes = run_dir.join("afl-out").join("default").join("crashes");
        fs::create_dir_all(&crashes).expect("create crashes dir");
        fs::write(crashes.join("README.txt"), b"metadata").expect("write readme");
        fs::write(crashes.join("id:000000,sig:08"), b"crash").expect("write crash");

        let scan = collect_backend_crash_artifacts(&run_dir, &RunBackend::Aflpp);
        assert_eq!(scan.scan_errors, 0);
        assert_eq!(scan.artifacts.len(), 1);
        assert!(scan.artifacts[0].path.ends_with("id:000000,sig:08"));

        let _ = fs::remove_dir_all(&run_dir);
    }

    // A28: a crash directory the process cannot read used to abort the whole engine run
    // through `?`, so status.json and the metrics event for a block that had already
    // finished were never written. An unreadable directory is now counted, not fatal.
    #[test]
    fn an_unreadable_crash_dir_is_counted_not_fatal() {
        use std::os::unix::fs::PermissionsExt;

        let run_dir = unique_temp_dir("a28-unreadable-crashes");
        let crashes = run_dir.join("afl-out").join("default").join("crashes");
        fs::create_dir_all(&crashes).expect("create crashes dir");
        fs::write(crashes.join("id:000000,sig:11"), b"crash").expect("write crash");
        fs::set_permissions(&crashes, fs::Permissions::from_mode(0o000)).expect("chmod");

        if fs::read_dir(&crashes).is_ok() {
            // Running as root, where the mode is not enforced. Nothing to assert.
            let _ = fs::set_permissions(&crashes, fs::Permissions::from_mode(0o755));
            let _ = fs::remove_dir_all(&run_dir);
            return;
        }

        let scan = collect_backend_crash_artifacts(&run_dir, &RunBackend::Aflpp);
        assert_eq!(scan.scan_errors, 1, "the unreadable directory must be counted");
        assert!(scan.artifacts.is_empty());

        let _ = fs::set_permissions(&crashes, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&run_dir);
    }

    #[test]
    fn run_status_records_the_crash_scan_errors() {
        use super::{write_run_status, RunStatusCounts};

        let run_dir = unique_temp_dir("a28-scan-errors-status");
        fs::create_dir_all(&run_dir).expect("create run dir");
        let status_path = write_run_status(
            &run_dir,
            7,
            &TargetKind::Onnx,
            &RunBackend::Aflpp,
            RunStatusCounts {
                total: 1,
                success: 1,
                failed: 0,
                timeout: 0,
                rejected: 0,
                retries: 0,
                job_errors: 0,
                worker_errors: 0,
                backend_crash_artifacts: 0,
                backend_crashes_triaged: 0,
                backend_crash_triage_errors: 0,
                backend_crash_scan_errors: 2,
            },
            1,
            30,
            1,
            "blackbox_n",
            std::path::Path::new("seeds/onnx"),
            None,
        )
        .expect("write status");

        let status = fs::read_to_string(&status_path).expect("read status");
        assert!(
            status.contains("\"backend_crash_scan_errors\": 2"),
            "status was: {status}"
        );
        let _ = fs::remove_dir_all(&run_dir);
    }

    // The crash file is listed but not stat-able when the directory denies search.
    // `Path::is_file` reports "not a file" for that permission error, which dropped a
    // real AFL++ crash artifact with neither an artifact nor an error to show for it.
    #[test]
    fn a_crash_file_in_a_search_denied_dir_is_not_silently_dropped() {
        use std::os::unix::fs::PermissionsExt;

        let run_dir = unique_temp_dir("aflpp-search-denied");
        let crashes = run_dir.join("afl-out").join("default").join("crashes");
        fs::create_dir_all(&crashes).expect("create crashes dir");
        let crash = crashes.join("id:000000,sig:11");
        fs::write(&crash, b"crash").expect("write crash");
        fs::set_permissions(&crashes, fs::Permissions::from_mode(0o444)).expect("chmod");

        if crash.metadata().is_ok() {
            // Running as root, where the mode is not enforced. Nothing to assert.
            let _ = fs::set_permissions(&crashes, fs::Permissions::from_mode(0o755));
            let _ = fs::remove_dir_all(&run_dir);
            return;
        }

        let scan = collect_backend_crash_artifacts(&run_dir, &RunBackend::Aflpp);
        assert_eq!(scan.artifacts.len(), 1, "the crash must not be dropped");
        assert!(scan.artifacts[0].path.ends_with("id:000000,sig:11"));

        let _ = fs::set_permissions(&crashes, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&run_dir);
    }

    // The listing reports a symlink's own type, which says nothing about its target,
    // so the target still has to be consulted.
    #[test]
    fn a_symlinked_crash_file_is_still_collected() {
        let run_dir = unique_temp_dir("aflpp-symlinked-crash");
        let crashes = run_dir.join("afl-out").join("default").join("crashes");
        fs::create_dir_all(&crashes).expect("create crashes dir");
        let real = run_dir.join("real-crash");
        fs::write(&real, b"crash").expect("write crash");
        std::os::unix::fs::symlink(&real, crashes.join("id:000001,sig:06")).expect("symlink");

        let scan = collect_backend_crash_artifacts(&run_dir, &RunBackend::Aflpp);
        assert_eq!(scan.artifacts.len(), 1);
        assert!(scan.artifacts[0].path.ends_with("id:000001,sig:06"));

        let _ = fs::remove_dir_all(&run_dir);
    }

    #[test]
    fn collects_libfuzzer_prefixed_artifacts() {
        let run_dir = unique_temp_dir("libfuzzer-crash-collect");
        let worker_dir = run_dir.join("backend-artifacts").join("w1");
        fs::create_dir_all(&worker_dir).expect("create worker artifact dir");
        fs::write(worker_dir.join("note.txt"), b"metadata").expect("write note");
        fs::write(worker_dir.join("crash-deadbeef"), b"crash").expect("write crash");

        let scan = collect_backend_crash_artifacts(&run_dir, &RunBackend::Libfuzzer);
        assert_eq!(scan.scan_errors, 0);
        assert_eq!(scan.artifacts.len(), 1);
        assert!(scan.artifacts[0].path.ends_with("crash-deadbeef"));

        let _ = fs::remove_dir_all(&run_dir);
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("tool-{name}-{}-{nanos}", std::process::id()))
    }
}
