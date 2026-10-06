use std::{fs, path::Path, process::ExitStatus};

use crate::common::{
    command_exists, command_with_core_dump_off, now_unix, now_unix_millis, output_with_deadline,
    validate_timeout_sec, AppPaths,
};
use crate::json_utils::json_escape;
use crate::metrics::MetricEvent;
use crate::target::{target_label, TargetKind};

struct TriageAttempt {
    attempt: u32,
    result: String,
    exit_code: Option<i32>,
    signal: String,
    sanitizer: String,
    crash_kind: String,
    crash_summary: String,
    signature_top3: Vec<String>,
    top_frames: Vec<String>,
    normalized_frames: Vec<String>,
    normalized_frame_hash: String,
    timeout: bool,
    infra_oom: bool,
}

struct TriageExecResult {
    result: TriageResult,
    output: String,
    exit_code: Option<i32>,
    signal: Option<i32>,
}

struct DeepTriageMetadata {
    version: &'static str,
    status: &'static str,
    grouping_confidence: &'static str,
    grouping_reason: &'static str,
    evidence_quality: &'static str,
    evidence_gaps: Vec<&'static str>,
    suggested_next_steps: Vec<&'static str>,
    replay_commands: Vec<String>,
}

#[derive(Debug)]
enum TriageResult {
    Clean,
    Crashed,
    Timeout,
}

pub(crate) fn run_triage_pipeline(
    app_paths: &AppPaths,
    target: &TargetKind,
    input: &Path,
    repro_retries: u32,
    timeout_sec: u64,
) -> Result<(), String> {
    if !input.exists() || !input.is_file() {
        return Err(format!("input is invalid: {}", input.display()));
    }
    if repro_retries == 0 {
        return Err("repro_retries must be >= 1".to_string());
    }
    // A29: `timeout 0s` means "no limit", so a zero budget silently unbounded every attempt.
    let timeout_sec = validate_timeout_sec(timeout_sec)?;

    let triage_id = now_unix_millis();
    let triage_dir = app_paths
        .data_dir
        .join("triage")
        .join(format!("triage-{triage_id}"));
    fs::create_dir_all(&triage_dir).map_err(|e| {
        format!(
            "failed to create triage dir '{}': {e}",
            triage_dir.display()
        )
    })?;

    let timeout_available = command_exists("timeout");
    let mut attempts = Vec::new();

    for attempt in 1..=repro_retries {
        let exec = execute_triage_subprocess(target, input, timeout_sec, timeout_available)?;
        // harness exit 0 = 정상 종료 (clean), non-zero = 크래시 (crashed) per specs.md §3.1
        let result_label = match exec.result {
            TriageResult::Clean => "clean".to_string(),
            TriageResult::Crashed => "crashed".to_string(),
            TriageResult::Timeout => "timeout".to_string(),
        };
        let parsed = parse_crash_log(&exec.output, exec.exit_code, exec.signal, &result_label);

        let log_path = triage_dir.join(format!("attempt-{}.log", attempt));
        let log_body = format!(
            "attempt: {}\nresult: {}\nexit_code: {}\nsignal: {}\nsanitizer: {}\ncrash_kind: {}\nnormalized_frame_hash: {}\nsignature_top3: {:?}\ntop_frames: {:?}\nnormalized_frames: {:?}\n{}\n",
            attempt,
            result_label,
            option_i32_json_value(exec.exit_code),
            parsed.signal,
            parsed.sanitizer,
            parsed.crash_kind,
            parsed.normalized_frame_hash,
            parsed.signature_top3,
            parsed.top_frames,
            parsed.normalized_frames,
            exec.output
        );
        fs::write(&log_path, log_body)
            .map_err(|e| format!("failed to write '{}': {e}", log_path.display()))?;

        attempts.push(TriageAttempt {
            attempt,
            result: result_label,
            exit_code: exec.exit_code,
            signal: parsed.signal,
            sanitizer: parsed.sanitizer,
            crash_kind: parsed.crash_kind,
            crash_summary: parsed.crash_summary,
            signature_top3: parsed.signature_top3,
            top_frames: parsed.top_frames,
            normalized_frames: parsed.normalized_frames,
            normalized_frame_hash: parsed.normalized_frame_hash,
            timeout: parsed.timeout,
            infra_oom: parsed.infra_oom,
        });
    }

    let timeout_count = attempts.iter().filter(|a| a.result == "timeout").count();
    let clean_count = attempts.iter().filter(|a| a.result == "clean").count();
    let crashed_count = attempts.iter().filter(|a| a.result == "crashed").count();
    let infra_oom_count = attempts.iter().filter(|a| a.infra_oom).count();
    let manual_review_count = attempts
        .iter()
        .filter(|a| a.result == "crashed" && requires_manual_review(&a.crash_kind))
        .count();

    let mut signature_consistent = true;
    let comparable_hashes = attempts
        .iter()
        .filter(|a| a.result == "crashed" && !a.normalized_frame_hash.is_empty())
        .map(|a| a.normalized_frame_hash.as_str())
        .collect::<Vec<_>>();
    if let Some(first) = comparable_hashes.first() {
        signature_consistent = comparable_hashes.iter().all(|hash| hash == first);
    }

    // Explicit verdicts: confirmed reports only come from reproduced; ambiguous cases go to manual review.
    let verdict = if infra_oom_count > 0 {
        "infra_oom"
    } else if attempts.iter().any(|a| a.timeout) || timeout_count > 0 {
        "timeout"
    } else if crashed_count == 0 {
        "not_reproduced"
    } else if crashed_count == attempts.len() && signature_consistent && manual_review_count == 0 {
        "reproduced"
    } else if crashed_count == attempts.len() && manual_review_count > 0 {
        "manual_review"
    } else if crashed_count <= 1 || !signature_consistent {
        "flaky"
    } else {
        "manual_review"
    };

    let deep_triage = build_deep_triage_metadata(
        target_label(target),
        &input.display().to_string(),
        repro_retries,
        timeout_sec,
        &attempts,
        crashed_count,
        timeout_count,
        infra_oom_count,
        signature_consistent,
        manual_review_count,
    );

    let summary_path = triage_dir.join("summary.json");
    let representative = attempts
        .iter()
        .find(|a| a.result == "crashed")
        .or_else(|| attempts.first());
    let attempts_json = attempts
        .iter()
        .map(|a| {
            let sig = a
                .signature_top3
                .iter()
                .map(|s| format!("\"{}\"", json_escape(s)))
                .collect::<Vec<_>>()
                .join(", ");
            let frames = json_string_array(&a.top_frames);
            let normalized_frames = json_string_array(&a.normalized_frames);
            format!(
                "    {{\"attempt\": {}, \"result\": \"{}\", \"exit_code\": {}, \"signal\": \"{}\", \"sanitizer\": \"{}\", \"crash_kind\": \"{}\", \"crash_summary\": \"{}\", \"timeout\": {}, \"infra_oom\": {}, \"signature_top3\": [{}], \"top_frames\": [{}], \"normalized_frames\": [{}], \"normalized_frame_hash\": \"{}\"}}",
                a.attempt,
                a.result,
                option_i32_json_value(a.exit_code),
                json_escape(&a.signal),
                json_escape(&a.sanitizer),
                json_escape(&a.crash_kind),
                json_escape(&a.crash_summary),
                if a.timeout { "true" } else { "false" },
                if a.infra_oom { "true" } else { "false" },
                sig,
                frames,
                normalized_frames,
                json_escape(&a.normalized_frame_hash)
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");

    let summary = format!(
        "{{\n  \"schema_version\": \"1.1\",\n  \"triage_id\": \"{}\",\n  \"target\": \"{}\",\n  \"input\": \"{}\",\n  \"repro_retries\": {},\n  \"timeout_sec\": {},\n  \"clean_count\": {},\n  \"crashed_count\": {},\n  \"timeout_count\": {},\n  \"infra_oom_count\": {},\n  \"signature_consistent\": {},\n  \"signature_basis\": \"normalized_frame_hash\",\n  \"normalized_frame_hash\": \"{}\",\n  \"crash_kind\": \"{}\",\n  \"sanitizer\": \"{}\",\n  \"signal\": \"{}\",\n  \"crash_summary\": \"{}\",\n  \"verdict\": \"{}\",\n  \"attempts\": [\n{}\n  ],\n  \"deep_triage\": {{\n    \"version\": \"{}\",\n    \"status\": \"{}\",\n    \"grouping_confidence\": \"{}\",\n    \"grouping_reason\": \"{}\",\n    \"evidence_quality\": \"{}\",\n    \"evidence_gaps\": [{}],\n    \"suggested_next_steps\": [{}],\n    \"replay_commands\": [{}]\n  }}\n}}\n",
        triage_id,
        target_label(target),
        json_escape(&input.display().to_string()),
        repro_retries,
        timeout_sec,
        clean_count,
        crashed_count,
        timeout_count,
        infra_oom_count,
        if signature_consistent { "true" } else { "false" },
        json_escape(representative.map(|a| a.normalized_frame_hash.as_str()).unwrap_or("")),
        json_escape(representative.map(|a| a.crash_kind.as_str()).unwrap_or("unknown")),
        json_escape(representative.map(|a| a.sanitizer.as_str()).unwrap_or("unknown")),
        json_escape(representative.map(|a| a.signal.as_str()).unwrap_or("unknown")),
        json_escape(representative.map(|a| a.crash_summary.as_str()).unwrap_or("")),
        verdict,
        attempts_json,
        deep_triage.version,
        deep_triage.status,
        deep_triage.grouping_confidence,
        json_escape(deep_triage.grouping_reason),
        deep_triage.evidence_quality,
        json_str_array(&deep_triage.evidence_gaps),
        json_str_array(&deep_triage.suggested_next_steps),
        json_string_array(&deep_triage.replay_commands)
    );
    fs::write(&summary_path, summary)
        .map_err(|e| format!("failed to write '{}': {e}", summary_path.display()))?;

    println!("[triage] done");
    println!("target: {}", target_label(target));
    println!("input: {}", input.display());
    println!("clean_count: {clean_count}");
    println!("crashed_count: {crashed_count}");
    println!("timeout_count: {timeout_count}");
    println!("infra_oom_count: {infra_oom_count}");
    println!("signature_consistent: {signature_consistent}");
    println!(
        "normalized_frame_hash: {}",
        representative
            .map(|a| a.normalized_frame_hash.as_str())
            .unwrap_or("")
    );
    println!("verdict: {verdict}");
    println!("summary: {}", summary_path.display());

    let valid_crashes = if verdict == "reproduced" { 1 } else { 0 };
    let new_crashes = if crashed_count > 0 { 1 } else { 0 };
    // The summary is already on disk; a metrics failure must not report this triage
    // as failed to the caller that will read the exit code.
    crate::metrics::record_metrics_event_best_effort(
        app_paths,
        MetricEvent {
            ts: now_unix(),
            kind: crate::metrics::KIND_TRIAGE,
            total: attempts.len() as u64,
            errors: (crashed_count + timeout_count) as u64,
            successful_runs_proxy: 0,
            library_session_ok: 0,
            new_crashes: new_crashes as u64,
            valid_crashes: valid_crashes as u64,
            total_crashes: new_crashes as u64,
        },
    );

    Ok(())
}

fn build_deep_triage_metadata(
    target: &str,
    input: &str,
    repro_retries: u32,
    timeout_sec: u64,
    attempts: &[TriageAttempt],
    crashed_count: usize,
    timeout_count: usize,
    infra_oom_count: usize,
    signature_consistent: bool,
    manual_review_count: usize,
) -> DeepTriageMetadata {
    let (grouping_confidence, grouping_reason) = classify_grouping_confidence(
        attempts,
        crashed_count,
        timeout_count,
        infra_oom_count,
        signature_consistent,
        manual_review_count,
    );
    let (evidence_quality, mut evidence_gaps, mut suggested_next_steps) =
        classify_evidence_metadata(
            attempts,
            crashed_count,
            timeout_count,
            infra_oom_count,
            signature_consistent,
            manual_review_count,
        );
    let (replay_commands, replay_gap, replay_next_step) =
        build_replay_commands(target, input, repro_retries, timeout_sec);
    if let Some(gap) = replay_gap {
        evidence_gaps.push(gap);
    }
    if let Some(next_step) = replay_next_step {
        suggested_next_steps.push(next_step);
    }
    DeepTriageMetadata {
        version: "1.0",
        status: "completed",
        grouping_confidence,
        grouping_reason,
        evidence_quality,
        evidence_gaps,
        suggested_next_steps,
        replay_commands,
    }
}

fn classify_grouping_confidence(
    attempts: &[TriageAttempt],
    crashed_count: usize,
    timeout_count: usize,
    infra_oom_count: usize,
    signature_consistent: bool,
    manual_review_count: usize,
) -> (&'static str, &'static str) {
    if crashed_count == 0 {
        return (
            "not_available",
            "no crashed attempts available for grouping",
        );
    }
    if timeout_count > 0 {
        return (
            "low",
            "timeout attempt observed; grouping confidence remains low",
        );
    }
    if infra_oom_count > 0 {
        return (
            "low",
            "infra_oom evidence observed; grouping confidence remains low",
        );
    }
    if manual_review_count > 0 {
        return (
            "low",
            "manual-review crash kind observed; grouping confidence remains low",
        );
    }
    if !signature_consistent {
        return (
            "low",
            "normalized_frame_hash differs across crashed attempts",
        );
    }
    if !crashed_field_consistent(attempts, |attempt| attempt.sanitizer.as_str())
        || !crashed_field_consistent(attempts, |attempt| attempt.crash_kind.as_str())
    {
        return (
            "low",
            "sanitizer or crash_kind differs across crashed attempts",
        );
    }
    if crashed_count == attempts.len() {
        return (
            "high",
            "all crashed attempts share normalized_frame_hash, sanitizer, and crash_kind",
        );
    }
    if crashed_count > 1 {
        return (
            "medium",
            "multiple crashed attempts share grouping signals, but reproduction is partial",
        );
    }
    (
        "low",
        "single crashed attempt only; grouping confidence remains low",
    )
}

fn crashed_field_consistent<F>(attempts: &[TriageAttempt], field: F) -> bool
where
    F: Fn(&TriageAttempt) -> &str,
{
    let mut values = attempts
        .iter()
        .filter(|attempt| attempt.result == "crashed")
        .map(field)
        .filter(|value| !value.is_empty());
    let Some(first) = values.next() else {
        return false;
    };
    values.all(|value| value == first)
}

fn classify_evidence_metadata(
    attempts: &[TriageAttempt],
    crashed_count: usize,
    timeout_count: usize,
    infra_oom_count: usize,
    signature_consistent: bool,
    manual_review_count: usize,
) -> (&'static str, Vec<&'static str>, Vec<&'static str>) {
    let mut gaps = Vec::new();
    let mut next_steps = Vec::new();

    if crashed_count == 0 {
        gaps.push("no_crashed_attempt");
        next_steps.push("rerun_triage_with_crashing_input");
        return ("not_available", gaps, next_steps);
    }

    if timeout_count > 0 {
        gaps.push("timeout_observed");
        next_steps.push("rerun_with_stable_timeout_before_grouping");
    }
    if infra_oom_count > 0 {
        gaps.push("infra_oom_observed");
        next_steps.push("confirm_oom_reproduces_under_fixed_resource_limits");
    }
    if attempts
        .iter()
        .any(|attempt| attempt.result == "crashed" && attempt.normalized_frame_hash.is_empty())
    {
        gaps.push("missing_normalized_frame_hash");
        next_steps.push("capture_stack_or_sanitizer_output");
    }
    if attempts.iter().any(|attempt| {
        attempt.result == "crashed" && attempt.sanitizer == "none" && attempt.signal == "none"
    }) {
        gaps.push("missing_sanitizer_or_signal");
        next_steps.push("rerun_with_sanitizer_or_signal_capture");
    }
    if manual_review_count > 0 {
        gaps.push("ambiguous_crash_kind");
        next_steps.push("manual_review_parser_runtime_error");
    }
    if !signature_consistent {
        gaps.push("signature_mismatch");
        next_steps.push("split_or_review_signatures_before_grouping");
    }
    if crashed_count < attempts.len() {
        gaps.push("partial_reproduction");
        next_steps.push("rerun_repro_attempts_before_report_candidate");
    }

    if gaps.is_empty() {
        next_steps.push("manual_confirm_impact_before_submission");
        return ("baseline_complete", gaps, next_steps);
    }

    let quality = if gaps.iter().any(|gap| {
        matches!(
            *gap,
            "missing_normalized_frame_hash"
                | "missing_sanitizer_or_signal"
                | "ambiguous_crash_kind"
        )
    }) {
        "weak"
    } else {
        "partial"
    };

    (quality, gaps, next_steps)
}

fn build_replay_commands(
    target: &str,
    input: &str,
    repro_retries: u32,
    timeout_sec: u64,
) -> (Vec<String>, Option<&'static str>, Option<&'static str>) {
    if target.trim().is_empty() || target == "unknown" {
        return (
            Vec::new(),
            Some("missing_replay_target"),
            Some("record_target_before_replay"),
        );
    }
    if input.trim().is_empty() || input == "unknown" {
        return (
            Vec::new(),
            Some("missing_replay_input"),
            Some("record_input_path_before_replay"),
        );
    }

    (
        vec![format!(
            "tool triage --target {} --input '{}' --repro-retries {} --timeout-sec {}",
            target,
            shell_escape_single_quoted(input),
            repro_retries,
            timeout_sec
        )],
        None,
        None,
    )
}

fn shell_escape_single_quoted(input: &str) -> String {
    input.replace('\'', "'\\''")
}

fn execute_triage_subprocess(
    target: &TargetKind,
    input: &Path,
    timeout_sec: u64,
    timeout_available: bool,
) -> Result<TriageExecResult, String> {
    let exe = std::env::current_exe().map_err(|e| format!("failed to resolve current exe: {e}"))?;
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
        .arg(target_label(target))
        .arg("--input")
        .arg(input)
        .env("OMP_NUM_THREADS", "1")
        .env("MKL_NUM_THREADS", "1")
        .env("OPENBLAS_NUM_THREADS", "1")
        .env("NUMEXPR_NUM_THREADS", "1")
        .env("VECLIB_MAXIMUM_THREADS", "1");

    // A38: same hole as A9 in the run pipeline - without the `timeout` binary the
    // harness child ran unbounded and a hanging input blocked triage forever.
    let (out, timed_out) = if timeout_available {
        let out = cmd
            .output()
            .map_err(|e| format!("failed to execute triage subprocess: {e}"))?;
        let timed_out = out.status.code() == Some(124);
        (out, timed_out)
    } else {
        output_with_deadline(cmd, timeout_sec)
            .map_err(|e| format!("failed to execute triage subprocess: {e}"))?
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut merged = format!("{}\n{}", stdout, stderr);
    let exit_code = out.status.code();
    let signal = exit_signal(&out.status);

    let result = classify_harness_exit(out.status.success(), exit_code, timed_out).map_err(|e| {
        // the harness reports the reason on stderr, so skip the empty stdout line
        let detail = merged
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("no output");
        format!("{e}: {detail}")
    })?;

    // OOM 137 triage 분기(DoS vs 인프라): v1은 infra_oom 힌트를 붙여 후속 triage/report에서 구분 가능하게 남긴다.
    if exit_code == Some(137) {
        merged = format!("infra_oom:exit_137\n{}", merged);
    }
    // G3: a rejected input is not a crash, but it must stay visible in the attempt log
    // so "clean" is not mistaken for "the library loaded this input".
    if exit_code == Some(i32::from(crate::EXIT_HARNESS_INPUT_REJECTED)) {
        merged = format!(
            "harness_error:exit_{}\n{}",
            crate::EXIT_HARNESS_INPUT_REJECTED,
            merged
        );
    }

    Ok(TriageExecResult {
        result,
        output: merged,
        exit_code,
        signal,
    })
}

// G3: map a harness process exit to a triage verdict. Only the two non-finding exit
// codes are carved out of "crashed"; every other non-zero exit and every signal death
// (which has no exit code at all) stays Crashed, so a real crash is never dropped
// (regression guard for the crash-propagation fix, commit 0a0b475). An unavailable
// harness is an error rather than a verdict: reporting a host that cannot run the
// library as "clean" would make a broken environment look like a non-crashing input.
fn classify_harness_exit(
    success: bool,
    exit_code: Option<i32>,
    timed_out: bool,
) -> Result<TriageResult, String> {
    if timed_out {
        return Ok(TriageResult::Timeout);
    }
    if success {
        return Ok(TriageResult::Clean);
    }
    if exit_code == Some(i32::from(crate::EXIT_HARNESS_UNAVAILABLE)) {
        return Err("harness could not run the target library".to_string());
    }
    if exit_code == Some(i32::from(crate::EXIT_HARNESS_INPUT_REJECTED)) {
        return Ok(TriageResult::Clean);
    }
    Ok(TriageResult::Crashed)
}

struct ParsedCrashLog {
    signal: String,
    sanitizer: String,
    crash_kind: String,
    crash_summary: String,
    signature_top3: Vec<String>,
    top_frames: Vec<String>,
    normalized_frames: Vec<String>,
    normalized_frame_hash: String,
    timeout: bool,
    infra_oom: bool,
}

fn parse_crash_log(
    output: &str,
    exit_code: Option<i32>,
    signal_number: Option<i32>,
    result_label: &str,
) -> ParsedCrashLog {
    if result_label == "clean" {
        return ParsedCrashLog {
            signal: "none".to_string(),
            sanitizer: "none".to_string(),
            crash_kind: "none".to_string(),
            crash_summary: String::new(),
            signature_top3: Vec::new(),
            top_frames: Vec::new(),
            normalized_frames: Vec::new(),
            normalized_frame_hash: String::new(),
            timeout: false,
            infra_oom: false,
        };
    }

    let sanitizer = extract_sanitizer(output);
    let signal = extract_signal(output, exit_code, signal_number);
    let timeout = result_label == "timeout" || contains_timeout(output);
    // G3: a kernel/cgroup OOM kill reaches triage as SIGKILL, not as exit_code 137 and
    // not as OOM text - the library subprocess dies instantly without printing and the
    // kernel logs "Out of memory: Killed process" to dmesg, while the tool itself exits 4.
    // Faulting code never raises SIGKILL, so a non-timeout SIGKILL is infrastructure, not
    // a library bug. Timeouts are excluded because the timeout killer is the only
    // in-pipeline SIGKILL producer.
    let infra_oom =
        exit_code == Some(137) || contains_oom(output) || (!timeout && signal == "SIGKILL");
    let crash_kind = classify_crash_kind(output, &sanitizer, &signal, timeout, infra_oom);
    let crash_summary = extract_crash_summary(output, &crash_kind);
    let top_frames = extract_top_frames(output);
    let normalized_frames = top_frames
        .iter()
        .map(|frame| normalize_stack_frame(frame))
        .filter(|frame| !frame.is_empty() && !is_ignored_frame(frame))
        .take(3)
        .collect::<Vec<_>>();
    let signature_top3 = if top_frames.is_empty() {
        extract_signature_top3(output)
    } else {
        top_frames.iter().take(3).cloned().collect()
    };
    let normalized_frame_hash = if normalized_frames.is_empty() {
        let normalized_hints = signature_top3
            .iter()
            .map(|hint| normalize_fallback_signature_hint(hint))
            .collect::<Vec<_>>();
        stable_hash_hex(&normalized_hints.join("\n"))
    } else {
        stable_hash_hex(&normalized_frames.join("\n"))
    };

    ParsedCrashLog {
        signal,
        sanitizer,
        crash_kind,
        crash_summary,
        signature_top3,
        top_frames,
        normalized_frames,
        normalized_frame_hash,
        timeout,
        infra_oom,
    }
}

fn extract_signature_top3(output: &str) -> Vec<String> {
    let mut selected = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if contains_stack_hint(trimmed) {
            selected.push(trimmed.to_string());
        }
        if selected.len() == 3 {
            return selected;
        }
    }

    // fallback: grab first 3 non-empty lines for stable comparison
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        selected.push(trimmed.to_string());
        if selected.len() == 3 {
            break;
        }
    }
    selected
}

fn contains_stack_hint(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if lower.starts_with("input:") {
        return false;
    }
    lower.contains("stack")
        || lower.contains("frame")
        || lower.contains("backtrace")
        || lower.contains("addresssanitizer")
        || lower.contains("segv")
        || lower.contains("sigabrt")
        || lower.contains("sigbus")
        || lower.contains("sigfpe")
        || lower.contains("sigill")
        || lower.contains("signal:")
        || lower.contains("onnxruntimeerror")
        || lower.contains("load_fail")
}

fn extract_sanitizer(output: &str) -> String {
    let lower = output.to_ascii_lowercase();
    if lower.contains("addresssanitizer") {
        "asan".to_string()
    } else if lower.contains("undefinedbehaviorsanitizer") || lower.contains("ubsan") {
        "ubsan".to_string()
    } else if lower.contains("memorysanitizer") {
        "msan".to_string()
    } else if lower.contains("threadsanitizer") {
        "tsan".to_string()
    } else if lower.contains("leaksanitizer") {
        "lsan".to_string()
    } else {
        "none".to_string()
    }
}

fn extract_signal(output: &str, exit_code: Option<i32>, signal_number: Option<i32>) -> String {
    if let Some(signal) = signal_number {
        return signal_name(signal).to_string();
    }
    let lower = output.to_ascii_lowercase();
    if lower.contains("sigsegv")
        || lower.contains("segmentation fault")
        || lower.contains("signal: 11")
    {
        "SIGSEGV".to_string()
    } else if lower.contains("sigabrt") || lower.contains("aborted") || lower.contains("signal: 6")
    {
        "SIGABRT".to_string()
    } else if lower.contains("sigbus") || lower.contains("bus error") || lower.contains("signal: 7")
    {
        "SIGBUS".to_string()
    } else if lower.contains("sigill")
        || lower.contains("illegal instruction")
        || lower.contains("signal: 4")
    {
        "SIGILL".to_string()
    } else if lower.contains("sigfpe")
        || lower.contains("floating point exception")
        || lower.contains("signal: 8")
    {
        "SIGFPE".to_string()
    } else if crash_line_reports_signal(output, &["sigkill", "signal: 9"]) {
        "SIGKILL".to_string()
    } else if crash_line_reports_signal(output, &["sigterm", "signal: 15"]) {
        "SIGTERM".to_string()
    } else if let Some(code) = exit_code.and_then(exit_code_signal_name) {
        code.to_string()
    } else {
        "none".to_string()
    }
}

/// A37: SIGKILL/SIGTERM never arrive as the tool's own exit status. run_harness turns
/// a killed library subprocess into Err, so the tool exits 4 and the only evidence is
/// the harness crash-detail line that target::crash_status_detail formats as
/// `... crashed (SIGKILL (signal: 9); stdout: ...; stderr: ...)`.
///
/// Matching is line-scoped and requires that crash-detail shape, and `input:` lines are
/// skipped: unlike the fault-signal names, kill names are ordinary words that show up in
/// paths and log text, and a filename must never decide a signal (the same false-positive
/// class the A1 fix removed from contains_oom). Deliberately not matched: "killed",
/// "terminated", "terminate" - `Out of memory: Killed process`, `killed by signal 11`,
/// bash's `Terminated` and C++'s `terminate called after throwing ...` would each
/// misclassify a non-kill as a kill.
fn crash_line_reports_signal(output: &str, needles: &[&str]) -> bool {
    output.lines().any(|line| {
        let lower = line.trim().to_ascii_lowercase();
        if lower.starts_with("input:") || !lower.contains("crashed (") {
            return false;
        }
        needles.iter().any(|needle| lower.contains(needle))
    })
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

fn signal_name(signal: i32) -> &'static str {
    match signal {
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

fn classify_crash_kind(
    output: &str,
    sanitizer: &str,
    signal: &str,
    timeout: bool,
    infra_oom: bool,
) -> String {
    let lower = output.to_ascii_lowercase();
    if timeout {
        return "timeout".to_string();
    }
    if infra_oom {
        return "infra_oom".to_string();
    }
    for kind in [
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "use-after-free",
        "null-dereference",
        "undefined-behavior",
    ] {
        if lower.contains(kind) {
            return kind.to_string();
        }
    }
    // The sanitizer's allocation ceiling, not the kernel's OOM killer (that is
    // infra_oom, exit 137). ASan cannot honour allocator_may_return_null for a
    // throwing operator new, so it aborts on a huge length before the parser's own
    // length_error handler runs - a property of the build, not a target bug.
    //
    // Both wordings are needed: ASan's ERROR line - the one line that survives
    // first_evidence_line and reaches triage - says "requested allocation size ...
    // exceeds maximum supported size", while "allocation-size-too-big" appears only
    // on the trailing SUMMARY line. There is deliberately no "out of memory" marker
    // here: contains_oom() matches that phrase and the infra_oom branch above has
    // already returned by then.
    if (lower.contains("requested allocation size") && lower.contains("exceeds maximum supported size"))
        || lower.contains("allocation-size-too-big")
    {
        return "sanitizer_alloc_limit".to_string();
    }
    if sanitizer != "none" {
        sanitizer.to_string()
    } else if signal != "none" {
        signal.to_ascii_lowercase()
    } else if lower.contains("panic") {
        "panic".to_string()
    } else if lower.contains("abort") {
        "abort".to_string()
    } else if lower.contains("load_fail") || lower.contains("onnxruntimeerror") {
        "parser_or_runtime_error".to_string()
    } else {
        "manual_review".to_string()
    }
}

fn requires_manual_review(crash_kind: &str) -> bool {
    // A37: "sigkill"/"sigterm" mean the process was killed from outside its own code,
    // which is never a reproduced library bug, so it must not reach the "reproduced"
    // verdict that feeds the report pipeline.
    matches!(
        crash_kind,
        "manual_review"
            | "parser_or_runtime_error"
            | "sigkill"
            | "sigterm"
            | "sanitizer_alloc_limit"
    )
}

fn extract_crash_summary(output: &str, crash_kind: &str) -> String {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("input:") {
            continue;
        }
        if lower.contains("summary:")
            || lower.contains("error:")
            || lower.contains("fatal")
            || lower.contains("runtimeerror")
            || lower.contains("load_fail")
            || contains_signal_hint(&lower)
        {
            return trimmed.to_string();
        }
    }
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains(crash_kind) && !lower.starts_with("input:") {
            return trimmed.to_string();
        }
    }
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .to_string()
}

fn contains_signal_hint(lower: &str) -> bool {
    lower.contains("sigsegv")
        || lower.contains("sigabrt")
        || lower.contains("sigbus")
        || lower.contains("sigfpe")
        || lower.contains("sigill")
        || lower.contains("signal:")
}

fn extract_top_frames(output: &str) -> Vec<String> {
    let mut frames = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if is_stack_frame(trimmed) {
            frames.push(trimmed.to_string());
        }
        if frames.len() == 8 {
            break;
        }
    }
    frames
}

fn is_stack_frame(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    line.starts_with('#')
        || lower.starts_with("frame ")
        || lower.contains(" in ")
            && (lower.contains(" at ") || lower.contains(" from ") || lower.contains("!"))
}

fn normalize_stack_frame(line: &str) -> String {
    let mut s = line.trim().to_string();
    if let Some(rest) = s.strip_prefix('#') {
        let trimmed = rest
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .trim_start();
        s = trimmed.to_string();
    }
    s = strip_hex_addresses(&s);
    s = strip_file_line_suffix(&s);
    s = strip_symbol_offsets(&s);
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_fallback_signature_hint(line: &str) -> String {
    strip_hex_addresses(line)
        .split_whitespace()
        .map(|token| {
            let token = normalize_sanitizer_process_id(token);
            let Some(path_start) = token.find('/') else {
                return token;
            };
            let prefix = &token[..path_start];
            if !prefix
                .chars()
                .all(|ch| matches!(ch, '\'' | '"' | '(' | '[' | '{' | '=' | ':'))
            {
                return token;
            }
            let components = token[path_start + 1..]
                .split('/')
                .filter(|component| !component.is_empty())
                .collect::<Vec<_>>();
            if components.len() < 2 {
                return token;
            }
            let suffix_start = components.len().saturating_sub(4);
            format!("{prefix}<ABS>/{}", components[suffix_start..].join("/"))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_sanitizer_process_id(token: &str) -> String {
    let Some(rest) = token.strip_prefix("==") else {
        return token.to_string();
    };
    let Some(pid_end) = rest.find("==") else {
        return token.to_string();
    };
    if pid_end == 0 || !rest[..pid_end].chars().all(|ch| ch.is_ascii_digit()) {
        return token.to_string();
    }
    format!("==PID=={}", &rest[pid_end + 2..])
}

fn strip_hex_addresses(input: &str) -> String {
    input
        .split_whitespace()
        .filter(|token| !token.starts_with("0x"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn strip_file_line_suffix(input: &str) -> String {
    let mut out = input.to_string();
    if let Some(idx) = out.find(" at ") {
        out.truncate(idx);
    }
    if let Some(idx) = out.find(" from ") {
        out.truncate(idx);
    }
    out
}

fn strip_symbol_offsets(input: &str) -> String {
    input
        .split_whitespace()
        .map(|part| {
            if let Some(idx) = part.find("+0x") {
                &part[..idx]
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_ignored_frame(frame: &str) -> bool {
    let lower = frame.to_ascii_lowercase();
    lower.contains("addresssanitizer")
        || lower.contains("libasan")
        || lower.contains("libubsan")
        || lower.contains("libc.so")
        || lower.contains("libstdc++")
        || lower.contains("libgcc")
        || lower.contains("libfuzzer")
}

fn contains_timeout(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("timeout") || lower.contains("timed out") || lower.contains("hang")
}

fn contains_oom(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    // Match only explicit OOM markers. Bare "oom"/"killed" substrings appear in
    // benign input paths (e.g. bloom-560m.onnx) and non-OOM crash text, so matching
    // them would discard real crashes as infra_oom. exit_code==137 is handled by the
    // caller; here we rely on the harness-injected marker and the kernel OOM lines.
    lower.contains("infra_oom")
        || lower.contains("out of memory")
        || lower.contains("oom-killer")
        || lower.contains("oom killer")
        || lower.contains("killed process")
}

fn stable_hash_hex(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn json_string_array(items: &[String]) -> String {
    items
        .iter()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn json_str_array(items: &[&str]) -> String {
    items
        .iter()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn option_i32_json_value(value: Option<i32>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string())
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
    use super::{
        build_deep_triage_metadata, classify_crash_kind, contains_oom, extract_crash_summary,
        extract_signal, extract_signature_top3, parse_crash_log, requires_manual_review,
        TriageAttempt,
    };
    use crate::json_utils::{extract_json_number_literal, extract_json_string_literal};

    // Backward-compatibility fixture: an old schema_version="1.1" triage summary
    // without a `deep_triage` nested object. Deep triage T2+ commits must keep
    // consumers tolerant of this shape (silent ignore of absent deep_triage).
    const SCHEMA_1_1_SAMPLE_SUMMARY: &str = r#"{
  "schema_version": "1.1",
  "triage_id": "1700000000000",
  "target": "onnx",
  "input": "data/runs/run-x/inputs/sample.onnx",
  "repro_retries": 3,
  "timeout_sec": 60,
  "clean_count": 0,
  "crashed_count": 3,
  "timeout_count": 0,
  "infra_oom_count": 0,
  "signature_consistent": true,
  "signature_basis": "normalized_frame_hash",
  "normalized_frame_hash": "abc123def456",
  "crash_kind": "heap-buffer-overflow",
  "sanitizer": "asan",
  "signal": "SIGSEGV",
  "crash_summary": "AddressSanitizer: heap-buffer-overflow",
  "verdict": "reproduced",
  "attempts": []
}
"#;

    #[test]
    fn schema_1_1_summary_top_level_fields_readable() {
        assert_eq!(
            extract_json_string_literal(SCHEMA_1_1_SAMPLE_SUMMARY, "schema_version").as_deref(),
            Some("1.1")
        );
        assert_eq!(
            extract_json_string_literal(SCHEMA_1_1_SAMPLE_SUMMARY, "verdict").as_deref(),
            Some("reproduced")
        );
        assert_eq!(
            extract_json_string_literal(SCHEMA_1_1_SAMPLE_SUMMARY, "target").as_deref(),
            Some("onnx")
        );
        assert_eq!(
            extract_json_string_literal(SCHEMA_1_1_SAMPLE_SUMMARY, "normalized_frame_hash")
                .as_deref(),
            Some("abc123def456")
        );
        assert_eq!(
            extract_json_string_literal(SCHEMA_1_1_SAMPLE_SUMMARY, "crash_kind").as_deref(),
            Some("heap-buffer-overflow")
        );
        assert_eq!(
            extract_json_number_literal(SCHEMA_1_1_SAMPLE_SUMMARY, "repro_retries").as_deref(),
            Some("3")
        );
    }

    #[test]
    fn sigfpe_summary_prefers_runtime_signal_over_input_path() {
        let output = "\
input: /tmp/poc_checker_valid_sigfpe.onnx
library_step: onnxruntime loader crashed (SIGFPE (signal: 8); stdout: no output; stderr: no output)
";

        assert_eq!(
            extract_crash_summary(output, "sigfpe"),
            "library_step: onnxruntime loader crashed (SIGFPE (signal: 8); stdout: no output; stderr: no output)"
        );
    }

    #[test]
    fn sigfpe_signal_line_is_signature_hint() {
        let output = "\
input: /tmp/poc_checker_valid_sigfpe.onnx
[harness] done
target: onnx
library_step: onnxruntime loader crashed (SIGFPE (signal: 8); stdout: no output; stderr: no output)
";

        assert_eq!(
            extract_signature_top3(output).first().map(String::as_str),
            Some("library_step: onnxruntime loader crashed (SIGFPE (signal: 8); stdout: no output; stderr: no output)")
        );
    }

    #[test]
    fn fallback_signature_hash_ignores_machine_specific_absolute_roots() {
        let crash_log = |root: &str, line: u32| {
            format!(
                "library_step: gguf parser native harness crashed (SIGABRT (signal: 6); \
                 stdout: no output; stderr: {root}/data/targets/llama.cpp/b7921/fuzz-build/\
                 src/ggml/src/gguf.cpp:{line}: GGML_ASSERT(!key.empty()) failed)"
            )
        };
        let dev = parse_crash_log(
            &crash_log("/home/ssw/bugbounty", 132),
            Some(4),
            None,
            "crashed",
        );
        let fuzz_pc = parse_crash_log(
            &crash_log("/home/fuzz/bugbounty", 132),
            Some(4),
            None,
            "crashed",
        );
        let different_assert = parse_crash_log(
            &crash_log("/home/fuzz/bugbounty", 133),
            Some(4),
            None,
            "crashed",
        );

        assert!(dev.normalized_frames.is_empty());
        assert!(fuzz_pc.normalized_frames.is_empty());
        assert_ne!(dev.signature_top3, fuzz_pc.signature_top3);
        assert_eq!(
            dev.normalized_frame_hash, fuzz_pc.normalized_frame_hash,
            "an absolute checkout root must not split one crash across hosts"
        );
        assert_ne!(
            fuzz_pc.normalized_frame_hash, different_assert.normalized_frame_hash,
            "the source line must remain part of the fallback signature"
        );
    }

    #[test]
    fn fallback_signature_hash_ignores_sanitizer_pid_and_addresses() {
        let crash_log = |pid: u32, address: &str| {
            format!(
                "library_step: gguf parser native harness crashed (SIGABRT (signal: 6); \
                 stdout: no output; stderr: =={pid}==ERROR: AddressSanitizer: FPE on \
                 unknown address {address} (pc {address} bp {address} sp {address} T0)"
            )
        };
        let first = parse_crash_log(
            &crash_log(10, "0x60fa95634694"),
            Some(4),
            None,
            "crashed",
        );
        let second = parse_crash_log(
            &crash_log(999, "0x5aa228fdc694"),
            Some(4),
            None,
            "crashed",
        );

        assert_ne!(first.signature_top3, second.signature_top3);
        assert_eq!(
            first.normalized_frame_hash, second.normalized_frame_hash,
            "sanitizer process IDs and addresses must not split one crash"
        );
    }

    #[test]
    fn contains_oom_ignores_bare_oom_and_killed_substrings() {
        // A1 regression: a benign input path (BLOOM is a real model family) contains
        // the trigram "oom", and non-OOM crash text can contain "killed"; neither must
        // be mistaken for an out-of-memory event (which would discard a real crash).
        assert!(!contains_oom("input: /data/models/bloom-560m.onnx"));
        assert!(!contains_oom(
            "library_step: onnxruntime loader crashed; process was killed by signal 11"
        ));
    }

    #[test]
    fn contains_oom_matches_explicit_oom_markers() {
        assert!(contains_oom("infra_oom:exit_137\ninput: /tmp/x.onnx"));
        assert!(contains_oom("terminate: Out of memory"));
        assert!(contains_oom("Out of memory: Killed process 1234 (python3)"));
        assert!(contains_oom("python invoked oom-killer: gfp_mask=0x100"));
    }

    #[test]
    fn crash_with_oom_in_input_path_is_not_infra_oom() {
        // A1 impact: a real SIGSEGV whose input path merely contains "oom" must be
        // classified as the real crash, not silently downgraded to infra_oom.
        let parsed = parse_crash_log(
            "input: /data/models/bloom-560m.onnx\n\
library_step: onnxruntime loader crashed (SIGSEGV (signal: 11); stdout: no output; stderr: no output)\n",
            Some(4),
            Some(11),
            "crashed",
        );
        assert!(
            !parsed.infra_oom,
            "benign 'oom' in the input path must not be classified as infra_oom"
        );
        assert_ne!(parsed.crash_kind, "infra_oom");
    }

    // (case, output, exit_code, signal_number, expected)
    type SignalCase = (
        &'static str,
        &'static str,
        Option<i32>,
        Option<i32>,
        &'static str,
    );

    #[test]
    fn extract_signal_table_covers_kill_signals_and_keeps_old_rows() {
        let cases: &[SignalCase] = &[
            // --- unchanged rows (must keep asserting today's behavior) ---
            (
                "runtime_signal_number_wins_over_text",
                "library_step: onnxruntime loader crashed (SIGKILL (signal: 9); stdout: ; stderr: )",
                Some(4),
                Some(11),
                "SIGSEGV",
            ),
            (
                "sigsegv_text",
                "library_step: onnxruntime loader crashed (SIGSEGV (signal: 11); stdout: ; stderr: )",
                Some(4),
                None,
                "SIGSEGV",
            ),
            (
                "sigfpe_text",
                "library_step: onnxruntime loader crashed (SIGFPE (signal: 8); stdout: ; stderr: )",
                Some(4),
                None,
                "SIGFPE",
            ),
            ("exit_code_139", "no signal text at all", Some(139), None, "SIGSEGV"),
            ("exit_code_136", "no signal text at all", Some(136), None, "SIGFPE"),
            ("exit_code_137", "no signal text at all", Some(137), None, "SIGKILL"),
            ("exit_code_143", "no signal text at all", Some(143), None, "SIGTERM"),
            (
                "cpp_terminate_text_still_falls_back_to_exit_code",
                "terminate called after throwing an instance of 'std::bad_alloc'",
                Some(134),
                None,
                "SIGABRT",
            ),
            (
                "no_evidence",
                "input: /tmp/x.onnx\nlibrary_step: onnxruntime loader invoked (non-zero exit: 1)",
                Some(1),
                None,
                "none",
            ),
            // --- A37: kill signals parsed out of the harness crash-detail line ---
            (
                "harness_sigkill_signal_line",
                "input: /tmp/x.onnx\nlibrary_step: onnxruntime loader crashed (SIGKILL (signal: 9); stdout: no output; stderr: no output)\nlibrary_outcome: crashed",
                Some(4),
                None,
                "SIGKILL",
            ),
            (
                "harness_sigkill_exit_code_detail",
                "library_step: safetensors loader crashed (SIGKILL (exit_code: 137); stdout: ; stderr: )",
                Some(4),
                None,
                "SIGKILL",
            ),
            (
                "harness_sigterm_signal_line",
                "library_step: llama.cpp parser invocation crashed (SIGTERM (signal: 15); stdout: ; stderr: )",
                Some(4),
                None,
                "SIGTERM",
            ),
            // --- rejected literals: these must NOT become a kill signal ---
            (
                "sigkill_in_input_path_is_ignored",
                "input: /data/models/sigkill-repro.onnx\nlibrary_step: onnxruntime loader invoked (non-zero exit: 1)",
                Some(4),
                None,
                "none",
            ),
            (
                "killed_word_on_a_crash_line_is_not_sigkill",
                "library_step: onnxruntime loader crashed (unknown (signal: 3); stdout: killed; stderr: no output)",
                Some(4),
                None,
                "none",
            ),
            (
                "terminated_word_is_not_sigterm",
                "external_step: TOOL_EXTERNAL_HARNESS_CMD executed but failed with status terminated",
                Some(4),
                None,
                "none",
            ),
        ];

        for (case, output, exit_code, signal_number, expected) in cases {
            assert_eq!(
                extract_signal(output, *exit_code, *signal_number),
                *expected,
                "case: {case}"
            );
        }
    }

    // (case, output, sanitizer, signal, timeout, infra_oom, expected)
    type CrashKindCase = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        bool,
        bool,
        &'static str,
    );

    // The sanitizer's own allocation ceiling is a property of the sanitizer, not of
    // the target: ASan aborts on a huge size before the parser's own length_error
    // handler can run. Classified as "asan" it reaches verdict "reproduced" and
    // report.rs drafts a submission for something upstream never did wrong.
    //
    // The text below is a real clang-17 ASan report, captured from a program that
    // resizes a string to 0x1000000000001. Note where the words actually are: the
    // ERROR line says "requested allocation size ... exceeds maximum supported
    // size", and "allocation-size-too-big" appears ONLY on the trailing SUMMARY
    // line. Triage sees one line (first_evidence_line), so a classifier keyed on
    // the SUMMARY wording alone would never fire on a real report.
    #[test]
    fn a_sanitizer_allocation_limit_is_not_a_reproduced_finding() {
        let error_line = "==16177==ERROR: AddressSanitizer: requested allocation size \
                          0x1000000000001 (0x1000000001008 after adjustments for alignment, \
                          red zones etc.) exceeds maximum supported size of 0x10000000000 \
                          (thread T0)";
        let kind = super::classify_crash_kind(error_line, "asan", "SIGABRT", false, false);
        assert_eq!(kind, "sanitizer_alloc_limit");
        assert!(super::requires_manual_review(&kind));

        // The SUMMARY wording still classifies, for callers that keep the full report.
        let summary = "SUMMARY: AddressSanitizer: allocation-size-too-big";
        assert_eq!(
            super::classify_crash_kind(summary, "asan", "SIGABRT", false, false),
            "sanitizer_alloc_limit"
        );
    }

    #[test]
    fn classify_crash_kind_table_keeps_branch_order() {
        let cases: &[CrashKindCase] = &[
            (
                "timeout_wins_over_infra_oom",
                "",
                "none",
                "SIGKILL",
                true,
                true,
                "timeout",
            ),
            (
                "infra_oom_wins_over_sanitizer_kind",
                "AddressSanitizer: heap-buffer-overflow",
                "asan",
                "SIGSEGV",
                false,
                true,
                "infra_oom",
            ),
            (
                "sanitizer_kind",
                "AddressSanitizer: heap-buffer-overflow",
                "asan",
                "SIGSEGV",
                false,
                false,
                "heap-buffer-overflow",
            ),
            (
                "sanitizer_over_signal",
                "asan report",
                "asan",
                "SIGSEGV",
                false,
                false,
                "asan",
            ),
            (
                "signal_lowercased",
                "crash",
                "none",
                "SIGSEGV",
                false,
                false,
                "sigsegv",
            ),
            (
                "sigkill_signal_lowercased",
                "crash",
                "none",
                "SIGKILL",
                false,
                false,
                "sigkill",
            ),
            (
                "parser_error",
                "onnxruntimeerror: invalid model",
                "none",
                "none",
                false,
                false,
                "parser_or_runtime_error",
            ),
            (
                "manual_review_fallback",
                "some text",
                "none",
                "none",
                false,
                false,
                "manual_review",
            ),
            // The sanitizer's allocation ceiling must outrank the bare sanitizer name,
            // or it goes back to being a "reproduced" asan finding.
            (
                "alloc_limit_over_sanitizer_name",
                "==1==ERROR: AddressSanitizer: requested allocation size 0x1000000000001 \
                 exceeds maximum supported size of 0x10000000000",
                "asan",
                "SIGABRT",
                false,
                false,
                "sanitizer_alloc_limit",
            ),
            // ...but the kernel OOM killer still outranks it. These are different
            // things and Task A6 said not to conflate them.
            (
                "infra_oom_over_alloc_limit",
                "SUMMARY: AddressSanitizer: allocation-size-too-big",
                "asan",
                "SIGABRT",
                false,
                true,
                "infra_oom",
            ),
            // A named memory-safety bug still wins: a heap overflow whose report also
            // mentions an allocation size is a real finding, not a build artifact.
            (
                "named_memory_bug_over_alloc_limit",
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow; requested allocation \
                 size 0x10 exceeds maximum supported size of 0x8",
                "asan",
                "SIGABRT",
                false,
                false,
                "heap-buffer-overflow",
            ),
        ];

        for (case, output, sanitizer, signal, timeout, infra_oom, expected) in cases {
            assert_eq!(
                classify_crash_kind(output, sanitizer, signal, *timeout, *infra_oom),
                *expected,
                "case: {case}"
            );
        }
    }

    #[test]
    fn oom_sigkill_from_harness_text_is_infra_oom() {
        // A37 + G3: the library subprocess is OOM-killed, so the tool exits 4 (not 137)
        // and no OOM text exists anywhere (the kernel logs to dmesg, and SIGKILL leaves
        // the child no chance to print). Before the fix extract_signal returned "none"
        // and classify_crash_kind fell through to manual_review.
        let output = "\
[harness] done
target: onnx
input: /data/runs/run-1/inputs/case.onnx
parser_step: onnx protobuf header ok
core_path_step: protobuf->onnxruntime session loader
library_step: onnxruntime loader crashed (SIGKILL (signal: 9); stdout: no output; stderr: no output)
library_outcome: crashed
external_step: skipped because library_connect crashed
[E_HARNESS_EXEC] harness error: library connect crashed: onnxruntime loader crashed (SIGKILL (signal: 9); stdout: no output; stderr: no output)
";
        let parsed = parse_crash_log(output, Some(4), None, "crashed");

        assert_eq!(parsed.signal, "SIGKILL");
        assert!(parsed.infra_oom, "a non-timeout SIGKILL is an infra kill");
        assert_eq!(parsed.crash_kind, "infra_oom");
        assert!(
            parsed.crash_summary.contains("SIGKILL (signal: 9)"),
            "the kill evidence must survive into crash_summary: {}",
            parsed.crash_summary
        );
    }

    #[test]
    fn timeout_sigkill_is_timeout_not_infra_oom() {
        // The timeout killer is the one in-pipeline SIGKILL producer; it must stay a
        // timeout so `verdict` is not silently rewritten to infra_oom.
        let output = "library_step: onnxruntime loader crashed (SIGKILL (signal: 9); stdout: no output; stderr: no output)\n";
        let parsed = parse_crash_log(output, Some(124), None, "timeout");

        assert!(!parsed.infra_oom);
        assert_eq!(parsed.crash_kind, "timeout");
    }

    #[test]
    fn library_sigsegv_stays_a_real_crash_after_signal_parsing() {
        // 0a0b475 non-regression: a real library crash (tool exit 4, SIGSEGV detail)
        // must still be a crash, never infra_oom.
        let output = "\
input: /data/runs/run-1/inputs/case.onnx
library_step: onnxruntime loader crashed (SIGSEGV (signal: 11); stdout: no output; stderr: no output)
library_outcome: crashed
";
        let parsed = parse_crash_log(output, Some(4), None, "crashed");

        assert_eq!(parsed.signal, "SIGSEGV");
        assert!(!parsed.infra_oom);
        assert_eq!(parsed.crash_kind, "sigsegv");
    }

    #[test]
    fn sigkill_in_input_path_is_not_an_infra_oom() {
        // A1-style false positive for the new kill literals: a PoC filename must never
        // downgrade a real finding to infra_oom.
        let parsed = parse_crash_log(
            "input: /data/models/sigkill-repro.onnx\n\
onnxruntimeerror: invalid model graph\n",
            Some(4),
            None,
            "crashed",
        );

        assert_eq!(parsed.signal, "none");
        assert!(!parsed.infra_oom);
        assert_eq!(parsed.crash_kind, "parser_or_runtime_error");
    }

    #[test]
    fn external_kill_crash_kinds_require_manual_review() {
        assert!(requires_manual_review("sigkill"));
        assert!(requires_manual_review("sigterm"));
        // unchanged rows
        assert!(requires_manual_review("manual_review"));
        assert!(requires_manual_review("parser_or_runtime_error"));
        assert!(!requires_manual_review("sigsegv"));
        assert!(!requires_manual_review("heap-buffer-overflow"));
        assert!(!requires_manual_review("asan"));
    }

    #[test]
    fn schema_1_1_summary_has_no_deep_triage_object() {
        // Deep triage T1 audit policy: old schema_version="1.1" summaries
        // never carry a `deep_triage` nested object. Readers must tolerate
        // its absence (silent ignore, no panic, Option=None).
        assert!(
            extract_json_string_literal(SCHEMA_1_1_SAMPLE_SUMMARY, "deep_triage").is_none(),
            "old 1.1 summary must not contain deep_triage"
        );
    }

    #[test]
    fn schema_1_1_summary_with_deep_triage_keeps_top_level_fields_readable() {
        let summary = r#"{
  "schema_version": "1.1",
  "triage_id": "1700000000001",
  "target": "onnx",
  "input": "data/runs/run-x/inputs/sample.onnx",
  "repro_retries": 3,
  "timeout_sec": 60,
  "clean_count": 0,
  "crashed_count": 3,
  "timeout_count": 0,
  "infra_oom_count": 0,
  "signature_consistent": true,
  "signature_basis": "normalized_frame_hash",
  "normalized_frame_hash": "abc123def456",
  "crash_kind": "heap-buffer-overflow",
  "sanitizer": "asan",
  "signal": "SIGSEGV",
  "crash_summary": "AddressSanitizer: heap-buffer-overflow",
  "verdict": "reproduced",
  "attempts": [],
  "deep_triage": {
    "version": "1.0",
    "status": "completed",
    "grouping_confidence": "high",
    "grouping_reason": "all crashed attempts share normalized_frame_hash, sanitizer, and crash_kind",
    "evidence_quality": "baseline_complete",
    "evidence_gaps": [],
    "suggested_next_steps": ["manual_confirm_impact_before_submission"],
    "replay_commands": ["tool triage --target onnx --input 'data/runs/run-x/inputs/sample.onnx' --repro-retries 3 --timeout-sec 60"]
  }
}
"#;

        assert_eq!(
            extract_json_string_literal(summary, "verdict").as_deref(),
            Some("reproduced")
        );
        assert_eq!(
            extract_json_string_literal(summary, "target").as_deref(),
            Some("onnx")
        );
        assert_eq!(
            extract_json_string_literal(summary, "normalized_frame_hash").as_deref(),
            Some("abc123def456")
        );
        assert_eq!(
            extract_json_string_literal(summary, "grouping_confidence").as_deref(),
            Some("high")
        );
        assert_eq!(
            extract_json_string_literal(summary, "evidence_quality").as_deref(),
            Some("baseline_complete")
        );
        assert_eq!(
            extract_json_string_literal(summary, "replay_commands").as_deref(),
            None
        );
    }

    #[test]
    fn deep_triage_grouping_high_when_all_crashes_match() {
        let attempts = vec![
            crashed_attempt(1, "asan", "heap-buffer-overflow", "hash-a"),
            crashed_attempt(2, "asan", "heap-buffer-overflow", "hash-a"),
            crashed_attempt(3, "asan", "heap-buffer-overflow", "hash-a"),
        ];

        let deep_triage = test_deep_triage_metadata(&attempts, 3, 0, 0, true, 0);

        assert_eq!(deep_triage.version, "1.0");
        assert_eq!(deep_triage.status, "completed");
        assert_eq!(deep_triage.grouping_confidence, "high");
        assert_eq!(deep_triage.evidence_quality, "baseline_complete");
        assert!(deep_triage.evidence_gaps.is_empty());
        assert_eq!(
            deep_triage.suggested_next_steps,
            vec!["manual_confirm_impact_before_submission"]
        );
        assert_eq!(
            deep_triage.replay_commands,
            vec!["tool triage --target onnx --input 'data/poc.onnx' --repro-retries 3 --timeout-sec 60"]
        );
        assert_eq!(
            deep_triage.grouping_reason,
            "all crashed attempts share normalized_frame_hash, sanitizer, and crash_kind"
        );
    }

    #[test]
    fn deep_triage_grouping_low_when_hashes_disagree() {
        let attempts = vec![
            crashed_attempt(1, "asan", "heap-buffer-overflow", "hash-a"),
            crashed_attempt(2, "asan", "heap-buffer-overflow", "hash-b"),
            crashed_attempt(3, "asan", "heap-buffer-overflow", "hash-a"),
        ];

        let deep_triage = test_deep_triage_metadata(&attempts, 3, 0, 0, false, 0);

        assert_eq!(deep_triage.grouping_confidence, "low");
        assert_eq!(
            deep_triage.grouping_reason,
            "normalized_frame_hash differs across crashed attempts"
        );
    }

    #[test]
    fn deep_triage_grouping_low_when_supporting_signals_disagree() {
        let attempts = vec![
            crashed_attempt(1, "asan", "heap-buffer-overflow", "hash-a"),
            crashed_attempt(2, "ubsan", "heap-buffer-overflow", "hash-a"),
            crashed_attempt(3, "asan", "heap-buffer-overflow", "hash-a"),
        ];

        let deep_triage = test_deep_triage_metadata(&attempts, 3, 0, 0, true, 0);

        assert_eq!(deep_triage.grouping_confidence, "low");
        assert_eq!(
            deep_triage.grouping_reason,
            "sanitizer or crash_kind differs across crashed attempts"
        );
    }

    #[test]
    fn deep_triage_grouping_medium_for_partial_reproduction() {
        let attempts = vec![
            crashed_attempt(1, "asan", "heap-buffer-overflow", "hash-a"),
            crashed_attempt(2, "asan", "heap-buffer-overflow", "hash-a"),
            clean_attempt(3),
        ];

        let deep_triage = test_deep_triage_metadata(&attempts, 2, 0, 0, true, 0);

        assert_eq!(deep_triage.grouping_confidence, "medium");
        assert_eq!(deep_triage.evidence_quality, "partial");
        assert_eq!(deep_triage.evidence_gaps, vec!["partial_reproduction"]);
        assert_eq!(
            deep_triage.grouping_reason,
            "multiple crashed attempts share grouping signals, but reproduction is partial"
        );
    }

    #[test]
    fn deep_triage_grouping_not_available_without_crashes() {
        let attempts = vec![clean_attempt(1), clean_attempt(2), clean_attempt(3)];

        let deep_triage = test_deep_triage_metadata(&attempts, 0, 0, 0, true, 0);

        assert_eq!(deep_triage.grouping_confidence, "not_available");
        assert_eq!(deep_triage.evidence_quality, "not_available");
        assert_eq!(deep_triage.evidence_gaps, vec!["no_crashed_attempt"]);
        assert_eq!(
            deep_triage.suggested_next_steps,
            vec!["rerun_triage_with_crashing_input"]
        );
        assert_eq!(
            deep_triage.grouping_reason,
            "no crashed attempts available for grouping"
        );
    }

    #[test]
    fn deep_triage_evidence_weak_when_runtime_evidence_is_missing() {
        let attempts = vec![crashed_attempt_without_runtime_evidence(1)];

        let deep_triage = test_deep_triage_metadata(&attempts, 1, 0, 0, true, 1);

        assert_eq!(deep_triage.grouping_confidence, "low");
        assert_eq!(deep_triage.evidence_quality, "weak");
        assert!(deep_triage
            .evidence_gaps
            .contains(&"missing_sanitizer_or_signal"));
        assert!(deep_triage.evidence_gaps.contains(&"ambiguous_crash_kind"));
        assert!(deep_triage
            .suggested_next_steps
            .contains(&"manual_review_parser_runtime_error"));
    }

    #[test]
    fn deep_triage_replay_gap_when_input_missing() {
        let attempts = vec![crashed_attempt(1, "asan", "heap-buffer-overflow", "hash-a")];

        let deep_triage =
            build_deep_triage_metadata("onnx", "unknown", 3, 60, &attempts, 1, 0, 0, true, 0);

        assert!(deep_triage.replay_commands.is_empty());
        assert!(deep_triage.evidence_gaps.contains(&"missing_replay_input"));
        assert!(deep_triage
            .suggested_next_steps
            .contains(&"record_input_path_before_replay"));
    }

    fn test_deep_triage_metadata(
        attempts: &[TriageAttempt],
        crashed_count: usize,
        timeout_count: usize,
        infra_oom_count: usize,
        signature_consistent: bool,
        manual_review_count: usize,
    ) -> super::DeepTriageMetadata {
        build_deep_triage_metadata(
            "onnx",
            "data/poc.onnx",
            3,
            60,
            attempts,
            crashed_count,
            timeout_count,
            infra_oom_count,
            signature_consistent,
            manual_review_count,
        )
    }

    fn crashed_attempt(
        attempt_number: u32,
        sanitizer: &str,
        crash_kind: &str,
        normalized_frame_hash: &str,
    ) -> TriageAttempt {
        TriageAttempt {
            attempt: attempt_number,
            result: "crashed".to_string(),
            exit_code: Some(1),
            signal: "SIGSEGV".to_string(),
            sanitizer: sanitizer.to_string(),
            crash_kind: crash_kind.to_string(),
            crash_summary: String::new(),
            signature_top3: Vec::new(),
            top_frames: Vec::new(),
            normalized_frames: Vec::new(),
            normalized_frame_hash: normalized_frame_hash.to_string(),
            timeout: false,
            infra_oom: false,
        }
    }

    fn clean_attempt(attempt_number: u32) -> TriageAttempt {
        TriageAttempt {
            attempt: attempt_number,
            result: "clean".to_string(),
            exit_code: Some(0),
            signal: "none".to_string(),
            sanitizer: "none".to_string(),
            crash_kind: "none".to_string(),
            crash_summary: String::new(),
            signature_top3: Vec::new(),
            top_frames: Vec::new(),
            normalized_frames: Vec::new(),
            normalized_frame_hash: String::new(),
            timeout: false,
            infra_oom: false,
        }
    }

    // A29: a zero timeout budget disables the bound instead of tightening it.
    #[test]
    fn triage_pipeline_rejects_a_zero_timeout() {
        use super::run_triage_pipeline;
        use crate::common::AppPaths;
        use crate::target::TargetKind;

        let root = std::env::temp_dir().join(format!(
            "tool-a29-triage-{}-{}",
            std::process::id(),
            crate::common::now_unix_millis()
        ));
        let seeds = root.join("seeds");
        std::fs::create_dir_all(&seeds).expect("create seeds dir");
        let input = seeds.join("case.onnx");
        std::fs::write(&input, b"bytes").expect("write input");
        let paths = AppPaths::prepare(&root.join("data"), &seeds).expect("prepare paths");

        let err = run_triage_pipeline(&paths, &TargetKind::Onnx, &input, 1, 0)
            .expect_err("timeout_sec=0 must be rejected");

        assert!(err.contains("timeout_sec"), "err was: {err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // G3: exit code 4 means the library crashed; a benign harness-side rejection
    // (missing input / precheck reject) exits with EXIT_HARNESS_BENIGN and must not
    // be counted as a crash. Every other non-zero exit stays Crashed so a real crash
    // is never silently dropped (regression guard for commit 0a0b475).
    #[test]
    fn benign_harness_exit_is_not_classified_as_crashed() {
        use super::{classify_harness_exit, TriageResult};

        assert!(matches!(
            classify_harness_exit(
                false,
                Some(i32::from(crate::EXIT_HARNESS_LIBRARY_CRASH)),
                false
            ),
            Ok(TriageResult::Crashed)
        ));
        assert!(matches!(
            classify_harness_exit(false, None, false),
            Ok(TriageResult::Crashed)
        ));
        assert!(matches!(
            classify_harness_exit(false, Some(139), false),
            Ok(TriageResult::Crashed)
        ));
        assert!(matches!(
            classify_harness_exit(
                false,
                Some(i32::from(crate::EXIT_HARNESS_INPUT_REJECTED)),
                false
            ),
            Ok(TriageResult::Clean)
        ));
        assert!(matches!(
            classify_harness_exit(true, Some(0), false),
            Ok(TriageResult::Clean)
        ));
        assert!(matches!(
            classify_harness_exit(false, Some(124), true),
            Ok(TriageResult::Timeout)
        ));
    }

    // Review follow-up: "the library never ran" (strict connect gate, unrunnable external
    // harness) must not read as "this input did not crash" - that hides a broken host
    // behind a not_reproduced verdict.
    #[test]
    fn unavailable_harness_is_an_error_not_a_clean_attempt() {
        use super::classify_harness_exit;

        let err = classify_harness_exit(
            false,
            Some(i32::from(crate::EXIT_HARNESS_UNAVAILABLE)),
            false,
        )
        .expect_err("an unavailable harness must fail triage loudly");
        assert!(err.contains("could not run"), "err was: {err}");
    }

    fn crashed_attempt_without_runtime_evidence(attempt_number: u32) -> TriageAttempt {
        TriageAttempt {
            attempt: attempt_number,
            result: "crashed".to_string(),
            exit_code: Some(1),
            signal: "none".to_string(),
            sanitizer: "none".to_string(),
            crash_kind: "manual_review".to_string(),
            crash_summary: String::new(),
            signature_top3: Vec::new(),
            top_frames: Vec::new(),
            normalized_frames: Vec::new(),
            normalized_frame_hash: "hash-a".to_string(),
            timeout: false,
            infra_oom: false,
        }
    }
}
