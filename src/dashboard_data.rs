use std::{
    collections::VecDeque,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::SystemTime,
};

pub(crate) const LOG_TAIL_LIMIT: usize = 200;

use crate::dashboard_charts::{
    build_crash_intake_series, build_run_result_series, build_throughput_proxy_series,
    build_triage_verdict_breakdown, collect_recent_run_statuses, collect_recent_triage_verdicts,
    CrashIntakePoint, RunResultPoint, ThroughputProxyPoint, VerdictBreakdownPoint,
    CHART_SERIES_LIMIT,
};
use crate::dashboard_discovery::{
    count_prefixed_dirs, find_evidence_bundle_path, find_latest_export,
    find_latest_mutation_manifest, find_latest_reproduced_triage,
    find_report_dir_by_source_triage_id, latest_prefixed_dir_name, read_report_severity_fields,
    recent_prefixed_dir_names, system_time_to_unix_string,
};

use crate::common::{artifact_contract, has_ext, now_unix, AppPaths};
use crate::json_utils::{extract_json_number_literal, extract_json_string_literal};
use crate::target::{all_target_specs, default_seed_dir, resolve_target_adapter, TargetKind};

#[derive(Clone, Debug)]
pub(crate) struct DashboardSnapshot {
    pub(crate) generated_at: u64,
    pub(crate) data_dir: String,
    pub(crate) seeds_dir: String,
    pub(crate) runs_count: usize,
    pub(crate) triage_count: usize,
    pub(crate) report_count: usize,
    pub(crate) latest_run: String,
    pub(crate) latest_triage: String,
    pub(crate) latest_report: String,
    pub(crate) metrics_exists: bool,
    pub(crate) successful_runs_per_hour_proxy: String,
    pub(crate) new_crashes_per_hour: String,
    pub(crate) valid_crash_ratio: String,
    pub(crate) valid_crash_ratio_status: String,
    pub(crate) valid_crash_ratio_source: String,
    pub(crate) valid_crashes: String,
    pub(crate) total_crashes: String,
    pub(crate) triage_summary_count: String,
    pub(crate) global_error_rate_5m: String,
    pub(crate) global_error_rate_5m_status: String,
    // The engine backends count workers, not inputs, so they get their own
    // counters rather than diluting the per-input ones.
    pub(crate) backend_worker_runs_per_hour: String,
    pub(crate) backend_worker_errors_5m: String,
    pub(crate) latest_valid_triage: String,
    pub(crate) latest_valid_input: String,
    pub(crate) latest_valid_signature: String,
    pub(crate) latest_valid_crash_kind: String,
    pub(crate) latest_valid_sanitizer: String,
    pub(crate) latest_valid_signal: String,
    pub(crate) latest_valid_normalized_frame_hash: String,
    pub(crate) latest_valid_signature_basis: String,
    pub(crate) latest_valid_crash_summary: String,
    pub(crate) latest_valid_deep_triage_grouping_confidence: String,
    pub(crate) latest_valid_deep_triage_evidence_quality: String,
    pub(crate) latest_valid_summary: String,
    pub(crate) latest_valid_report: String,
    pub(crate) latest_valid_manifest: String,
    pub(crate) latest_valid_bundle: String,
    pub(crate) latest_suggested_severity: String,
    pub(crate) latest_severity_confidence: String,
    pub(crate) latest_suggested_cvss_vector: String,
    pub(crate) recent_triage_ids: Vec<String>,
    pub(crate) recent_report_ids: Vec<String>,
    pub(crate) recent_coverage_ids: Vec<String>,
    pub(crate) recent_diagnostic_ids: Vec<String>,
    pub(crate) seeds_onnx_count: usize,
    pub(crate) seeds_gguf_count: usize,
    pub(crate) seeds_safetensors_count: usize,
    pub(crate) seeds_total_count: usize,
    pub(crate) coverage_count: usize,
    pub(crate) latest_coverage: String,
    pub(crate) latest_coverage_summary: String,
    pub(crate) latest_export_id: String,
    pub(crate) latest_export_path: String,
    pub(crate) latest_export_summary: String,
    pub(crate) latest_mutation_batch_id: String,
    pub(crate) latest_mutation_manifest_path: String,
    pub(crate) latest_mutation_target: String,
    pub(crate) latest_mutation_count: String,
    pub(crate) latest_run_target: String,
    pub(crate) latest_run_backend: String,
    pub(crate) latest_campaign_id: String,
    pub(crate) latest_campaign_mode: String,
    pub(crate) latest_campaign_state: String,
    pub(crate) latest_campaign_target: String,
    pub(crate) latest_campaign_backends: String,
    pub(crate) latest_campaign_arms: String,
    pub(crate) latest_campaign_updated_at: String,
    pub(crate) latest_run_total: String,
    pub(crate) latest_run_success: String,
    pub(crate) latest_run_failed: String,
    pub(crate) latest_run_timeout: String,
    pub(crate) triage_verdict_reproduced: usize,
    pub(crate) triage_verdict_manual_review: usize,
    pub(crate) triage_verdict_not_reproduced: usize,
    pub(crate) triage_verdict_timeout: usize,
    pub(crate) triage_verdict_infra_oom: usize,
    pub(crate) triage_verdict_flaky: usize,
    pub(crate) triage_verdict_other: usize,
    pub(crate) run_state: String,
    pub(crate) latest_triage_verdict: String,
    pub(crate) latest_triage_target: String,
    pub(crate) latest_run_updated_at: String,
    pub(crate) latest_triage_updated_at: String,
    pub(crate) latest_report_updated_at: String,
    pub(crate) latest_export_updated_at: String,
    pub(crate) latest_mutation_updated_at: String,
    pub(crate) latest_mutation_source_corpus: String,
    pub(crate) latest_mutation_validation_summary: String,
    pub(crate) run_result_series: Vec<RunResultPoint>,
    pub(crate) throughput_proxy_series: Vec<ThroughputProxyPoint>,
    pub(crate) crash_intake_series: Vec<CrashIntakePoint>,
    pub(crate) triage_verdict_breakdown: Vec<VerdictBreakdownPoint>,
    pub(crate) logs_source_path: String,
    pub(crate) logs_tail: Vec<String>,
    pub(crate) logs_total_lines: usize,
    pub(crate) logs_error: String,
}

/// `tool list` 용. kind 별로 최근 N개 ID 목록을 돌려준다.
pub(crate) fn list_recent_ids(
    app_paths: &AppPaths,
    kind: &str,
    limit: usize,
) -> Result<Vec<String>, String> {
    let artifact = artifact_contract(app_paths);
    let (root, prefix) = match kind {
        "runs" => (artifact.runs_root, "run-"),
        "triages" => (artifact.triage_root, "triage-"),
        "reports" => (artifact.reports_root, "report-"),
        "coverage" => (artifact.coverage_root, "coverage-"),
        "diagnostics" => {
            return recent_diagnostic_ids(&artifact.diagnostics_root, limit);
        }
        other => {
            return Err(format!(
                "unknown kind: '{other}' (use runs|triages|reports|coverage|diagnostics|all)"
            ))
        }
    };
    recent_prefixed_dir_names(&root, prefix, limit)
}

pub(crate) fn collect_dashboard_snapshot(
    app_paths: &AppPaths,
) -> Result<DashboardSnapshot, String> {
    let artifact = artifact_contract(app_paths);
    let runs_root = artifact.runs_root;
    let triage_root = artifact.triage_root;
    let reports_root = artifact.reports_root;
    let coverage_root = artifact.coverage_root;
    let exports_root = artifact.exports_root;
    let mutated_root = artifact.mutated_root;
    let legacy_mutated_root = artifact.legacy_mutated_root;
    let campaigns_root = app_paths.data_dir.join("campaigns");
    let metrics_path = artifact.metrics_root.join("latest.json");
    let seeds_onnx_count = count_seed_files(
        &default_seed_dir(app_paths, &TargetKind::Onnx),
        resolve_target_adapter(&TargetKind::Onnx).input_ext,
    )?;
    let seeds_gguf_count = count_seed_files(
        &default_seed_dir(app_paths, &TargetKind::Gguf),
        resolve_target_adapter(&TargetKind::Gguf).input_ext,
    )?;
    let seeds_safetensors_count = count_seed_files(
        &default_seed_dir(app_paths, &TargetKind::Safetensors),
        resolve_target_adapter(&TargetKind::Safetensors).input_ext,
    )?;
    let seeds_total_count = all_target_specs()
        .iter()
        .map(|spec| count_seed_files(&default_seed_dir(app_paths, &spec.kind), spec.input_ext))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum();

    let runs_count = count_prefixed_dirs(&runs_root, "run-")?;
    let triage_count = count_prefixed_dirs(&triage_root, "triage-")?;
    let report_count = count_prefixed_dirs(&reports_root, "report-")?;
    let coverage_count = count_prefixed_dirs(&coverage_root, "coverage-")?;

    let latest_run =
        latest_prefixed_dir_name(&runs_root, "run-")?.unwrap_or_else(|| "not_available".to_string());
    let latest_triage =
        latest_prefixed_dir_name(&triage_root, "triage-")?.unwrap_or_else(|| "not_available".to_string());
    let latest_report =
        latest_prefixed_dir_name(&reports_root, "report-")?.unwrap_or_else(|| "not_available".to_string());
    let latest_coverage = latest_prefixed_dir_name(&coverage_root, "coverage-")?
        .unwrap_or_else(|| "not_available".to_string());
    let recent_triage_ids = recent_prefixed_dir_names(&triage_root, "triage-", 8)?;
    let recent_report_ids = recent_prefixed_dir_names(&reports_root, "report-", 8)?;
    let recent_coverage_ids = recent_prefixed_dir_names(&coverage_root, "coverage-", 8)?;
    let recent_diagnostic_ids = recent_diagnostic_ids(&artifact.diagnostics_root, 8)?;
    let latest_coverage_summary = if latest_coverage == "not_available" {
        "not_available".to_string()
    } else {
        coverage_root
            .join(&latest_coverage)
            .join("summary.json")
            .display()
            .to_string()
    };

    let latest_export = find_latest_export(&exports_root)?;
    let (
        latest_export_id,
        latest_export_path,
        latest_export_summary,
        latest_export_updated_at,
    ) = if let Some(view) = latest_export {
        (view.id, view.path, view.summary, view.updated_at)
    } else {
        (
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
        )
    };

    let latest_mutation = find_latest_mutation_manifest(&mutated_root, &legacy_mutated_root)?;
    let (
        latest_mutation_batch_id,
        latest_mutation_manifest_path,
        latest_mutation_target,
        latest_mutation_count,
        latest_mutation_updated_at,
        latest_mutation_source_corpus,
        latest_mutation_validation_summary,
    ) = if let Some(view) = latest_mutation {
        (
            view.batch_id,
            view.manifest_path,
            view.target,
            view.count,
            view.updated_at,
            view.source_corpus,
            view.validation_summary,
        )
    } else {
        (
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
        )
    };

    let latest_run_view = read_run_status(&runs_root, &latest_run)?;
    let (
        latest_run_target,
        latest_run_backend,
        latest_run_total,
        latest_run_success,
        latest_run_failed,
        latest_run_timeout,
    ) = if let Some(view) = latest_run_view {
        (
            view.target,
            view.backend,
            view.total,
            view.success,
            view.failed,
            view.timeout,
        )
    } else {
        (
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
        )
    };
    let run_state = if latest_run == "not_available" {
        "no_run".to_string()
    } else {
        "finished".to_string()
    };

    let latest_campaign = read_latest_campaign_status(&campaigns_root)?;
    let (
        latest_campaign_id,
        latest_campaign_mode,
        latest_campaign_state,
        latest_campaign_target,
        latest_campaign_backends,
        latest_campaign_arms,
        latest_campaign_updated_at,
    ) = if let Some(view) = latest_campaign {
        (
            view.id,
            view.mode,
            view.state,
            view.target,
            view.backends,
            view.arms,
            view.updated_at,
        )
    } else {
        (
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
        )
    };

    let latest_triage_summary = read_latest_triage_summary(&triage_root, &latest_triage)?;
    let (latest_triage_verdict, latest_triage_target) = match latest_triage_summary {
        Some(view) => (view.verdict, view.target),
        None => ("not_available".to_string(), "not_available".to_string()),
    };

    let latest_run_updated_at = dir_mtime_unix_string(&runs_root, &latest_run);
    let latest_triage_updated_at = dir_mtime_unix_string(&triage_root, &latest_triage);
    let latest_report_updated_at = dir_mtime_unix_string(&reports_root, &latest_report);

    let triage_verdicts = count_triage_verdicts(&triage_root)?;

    let recent_run_statuses = collect_recent_run_statuses(&runs_root, CHART_SERIES_LIMIT)?;
    let run_result_series = build_run_result_series(&recent_run_statuses);
    let throughput_proxy_series = build_throughput_proxy_series(&recent_run_statuses);
    let recent_triage_verdicts =
        collect_recent_triage_verdicts(&triage_root, CHART_SERIES_LIMIT)?;
    let crash_intake_series = build_crash_intake_series(&recent_triage_verdicts);
    let triage_verdict_breakdown = build_triage_verdict_breakdown(&triage_verdicts);

    let logs_view = collect_latest_log_tail(&runs_root, &latest_run, LOG_TAIL_LIMIT);
    let (logs_source_path, logs_tail, logs_total_lines, logs_error) = match logs_view {
        Ok(view) => (view.source_path, view.tail, view.total_lines, view.error),
        Err(message) => ("not_available".to_string(), Vec::new(), 0, message),
    };

    let mut successful_runs_per_hour_proxy = "0".to_string();
    let mut new_crashes_per_hour = "0".to_string();
    let mut valid_crash_ratio = "not_available".to_string();
    let mut valid_crash_ratio_status = "not_available".to_string();
    let mut valid_crash_ratio_source = "not_available".to_string();
    let mut valid_crashes = "0".to_string();
    let mut total_crashes = "0".to_string();
    let mut triage_summary_count = "0".to_string();
    let mut global_error_rate_5m = "not_available".to_string();
    let mut global_error_rate_5m_status = "not_available".to_string();
    let mut backend_worker_runs_per_hour = "0".to_string();
    let mut backend_worker_errors_5m = "0".to_string();
    let metrics_exists = metrics_path.exists();
    if metrics_exists {
        let metrics = fs::read_to_string(&metrics_path)
            .map_err(|e| format!("failed to read '{}': {e}", metrics_path.display()))?;
        successful_runs_per_hour_proxy =
            extract_json_number_literal(&metrics, "successful_runs_per_hour_proxy")
                .or_else(|| extract_json_number_literal(&metrics, "new_paths_per_hour"))
                .unwrap_or_else(|| "0".to_string());
        new_crashes_per_hour = extract_json_number_literal(&metrics, "new_crashes_per_hour")
            .unwrap_or_else(|| "0".to_string());
        valid_crash_ratio_status =
            extract_json_string_literal(&metrics, "valid_crash_ratio_status")
                .unwrap_or_else(|| "legacy_unverified".to_string());
        valid_crash_ratio = if valid_crash_ratio_status == "available" {
            extract_json_number_literal(&metrics, "valid_crash_ratio")
                .unwrap_or_else(|| "not_available".to_string())
        } else {
            valid_crash_ratio_status.clone()
        };
        valid_crash_ratio_source =
            extract_json_string_literal(&metrics, "valid_crash_ratio_source")
                .unwrap_or_else(|| "legacy_event_log".to_string());
        valid_crashes = extract_json_number_literal(&metrics, "valid_crashes")
            .unwrap_or_else(|| "0".to_string());
        total_crashes = extract_json_number_literal(&metrics, "total_crashes")
            .unwrap_or_else(|| "0".to_string());
        triage_summary_count = extract_json_number_literal(&metrics, "triage_summary_count")
            .unwrap_or_else(|| "0".to_string());
        backend_worker_runs_per_hour =
            extract_json_number_literal(&metrics, "backend_worker_runs_per_hour")
                .unwrap_or_else(|| "0".to_string());
        backend_worker_errors_5m =
            extract_json_number_literal(&metrics, "backend_worker_errors_5m")
                .unwrap_or_else(|| "0".to_string());
        // Read the status first: a `null` value would otherwise fall back to "0.0",
        // which is indistinguishable from a real zero.
        global_error_rate_5m_status =
            extract_json_string_literal(&metrics, "global_error_rate_5m_status")
                .unwrap_or_else(|| "available".to_string());
        global_error_rate_5m = if global_error_rate_5m_status == "available" {
            extract_json_number_literal(&metrics, "global_error_rate_5m")
                .unwrap_or_else(|| "not_available".to_string())
        } else {
            global_error_rate_5m_status.clone()
        };
    }

    let latest_valid = find_latest_reproduced_triage(&triage_root)?;
    let (
        latest_valid_triage,
        latest_valid_input,
        latest_valid_signature,
        latest_valid_crash_kind,
        latest_valid_sanitizer,
        latest_valid_signal,
        latest_valid_normalized_frame_hash,
        latest_valid_signature_basis,
        latest_valid_crash_summary,
        latest_valid_deep_triage_grouping_confidence,
        latest_valid_deep_triage_evidence_quality,
        latest_valid_summary,
        latest_valid_report,
        latest_valid_manifest,
        latest_valid_bundle,
        latest_suggested_severity,
        latest_severity_confidence,
        latest_suggested_cvss_vector,
    ) = if let Some(item) = latest_valid {
        let report_dir = find_report_dir_by_source_triage_id(&reports_root, &item.triage_id)?;
        let report = report_dir
            .as_ref()
            .map(|dir| dir.join("report.md").display().to_string())
            .unwrap_or_else(|| "not_available".to_string());
        let manifest = report_dir
            .as_ref()
            .map(|dir| dir.join("manifest.json").display().to_string())
            .filter(|path| Path::new(path).exists())
            .unwrap_or_else(|| "not_available".to_string());
        let bundle = report_dir
            .as_ref()
            .and_then(|dir| find_evidence_bundle_path(dir))
            .unwrap_or_else(|| "not_available".to_string());
        let severity = report_dir
            .as_ref()
            .and_then(|dir| read_report_severity_fields(dir).ok())
            .unwrap_or_default();
        (
            format!("triage-{}", item.triage_id),
            item.input,
            item.signature_top1,
            item.crash_kind,
            item.sanitizer,
            item.signal,
            item.normalized_frame_hash,
            item.signature_basis,
            item.crash_summary,
            item.deep_triage_grouping_confidence,
            item.deep_triage_evidence_quality,
            item.summary_path,
            report,
            manifest,
            bundle,
            severity.suggested_severity,
            severity.confidence,
            severity.suggested_cvss_vector,
        )
    } else {
        (
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
            "not_available".to_string(),
        )
    };

    Ok(DashboardSnapshot {
        generated_at: now_unix(),
        data_dir: app_paths.data_dir.display().to_string(),
        seeds_dir: app_paths.seeds_dir.display().to_string(),
        runs_count,
        triage_count,
        report_count,
        latest_run,
        latest_triage,
        latest_report,
        metrics_exists,
        successful_runs_per_hour_proxy,
        new_crashes_per_hour,
        valid_crash_ratio,
        valid_crash_ratio_status,
        valid_crash_ratio_source,
        valid_crashes,
        total_crashes,
        triage_summary_count,
        global_error_rate_5m,
        global_error_rate_5m_status,
        backend_worker_runs_per_hour,
        backend_worker_errors_5m,
        latest_valid_triage,
        latest_valid_input,
        latest_valid_signature,
        latest_valid_crash_kind,
        latest_valid_sanitizer,
        latest_valid_signal,
        latest_valid_normalized_frame_hash,
        latest_valid_signature_basis,
        latest_valid_crash_summary,
        latest_valid_deep_triage_grouping_confidence,
        latest_valid_deep_triage_evidence_quality,
        latest_valid_summary,
        latest_valid_report,
        latest_valid_manifest,
        latest_valid_bundle,
        latest_suggested_severity,
        latest_severity_confidence,
        latest_suggested_cvss_vector,
        recent_triage_ids,
        recent_report_ids,
        recent_coverage_ids,
        recent_diagnostic_ids,
        seeds_onnx_count,
        seeds_gguf_count,
        seeds_safetensors_count,
        seeds_total_count,
        coverage_count,
        latest_coverage,
        latest_coverage_summary,
        latest_export_id,
        latest_export_path,
        latest_export_summary,
        latest_mutation_batch_id,
        latest_mutation_manifest_path,
        latest_mutation_target,
        latest_mutation_count,
        latest_run_target,
        latest_run_backend,
        latest_campaign_id,
        latest_campaign_mode,
        latest_campaign_state,
        latest_campaign_target,
        latest_campaign_backends,
        latest_campaign_arms,
        latest_campaign_updated_at,
        latest_run_total,
        latest_run_success,
        latest_run_failed,
        latest_run_timeout,
        triage_verdict_reproduced: triage_verdicts.reproduced,
        triage_verdict_manual_review: triage_verdicts.manual_review,
        triage_verdict_not_reproduced: triage_verdicts.not_reproduced,
        triage_verdict_timeout: triage_verdicts.timeout,
        triage_verdict_infra_oom: triage_verdicts.infra_oom,
        triage_verdict_flaky: triage_verdicts.flaky,
        triage_verdict_other: triage_verdicts.other,
        run_state,
        latest_triage_verdict,
        latest_triage_target,
        latest_run_updated_at,
        latest_triage_updated_at,
        latest_report_updated_at,
        latest_export_updated_at,
        latest_mutation_updated_at,
        latest_mutation_source_corpus,
        latest_mutation_validation_summary,
        run_result_series,
        throughput_proxy_series,
        crash_intake_series,
        triage_verdict_breakdown,
        logs_source_path,
        logs_tail,
        logs_total_lines,
        logs_error,
    })
}

fn recent_diagnostic_ids(root: &Path, limit: usize) -> Result<Vec<String>, String> {
    if !root.exists() || limit == 0 {
        return Ok(Vec::new());
    }
    let mut ids = fs::read_dir(root)
        .map_err(|e| format!("failed to read '{}': {e}", root.display()))?
        .map(|entry| {
            let entry = entry.map_err(|e| format!("failed to read diagnostic entry: {e}"))?;
            let metadata = entry
                .file_type()
                .map_err(|e| format!("failed to inspect diagnostic entry: {e}"))?;
            if !metadata.is_dir() {
                return Ok(None);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "diagnostic ID is not UTF-8".to_string())?;
            Ok(name.starts_with("diagnostic-").then_some(name))
        })
        .collect::<Result<Vec<_>, String>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    ids.sort_by(|left, right| right.cmp(left));
    ids.truncate(limit);
    Ok(ids)
}

fn count_seed_files(root: &Path, ext: &str) -> Result<usize, String> {
    if !root.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in
        fs::read_dir(root).map_err(|e| format!("failed to read '{}': {e}", root.display()))?
    {
        let entry =
            entry.map_err(|e| format!("failed to read entry in '{}': {e}", root.display()))?;
        let path = entry.path();
        if path.is_file() && has_ext(&path, ext) {
            count += 1;
        }
    }
    Ok(count)
}

pub(crate) fn entry_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

pub(crate) struct LatestLogTailView {
    pub(crate) source_path: String,
    pub(crate) tail: Vec<String>,
    pub(crate) total_lines: usize,
    pub(crate) error: String,
}

fn collect_latest_log_tail(
    runs_root: &Path,
    latest_run_name: &str,
    tail_limit: usize,
) -> Result<LatestLogTailView, String> {
    if latest_run_name == "not_available" {
        return Ok(LatestLogTailView {
            source_path: "not_available".to_string(),
            tail: Vec::new(),
            total_lines: 0,
            error: "not_available".to_string(),
        });
    }
    let logs_dir = runs_root.join(latest_run_name).join("logs");
    if !logs_dir.is_dir() {
        return Ok(LatestLogTailView {
            source_path: "not_available".to_string(),
            tail: Vec::new(),
            total_lines: 0,
            error: "not_available".to_string(),
        });
    }
    let selected = match select_most_recent_log(&logs_dir) {
        Ok(opt) => opt,
        Err(message) => {
            return Ok(LatestLogTailView {
                source_path: "not_available".to_string(),
                tail: Vec::new(),
                total_lines: 0,
                error: message,
            })
        }
    };
    let Some(log_path) = selected else {
        return Ok(LatestLogTailView {
            source_path: "not_available".to_string(),
            tail: Vec::new(),
            total_lines: 0,
            error: "not_available".to_string(),
        });
    };
    let total_lines = match count_log_lines(&log_path) {
        Ok(n) => n,
        Err(message) => {
            return Ok(LatestLogTailView {
                source_path: log_path.display().to_string(),
                tail: Vec::new(),
                total_lines: 0,
                error: message,
            })
        }
    };
    let tail = match read_log_tail(&log_path, tail_limit) {
        Ok(rows) => rows,
        Err(message) => {
            return Ok(LatestLogTailView {
                source_path: log_path.display().to_string(),
                tail: Vec::new(),
                total_lines,
                error: message,
            })
        }
    };
    Ok(LatestLogTailView {
        source_path: log_path.display().to_string(),
        tail,
        total_lines,
        error: "not_available".to_string(),
    })
}

fn select_most_recent_log(logs_dir: &Path) -> Result<Option<PathBuf>, String> {
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(logs_dir)
        .map_err(|e| format!("failed to read '{}': {e}", logs_dir.display()))?
    {
        let entry = entry
            .map_err(|e| format!("failed to read entry in '{}': {e}", logs_dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !has_ext(&path, "log") {
            continue;
        }
        let mtime = entry_mtime(&path).unwrap_or(SystemTime::UNIX_EPOCH);
        match &best {
            Some((best_mtime, _)) if mtime <= *best_mtime => {}
            _ => best = Some((mtime, path)),
        }
    }
    Ok(best.map(|(_, p)| p))
}

fn count_log_lines(path: &Path) -> Result<usize, String> {
    let file = fs::File::open(path)
        .map_err(|e| format!("failed to open '{}': {e}", path.display()))?;
    let reader = BufReader::new(file);
    let mut count = 0usize;
    for line in reader.lines() {
        line.map_err(|e| format!("failed to read line in '{}': {e}", path.display()))?;
        count += 1;
    }
    Ok(count)
}

fn read_log_tail(path: &Path, tail_limit: usize) -> Result<Vec<String>, String> {
    let file = fs::File::open(path)
        .map_err(|e| format!("failed to open '{}': {e}", path.display()))?;
    let reader = BufReader::new(file);
    let mut ring: VecDeque<String> = VecDeque::with_capacity(tail_limit);
    for line in reader.lines() {
        let line =
            line.map_err(|e| format!("failed to read line in '{}': {e}", path.display()))?;
        if ring.len() == tail_limit {
            ring.pop_front();
        }
        ring.push_back(line);
    }
    Ok(ring.into_iter().collect())
}

fn dir_mtime_unix_string(root: &Path, dir_name: &str) -> String {
    if dir_name == "not_available" {
        return "not_available".to_string();
    }
    let path = root.join(dir_name);
    entry_mtime(&path)
        .map(system_time_to_unix_string)
        .unwrap_or_else(|| "not_available".to_string())
}

struct CampaignStatusView {
    id: String,
    mode: String,
    state: String,
    target: String,
    backends: String,
    arms: String,
    updated_at: String,
}

fn read_latest_campaign_status(
    campaigns_root: &Path,
) -> Result<Option<CampaignStatusView>, String> {
    if !campaigns_root.exists() {
        return Ok(None);
    }

    let mut best: Option<(SystemTime, CampaignStatusView)> = None;
    for entry in fs::read_dir(campaigns_root)
        .map_err(|e| format!("failed to read '{}': {e}", campaigns_root.display()))?
    {
        let entry = entry
            .map_err(|e| format!("failed to read campaign entry: {e}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        let status_path = path.join("status.json");
        let manifest_path = path.join("manifest.json");
        let source_path = if status_path.is_file() {
            status_path
        } else if manifest_path.is_file() {
            manifest_path
        } else {
            continue;
        };
        let mtime = entry_mtime(&source_path).unwrap_or(SystemTime::UNIX_EPOCH);
        let body = fs::read_to_string(&source_path)
            .map_err(|e| format!("failed to read '{}': {e}", source_path.display()))?;
        let view = CampaignStatusView {
            id: extract_json_string_literal(&body, "campaign_id")
                .unwrap_or_else(|| dir_name.to_string()),
            mode: extract_json_string_literal(&body, "mode")
                .unwrap_or_else(|| "not_available".to_string()),
            state: extract_json_string_literal(&body, "state")
                .unwrap_or_else(|| "manifest_only".to_string()),
            target: extract_json_string_literal(&body, "target")
                .unwrap_or_else(|| "not_available".to_string()),
            backends: extract_json_string_literal(&body, "backends_label")
                .unwrap_or_else(|| "not_available".to_string()),
            arms: extract_json_string_literal(&body, "arms_label")
                .unwrap_or_else(|| "not_available".to_string()),
            updated_at: extract_json_string_literal(&body, "updated_at")
                .unwrap_or_else(|| system_time_to_unix_string(mtime)),
        };
        match &best {
            Some((best_mtime, _)) if mtime <= *best_mtime => {}
            _ => best = Some((mtime, view)),
        }
    }
    Ok(best.map(|(_, view)| view))
}

struct LatestTriageSummaryView {
    verdict: String,
    target: String,
}

fn read_latest_triage_summary(
    triage_root: &Path,
    triage_dir_name: &str,
) -> Result<Option<LatestTriageSummaryView>, String> {
    if triage_dir_name == "not_available" {
        return Ok(None);
    }
    let summary_path = triage_root.join(triage_dir_name).join("summary.json");
    if !summary_path.is_file() {
        return Ok(None);
    }
    let body = fs::read_to_string(&summary_path)
        .map_err(|e| format!("failed to read '{}': {e}", summary_path.display()))?;
    Ok(Some(LatestTriageSummaryView {
        verdict: extract_json_string_literal(&body, "verdict")
            .unwrap_or_else(|| "not_available".to_string()),
        target: extract_json_string_literal(&body, "target")
            .unwrap_or_else(|| "not_available".to_string()),
    }))
}

pub(crate) struct RunStatusView {
    pub(crate) target: String,
    pub(crate) backend: String,
    pub(crate) total: String,
    pub(crate) success: String,
    pub(crate) failed: String,
    pub(crate) timeout: String,
}

pub(crate) fn read_run_status(
    runs_root: &Path,
    run_dir_name: &str,
) -> Result<Option<RunStatusView>, String> {
    if run_dir_name == "not_available" {
        return Ok(None);
    }
    let status_path = runs_root.join(run_dir_name).join("status.json");
    if !status_path.is_file() {
        return Ok(None);
    }
    let body = fs::read_to_string(&status_path)
        .map_err(|e| format!("failed to read '{}': {e}", status_path.display()))?;
    Ok(Some(RunStatusView {
        target: extract_json_string_literal(&body, "target")
            .unwrap_or_else(|| "not_available".to_string()),
        backend: extract_json_string_literal(&body, "backend")
            .unwrap_or_else(|| "not_available".to_string()),
        total: extract_json_number_literal(&body, "total")
            .unwrap_or_else(|| "not_available".to_string()),
        success: extract_json_number_literal(&body, "success")
            .unwrap_or_else(|| "not_available".to_string()),
        failed: extract_json_number_literal(&body, "failed")
            .unwrap_or_else(|| "not_available".to_string()),
        timeout: extract_json_number_literal(&body, "timeout")
            .unwrap_or_else(|| "not_available".to_string()),
    }))
}

#[derive(Default)]
pub(crate) struct TriageVerdictCounts {
    pub(crate) reproduced: usize,
    pub(crate) manual_review: usize,
    pub(crate) not_reproduced: usize,
    pub(crate) timeout: usize,
    pub(crate) infra_oom: usize,
    pub(crate) flaky: usize,
    pub(crate) other: usize,
}

fn count_triage_verdicts(triage_root: &Path) -> Result<TriageVerdictCounts, String> {
    let mut counts = TriageVerdictCounts::default();
    if !triage_root.exists() {
        return Ok(counts);
    }
    for entry in fs::read_dir(triage_root)
        .map_err(|e| format!("failed to read '{}': {e}", triage_root.display()))?
    {
        let entry = entry
            .map_err(|e| format!("failed to read triage verdict entry: {e}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("triage-") {
            continue;
        }
        let summary_path = path.join("summary.json");
        if !summary_path.is_file() {
            continue;
        }
        let body = fs::read_to_string(&summary_path)
            .map_err(|e| format!("failed to read '{}': {e}", summary_path.display()))?;
        let verdict = extract_json_string_literal(&body, "verdict").unwrap_or_default();
        match verdict.as_str() {
            "reproduced" => counts.reproduced += 1,
            "manual_review" => counts.manual_review += 1,
            "not_reproduced" => counts.not_reproduced += 1,
            "timeout" => counts.timeout += 1,
            "infra_oom" => counts.infra_oom += 1,
            "flaky" => counts.flaky += 1,
            _ => counts.other += 1,
        }
    }
    Ok(counts)
}
