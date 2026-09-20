use std::{
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::common::{now_unix, now_unix_millis, AppPaths};
use crate::json_utils::{extract_json_string_literal, extract_json_u64_field};

/// A per-input local-harness run: one event unit is one input the library saw.
pub(crate) const KIND_RUN: &str = "run";
/// An engine-backend block: one event unit is one worker, not one input.
pub(crate) const KIND_RUN_BACKEND: &str = "run-backend";
/// A triage of one crash artifact: one unit is one reproduction attempt, and its
/// `errors` counts attempts that DID crash - the outcome triage is looking for.
pub(crate) const KIND_TRIAGE: &str = "triage";

pub(crate) struct MetricEvent {
    pub(crate) ts: u64,
    pub(crate) kind: &'static str,
    pub(crate) total: u64,
    pub(crate) errors: u64,
    pub(crate) successful_runs_proxy: u64,
    pub(crate) library_session_ok: u64,
    pub(crate) new_crashes: u64,
    pub(crate) valid_crashes: u64,
    pub(crate) total_crashes: u64,
}

pub(crate) fn record_metrics_event(app_paths: &AppPaths, event: MetricEvent) -> Result<(), String> {
    let metrics_dir = app_paths.data_dir.join("metrics");
    fs::create_dir_all(&metrics_dir).map_err(|e| {
        format!(
            "failed to create metrics dir '{}': {e}",
            metrics_dir.display()
        )
    })?;

    let events_path = metrics_dir.join("events.jsonl");
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&events_path)
        .map_err(|e| format!("failed to open '{}': {e}", events_path.display()))?;

    let line = format!(
        "{{\"ts\":{},\"kind\":\"{}\",\"total\":{},\"errors\":{},\"successful_runs_proxy\":{},\"library_session_ok\":{},\"new_crashes\":{},\"valid_crashes\":{},\"total_crashes\":{}}}\n",
        event.ts,
        event.kind,
        event.total,
        event.errors,
        event.successful_runs_proxy,
        event.library_session_ok,
        event.new_crashes,
        event.valid_crashes,
        event.total_crashes
    );
    f.write_all(line.as_bytes())
        .map_err(|e| format!("failed to append '{}': {e}", events_path.display()))?;

    let snapshot = build_metrics_snapshot(app_paths, &events_path, now_unix())?;
    let snapshot_path = metrics_dir.join("latest.json");
    // atomic write: temp 파일에 먼저 쓰고 rename으로 교체해서 partial 파일 상태 방지
    let tmp_path = snapshot_tmp_path(&metrics_dir);
    if let Err(e) = fs::write(&tmp_path, snapshot) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "failed to write temp '{}': {e}",
            tmp_path.display()
        ));
    }
    if let Err(e) = fs::rename(&tmp_path, &snapshot_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "failed to rename '{}' -> '{}': {e}",
            tmp_path.display(),
            snapshot_path.display()
        ));
    }
    Ok(())
}

/// A temp path no other writer will pick.
///
/// A23: the fixed `latest.json.tmp` was shared by every process against one data
/// dir, so two concurrent writers could rename a half-written snapshot into place.
/// The rename itself stays last-writer-wins, which is the intended snapshot
/// semantics.
fn snapshot_tmp_path(metrics_dir: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    metrics_dir.join(format!(
        "latest.json.{}-{}-{}.tmp",
        std::process::id(),
        now_unix_millis(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Record an event, reporting a failure instead of propagating it.
///
/// The callers reach this only after the work is finished and its artifact is on
/// disk. Failing the command there reports "the run failed" for what is really a
/// bookkeeping problem, and campaign loops read that exit code.
pub(crate) fn record_metrics_event_best_effort(app_paths: &AppPaths, event: MetricEvent) {
    if let Err(e) = record_metrics_event(app_paths, event) {
        eprintln!("[metrics] warning: failed to record event: {e}");
    }
}

fn build_metrics_snapshot(
    app_paths: &AppPaths,
    events_path: &Path,
    now_ts: u64,
) -> Result<String, String> {
    let content = fs::read_to_string(events_path)
        .map_err(|e| format!("failed to read '{}': {e}", events_path.display()))?;
    let mut successful_runs_proxy_1h = 0u64;
    let mut new_crashes_1h = 0u64;
    let mut total_1h = 0u64;
    let mut library_session_ok_1h = 0u64;
    let mut total_5m = 0u64;
    let mut errors_5m = 0u64;
    let mut backend_worker_runs_1h = 0u64;
    let mut backend_worker_errors_5m = 0u64;

    for line in content.lines() {
        let ts = extract_json_u64_field(line, "ts").unwrap_or(0);
        // A8/A21/A27: the units differ per kind - inputs for a local run, workers for
        // an engine block, reproduction attempts for a triage - so they cannot share
        // a denominator. An event written before this split carries kind="run" for
        // an engine block, so historical windows stay mixed; this is a forward fix.
        let kind = extract_json_string_literal(line, "kind").unwrap_or_default();
        let total = extract_json_u64_field(line, "total").unwrap_or(0);
        let errors = extract_json_u64_field(line, "errors").unwrap_or(0);
        let successful_runs_proxy = extract_json_u64_field(line, "successful_runs_proxy")
            .or_else(|| extract_json_u64_field(line, "new_paths"))
            .unwrap_or(0);
        let library_session_ok =
            extract_json_u64_field(line, "library_session_ok").unwrap_or(0);
        let new_crashes = extract_json_u64_field(line, "new_crashes").unwrap_or(0);
        let within_hour = now_ts.saturating_sub(ts) <= 3600;
        let within_5m = now_ts.saturating_sub(ts) <= 300;
        if within_hour {
            new_crashes_1h += new_crashes;
        }
        match kind.as_str() {
            KIND_RUN_BACKEND => {
                if within_hour {
                    backend_worker_runs_1h += successful_runs_proxy;
                }
                if within_5m {
                    backend_worker_errors_5m += errors;
                }
            }
            KIND_TRIAGE => {}
            // Anything else is a per-input local run. Events written before the
            // kinds were separated say "run" for both, which is the pre-existing
            // behaviour rather than a new one.
            _ => {
                if within_hour {
                    successful_runs_proxy_1h += successful_runs_proxy;
                    total_1h += total;
                    library_session_ok_1h += library_session_ok;
                }
                if within_5m {
                    total_5m += total;
                    errors_5m += errors;
                }
            }
        }
    }

    let (lib_rate_literal, lib_rate_status) = if total_1h == 0 {
        ("null".to_string(), "not_available")
    } else {
        (
            format!(
                "{:.4}",
                library_session_ok_1h as f64 / total_1h as f64
            ),
            "available",
        )
    };

    let triage_ratio = calculate_valid_crash_ratio_from_triage(&app_paths.data_dir.join("triage"))?;
    let (valid_ratio_literal, valid_ratio_status) = if triage_ratio.total_crashes == 0 {
        ("null".to_string(), "not_available")
    } else {
        (
            format!(
                "{:.4}",
                triage_ratio.valid_crashes as f64 / triage_ratio.total_crashes as f64
            ),
            "available",
        )
    };
    // A window with no local run events is not a window with no errors. Publishing
    // 0.0000 for it read as a perfectly healthy five minutes, which after the
    // per-kind split is the normal state of an engine-backend data dir.
    let (error_rate_literal, error_rate_status) = if total_5m == 0 {
        ("null".to_string(), "not_available")
    } else {
        (
            format!("{:.4}", errors_5m as f64 / total_5m as f64),
            "available",
        )
    };

    Ok(format!(
        "{{\n  \"schema_version\": \"1.0\",\n  \"generated_at\": {},\n  \"metrics\": {{\n    \"successful_runs_per_hour_proxy\": {},\n    \"library_connect_rate_proxy\": {},\n    \"library_connect_rate_proxy_status\": \"{}\",\n    \"library_connect_rate_proxy_source\": \"session_ok_over_local_run_total_1h\",\n    \"new_crashes_per_hour\": {},\n    \"valid_crash_ratio\": {},\n    \"valid_crash_ratio_status\": \"{}\",\n    \"valid_crash_ratio_source\": \"triage_summary_scan\",\n    \"valid_crashes\": {},\n    \"total_crashes\": {},\n    \"triage_summary_count\": {},\n    \"global_error_rate_5m\": {},\n    \"global_error_rate_5m_status\": \"{}\",\n    \"backend_worker_runs_per_hour\": {},\n    \"backend_worker_errors_5m\": {}\n  }}\n}}\n",
        now_ts,
        successful_runs_proxy_1h,
        lib_rate_literal,
        lib_rate_status,
        new_crashes_1h,
        valid_ratio_literal,
        valid_ratio_status,
        triage_ratio.valid_crashes,
        triage_ratio.total_crashes,
        triage_ratio.summary_count,
        error_rate_literal,
        error_rate_status,
        backend_worker_runs_1h,
        backend_worker_errors_5m
    ))
}

struct TriageCrashRatio {
    valid_crashes: u64,
    total_crashes: u64,
    summary_count: u64,
}

fn calculate_valid_crash_ratio_from_triage(triage_root: &Path) -> Result<TriageCrashRatio, String> {
    let mut ratio = TriageCrashRatio {
        valid_crashes: 0,
        total_crashes: 0,
        summary_count: 0,
    };

    if !triage_root.exists() {
        return Ok(ratio);
    }

    for entry in fs::read_dir(triage_root)
        .map_err(|e| format!("failed to read triage dir '{}': {e}", triage_root.display()))?
    {
        let entry = entry.map_err(|e| format!("failed to read triage entry: {e}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let summary_path = path.join("summary.json");
        if !summary_path.is_file() {
            continue;
        }

        let summary = fs::read_to_string(&summary_path)
            .map_err(|e| format!("failed to read '{}': {e}", summary_path.display()))?;
        ratio.summary_count += 1;

        let crashed_count = extract_json_u64_field(&summary, "crashed_count").unwrap_or(0);
        if crashed_count == 0 {
            continue;
        }

        ratio.total_crashes += 1;
        if extract_json_string_literal(&summary, "verdict").as_deref() == Some("reproduced") {
            ratio.valid_crashes += 1;
        }
    }

    Ok(ratio)
}

#[cfg(test)]
mod tests {
    // With no run events in the window the rate was published as 0.0000, which reads
    // as a perfectly healthy five minutes. After the per-kind split that is the
    // normal state of an aflpp or libfuzzer data dir, so the difference between
    // "nothing ran" and "nothing failed" has to be visible.
    #[test]
    fn the_error_rate_is_not_available_when_no_run_events_are_in_the_window() {
        let data = unique_tmp_data_dir("metrics_error_rate_gate");
        let seeds = data.join("seeds");
        fs::create_dir_all(&seeds).expect("create seeds dir");
        let events_path = data.join("metrics").join("events.jsonl");
        fs::create_dir_all(events_path.parent().expect("parent")).expect("create metrics dir");

        let ts = 1_700_000_000u64;
        let line = format!("{{\"ts\":{ts},\"kind\":\"run-backend\",\"total\":4,\"errors\":0,\"successful_runs_proxy\":4,\"library_session_ok\":0,\"new_crashes\":0,\"valid_crashes\":0,\"total_crashes\":0}}");
        fs::write(&events_path, line + "\n").expect("write events");

        let app_paths = AppPaths {
            data_dir: data.clone(),
            seeds_dir: seeds,
        };
        let snapshot =
            build_metrics_snapshot(&app_paths, &events_path, ts).expect("build snapshot");

        assert!(
            snapshot.contains("\"global_error_rate_5m\": null"),
            "snapshot was: {snapshot}"
        );
        assert!(
            snapshot.contains("\"global_error_rate_5m_status\": \"not_available\""),
            "snapshot was: {snapshot}"
        );

        let _ = fs::remove_dir_all(&data);
    }

    // A8/A21/A27: the snapshot summed `total` and `errors` across every event kind,
    // but only a local-harness run ever probes the library, and only a local run
    // counts inputs. A triage event counts attempts and reports a REPRODUCED crash
    // as an error - the desired outcome - while an engine-backend event counts
    // workers. So the connect rate was diluted by events that never probed, and the
    // error rate rose when triage succeeded.
    #[test]
    fn per_input_metrics_count_local_runs_only() {
        let data = unique_tmp_data_dir("metrics_kind_split");
        let seeds = data.join("seeds");
        fs::create_dir_all(&seeds).expect("create seeds dir");
        let events_path = data.join("metrics").join("events.jsonl");
        fs::create_dir_all(events_path.parent().expect("parent")).expect("create metrics dir");

        let ts = 1_700_000_000u64;
        let lines = [
            format!("{{\"ts\":{ts},\"kind\":\"run\",\"total\":10,\"errors\":4,\"successful_runs_proxy\":6,\"library_session_ok\":3,\"new_crashes\":0,\"valid_crashes\":0,\"total_crashes\":0}}"),
            format!("{{\"ts\":{ts},\"kind\":\"triage\",\"total\":20,\"errors\":20,\"successful_runs_proxy\":0,\"library_session_ok\":0,\"new_crashes\":1,\"valid_crashes\":1,\"total_crashes\":1}}"),
            format!("{{\"ts\":{ts},\"kind\":\"run-backend\",\"total\":4,\"errors\":1,\"successful_runs_proxy\":3,\"library_session_ok\":0,\"new_crashes\":0,\"valid_crashes\":0,\"total_crashes\":0}}"),
        ];
        fs::write(&events_path, lines.join("\n") + "\n").expect("write events");

        let app_paths = AppPaths {
            data_dir: data.clone(),
            seeds_dir: seeds,
        };
        let snapshot =
            build_metrics_snapshot(&app_paths, &events_path, ts).expect("build snapshot");

        // 3 of the 10 inputs the library actually saw, not 3 of 34.
        assert!(
            snapshot.contains("\"library_connect_rate_proxy\": 0.3000"),
            "snapshot was: {snapshot}"
        );
        // 4 of 10 local inputs failed; triage reproducing a crash is not an error.
        assert!(
            snapshot.contains("\"global_error_rate_5m\": 0.4000"),
            "snapshot was: {snapshot}"
        );
        assert!(
            snapshot.contains("\"successful_runs_per_hour_proxy\": 6"),
            "snapshot was: {snapshot}"
        );
        // The backend arm keeps its own counters, in its own unit, so its dashboard
        // reads "3 workers finished" rather than "nothing is running".
        assert!(
            snapshot.contains("\"backend_worker_runs_per_hour\": 3"),
            "snapshot was: {snapshot}"
        );
        assert!(
            snapshot.contains("\"backend_worker_errors_5m\": 1"),
            "snapshot was: {snapshot}"
        );

        let _ = fs::remove_dir_all(&data);
    }

    use super::*;
    use crate::common::{now_unix_millis, AppPaths};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_tmp_data_dir(label: &str) -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(tmp_data_dir_name(
            label,
            std::process::id(),
            now_unix_millis(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir_all(&p).expect("create tmp data dir");
        p
    }

    fn tmp_data_dir_name(
        label: &str,
        process_id: u32,
        timestamp_ms: u128,
        sequence: u64,
    ) -> String {
        format!("v1_{label}_{process_id}_{timestamp_ms}_{sequence}")
    }

    #[test]
    fn tmp_data_dir_name_separates_processes_and_calls_at_the_same_millisecond() {
        let first = tmp_data_dir_name("metrics_best_effort", 101, 5_000, 0);
        let same_process = tmp_data_dir_name("metrics_best_effort", 101, 5_000, 1);
        let other_process = tmp_data_dir_name("metrics_best_effort", 102, 5_000, 0);

        assert_ne!(first, same_process);
        assert_ne!(first, other_process);
    }

    // A23: every process wrote through the same latest.json.tmp, so two writers
    // against one data dir could rename a half-written snapshot into place.
    #[test]
    fn snapshot_tmp_path_is_unique_per_call() {
        let dir = unique_tmp_data_dir("snapshot_tmp_unique").join("metrics");
        let first = snapshot_tmp_path(&dir);
        let second = snapshot_tmp_path(&dir);

        assert_ne!(first, second, "two writers must not share a temp file");
        for path in [&first, &second] {
            assert_eq!(path.parent(), Some(dir.as_path()));
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("temp file name");
            assert!(name.starts_with("latest.json."), "name was {name}");
            assert!(name.ends_with(".tmp"), "name was {name}");
        }
    }

    // A finished run had already written status.json; a metrics-side failure used to
    // turn that into a non-zero exit, which reads as "the block failed".
    #[test]
    fn a_metrics_failure_is_reported_without_failing_the_command() {
        let data = unique_tmp_data_dir("metrics_best_effort");
        let seeds = data.join("seeds");
        fs::create_dir_all(&seeds).expect("create seeds dir");
        // A regular file where the metrics directory has to go: every write fails.
        fs::write(data.join("metrics"), b"not a directory").expect("write blocker");
        let app_paths = AppPaths {
            data_dir: data.clone(),
            seeds_dir: seeds,
        };

        assert!(
            record_metrics_event(&app_paths, sample_event()).is_err(),
            "the underlying write must still report the failure"
        );
        // What run and triage call: it reports and returns instead of failing.
        record_metrics_event_best_effort(&app_paths, sample_event());

        let _ = fs::remove_dir_all(&data);
    }

    fn sample_event() -> MetricEvent {
        MetricEvent {
            ts: 1_700_000_000,
            kind: "run",
            total: 1,
            errors: 0,
            successful_runs_proxy: 1,
            library_session_ok: 1,
            new_crashes: 0,
            valid_crashes: 0,
            total_crashes: 0,
        }
    }

    // Coverage V1 audit fixture: metrics snapshot JSON must emit the
    // throughput field under its `_proxy` name and must not emit real
    // coverage fields (`line_coverage`, `function_coverage`,
    // `edge_coverage`) without instrumentation. This locks in plan
    // §Metric Naming Rules and plan §Pass Criteria so a silent rename
    // from `_proxy` to real-coverage naming would break the build.
    #[test]
    fn metrics_snapshot_emits_successful_runs_per_hour_proxy_label() {
        let data = unique_tmp_data_dir("metrics_proxy_label");
        let seeds = data.join("seeds");
        fs::create_dir_all(&seeds).expect("create seeds dir");

        let events_path = data.join("metrics").join("events.jsonl");
        fs::create_dir_all(events_path.parent().unwrap()).expect("create metrics dir");
        fs::write(&events_path, b"").expect("write empty events log");

        let paths = AppPaths {
            data_dir: data.clone(),
            seeds_dir: seeds,
        };

        let snapshot = build_metrics_snapshot(&paths, &events_path, 1_700_000_000)
            .expect("build_metrics_snapshot should succeed with empty events");

        assert!(
            snapshot.contains("\"successful_runs_per_hour_proxy\":"),
            "Coverage V1 audit: metrics snapshot must emit `successful_runs_per_hour_proxy` (throughput proxy). Snapshot was: {snapshot}"
        );
        assert!(
            !snapshot.contains("\"line_coverage\"")
                && !snapshot.contains("\"function_coverage\"")
                && !snapshot.contains("\"edge_coverage\""),
            "Coverage V1 audit: metrics snapshot must NOT emit real-coverage fields without instrumentation. Snapshot was: {snapshot}"
        );

        let _ = fs::remove_dir_all(&data);
    }

    // library_connect_rate_proxy = session_ok / total over 1h rolling window.
    // Paper §3 fuzzer-depth differentiator (proxies how often mutations
    // reach the parser library beyond format precheck). Emitted with
    // `_proxy` suffix per plan §Metric Naming because there is no
    // coverage instrumentation — only probe outcome counting.
    #[test]
    fn metrics_snapshot_emits_library_connect_rate_proxy_with_session_ok_ratio() {
        let data = unique_tmp_data_dir("metrics_lib_connect_proxy");
        let seeds = data.join("seeds");
        fs::create_dir_all(&seeds).expect("create seeds dir");
        let events_path = data.join("metrics").join("events.jsonl");
        fs::create_dir_all(events_path.parent().unwrap()).expect("create metrics dir");

        let event_line = format!(
            "{{\"ts\":{},\"kind\":\"run\",\"total\":10,\"errors\":4,\"successful_runs_proxy\":6,\"library_session_ok\":3,\"new_crashes\":0,\"valid_crashes\":0,\"total_crashes\":0}}\n",
            1_700_000_000u64
        );
        fs::write(&events_path, event_line).expect("write event");

        let paths = AppPaths {
            data_dir: data.clone(),
            seeds_dir: seeds,
        };
        let snapshot = build_metrics_snapshot(&paths, &events_path, 1_700_000_000)
            .expect("build_metrics_snapshot should succeed");

        assert!(
            snapshot.contains("\"library_connect_rate_proxy\":"),
            "library_connect_rate_proxy must be emitted (paper §3 differentiator). Snapshot was: {snapshot}"
        );
        assert!(
            snapshot.contains("\"library_connect_rate_proxy_status\": \"available\"")
                || snapshot.contains("\"library_connect_rate_proxy_status\":\"available\""),
            "library_connect_rate_proxy_status must be 'available' when 1h total > 0. Snapshot was: {snapshot}"
        );
        assert!(
            snapshot.contains("0.3000"),
            "library_connect_rate_proxy must be 0.3000 (3 session_ok / 10 total). Snapshot was: {snapshot}"
        );

        let _ = fs::remove_dir_all(&data);
    }
}
