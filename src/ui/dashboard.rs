use crate::dashboard_charts::{
    CrashIntakePoint, RunResultPoint, ThroughputProxyPoint, VerdictBreakdownPoint,
};
use crate::dashboard_data::{DashboardSnapshot, LOG_TAIL_LIMIT};
use crate::json_utils::{html_escape, json_escape, url_encode};
use crate::target::{all_target_specs, parse_target_id, target_spec};
use std::fs;

const DEFAULT_DASHBOARD_HTML_TEMPLATE: &str = include_str!("../../templates/dashboard.html");
const DASHBOARD_HTML_TEMPLATE_PATH: &str = "templates/dashboard.html";

pub(crate) fn render_dashboard_json(s: &DashboardSnapshot) -> String {
    format!(
        "{{\n  \"schema_version\": \"1.0\",\n  \"generated_at\": {},\n  \"config\": {{\n    \"data_dir\": \"{}\",\n    \"seeds_dir\": \"{}\"\n  }},\n  \"snapshot\": {{\n    \"runs_count\": {},\n    \"triage_count\": {},\n    \"report_count\": {},\n    \"coverage_count\": {},\n    \"latest_run\": \"{}\",\n    \"latest_triage\": \"{}\",\n    \"latest_report\": \"{}\",\n    \"latest_coverage\": \"{}\"\n  }},\n  \"metrics\": {{\n    \"exists\": {},\n    \"successful_runs_per_hour_proxy\": {},\n    \"new_crashes_per_hour\": {},\n    \"valid_crash_ratio\": {},\n    \"valid_crash_ratio_status\": \"{}\",\n    \"valid_crash_ratio_source\": \"{}\",\n    \"valid_crashes\": {},\n    \"total_crashes\": {},\n    \"triage_summary_count\": {},\n    \"global_error_rate_5m\": {},\n    \"global_error_rate_5m_status\": \"{}\",\n    \"backend_worker_runs_per_hour\": {},\n    \"backend_worker_errors_5m\": {}\n  }},\n  \"seeds\": {{\n    \"onnx_count\": {},\n    \"gguf_count\": {},\n    \"safetensors_count\": {},\n    \"total_count\": {}\n  }},\n  \"crash\": {{\n    \"latest_valid_triage\": \"{}\",\n    \"input\": \"{}\",\n    \"signature_top1\": \"{}\",\n    \"crash_kind\": \"{}\",\n    \"sanitizer\": \"{}\",\n    \"signal\": \"{}\",\n    \"normalized_frame_hash\": \"{}\",\n    \"signature_basis\": \"{}\",\n    \"crash_summary\": \"{}\",\n    \"deep_triage_grouping_confidence\": \"{}\",\n    \"deep_triage_evidence_quality\": \"{}\",\n    \"summary\": \"{}\",\n    \"report\": \"{}\",\n    \"manifest\": \"{}\",\n    \"bundle\": \"{}\",\n    \"suggested_severity\": \"{}\",\n    \"severity_confidence\": \"{}\",\n    \"suggested_cvss_vector\": \"{}\"\n  }},\n  \"coverage\": {{\n    \"latest\": \"{}\",\n    \"summary\": \"{}\"\n  }},\n  \"exports\": {{\n    \"latest_id\": \"{}\",\n    \"latest_path\": \"{}\",\n    \"latest_summary\": \"{}\",\n    \"latest_updated_at\": \"{}\"\n  }},\n  \"mutation\": {{\n    \"latest_batch_id\": \"{}\",\n    \"latest_manifest_path\": \"{}\",\n    \"latest_target\": \"{}\",\n    \"latest_count\": \"{}\",\n    \"latest_updated_at\": \"{}\",\n    \"latest_source_corpus\": \"{}\",\n    \"latest_validation_summary\": \"{}\"\n  }},\n  \"run_state\": {{\n    \"state\": \"{}\",\n    \"target\": \"{}\",\n    \"backend\": \"{}\",\n    \"total\": \"{}\",\n    \"success\": \"{}\",\n    \"failed\": \"{}\",\n    \"timeout\": \"{}\",\n    \"updated_at\": \"{}\"\n  }},\n  \"campaign\": {{\n    \"id\": \"{}\",\n    \"mode\": \"{}\",\n    \"state\": \"{}\",\n    \"target\": \"{}\",\n    \"backends\": \"{}\",\n    \"arms\": \"{}\",\n    \"updated_at\": \"{}\"\n  }},\n  \"latest_triage\": {{\n    \"verdict\": \"{}\",\n    \"target\": \"{}\",\n    \"updated_at\": \"{}\"\n  }},\n  \"latest_report\": {{\n    \"updated_at\": \"{}\"\n  }},\n  \"triage_verdicts\": {{\n    \"reproduced\": {},\n    \"manual_review\": {},\n    \"not_reproduced\": {},\n    \"timeout\": {},\n    \"infra_oom\": {},\n    \"flaky\": {},\n    \"other\": {}\n  }}\n}}",
        s.generated_at,
        json_escape(&s.data_dir),
        json_escape(&s.seeds_dir),
        s.runs_count,
        s.triage_count,
        s.report_count,
        s.coverage_count,
        json_escape(&s.latest_run),
        json_escape(&s.latest_triage),
        json_escape(&s.latest_report),
        json_escape(&s.latest_coverage),
        if s.metrics_exists { "true" } else { "false" },
        s.successful_runs_per_hour_proxy,
        s.new_crashes_per_hour,
        valid_crash_ratio_json_literal(s),
        json_escape(&s.valid_crash_ratio_status),
        json_escape(&s.valid_crash_ratio_source),
        s.valid_crashes,
        s.total_crashes,
        s.triage_summary_count,
        global_error_rate_5m_json_literal(s),
        json_escape(&s.global_error_rate_5m_status),
        s.backend_worker_runs_per_hour,
        s.backend_worker_errors_5m,
        s.seeds_onnx_count,
        s.seeds_gguf_count,
        s.seeds_safetensors_count,
        s.seeds_total_count,
        json_escape(&s.latest_valid_triage),
        json_escape(&s.latest_valid_input),
        json_escape(&s.latest_valid_signature),
        json_escape(&s.latest_valid_crash_kind),
        json_escape(&s.latest_valid_sanitizer),
        json_escape(&s.latest_valid_signal),
        json_escape(&s.latest_valid_normalized_frame_hash),
        json_escape(&s.latest_valid_signature_basis),
        json_escape(&s.latest_valid_crash_summary),
        json_escape(&s.latest_valid_deep_triage_grouping_confidence),
        json_escape(&s.latest_valid_deep_triage_evidence_quality),
        json_escape(&s.latest_valid_summary),
        json_escape(&s.latest_valid_report),
        json_escape(&s.latest_valid_manifest),
        json_escape(&s.latest_valid_bundle),
        json_escape(&s.latest_suggested_severity),
        json_escape(&s.latest_severity_confidence),
        json_escape(&s.latest_suggested_cvss_vector),
        json_escape(&s.latest_coverage),
        json_escape(&s.latest_coverage_summary),
        json_escape(&s.latest_export_id),
        json_escape(&s.latest_export_path),
        json_escape(&s.latest_export_summary),
        json_escape(&s.latest_export_updated_at),
        json_escape(&s.latest_mutation_batch_id),
        json_escape(&s.latest_mutation_manifest_path),
        json_escape(&s.latest_mutation_target),
        json_escape(&s.latest_mutation_count),
        json_escape(&s.latest_mutation_updated_at),
        json_escape(&s.latest_mutation_source_corpus),
        json_escape(&s.latest_mutation_validation_summary),
        json_escape(&s.run_state),
        json_escape(&s.latest_run_target),
        json_escape(&s.latest_run_backend),
        json_escape(&s.latest_run_total),
        json_escape(&s.latest_run_success),
        json_escape(&s.latest_run_failed),
        json_escape(&s.latest_run_timeout),
        json_escape(&s.latest_run_updated_at),
        json_escape(&s.latest_campaign_id),
        json_escape(&s.latest_campaign_mode),
        json_escape(&s.latest_campaign_state),
        json_escape(&s.latest_campaign_target),
        json_escape(&s.latest_campaign_backends),
        json_escape(&s.latest_campaign_arms),
        json_escape(&s.latest_campaign_updated_at),
        json_escape(&s.latest_triage_verdict),
        json_escape(&s.latest_triage_target),
        json_escape(&s.latest_triage_updated_at),
        json_escape(&s.latest_report_updated_at),
        s.triage_verdict_reproduced,
        s.triage_verdict_manual_review,
        s.triage_verdict_not_reproduced,
        s.triage_verdict_timeout,
        s.triage_verdict_infra_oom,
        s.triage_verdict_flaky,
        s.triage_verdict_other,
    )
}

pub(crate) fn render_dashboard_html(s: &DashboardSnapshot) -> String {
    let metrics_badge = if s.metrics_exists {
        "<span class=\"badge\">available</span>"
    } else {
        "<span class=\"badge\">missing</span>"
    };
    let latest_run_html = id_to_route_link(&s.latest_run, "run");
    let latest_triage_html = id_to_route_link(&s.latest_triage, "triage");
    let latest_report_html = id_to_route_link(&s.latest_report, "report");
    let latest_coverage_html = id_to_route_link(&s.latest_coverage, "coverage");
    let latest_valid_triage_html = id_to_route_link(&s.latest_valid_triage, "triage");
    let latest_valid_summary_html = file_link(&s.latest_valid_summary, &s.latest_valid_summary);
    let latest_valid_report_html = file_link(&s.latest_valid_report, &s.latest_valid_report);
    let latest_valid_manifest_html = file_link(&s.latest_valid_manifest, &s.latest_valid_manifest);
    let latest_valid_bundle_html = file_link(&s.latest_valid_bundle, &s.latest_valid_bundle);
    let latest_coverage_summary_html =
        file_link(&s.latest_coverage_summary, &s.latest_coverage_summary);
    let latest_export_html = file_link(&s.latest_export_path, &s.latest_export_id);
    let latest_export_summary_html = file_link(&s.latest_export_summary, &s.latest_export_summary);
    let latest_mutation_html = file_link(
        &s.latest_mutation_manifest_path,
        &s.latest_mutation_batch_id,
    );
    let latest_report_status = artifact_status_label(&s.latest_report);
    let latest_export_status = artifact_status_label(&s.latest_export_id);
    let latest_mutation_status = artifact_status_label(&s.latest_mutation_batch_id);
    let run_state = run_state_label(&s.run_state);
    let latest_run_target = friendly_value(&s.latest_run_target);
    let latest_run_backend = friendly_value(&s.latest_run_backend);
    let latest_campaign_id = friendly_value(&s.latest_campaign_id);
    let latest_campaign_mode = friendly_value(&s.latest_campaign_mode);
    let latest_campaign_state = friendly_value(&s.latest_campaign_state);
    let latest_campaign_target = friendly_value(&s.latest_campaign_target);
    let latest_campaign_backends = friendly_value(&s.latest_campaign_backends);
    let latest_campaign_arms = friendly_value(&s.latest_campaign_arms);
    let latest_run_total = friendly_value(&s.latest_run_total);
    let latest_run_success = friendly_value(&s.latest_run_success);
    let latest_run_failed = friendly_value(&s.latest_run_failed);
    let latest_run_timeout = friendly_value(&s.latest_run_timeout);
    let latest_mutation_target = friendly_value(&s.latest_mutation_target);
    let latest_mutation_count = friendly_value(&s.latest_mutation_count);
    let latest_run_freshness = run_freshness_summary(s.generated_at, &s.latest_run_updated_at);
    let latest_run_error = run_error_rate_summary(
        &s.latest_run_total,
        &s.latest_run_success,
        &s.latest_run_failed,
        &s.latest_run_timeout,
    );
    let dashboard_status = dashboard_status_summary(
        &latest_run_freshness,
        &latest_run_error,
        s.triage_verdict_reproduced,
        s.triage_verdict_manual_review,
    );
    let latest_crash_status = crash_status_summary(
        &s.latest_valid_triage,
        &s.latest_valid_crash_kind,
        &s.latest_suggested_severity,
    );
    let latest_valid_triage_display = crash_candidate_presence(&s.latest_valid_triage);
    let latest_valid_input_display = friendly_path_leaf(&s.latest_valid_input);
    let latest_valid_crash_kind_display = friendly_value(&s.latest_valid_crash_kind);
    let latest_valid_runtime_display =
        runtime_signal_summary(&s.latest_valid_sanitizer, &s.latest_valid_signal);
    let latest_valid_crash_summary_display = friendly_value(&s.latest_valid_crash_summary);
    let latest_valid_deep_triage_grouping_confidence_display =
        friendly_value(&s.latest_valid_deep_triage_grouping_confidence);
    let latest_valid_deep_triage_evidence_quality_display =
        friendly_value(&s.latest_valid_deep_triage_evidence_quality);
    let latest_suggested_severity_display = friendly_value(&s.latest_suggested_severity);
    let latest_severity_confidence_display = friendly_value(&s.latest_severity_confidence);
    let run_result_chart = render_run_result_chart(&s.run_result_series);
    let throughput_proxy_chart = render_throughput_proxy_chart(&s.throughput_proxy_series);
    let crash_intake_chart = render_crash_intake_chart(&s.crash_intake_series);
    let verdict_breakdown_chart = render_verdict_breakdown_chart(&s.triage_verdict_breakdown);
    let (logs_meta_html, logs_body_html) = render_logs_section(
        &s.logs_source_path,
        &s.logs_tail,
        s.logs_total_lines,
        LOG_TAIL_LIMIT,
        &s.logs_error,
    );
    let suggested_commands_html = render_suggested_commands(s);
    let recent_triage_rows = render_recent_triage_rows(&s.data_dir, &s.recent_triage_ids);
    let recent_report_rows = render_recent_report_rows(&s.data_dir, &s.recent_report_ids);
    let recent_coverage_rows = render_recent_coverage_rows(&s.data_dir, &s.recent_coverage_ids);
    let recent_diagnostic_rows =
        render_recent_diagnostic_rows(&s.data_dir, &s.recent_diagnostic_ids);
    let target_prepare_options = render_target_options("onnx");
    let target_build_options = render_target_options("gguf");

    dashboard_html_template()
        .replace("{{target_prepare_options}}", &target_prepare_options)
        .replace("{{target_build_options}}", &target_build_options)
        .replace("{{generated_at}}", &s.generated_at.to_string())
        .replace("{{config_data_dir}}", &html_escape(&s.data_dir))
        .replace("{{config_seeds_dir}}", &html_escape(&s.seeds_dir))
        .replace("{{seeds_onnx_count}}", &s.seeds_onnx_count.to_string())
        .replace("{{seeds_gguf_count}}", &s.seeds_gguf_count.to_string())
        .replace(
            "{{seeds_safetensors_count}}",
            &s.seeds_safetensors_count.to_string(),
        )
        .replace("{{seeds_total_count}}", &s.seeds_total_count.to_string())
        .replace("{{runs_count}}", &s.runs_count.to_string())
        .replace("{{triage_count}}", &s.triage_count.to_string())
        .replace("{{report_count}}", &s.report_count.to_string())
        .replace("{{coverage_count}}", &s.coverage_count.to_string())
        .replace("{{metrics_badge}}", metrics_badge)
        .replace("{{latest_run_html}}", &latest_run_html)
        .replace("{{latest_triage_html}}", &latest_triage_html)
        .replace("{{latest_report_html}}", &latest_report_html)
        .replace("{{latest_coverage_html}}", &latest_coverage_html)
        .replace(
            "{{latest_coverage_summary_html}}",
            &latest_coverage_summary_html,
        )
        .replace("{{latest_export_html}}", &latest_export_html)
        .replace(
            "{{latest_export_summary_html}}",
            &latest_export_summary_html,
        )
        .replace("{{latest_mutation_html}}", &latest_mutation_html)
        .replace(
            "{{latest_mutation_target}}",
            &html_escape(&latest_mutation_target),
        )
        .replace(
            "{{latest_mutation_count}}",
            &html_escape(&latest_mutation_count),
        )
        .replace("{{latest_run_target}}", &html_escape(&latest_run_target))
        .replace("{{latest_run_backend}}", &html_escape(&latest_run_backend))
        .replace("{{latest_campaign_id}}", &html_escape(&latest_campaign_id))
        .replace(
            "{{latest_campaign_mode}}",
            &html_escape(&latest_campaign_mode),
        )
        .replace(
            "{{latest_campaign_state}}",
            &html_escape(&latest_campaign_state),
        )
        .replace(
            "{{latest_campaign_target}}",
            &html_escape(&latest_campaign_target),
        )
        .replace(
            "{{latest_campaign_backends}}",
            &html_escape(&latest_campaign_backends),
        )
        .replace(
            "{{latest_campaign_arms}}",
            &html_escape(&latest_campaign_arms),
        )
        .replace(
            "{{latest_campaign_updated_at}}",
            &html_escape(&s.latest_campaign_updated_at),
        )
        .replace("{{latest_run_total}}", &html_escape(&latest_run_total))
        .replace("{{latest_run_success}}", &html_escape(&latest_run_success))
        .replace("{{latest_run_failed}}", &html_escape(&latest_run_failed))
        .replace("{{latest_run_timeout}}", &html_escape(&latest_run_timeout))
        .replace(
            "{{triage_verdict_reproduced}}",
            &s.triage_verdict_reproduced.to_string(),
        )
        .replace(
            "{{triage_verdict_manual_review}}",
            &s.triage_verdict_manual_review.to_string(),
        )
        .replace(
            "{{triage_verdict_not_reproduced}}",
            &s.triage_verdict_not_reproduced.to_string(),
        )
        .replace(
            "{{triage_verdict_timeout}}",
            &s.triage_verdict_timeout.to_string(),
        )
        .replace(
            "{{triage_verdict_infra_oom}}",
            &s.triage_verdict_infra_oom.to_string(),
        )
        .replace(
            "{{triage_verdict_flaky}}",
            &s.triage_verdict_flaky.to_string(),
        )
        .replace(
            "{{triage_verdict_other}}",
            &s.triage_verdict_other.to_string(),
        )
        .replace("{{run_state}}", &html_escape(&run_state))
        .replace("{{dashboard_status_class}}", dashboard_status.class_name)
        .replace(
            "{{dashboard_status_title}}",
            &html_escape(&dashboard_status.title),
        )
        .replace(
            "{{dashboard_status_body}}",
            &html_escape(&dashboard_status.body),
        )
        .replace(
            "{{latest_run_freshness}}",
            &html_escape(&latest_run_freshness.label),
        )
        .replace(
            "{{latest_run_freshness_class}}",
            latest_run_freshness.class_name,
        )
        .replace(
            "{{latest_run_freshness_note}}",
            &html_escape(&latest_run_freshness.note),
        )
        .replace(
            "{{latest_run_error_rate}}",
            &html_escape(&latest_run_error.label),
        )
        .replace("{{latest_run_error_class}}", latest_run_error.class_name)
        .replace(
            "{{latest_run_error_note}}",
            &html_escape(&latest_run_error.note),
        )
        .replace(
            "{{latest_triage_verdict}}",
            &html_escape(&s.latest_triage_verdict),
        )
        .replace(
            "{{latest_triage_target}}",
            &html_escape(&s.latest_triage_target),
        )
        .replace(
            "{{latest_run_updated_at}}",
            &html_escape(&s.latest_run_updated_at),
        )
        .replace(
            "{{latest_triage_updated_at}}",
            &html_escape(&s.latest_triage_updated_at),
        )
        .replace(
            "{{latest_report_updated_at}}",
            &html_escape(&s.latest_report_updated_at),
        )
        .replace(
            "{{latest_export_updated_at}}",
            &html_escape(&s.latest_export_updated_at),
        )
        .replace(
            "{{latest_mutation_updated_at}}",
            &html_escape(&s.latest_mutation_updated_at),
        )
        .replace("{{latest_report_status}}", latest_report_status)
        .replace("{{latest_export_status}}", latest_export_status)
        .replace("{{latest_mutation_status}}", latest_mutation_status)
        .replace(
            "{{latest_mutation_source_corpus}}",
            &html_escape(&s.latest_mutation_source_corpus),
        )
        .replace(
            "{{latest_mutation_validation_summary}}",
            &html_escape(&s.latest_mutation_validation_summary),
        )
        .replace("{{run_result_chart}}", &run_result_chart)
        .replace("{{throughput_proxy_chart}}", &throughput_proxy_chart)
        .replace("{{crash_intake_chart}}", &crash_intake_chart)
        .replace("{{verdict_breakdown_chart}}", &verdict_breakdown_chart)
        .replace("{{logs_meta_html}}", &logs_meta_html)
        .replace("{{logs_body_html}}", &logs_body_html)
        .replace("{{suggested_commands_html}}", &suggested_commands_html)
        .replace(
            "{{successful_runs_per_hour_proxy}}",
            &html_escape(&s.successful_runs_per_hour_proxy),
        )
        .replace(
            "{{new_crashes_per_hour}}",
            &html_escape(&s.new_crashes_per_hour),
        )
        .replace("{{valid_crash_ratio}}", &html_escape(&s.valid_crash_ratio))
        .replace(
            "{{valid_crash_ratio_source}}",
            &html_escape(&s.valid_crash_ratio_source),
        )
        .replace("{{valid_crashes}}", &html_escape(&s.valid_crashes))
        .replace("{{total_crashes}}", &html_escape(&s.total_crashes))
        .replace(
            "{{triage_summary_count}}",
            &html_escape(&s.triage_summary_count),
        )
        .replace(
            "{{global_error_rate_5m}}",
            &html_escape(&s.global_error_rate_5m),
        )
        .replace("{{latest_valid_triage}}", &latest_valid_triage_html)
        .replace(
            "{{latest_valid_triage_id}}",
            &html_escape(&s.latest_valid_triage),
        )
        .replace(
            "{{latest_valid_triage_display}}",
            &html_escape(&latest_valid_triage_display),
        )
        .replace(
            "{{latest_crash_status_class}}",
            latest_crash_status.class_name,
        )
        .replace(
            "{{latest_crash_status_title}}",
            &html_escape(&latest_crash_status.title),
        )
        .replace(
            "{{latest_crash_status_body}}",
            &html_escape(&latest_crash_status.body),
        )
        .replace(
            "{{latest_valid_input}}",
            &html_escape(&s.latest_valid_input),
        )
        .replace(
            "{{latest_valid_input_display}}",
            &html_escape(&latest_valid_input_display),
        )
        .replace(
            "{{latest_valid_signature}}",
            &html_escape(&s.latest_valid_signature),
        )
        .replace(
            "{{latest_valid_crash_kind}}",
            &html_escape(&s.latest_valid_crash_kind),
        )
        .replace(
            "{{latest_valid_crash_kind_display}}",
            &html_escape(&latest_valid_crash_kind_display),
        )
        .replace(
            "{{latest_valid_sanitizer}}",
            &html_escape(&s.latest_valid_sanitizer),
        )
        .replace(
            "{{latest_valid_signal}}",
            &html_escape(&s.latest_valid_signal),
        )
        .replace(
            "{{latest_valid_runtime_display}}",
            &html_escape(&latest_valid_runtime_display),
        )
        .replace(
            "{{latest_valid_normalized_frame_hash}}",
            &html_escape(&s.latest_valid_normalized_frame_hash),
        )
        .replace(
            "{{latest_valid_signature_basis}}",
            &html_escape(&s.latest_valid_signature_basis),
        )
        .replace(
            "{{latest_valid_crash_summary}}",
            &html_escape(&s.latest_valid_crash_summary),
        )
        .replace(
            "{{latest_valid_crash_summary_display}}",
            &html_escape(&latest_valid_crash_summary_display),
        )
        .replace(
            "{{latest_valid_deep_triage_grouping_confidence}}",
            &html_escape(&s.latest_valid_deep_triage_grouping_confidence),
        )
        .replace(
            "{{latest_valid_deep_triage_grouping_confidence_display}}",
            &html_escape(&latest_valid_deep_triage_grouping_confidence_display),
        )
        .replace(
            "{{latest_valid_deep_triage_evidence_quality}}",
            &html_escape(&s.latest_valid_deep_triage_evidence_quality),
        )
        .replace(
            "{{latest_valid_deep_triage_evidence_quality_display}}",
            &html_escape(&latest_valid_deep_triage_evidence_quality_display),
        )
        .replace("{{latest_valid_summary_html}}", &latest_valid_summary_html)
        .replace("{{latest_valid_report_html}}", &latest_valid_report_html)
        .replace(
            "{{latest_valid_manifest_html}}",
            &latest_valid_manifest_html,
        )
        .replace("{{latest_valid_bundle_html}}", &latest_valid_bundle_html)
        .replace(
            "{{latest_suggested_severity}}",
            &html_escape(&s.latest_suggested_severity),
        )
        .replace(
            "{{latest_suggested_severity_display}}",
            &html_escape(&latest_suggested_severity_display),
        )
        .replace(
            "{{latest_severity_confidence}}",
            &html_escape(&s.latest_severity_confidence),
        )
        .replace(
            "{{latest_severity_confidence_display}}",
            &html_escape(&latest_severity_confidence_display),
        )
        .replace(
            "{{latest_suggested_cvss_vector}}",
            &html_escape(&s.latest_suggested_cvss_vector),
        )
        .replace("{{recent_triage_rows}}", &recent_triage_rows)
        .replace("{{recent_report_rows}}", &recent_report_rows)
        .replace("{{recent_coverage_rows}}", &recent_coverage_rows)
        .replace("{{recent_diagnostic_rows}}", &recent_diagnostic_rows)
}

fn render_target_options(default_target: &str) -> String {
    all_target_specs()
        .iter()
        .filter(|spec| spec.ui_supported)
        .map(|spec| {
            let selected = if spec.target_id == default_target {
                " selected"
            } else {
                ""
            };
            let target = html_escape(spec.target_id);
            format!("<option value=\"{target}\"{selected}>{target}</option>")
        })
        .collect::<Vec<_>>()
        .join("")
}

fn dashboard_html_template() -> String {
    fs::read_to_string(DASHBOARD_HTML_TEMPLATE_PATH)
        .unwrap_or_else(|_| DEFAULT_DASHBOARD_HTML_TEMPLATE.to_string())
}

fn friendly_value(value: &str) -> String {
    match value {
        "not_available" | "" => "기록 없음".to_string(),
        other => other.to_string(),
    }
}

fn friendly_path_leaf(value: &str) -> String {
    if value == "not_available" || value.is_empty() {
        return "기록 없음".to_string();
    }
    value
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(value)
        .to_string()
}

fn crash_candidate_presence(latest_valid_triage: &str) -> String {
    if latest_valid_triage == "not_available" {
        "기록 없음".to_string()
    } else {
        "재현 후보 있음".to_string()
    }
}

fn run_state_label(value: &str) -> String {
    match value {
        "finished" => "최근 결과 있음".to_string(),
        "no_run" => "검사 기록 없음".to_string(),
        "not_available" | "" => "기록 없음".to_string(),
        other => other.to_string(),
    }
}

struct StatusMetric {
    label: String,
    note: String,
    class_name: &'static str,
}

struct DashboardStatusSummary {
    title: String,
    body: String,
    class_name: &'static str,
}

fn run_freshness_summary(generated_at: u64, updated_at: &str) -> StatusMetric {
    let Some(updated_at) = updated_at.parse::<u64>().ok() else {
        return StatusMetric {
            label: "기록 없음".to_string(),
            note: "아직 검사 결과를 찾지 못했습니다".to_string(),
            class_name: "muted",
        };
    };
    let age = generated_at.saturating_sub(updated_at);
    let (label, class_name) = if age <= 600 {
        ("방금 갱신됨", "good")
    } else if age <= 3600 {
        ("최근 갱신됨", "good")
    } else if age <= 86_400 {
        ("갱신 지연", "warn")
    } else {
        ("오래된 결과", "danger")
    };
    StatusMetric {
        label: label.to_string(),
        note: format!("마지막 결과 {}", human_duration_ago(age)),
        class_name,
    }
}

fn human_duration_ago(seconds: u64) -> String {
    if seconds < 60 {
        "방금 전".to_string()
    } else if seconds < 3600 {
        format!("{}분 전", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}시간 전", seconds / 3600)
    } else {
        format!("{}일 전", seconds / 86_400)
    }
}

fn run_error_rate_summary(total: &str, success: &str, failed: &str, timeout: &str) -> StatusMetric {
    let success = success.parse::<u64>().unwrap_or(0);
    let failed = failed.parse::<u64>().unwrap_or(0);
    let timeout = timeout.parse::<u64>().unwrap_or(0);
    let total = total
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .unwrap_or(success + failed + timeout);
    if total == 0 {
        return StatusMetric {
            label: "기록 없음".to_string(),
            note: "오류율을 계산할 검사 결과가 없습니다".to_string(),
            class_name: "muted",
        };
    }
    let errors = failed + timeout;
    let error_rate = (errors as f64 / total as f64) * 100.0;
    let class_name = if error_rate == 0.0 {
        "good"
    } else if error_rate <= 10.0 {
        "warn"
    } else {
        "danger"
    };
    StatusMetric {
        label: format!("{error_rate:.1}%"),
        note: format!("{errors}개 오류 / {total}개 입력"),
        class_name,
    }
}

fn dashboard_status_summary(
    freshness: &StatusMetric,
    error: &StatusMetric,
    reproduced: usize,
    manual_review: usize,
) -> DashboardStatusSummary {
    if freshness.class_name == "muted" {
        return DashboardStatusSummary {
            title: "아직 검사 결과가 없습니다".to_string(),
            body: "퍼징을 실행하면 검사 상태와 오류율이 여기에 표시됩니다.".to_string(),
            class_name: "muted",
        };
    }
    if freshness.class_name == "danger" {
        return DashboardStatusSummary {
            title: "검사 결과가 오래되었습니다".to_string(),
            body: format!("{}입니다. 퍼징이 멈췄는지 확인하세요.", freshness.note),
            class_name: "danger",
        };
    }
    if freshness.class_name == "warn" {
        return DashboardStatusSummary {
            title: "검사 갱신이 지연되고 있습니다".to_string(),
            body: format!(
                "{}입니다. 실행 환경이 계속 동작 중인지 확인할 필요가 있습니다.",
                freshness.note
            ),
            class_name: "warn",
        };
    }
    if error.class_name == "danger" {
        return DashboardStatusSummary {
            title: "최근 오류율이 높습니다".to_string(),
            body: format!(
                "{}입니다. 입력/환경/타임아웃 설정을 우선 확인하세요.",
                error.note
            ),
            class_name: "danger",
        };
    }
    if reproduced > 0 {
        return DashboardStatusSummary {
            title: "재현된 문제 후보가 있습니다".to_string(),
            body: format!("재현 후보 {reproduced}개가 있습니다. 리포트 가능 여부를 확인하세요."),
            class_name: "warn",
        };
    }
    if manual_review > 0 {
        return DashboardStatusSummary {
            title: "수동 확인할 후보가 있습니다".to_string(),
            body: format!("{manual_review}개 후보는 사람이 한 번 더 확인해야 합니다."),
            class_name: "warn",
        };
    }
    if error.class_name == "warn" {
        return DashboardStatusSummary {
            title: "소수의 오류가 있습니다".to_string(),
            body: format!("{}입니다. 급증하지 않는지 추이를 보면 됩니다.", error.note),
            class_name: "warn",
        };
    }
    DashboardStatusSummary {
        title: "최근 검사 결과는 안정적입니다".to_string(),
        body: format!(
            "{}이며 재현된 문제 후보는 {reproduced}개입니다.",
            error.note
        ),
        class_name: "good",
    }
}

fn crash_status_summary(
    latest_valid_triage: &str,
    crash_kind: &str,
    severity: &str,
) -> DashboardStatusSummary {
    if latest_valid_triage == "not_available" {
        return DashboardStatusSummary {
            title: "재현된 문제 후보가 없습니다".to_string(),
            body: "아직 리포트로 이어질 수 있는 재현 후보를 찾지 못했습니다.".to_string(),
            class_name: "muted",
        };
    }
    let crash_kind = friendly_value(crash_kind);
    let severity = friendly_value(severity);
    DashboardStatusSummary {
        title: "재현된 문제 후보가 있습니다".to_string(),
        body: format!("원인 유형은 {crash_kind}, 심각도 후보는 {severity}입니다."),
        class_name: "warn",
    }
}

fn runtime_signal_summary(sanitizer: &str, signal: &str) -> String {
    let sanitizer = friendly_value(sanitizer);
    let signal = friendly_value(signal);
    if sanitizer == "기록 없음" && signal == "기록 없음" {
        "기록 없음".to_string()
    } else {
        format!("{sanitizer} / {signal}")
    }
}

/// The rate is a bare JSON literal, so an unavailable one must be the `null`
/// keyword rather than the string the snapshot carries - otherwise /dashboard.json
/// stops parsing.
fn global_error_rate_5m_json_literal(s: &DashboardSnapshot) -> &str {
    if s.global_error_rate_5m_status == "available" {
        &s.global_error_rate_5m
    } else {
        "null"
    }
}

fn valid_crash_ratio_json_literal(s: &DashboardSnapshot) -> &str {
    if s.valid_crash_ratio_status == "available" {
        &s.valid_crash_ratio
    } else {
        "null"
    }
}

fn artifact_status_label(id_text: &str) -> &'static str {
    if id_text == "not_available" {
        "not_available"
    } else {
        "present"
    }
}

fn id_to_route_link(id_text: &str, route: &str) -> String {
    if id_text == "not_available" {
        return "not_available".to_string();
    }
    format!(
        "<a class=\"path-link\" href=\"/{}/{}\">{}</a>",
        html_escape(route),
        url_encode(id_text),
        html_escape(id_text)
    )
}

fn file_link(path: &str, label: &str) -> String {
    if path == "not_available" {
        return "not_available".to_string();
    }
    let href = format!("/file?path={}", url_encode(path));
    format!(
        "<a class=\"path-link\" href=\"{}\">{}</a>",
        html_escape(&href),
        html_escape(label)
    )
}

// The links were built from the literal "./data/...", so under a data dir other
// than the default every one of them 500'd on /file?path=.
fn render_recent_triage_rows(data_dir: &str, ids: &[String]) -> String {
    if ids.is_empty() {
        return "<li>not_available</li>".to_string();
    }
    ids.iter()
        .map(|id| {
            let route = id_to_route_link(id, "triage");
            let summary = format!("{data_dir}/triage/{id}/summary.json");
            let summary_link = file_link(&summary, "summary.json");
            format!("<li>{route} <span class=\"sep\">|</span> {summary_link}</li>")
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_recent_report_rows(data_dir: &str, ids: &[String]) -> String {
    if ids.is_empty() {
        return "<li>not_available</li>".to_string();
    }
    ids.iter()
        .map(|id| {
            let route = id_to_route_link(id, "report");
            let report_md = format!("{data_dir}/reports/{id}/report.md");
            let manifest = format!("{data_dir}/reports/{id}/manifest.json");
            let bundle = format!("{data_dir}/reports/{id}/{id}-evidence.zip");
            let report_link = file_link(&report_md, "report.md");
            let manifest_link = file_link(&manifest, "manifest.json");
            let bundle_link = file_link(&bundle, "evidence.zip");
            format!(
                "<li>{route} <span class=\"sep\">|</span> {report_link} <span class=\"sep\">|</span> {manifest_link} <span class=\"sep\">|</span> {bundle_link}</li>"
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_recent_coverage_rows(data_dir: &str, ids: &[String]) -> String {
    if ids.is_empty() {
        return "<li>not_available</li>".to_string();
    }
    ids.iter()
        .map(|id| {
            let route = id_to_route_link(id, "coverage");
            let summary = format!("{data_dir}/coverage/{id}/summary.json");
            let summary_link = file_link(&summary, "summary.json");
            format!("<li>{route} <span class=\"sep\">|</span> {summary_link}</li>")
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_recent_diagnostic_rows(data_dir: &str, ids: &[String]) -> String {
    if ids.is_empty() {
        return "<li>not_available</li>".to_string();
    }
    ids.iter()
        .map(|id| {
            let route = id_to_route_link(id, "diagnostic");
            let record = format!("{data_dir}/diagnostics/{id}/diagnostic.json");
            let record_link = file_link(&record, "diagnostic.json");
            format!("<li>{route} <span class=\"sep\">|</span> {record_link}</li>")
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_run_result_chart(points: &[RunResultPoint]) -> String {
    if points.is_empty() {
        return "<p class=\"chart-empty\">최근 검사 기록이 없습니다</p>".to_string();
    }
    let max = points
        .iter()
        .map(|p| p.success + p.failed + p.timeout)
        .max()
        .unwrap_or(1)
        .max(1);
    let rows = points
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let label = run_chart_label(idx, points.len());
            let s_pct = (p.success as f64 / max as f64) * 100.0;
            let f_pct = (p.failed as f64 / max as f64) * 100.0;
            let t_pct = (p.timeout as f64 / max as f64) * 100.0;
            let error_count = p.failed + p.timeout;
            let total = p.success + error_count;
            let error_rate = if total == 0 {
                0.0
            } else {
                (error_count as f64 / total as f64) * 100.0
            };
            format!(
                "<div class=\"chart-row\"><span class=\"chart-label\" title=\"{}\">{}</span><div class=\"chart-bar-track\"><div class=\"chart-bar chart-bar-success\" style=\"width:{:.1}%\"></div><div class=\"chart-bar chart-bar-failed\" style=\"width:{:.1}%\"></div><div class=\"chart-bar chart-bar-timeout\" style=\"width:{:.1}%\"></div></div><span class=\"chart-value\">오류 {} · {:.1}%</span></div>",
                html_escape(&p.run_id),
                html_escape(&label),
                s_pct,
                f_pct,
                t_pct,
                error_count,
                error_rate
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!("<div class=\"chart-stack\">{rows}</div><div class=\"chart-legend\"><span class=\"chart-bar-success\"></span>정상 처리 <span class=\"chart-bar-failed\"></span>실패 <span class=\"chart-bar-timeout\"></span>시간 초과</div>")
}

fn render_throughput_proxy_chart(points: &[ThroughputProxyPoint]) -> String {
    if points.is_empty() {
        return "<p class=\"chart-empty\">최근 처리량 기록이 없습니다</p>".to_string();
    }
    let max = points.iter().map(|p| p.success).max().unwrap_or(1).max(1);
    let rows = points
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let label = run_chart_label(idx, points.len());
            let pct = (p.success as f64 / max as f64) * 100.0;
            format!(
                "<div class=\"chart-row\"><span class=\"chart-label\" title=\"{}\">{}</span><div class=\"chart-bar-track\"><div class=\"chart-bar chart-bar-success\" style=\"width:{:.1}%\"></div></div><span class=\"chart-value\">{}개 정상 처리</span></div>",
                html_escape(&p.run_id),
                html_escape(&label),
                pct,
                p.success
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!("<div class=\"chart-stack\">{rows}</div>")
}

fn run_chart_label(index: usize, total: usize) -> String {
    if index + 1 == total {
        "가장 최근".to_string()
    } else {
        format!("{}회 전", total.saturating_sub(index + 1))
    }
}

fn render_crash_intake_chart(points: &[CrashIntakePoint]) -> String {
    if points.is_empty() {
        return "<p class=\"chart-empty\">no recent triages</p>".to_string();
    }
    let cells = points
        .iter()
        .map(|p| {
            let class = match p.verdict.as_str() {
                "reproduced" => "chart-bar-success",
                "manual_review" => "chart-bar-warn",
                "timeout" | "infra_oom" => "chart-bar-timeout",
                "flaky" => "chart-bar-failed",
                _ => "chart-bar-neutral",
            };
            format!(
                "<div class=\"chart-strip-cell {class}\" title=\"{} verdict={}\"></div>",
                html_escape(&p.triage_id),
                html_escape(&p.verdict)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!("<div class=\"chart-strip\">{cells}</div><div class=\"chart-legend\"><span class=\"chart-bar-success\"></span>reproduced <span class=\"chart-bar-warn\"></span>manual_review <span class=\"chart-bar-timeout\"></span>timeout/infra_oom <span class=\"chart-bar-failed\"></span>flaky <span class=\"chart-bar-neutral\"></span>not_reproduced/other</div>")
}

fn render_logs_section(
    source_path: &str,
    tail: &[String],
    total: usize,
    limit: usize,
    error: &str,
) -> (String, String) {
    if source_path == "not_available" {
        return (
            "no log available".to_string(),
            "<p class=\"chart-empty\">no log available</p>".to_string(),
        );
    }
    if error != "not_available" {
        return (
            format!(
                "source: {} <span class=\"hint\">read error: {}</span>",
                html_escape(source_path),
                html_escape(error)
            ),
            "<p class=\"chart-empty\">no log available</p>".to_string(),
        );
    }
    let meta = if total > limit {
        format!(
            "source: {} <span class=\"hint\">showing last {} of {} total lines</span>",
            html_escape(source_path),
            tail.len(),
            total
        )
    } else {
        format!(
            "source: {} <span class=\"hint\">showing all {} lines</span>",
            html_escape(source_path),
            total
        )
    };
    let body = if tail.is_empty() {
        "<pre class=\"log-body\">(empty)</pre>".to_string()
    } else {
        let escaped = tail
            .iter()
            .map(|l| html_escape(l))
            .collect::<Vec<_>>()
            .join("\n");
        format!("<pre class=\"log-body\">{escaped}</pre>")
    };
    (meta, body)
}

fn render_suggested_commands(s: &DashboardSnapshot) -> String {
    let target = if s.latest_run_target != "not_available" {
        s.latest_run_target.as_str()
    } else {
        "<target>"
    };
    let backend = if s.latest_run_backend != "not_available" {
        s.latest_run_backend.as_str()
    } else {
        "<backend>"
    };
    let seed_subdir = parse_target_id(target)
        .map(|kind| target_spec(&kind).seed_subdir)
        .unwrap_or(target);
    let commands: Vec<(&str, String)> = vec![
        (
            "Run",
            format!(
                "tool run --target {target} --backend local-harness --corpus-dir seeds/{seed_subdir} --timeout-sec 30 --restart-limit 1"
            ),
        ),
        (
            "Serial campaign",
            format!(
                "tool campaign --mode serial --target {target} --hours 168 --campaign-id <campaign-id>"
            ),
        ),
        (
            "Parallel campaign",
            format!(
                "tool campaign --mode parallel --target {target} --hours 168 --campaign-id <campaign-id>"
            ),
        ),
        (
            "Smoke campaign",
            format!(
                "tool campaign --mode parallel --target {target} --duration-seconds 10 --campaign-id smoke-{target}-<id> --backends local-harness --max-jobs 1"
            ),
        ),
        (
            "Triage",
            format!(
                "tool triage --target {target} --input <crash-input> --repro-retries 3 --timeout-sec 60"
            ),
        ),
        ("Report", "tool report --minimize".to_string()),
        (
            "Export",
            format!(
                "scripts/export_experiment_summary.sh --experiment-id <name> --machine-label <label> --target {target} --backend {backend} --duration-hours <hours> --out-dir data/exports/<name> --data-dir data"
            ),
        ),
        (
            "Mutate",
            format!(
                "tool mutate --target {target} --input-dir seeds/{seed_subdir} --out-dir data/corpus/mutated/{target}/<batch-id> --count 5 --seed 1"
            ),
        ),
        (
            "Open dashboard",
            "tool dashboard --format html --out /tmp/dashboard.html".to_string(),
        ),
    ];
    commands
        .iter()
        .map(|(label, cmd)| {
            format!(
                "<div class=\"cmd-block\"><div class=\"cmd-label\">{}</div><pre class=\"cmd-code\"><code>{}</code></pre></div>",
                html_escape(label),
                html_escape(cmd)
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_verdict_breakdown_chart(points: &[VerdictBreakdownPoint]) -> String {
    if points.is_empty() {
        return "<p class=\"chart-empty\">no triage verdicts</p>".to_string();
    }
    let max = points.iter().map(|p| p.count).max().unwrap_or(1).max(1);
    let rows = points
        .iter()
        .map(|p| {
            let pct = (p.count as f64 / max as f64) * 100.0;
            let class = match p.verdict.as_str() {
                "reproduced" => "chart-bar-success",
                "manual_review" => "chart-bar-warn",
                "timeout" | "infra_oom" => "chart-bar-timeout",
                "flaky" => "chart-bar-failed",
                _ => "chart-bar-neutral",
            };
            format!(
                "<div class=\"chart-row\"><span class=\"chart-label\">{}</span><div class=\"chart-bar-track\"><div class=\"chart-bar {class}\" style=\"width:{:.1}%\"></div></div><span class=\"chart-value\">{}</span></div>",
                html_escape(&p.verdict), pct, p.count
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!("<div class=\"chart-stack\">{rows}</div>")
}
