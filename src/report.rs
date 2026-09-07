use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use crate::common::{
    artifact_contract_for_data_dir, command_exists, command_with_core_dump_off, now_unix_millis,
    sha256_file, AppPaths,
};
use crate::json_utils::{
    extract_first_signature_top3_list, extract_json_string_literal, extract_json_u64_field,
    json_escape,
};
use crate::retention::apply_retention_policy;

pub(crate) fn run_report_pipeline(
    app_paths: &AppPaths,
    minimize_requested: bool,
) -> Result<(), String> {
    let retention = apply_retention_policy(app_paths, 30)?;
    let (triage_id, triage_dir, summary_path) = find_latest_triage_summary(&app_paths.data_dir)?;
    let summary = fs::read_to_string(&summary_path)
        .map_err(|e| format!("failed to read '{}': {e}", summary_path.display()))?;

    let target =
        extract_json_string_literal(&summary, "target").unwrap_or_else(|| "unknown".to_string());
    let input =
        extract_json_string_literal(&summary, "input").unwrap_or_else(|| "unknown".to_string());
    let verdict =
        extract_json_string_literal(&summary, "verdict").unwrap_or_else(|| "unknown".to_string());

    // verdict gate per specs.md §4: only "reproduced" (High Confidence) generates a report.
    // Others are queued for Manual Review (§4 line 148).
    if verdict != "reproduced" {
        record_manual_review(
            app_paths,
            triage_id,
            &target,
            &input,
            &verdict,
            &summary_path,
        )?;
        return Err(format!(
            "report skipped: verdict '{verdict}' != 'reproduced' (triage {triage_id}); queued for manual review"
        ));
    }

    let repro_retries = extract_json_u64_field(&summary, "repro_retries").unwrap_or(3);
    let timeout_sec = extract_json_u64_field(&summary, "timeout_sec").unwrap_or(60);
    let signature_top3 = extract_first_signature_top3_list(&summary);
    let triage_crash = extract_triage_crash_fields(&summary);
    let triage_deep = extract_triage_deep_fields(&summary);

    let input_sha256 = if input != "unknown" {
        sha256_file(Path::new(&input)).unwrap_or_else(|_| "unavailable".to_string())
    } else {
        "unavailable".to_string()
    };

    let report_id = now_unix_millis();
    let report_dir = app_paths
        .data_dir
        .join("reports")
        .join(format!("report-{report_id}"));
    fs::create_dir_all(&report_dir).map_err(|e| {
        format!(
            "failed to create report dir '{}': {e}",
            report_dir.display()
        )
    })?;
    let poc = collect_report_poc(
        &report_dir,
        triage_id,
        &target,
        &input,
        &input_sha256,
        &verdict,
    );
    let mut minimization =
        collect_minimization_artifact(&report_dir, triage_id, &target, &poc, minimize_requested);
    apply_minimization_validation(
        &mut minimization,
        triage_id,
        &target,
        &poc,
        &triage_crash.normalized_frame_hash,
    );
    let repro_input = poc.repro_input_or(&input);

    let crash_report = build_crash_report(&triage_dir, &summary);
    let crash_report_path = report_dir.join("crash_report.txt");
    fs::write(&crash_report_path, &crash_report)
        .map_err(|e| format!("failed to write '{}': {e}", crash_report_path.display()))?;

    let repro_script = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\ntool triage --target {} --input '{}' --repro-retries {} --timeout-sec {}\n",
        target,
        shell_escape_single_quoted(&repro_input),
        repro_retries,
        timeout_sec
    );
    let repro_path = report_dir.join("repro.sh");
    fs::write(&repro_path, repro_script)
        .map_err(|e| format!("failed to write '{}': {e}", repro_path.display()))?;

    let stack_lines = if signature_top3.is_empty() {
        vec!["(no signature)".to_string()]
    } else {
        signature_top3
    };
    let severity = suggest_report_severity(&crash_report, &stack_lines, &triage_crash);

    let meta_json = format!(
        "{{\n  \"schema_version\": \"1.3\",\n  \"report_id\": \"{}\",\n  \"source_triage_id\": \"{}\",\n  \"source_summary\": \"{}\",\n  \"target\": \"{}\",\n  \"input\": \"{}\",\n  \"input_sha256\": \"{}\",\n  \"verdict\": \"{}\",\n  \"crash_kind\": \"{}\",\n  \"sanitizer\": \"{}\",\n  \"signal\": \"{}\",\n  \"normalized_frame_hash\": \"{}\",\n  \"signature_basis\": \"{}\",\n  \"crash_summary\": \"{}\",\n  \"deep_triage_version\": \"{}\",\n  \"deep_triage_status\": \"{}\",\n  \"deep_triage_grouping_confidence\": \"{}\",\n  \"deep_triage_grouping_reason\": \"{}\",\n  \"deep_triage_evidence_quality\": \"{}\",\n  \"suggested_severity\": \"{}\",\n  \"suggested_cvss_vector\": \"{}\",\n  \"severity_confidence\": \"{}\",\n  \"severity_reason\": \"{}\",\n  \"poc_collected\": {},\n  \"poc_path\": \"{}\",\n  \"poc_sha256\": \"{}\",\n  \"poc_size_bytes\": {},\n  \"poc_source_input\": \"{}\",\n  \"poc_error\": \"{}\",\n  \"minimize_requested\": {},\n  \"minimized\": {},\n  \"minimize_strategy\": \"{}\",\n  \"minimized_input\": \"{}\",\n  \"minimized_sha256\": \"{}\",\n  \"minimized_size_bytes\": {},\n  \"original_sha256\": \"{}\",\n  \"original_size_bytes\": {},\n  \"size_reduction_ratio\": {:.4},\n  \"minimize_error\": \"{}\",\n  \"minimize_validation_status\": \"{}\",\n  \"minimize_validation_verdict\": \"{}\",\n  \"minimize_validation_summary\": \"{}\",\n  \"minimized_normalized_frame_hash\": \"{}\",\n  \"retention_days\": 30,\n  \"retention\": {{\n    \"compressed_logs\": {},\n    \"deleted_dirs\": {},\n    \"skipped_log_compress\": {}\n  }}\n}}\n",
        report_id,
        triage_id,
        json_escape(&summary_path.display().to_string()),
        json_escape(&target),
        json_escape(&input),
        json_escape(&input_sha256),
        json_escape(&verdict),
        json_escape(&triage_crash.crash_kind),
        json_escape(&triage_crash.sanitizer),
        json_escape(&triage_crash.signal),
        json_escape(&triage_crash.normalized_frame_hash),
        json_escape(&triage_crash.signature_basis),
        json_escape(&triage_crash.crash_summary),
        json_escape(&triage_deep.version),
        json_escape(&triage_deep.status),
        json_escape(&triage_deep.grouping_confidence),
        json_escape(&triage_deep.grouping_reason),
        json_escape(&triage_deep.evidence_quality),
        json_escape(severity.suggested_severity),
        json_escape(severity.suggested_cvss_vector),
        json_escape(severity.confidence),
        json_escape(severity.reason),
        if poc.collected { "true" } else { "false" },
        json_escape(&poc.path),
        json_escape(&poc.sha256),
        poc.size_bytes,
        json_escape(&input),
        json_escape(&poc.error),
        if minimization.requested {
            "true"
        } else {
            "false"
        },
        if minimization.minimized {
            "true"
        } else {
            "false"
        },
        json_escape(&minimization.strategy),
        json_escape(&minimization.input_path),
        json_escape(&minimization.sha256),
        minimization.size_bytes,
        json_escape(&minimization.original_sha256),
        minimization.original_size_bytes,
        minimization.size_reduction_ratio,
        json_escape(&minimization.error),
        json_escape(&minimization.validation_status),
        json_escape(&minimization.validation_verdict),
        json_escape(&minimization.validation_summary),
        json_escape(&minimization.validation_normalized_frame_hash),
        retention.compressed_logs,
        retention.deleted_dirs,
        retention.skipped_log_compress
    );
    let meta_path = report_dir.join("meta.json");
    fs::write(&meta_path, meta_json)
        .map_err(|e| format!("failed to write '{}': {e}", meta_path.display()))?;

    let stack_text = stack_lines
        .iter()
        .map(|s| format!("- {}", markdown_inline_code(s)))
        .collect::<Vec<_>>()
        .join("\n");

    let report_title = build_report_title(&target, &stack_lines, &triage_crash);
    let target_code = markdown_inline_code(&target);
    let verdict_code = markdown_inline_code(&verdict);
    let crash_kind_code = markdown_inline_code(&triage_crash.crash_kind);
    let sanitizer_code = markdown_inline_code(&triage_crash.sanitizer);
    let signal_code = markdown_inline_code(&triage_crash.signal);
    let normalized_signature_code = markdown_inline_code(&triage_crash.normalized_frame_hash);
    let input_code = markdown_inline_code(&input);
    let poc_path = if poc.path.is_empty() { "-" } else { &poc.path };
    let poc_path_code = markdown_inline_code(poc_path);
    let repro_command = format!(
        "tool triage --target {} --input '{}' --repro-retries {} --timeout-sec {}",
        target,
        shell_escape_single_quoted(&repro_input),
        repro_retries,
        timeout_sec
    );
    let repro_command_code = markdown_inline_code(&repro_command);
    let severity_code = markdown_inline_code(severity.suggested_severity);
    let cvss_code = markdown_inline_code(severity.suggested_cvss_vector);
    let confidence_code = markdown_inline_code(severity.confidence);
    let severity_reason_code = markdown_inline_code(severity.reason);
    let input_sha256_code = markdown_inline_code(&input_sha256);
    let collection_status_code = markdown_inline_code(if poc.collected {
        "collected"
    } else {
        "not_collected"
    });
    let minimize_requested_code =
        markdown_inline_code(if minimization.requested { "yes" } else { "no" });
    let minimized_code = markdown_inline_code(if minimization.minimized { "yes" } else { "no" });
    let minimize_strategy_code = markdown_inline_code(&minimization.strategy);
    let minimized_input = if minimization.input_path.is_empty() {
        "-"
    } else {
        &minimization.input_path
    };
    let minimized_input_code = markdown_inline_code(minimized_input);
    let original_size_code = markdown_inline_code(&minimization.original_size_bytes.to_string());
    let minimized_size_code = markdown_inline_code(&minimization.size_bytes.to_string());
    let reduction_ratio_code =
        markdown_inline_code(&format!("{:.4}", minimization.size_reduction_ratio));
    let minimize_error = if minimization.error.is_empty() {
        "-"
    } else {
        &minimization.error
    };
    let minimize_error_code = markdown_inline_code(minimize_error);
    let validation_status_code = markdown_inline_code(&minimization.validation_status);
    let validation_verdict_code = markdown_inline_code(&minimization.validation_verdict);
    let minimized_signature = if minimization.validation_normalized_frame_hash.is_empty() {
        "-"
    } else {
        &minimization.validation_normalized_frame_hash
    };
    let minimized_signature_code = markdown_inline_code(minimized_signature);
    let validation_summary = if minimization.validation_summary.is_empty() {
        "-"
    } else {
        &minimization.validation_summary
    };
    let validation_summary_code = markdown_inline_code(validation_summary);
    let crash_summary = &triage_crash.crash_summary;
    let crash_summary_fence = markdown_fence(crash_summary);

    let report_md = format!(
        "# {report_title}\n\n## Summary\nA reproduced crash was observed while processing a {target_code} model input.\n\n- Target: {target_code}\n- Verdict: {verdict_code}\n- Crash kind: {crash_kind_code}\n- Sanitizer: {sanitizer_code}\n- Signal: {signal_code}\n- Normalized signature: {normalized_signature_code}\n- Source input: {input_code}\n- Evidence manifest: `manifest.json`\n\n## Steps to Reproduce\n1. Review `meta.json` for source triage metadata and input hashes.\n2. Use the collected PoC input when available: {poc_path_code}.\n3. Run: {repro_command_code}\n4. Compare `normalized_frame_hash` with `crash_report.txt` and the stack frames below.\n\n## Impact\nObserved crash signature and parser/runtime failure require manual impact confirmation. Treat this as a submission candidate, not an automatic exploitability conclusion.\n\n## Suggested Severity\n- Suggested severity: {severity_code}\n- Suggested CVSS vector: {cvss_code}\n- Confidence: {confidence_code}\n- Reason: {severity_reason_code}\n- Manual confirmation required: yes\n\n## Suggested Fix\nValidate parser assumptions around the crashing input path, add regression coverage for the PoC, and reject malformed model files before reaching the crashing code path.\n\n## PoC\n- Original input: {input_code}\n- Original sha256: {input_sha256_code}\n- Collected copy: {poc_path_code}\n- Collection status: {collection_status_code}\n\n## Minimization\n- Requested: {minimize_requested_code}\n- Minimized: {minimized_code}\n- Strategy: {minimize_strategy_code}\n- Minimized input: {minimized_input_code}\n- Original size: {original_size_code} bytes\n- Minimized size: {minimized_size_code} bytes\n- Size reduction ratio: {reduction_ratio_code}\n- Error: {minimize_error_code}\n- Validation status: {validation_status_code}\n- Validation verdict: {validation_verdict_code}\n- Minimized normalized signature: {minimized_signature_code}\n- Validation summary: {validation_summary_code}\n- Report generation blocked by minimization failure: no\n\n## Exploit Scenario\nA crafted model file reaches the {target_code} parsing path and triggers the reproduced crash condition.\n\n## Crash Summary\n{crash_summary_fence}text\n{crash_summary}\n{crash_summary_fence}\n\n## Stack Top3\n{stack_text}\n"
    );
    let report_md_path = report_dir.join("report.md");
    fs::write(&report_md_path, report_md)
        .map_err(|e| format!("failed to write '{}': {e}", report_md_path.display()))?;

    let submission_draft = build_submission_draft(
        &target,
        &input,
        &input_sha256,
        &repro_input,
        repro_retries,
        timeout_sec,
        &triage_crash,
        &stack_lines,
        &crash_report,
        &poc,
        &severity,
    );
    let submission_draft_path = report_dir.join("submission_draft.md");
    fs::write(&submission_draft_path, submission_draft)
        .map_err(|e| format!("failed to write '{}': {e}", submission_draft_path.display()))?;

    let manifest_path = write_report_manifest(
        &report_dir,
        report_id,
        triage_id,
        &target,
        &verdict,
        &poc,
        &minimization,
    )?;
    let bundle_path = write_evidence_zip(&report_dir, report_id, &poc, &minimization)?;

    println!("[report] done");
    println!("source_triage: {}", triage_dir.display());
    println!("report_dir: {}", report_dir.display());
    println!("report: {}", report_md_path.display());
    println!(
        "evidence: {}, {}, {}, {}, {}",
        crash_report_path.display(),
        repro_path.display(),
        meta_path.display(),
        submission_draft_path.display(),
        manifest_path.display()
    );
    println!("bundle: {}", bundle_path.display());
    if poc.collected {
        println!("poc: {}", poc.path);
    } else if !poc.error.is_empty() {
        println!("poc: {}", poc.error);
    }
    println!(
        "retention: compressed_logs={}, deleted_dirs={}, skipped_log_compress={}",
        retention.compressed_logs, retention.deleted_dirs, retention.skipped_log_compress
    );
    Ok(())
}

fn find_latest_triage_summary(data_dir: &Path) -> Result<(u128, PathBuf, PathBuf), String> {
    let triage_root = artifact_contract_for_data_dir(data_dir).triage_root;
    if !triage_root.exists() {
        return Err(format!(
            "triage directory not found: {}",
            triage_root.display()
        ));
    }

    let mut selected: Option<(u128, PathBuf, PathBuf)> = None;
    for entry in fs::read_dir(&triage_root)
        .map_err(|e| format!("failed to read '{}': {e}", triage_root.display()))?
    {
        let entry = entry.map_err(|e| format!("failed to read triage entry: {e}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(id_text) = name.strip_prefix("triage-") else {
            continue;
        };
        let Ok(id) = id_text.parse::<u128>() else {
            continue;
        };
        let summary = path.join("summary.json");
        if !summary.exists() {
            continue;
        }
        match &selected {
            Some((best, _, _)) if id <= *best => {}
            _ => selected = Some((id, path.clone(), summary)),
        }
    }

    selected.ok_or_else(|| "no triage summary found under data/triage".to_string())
}

fn build_crash_report(triage_dir: &Path, summary: &str) -> String {
    let mut lines = Vec::new();
    lines.push("== summary.json excerpt ==".to_string());
    lines.extend(excerpt_lines(summary, 50, 50));
    lines.push(String::new());
    let attempt1 = triage_dir.join("attempt-1.log");
    if let Ok(log) = fs::read_to_string(&attempt1) {
        lines.push("== attempt-1.log excerpt ==".to_string());
        lines.extend(excerpt_lines(&log, 50, 50));
    } else {
        lines.push("attempt-1.log not found".to_string());
    }
    lines.join("\n") + "\n"
}

struct TriageCrashFields {
    crash_kind: String,
    sanitizer: String,
    signal: String,
    normalized_frame_hash: String,
    signature_basis: String,
    crash_summary: String,
}

struct TriageDeepFields {
    version: String,
    status: String,
    grouping_confidence: String,
    grouping_reason: String,
    evidence_quality: String,
}

fn extract_triage_crash_fields(summary: &str) -> TriageCrashFields {
    TriageCrashFields {
        crash_kind: extract_json_string_literal(summary, "crash_kind")
            .unwrap_or_else(|| "unknown".to_string()),
        sanitizer: extract_json_string_literal(summary, "sanitizer")
            .unwrap_or_else(|| "unknown".to_string()),
        signal: extract_json_string_literal(summary, "signal")
            .unwrap_or_else(|| "unknown".to_string()),
        normalized_frame_hash: extract_json_string_literal(summary, "normalized_frame_hash")
            .unwrap_or_else(|| "legacy_signature_top3".to_string()),
        signature_basis: extract_json_string_literal(summary, "signature_basis")
            .unwrap_or_else(|| "signature_top3".to_string()),
        crash_summary: extract_json_string_literal(summary, "crash_summary")
            .unwrap_or_else(|| "not_available".to_string()),
    }
}

fn extract_triage_deep_fields(summary: &str) -> TriageDeepFields {
    TriageDeepFields {
        version: extract_json_string_literal(summary, "version")
            .unwrap_or_else(|| "not_available".to_string()),
        status: extract_json_string_literal(summary, "status")
            .unwrap_or_else(|| "not_available".to_string()),
        grouping_confidence: extract_json_string_literal(summary, "grouping_confidence")
            .unwrap_or_else(|| "not_available".to_string()),
        grouping_reason: extract_json_string_literal(summary, "grouping_reason")
            .unwrap_or_else(|| "not_available".to_string()),
        evidence_quality: extract_json_string_literal(summary, "evidence_quality")
            .unwrap_or_else(|| "not_available".to_string()),
    }
}

fn build_report_title(
    target: &str,
    stack_lines: &[String],
    triage_crash: &TriageCrashFields,
) -> String {
    if triage_crash.crash_kind != "unknown" && triage_crash.crash_kind != "none" {
        return format!(
            "{target} reproduced crash candidate: {}",
            triage_crash.crash_kind
        );
    }
    let signature = stack_lines
        .iter()
        .find(|s| s.as_str() != "(no signature)")
        .map(|s| s.as_str())
        .unwrap_or("reproduced crash");
    format!("{target} reproduced crash candidate: {signature}")
}

fn build_submission_draft(
    target: &str,
    input: &str,
    input_sha256: &str,
    repro_input: &str,
    repro_retries: u64,
    timeout_sec: u64,
    triage_crash: &TriageCrashFields,
    stack_lines: &[String],
    crash_report: &str,
    poc: &PocCollection,
    severity: &SeveritySuggestion,
) -> String {
    let title = build_submission_title(target, triage_crash);
    let crash = crash_label(triage_crash);
    let poc_path = poc_path_or_dash(poc);
    let poc_sha = poc_sha_or_fallback(poc, input_sha256);
    let stack_text = markdown_list(stack_lines);
    let crash_evidence = crash_report_excerpt(crash_report);
    let evidence_fence = markdown_fence(&crash_evidence);
    let repro_input_escaped = shell_escape_single_quoted(repro_input);
    let repro_fence = markdown_fence(&repro_input_escaped);
    let crash_kind = &triage_crash.crash_kind;
    let sanitizer = &triage_crash.sanitizer;
    let signal = &triage_crash.signal;
    let normalized_signature = &triage_crash.normalized_frame_hash;
    let suggested_severity = severity.suggested_severity;
    let suggested_cvss_vector = severity.suggested_cvss_vector;
    let severity_confidence = severity.confidence;
    let severity_reason = severity.reason;
    format!(
        "# Submission Draft\n\n## Target\n\n`{target}`\n\n## Title\n\n{title}\n\n## External PoC URL\n\nPASTE_PUBLIC_OR_PRIVATE_POC_URL_HERE\n\n## Summary\n\nA crafted `{target}` input triggers a reproduced native `{crash}` while being processed by the target loader/parser/runtime path.\n\nThis is a target-neutral draft. Fill target-specific API calls, package versions, validation behavior, and impact details before submission.\n\n## Affected Input\n\n- Target: `{target}`\n- Source input: `{input}`\n- Source SHA256: `{input_sha256}`\n- Collected PoC: `{poc_path}`\n- Collected PoC SHA256: `{poc_sha}`\n\n## Environment\n\nFill these with the exact environment used for the final reproduction:\n\n- OS/architecture: `uname -a`\n- Target/library version: `FILL_ME`\n- Build or package source: `FILL_ME`\n- Sanitizer/debug build: `FILL_ME`\n\n## Validation Notes\n\nRecord target-specific validation results here. Do not claim format-valid, checker-valid, sandbox impact, or exploitability status until directly verified on the final PoC.\n\n- Parser/checker result: `FILL_ME`\n- Loader/runtime result: `FILL_ME`\n- Inference/execution result, if applicable: `FILL_ME`\n\n## Reproduction Steps\n\n1. Use the collected PoC when available: `{poc_path}`.\n2. Run project triage:\n\n{repro_fence}bash\ntool triage --target {target} --input '{repro_input_escaped}' --repro-retries {repro_retries} --timeout-sec {timeout_sec}\n{repro_fence}\n\n3. Add the minimal target-specific loader/parser command here:\n\n```bash\n# FILL_ME: target-specific reproduction command\n```\n\n## Expected Result\n\nThe loader/parser/runtime should reject malformed input with a managed error and should not terminate the host process.\n\n## Actual Result\n\n- Verdict: `reproduced`\n- Crash kind: `{crash_kind}`\n- Sanitizer: `{sanitizer}`\n- Signal: `{signal}`\n- Normalized signature: `{normalized_signature}`\n\n## Security Impact\n\nThis is a denial-of-service candidate for systems that process untrusted `{target}` files. Manual impact confirmation is required before submission. No arbitrary code execution is claimed in this draft.\n\n## Suggested Severity\n\n- Suggested severity: `{suggested_severity}`\n- Suggested CVSS vector: `{suggested_cvss_vector}`\n- Confidence: `{severity_confidence}`\n- Reason: `{severity_reason}`\n\n## Crash Evidence\n\n{evidence_fence}text\n{crash_evidence}\n{evidence_fence}\n\n## Stack Top3\n\n{stack_text}\n\n## Submission Checklist\n\n- Replace the PoC URL placeholder.\n- Fill exact target/library versions and OS details.\n- Add a minimal target-specific reproduction command.\n- Confirm validation behavior on the final PoC.\n- Keep claims limited to the reproduced crash path and observed impact.\n"
    )
}

fn build_submission_title(target: &str, triage_crash: &TriageCrashFields) -> String {
    let crash = crash_label(triage_crash);
    format!("{target} input triggers {crash} during loader/parser/runtime processing")
}

fn crash_label(triage_crash: &TriageCrashFields) -> &str {
    if !triage_crash.signal.is_empty()
        && triage_crash.signal != "unknown"
        && triage_crash.signal != "none"
    {
        &triage_crash.signal
    } else if !triage_crash.crash_kind.is_empty()
        && triage_crash.crash_kind != "unknown"
        && triage_crash.crash_kind != "none"
    {
        &triage_crash.crash_kind
    } else {
        "native crash"
    }
}

fn poc_path_or_dash(poc: &PocCollection) -> &str {
    if poc.collected && !poc.path.is_empty() {
        &poc.path
    } else {
        "-"
    }
}

fn poc_sha_or_fallback<'a>(poc: &'a PocCollection, fallback: &'a str) -> &'a str {
    if poc.collected && !poc.sha256.is_empty() {
        &poc.sha256
    } else {
        fallback
    }
}

fn markdown_list(lines: &[String]) -> String {
    if lines.is_empty() {
        return "- not_available".to_string();
    }
    lines
        .iter()
        .map(|line| format!("- {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A fence long enough to hold `content` in one block.
///
/// A20: crash evidence is raw bytes from the library under test. A line inside it
/// that contains three backticks closed the block early, so everything after it
/// rendered as markdown on whatever platform the operator pasted the draft into -
/// an attacker-steered submission report. Markdown allows a longer fence, so the
/// evidence is preserved byte for byte instead of being mangled.
fn markdown_fence(content: &str) -> String {
    "`".repeat(longest_backtick_run(content).saturating_add(1).max(3))
}

/// Wrap one value in a Markdown code span that its own backticks cannot close.
///
/// Ordinary values keep the existing one-backtick rendering. Only a value that
/// contains backticks gets a longer delimiter, so this is an escaping fix rather
/// than a report-format change.
fn markdown_inline_code(content: &str) -> String {
    let fence = "`".repeat(longest_backtick_run(content).saturating_add(1));
    if content.starts_with(['`', ' ']) || content.ends_with(['`', ' ']) {
        format!("{fence} {content} {fence}")
    } else {
        format!("{fence}{content}{fence}")
    }
}

fn longest_backtick_run(content: &str) -> usize {
    let mut longest = 0usize;
    let mut run = 0usize;
    for c in content.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    longest
}

fn crash_report_excerpt(crash_report: &str) -> String {
    excerpt_lines(crash_report, 25, 25).join("\n")
}

struct SeveritySuggestion {
    suggested_severity: &'static str,
    suggested_cvss_vector: &'static str,
    confidence: &'static str,
    reason: &'static str,
}

fn suggest_report_severity(
    crash_report: &str,
    stack_lines: &[String],
    triage_crash: &TriageCrashFields,
) -> SeveritySuggestion {
    let evidence = format!(
        "{}\n{}\n{}\n{}\n{}",
        crash_report,
        stack_lines.join("\n"),
        triage_crash.crash_kind,
        triage_crash.sanitizer,
        triage_crash.signal
    )
    .to_ascii_lowercase();

    if evidence.contains("heap-buffer-overflow") {
        return SeveritySuggestion {
            suggested_severity: "high_candidate",
            suggested_cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
            confidence: "medium",
            reason: "AddressSanitizer heap-buffer-overflow pattern observed",
        };
    }
    if evidence.contains("stack-buffer-overflow") {
        return SeveritySuggestion {
            suggested_severity: "high_candidate",
            suggested_cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
            confidence: "medium",
            reason: "AddressSanitizer stack-buffer-overflow pattern observed",
        };
    }
    if evidence.contains("use-after-free") {
        return SeveritySuggestion {
            suggested_severity: "high_candidate",
            suggested_cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
            confidence: "medium",
            reason: "use-after-free pattern observed",
        };
    }
    if evidence.contains("null dereference") || evidence.contains("null-dereference") {
        return SeveritySuggestion {
            suggested_severity: "medium_candidate",
            suggested_cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
            confidence: "low",
            reason: "null dereference pattern observed",
        };
    }
    if has_timeout_or_oom_signal(&evidence, triage_crash) {
        return SeveritySuggestion {
            suggested_severity: "dos_candidate",
            suggested_cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
            confidence: "low",
            reason: "timeout/OOM/hang pattern observed",
        };
    }
    if evidence.contains("sigsegv")
        || evidence.contains("segmentation fault")
        || evidence.contains("signal: 11")
        || evidence.contains("sigabrt")
        || evidence.contains("abort")
        || evidence.contains("panic")
    {
        return SeveritySuggestion {
            suggested_severity: "medium_candidate",
            suggested_cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
            confidence: "low",
            reason: "crash signal or panic pattern observed",
        };
    }

    SeveritySuggestion {
        suggested_severity: "manual_review",
        suggested_cvss_vector: "not_suggested",
        confidence: "low",
        reason: "no mapped sanitizer, signal, timeout, or OOM pattern observed",
    }
}

fn has_timeout_or_oom_signal(evidence: &str, triage_crash: &TriageCrashFields) -> bool {
    matches!(triage_crash.crash_kind.as_str(), "timeout" | "infra_oom")
        || evidence.contains("\"verdict\": \"timeout\"")
        || evidence.contains("\"result\": \"timeout\"")
        || evidence.contains("\"timeout\": true")
        || evidence.contains("\"infra_oom\": true")
        || evidence.contains("infra_oom")
        || evidence.contains("out of memory")
        || evidence.contains("timed out")
        || evidence.contains("hang")
}

fn write_report_manifest(
    report_dir: &Path,
    report_id: u128,
    triage_id: u128,
    target: &str,
    verdict: &str,
    poc: &PocCollection,
    minimization: &MinimizationResult,
) -> Result<PathBuf, String> {
    let mut relative_paths = vec![
        "report.md".to_string(),
        "submission_draft.md".to_string(),
        "repro.sh".to_string(),
        "meta.json".to_string(),
        "crash_report.txt".to_string(),
    ];
    if let Some(path) = relative_report_path(report_dir, &poc.path) {
        relative_paths.push(path);
    }
    if let Some(path) = relative_report_path(report_dir, &minimization.input_path) {
        relative_paths.push(path);
    }

    let mut file_entries = Vec::new();
    for relative_path in relative_paths {
        let path = report_dir.join(&relative_path);
        let metadata = fs::metadata(&path)
            .map_err(|e| format!("failed to stat report artifact '{}': {e}", path.display()))?;
        let sha256 = sha256_file(&path)
            .map_err(|e| format!("failed to hash report artifact '{}': {e}", path.display()))?;
        file_entries.push(format!(
            "    {{\"path\":\"{}\",\"sha256\":\"{}\",\"size_bytes\":{}}}",
            json_escape(&relative_path),
            json_escape(&sha256),
            metadata.len()
        ));
    }

    let manifest = format!(
        "{{\n  \"schema_version\": \"1.0\",\n  \"bundle_type\": \"report_evidence\",\n  \"report_id\": \"{}\",\n  \"source_triage_id\": \"{}\",\n  \"target\": \"{}\",\n  \"verdict\": \"{}\",\n  \"generated_at\": {},\n  \"hash_algorithm\": \"sha256\",\n  \"manifest_path\": \"manifest.json\",\n  \"manifest_self_hash\": \"not_self_hashed\",\n  \"files\": [\n{}\n  ]\n}}\n",
        report_id,
        triage_id,
        json_escape(target),
        json_escape(verdict),
        now_unix_millis(),
        file_entries.join(",\n")
    );
    let manifest_path = report_dir.join("manifest.json");
    fs::write(&manifest_path, manifest)
        .map_err(|e| format!("failed to write '{}': {e}", manifest_path.display()))?;
    Ok(manifest_path)
}

fn write_evidence_zip(
    report_dir: &Path,
    report_id: u128,
    poc: &PocCollection,
    minimization: &MinimizationResult,
) -> Result<PathBuf, String> {
    let mut relative_paths = vec![
        "report.md".to_string(),
        "submission_draft.md".to_string(),
        "repro.sh".to_string(),
        "meta.json".to_string(),
        "crash_report.txt".to_string(),
        "manifest.json".to_string(),
    ];
    if let Some(path) = relative_report_path(report_dir, &poc.path) {
        relative_paths.push(path);
    }
    if let Some(path) = relative_report_path(report_dir, &minimization.input_path) {
        relative_paths.push(path);
    }

    let bundle_path = report_dir.join(format!("report-{report_id}-evidence.zip"));
    write_store_zip(&bundle_path, report_dir, &relative_paths)?;
    Ok(bundle_path)
}

fn write_store_zip(zip_path: &Path, root: &Path, relative_paths: &[String]) -> Result<(), String> {
    let mut out = File::create(zip_path).map_err(|e| {
        format!(
            "failed to create evidence zip '{}': {e}",
            zip_path.display()
        )
    })?;
    let mut central_entries = Vec::new();
    let mut offset = 0u64;

    for relative_path in relative_paths {
        let input_path = root.join(relative_path);
        let data = fs::read(&input_path)
            .map_err(|e| format!("failed to read zip input '{}': {e}", input_path.display()))?;
        let name = relative_path.replace('\\', "/");
        let name_bytes = name.as_bytes();
        let size = checked_zip_u32(data.len() as u64, "file size")?;
        let name_len = checked_zip_u16(name_bytes.len(), "file name length")?;
        let crc = crc32(&data);
        let local_offset = checked_zip_u32(offset, "local header offset")?;

        write_u32_le(&mut out, 0x0403_4b50)?;
        write_u16_le(&mut out, 20)?;
        write_u16_le(&mut out, 0)?;
        write_u16_le(&mut out, 0)?;
        write_u16_le(&mut out, 0)?;
        write_u16_le(&mut out, 33)?;
        write_u32_le(&mut out, crc)?;
        write_u32_le(&mut out, size)?;
        write_u32_le(&mut out, size)?;
        write_u16_le(&mut out, name_len)?;
        write_u16_le(&mut out, 0)?;
        out.write_all(name_bytes)
            .map_err(|e| format!("failed to write zip file name: {e}"))?;
        out.write_all(&data)
            .map_err(|e| format!("failed to write zip file data: {e}"))?;

        offset += 30 + name_bytes.len() as u64 + data.len() as u64;
        central_entries.push(ZipCentralEntry {
            name,
            crc,
            size,
            local_offset,
        });
    }

    let central_dir_offset = offset;
    for entry in &central_entries {
        let name_bytes = entry.name.as_bytes();
        let name_len = checked_zip_u16(name_bytes.len(), "central file name length")?;

        write_u32_le(&mut out, 0x0201_4b50)?;
        write_u16_le(&mut out, 20)?;
        write_u16_le(&mut out, 20)?;
        write_u16_le(&mut out, 0)?;
        write_u16_le(&mut out, 0)?;
        write_u16_le(&mut out, 0)?;
        write_u16_le(&mut out, 33)?;
        write_u32_le(&mut out, entry.crc)?;
        write_u32_le(&mut out, entry.size)?;
        write_u32_le(&mut out, entry.size)?;
        write_u16_le(&mut out, name_len)?;
        write_u16_le(&mut out, 0)?;
        write_u16_le(&mut out, 0)?;
        write_u16_le(&mut out, 0)?;
        write_u16_le(&mut out, 0)?;
        write_u32_le(&mut out, 0)?;
        write_u32_le(&mut out, entry.local_offset)?;
        out.write_all(name_bytes)
            .map_err(|e| format!("failed to write central zip file name: {e}"))?;

        offset += 46 + name_bytes.len() as u64;
    }

    let central_dir_size = checked_zip_u32(offset - central_dir_offset, "central directory size")?;
    let central_dir_offset = checked_zip_u32(central_dir_offset, "central directory offset")?;
    let entry_count = checked_zip_u16(central_entries.len(), "zip entry count")?;

    write_u32_le(&mut out, 0x0605_4b50)?;
    write_u16_le(&mut out, 0)?;
    write_u16_le(&mut out, 0)?;
    write_u16_le(&mut out, entry_count)?;
    write_u16_le(&mut out, entry_count)?;
    write_u32_le(&mut out, central_dir_size)?;
    write_u32_le(&mut out, central_dir_offset)?;
    write_u16_le(&mut out, 0)?;
    Ok(())
}

struct ZipCentralEntry {
    name: String,
    crc: u32,
    size: u32,
    local_offset: u32,
}

fn write_u16_le(out: &mut File, value: u16) -> Result<(), String> {
    out.write_all(&value.to_le_bytes())
        .map_err(|e| format!("failed to write zip u16: {e}"))
}

fn write_u32_le(out: &mut File, value: u32) -> Result<(), String> {
    out.write_all(&value.to_le_bytes())
        .map_err(|e| format!("failed to write zip u32: {e}"))
}

fn checked_zip_u16(value: usize, label: &str) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| format!("{label} exceeds ZIP32 limit: {value}"))
}

fn checked_zip_u32(value: u64, label: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{label} exceeds ZIP32 limit: {value}"))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn relative_report_path(report_dir: &Path, path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let path = Path::new(path);
    let relative = path.strip_prefix(report_dir).ok()?;
    Some(relative.display().to_string().replace('\\', "/"))
}

fn excerpt_lines(text: &str, head: usize, tail: usize) -> Vec<String> {
    let lines = text.lines().map(|s| s.to_string()).collect::<Vec<_>>();
    if lines.len() <= head + tail {
        return lines;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&lines[..head]);
    out.push(format!(
        "... ({} lines omitted) ...",
        lines.len() - head - tail
    ));
    out.extend_from_slice(&lines[lines.len() - tail..]);
    out
}

fn shell_escape_single_quoted(input: &str) -> String {
    input.replace('\'', "'\"'\"'")
}

fn shell_quote_arg(input: &str) -> String {
    format!("'{}'", shell_escape_single_quoted(input))
}

struct PocCollection {
    collected: bool,
    path: String,
    sha256: String,
    size_bytes: u64,
    error: String,
}

impl PocCollection {
    fn repro_input_or(&self, default_input: &str) -> String {
        if self.collected && !self.path.is_empty() {
            self.path.clone()
        } else {
            default_input.to_string()
        }
    }
}

struct MinimizationResult {
    requested: bool,
    minimized: bool,
    strategy: String,
    input_path: String,
    sha256: String,
    size_bytes: u64,
    original_sha256: String,
    original_size_bytes: u64,
    size_reduction_ratio: f64,
    error: String,
    validation_status: String,
    validation_verdict: String,
    validation_summary: String,
    validation_normalized_frame_hash: String,
}

fn collect_minimization_artifact(
    report_dir: &Path,
    triage_id: u128,
    target: &str,
    poc: &PocCollection,
    requested: bool,
) -> MinimizationResult {
    if !requested {
        return MinimizationResult {
            requested: false,
            minimized: false,
            strategy: "not_requested".to_string(),
            input_path: String::new(),
            sha256: String::new(),
            size_bytes: 0,
            original_sha256: poc.sha256.clone(),
            original_size_bytes: poc.size_bytes,
            size_reduction_ratio: 0.0,
            error: String::new(),
            validation_status: "not_checked".to_string(),
            validation_verdict: "not_checked".to_string(),
            validation_summary: "minimization not requested".to_string(),
            validation_normalized_frame_hash: String::new(),
        };
    }

    if !poc.collected || poc.path.is_empty() {
        return MinimizationResult {
            requested: true,
            minimized: false,
            strategy: "copy_baseline".to_string(),
            input_path: String::new(),
            sha256: String::new(),
            size_bytes: 0,
            original_sha256: poc.sha256.clone(),
            original_size_bytes: poc.size_bytes,
            size_reduction_ratio: 0.0,
            error: "poc_not_collected".to_string(),
            validation_status: "skipped".to_string(),
            validation_verdict: "no_candidate_manual_review".to_string(),
            validation_summary: "PoC was not collected; no minimized candidate to validate"
                .to_string(),
            validation_normalized_frame_hash: String::new(),
        };
    }

    if let Ok(template) = std::env::var("TOOL_MINIMIZER_CMD") {
        if !template.trim().is_empty() {
            return run_external_minimizer(report_dir, triage_id, target, poc, &template);
        }
    }

    collect_baseline_minimization_artifact(report_dir, triage_id, target, poc)
}

fn collect_baseline_minimization_artifact(
    report_dir: &Path,
    triage_id: u128,
    target: &str,
    poc: &PocCollection,
) -> MinimizationResult {
    let poc_path = Path::new(&poc.path);
    let ext = poc_path
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let hash12 = short_hash12(&poc.sha256);
    let target_safe = sanitize_filename_component(target);
    let filename = format!("minimized-{target_safe}-triage-{triage_id}-{hash12}{ext}");
    let dst = report_dir.join("poc").join(filename);

    if let Err(e) = fs::copy(poc_path, &dst) {
        return MinimizationResult {
            requested: true,
            minimized: false,
            strategy: "copy_baseline".to_string(),
            input_path: String::new(),
            sha256: String::new(),
            size_bytes: 0,
            original_sha256: poc.sha256.clone(),
            original_size_bytes: poc.size_bytes,
            size_reduction_ratio: 0.0,
            error: format!("baseline_copy_failed:{e}"),
            validation_status: "skipped".to_string(),
            validation_verdict: "no_candidate_manual_review".to_string(),
            validation_summary: "baseline copy failed; no minimized candidate to validate"
                .to_string(),
            validation_normalized_frame_hash: String::new(),
        };
    }

    let size_bytes = fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
    let sha256 = sha256_file(&dst).unwrap_or_else(|_| "unavailable".to_string());
    MinimizationResult {
        requested: true,
        minimized: false,
        strategy: "copy_baseline".to_string(),
        input_path: dst.display().to_string(),
        sha256,
        size_bytes,
        original_sha256: poc.sha256.clone(),
        original_size_bytes: poc.size_bytes,
        size_reduction_ratio: calculate_size_reduction_ratio(poc.size_bytes, size_bytes),
        error: String::new(),
        validation_status: "not_checked".to_string(),
        validation_verdict: "not_checked".to_string(),
        validation_summary: "validation command not configured".to_string(),
        validation_normalized_frame_hash: String::new(),
    }
}

fn calculate_size_reduction_ratio(original_size: u64, minimized_size: u64) -> f64 {
    if original_size == 0 || minimized_size == 0 || minimized_size >= original_size {
        0.0
    } else {
        (original_size - minimized_size) as f64 / original_size as f64
    }
}

fn run_external_minimizer(
    report_dir: &Path,
    triage_id: u128,
    target: &str,
    poc: &PocCollection,
    template: &str,
) -> MinimizationResult {
    let output_path = minimization_output_path(report_dir, triage_id, target, poc);
    let command = render_minimizer_command(template, &poc.path, &output_path, target, triage_id);
    let timeout_sec = std::env::var("TOOL_MINIMIZER_TIMEOUT_SEC")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(60);
    let timeout_available = command_exists("timeout");

    let output = if timeout_available {
        let mut cmd = command_with_core_dump_off("timeout");
        cmd.arg(format!("{}s", timeout_sec))
            .arg("bash")
            .arg("-lc")
            .arg(&command)
            .output()
    } else {
        Command::new("bash").arg("-lc").arg(&command).output()
    };

    match output {
        Ok(out) if out.status.success() && output_path.is_file() => {
            build_external_minimization_result(poc, output_path, true, String::new())
        }
        Ok(out) => {
            let error = external_minimizer_error(&out, timeout_available, timeout_sec);
            if output_path.is_file() {
                build_external_minimization_result(poc, output_path, false, error)
            } else {
                MinimizationResult {
                    requested: true,
                    minimized: false,
                    strategy: "external_command".to_string(),
                    input_path: String::new(),
                    sha256: String::new(),
                    size_bytes: 0,
                    original_sha256: poc.sha256.clone(),
                    original_size_bytes: poc.size_bytes,
                    size_reduction_ratio: 0.0,
                    error,
                    validation_status: "skipped".to_string(),
                    validation_verdict: "no_candidate_manual_review".to_string(),
                    validation_summary: "external minimizer did not produce a candidate"
                        .to_string(),
                    validation_normalized_frame_hash: String::new(),
                }
            }
        }
        Err(e) => MinimizationResult {
            requested: true,
            minimized: false,
            strategy: "external_command".to_string(),
            input_path: String::new(),
            sha256: String::new(),
            size_bytes: 0,
            original_sha256: poc.sha256.clone(),
            original_size_bytes: poc.size_bytes,
            size_reduction_ratio: 0.0,
            error: format!("external_command_spawn_failed:{e}"),
            validation_status: "skipped".to_string(),
            validation_verdict: "no_candidate_manual_review".to_string(),
            validation_summary: "external minimizer did not produce a candidate".to_string(),
            validation_normalized_frame_hash: String::new(),
        },
    }
}

fn minimization_output_path(
    report_dir: &Path,
    triage_id: u128,
    target: &str,
    poc: &PocCollection,
) -> PathBuf {
    let poc_path = Path::new(&poc.path);
    let ext = poc_path
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let hash12 = short_hash12(&poc.sha256);
    let target_safe = sanitize_filename_component(target);
    report_dir.join("poc").join(format!(
        "minimized-{target_safe}-triage-{triage_id}-{hash12}{ext}"
    ))
}

fn render_minimizer_command(
    template: &str,
    input_path: &str,
    output_path: &Path,
    target: &str,
    triage_id: u128,
) -> String {
    template
        .replace("{input}", &shell_quote_arg(input_path))
        .replace(
            "{output}",
            &shell_quote_arg(&output_path.display().to_string()),
        )
        .replace("{target}", &shell_quote_arg(target))
        .replace("{triage_id}", &triage_id.to_string())
}

fn build_external_minimization_result(
    poc: &PocCollection,
    output_path: PathBuf,
    command_success: bool,
    error: String,
) -> MinimizationResult {
    let size_bytes = fs::metadata(&output_path).map(|m| m.len()).unwrap_or(0);
    let sha256 = sha256_file(&output_path).unwrap_or_else(|_| "unavailable".to_string());
    let size_reduction_ratio = calculate_size_reduction_ratio(poc.size_bytes, size_bytes);
    let minimized = command_success && size_bytes > 0 && size_bytes < poc.size_bytes;
    MinimizationResult {
        requested: true,
        minimized,
        strategy: "external_command".to_string(),
        input_path: output_path.display().to_string(),
        sha256,
        size_bytes,
        original_sha256: poc.sha256.clone(),
        original_size_bytes: poc.size_bytes,
        size_reduction_ratio,
        error,
        validation_status: "not_checked".to_string(),
        validation_verdict: "not_checked".to_string(),
        validation_summary: "validation command not configured".to_string(),
        validation_normalized_frame_hash: String::new(),
    }
}

fn external_minimizer_error(
    output: &std::process::Output,
    timeout_available: bool,
    timeout_sec: u64,
) -> String {
    if timeout_available && output.status.code() == Some(124) {
        return format!("external_command_timeout:{timeout_sec}s");
    }
    let code = output
        .status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    if detail.is_empty() {
        format!("external_command_failed:exit_code={code}")
    } else {
        format!(
            "external_command_failed:exit_code={code}:{}",
            single_line_excerpt(detail, 240)
        )
    }
}

fn single_line_excerpt(input: &str, max_len: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.len() <= max_len {
        compact
    } else {
        // Truncate at the largest char boundary <= max_len so multibyte subprocess
        // output (accents/CJK/emoji) cannot panic on a mid-character byte slice.
        let mut end = max_len;
        while end > 0 && !compact.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &compact[..end])
    }
}

fn apply_minimization_validation(
    minimization: &mut MinimizationResult,
    triage_id: u128,
    target: &str,
    poc: &PocCollection,
    expected_normalized_frame_hash: &str,
) {
    if !minimization.requested {
        return;
    }
    if minimization.input_path.is_empty() {
        minimization.validation_status = "skipped".to_string();
        minimization.validation_verdict = "no_candidate_manual_review".to_string();
        if minimization.validation_summary.is_empty()
            || minimization.validation_summary == "validation command not configured"
        {
            minimization.validation_summary =
                "no minimized candidate path available for validation".to_string();
        }
        return;
    }

    let Ok(template) = std::env::var("TOOL_MINIMIZER_VALIDATE_CMD") else {
        return;
    };
    if template.trim().is_empty() {
        return;
    }

    let candidate_path = Path::new(&minimization.input_path);
    if !candidate_path.is_file() {
        minimization.validation_status = "skipped".to_string();
        minimization.validation_verdict = "no_candidate_manual_review".to_string();
        minimization.validation_summary =
            "minimized candidate path does not exist for validation".to_string();
        return;
    }

    let command = render_minimizer_validation_command(
        &template,
        &minimization.input_path,
        &poc.path,
        target,
        triage_id,
    );
    let timeout_sec = std::env::var("TOOL_MINIMIZER_VALIDATE_TIMEOUT_SEC")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(60);
    let timeout_available = command_exists("timeout");

    let output = if timeout_available {
        let mut cmd = command_with_core_dump_off("timeout");
        cmd.arg(format!("{}s", timeout_sec))
            .arg("bash")
            .arg("-lc")
            .arg(&command)
            .output()
    } else {
        Command::new("bash").arg("-lc").arg(&command).output()
    };

    match output {
        Ok(out) if out.status.success() => {
            let evidence = validation_output_text(&out);
            let candidate_hash = extract_validation_normalized_frame_hash(&evidence);
            let candidate_verdict = extract_validation_verdict(&evidence);
            minimization.validation_status = "checked".to_string();
            minimization.validation_normalized_frame_hash = candidate_hash.clone();
            minimization.validation_verdict = classify_minimization_validation(
                expected_normalized_frame_hash,
                &candidate_hash,
                &candidate_verdict,
            );
            minimization.validation_summary = build_minimization_validation_summary(
                expected_normalized_frame_hash,
                &candidate_hash,
                &candidate_verdict,
            );
        }
        Ok(out) => {
            minimization.validation_status = "failed".to_string();
            minimization.validation_verdict = "validation_failed_manual_review".to_string();
            minimization.validation_summary =
                external_validation_error(&out, timeout_available, timeout_sec);
        }
        Err(e) => {
            minimization.validation_status = "failed".to_string();
            minimization.validation_verdict = "validation_failed_manual_review".to_string();
            minimization.validation_summary = format!("validation_command_spawn_failed:{e}");
        }
    }
}

fn render_minimizer_validation_command(
    template: &str,
    input_path: &str,
    original_input_path: &str,
    target: &str,
    triage_id: u128,
) -> String {
    template
        .replace("{input}", &shell_quote_arg(input_path))
        .replace("{original_input}", &shell_quote_arg(original_input_path))
        .replace("{target}", &shell_quote_arg(target))
        .replace("{triage_id}", &triage_id.to_string())
}

fn validation_output_text(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("{stdout}\n{stderr}")
}

fn extract_validation_normalized_frame_hash(output: &str) -> String {
    extract_json_string_literal(output, "normalized_frame_hash")
        .or_else(|| extract_prefixed_value(output, "normalized_frame_hash"))
        .unwrap_or_default()
}

fn extract_validation_verdict(output: &str) -> String {
    extract_json_string_literal(output, "verdict")
        .or_else(|| extract_prefixed_value(output, "verdict"))
        .unwrap_or_default()
}

fn extract_prefixed_value(output: &str, key: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix(&format!("{key}:")) {
            return Some(value.trim().to_string());
        }
        if let Some(value) = trimmed.strip_prefix(&format!("{key}=")) {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn classify_minimization_validation(
    expected_hash: &str,
    candidate_hash: &str,
    candidate_verdict: &str,
) -> String {
    if !candidate_verdict.is_empty() && candidate_verdict != "reproduced" {
        return "not_reproduced_manual_review".to_string();
    }
    if expected_hash.is_empty() {
        return "missing_original_signature_manual_review".to_string();
    }
    if candidate_hash.is_empty() {
        return "missing_candidate_signature_manual_review".to_string();
    }
    if candidate_hash == expected_hash {
        "same_signature_candidate".to_string()
    } else {
        "different_signature_manual_review".to_string()
    }
}

fn build_minimization_validation_summary(
    expected_hash: &str,
    candidate_hash: &str,
    candidate_verdict: &str,
) -> String {
    let verdict = if candidate_verdict.is_empty() {
        "not_reported"
    } else {
        candidate_verdict
    };
    let candidate = if candidate_hash.is_empty() {
        "not_reported"
    } else {
        candidate_hash
    };
    format!(
        "manual confirmation required; original_hash={}; candidate_hash={}; candidate_verdict={}",
        if expected_hash.is_empty() {
            "not_reported"
        } else {
            expected_hash
        },
        candidate,
        verdict
    )
}

fn external_validation_error(
    output: &std::process::Output,
    timeout_available: bool,
    timeout_sec: u64,
) -> String {
    if timeout_available && output.status.code() == Some(124) {
        return format!("validation_command_timeout:{timeout_sec}s");
    }
    let code = output
        .status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string());
    let detail = validation_output_text(output);
    let detail = detail.trim();
    if detail.is_empty() {
        format!("validation_command_failed:exit_code={code}")
    } else {
        format!(
            "validation_command_failed:exit_code={code}:{}",
            single_line_excerpt(detail, 240)
        )
    }
}

fn collect_report_poc(
    report_dir: &Path,
    triage_id: u128,
    target: &str,
    input: &str,
    input_sha256: &str,
    verdict: &str,
) -> PocCollection {
    if verdict != "reproduced" {
        return PocCollection {
            collected: false,
            path: String::new(),
            sha256: String::new(),
            size_bytes: 0,
            error: "skipped_non_reproduced".to_string(),
        };
    }

    let input_path = Path::new(input);
    if !input_path.exists() || !input_path.is_file() {
        return PocCollection {
            collected: false,
            path: String::new(),
            sha256: String::new(),
            size_bytes: 0,
            error: "source_input_not_found".to_string(),
        };
    }

    let ext = input_path
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let hash12 = short_hash12(input_sha256);
    let target_safe = sanitize_filename_component(target);
    let filename = format!("poc-{target_safe}-triage-{triage_id}-{hash12}{ext}");
    let poc_dir = report_dir.join("poc");
    if let Err(e) = fs::create_dir_all(&poc_dir) {
        return PocCollection {
            collected: false,
            path: String::new(),
            sha256: String::new(),
            size_bytes: 0,
            error: format!("poc_dir_create_failed:{e}"),
        };
    }

    let dst = poc_dir.join(filename);
    if let Err(e) = fs::copy(input_path, &dst) {
        return PocCollection {
            collected: false,
            path: String::new(),
            sha256: String::new(),
            size_bytes: 0,
            error: format!("poc_copy_failed:{e}"),
        };
    }

    let size_bytes = fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
    let poc_sha256 = sha256_file(&dst).unwrap_or_else(|_| "unavailable".to_string());
    PocCollection {
        collected: true,
        path: dst.display().to_string(),
        sha256: poc_sha256,
        size_bytes,
        error: String::new(),
    }
}

fn short_hash12(input_sha256: &str) -> String {
    let hex = input_sha256
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>();
    if hex.len() >= 12 {
        hex[..12].to_string()
    } else if !hex.is_empty() {
        hex
    } else {
        "unknownhash".to_string()
    }
}

fn sanitize_filename_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "target".to_string()
    } else {
        trimmed.to_string()
    }
}

fn record_manual_review(
    app_paths: &AppPaths,
    triage_id: u128,
    target: &str,
    input: &str,
    verdict: &str,
    summary_path: &Path,
) -> Result<(), String> {
    let review_dir = app_paths.data_dir.join("manual_review");
    fs::create_dir_all(&review_dir).map_err(|e| {
        format!(
            "failed to create manual_review dir '{}': {e}",
            review_dir.display()
        )
    })?;
    let review_path = review_dir.join(format!("triage-{triage_id}.json"));
    let body = format!(
        "{{\n  \"schema_version\": \"1.0\",\n  \"triage_id\": \"{}\",\n  \"target\": \"{}\",\n  \"input\": \"{}\",\n  \"verdict\": \"{}\",\n  \"summary_path\": \"{}\",\n  \"queued_at\": {}\n}}\n",
        triage_id,
        json_escape(target),
        json_escape(input),
        json_escape(verdict),
        json_escape(&summary_path.display().to_string()),
        now_unix_millis()
    );
    fs::write(&review_path, body).map_err(|e| {
        format!(
            "failed to write manual review '{}': {e}",
            review_path.display()
        )
    })?;
    println!("[manual_review] queued: {}", review_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    // R15 / A20 stage 2: report.md repeats attacker-influenced values inside
    // one-backtick spans and leaves crash evidence / stack frames in raw Markdown.
    // A backtick from an input path or parser message can therefore close the span
    // or fence and turn the rest into active report markup.
    #[test]
    fn report_markdown_keeps_attacker_backticks_inside_code_boundaries() {
        let root = std::env::temp_dir().join(format!(
            "tool-r15-report-markdown-{}-{}",
            std::process::id(),
            crate::common::now_unix_millis()
        ));
        let data = root.join("data");
        let seeds = root.join("seeds");
        let app_paths = crate::common::AppPaths::prepare(&data, &seeds).expect("prepare paths");
        let input = root.join("input`close-span.gguf");
        std::fs::write(&input, b"GGUF test input").expect("write input");

        let triage_dir = data.join("triage").join("triage-1700000000999");
        std::fs::create_dir_all(&triage_dir).expect("create triage dir");
        let crash_summary = "parser said ```\n# attacker heading";
        let stack_frame = "frame` # attacker list item";
        let summary = format!(
            "{{\n  \"target\": \"gguf\",\n  \"input\": \"{}\",\n  \"verdict\": \"reproduced\",\n  \"repro_retries\": 3,\n  \"timeout_sec\": 60,\n  \"signature_top3\":[\"{}\"],\n  \"crash_kind\": \"signal\",\n  \"sanitizer\": \"none\",\n  \"signal\": \"SIGSEGV\",\n  \"normalized_frame_hash\": \"abc123\",\n  \"signature_basis\": \"normalized_frame_hash\",\n  \"crash_summary\": \"{}\"\n}}\n",
            crate::json_utils::json_escape(&input.display().to_string()),
            crate::json_utils::json_escape(stack_frame),
            crate::json_utils::json_escape(crash_summary),
        );
        std::fs::write(triage_dir.join("summary.json"), summary).expect("write summary");
        std::fs::write(
            triage_dir.join("attempt-1.log"),
            "parser evidence ```\n# attacker evidence heading\n",
        )
        .expect("write attempt log");

        super::run_report_pipeline(&app_paths, false).expect("generate report");
        let report_dir = std::fs::read_dir(data.join("reports"))
            .expect("read reports")
            .map(|entry| entry.expect("report entry").path())
            .find(|path| path.is_dir())
            .expect("report directory");
        let report = std::fs::read_to_string(report_dir.join("report.md")).expect("read report");
        let expected_source = format!("- Source input: ``{}``", input.display());
        let expected_crash =
            "## Crash Summary\n````text\nparser said ```\n# attacker heading\n````";
        let expected_stack = "- ``frame` # attacker list item``";
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            report.contains(&expected_source),
            "input path escaped its inline-code boundary:\n{report}"
        );
        assert!(
            report.contains(expected_crash),
            "crash summary escaped its fenced block:\n{report}"
        );
        assert!(
            report.contains(expected_stack),
            "stack frame escaped its inline-code boundary:\n{report}"
        );
    }

    // A20: crash evidence is raw output from the library under test. A closing
    // fence inside it used to end the code block early, so the rest of the draft
    // rendered as markdown wherever the operator pasted it.
    #[test]
    fn crash_evidence_stays_inside_its_own_fence() {
        use super::markdown_fence;

        let evidence = "boom\n```\n# attacker heading\n";
        let fence = markdown_fence(evidence);
        assert!(
            fence.len() > 3,
            "a fence of {} backticks cannot hold evidence containing three",
            fence.len()
        );
        assert!(!evidence.contains(&fence), "the evidence can still close the block");
    }

    #[test]
    fn ordinary_evidence_keeps_the_usual_three_backtick_fence() {
        use super::markdown_fence;

        assert_eq!(super::markdown_fence("plain crash output"), "```");
        assert_eq!(markdown_fence("one ` backtick"), "```");
    }

    #[test]
    fn inline_code_keeps_ordinary_rendering_and_separates_edge_backticks() {
        use super::markdown_inline_code;

        assert_eq!(markdown_inline_code("gguf"), "`gguf`");
        assert_eq!(markdown_inline_code("left`right"), "``left`right``");
        assert_eq!(markdown_inline_code("`edge`"), "`` `edge` ``");
    }

    use super::{
        build_submission_draft, extract_triage_crash_fields, extract_triage_deep_fields,
        single_line_excerpt, PocCollection, SeveritySuggestion,
    };

    #[test]
    fn single_line_excerpt_truncates_multibyte_on_char_boundary_without_panicking() {
        // A7 regression: byte max_len can land inside a multibyte char (subprocess
        // error text with accents/CJK/emoji). Slicing at a raw byte index panics and
        // aborts the whole report run, losing evidence for a real crash.
        let input = "é".repeat(200); // each 'é' is 2 bytes; odd byte indices are mid-char
        let out = single_line_excerpt(&input, 5);
        let body = out
            .strip_suffix("...")
            .expect("over-long input must be truncated with an ellipsis");
        assert!(body.len() <= 5, "truncated body {} bytes exceeds max", body.len());
        assert!(body.chars().all(|c| c == 'é'), "body must contain only whole chars: {body}");
    }

    #[test]
    fn triage_crash_fields_read_top_level_values_with_deep_triage_present() {
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
    "evidence_quality": "baseline_complete"
  }
}
"#;

        let fields = extract_triage_crash_fields(summary);

        assert_eq!(fields.crash_kind, "heap-buffer-overflow");
        assert_eq!(fields.sanitizer, "asan");
        assert_eq!(fields.signal, "SIGSEGV");
        assert_eq!(fields.normalized_frame_hash, "abc123def456");
        assert_eq!(fields.signature_basis, "normalized_frame_hash");
        assert_eq!(
            fields.crash_summary,
            "AddressSanitizer: heap-buffer-overflow"
        );
    }

    #[test]
    fn triage_deep_fields_are_preserved_when_present() {
        let summary = r#"{
  "schema_version": "1.1",
  "verdict": "reproduced",
  "deep_triage": {
    "version": "1.0",
    "status": "completed",
    "grouping_confidence": "medium",
    "grouping_reason": "multiple crashed attempts share grouping signals, but reproduction is partial",
    "evidence_quality": "partial"
  }
}
"#;

        let fields = extract_triage_deep_fields(summary);

        assert_eq!(fields.version, "1.0");
        assert_eq!(fields.status, "completed");
        assert_eq!(fields.grouping_confidence, "medium");
        assert_eq!(
            fields.grouping_reason,
            "multiple crashed attempts share grouping signals, but reproduction is partial"
        );
        assert_eq!(fields.evidence_quality, "partial");
    }

    #[test]
    fn triage_deep_fields_fallback_when_absent() {
        let summary = r#"{
  "schema_version": "1.1",
  "verdict": "reproduced",
  "attempts": []
}
"#;

        let fields = extract_triage_deep_fields(summary);

        assert_eq!(fields.version, "not_available");
        assert_eq!(fields.status, "not_available");
        assert_eq!(fields.grouping_confidence, "not_available");
        assert_eq!(fields.grouping_reason, "not_available");
        assert_eq!(fields.evidence_quality, "not_available");
    }

    #[test]
    fn submission_draft_contains_target_neutral_sections() {
        let summary = r#"{
  "target": "gguf",
  "crash_kind": "signal",
  "sanitizer": "none",
  "signal": "SIGSEGV",
  "normalized_frame_hash": "abc123def456",
  "signature_basis": "normalized_frame_hash",
  "crash_summary": "loader terminated by SIGSEGV"
}
"#;
        let triage_crash = extract_triage_crash_fields(summary);
        let poc = PocCollection {
            collected: true,
            path: "data/reports/report-1/poc/crash.gguf".to_string(),
            sha256: "61d1c65cde3c8ba65433229f23704f5163708f001664c5a5cced5e28cc202ac8".to_string(),
            size_bytes: 123,
            error: String::new(),
        };
        let severity = SeveritySuggestion {
            suggested_severity: "dos_candidate",
            suggested_cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
            confidence: "low",
            reason: "signal crash observed",
        };

        let draft = build_submission_draft(
            "gguf",
            "data/crashes/crash.gguf",
            "inputsha",
            "data/reports/report-1/poc/crash.gguf",
            3,
            60,
            &triage_crash,
            &["target_loader_frame".to_string()],
            "Thread received signal SIGSEGV\n",
            &poc,
            &severity,
        );

        assert!(draft.contains("# Submission Draft"));
        assert!(draft.contains("`gguf`"));
        assert!(draft.contains("PASTE_PUBLIC_OR_PRIVATE_POC_URL_HERE"));
        assert!(draft.contains("## Validation Notes"));
        assert!(draft.contains("Do not claim format-valid"));
        assert!(draft.contains("tool triage --target gguf"));
        assert!(draft.contains("target-specific reproduction command"));
        assert!(draft.contains("No arbitrary code execution is claimed"));
        assert!(draft.contains("crash.gguf"));
        assert!(draft.contains("SIGSEGV"));
    }
}
