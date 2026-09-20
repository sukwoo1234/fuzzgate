use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use crate::common::{command_exists, command_with_core_dump_off, AppPaths};

pub(crate) struct RetentionStats {
    pub(crate) compressed_logs: usize,
    pub(crate) deleted_dirs: usize,
    pub(crate) skipped_log_compress: usize,
}

pub(crate) fn apply_retention_policy(
    app_paths: &AppPaths,
    retention_days: u64,
) -> Result<RetentionStats, String> {
    let cutoff_secs = retention_days
        .checked_mul(24 * 60 * 60)
        .ok_or_else(|| "retention days overflow".to_string())?;
    let now = SystemTime::now();
    let mut stats = RetentionStats {
        compressed_logs: 0,
        deleted_dirs: 0,
        skipped_log_compress: 0,
    };

    let logs = collect_log_files(&app_paths.data_dir)?;
    let has_zstd = command_exists("zstd");
    for log in logs {
        if !is_older_than(&log, now, cutoff_secs)? {
            continue;
        }
        if !has_zstd {
            stats.skipped_log_compress += 1;
            continue;
        }
        let status = command_with_core_dump_off("zstd")
            .args(["-q", "-f", "--rm", &log.display().to_string()])
            .status()
            .map_err(|e| format!("failed to execute zstd for '{}': {e}", log.display()))?;
        if status.success() {
            stats.compressed_logs += 1;
        }
    }

    for (base, prefix) in [
        ("runs", "run-"),
        ("triage", "triage-"),
        ("reports", "report-"),
    ] {
        let root = app_paths.data_dir.join(base);
        if !root.exists() {
            continue;
        }
        for entry in
            fs::read_dir(&root).map_err(|e| format!("failed to read '{}': {e}", root.display()))?
        {
            let entry =
                entry.map_err(|e| format!("failed to read entry in '{}': {e}", root.display()))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with(prefix) {
                continue;
            }
            if is_older_than(&path, now, cutoff_secs)? {
                fs::remove_dir_all(&path)
                    .map_err(|e| format!("failed to remove old dir '{}': {e}", path.display()))?;
                stats.deleted_dirs += 1;
            }
        }
    }

    Ok(stats)
}

fn collect_log_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    collect_log_files_recursive(root, &mut out)?;
    Ok(out)
}

fn collect_log_files_recursive(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        fs::read_dir(root).map_err(|e| format!("failed to read '{}': {e}", root.display()))?
    {
        let entry =
            entry.map_err(|e| format!("failed to read entry in '{}': {e}", root.display()))?;
        let path = entry.path();
        // C1 contract: skip symlinked subtrees so HDD-mounted
        // corpus/mutated (and any other symlink) is not walked into.
        // `entry.file_type()` uses lstat and does not follow.
        let file_type = entry
            .file_type()
            .map_err(|e| format!("failed to stat entry '{}': {e}", path.display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_log_files_recursive(&path, out)?;
            continue;
        }
        if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("log"))
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
    Ok(())
}

fn is_older_than(path: &Path, now: SystemTime, age_secs: u64) -> Result<bool, String> {
    let modified = fs::metadata(path)
        .and_then(|m| m.modified())
        .map_err(|e| format!("failed to read mtime '{}': {e}", path.display()))?;
    let elapsed = now
        .duration_since(modified)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    Ok(elapsed > age_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{now_unix_millis, AppPaths};
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
        format!("c1_{label}_{process_id}_{timestamp_ms}_{sequence}")
    }

    #[test]
    fn tmp_data_dir_name_separates_processes_and_calls_at_the_same_millisecond() {
        let first = tmp_data_dir_name("retention_audit", 101, 5_000, 0);
        let same_process = tmp_data_dir_name("retention_audit", 101, 5_000, 1);
        let other_process = tmp_data_dir_name("retention_audit", 102, 5_000, 0);

        assert_ne!(first, same_process);
        assert_ne!(first, other_process);
    }

    // Corpus Lifecycle C1 audit fixture: `data/corpus/mutated/` must never
    // be scanned by `apply_retention_policy`. The function iterates only
    // [("runs", "run-"), ("triage", "triage-"), ("reports", "report-")].
    // This is the load-bearing invariant for step 6 (1-week fuzzing safety).
    #[test]
    fn retention_does_not_touch_corpus_mutated() {
        let data = unique_tmp_data_dir("retention_audit");
        let seeds = data.join("seeds");
        fs::create_dir_all(&seeds).expect("create seeds dir");

        let corpus_file = data
            .join("corpus")
            .join("mutated")
            .join("onnx")
            .join("batch-x")
            .join("file.txt");
        fs::create_dir_all(corpus_file.parent().unwrap()).expect("create corpus dir");
        fs::write(&corpus_file, b"audit fixture").expect("write corpus fixture");

        let paths = AppPaths {
            data_dir: data.clone(),
            seeds_dir: seeds,
        };

        let stats = apply_retention_policy(&paths, 0)
            .expect("apply_retention_policy should succeed even with cutoff 0");

        assert_eq!(
            stats.deleted_dirs, 0,
            "no runs/triage/reports present, nothing to delete"
        );
        assert!(
            corpus_file.exists(),
            "data/corpus/mutated/ must not be in retention scope (C1 audit contract)"
        );

        let _ = fs::remove_dir_all(&data);
    }

    // 6단계(퍼징컴 1주 fuzzing) audit: SSD 250GB 한계로
    // `data/corpus/mutated/`는 HDD 1TB symlink. log compression
    // scope(`data/` 전체 재귀 walk)에 mutated가 끼면 C1 contract 위반.
    // collect_log_files_recursive는 entry.file_type().is_symlink()로
    // symlinked dir을 skip해서 HDD-mounted mutated 보호.
    //
    // 본 fixture는 mutated symlink target 안에 `.log` 파일(mtime
    // UNIX_EPOCH로 충분히 옛날)을 두고 retention 호출 후
    // `compressed_logs + skipped_log_compress == 0`인지 확인한다.
    // > 0 이면 symlink follow가 다시 일어났다 = C1 leak 회귀.
    #[cfg(unix)]
    #[test]
    fn retention_does_not_traverse_corpus_mutated_symlink() {
        use std::os::unix::fs::symlink;

        let data = unique_tmp_data_dir("retention_symlink_audit");
        let seeds = data.join("seeds");
        fs::create_dir_all(&seeds).expect("create seeds dir");

        let hdd_target = unique_tmp_data_dir("hdd_mutated_target");
        let hdd_corpus_file = hdd_target.join("onnx").join("batch-x").join("file.bin");
        fs::create_dir_all(hdd_corpus_file.parent().unwrap()).expect("create hdd corpus dir");
        fs::write(&hdd_corpus_file, b"mutated input on hdd").expect("write corpus file");
        let hdd_log_file = hdd_target.join("stray.log");
        fs::write(&hdd_log_file, b"stray log on hdd").expect("write stray log");
        // log mtime을 명시적으로 옛날로 설정. 그래야 `is_older_than(cutoff
        // 0)`이 elapsed > 0를 통과해 실제 compression 경로가 노출된다.
        // mtime 조작 없이는 fresh file이라 mtime check에서 걸러져 audit
        // 동작을 검증하지 못한다.
        let log_handle = fs::OpenOptions::new()
            .write(true)
            .open(&hdd_log_file)
            .expect("open log for mtime");
        log_handle
            .set_modified(SystemTime::UNIX_EPOCH)
            .expect("set old mtime on log");
        drop(log_handle);

        fs::create_dir_all(data.join("corpus")).expect("create corpus parent");
        symlink(&hdd_target, data.join("corpus").join("mutated"))
            .expect("create mutated symlink");

        let paths = AppPaths {
            data_dir: data.clone(),
            seeds_dir: seeds,
        };

        let stats = apply_retention_policy(&paths, 0)
            .expect("apply_retention_policy should succeed even with cutoff 0");

        assert!(
            hdd_corpus_file.exists(),
            "HDD-symlinked mutated corpus file must survive (C1 + symlink contract)"
        );
        assert!(
            hdd_log_file.exists(),
            "HDD-symlinked .log file under mutated must survive (no symlink traversal into C1 scope)"
        );
        assert_eq!(
            stats.compressed_logs + stats.skipped_log_compress,
            0,
            "collect_log_files must NOT traverse corpus/mutated symlink (found {} compressed + {} skipped)",
            stats.compressed_logs,
            stats.skipped_log_compress
        );

        let _ = fs::remove_dir_all(&data);
        let _ = fs::remove_dir_all(&hdd_target);
    }
}
