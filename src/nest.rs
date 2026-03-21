use rusqlite::Connection;
use std::path::Path;

use crate::models::{Confidence, ScanMode, ScanResult};

const DB_FILE: &str = ".magpie.db";

pub fn db_exists(repo_root: &Path) -> bool {
    repo_root.join(DB_FILE).exists()
}

pub fn init_db(repo_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(repo_root.join(DB_FILE))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            mode TEXT NOT NULL,
            head_sha TEXT,
            commits_scanned INTEGER NOT NULL,
            files_scanned INTEGER NOT NULL,
            findings_count INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            rule_id TEXT NOT NULL,
            description TEXT NOT NULL,
            matched_text TEXT NOT NULL,
            file_path TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            line_number INTEGER NOT NULL,
            confidence TEXT NOT NULL
        );"
    )?;
    Ok(())
}

fn timestamp_now() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string()
}

pub fn persist(
    repo_root: &Path,
    result: &ScanResult,
    head_sha: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !db_exists(repo_root) {
        return Ok(());
    }

    let conn = Connection::open(repo_root.join(DB_FILE))?;

    let mode = match result.mode {
        ScanMode::Full => "full",
        ScanMode::Incremental => "incremental",
        ScanMode::Watch => "watch",
    };
    let now = timestamp_now();

    conn.execute(
        "INSERT INTO scans (mode, head_sha, commits_scanned, files_scanned, findings_count, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            mode,
            head_sha,
            result.commits_scanned as i64,
            result.files_scanned as i64,
            result.findings.len() as i64,
            now,
        ],
    )?;
    let scan_id = conn.last_insert_rowid();

    for finding in &result.findings {
        let confidence = match finding.confidence {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        };
        conn.execute(
            "INSERT INTO findings (scan_id, rule_id, description, matched_text, file_path, commit_sha, line_number, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                scan_id,
                finding.rule_id,
                finding.description,
                finding.matched_text,
                finding.file_path,
                finding.commit_sha,
                finding.line_number as i64,
                confidence,
            ],
        )?;
    }

    Ok(())
}

pub fn dashboard(repo_root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    if !db_exists(repo_root) {
        return Ok("No scans recorded yet. Run magpie scan to start tracking.\n".to_string());
    }
    let conn = Connection::open(repo_root.join(DB_FILE))?;

    let scan_count: i64 = conn.query_row("SELECT count(*) FROM scans", [], |r| r.get(0))?;

    if scan_count == 0 {
        return Ok("No scans recorded yet. Run magpie scan to start tracking.\n".to_string());
    }

    // Last scan info
    let (last_scan_id, mode, commits, files, _fcount, created_at): (i64, String, i64, i64, i64, String) = conn.query_row(
        "SELECT id, mode, commits_scanned, files_scanned, findings_count, created_at FROM scans ORDER BY id DESC LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;

    // Last scan breakdown
    let last_high: i64 = conn.query_row("SELECT count(*) FROM findings WHERE scan_id = ?1 AND confidence = 'high'", [last_scan_id], |r| r.get(0))?;
    let last_medium: i64 = conn.query_row("SELECT count(*) FROM findings WHERE scan_id = ?1 AND confidence = 'medium'", [last_scan_id], |r| r.get(0))?;
    let last_low: i64 = conn.query_row("SELECT count(*) FROM findings WHERE scan_id = ?1 AND confidence = 'low'", [last_scan_id], |r| r.get(0))?;
    let last_total = last_high + last_medium + last_low;

    // Global stats
    let total_findings: i64 = conn.query_row("SELECT count(*) FROM findings", [], |r| r.get(0))?;
    let global_high: i64 = conn.query_row("SELECT count(*) FROM findings WHERE confidence = 'high'", [], |r| r.get(0))?;
    let global_medium: i64 = conn.query_row("SELECT count(*) FROM findings WHERE confidence = 'medium'", [], |r| r.get(0))?;
    let global_low: i64 = conn.query_row("SELECT count(*) FROM findings WHERE confidence = 'low'", [], |r| r.get(0))?;

    // Top rules (global)
    let mut stmt = conn.prepare(
        "SELECT rule_id, count(*) as c FROM findings GROUP BY rule_id ORDER BY c DESC LIMIT 5"
    )?;
    let top_rules: Vec<(String, i64)> = stmt.query_map([], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })?.filter_map(|r| r.ok()).collect();

    let top_rules_str = top_rules
        .iter()
        .map(|(rule, count)| format!("{rule} ({count})"))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = String::new();
    out.push_str(&format!("Last scan: {created_at} ({mode}, {commits} commits, {files} files)\n"));
    out.push_str(&format!("  {last_total} findings: {last_high} high, {last_medium} medium, {last_low} low\n"));
    out.push_str(&format!("\nHistory: {scan_count} scans, {total_findings} total findings\n"));
    out.push_str(&format!("  By confidence: {global_high} high, {global_medium} medium, {global_low} low\n"));
    if !top_rules_str.is_empty() {
        out.push_str(&format!("  Top rules: {top_rules_str}\n"));
    }

    Ok(out)
}

pub fn reset(repo_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !db_exists(repo_root) {
        return Err("No nest database found.".into());
    }
    let conn = Connection::open(repo_root.join(DB_FILE))?;
    conn.execute_batch("DELETE FROM findings; DELETE FROM scans;")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Finding, ScanMode, ScanResult};
    use tempfile::TempDir;

    #[test]
    fn init_db_creates_tables() {
        let dir = TempDir::new().unwrap();
        init_db(dir.path()).unwrap();
        assert!(dir.path().join(".magpie.db").exists());

        let conn = Connection::open(dir.path().join(".magpie.db")).unwrap();
        let _: i64 = conn.query_row("SELECT count(*) FROM scans", [], |r| r.get(0)).unwrap();
        let _: i64 = conn.query_row("SELECT count(*) FROM findings", [], |r| r.get(0)).unwrap();
    }

    #[test]
    fn init_db_idempotent() {
        let dir = TempDir::new().unwrap();
        init_db(dir.path()).unwrap();
        init_db(dir.path()).unwrap();
    }

    #[test]
    fn db_exists_returns_false_when_absent() {
        let dir = TempDir::new().unwrap();
        assert!(!db_exists(dir.path()));
    }

    #[test]
    fn db_exists_returns_true_after_init() {
        let dir = TempDir::new().unwrap();
        init_db(dir.path()).unwrap();
        assert!(db_exists(dir.path()));
    }

    fn make_result(mode: ScanMode, findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            commits_scanned: 5,
            files_scanned: 3,
            findings,
            mode,
        }
    }

    fn make_finding(rule_id: &str, confidence: Confidence) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            description: "Test".to_string(),
            matched_text: "SECRET123".to_string(),
            file_path: "config.env".to_string(),
            commit_sha: "abc1234".to_string(),
            line_number: 1,
            confidence,
        }
    }

    #[test]
    fn persist_writes_scan_and_findings() {
        let dir = TempDir::new().unwrap();
        init_db(dir.path()).unwrap();

        let result = make_result(
            ScanMode::Full,
            vec![
                make_finding("aws-access-key-id", Confidence::High),
                make_finding("generic-secret", Confidence::Low),
            ],
        );
        persist(dir.path(), &result, Some("abc1234def5678")).unwrap();

        let conn = Connection::open(dir.path().join(".magpie.db")).unwrap();
        let scan_count: i64 = conn.query_row("SELECT count(*) FROM scans", [], |r| r.get(0)).unwrap();
        let finding_count: i64 = conn.query_row("SELECT count(*) FROM findings", [], |r| r.get(0)).unwrap();
        assert_eq!(scan_count, 1);
        assert_eq!(finding_count, 2);
    }

    #[test]
    fn persist_with_no_head_sha_for_watch() {
        let dir = TempDir::new().unwrap();
        init_db(dir.path()).unwrap();

        let result = make_result(ScanMode::Watch, vec![]);
        persist(dir.path(), &result, None).unwrap();

        let conn = Connection::open(dir.path().join(".magpie.db")).unwrap();
        let head: Option<String> = conn.query_row(
            "SELECT head_sha FROM scans WHERE id = 1", [], |r| r.get(0)
        ).unwrap();
        assert!(head.is_none());
    }

    #[test]
    fn persist_skips_if_no_db() {
        let dir = TempDir::new().unwrap();
        let result = make_result(ScanMode::Full, vec![]);
        persist(dir.path(), &result, Some("abc1234")).unwrap();
    }

    #[test]
    fn dashboard_no_scans() {
        let dir = TempDir::new().unwrap();
        init_db(dir.path()).unwrap();
        let output = dashboard(dir.path()).unwrap();
        assert!(output.contains("No scans recorded yet"));
    }

    #[test]
    fn dashboard_with_scans() {
        let dir = TempDir::new().unwrap();
        init_db(dir.path()).unwrap();

        let result = make_result(
            ScanMode::Full,
            vec![
                make_finding("aws-access-key-id", Confidence::High),
                make_finding("aws-access-key-id", Confidence::High),
                make_finding("generic-secret", Confidence::Medium),
            ],
        );
        persist(dir.path(), &result, Some("abc1234")).unwrap();

        let output = dashboard(dir.path()).unwrap();
        assert!(output.contains("Last scan:"));
        assert!(output.contains("full"));
        assert!(output.contains("3 findings: 2 high, 1 medium, 0 low"));
        assert!(output.contains("aws-access-key-id"));
    }

    #[test]
    fn dashboard_without_db_shows_no_scans() {
        let dir = TempDir::new().unwrap();
        let output = dashboard(dir.path()).unwrap();
        assert!(output.contains("No scans recorded yet"));
    }

    #[test]
    fn reset_clears_all_data() {
        let dir = TempDir::new().unwrap();
        init_db(dir.path()).unwrap();

        let result = make_result(ScanMode::Full, vec![make_finding("test", Confidence::High)]);
        persist(dir.path(), &result, Some("abc")).unwrap();

        reset(dir.path()).unwrap();

        let output = dashboard(dir.path()).unwrap();
        assert!(output.contains("No scans recorded yet"));
    }

    #[test]
    fn dashboard_does_not_expose_raw_secrets() {
        let dir = TempDir::new().unwrap();
        init_db(dir.path()).unwrap();

        let mut finding = make_finding("test", Confidence::High);
        finding.matched_text = "AKIAIOSFODNN7EXAMPLE".to_string();
        let result = make_result(ScanMode::Full, vec![finding]);
        persist(dir.path(), &result, Some("abc")).unwrap();

        let output = dashboard(dir.path()).unwrap();
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn reset_without_db_returns_error() {
        let dir = TempDir::new().unwrap();
        assert!(reset(dir.path()).is_err());
    }
}
