use rusqlite::Connection;
use std::path::Path;

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
