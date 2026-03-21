pub mod models;
pub mod entropy;
pub mod rules;
pub mod output;
pub mod scanner;
pub mod scoring;
pub mod engine;

use std::collections::HashSet;
use std::path::Path;

pub fn run_scan(repo_path: &Path) -> Result<models::ScanResult, Box<dyn std::error::Error>> {
    let rules = rules::load_builtin_rules()?;
    let lines = scanner::walk_diffs(repo_path)?;

    let commits_scanned = lines.iter().map(|l| &l.commit_sha).collect::<HashSet<_>>().len();
    let files_scanned = lines.iter().map(|l| &l.file_path).collect::<HashSet<_>>().len();
    let findings = engine::scan_all(&lines, &rules);

    Ok(models::ScanResult {
        findings,
        commits_scanned,
        files_scanned,
        mode: models::ScanMode::Full,
    })
}
