pub mod allowlist;
pub mod engine;
pub mod entropy;
pub mod models;
pub mod output;
pub mod rules;
pub mod scanner;
pub mod scoring;
pub mod state;

use git2::Oid;
use std::collections::HashSet;
use std::path::Path;

pub fn run_scan(
    repo_path: &Path,
    force_full: bool,
) -> Result<(models::ScanResult, Oid), Box<dyn std::error::Error>> {
    let since = if force_full {
        None
    } else {
        state::read(repo_path)
    };

    let mode = if since.is_some() {
        models::ScanMode::Incremental
    } else {
        models::ScanMode::Full
    };

    let rules = rules::load_builtin_rules()?;
    let (lines, head_oid) = scanner::walk_diffs(repo_path, since)?;

    let commits_scanned = lines.iter().map(|l| &l.commit_sha).collect::<HashSet<_>>().len();
    let files_scanned = lines.iter().map(|l| &l.file_path).collect::<HashSet<_>>().len();

    let findings = engine::scan_all(&lines, &rules);
    let al = allowlist::load(repo_path);
    let findings = al.filter(findings);

    Ok((
        models::ScanResult {
            findings,
            commits_scanned,
            files_scanned,
            mode,
        },
        head_oid,
    ))
}
