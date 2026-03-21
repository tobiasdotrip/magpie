pub mod allowlist;
pub mod engine;
pub mod entropy;
pub mod models;
pub mod output;
pub mod rules;
pub mod scanner;
pub mod scoring;
pub mod state;
pub mod nest;
pub mod watch;

use git2::{Oid, Repository};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub fn resolve_root(repo_path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let repo = Repository::open(repo_path)?;
    repo.workdir()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "bare repository not supported".into())
}

pub fn run_watch(repo_path: &Path) -> Result<models::ScanResult, Box<dyn std::error::Error>> {
    let root = resolve_root(repo_path)?;
    let rules = rules::load_rules(&root)?;
    let lines = watch::scan_staged(&root)?;

    let files_scanned = lines.iter().map(|l| &l.file_path).collect::<HashSet<_>>().len();
    let findings = engine::scan_all(&lines, &rules);
    let al = allowlist::load(&root);
    let findings = al.filter(findings);

    Ok(models::ScanResult {
        findings,
        commits_scanned: 0,
        files_scanned,
        mode: models::ScanMode::Watch,
    })
}

pub fn run_scan(
    repo_path: &Path,
    force_full: bool,
) -> Result<(models::ScanResult, Oid, PathBuf), Box<dyn std::error::Error>> {
    let root = resolve_root(repo_path)?;

    let since = if force_full {
        None
    } else {
        state::read(&root)
    };

    let mode = if since.is_some() {
        models::ScanMode::Incremental
    } else {
        models::ScanMode::Full
    };

    let rules = rules::load_rules(&root)?;
    let (lines, head_oid) = scanner::walk_diffs(&root, since)?;

    let commits_scanned = lines.iter().map(|l| &l.commit_sha).collect::<HashSet<_>>().len();
    let files_scanned = lines.iter().map(|l| &l.file_path).collect::<HashSet<_>>().len();

    let findings = engine::scan_all(&lines, &rules);
    let al = allowlist::load(&root);
    let findings = al.filter(findings);

    Ok((
        models::ScanResult {
            findings,
            commits_scanned,
            files_scanned,
            mode,
        },
        head_oid,
        root,
    ))
}
