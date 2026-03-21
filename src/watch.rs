use git2::{DiffOptions, Repository};
use std::path::Path;

use crate::scanner::DiffLine;

pub fn scan_staged(repo_path: &Path) -> Result<Vec<DiffLine>, Box<dyn std::error::Error>> {
    let repo = Repository::open(repo_path)?;

    let head_tree = repo.head().ok().and_then(|h| h.peel_to_tree().ok());

    let mut diff_opts = DiffOptions::new();
    let diff = repo.diff_tree_to_index(head_tree.as_ref(), None, Some(&mut diff_opts))?;

    let mut lines = Vec::new();

    diff.foreach(
        &mut |_, _| true,
        None,
        None,
        Some(&mut |delta, _hunk, line| {
            if line.origin() == '+' {
                if let Some(path) = delta.new_file().path().and_then(|p| p.to_str()) {
                    if let Ok(content) = std::str::from_utf8(line.content()) {
                        lines.push(DiffLine {
                            content: content.trim_end().to_string(),
                            file_path: path.to_string(),
                            commit_sha: "staged".to_string(),
                            line_number: line.new_lineno().unwrap_or(0) as usize,
                        });
                    }
                }
            }
            true
        }),
    )?;

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn run_git(dir: &std::path::Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn create_repo_with_staged_secret() -> TempDir {
        let dir = TempDir::new().unwrap();
        let p = dir.path();

        run_git(p, &["init"]);
        run_git(p, &["config", "user.email", "test@test.com"]);
        run_git(p, &["config", "user.name", "Test"]);

        std::fs::write(p.join("readme.md"), "# test\n").unwrap();
        run_git(p, &["add", "."]);
        run_git(p, &["commit", "-m", "init"]);

        std::fs::write(p.join(".env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        run_git(p, &["add", ".env"]);

        dir
    }

    #[test]
    fn scan_staged_finds_added_lines() {
        let dir = create_repo_with_staged_secret();
        let lines = scan_staged(dir.path()).unwrap();

        assert!(!lines.is_empty());
        assert!(lines
            .iter()
            .any(|l| l.content.contains("AKIAIOSFODNN7EXAMPLE")));
        assert!(lines.iter().any(|l| l.file_path == ".env"));
    }

    #[test]
    fn scan_staged_sets_commit_sha_to_staged() {
        let dir = create_repo_with_staged_secret();
        let lines = scan_staged(dir.path()).unwrap();

        for line in &lines {
            assert_eq!(line.commit_sha, "staged");
        }
    }

    #[test]
    fn scan_staged_empty_returns_empty() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init"]);
        run_git(p, &["config", "user.email", "test@test.com"]);
        run_git(p, &["config", "user.name", "Test"]);
        std::fs::write(p.join("readme.md"), "# test\n").unwrap();
        run_git(p, &["add", "."]);
        run_git(p, &["commit", "-m", "init"]);
        let lines = scan_staged(p).unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn scan_staged_on_fresh_repo_no_head() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        run_git(p, &["init"]);
        run_git(p, &["config", "user.email", "test@test.com"]);
        run_git(p, &["config", "user.name", "Test"]);
        std::fs::write(
            p.join("secret.env"),
            "TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n",
        )
        .unwrap();
        run_git(p, &["add", "secret.env"]);

        let lines = scan_staged(p).unwrap();
        assert!(!lines.is_empty());
        assert!(lines.iter().any(|l| l.file_path == "secret.env"));
    }
}
