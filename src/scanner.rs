use git2::{DiffOptions, Oid, Repository};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DiffLine {
    pub content: String,
    pub file_path: String,
    pub commit_sha: String,
    pub line_number: usize,
}

pub fn walk_diffs(
    repo_path: &Path,
    since: Option<Oid>,
) -> Result<(Vec<DiffLine>, Oid), Box<dyn std::error::Error>> {
    let repo = Repository::open(repo_path)?;
    let head_oid = repo.head()?.target().ok_or("HEAD has no target")?;
    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(git2::Sort::REVERSE)?;

    if let Some(oid) = since {
        if repo.find_commit(oid).is_ok() {
            revwalk.hide(oid)?;
        } else {
            eprintln!(
                "warning: stored commit {} not found in history, falling back to full scan",
                oid
            );
        }
    }

    let mut lines = Vec::new();

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let commit_sha = oid.to_string()[..7].to_string();
        let tree = commit.tree()?;

        let parent_tree = if commit.parent_count() > 0 {
            Some(commit.parent(0)?.tree()?)
        } else {
            None
        };

        let mut diff_opts = DiffOptions::new();
        let diff =
            repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut diff_opts))?;

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
                                commit_sha: commit_sha.clone(),
                                line_number: line.new_lineno().unwrap_or(0) as usize,
                            });
                        }
                    }
                }
                true
            }),
        )?;
    }

    Ok((lines, head_oid))
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

    fn create_test_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        let path = dir.path();

        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test"]);

        std::fs::write(path.join("secret.env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        run_git(path, &["add", "."]);
        run_git(path, &["commit", "-m", "add secret"]);

        std::fs::write(path.join("clean.txt"), "nothing here\n").unwrap();
        run_git(path, &["add", "."]);
        run_git(path, &["commit", "-m", "add clean file"]);

        dir
    }

    #[test]
    fn walks_all_commits_and_yields_added_lines() {
        let dir = create_test_repo();
        let (lines, _) = walk_diffs(dir.path(), None).unwrap();

        assert!(!lines.is_empty());
        assert!(lines
            .iter()
            .any(|l| l.content.contains("AKIAIOSFODNN7EXAMPLE")));
        assert!(lines.iter().any(|l| l.file_path == "secret.env"));
    }

    #[test]
    fn includes_commit_metadata() {
        let dir = create_test_repo();
        let (lines, _) = walk_diffs(dir.path(), None).unwrap();

        for line in &lines {
            assert!(!line.commit_sha.is_empty());
            assert!(line.line_number > 0);
        }
    }

    #[test]
    fn incremental_scan_skips_old_commits() {
        let dir = TempDir::new().unwrap();
        let path = dir.path();

        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test"]);

        std::fs::write(path.join("old.txt"), "old content\n").unwrap();
        run_git(path, &["add", "."]);
        run_git(path, &["commit", "-m", "old commit"]);

        let repo = git2::Repository::open(path).unwrap();
        let old_head = repo.head().unwrap().target().unwrap();

        std::fs::write(path.join("new.txt"), "new content\n").unwrap();
        run_git(path, &["add", "."]);
        run_git(path, &["commit", "-m", "new commit"]);

        let (lines, head_oid) = walk_diffs(path, Some(old_head)).unwrap();

        assert!(lines.iter().any(|l| l.file_path == "new.txt"));
        assert!(!lines.iter().any(|l| l.file_path == "old.txt"));
        assert_ne!(head_oid, old_head);
    }

    #[test]
    fn full_scan_returns_head_oid() {
        let dir = create_test_repo();
        let (lines, head_oid) = walk_diffs(dir.path(), None).unwrap();
        assert!(!lines.is_empty());

        let repo = git2::Repository::open(dir.path()).unwrap();
        let expected_head = repo.head().unwrap().target().unwrap();
        assert_eq!(head_oid, expected_head);
    }

    #[test]
    fn invalid_since_oid_falls_back_to_full() {
        let dir = create_test_repo();
        let fake_oid = git2::Oid::from_str("0000000000000000000000000000000000000000").unwrap();
        let (lines, _) = walk_diffs(dir.path(), Some(fake_oid)).unwrap();
        assert!(lines
            .iter()
            .any(|l| l.content.contains("AKIAIOSFODNN7EXAMPLE")));
    }
}
