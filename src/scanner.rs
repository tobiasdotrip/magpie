use git2::{DiffOptions, Repository};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DiffLine {
    pub content: String,
    pub file_path: String,
    pub commit_sha: String,
    pub line_number: usize,
}

pub fn walk_diffs(repo_path: &Path) -> Result<Vec<DiffLine>, Box<dyn std::error::Error>> {
    let repo = Repository::open(repo_path)?;
    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(git2::Sort::REVERSE)?;

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
        let diff = repo.diff_tree_to_tree(
            parent_tree.as_ref(),
            Some(&tree),
            Some(&mut diff_opts),
        )?;

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
        let lines: Vec<DiffLine> = walk_diffs(dir.path()).unwrap();

        assert!(!lines.is_empty());
        assert!(lines.iter().any(|l| l.content.contains("AKIAIOSFODNN7EXAMPLE")));
        assert!(lines.iter().any(|l| l.file_path == "secret.env"));
    }

    #[test]
    fn includes_commit_metadata() {
        let dir = create_test_repo();
        let lines: Vec<DiffLine> = walk_diffs(dir.path()).unwrap();

        for line in &lines {
            assert!(!line.commit_sha.is_empty());
            assert!(line.line_number > 0);
        }
    }
}
