use crate::models::Finding;
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::Path;

const ALLOWLIST_FILE: &str = ".magpie-allow";

struct AllowEntry {
    rule_id: String,
    glob_index: usize,
    commit_sha: Option<String>,
}

pub struct Allowlist {
    entries: Vec<AllowEntry>,
    globs: GlobSet,
}

impl Allowlist {
    pub fn is_allowed(&self, finding: &Finding) -> bool {
        self.entries.iter().any(|entry| {
            entry.rule_id == finding.rule_id
                && self
                    .globs
                    .matches(&finding.file_path)
                    .contains(&entry.glob_index)
                && entry
                    .commit_sha
                    .as_deref()
                    .is_none_or(|sha| sha == finding.commit_sha)
        })
    }

    pub fn filter(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| !self.is_allowed(f))
            .collect()
    }
}

pub fn load(repo_path: &Path) -> Allowlist {
    let path = repo_path.join(ALLOWLIST_FILE);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            return Allowlist {
                entries: vec![],
                globs: GlobSet::empty(),
            };
        }
    };

    let mut builder = GlobSetBuilder::new();
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 2 || parts[0].is_empty() {
            eprintln!("warning: malformed allowlist entry: {line}");
            continue;
        }

        let rule_id = parts[0].to_string();
        let glob_pattern = parts[1];
        let commit_sha = parts.get(2).map(|s| s.to_string());

        match Glob::new(glob_pattern) {
            Ok(glob) => {
                let index = entries.len();
                builder.add(glob);
                entries.push(AllowEntry {
                    rule_id,
                    glob_index: index,
                    commit_sha,
                });
            }
            Err(e) => {
                eprintln!("warning: invalid glob pattern '{glob_pattern}': {e}");
            }
        }
    }

    let globs = builder.build().unwrap_or_else(|_| GlobSet::empty());
    Allowlist { entries, globs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Finding};
    use tempfile::TempDir;

    fn make_finding(rule_id: &str, file_path: &str, commit_sha: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            description: String::new(),
            matched_text: "secret".to_string(),
            file_path: file_path.to_string(),
            commit_sha: commit_sha.to_string(),
            line_number: 1,
            confidence: Confidence::High,
        }
    }

    #[test]
    fn no_allowlist_file_allows_nothing() {
        let dir = TempDir::new().unwrap();
        let al = load(dir.path());
        let finding = make_finding("aws-access-key-id", "config.env", "abc1234");
        assert!(!al.is_allowed(&finding));
    }

    #[test]
    fn rule_and_glob_match() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie-allow"),
            "aws-access-key-id:src/tests/**\n",
        )
        .unwrap();
        let al = load(dir.path());

        assert!(al.is_allowed(&make_finding(
            "aws-access-key-id",
            "src/tests/fixture.rs",
            "abc1234"
        )));
        assert!(!al.is_allowed(&make_finding("aws-access-key-id", "src/main.rs", "abc1234")));
        assert!(!al.is_allowed(&make_finding(
            "github-token",
            "src/tests/fixture.rs",
            "abc1234"
        )));
    }

    #[test]
    fn commit_pinned_entry() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie-allow"),
            "generic-secret:config.yml:abc1234\n",
        )
        .unwrap();
        let al = load(dir.path());

        assert!(al.is_allowed(&make_finding("generic-secret", "config.yml", "abc1234")));
        assert!(!al.is_allowed(&make_finding("generic-secret", "config.yml", "def5678")));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie-allow"),
            "# this is a comment\n\naws-access-key-id:tests/**\n",
        )
        .unwrap();
        let al = load(dir.path());
        assert!(al.is_allowed(&make_finding(
            "aws-access-key-id",
            "tests/foo.rs",
            "abc1234"
        )));
    }

    #[test]
    fn filter_removes_allowed_findings() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie-allow"),
            "aws-access-key-id:tests/**\n",
        )
        .unwrap();
        let al = load(dir.path());

        let findings = vec![
            make_finding("aws-access-key-id", "tests/fixture.rs", "abc1234"),
            make_finding("aws-access-key-id", "src/config.rs", "abc1234"),
            make_finding("github-token", "ci.yml", "def5678"),
        ];
        let filtered = al.filter(findings);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].file_path, "src/config.rs");
        assert_eq!(filtered[1].file_path, "ci.yml");
    }

    #[test]
    fn malformed_line_skipped() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie-allow"),
            "this-has-no-colon\naws-access-key-id:tests/**\n",
        )
        .unwrap();
        let al = load(dir.path());
        assert!(al.is_allowed(&make_finding(
            "aws-access-key-id",
            "tests/foo.rs",
            "abc1234"
        )));
    }

    #[test]
    fn empty_rule_id_skipped() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie-allow"),
            ":tests/**\naws-access-key-id:tests/**\n",
        )
        .unwrap();
        let al = load(dir.path());
        assert!(!al.is_allowed(&make_finding("", "tests/foo.rs", "abc1234")));
        assert!(al.is_allowed(&make_finding(
            "aws-access-key-id",
            "tests/foo.rs",
            "abc1234"
        )));
    }
}
