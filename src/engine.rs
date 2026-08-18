use crate::models::Finding;
use crate::rules::CompiledRule;
use crate::scanner::DiffLine;
use crate::scoring::score_finding;

pub fn scan_line(line: &DiffLine, rules: &[CompiledRule]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in rules {
        for caps in rule.regex.captures_iter(&line.content) {
            let full_match = caps.get(0).unwrap().as_str();
            let scoring_text = caps.get(1).map(|m| m.as_str()).unwrap_or(full_match);

            let finding = Finding {
                rule_id: rule.definition.id.clone(),
                description: rule.definition.description.clone(),
                matched_text: full_match.to_string(),
                file_path: line.file_path.clone(),
                commit_sha: line.commit_sha.clone(),
                line_number: line.line_number,
                confidence: score_finding(&rule.definition, scoring_text, &line.file_path),
            };
            findings.push(finding);
        }
    }
    findings
}

pub fn scan_all(lines: &[DiffLine], rules: &[CompiledRule]) -> Vec<Finding> {
    lines
        .iter()
        .flat_map(|line| scan_line(line, rules))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::load_builtin_rules;
    use crate::scanner::DiffLine;

    fn make_line(content: &str, file_path: &str) -> DiffLine {
        DiffLine {
            content: content.to_string(),
            file_path: file_path.to_string(),
            commit_sha: "abc1234".to_string(),
            line_number: 1,
        }
    }

    #[test]
    fn detects_aws_key() {
        let rules = load_builtin_rules().unwrap();
        let line = make_line("access_key = AKIAIOSFODNN7EXAMPLE", "config.env");
        let matches = scan_line(&line, &rules);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "aws-access-key-id");
    }

    #[test]
    fn detects_github_token() {
        let rules = load_builtin_rules().unwrap();
        let line = make_line("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "ci.yml");
        let matches = scan_line(&line, &rules);
        assert!(matches.iter().any(|m| m.rule_id == "github-token"));
    }

    #[test]
    fn clean_line_no_match() {
        let rules = load_builtin_rules().unwrap();
        let line = make_line("let x = 42;", "main.rs");
        let matches = scan_line(&line, &rules);
        assert!(matches.is_empty());
    }

    #[test]
    fn detects_every_occurrence_of_the_same_rule() {
        let rules = load_builtin_rules().unwrap();
        let line = make_line(
            "primary=AKIAIOSFODNN7EXAMPLE backup=AKIA1234567890ABCDEF",
            "config.env",
        );
        let matches = scan_line(&line, &rules);
        let aws_matches: Vec<_> = matches
            .iter()
            .filter(|finding| finding.rule_id == "aws-access-key-id")
            .collect();

        assert_eq!(aws_matches.len(), 2);
        assert_eq!(aws_matches[0].matched_text, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(aws_matches[1].matched_text, "AKIA1234567890ABCDEF");
    }

    #[test]
    fn uses_capture_group_for_scoring() {
        let rules = load_builtin_rules().unwrap();
        // 20 unique chars → entropy = log2(20) ≈ 4.32, above ENTROPY_THRESHOLD (4.0)
        let line = make_line("password = \"aB3kL9mZ2pQ7xY5nW8jR\"", "config.yml");
        let matches = scan_line(&line, &rules);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].confidence, crate::models::Confidence::Medium);
    }
}
