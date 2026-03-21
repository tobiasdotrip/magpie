use crate::models::{Confidence, Finding, ScanResult};
use owo_colors::OwoColorize;

pub fn redact(s: &str) -> String {
    let prefix: String = s.chars().take(4).collect();
    format!("{prefix}****")
}

pub fn format_finding(finding: &Finding) -> String {
    let severity_tag = match finding.confidence {
        Confidence::High => "HIGH".red().bold().to_string(),
        Confidence::Medium => "MEDIUM".yellow().bold().to_string(),
        Confidence::Low => "LOW".dimmed().to_string(),
    };

    format!(
        "[{severity}] {rule} — {desc}\n  File: {file}:{line} (commit {sha})\n  Match: {matched}\n",
        severity = severity_tag,
        rule = finding.rule_id,
        desc = finding.description,
        file = finding.file_path,
        line = finding.line_number,
        sha = finding.commit_sha,
        matched = redact(&finding.matched_text),
    )
}

pub fn format_summary(result: &ScanResult) -> String {
    let count = result.findings.len();
    let high = result
        .findings
        .iter()
        .filter(|f| f.confidence == Confidence::High)
        .count();
    let medium = result
        .findings
        .iter()
        .filter(|f| f.confidence == Confidence::Medium)
        .count();
    let low = result
        .findings
        .iter()
        .filter(|f| f.confidence == Confidence::Low)
        .count();

    format!(
        "\n{icon} Scan complete: {commits} commits, {files} files scanned\n  {count} findings: {high} high, {medium} medium, {low} low\n",
        icon = if high > 0 {
            "!".red().bold().to_string()
        } else {
            "OK".green().bold().to_string()
        },
        commits = result.commits_scanned,
        files = result.files_scanned,
        count = count,
        high = high,
        medium = medium,
        low = low,
    )
}

pub fn render(result: &ScanResult) -> String {
    let mut out = String::new();
    for finding in &result.findings {
        out.push_str(&format_finding(finding));
    }
    out.push_str(&format_summary(result));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Finding, ScanResult};

    #[test]
    fn formats_finding_with_all_fields() {
        let finding = Finding {
            rule_id: "aws-access-key-id".to_string(),
            description: "AWS Access Key ID".to_string(),
            matched_text: "AKIAIOSFODNN7EXAMPLE".to_string(),
            file_path: "config.env".to_string(),
            commit_sha: "abc1234".to_string(),
            line_number: 5,
            confidence: Confidence::High,
        };
        let output = format_finding(&finding);
        assert!(output.contains("aws-access-key-id"));
        assert!(output.contains("config.env"));
        assert!(output.contains("abc1234"));
        assert!(output.contains("AKIA****"));
    }

    #[test]
    fn formats_summary() {
        let result = ScanResult {
            findings: vec![],
            commits_scanned: 42,
            files_scanned: 100,
        };
        let output = format_summary(&result);
        assert!(output.contains("42"));
        assert!(output.contains("0"));
    }

    #[test]
    fn redacts_matched_text() {
        assert_eq!(redact("AKIAIOSFODNN7EXAMPLE"), "AKIA****");
        assert_eq!(redact("short"), "shor****");
        assert_eq!(redact("ab"), "ab****");
    }
}
