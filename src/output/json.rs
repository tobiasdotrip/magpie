use crate::models::ScanResult;
use serde::Serialize;

#[derive(Serialize)]
struct JsonOutput<'a> {
    findings: &'a [crate::models::Finding],
    commits_scanned: usize,
    files_scanned: usize,
}

pub fn render(result: &ScanResult) -> String {
    let output = JsonOutput {
        findings: &result.findings,
        commits_scanned: result.commits_scanned,
        files_scanned: result.files_scanned,
    };
    serde_json::to_string_pretty(&output).expect("ScanResult is always serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Finding, ScanResult};

    #[test]
    fn produces_valid_json() {
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "test".to_string(),
                description: "Test".to_string(),
                matched_text: "secret123".to_string(),
                file_path: "file.txt".to_string(),
                commit_sha: "abc1234".to_string(),
                line_number: 1,
                confidence: Confidence::High,
            }],
            commits_scanned: 1,
            files_scanned: 1,
        };
        let json = render(&result);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["findings"][0]["rule_id"], "test");
        assert_eq!(parsed["commits_scanned"], 1);
    }

    #[test]
    fn matched_text_is_not_redacted() {
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "test".to_string(),
                description: "Test".to_string(),
                matched_text: "AKIAIOSFODNN7EXAMPLE".to_string(),
                file_path: "file.txt".to_string(),
                commit_sha: "abc1234".to_string(),
                line_number: 1,
                confidence: Confidence::High,
            }],
            commits_scanned: 1,
            files_scanned: 1,
        };
        let json = render(&result);
        assert!(json.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
