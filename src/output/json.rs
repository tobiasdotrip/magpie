use crate::models::ScanResult;
use serde::Serialize;

#[derive(Serialize)]
struct JsonOutput {
    findings: Vec<crate::models::Finding>,
    commits_scanned: usize,
    files_scanned: usize,
    mode: crate::models::ScanMode,
}

pub fn render(result: &ScanResult, show_secrets: bool) -> String {
    let findings = result
        .findings
        .iter()
        .cloned()
        .map(|mut finding| {
            if !show_secrets {
                finding.matched_text = crate::output::text::redact(&finding.matched_text);
            }
            finding
        })
        .collect();
    let output = JsonOutput {
        findings,
        commits_scanned: result.commits_scanned,
        files_scanned: result.files_scanned,
        mode: result.mode,
    };
    serde_json::to_string_pretty(&output).expect("ScanResult is always serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, Finding, ScanMode, ScanResult};

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
            mode: ScanMode::Full,
        };
        let json = render(&result, false);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["findings"][0]["rule_id"], "test");
        assert_eq!(parsed["commits_scanned"], 1);
    }

    #[test]
    fn matched_text_is_redacted_by_default() {
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
            mode: ScanMode::Full,
        };
        let json = render(&result, false);
        assert!(json.contains("AKIA****"));
        assert!(!json.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn matched_text_can_be_shown_explicitly() {
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
            mode: ScanMode::Full,
        };
        let json = render(&result, true);
        assert!(json.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn json_includes_mode() {
        let result = ScanResult {
            findings: vec![],
            commits_scanned: 1,
            files_scanned: 1,
            mode: ScanMode::Incremental,
        };
        let json = render(&result, false);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["mode"], "incremental");
    }
}
