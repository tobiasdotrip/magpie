use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub id: String,
    pub description: String,
    pub pattern: String,
    #[serde(default)]
    pub keywords: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    pub matched_text: String,
    pub file_path: String,
    pub commit_sha: String,
    pub line_number: usize,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Full,
    Incremental,
    Watch,
}

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub commits_scanned: usize,
    pub files_scanned: usize,
    pub mode: ScanMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_display_shows_severity() {
        let finding = Finding {
            rule_id: "aws-access-key".to_string(),
            description: "AWS Access Key".to_string(),
            matched_text: "AKIA1234567890ABCDEF".to_string(),
            file_path: "config.env".to_string(),
            commit_sha: "abc1234".to_string(),
            line_number: 10,
            confidence: Confidence::High,
        };
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.rule_id, "aws-access-key");
    }

    #[test]
    fn scan_mode_serializes() {
        assert_eq!(
            serde_json::to_string(&ScanMode::Incremental).unwrap(),
            "\"incremental\""
        );
        assert_eq!(serde_json::to_string(&ScanMode::Full).unwrap(), "\"full\"");
    }

    #[test]
    fn confidence_ordering() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }
}
