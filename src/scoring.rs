use crate::entropy::shannon_entropy;
use crate::models::{Confidence, RuleDefinition};

const HIGH_CONFIDENCE_RULES: &[&str] = &[
    "aws-access-key-id",
    "github-token",
    "github-oauth",
    "private-key",
];

const SENSITIVE_EXTENSIONS: &[&str] = &[".env", ".pem", ".key", ".secret", ".credentials"];

const TEST_INDICATORS: &[&str] = &[
    "test", "fixture", "mock", "fake", "example", "sample", "dummy",
];

const ENTROPY_THRESHOLD: f64 = 4.0;

pub fn score_finding(rule: &RuleDefinition, matched_text: &str, file_path: &str) -> Confidence {
    let file_lower = file_path.to_lowercase();

    if TEST_INDICATORS.iter().any(|t| file_lower.contains(t)) {
        return Confidence::Low;
    }

    if HIGH_CONFIDENCE_RULES.contains(&rule.id.as_str()) {
        return Confidence::High;
    }

    let in_sensitive_file = SENSITIVE_EXTENSIONS
        .iter()
        .any(|ext| file_lower.ends_with(ext));

    let entropy = shannon_entropy(matched_text);
    let high_entropy = entropy > ENTROPY_THRESHOLD;

    match (in_sensitive_file, high_entropy) {
        (true, _) => Confidence::High,
        (false, true) => Confidence::Medium,
        (false, false) => Confidence::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::RuleDefinition;

    fn rule(id: &str) -> RuleDefinition {
        RuleDefinition {
            id: id.to_string(),
            description: String::new(),
            pattern: String::new(),
            keywords: vec![],
        }
    }

    #[test]
    fn env_file_boosts_confidence() {
        let c = score_finding(&rule("generic-secret"), "password=abc123xyz", ".env");
        assert_eq!(c, Confidence::High);
    }

    #[test]
    fn test_file_lowers_confidence() {
        let c = score_finding(
            &rule("aws-access-key-id"),
            "AKIAIOSFODNN7EXAMPLE",
            "tests/fixtures/test_data.rs",
        );
        assert_eq!(c, Confidence::Low);
    }

    #[test]
    fn specific_pattern_in_normal_file() {
        let c = score_finding(
            &rule("aws-access-key-id"),
            "AKIAIOSFODNN7EXAMPLE",
            "src/config.rs",
        );
        assert_eq!(c, Confidence::High);
    }

    #[test]
    fn generic_pattern_low_entropy_is_low() {
        let c = score_finding(&rule("generic-secret"), "password=test", "config.yml");
        assert_eq!(c, Confidence::Low);
    }

    #[test]
    fn generic_pattern_high_entropy_is_medium() {
        let c = score_finding(
            &rule("generic-secret"),
            "aB3$kL9!mZ2@pQ7&xY5#",
            "config.yml",
        );
        assert_eq!(c, Confidence::Medium);
    }
}
