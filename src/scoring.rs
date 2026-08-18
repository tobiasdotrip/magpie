use crate::entropy::shannon_entropy;
use crate::models::{Confidence, RuleDefinition};

const HIGH_CONFIDENCE_RULES: &[&str] = &[
    "aws-access-key-id",
    "aws-secret-access-key",
    "github-token",
    "github-oauth",
    "private-key",
];

const SENSITIVE_EXTENSIONS: &[&str] = &[".env", ".pem", ".key", ".secret", ".credentials"];

const TEST_INDICATORS: &[&str] = &[
    "test", "tests", "fixture", "fixtures", "mock", "mocks", "fake", "fakes", "example",
    "examples", "sample", "samples", "dummy", "dummies",
];

const ENTROPY_THRESHOLD: f64 = 4.0;

pub fn score_finding(rule: &RuleDefinition, matched_text: &str, file_path: &str) -> Confidence {
    let file_lower = file_path.to_lowercase();

    if HIGH_CONFIDENCE_RULES.contains(&rule.id.as_str()) {
        return Confidence::High;
    }

    if file_lower
        .split(|c: char| !c.is_alphanumeric())
        .any(|token| TEST_INDICATORS.contains(&token))
    {
        return Confidence::Low;
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
    fn strong_rule_stays_high_in_test_file() {
        for id in [
            "aws-access-key-id",
            "aws-secret-access-key",
            "github-token",
            "github-oauth",
            "private-key",
        ] {
            let c = score_finding(
                &rule(id),
                "known-specific-secret",
                "tests/fixtures/test_data.rs",
            );
            assert_eq!(c, Confidence::High, "{id}");
        }
    }

    #[test]
    fn actual_test_path_lowers_generic_confidence() {
        let c = score_finding(
            &rule("generic-secret"),
            "aB3$kL9!mZ2@pQ7&xY5#",
            "tests/fixtures/config.rs",
        );
        assert_eq!(c, Confidence::Low);
    }

    #[test]
    fn indicator_substring_does_not_lower_confidence() {
        let c = score_finding(
            &rule("generic-secret"),
            "aB3$kL9!mZ2@pQ7&xY5#",
            "config/latest.env",
        );
        assert_eq!(c, Confidence::High);
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
