use regex::Regex;
use serde::Deserialize;

use crate::models::RuleDefinition;

#[derive(Debug, Clone, Deserialize)]
struct RulesFile {
    rules: Vec<RuleDefinition>,
}

pub struct CompiledRule {
    pub definition: RuleDefinition,
    pub regex: Regex,
}

static BUILTIN_TOML: &str = include_str!("../rules/builtin.toml");

pub fn load_builtin_rules() -> Result<Vec<CompiledRule>, Box<dyn std::error::Error>> {
    let file: RulesFile = toml::from_str(BUILTIN_TOML)?;
    let mut compiled = Vec::with_capacity(file.rules.len());
    for def in file.rules {
        let regex = Regex::new(&def.pattern)?;
        compiled.push(CompiledRule {
            definition: def,
            regex,
        });
    }
    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_builtin_rules() {
        let rules = load_builtin_rules().unwrap();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.definition.id == "aws-access-key-id"));
    }

    #[test]
    fn all_patterns_compile() {
        let rules = load_builtin_rules().unwrap();
        assert_eq!(rules.len(), 8);
    }

    #[test]
    fn aws_key_pattern_matches() {
        let rules = load_builtin_rules().unwrap();
        let aws_rule = rules
            .iter()
            .find(|r| r.definition.id == "aws-access-key-id")
            .unwrap();
        assert!(aws_rule.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!aws_rule.regex.is_match("not-a-key"));
    }
}
