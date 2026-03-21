use std::path::Path;

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

const CONFIG_FILE: &str = ".magpie.toml";

#[derive(Debug, Deserialize, Default)]
struct MagpieConfig {
    #[serde(default)]
    config: ConfigSection,
    #[serde(default)]
    rules: Vec<crate::models::RuleDefinition>,
}

#[derive(Debug, Deserialize, Default)]
struct ConfigSection {
    #[serde(default)]
    disable_rules: Vec<String>,
}

pub fn load_rules(repo_root: &Path) -> Result<Vec<CompiledRule>, Box<dyn std::error::Error>> {
    let mut rules = load_builtin_rules()?;

    let config_path = repo_root.join(CONFIG_FILE);
    if !config_path.exists() {
        return Ok(rules);
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: MagpieConfig = toml::from_str(&content)?;

    for id in &config.config.disable_rules {
        if !rules.iter().any(|r| r.definition.id == *id) {
            eprintln!("warning: disable_rules references unknown rule '{id}'");
        }
    }

    rules.retain(|r| !config.config.disable_rules.contains(&r.definition.id));

    for def in config.rules {
        rules.retain(|r| r.definition.id != def.id);
        let regex = Regex::new(&def.pattern)?;
        rules.push(CompiledRule {
            definition: def,
            regex,
        });
    }

    Ok(rules)
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

    #[test]
    fn load_rules_without_config_returns_builtin() {
        let dir = tempfile::TempDir::new().unwrap();
        let rules = load_rules(dir.path()).unwrap();
        assert_eq!(rules.len(), 8);
    }

    #[test]
    fn load_rules_with_custom_adds_rules() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie.toml"),
            r#"
[[rules]]
id = "custom-test"
description = "Custom test rule"
pattern = 'CUSTOM_[A-Z]{10}'
"#,
        ).unwrap();
        let rules = load_rules(dir.path()).unwrap();
        assert_eq!(rules.len(), 9);
        assert!(rules.iter().any(|r| r.definition.id == "custom-test"));
    }

    #[test]
    fn load_rules_disable_removes_builtin() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie.toml"),
            r#"
[config]
disable_rules = ["jwt", "generic-secret"]
"#,
        ).unwrap();
        let rules = load_rules(dir.path()).unwrap();
        assert_eq!(rules.len(), 6);
        assert!(!rules.iter().any(|r| r.definition.id == "jwt"));
        assert!(!rules.iter().any(|r| r.definition.id == "generic-secret"));
    }

    #[test]
    fn load_rules_custom_overrides_builtin_with_same_id() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie.toml"),
            r#"
[[rules]]
id = "jwt"
description = "Custom JWT rule"
pattern = 'MY_JWT_[A-Z]{20}'
"#,
        ).unwrap();
        let rules = load_rules(dir.path()).unwrap();
        let jwt = rules.iter().find(|r| r.definition.id == "jwt").unwrap();
        assert_eq!(jwt.definition.description, "Custom JWT rule");
        assert_eq!(rules.iter().filter(|r| r.definition.id == "jwt").count(), 1);
    }

    #[test]
    fn load_rules_disable_and_custom_same_id() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie.toml"),
            r#"
[config]
disable_rules = ["generic-secret"]

[[rules]]
id = "generic-secret"
description = "My custom generic secret"
pattern = 'MY_SECRET_[A-Z]{10}'
"#,
        ).unwrap();
        let rules = load_rules(dir.path()).unwrap();
        let gs = rules.iter().find(|r| r.definition.id == "generic-secret").unwrap();
        assert_eq!(gs.definition.description, "My custom generic secret");
    }

    #[test]
    fn load_rules_malformed_toml_returns_error() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(".magpie.toml"), "not valid toml {{{").unwrap();
        assert!(load_rules(dir.path()).is_err());
    }

    #[test]
    fn load_rules_invalid_regex_returns_error() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".magpie.toml"),
            r#"
[[rules]]
id = "bad-regex"
description = "Bad"
pattern = '[invalid('
"#,
        ).unwrap();
        assert!(load_rules(dir.path()).is_err());
    }
}
