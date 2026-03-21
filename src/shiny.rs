use crate::rules::CompiledRule;
use serde::Serialize;

#[derive(Serialize)]
struct RuleInfo {
    id: String,
    description: String,
    custom: bool,
}

#[derive(Serialize)]
struct ShinyJson {
    rules: Vec<RuleInfo>,
    total: usize,
    builtin: usize,
    custom: usize,
}

pub fn render_text(rules: &[CompiledRule], builtin_ids: &[String]) -> String {
    let mut out = String::new();

    let max_id_len = rules.iter().map(|r| r.definition.id.len()).max().unwrap_or(0);

    for rule in rules {
        let is_custom = !builtin_ids.contains(&rule.definition.id);
        let tag = if is_custom { " [custom]" } else { "" };
        out.push_str(&format!(
            "{:<width$} — {}{}\n",
            rule.definition.id,
            rule.definition.description,
            tag,
            width = max_id_len,
        ));
    }

    let total = rules.len();
    let custom_count = rules
        .iter()
        .filter(|r| !builtin_ids.contains(&r.definition.id))
        .count();
    let builtin_count = total - custom_count;
    out.push_str(&format!(
        "\n{total} rules active ({builtin_count} built-in, {custom_count} custom)\n"
    ));

    out
}

pub fn render_json(rules: &[CompiledRule], builtin_ids: &[String]) -> String {
    let rule_infos: Vec<RuleInfo> = rules
        .iter()
        .map(|r| {
            let is_custom = !builtin_ids.contains(&r.definition.id);
            RuleInfo {
                id: r.definition.id.clone(),
                description: r.definition.description.clone(),
                custom: is_custom,
            }
        })
        .collect();

    let total = rule_infos.len();
    let custom_count = rule_infos.iter().filter(|r| r.custom).count();
    let builtin_count = total - custom_count;

    let output = ShinyJson {
        rules: rule_infos,
        total,
        builtin: builtin_count,
        custom: custom_count,
    };

    serde_json::to_string_pretty(&output).expect("ShinyJson is always serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::load_builtin_rules;

    #[test]
    fn text_output_lists_all_rules() {
        let rules = load_builtin_rules().unwrap();
        let builtin_ids: Vec<String> = rules.iter().map(|r| r.definition.id.clone()).collect();
        let output = render_text(&rules, &builtin_ids);
        assert!(output.contains("aws-access-key-id"));
        assert!(output.contains("8 rules active (8 built-in, 0 custom)"));
    }

    #[test]
    fn text_output_tags_custom_rules() {
        let mut rules = load_builtin_rules().unwrap();
        let builtin_ids: Vec<String> = rules.iter().map(|r| r.definition.id.clone()).collect();

        let custom_def = crate::models::RuleDefinition {
            id: "my-custom".to_string(),
            description: "My Custom Rule".to_string(),
            pattern: "CUSTOM_[A-Z]+".to_string(),
            keywords: vec![],
        };
        rules.push(CompiledRule {
            definition: custom_def,
            regex: regex::Regex::new("CUSTOM_[A-Z]+").unwrap(),
        });

        let output = render_text(&rules, &builtin_ids);
        assert!(output.contains("my-custom"));
        assert!(output.contains("[custom]"));
        assert!(output.contains("9 rules active (8 built-in, 1 custom)"));
    }

    #[test]
    fn json_output_is_valid() {
        let rules = load_builtin_rules().unwrap();
        let builtin_ids: Vec<String> = rules.iter().map(|r| r.definition.id.clone()).collect();
        let json = render_json(&rules, &builtin_ids);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["total"], 8);
        assert_eq!(parsed["builtin"], 8);
        assert_eq!(parsed["custom"], 0);
        assert_eq!(parsed["rules"][0]["custom"], false);
    }
}
