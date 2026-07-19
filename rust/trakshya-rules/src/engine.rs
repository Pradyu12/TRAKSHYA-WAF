use crate::models::RuleMatch;
use regex::Regex;

struct CompiledRule {
    id: String,
    attack_type: String,
    severity: String,
    regex: Regex,
}

pub struct Engine {
    rules: Vec<CompiledRule>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        Self {
            rules: build_rules(),
        }
    }

    pub fn check_attack(&self, content: &str) -> Option<RuleMatch> {
        for rule in &self.rules {
            if let Some(captures) = rule.regex.captures(content) {
                let matched = captures.get(0).map(|m| m.as_str()).unwrap_or("");
                return Some(RuleMatch {
                    rule_id: rule.id.clone(),
                    attack_type: rule.attack_type.clone(),
                    severity: rule.severity.clone(),
                    pattern: rule.regex.as_str().to_string(),
                    matched_content: matched.to_string(),
                });
            }
        }
        None
    }

    pub fn check_all(&self, content: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if let Some(captures) = rule.regex.captures(content) {
                let matched = captures.get(0).map(|m| m.as_str()).unwrap_or("");
                matches.push(RuleMatch {
                    rule_id: rule.id.clone(),
                    attack_type: rule.attack_type.clone(),
                    severity: rule.severity.clone(),
                    pattern: rule.regex.as_str().to_string(),
                    matched_content: matched.to_string(),
                });
            }
        }
        matches
    }

    pub fn reload(&mut self, patterns: Vec<(String, String, String, String)>) {
        let mut rules = Vec::new();
        for (id, attack_type, severity, pattern) in patterns {
            if let Ok(regex) = Regex::new(&pattern) {
                rules.push(CompiledRule {
                    id,
                    attack_type,
                    severity,
                    regex,
                });
            }
        }
        self.rules = rules;
    }
}

fn build_rules() -> Vec<CompiledRule> {
    crate::rules::sqli::rules()
        .into_iter()
        .chain(crate::rules::xss::rules())
        .chain(crate::rules::cmdi::rules())
        .chain(crate::rules::rfi::rules())
        .chain(crate::rules::path_traversal::rules())
        .chain(crate::rules::lfi::rules())
        .chain(crate::rules::xxe::rules())
        .chain(crate::rules::ssti::rules())
        .filter_map(|r| {
            Regex::new(&r.pattern).ok().map(|regex| CompiledRule {
                id: r.id,
                attack_type: r.attack_type,
                severity: r.severity,
                regex,
            })
        })
        .collect()
}
