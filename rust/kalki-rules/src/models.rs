use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub attack_type: String,
    pub severity: String,
    pub pattern: String,
    pub matched_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub attack_type: String,
    pub severity: String,
    pub enabled: bool,
}
