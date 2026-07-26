use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "CMDI-001".into(),
            name: "Command Injection - Shell Metacharacters".into(),
            pattern: "(?i)([|;&`]\\s*(bash|sh|cmd|powershell|python|perl|ruby|php|node|java)\\b|\\$\\([a-zA-Z0-9_/]+\\))".into(),
            attack_type: "command_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "CMDI-002".into(),
            name: "Command Injection - Chained Commands".into(),
            pattern: "(?i)([;&|]\\s*(?:cat|ls|rm|whoami|id|uname|wget|curl|nc|ncat|bash|sh|python|perl|ruby|php|node|java|gcc|make|chmod|chown|kill|ps|top|dd|tar|grep|awk|sed|eval|exec|passwd|shadow|sudo|su|ssh|scp|rsync)\\b\\s+[\\-\\/])".into(),
            attack_type: "command_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "CMDI-003".into(),
            name: "Command Substitution".into(),
            pattern: "(?i)\\$\\([a-zA-Z0-9_/]+\\s+[a-zA-Z0-9_/\\-]+\\)".into(),
            attack_type: "command_injection".into(),
            severity: "high".into(),
            enabled: true,
        },
    ]
}
