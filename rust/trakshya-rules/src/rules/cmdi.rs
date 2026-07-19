use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "CMDI-001".into(),
            name: "Command Injection - Shell Metacharacters".into(),
            pattern: "(?i)([|;&`]\\s*\\b(bash|sh|cmd|powershell|python|perl|ruby|php)\\b|\\$\\(|`[^`]*`)".into(),
            attack_type: "command_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "CMDI-002".into(),
            name: "Command Injection - Pipe/Redirect".into(),
            pattern: "(?i)(\\||;|&|`|\\$\\(|\\)\\{).*(\\bcat\\b|\\bls\\b|\\brm\\b|\\bwhoami\\b|\\bid\\b|\\buname\\b|\\bwget\\b|\\bcurl\\b|\\bnc\\b)".into(),
            attack_type: "command_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "CMDI-003".into(),
            name: "Command Substitution".into(),
            pattern: "(?i)\\$[^)]+\\)|`[^`]+`".into(),
            attack_type: "command_injection".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "CMDI-004".into(),
            name: "Subshell Execution".into(),
            pattern: "(?i)\\(\\s*\\)\\s*\\{|\\(\\s*\\).*\\{".into(),
            attack_type: "command_injection".into(),
            severity: "high".into(),
            enabled: true,
        },
    ]
}
