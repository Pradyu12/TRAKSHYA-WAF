use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "PT-001".into(),
            name: "Directory Traversal - Unix".into(),
            pattern: "(?i)(\\.\\./|\\.\\.\\\\)|(\\.\\.%2f|\\.\\.%5c|%2e%2e%2f|%2e%2e%5c)".into(),
            attack_type: "path_traversal".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "PT-002".into(),
            name: "Directory Traversal - Windows".into(),
            pattern: "(?i)(\\.\\.\\\\[^.]|\\.\\.\\\\\\\\[^.])".into(),
            attack_type: "path_traversal".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "PT-003".into(),
            name: "Absolute Path Access".into(),
            pattern: "(?i)(file://|/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|/boot\\.ini|/windows/win\\.ini)".into(),
            attack_type: "path_traversal".into(),
            severity: "high".into(),
            enabled: true,
        },
    ]
}
