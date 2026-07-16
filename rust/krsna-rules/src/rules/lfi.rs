use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "LFI-001".into(),
            name: "Local File Inclusion - System Files".into(),
            pattern: "(?i)(\\.\\./\\.\\./etc/passwd|\\.\\./\\.\\./etc/shadow|\\.\\./\\.\\./windows/system32)".into(),
            attack_type: "local_file_inclusion".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "LFI-002".into(),
            name: "LFI via Null Byte Injection".into(),
            pattern: "(?i)(\\.\\./\\.\\./%00|%00\\.php|%00\\.html)".into(),
            attack_type: "local_file_inclusion".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "LFI-003".into(),
            name: "PHP Wrapper for LFI".into(),
            pattern: "(?i)(php://filter|php://input|php://output)".into(),
            attack_type: "local_file_inclusion".into(),
            severity: "critical".into(),
            enabled: true,
        },
    ]
}
