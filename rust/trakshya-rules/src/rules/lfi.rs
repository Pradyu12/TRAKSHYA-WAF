use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "LFI-001".into(),
            name: "Local File Inclusion - System Files".into(),
            pattern: "(?i)((\\.\\./){1,}(etc/(passwd|shadow|hostname|crontab|hosts|environment|apache2/apache2\\.conf|nginx/nginx\\.conf)|proc/(version|self/environ|self/fd|net/tcp)|var/log/(syslog|auth\\.log)|windows/(system32|win\\.ini|SAM|SYSTEM)))".into(),
            attack_type: "local_file_inclusion".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "LFI-002".into(),
            name: "LFI via Null Byte Injection".into(),
            pattern: "(?i)(\\.\\./)*%00(\\.php|\\.html|\\.txt|\\.asp|\\.jsp)".into(),
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
