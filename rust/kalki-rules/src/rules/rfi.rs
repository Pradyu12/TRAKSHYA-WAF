use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "RFI-001".into(),
            name: "Remote File Inclusion - HTTP".into(),
            pattern: "(?i)(include|require|include_once|require_once)\\s*\\(?\\s*['\\\"]?\\s*https?://".into(),
            attack_type: "remote_file_inclusion".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "RFI-002".into(),
            name: "Remote File Inclusion - FTP".into(),
            pattern: "(?i)(include|require)\\s*\\(?\\s*['\\\"]?\\s*ftp://".into(),
            attack_type: "remote_file_inclusion".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "RFI-003".into(),
            name: "Wrapper Protocol Inclusion".into(),
            pattern: "(?i)(php://|data://|expect://|zip://|phar://|compress\\.zlib://|compress\\.bzip2://)".into(),
            attack_type: "remote_file_inclusion".into(),
            severity: "critical".into(),
            enabled: true,
        },
    ]
}
