use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SSRF-001".into(),
            name: "SSRF - Cloud Metadata Endpoint".into(),
            pattern: "(?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal|100\\.100\\.100\\.200|169\\.254\\.169\\.254/latest)".into(),
            attack_type: "ssrf".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "SSRF-002".into(),
            name: "SSRF - Localhost/Internal Network".into(),
            pattern: "(?i)(https?://(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::1\\]|10\\.\\d+\\.\\d+\\.\\d+|172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+))".into(),
            attack_type: "ssrf".into(),
            severity: "high".into(),
            enabled: true,
        },
    ]
}
