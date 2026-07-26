use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "CRLF-001".into(),
            name: "CRLF Injection in Headers".into(),
            pattern: "(%0[dD]%0[aA]|%0[dD]|\\r\\n|\\r|\\n)(content-type|location|set-cookie|x-|server|pragma|cache-control|www-authenticate|proxy-authenticate)".into(),
            attack_type: "crlf_injection".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "CRLF-002".into(),
            name: "HTTP Response Splitting".into(),
            pattern: "(%0[dD]%0[aA]|\\r\\n)\\s*(HTTP/[\\d.]+\\s+\\d{3})".into(),
            attack_type: "crlf_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
    ]
}
