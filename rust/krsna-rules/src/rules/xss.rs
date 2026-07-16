use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "XSS-001".into(),
            name: "Script Tag Injection".into(),
            pattern: "<[iI][sS][cC][rR][iI][pP][tT]".into(),
            attack_type: "xss".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "XSS-002".into(),
            name: "Event Handler Injection".into(),
            pattern: " on\\w+\\s*=".into(),
            attack_type: "xss".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "XSS-003".into(),
            name: "JavaScript URI Scheme".into(),
            pattern: "javascript\\s*:".into(),
            attack_type: "xss".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "XSS-004".into(),
            name: "HTML Tag Injection".into(),
            pattern: "(<iframe|<img[^>]+onerror|<svg|<input[^>]+onfocus)".into(),
            attack_type: "xss".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "XSS-005".into(),
            name: "Expression Injection".into(),
            pattern: "(\\{\\{|\\{\\%|\\$\\{)".into(),
            attack_type: "xss".into(),
            severity: "medium".into(),
            enabled: true,
        },
    ]
}
