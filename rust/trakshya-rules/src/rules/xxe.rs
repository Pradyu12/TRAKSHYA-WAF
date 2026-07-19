use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "XXE-001".into(),
            name: "XML External Entity - DOCTYPE".into(),
            pattern: "(?i)(<!DOCTYPE\\s+[^[]*\\s+\\[|<!ENTITY\\s+[a-z]+\\s+SYSTEM|<!ENTITY\\s+[a-z]+\\s+PUBLIC)".into(),
            attack_type: "xxe".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "XXE-002".into(),
            name: "XXE - External Entity Reference".into(),
            pattern: "(?i)(&[a-z]+;\\s*&[a-z]+;|<!ENTITY\\s+%\\s+[a-z]+\\s+SYSTEM)".into(),
            attack_type: "xxe".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "XXE-003".into(),
            name: "XXE via File Reading".into(),
            pattern: "(?i)(SYSTEM\\s+['\\\"]file://|SYSTEM\\s+['\\\"]php://|SYSTEM\\s+['\\\"]expect://)".into(),
            attack_type: "xxe".into(),
            severity: "critical".into(),
            enabled: true,
        },
    ]
}
