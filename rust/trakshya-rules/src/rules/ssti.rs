use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SSTI-001".into(),
            name: "Template Expression Injection".into(),
            pattern: "(?i)(\\{\\{.+?\\}\\}|\\{%.+?%\\})".into(),
            attack_type: "ssti".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "SSTI-002".into(),
            name: "Template Variable Interpolation".into(),
            pattern: "(?i)(\\$\\{.+?\\}|#\\{.+?\\})".into(),
            attack_type: "ssti".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "SSTI-003".into(),
            name: "Python Class/Object Access".into(),
            pattern: "(?i)(__class__|__subclasses__|__mro__|__base__|__globals__)".into(),
            attack_type: "ssti".into(),
            severity: "high".into(),
            enabled: true,
        },
    ]
}
