use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SSTI-001".into(),
            name: "Template Expression Injection".into(),
            pattern: "(?i)(\\{\\{\\s*[^}]*\\b(os|subprocess|system|exec|eval|popen|system|require|file|open|read|write|import|class|base|subclasses|mro|globals|builtins)\\b|\\{%[\\s\\S]*?\\b(include|import|extends|set|macro|call|block)\\b[\\s\\S]*?%\\})".into(),
            attack_type: "ssti".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "SSTI-002".into(),
            name: "Python SSTI Payloads".into(),
            pattern: "(?i)(\\{\\{.*\\}\\}).*\\b(__class__|__subclasses__|__mro__|__globals__|__builtins__|config\\[|request\\.args|lipsum|cycler|joiner|namespace)".into(),
            attack_type: "ssti".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "SSTI-003".into(),
            name: "Python Class/Object Access".into(),
            pattern: "(?i)(__class__|__subclasses__|__mro__|__base__|__globals__|__builtins__|__import__|lipsum|request\\.application)".into(),
            attack_type: "ssti".into(),
            severity: "high".into(),
            enabled: true,
        },
    ]
}
