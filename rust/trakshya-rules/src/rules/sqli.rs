use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SQLI-001".into(),
            name: "Basic SQL Injection".into(),
            pattern: "(?i)\\b(union\\b[\\s\\S]{0,200}\\bselect\\b|select\\b[\\s\\S]{0,200}\\bfrom\\b|insert\\s+into\\b|drop\\s+table\\b|delete\\s+from\\b|update\\b[\\s\\S]{0,100}\\bset\\b)".into(),
            attack_type: "sql_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "SQLI-002".into(),
            name: "SQL Comment Injection".into(),
            pattern: "(?i)(--\\s|/\\*[\\s\\S]*\\*/)".into(),
            attack_type: "sql_injection".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "SQLI-003".into(),
            name: "SQL OR/AND Tautology".into(),
            pattern: "(?i)(\\bor\\b\\s+\\d+\\s*=\\s*\\d+|\\band\\b\\s+\\d+\\s*=\\s*\\d+|\\bor\\b\\s+['\"]?\\w+['\"]?\\s*=\\s*['\"]?\\w+['\"]?\\s*[;]|\\bor\\b\\s+true\\b|\\band\\b\\s+false\\b|\\bor\\s+1\\b|\\band\\s+1\\b)".into(),
            attack_type: "sql_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "SQLI-004".into(),
            name: "UNION SELECT Injection".into(),
            pattern: "(?i)union[\\s/*]+(all[\\s/*]+)?select".into(),
            attack_type: "sql_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "SQLI-005".into(),
            name: "SQL Sleep-Based Timing".into(),
            pattern: "(?i)\\b(sleep|waitfor\\s+delay|pg_sleep|benchmark)\\s*\\(".into(),
            attack_type: "sql_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
    ]
}
