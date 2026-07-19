use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SQLI-001".into(),
            name: "Basic SQL Injection".into(),
            pattern: "(?i)(\\bunion\\b.*\\bselect\\b|\\bselect\\b.*\\bfrom\\b|\\binsert\\s+into\\b|\\bdrop\\s+table\\b|\\bdelete\\s+from\\b|\\bupdate\\s+.*\\bset\\b)".into(),
            attack_type: "sql_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "SQLI-002".into(),
            name: "SQL Comment Injection".into(),
            pattern: "(?i)(--|#|/\\*.*\\*/)".into(),
            attack_type: "sql_injection".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "SQLI-003".into(),
            name: "SQL OR/AND Injection".into(),
            pattern: "(?i)(\\bor\\b\\s*1\\s*=\\s*1|\\band\\b\\s*1\\s*=\\s*1|\\bor\\s+'1'|'or'\\s*1\\s*=\\s*1)".into(),
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
            pattern: "(?i)\\b(sleep|waitfor\\s+delay|pg_sleep)\\s*\\(".into(),
            attack_type: "sql_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
    ]
}
