use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "JNDI-001".into(),
            name: "JNDI Injection (Log4Shell)".into(),
            pattern: "(?i)\\$\\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)://".into(),
            attack_type: "jndi_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "JNDI-002".into(),
            name: "JNDI Lookup Obfuscation".into(),
            pattern: "(?i)\\$\\{(lower|upper|env|sys|java|date|::-?|\\$\\{).*jndi".into(),
            attack_type: "jndi_injection".into(),
            severity: "critical".into(),
            enabled: true,
        },
    ]
}
