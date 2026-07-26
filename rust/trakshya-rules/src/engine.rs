use crate::models::RuleMatch;
use percent_encoding::percent_decode;
use regex::Regex;

struct CompiledRule {
    id: String,
    attack_type: String,
    severity: String,
    regex: Regex,
}

pub struct Engine {
    rules: Vec<CompiledRule>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        Self {
            rules: build_rules(),
        }
    }

    pub fn check_attack(&self, content: &str) -> Option<RuleMatch> {
        let normalized = normalize_input(content);
        for rule in &self.rules {
            if let Some(captures) = rule.regex.captures(&normalized) {
                let matched = captures.get(0).map(|m| m.as_str()).unwrap_or("");
                return Some(RuleMatch {
                    rule_id: rule.id.clone(),
                    attack_type: rule.attack_type.clone(),
                    severity: rule.severity.clone(),
                    pattern: rule.regex.as_str().to_string(),
                    matched_content: matched.to_string(),
                });
            }
        }
        None
    }

    pub fn check_all(&self, content: &str) -> Vec<RuleMatch> {
        let normalized = normalize_input(content);
        let mut matches = Vec::new();
        for rule in &self.rules {
            if let Some(captures) = rule.regex.captures(&normalized) {
                let matched = captures.get(0).map(|m| m.as_str()).unwrap_or("");
                matches.push(RuleMatch {
                    rule_id: rule.id.clone(),
                    attack_type: rule.attack_type.clone(),
                    severity: rule.severity.clone(),
                    pattern: rule.regex.as_str().to_string(),
                    matched_content: matched.to_string(),
                });
            }
        }
        matches
    }

    pub fn reload(&mut self, patterns: Vec<(String, String, String, String)>) {
        let mut rules = Vec::new();
        for (id, attack_type, severity, pattern) in patterns {
            match Regex::new(&pattern) {
                Ok(regex) => {
                    rules.push(CompiledRule {
                        id,
                        attack_type,
                        severity,
                        regex,
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to compile regex for rule {}: {} - {}", id, pattern, e);
                }
            }
        }
        self.rules = rules;
    }
}

fn normalize_input(input: &str) -> String {
    let mut result = input.to_string();

    // Step 1: Double URL decode (catch %25XX → %XX → char)
    result = double_url_decode(&result);

    // Step 2: HTML entity decoding (&#60; → <, &#x3C; → <, &lt; → <, etc.)
    result = decode_html_entities(&result);

    // Step 3: Null byte stripping
    result = result.replace('\0', "");
    result = result.replace("%00", "");

    // Step 4: Unicode full-width normalization
    result = normalize_fullwidth(&result);

    result
}

fn double_url_decode(input: &str) -> String {
    // First pass: standard percent-decoding
    let decoded = percent_decode(input.as_bytes())
        .decode_utf8_lossy()
        .to_string();

    // Second pass: if anything changed, decode again (handles double-encoding)
    if decoded != input {
        let double_decoded = percent_decode(decoded.as_bytes())
            .decode_utf8_lossy()
            .to_string();
        if double_decoded != decoded {
            return double_decoded;
        }
    }
    decoded
}

fn decode_html_entities(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '&' {
            let mut entity = String::new();
            entity.push(c);
            // Collect until semicolon or non-entity character
            let mut found_semicolon = false;
            while let Some(&next) = chars.peek() {
                entity.push(next);
                chars.next();
                if next == ';' {
                    found_semicolon = true;
                    break;
                }
                // Stop if it doesn't look like an entity
                if entity.len() > 12 {
                    break;
                }
            }

            if found_semicolon {
                if let Some(decoded) = lookup_html_entity(&entity) {
                    result.push_str(&decoded);
                } else {
                    result.push_str(&entity);
                }
            } else {
                result.push_str(&entity);
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn lookup_html_entity(entity: &str) -> Option<String> {
    // Handle numeric entities: &#60; or &#x3C;
    if entity.starts_with("&#x") || entity.starts_with("&#X") {
        let hex_str = &entity[3..entity.len() - 1]; // strip &#x and ;
        if let Ok(code) = u32::from_str_radix(hex_str, 16) {
            if let Some(c) = char::from_u32(code) {
                return Some(c.to_string());
            }
        }
    } else if entity.starts_with("&#") {
        let dec_str = &entity[2..entity.len() - 1]; // strip &# and ;
        if let Ok(code) = dec_str.parse::<u32>() {
            if let Some(c) = char::from_u32(code) {
                return Some(c.to_string());
            }
        }
    } else {
        // Named entities
        let name = &entity[1..entity.len() - 1]; // strip & and ;
        match name {
            "lt" => return Some("<".to_string()),
            "gt" => return Some(">".to_string()),
            "amp" => return Some("&".to_string()),
            "quot" => return Some("\"".to_string()),
            "apos" | "squote" => return Some("'".to_string()),
            "nbsp" => return Some(" ".to_string()),
            "#" => return Some("#".to_string()),
            _ => {}
        }
    }
    None
}

fn normalize_fullwidth(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\u{FF1C}' => result.push('<'),   // ＜
            '\u{FF1E}' => result.push('>'),   // ＞
            '\u{FF06}' => result.push('&'),   // ＆
            '\u{FF07}' => result.push('\''),  // ＇
            '\u{FF02}' => result.push('"'),   // ＂
            '\u{FF03}' => result.push('#'),   // ＃
            '\u{FF0F}' => result.push('/'),   // ／
            '\u{FF3C}' => result.push('\\'),  // ＼
            '\u{FF5C}' => result.push('|'),   // ｜
            '\u{FF04}' => result.push('$'),   // ＄
            _ => result.push(c),
        }
    }
    result
}

fn build_rules() -> Vec<CompiledRule> {
    crate::rules::sqli::rules()
        .into_iter()
        .chain(crate::rules::xss::rules())
        .chain(crate::rules::cmdi::rules())
        .chain(crate::rules::rfi::rules())
        .chain(crate::rules::path_traversal::rules())
        .chain(crate::rules::lfi::rules())
        .chain(crate::rules::xxe::rules())
        .chain(crate::rules::ssti::rules())
        .chain(crate::rules::ssrf::rules())
        .chain(crate::rules::crlf::rules())
        .chain(crate::rules::jndi::rules())
        .filter(|r| r.enabled)
        .filter_map(|r| {
            Regex::new(&r.pattern).ok().map(|regex| CompiledRule {
                id: r.id,
                attack_type: r.attack_type,
                severity: r.severity,
                regex,
            })
        })
        .collect()
}
