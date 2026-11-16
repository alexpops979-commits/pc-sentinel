//! Движок правил в стиле YARA.
//!
//! Правила лежат в текстовом файле и не требуют пересборки — как `rules.txt`
//! у эвристик процессов. Формат намеренно простой, чтобы правило можно было
//! написать в блокноте:
//!
//! ```text
//! rule PowerShellEncoded
//!   severity = warning
//!   text = "powershell -enc"
//!   text = "-windowstyle hidden"
//!   condition = all
//! ```
//!
//! `text` ищется без учёта регистра, `hex` — точные байты, где `??` означает
//! «любой байт». `condition = any` (по умолчанию) — достаточно одного
//! совпадения, `all` — нужны все.

use std::path::PathBuf;

/// Один шаблон внутри правила.
#[derive(Clone)]
pub enum Pattern {
    /// Текст без учёта регистра.
    Text(String),
    /// Байты; `None` — любой байт (wildcard).
    Hex(Vec<Option<u8>>),
}

/// Правило.
#[derive(Clone)]
pub struct Rule {
    pub name: String,
    pub severity: String,
    pub patterns: Vec<Pattern>,
    /// `true` — нужны все шаблоны, `false` — достаточно одного.
    pub require_all: bool,
}

/// Совпадение правила с файлом.
pub struct Match {
    pub rule: String,
    pub severity: String,
    /// Сколько шаблонов сработало.
    pub hits: usize,
    pub total: usize,
}

/// Ищет файл правил рядом с exe, в корне проекта и в данных приложения.
pub fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("yara.txt"));
            if let Some(root) = dir.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
                out.push(root.join("yara.txt"));
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        out.push(cwd.join("yara.txt"));
        out.push(cwd.join("..").join("yara.txt"));
    }
    out.push(crate::store::data_dir().join("yara.txt"));
    out
}

/// Загружает правила и сообщает, из какого файла они взяты.
pub fn load_with_source() -> (Vec<Rule>, Option<PathBuf>) {
    for path in candidates() {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let rules = parse(&text);
            if !rules.is_empty() {
                return (rules, Some(path));
            }
        }
    }
    (Vec::new(), None)
}

/// Загружает правила из первого найденного файла.
pub fn load() -> Vec<Rule> {
    load_with_source().0
}

/// Разбирает текст правил.
pub fn parse(text: &str) -> Vec<Rule> {
    let mut out: Vec<Rule> = Vec::new();
    let mut current: Option<Rule> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("rule ") {
            // Новое правило: предыдущее сохраняем.
            if let Some(rule) = current.take() {
                if !rule.patterns.is_empty() {
                    out.push(rule);
                }
            }
            let name = rest.trim().trim_end_matches('{').trim().to_string();
            if name.is_empty() {
                continue;
            }
            current = Some(Rule {
                name,
                severity: "warning".into(),
                patterns: Vec::new(),
                require_all: false,
            });
            continue;
        }
        let rule = match current.as_mut() {
            Some(r) => r,
            None => continue,
        };
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        match key {
            "severity" => {
                let v = value.trim_matches('"').to_lowercase();
                if v == "critical" || v == "warning" {
                    rule.severity = v;
                }
            }
            "condition" => {
                rule.require_all = value.trim_matches('"').eq_ignore_ascii_case("all");
            }
            "text" => {
                let v = value.trim_matches('"');
                if !v.is_empty() {
                    rule.patterns.push(Pattern::Text(v.to_string()));
                }
            }
            "hex" => {
                if let Some(bytes) = parse_hex(value) {
                    if !bytes.is_empty() {
                        rule.patterns.push(Pattern::Hex(bytes));
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(rule) = current.take() {
        if !rule.patterns.is_empty() {
            out.push(rule);
        }
    }
    out
}

/// Разбирает hex-строку: `4D 5A ?? 00`.
fn parse_hex(value: &str) -> Option<Vec<Option<u8>>> {
    let cleaned = value.trim().trim_matches('"').trim_matches('{').trim_matches('}');
    let mut out = Vec::new();
    for token in cleaned.split_whitespace() {
        if token == "??" || token == "?" {
            out.push(None);
            continue;
        }
        if token.len() != 2 {
            return None;
        }
        let byte = u8::from_str_radix(token, 16).ok()?;
        out.push(Some(byte));
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Ищет подстроку без учёта регистра.
fn find_text(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let lower_needle: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    haystack
        .windows(needle.len())
        .any(|w| w.iter().map(|b| b.to_ascii_lowercase()).eq(lower_needle.iter().copied()))
}

/// Ищет байтовый шаблон с wildcard-ами.
fn find_hex(haystack: &[u8], pattern: &[Option<u8>]) -> bool {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return false;
    }
    haystack.windows(pattern.len()).any(|window| {
        window
            .iter()
            .zip(pattern.iter())
            .all(|(byte, want)| match want {
                Some(w) => byte == w,
                None => true,
            })
    })
}

/// Проверяет файл по всем правилам.
pub fn scan(data: &[u8], rules: &[Rule]) -> Vec<Match> {
    let mut out = Vec::new();
    for rule in rules {
        let total = rule.patterns.len();
        if total == 0 {
            continue;
        }
        let hits = rule
            .patterns
            .iter()
            .filter(|p| match p {
                Pattern::Text(t) => find_text(data, t),
                Pattern::Hex(h) => find_hex(data, h),
            })
            .count();
        let matched = if rule.require_all {
            hits == total
        } else {
            hits > 0
        };
        if matched {
            out.push(Match {
                rule: rule.name.clone(),
                severity: rule.severity.clone(),
                hits,
                total,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Строки намеренно нейтральные: настоящие маркеры вредоносов в тестовом
    // коде попали бы в бинарник, и антивирус заблокировал бы его запуск.
    const SAMPLE: &str = r#"
# комментарий
rule TwoMarkers
  severity = warning
  text = "marker-one"
  text = "marker-two"
  condition = all

rule SingleMarker
  severity = critical
  text = "MARKER-SINGLE"

rule MzHeader
  severity = warning
  hex = 4D 5A ?? 00
"#;

    #[test]
    fn parses_rules() {
        let rules = parse(SAMPLE);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].name, "TwoMarkers");
        assert_eq!(rules[0].severity, "warning");
        assert!(rules[0].require_all);
        assert_eq!(rules[0].patterns.len(), 2);
        assert!(!rules[1].require_all);
    }

    #[test]
    fn parses_hex_with_wildcard() {
        let rules = parse(SAMPLE);
        let hex = rules
            .iter()
            .find(|r| r.name == "MzHeader")
            .and_then(|r| r.patterns.first());
        match hex {
            Some(Pattern::Hex(bytes)) => {
                assert_eq!(bytes.len(), 4);
                assert_eq!(bytes[0], Some(0x4D));
                assert_eq!(bytes[2], None);
            }
            _ => panic!("hex не разобран"),
        }
    }

    #[test]
    fn condition_all_requires_every_pattern() {
        let rules = parse(SAMPLE);
        // Только одна из двух строк — правило не должно сработать.
        let data = b"marker-one AAAA";
        let matches = scan(data, &rules);
        assert!(matches.iter().all(|m| m.rule != "TwoMarkers"));
    }

    #[test]
    fn condition_all_matches_when_both_present() {
        let rules = parse(SAMPLE);
        let data = b"marker-one AAAA marker-two";
        let matches = scan(data, &rules);
        assert!(matches.iter().any(|m| m.rule == "TwoMarkers"));
    }

    #[test]
    fn text_match_is_case_insensitive() {
        let rules = parse(SAMPLE);
        let data = b"marker-single";
        let matches = scan(data, &rules);
        assert!(matches.iter().any(|m| m.rule == "SingleMarker"));
    }

    #[test]
    fn hex_wildcard_matches() {
        let rules = parse(SAMPLE);
        let data = b"\x4D\x5A\x90\x00rest";
        let matches = scan(data, &rules);
        assert!(matches.iter().any(|m| m.rule == "MzHeader"));
    }

    #[test]
    fn hex_wildcard_rejects_mismatch() {
        let rules = parse(SAMPLE);
        let data = b"\x4D\x5B\x90\x00";
        let matches = scan(data, &rules);
        assert!(matches.iter().all(|m| m.rule != "MzHeader"));
    }

    #[test]
    fn empty_rules_give_no_matches() {
        assert!(scan(b"anything", &[]).is_empty());
        assert!(parse("").is_empty());
    }

    #[test]
    fn rule_without_patterns_is_dropped() {
        let rules = parse("rule Empty\n  severity = critical\n");
        assert!(rules.is_empty());
    }

    #[test]
    fn bad_hex_is_ignored() {
        let rules = parse("rule Bad\n  hex = ZZ ZZ\n");
        assert!(rules.is_empty());
    }

    #[test]
    fn severity_defaults_to_warning() {
        let rules = parse("rule X\n  text = \"abc\"\n");
        assert_eq!(rules[0].severity, "warning");
    }

    #[test]
    fn scan_reports_hit_counts() {
        let rules = parse(SAMPLE);
        let data = b"marker-one AAAA marker-two";
        let m = scan(data, &rules)
            .into_iter()
            .find(|m| m.rule == "TwoMarkers")
            .expect("правило не сработало");
        assert_eq!(m.hits, 2);
        assert_eq!(m.total, 2);
    }

    #[test]
    fn real_rules_file_parses_with_expected_severity() {
        // Настоящий `yara.txt`: проверка, что уровни из файла доезжают
        // до движка. Иначе весь вес признаков считается неверно.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../yara.txt");
        let text = std::fs::read_to_string(path).expect("yara.txt не найден");
        let rules = parse(&text);
        assert!(!rules.is_empty());
        let rule = rules
            .iter()
            .find(|r| r.name == "EncodedPowerShell")
            .expect("правило EncodedPowerShell не разобрано");
        assert_eq!(rule.severity, "warning", "уровень из файла не применён");
    }
}
