//! Загрузка эвристических правил из текстового файла.
//!
//! Правила намеренно не хранятся в бинарнике. Причина практическая: имена
//! функций вроде `VirtualAllocEx` и `CreateRemoteThread` рядом в одном exe —
//! готовый шаблон дроппера, и антивирус (в том числе Kaspersky) блокирует
//! запуск такого файла, принимая защитный инструмент за вредонос.
//! Файл правил решает это и заодно позволяет дополнять детект без пересборки.

use std::path::PathBuf;

/// Связка API: функции, которые должны встретиться вместе.
#[derive(Clone)]
pub struct ApiCombo {
    pub functions: Vec<String>,
    pub name: String,
    pub severity: String,
    pub reason: String,
}

/// Все правила.
#[derive(Clone, Default)]
pub struct Heuristics {
    pub combos: Vec<ApiCombo>,
    pub packers: Vec<(String, String)>,
    pub script_download: Vec<String>,
    pub script_exec: Vec<String>,
    /// Имена потоков, по которым узнаётся проект макросов в документе Office.
    pub macro_markers: Vec<String>,
    /// Приёмы, которыми макрос запускает код.
    pub macro_exec: Vec<String>,
    /// Откуда загружено — показываем в диагностике.
    pub source: String,
}

impl Heuristics {
    pub fn is_empty(&self) -> bool {
        self.combos.is_empty()
            && self.packers.is_empty()
            && self.script_download.is_empty()
            && self.script_exec.is_empty()
            && self.macro_markers.is_empty()
            && self.macro_exec.is_empty()
    }
}

/// Ищет файл правил рядом с exe, в корне проекта и в данных приложения.
pub fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("heuristics.txt"));
            if let Some(root) = dir.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
                out.push(root.join("heuristics.txt"));
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        out.push(cwd.join("heuristics.txt"));
        out.push(cwd.join("..").join("heuristics.txt"));
    }
    out.push(crate::store::data_dir().join("heuristics.txt"));
    out
}

/// Загружает правила из первого найденного файла.
pub fn load() -> Heuristics {
    for path in candidates() {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let mut rules = parse(&text);
            if !rules.is_empty() {
                rules.source = path.to_string_lossy().to_string();
                return rules;
            }
        }
    }
    Heuristics {
        source: "файл правил не найден".into(),
        ..Default::default()
    }
}

/// Разбирает файл правил.
///
/// Формат строки: `ключ = значение`, где значение — поля через `|`.
/// ```text
/// api = VirtualAllocEx + WriteProcessMemory | Название | critical | Объяснение
/// packer = UPX0 | UPX
/// script-download = downloadstring
/// script-exec = wscript.shell
/// ```
pub fn parse(text: &str) -> Heuristics {
    let mut out = Heuristics::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        match key {
            "api" => {
                let parts: Vec<&str> = value.split('|').map(|p| p.trim()).collect();
                if parts.len() < 2 {
                    continue;
                }
                let functions: Vec<String> = parts[0]
                    .split('+')
                    .map(|f| f.trim().to_string())
                    .filter(|f| !f.is_empty())
                    .collect();
                if functions.len() < 2 {
                    continue;
                }
                out.combos.push(ApiCombo {
                    functions,
                    name: parts[1].to_string(),
                    severity: parts
                        .get(2)
                        .map(|s| s.to_string())
                        // `info` — связка, которая встречается и у нормальных
                        // программ: установщики создают службы, бэкапы меняют
                        // привилегии. Такая связка только добавляет вес.
                        .filter(|s| s == "critical" || s == "warning" || s == "info")
                        .unwrap_or_else(|| "warning".into()),
                    reason: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
                });
            }
            "packer" => {
                let parts: Vec<&str> = value.split('|').map(|p| p.trim()).collect();
                if parts.len() == 2 && !parts[0].is_empty() {
                    out.packers.push((parts[0].to_string(), parts[1].to_string()));
                }
            }
            "script-download" => {
                if !value.is_empty() {
                    out.script_download.push(value.to_lowercase());
                }
            }
            "script-exec" => {
                if !value.is_empty() {
                    out.script_exec.push(value.to_lowercase());
                }
            }
            "macro-marker" => {
                if !value.is_empty() {
                    out.macro_markers.push(value.to_lowercase());
                }
            }
            "macro-exec" => {
                if !value.is_empty() {
                    out.macro_exec.push(value.to_lowercase());
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# комментарий
api = VirtualAllocEx + WriteProcessMemory + CreateRemoteThread | Внедрение кода | critical | Пишет код в чужой процесс
api = URLDownloadToFile + WinExec | Загрузка из сети | warning | Скачивает и запускает
packer = UPX0 | UPX
packer = .aspack | ASPack
script-download = downloadstring
script-exec = wscript.shell
"#;

    #[test]
    fn parses_api_combo() {
        let rules = parse(SAMPLE);
        assert_eq!(rules.combos.len(), 2);
        let first = &rules.combos[0];
        assert_eq!(first.functions.len(), 3);
        assert_eq!(first.functions[0], "VirtualAllocEx");
        assert_eq!(first.name, "Внедрение кода");
        assert_eq!(first.severity, "critical");
        assert!(first.reason.contains("чужой процесс"));
    }

    #[test]
    fn parses_packers() {
        let rules = parse(SAMPLE);
        assert_eq!(rules.packers.len(), 2);
        assert_eq!(rules.packers[0], ("UPX0".to_string(), "UPX".to_string()));
    }

    #[test]
    fn parses_script_markers() {
        let rules = parse(SAMPLE);
        assert_eq!(rules.script_download, vec!["downloadstring"]);
        assert_eq!(rules.script_exec, vec!["wscript.shell"]);
    }

    #[test]
    fn combo_needs_two_functions() {
        // Одна функция — не связка, правило отбрасывается.
        let rules = parse("api = VirtualAllocEx | Один | critical | x\n");
        assert!(rules.combos.is_empty());
    }

    #[test]
    fn severity_defaults_to_warning() {
        let rules = parse("api = A + B | Имя | непонятно | причина\n");
        assert_eq!(rules.combos[0].severity, "warning");
    }

    #[test]
    fn empty_text_gives_empty_rules() {
        assert!(parse("").is_empty());
        assert!(parse("# только комментарий\n").is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let rules = parse("api\npacker\nмусор\napi = | | |\n");
        assert!(rules.is_empty());
    }
}
