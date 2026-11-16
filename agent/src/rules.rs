//! Правила детекции, загружаемые из `rules.txt`.
//!
//! Списки намеренно не хранятся в бинарнике: антивирусная эвристика реагирует
//! на строки скриптовых хостов внутри исполняемого файла, принимая защитный
//! инструмент за дроппер. Файл правил также позволяет расширять детект без сборки.

use std::path::PathBuf;

#[derive(Clone, Default)]
pub struct Rules {
    pub miner_names: Vec<String>,
    pub miner_args: Vec<String>,
    pub script_hosts: Vec<String>,
    pub suspicious_dirs: Vec<String>,
    pub source: String,
}

impl Rules {
    pub fn contains_any(&self, list: &[String], haystack: &str) -> bool {
        let h = haystack.to_ascii_lowercase();
        list.iter().any(|needle| !needle.is_empty() && h.contains(needle))
    }

    pub fn is_miner_name(&self, name: &str) -> bool {
        self.contains_any(&self.miner_names, name)
    }

    pub fn is_miner_arg(&self, cmd: &str) -> bool {
        self.contains_any(&self.miner_args, cmd)
    }

    pub fn is_script_launch(&self, cmd: &str) -> bool {
        self.contains_any(&self.script_hosts, cmd)
    }

    pub fn is_user_writable(&self, path: &str) -> bool {
        self.contains_any(&self.suspicious_dirs, &path.replace('/', "\\"))
    }

    pub fn is_empty(&self) -> bool {
        self.miner_names.is_empty()
            && self.miner_args.is_empty()
            && self.script_hosts.is_empty()
            && self.suspicious_dirs.is_empty()
    }
}

/// Ищет `rules.txt` рядом с exe, в каталоге проекта и в данных приложения.
pub fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("rules.txt"));
            if let Some(root) = dir.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
                out.push(root.join("rules.txt"));
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        out.push(cwd.join("rules.txt"));
        out.push(cwd.join("..").join("rules.txt"));
    }
    out.push(crate::store::data_dir().join("rules.txt"));
    out
}

pub fn load() -> Rules {
    for path in candidates() {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let mut rules = parse(&text);
            rules.source = path.to_string_lossy().to_string();
            if !rules.is_empty() {
                return rules;
            }
        }
    }
    Rules {
        source: "встроенный минимум".to_string(),
        ..Default::default()
    }
}

fn parse(text: &str) -> Rules {
    let mut rules = Rules::default();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        let value = line.to_ascii_lowercase();
        match section.as_str() {
            "miner_names" => rules.miner_names.push(value),
            "miner_args" => rules.miner_args.push(value),
            "script_hosts" => rules.script_hosts.push(value),
            "suspicious_dirs" => rules.suspicious_dirs.push(value),
            _ => {}
        }
    }
    rules
}
