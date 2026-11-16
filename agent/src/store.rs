//! Хранение настроек и истории оценок (простые текстовые форматы, без зависимостей).

use std::collections::HashMap;
use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    // Переопределение нужно тестам и портативному запуску: иначе они писали бы
    // в реальные настройки пользователя.
    if let Ok(custom) = std::env::var("PC_SENTINEL_DATA") {
        if !custom.trim().is_empty() {
            let dir = PathBuf::from(custom);
            let _ = std::fs::create_dir_all(&dir);
            return dir;
        }
    }
    let base = crate::win::env_var("LOCALAPPDATA").unwrap_or_else(|| ".".to_string());
    let dir = PathBuf::from(base).join("PCSentinel");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[derive(Clone, Default, Copy)]
pub struct HistoryPoint {
    pub ts: u64,
    pub score: f64,
    pub cpu: f64,
    pub mem: f64,
    pub disk: f64,
}

pub fn load_history() -> Vec<HistoryPoint> {
    let path = data_dir().join("history.csv");
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 5 {
                continue;
            }
            let ts = parts[0].trim().parse().unwrap_or(0);
            let score = parts[1].trim().parse().unwrap_or(0.0);
            let cpu = parts[2].trim().parse().unwrap_or(0.0);
            let mem = parts[3].trim().parse().unwrap_or(0.0);
            let disk = parts[4].trim().parse().unwrap_or(0.0);
            if ts > 0 {
                out.push(HistoryPoint {
                    ts,
                    score,
                    cpu,
                    mem,
                    disk,
                });
            }
        }
    }
    out
}

pub fn save_history(points: &[HistoryPoint]) {
    let path = data_dir().join("history.csv");
    let mut text = String::from("ts,score,cpu,mem,disk\n");
    for p in points {
        text.push_str(&format!(
            "{},{:.1},{:.1},{:.1},{:.1}\n",
            p.ts, p.score, p.cpu, p.mem, p.disk
        ));
    }
    let _ = std::fs::write(path, text);
}

pub fn load_settings() -> HashMap<String, String> {
    let path = data_dir().join("settings.ini");
    let mut map = HashMap::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    if !map.contains_key("refresh_ms") {
        map.insert("refresh_ms".into(), "1500".into());
    }
    if !map.contains_key("autorun_backup") {
        map.insert("autorun_backup".into(), "1".into());
    }
    map
}

pub fn save_settings(map: &HashMap<String, String>) {
    let path = data_dir().join("settings.ini");
    let mut text = String::new();
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for k in keys {
        text.push_str(&format!("{}={}\n", k, map[k]));
    }
    let _ = std::fs::write(path, text);
}

pub fn backup_autorun(line: &str) {
    let path = data_dir().join("autorun-backup.txt");
    let mut text = std::fs::read_to_string(&path).unwrap_or_default();
    text.push_str(line);
    text.push('\n');
    let _ = std::fs::write(path, text);
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
