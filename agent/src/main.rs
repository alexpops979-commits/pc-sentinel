//! PC Sentinel — локальный агент: телеметрия, защита, аналитика FPS.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod av;
mod archive;
mod fps;
mod game;
mod health;
mod heur;
mod http;
mod inflate;
mod install;
mod json;
mod pe;
mod optimize;
mod rules;
mod sec;
mod shell;
mod store;
mod sys;
mod win;
mod yara;

use json::J;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

static WINDOW_PID: AtomicU32 = AtomicU32::new(0);

/// Заголовок окна приложения: по нему агент понимает, что окно ещё открыто.
const WINDOW_TITLE: &str = "PC Sentinel";

/// Вывод в консоль родителя: release-сборка не имеет собственной консоли.
macro_rules! cli {
    ($($arg:tt)*) => {
        crate::win::con_print(&format!($($arg)*))
    };
}

struct App {
    sampler: sys::Sampler,
    rules: rules::Rules,
    settings: HashMap<String, String>,
    history: Vec<store::HistoryPoint>,
    scan: Option<sec::ScanReport>,
    autoruns: Vec<sec::Autorun>,
    autoruns_loaded: bool,
    fps_sessions: Vec<fps::FpsReport>,
    game: game::GameState,
    av: AvState,
    started_at: u64,
    last_point: u64,
}

/// Состояние встроенной проверки на вирусы.
///
/// Полная проверка диска идёт долго, поэтому движок работает в отдельном потоке,
/// а интерфейс опрашивает прогресс и может проверку прервать.
struct AvState {
    progress: av::Progress,
    threats: Vec<av::Threat>,
    /// Флаг отмены: движок проверяет его на каждом файле.
    cancel: Arc<std::sync::atomic::AtomicBool>,
    /// Сколько подписей загружено — показываем в интерфейсе.
    signatures: usize,
    /// Сколько правил в стиле YARA загружено.
    rules: usize,
    /// Сколько путей в исключениях и игнорируемых.
    exclusions: usize,
    ignored: usize,
}

impl AvState {
    fn new() -> AvState {
        AvState {
            progress: av::Progress::default(),
            threats: Vec::new(),
            cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            signatures: av::load_signatures().len(),
            rules: yara::load().len(),
            exclusions: av::load_list(&av::exclusions_path()).len(),
            ignored: av::load_list(&av::ignored_path()).len(),
        }
    }

    fn to_json(&self) -> J {
        let mut obj = match self.progress.to_json() {
            J::Obj(pairs) => pairs,
            other => vec![("progress".to_string(), other)],
        };
        obj.push(("signatures".into(), J::Int(self.signatures as i64)));
        obj.push(("rules".into(), J::Int(self.rules as i64)));
        obj.push(("exclusions".into(), J::Int(self.exclusions as i64)));
        obj.push(("ignored".into(), J::Int(self.ignored as i64)));
        obj.push((
            "found".to_string(),
            J::Arr(self.threats.iter().map(|t| t.to_json()).collect()),
        ));
        J::Obj(obj)
    }
}

impl App {
    fn new() -> App {
        let rules = rules::load();
        App {
            sampler: sys::Sampler::new(),
            rules,
            settings: store::load_settings(),
            history: store::load_history(),
            scan: None,
            autoruns: Vec::new(),
            autoruns_loaded: false,
            fps_sessions: Vec::new(),
            game: game::GameState::new(),
            av: AvState::new(),
            started_at: store::now_unix(),
            last_point: 0,
        }
    }

    fn ensure_autoruns(&mut self) {
        if !self.autoruns_loaded {
            self.autoruns = sec::autoruns(&self.rules);
            self.autoruns_loaded = true;
        }
    }

    fn scan_score(&self) -> Option<f64> {
        self.scan.as_ref().map(|s| s.score())
    }

    /// Фоновый такт: свежие метрики и точки истории без запросов от интерфейса.
    fn background_tick(&mut self) {
        self.ensure_autoruns();
        // Игровой профиль: включаем оптимизацию только пока игра запущена.
        self.game.tick();
        let scan_score = self.scan_score();
        let findings = self
            .scan
            .as_ref()
            .map(|s| s.threats.clone())
            .unwrap_or_default();
        let autoruns = self.autoruns.clone();
        let (score, cpu, mem, disk) = {
            let snap = self.sampler.sample();
            let report = health::evaluate(snap, scan_score, &findings, &autoruns);
            let worst = snap.disks.iter().map(|d| d.percent).fold(0.0f64, f64::max);
            (report.score, snap.cpu.usage, snap.mem.percent, worst)
        };
        self.tick_history(cpu, mem, disk, score);
    }

    /// Обновляет историю (точка раз в минуту, храним сутки).
    fn tick_history(&mut self, cpu: f64, mem: f64, disk: f64, score: f64) {
        let now = store::now_unix();
        if now.saturating_sub(self.last_point) < 55 {
            return;
        }
        self.last_point = now;
        self.history.push(store::HistoryPoint {
            ts: now,
            score,
            cpu,
            mem,
            disk,
        });
        if self.history.len() > 1440 {
            let drop = self.history.len() - 1440;
            self.history.drain(0..drop);
        }
        store::save_history(&self.history);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Установщик не может удалить старый exe, пока тот запущен: он уводит его
    // в `pc-sentinel.old`. Убираем остаток при следующем запуске.
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(exe.with_extension("old"));
    }
    // Паника в оконной сборке уходит в никуда: stderr некуда писать.
    // Пишем её в файл рядом с данными, иначе сбой проверки не объяснить.
    std::panic::set_hook(Box::new(|info| {
        let text = format!(
            "{} {}: {info}\n",
            store::now_unix(),
            std::thread::current().name().unwrap_or("main")
        );
        let path = store::data_dir().join("panic.log");
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = file.write_all(text.as_bytes());
        }
    }));
    let no_window = args.iter().any(|a| a == "--no-window");
    let port = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(47821);

    // Командные режимы работают без окна и пишут в консоль вызывающего.
    let cli_mode = args
        .iter()
        .any(|a| {
            a == "--diag"
                || a == "--install"
                || a == "--uninstall"
                || a == "--scan"
                || a == "--pe"
                || a == "--rules"
                || a == "--trust"
        });
    if cli_mode {
        win::attach_console();
    }

    if args.iter().any(|a| a == "--diag") {
        diagnose();
        return;
    }

    // Доверенные пути: антивирус не должен трогать наше приложение, а мы —
    // его каталоги. Команда показывает, что и куда добавить.
    if args.iter().any(|a| a == "--trust") {
        let app = install::app_dir();
        let data = store::data_dir();
        let mut added = Vec::new();
        for path in [&app, &data] {
            let text = path.to_string_lossy().to_string();
            if av::add_to_list(&av::exclusions_path(), &text).is_ok() {
                added.push(text);
            }
        }
        cli!("Доверенные пути PC Sentinel");
        cli!("");
        cli!("Добавлено в собственные исключения:");
        for path in &added {
            cli!("  {path}");
        }
        cli!("");
        cli!("Чтобы Kaspersky не трогал приложение, добавьте те же пути в его исключения:");
        cli!("  Настройки → Безопасность → Угрозы и исключения → Управлять исключениями");
        cli!("  → Добавить → выбрать папку:");
        cli!("      {}", app.display());
        cli!("      {}", data.display());
        cli!("  и файл:");
        cli!("      {}", app.join("pc-sentinel.exe").display());
        cli!("");
        cli!("Папки других антивирусов движок не сканирует сам: их защита");
        cli!("снимает посторонние процессы, которые читают их файлы.");
        return;
    }

    // Какие правила реально загружены и откуда: без этого не понять, почему
    // находка объясняется не тем правилом, которое правили в файле.
    if args.iter().any(|a| a == "--rules") {
        let (rules, source) = yara::load_with_source();
        match &source {
            Some(path) => cli!("Правила: {}", path.display()),
            None => cli!("Файл правил не найден — работает без правил"),
        }
        cli!("Правил загружено: {}", rules.len());
        for rule in &rules {
            cli!(
                "  [{}] {} (шаблонов: {}, условие: {})",
                rule.severity,
                rule.name,
                rule.patterns.len(),
                if rule.require_all { "all" } else { "any" }
            );
        }
        let heur = heur::load();
        cli!("Эвристики: {}", heur.source);
        cli!("  связок API: {}", heur.combos.len());
        cli!("  упаковщиков: {}", heur.packers.len());
        return;
    }

    // Разбор PE-файла: что именно увидел движок. Нужен, чтобы объяснить
    // находку и проверить сам разбор на реальных файлах.
    if let Some(index) = args.iter().position(|a| a == "--pe") {
        let target = match args.get(index + 1) {
            Some(value) => value.clone(),
            None => {
                cli!("Укажите файл: pc-sentinel.exe --pe \"C:\\Файл.exe\"");
                std::process::exit(1);
            }
        };
        let data = match std::fs::read(&target) {
            Ok(data) => data,
            Err(e) => {
                cli!("Не удалось прочитать «{target}»: {e}");
                std::process::exit(1);
            }
        };
        match pe::parse(&data) {
            Some(info) => {
                cli!("Секции: {}", info.sections.len());
                for section in &info.sections {
                    cli!(
                        "  {:<8} адрес {:#010x}  в файле {:#010x}  размер {:#x}  энтропия {:.2}",
                        section.name,
                        section.virtual_address,
                        section.raw_offset,
                        section.raw_size,
                        section.entropy
                    );
                }
                cli!("Импорт: {}", info.imports.len());
                for import in &info.imports {
                    cli!("  {}!{}", import.dll, import.name);
                }
                cli!(
                    "Точка входа {:#x}, дата сборки {}, подсистема {}, данных после секций {}",
                    info.entry_point,
                    info.timestamp,
                    info.subsystem,
                    info.overlay_size
                );
                let signals = pe::analyze(&info, &heur::load());
                cli!("Признаки: {}", signals.len());
                for scored in &signals {
                    cli!(
                        "  [{}] вес {} — {}",
                        scored.signal.severity,
                        scored.weight,
                        scored.signal.name
                    );
                }
            }
            None => cli!("Это не PE-файл или заголовок повреждён"),
        }
        return;
    }

    if let Some(index) = args.iter().position(|a| a == "--scan") {
        let target = match args.get(index + 1) {
            Some(value) => value.clone(),
            None => {
                cli!("Укажите, что проверять: pc-sentinel.exe --scan \"C:\\Папка\"");
                std::process::exit(1);
            }
        };
        let (found, progress) = av::scan_path(std::path::Path::new(&target));
        if let Some(error) = &progress.error {
            cli!("{error}");
            std::process::exit(1);
        }
        let mut report = String::new();
        report.push_str(&format!("Проверено файлов: {}\n", progress.scanned));
        if progress.cached > 0 {
            report.push_str(&format!(
                "Из кеша (не менялись с прошлой проверки): {}\n",
                progress.cached
            ));
        }
        if progress.skipped > 0 {
            report.push_str(&format!(
                "Не прочитано (заняты или нет прав): {}\n",
                progress.skipped
            ));
        }
        report.push_str(&format!("Находок: {}\n", found.len()));
        for threat in &found {
            let signature = match sec::verify_signature(&threat.path) {
                Some(true) => "подпись действительна",
                Some(false) => "файл не подписан",
                None => "подпись проверить не удалось",
            };
            report.push_str(&format!("  [{}] {}\n", threat.severity, threat.path));
            report.push_str(&format!("      {} — {}\n", threat.name, threat.reason));
            report.push_str(&format!("      {signature}\n"));
        }
        for line in report.lines() {
            cli!("{line}");
        }
        // Отчёт в файл: длинный обход удобнее разбирать, чем ловить в консоли.
        if let Some(index) = args.iter().position(|a| a == "--out") {
            if let Some(path) = args.get(index + 1) {
                if let Err(e) = std::fs::write(path, &report) {
                    cli!("Не удалось записать отчёт: {e}");
                }
            }
        }
        return;
    }

    if args.iter().any(|a| a == "--install") {
        match install::install() {
            Ok(report) => {
                cli!("PC Sentinel установлен");
                cli!("  каталог: {}", report.app_dir.display());
                cli!("  файлов скопировано: {}", report.files);
                for link in &report.shortcuts {
                    cli!("  ярлык: {link}");
                }
                for warning in &report.warnings {
                    cli!("  предупреждение: {warning}");
                }
                if report.already_installed {
                    cli!("  (запущено из уже установленного каталога)");
                }
                if report.stopped_running {
                    cli!("  (работавшее приложение было закрыто для замены файлов)");
                }
                cli!("");
                cli!("Запуск: ярлык «PC Sentinel» на рабочем столе или в меню Пуск.");
            }
            Err(e) => {
                cli!("Установка не выполнена: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if args.iter().any(|a| a == "--uninstall") {
        let (removed, warnings) = install::uninstall();
        if removed.is_empty() && warnings.is_empty() {
            cli!("Установка не найдена");
        }
        for item in &removed {
            cli!("удалено: {item}");
        }
        for warning in &warnings {
            cli!("предупреждение: {warning}");
        }
        return;
    }

    let dist = find_dist();
    let state = Arc::new(Mutex::new(App::new()));
    {
        // Прогрев: к первому запросу уже есть корректные дельты CPU и сети.
        let mut app = state.lock().unwrap();
        app.ensure_autoruns();
        let _ = app.sampler.sample();
        std::thread::sleep(std::time::Duration::from_millis(620));
        let _ = app.sampler.sample();
    }
    {
        let st = Arc::clone(&state);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            if let Ok(mut app) = st.lock() {
                app.background_tick();
            }
        });
    }

    // Настройка «проверка при запуске» действительно запускает скан.
    let scan_on_start = state
        .lock()
        .map(|app| app.settings.get("scan_on_start").map(|v| v == "1").unwrap_or(false))
        .unwrap_or(false);
    if scan_on_start {
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            let _ = api_scan(&st);
        });
    }

    // Порт занимаем до открытия окна: иначе при занятом порте окно успевало
    // открыться и показать пустую страницу, а процесс молча завершался.
    let listener = match http::bind(port) {
        Ok(l) => l,
        Err(e) => {
            // Порт занят: если на нём отвечает наш же агент, второй экземпляр
            // не нужен — открываем окно к работающему.
            if is_our_instance(port) {
                if !no_window {
                    open_window(port, dist.is_some());
                }
                return;
            }
            win::error_box(
                "PC Sentinel",
                &format!(
                    "{e}\n\nПорт занят другой программой. Закройте её или запустите\n\
                     PC Sentinel с другим портом: pc-sentinel.exe --port 47900"
                ),
            );
            std::process::exit(1);
        }
    };

    if !no_window {
        let dist_ok = dist.is_some();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(320));
            open_window(port, dist_ok);
            // Окно закрыли — приложение должно завершиться, а не висеть в фоне.
            install::watch_window(WINDOW_TITLE);
        });
    }

    let st = Arc::clone(&state);
    http::serve_on(listener, move |req| route(req, &st, &dist));
}

/// Отвечает ли на порту наш агент.
///
/// Проверяем именно содержимое ответа: любой чужой сервер на этом порту
/// не должен приниматься за уже запущенный PC Sentinel.
fn is_our_instance(port: u16) -> bool {
    use std::io::{Read, Write};
    let addr = format!("127.0.0.1:{port}");
    let mut stream = match std::net::TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(700)));
    let request = format!("GET /api/av HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut answer = String::new();
    let _ = stream.take(4096).read_to_string(&mut answer);
    answer.contains("\"signatures\"") && answer.contains("\"found\"")
}

fn find_dist() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("PC_SENTINEL_DIST") {
        candidates.push(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("dist"));
            if let Some(root) = dir.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
                candidates.push(root.join("dist"));
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("dist"));
        candidates.push(cwd.join("..").join("dist"));
    }
    candidates
        .into_iter()
        .find(|p| p.join("index.html").exists())
}

fn route(req: &http::Req, state: &Arc<Mutex<App>>, dist: &Option<PathBuf>) -> http::Body {
    let path = req.path.split('?').next().unwrap_or("/");
    if let Some(api) = path.strip_prefix("/api/") {
        // Интерфейс открыт с того же адреса, поэтому Origin либо отсутствует,
        // либо локальный. Чужой сайт не должен управлять агентом.
        if !origin_allowed(req.origin.as_deref()) {
            return http::Body::Error(
                403,
                J::obj(vec![("error", J::s("Запрос с чужого источника отклонён"))]).to_json(),
            );
        }
        let result = match (req.method.as_str(), api) {
            ("GET", "meta") => api_meta(state),
            ("GET", "snapshot") => api_snapshot(state),
            ("GET", "processes") => api_processes(state),
            ("GET", "autoruns") => api_autoruns(state),
            ("GET", "connections") => api_connections(state),
            ("POST", "scan") => api_scan(state),
            ("GET", "scan") => api_last_scan(state),
            ("GET", "health") => api_health(state),
            ("GET", "history") => api_history(state),
            ("GET", "fps") => api_fps(state),
            ("POST", "fps/import") => api_fps_import(state, &req.body),
            ("GET", "optimize") => api_optimize(state),
            ("POST", "action") => api_action(state, &req.body),
            ("GET", "game") => api_game(state),
            ("POST", "game") => api_game_set(state, &req.body),
            ("POST", "game/pick") => api_game_pick(),
            ("GET", "av") => api_av(state),
            ("POST", "av/scan") => api_av_scan(state, &req.body),
            ("POST", "av/cancel") => api_av_cancel(state),
            ("POST", "av/exclude") => api_av_exclude(state, &req.body),
            ("POST", "av/ignore") => api_av_ignore(state, &req.body),
            ("POST", "av/open") => api_av_open(&req.body),
            ("POST", "av/clear-lists") => api_av_clear_lists(state),
            ("POST", "process/kill") => api_kill(&req.body),
            ("GET", "settings") => api_settings_get(state),
            ("POST", "settings") => api_settings_set(state, &req.body),
            ("POST", "app/quit") => {
                let pid = WINDOW_PID.load(Ordering::SeqCst);
                if pid != 0 {
                    win::kill(pid);
                }
                std::thread::spawn(|| {
                    std::thread::sleep(std::time::Duration::from_millis(120));
                    std::process::exit(0);
                });
                Ok(r#"{"ok":true}"#.to_string())
            }
            // Неизвестный маршрут — это 404, а не ошибка обработчика.
            _ => return http::Body::NotFound,
        };
        return match result {
            Ok(body) => http::Body::Json(body),
            // Текст ошибки нужен интерфейсу: иначе вместо «Не указан путь к файлу»
            // пользователь видел бы «not found».
            Err(message) => http::Body::Error(
                400,
                J::obj(vec![("error", J::s(message))]).to_json(),
            ),
        };
    }

    // Статика
    let rel = if path == "/" { "/index.html" } else { path };
    if rel.contains("..") {
        return http::Body::NotFound;
    }
    let dir = match dist {
        Some(d) => d,
        None => return http::Body::NotFound,
    };
    let file = dir.join(rel.trim_start_matches('/'));
    match std::fs::read(&file) {
        Ok(bytes) => http::Body::File(bytes, http::mime_for(rel)),
        Err(_) => http::Body::NotFound,
    }
}

/// Разрешён ли запрос к API с указанного источника.
///
/// Интерфейс живёт на `http://127.0.0.1:<порт>`, поэтому Origin либо не приходит
/// (навигация, curl), либо совпадает с локальным адресом. Всё остальное — чужая
/// страница, которая пытается управлять агентом через localhost.
fn origin_allowed(origin: Option<&str>) -> bool {
    let origin = match origin {
        Some(o) => o.trim(),
        None => return true,
    };
    if origin.is_empty() || origin == "null" {
        // "null" присылают sandbox-iframe и file:// — доверять им нельзя.
        return origin.is_empty();
    }
    let rest = match origin.split_once("://") {
        Some((_, r)) => r,
        None => return false,
    };
    let host = rest.split('/').next().unwrap_or("");
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

fn json_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let pos = body.find(&needle)?;
    let rest = &body[pos + needle.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if let Some(inner) = after.strip_prefix('"') {
        let mut out = String::new();
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                out.push(match ch {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    other => other,
                });
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                break;
            } else {
                out.push(ch);
            }
        }
        Some(out)
    } else {
        let end = after
            .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
            .unwrap_or(after.len());
        Some(after[..end].to_string())
    }
}

fn num_field(body: &str, key: &str) -> Option<f64> {
    json_field(body, key).and_then(|v| v.parse().ok())
}

fn api_meta(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    let snap = &app.sampler.last;
    let gpu = snap.as_ref().map(|s| s.gpu.available).unwrap_or(false);
    Ok(J::obj(vec![
        ("app", J::s("PC Sentinel")),
        ("version", J::s("1.0.0")),
        ("startedAt", J::Int(app.started_at as i64)),
        ("gpuAvailable", J::Bool(gpu)),
        (
            "cpu",
            J::s(snap
                .as_ref()
                .map(|s| s.cpu.name.clone())
                .unwrap_or_default()),
        ),
        (
            "cores",
            J::Int(snap.as_ref().map(|s| s.cpu.cores as i64).unwrap_or(0)),
        ),
        ("host", J::s(win::computer_name())),
    ])
    .to_json())
}

fn api_snapshot(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let mut app = state.lock().map_err(|e| e.to_string())?;
    app.ensure_autoruns();
    let scan_score = app.scan_score();
    let findings = app
        .scan
        .as_ref()
        .map(|s| s.threats.clone())
        .unwrap_or_default();
    let autoruns = app.autoruns.clone();
    let (snap_json, score, grade, cpu_now, mem_now, disk_now) = {
        let snap = app.sampler.sample();
        let report = health::evaluate(snap, scan_score, &findings, &autoruns);
        let json = snap.to_json();
        let s = report.score;
        let g = report.grade.clone();
        let worst = snap.disks.iter().map(|d| d.percent).fold(0.0f64, f64::max);
        (json, s, g, snap.cpu.usage, snap.mem.percent, worst)
    };
    app.tick_history(cpu_now, mem_now, disk_now, score);
    let mut obj = match snap_json {
        J::Obj(pairs) => pairs,
        other => vec![("data".to_string(), other)],
    };
    obj.push((
        "health".into(),
        J::obj(vec![("score", J::num(score)), ("grade", J::s(grade))]),
    ));
    obj.push((
        "threats".into(),
        J::Int(
            app.scan
                .as_ref()
                .map(|s| s.threats.len() as i64)
                .unwrap_or(0),
        ),
    ));
    obj.push(("startup".into(), J::Int(app.autoruns.len() as i64)));
    Ok(J::Obj(obj).to_json())
}

fn api_processes(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let mut app = state.lock().map_err(|e| e.to_string())?;
    let procs = {
        let snap = app.sampler.sample();
        snap.procs.clone()
    };
    let anomalies = procs
        .iter()
        .filter(|p| p.cpu > 20.0 && !sec::is_system_path(&p.path))
        .count();
    Ok(J::obj(vec![
        ("items", J::Arr(procs.iter().map(sys::proc_json).collect())),
        ("count", J::Int(procs.len() as i64)),
        ("anomalies", J::Int(anomalies as i64)),
    ])
    .to_json())
}

fn api_autoruns(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let mut app = state.lock().map_err(|e| e.to_string())?;
    app.ensure_autoruns();
    Ok(J::obj(vec![
        (
            "items",
            J::Arr(app.autoruns.iter().map(|a| a.to_json()).collect()),
        ),
        ("count", J::Int(app.autoruns.len() as i64)),
        (
            "suspicious",
            J::Int(app.autoruns.iter().filter(|a| a.suspicious).count() as i64),
        ),
    ])
    .to_json())
}

fn api_connections(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let mut app = state.lock().map_err(|e| e.to_string())?;
    let procs = {
        let snap = app.sampler.sample();
        snap.procs.clone()
    };
    let mut conns = sec::connections();
    sec::attach_process_names(&mut conns, &procs);
    let established = conns.iter().filter(|c| c.state == "ESTABLISHED").count();
    let listening = conns.iter().filter(|c| c.state == "LISTEN").count();
    Ok(J::obj(vec![
        ("items", J::Arr(conns.iter().map(|c| c.to_json()).collect())),
        ("established", J::Int(established as i64)),
        ("listening", J::Int(listening as i64)),
    ])
    .to_json())
}

fn api_scan(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let started = store::now_unix();
    let tick = unsafe { win::GetTickCount64() };
    let (procs, rules) = {
        let mut app = state.lock().map_err(|e| e.to_string())?;
        let snap = app.sampler.sample();
        (snap.procs.clone(), app.rules.clone())
    };
    let (threats, signed, unsigned) = sec::analyze_processes(&procs, &rules);
    let autoruns = sec::autoruns(&rules);
    let mut conns = sec::connections();
    sec::attach_process_names(&mut conns, &procs);
    let risky: Vec<sec::Conn> = conns
        .iter()
        .filter(|c| {
            c.state == "ESTABLISHED"
                && !c.remote_ip.starts_with("127.")
                && !c.remote_ip.starts_with("0.")
                && c.remote_ip != "0.0.0.0"
                && threats.iter().any(|t| t.pid == c.pid)
        })
        .cloned()
        .collect();
    let duration = unsafe { win::GetTickCount64() } - tick;
    let report = sec::ScanReport {
        started,
        duration_ms: duration,
        checked: procs.len(),
        signed,
        unsigned,
        threats,
        autoruns,
        risky_conns: risky,
    };
    let json = report.to_json().to_json();
    let mut app = state.lock().map_err(|e| e.to_string())?;
    app.autoruns = report.autoruns.clone();
    app.autoruns_loaded = true;
    app.scan = Some(report);
    Ok(json)
}

fn api_last_scan(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    match &app.scan {
        Some(report) => Ok(report.to_json().to_json()),
        None => Ok(J::obj(vec![
            ("startedAt", J::Int(0)),
            ("durationMs", J::Int(0)),
            ("checked", J::Int(0)),
            ("signed", J::Int(0)),
            ("unsigned", J::Int(0)),
            ("score", J::num(0.0)),
            ("coverage", J::num(0.0)),
            ("skipped", J::Int(0)),
            ("threats", J::Arr(vec![])),
            ("autoruns", J::Arr(vec![])),
            ("riskyConnections", J::Arr(vec![])),
        ])
        .to_json()),
    }
}

fn api_health(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let mut app = state.lock().map_err(|e| e.to_string())?;
    app.ensure_autoruns();
    let scan_score = app.scan_score();
    let findings = app
        .scan
        .as_ref()
        .map(|s| s.threats.clone())
        .unwrap_or_default();
    let autoruns = app.autoruns.clone();
    let report = {
        let snap = app.sampler.sample();
        health::evaluate(snap, scan_score, &findings, &autoruns)
    };
    Ok(report.to_json().to_json())
}

fn api_history(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    Ok(J::obj(vec![(
        "points",
        J::Arr(
            app.history
                .iter()
                .map(|p| {
                    J::obj(vec![
                        ("ts", J::Int(p.ts as i64)),
                        ("score", J::num(p.score)),
                        ("cpu", J::num(p.cpu)),
                        ("mem", J::num(p.mem)),
                        ("disk", J::num(p.disk)),
                    ])
                })
                .collect(),
        ),
    )])
    .to_json())
}

fn api_fps(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    Ok(J::obj(vec![(
        "sessions",
        J::Arr(app.fps_sessions.iter().map(|s| s.to_json()).collect()),
    )])
    .to_json())
}

fn api_fps_import(state: &Arc<Mutex<App>>, body: &str) -> Result<String, String> {
    let path = json_field(body, "path").ok_or("Не указан путь к файлу")?;
    let report = fps::import_capture(&path)?;
    let json = report.to_json().to_json();
    let mut app = state.lock().map_err(|e| e.to_string())?;
    app.fps_sessions.insert(0, report);
    if app.fps_sessions.len() > 20 {
        app.fps_sessions.truncate(20);
    }
    Ok(json)
}

fn api_optimize(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let mut app = state.lock().map_err(|e| e.to_string())?;
    app.ensure_autoruns();
    let autoruns = app.autoruns.clone();
    let actions = {
        let snap = app.sampler.sample();
        optimize::recommendations(snap, &autoruns)
    };
    Ok(J::obj(vec![(
        "actions",
        J::Arr(actions.iter().map(|a| a.to_json()).collect()),
    )])
    .to_json())
}

fn api_action(state: &Arc<Mutex<App>>, body: &str) -> Result<String, String> {
    let id = json_field(body, "id").ok_or("Не указан идентификатор действия")?;
    // Настройка «резервная копия автозагрузки» реально влияет на действие.
    let backup = state
        .lock()
        .map(|app| app.settings.get("autorun_backup").map(|v| v != "0").unwrap_or(true))
        .unwrap_or(true);
    let (ok, message) = optimize::apply(&id, backup);
    if ok && id.starts_with("disable:") {
        if let Ok(mut app) = state.lock() {
            app.autoruns_loaded = false;
            app.ensure_autoruns();
        }
    }
    Ok(J::obj(vec![("ok", J::Bool(ok)), ("message", J::s(message))]).to_json())
}

fn api_game(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let mut app = state.lock().map_err(|e| e.to_string())?;
    // Свежий статус без ожидания фонового такта: интерфейс спрашивает часто.
    app.game.tick();
    Ok(app.game.to_json().to_json())
}

fn api_game_set(state: &Arc<Mutex<App>>, body: &str) -> Result<String, String> {
    let mut app = state.lock().map_err(|e| e.to_string())?;
    // Основной путь: пользователь указывает папку игры, exe агент находит сам.
    if let Some(path) = json_field(body, "path") {
        if path.trim().is_empty() {
            app.game.clear_profile();
        } else {
            app.game.set_profile_from_path(&path)?;
        }
        app.game.tick();
        return Ok(app.game.to_json().to_json());
    }
    // Ручной режим остаётся для совместимости со старыми профилями.
    let name = json_field(body, "name").unwrap_or_default();
    let process = json_field(body, "process").unwrap_or_default();
    if name.trim().is_empty() || process.trim().is_empty() {
        app.game.clear_profile();
    } else {
        app.game.set_profile(&name, &process);
    }
    app.game.tick();
    Ok(app.game.to_json().to_json())
}

/// Системный диалог выбора папки. Блокирует только этот запрос.
fn api_game_pick() -> Result<String, String> {
    let picked = win::pick_folder("Выберите папку с игрой");
    Ok(J::obj(vec![(
        "path",
        match picked {
            Some(p) => J::s(p),
            None => J::Null,
        },
    )])
    .to_json())
}

fn api_av(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    Ok(app.av.to_json().to_json())
}

/// Запускает проверку в фоне и сразу отвечает.
///
/// Тело запроса: `{"mode":"quick"}` или `{"mode":"full"}`.
fn api_av_scan(state: &Arc<Mutex<App>>, body: &str) -> Result<String, String> {
    let mode = json_field(body, "mode")
        .and_then(|m| av::Mode::from_str(&m))
        .ok_or("Неизвестный режим проверки")?;
    let cancel = {
        let mut app = state.lock().map_err(|e| e.to_string())?;
        if app.av.progress.running {
            return Err("Проверка уже идёт".into());
        }
        // Новый флаг на каждую проверку: старый мог остаться взведённым.
        app.av.cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        app.av.progress = av::Progress {
            running: true,
            mode: mode.as_str().to_string(),
            started: store::now_unix(),
            ..Default::default()
        };
        app.av.threats.clear();
        app.av.signatures = av::load_signatures().len();
        Arc::clone(&app.av.cancel)
    };

    let st = Arc::clone(state);
    std::thread::spawn(move || {
        let signatures = av::load_signatures();
        let rules = yara::load();
        let heur = heur::load();
        // Списки читаем на старте проверки: пользователь мог изменить их только что.
        let exclusions = av::load_list(&av::exclusions_path());
        let ignored = av::load_list(&av::ignored_path());
        let mut progress = av::Progress {
            running: true,
            mode: mode.as_str().to_string(),
            started: store::now_unix(),
            ..Default::default()
        };
        let mut found: Vec<av::Threat> = Vec::new();
        // Прогресс обновляем пачками: блокировать мьютекс на каждом файле дорого.
        let result = av::run(
            mode,
            &signatures,
            &rules,
            &heur,
            &exclusions,
            &ignored,
            &cancel,
            &mut progress,
            &mut found,
            &mut |p, list| {
                if let Ok(mut app) = st.lock() {
                    app.av.progress = p.clone();
                    // Находки показываем сразу, не дожидаясь конца проверки.
                    app.av.threats = list
                        .iter()
                        .filter(|t| !av::is_listed(&ignored, &t.path))
                        .cloned()
                        .collect();
                }
            },
        );
        if let Ok(mut app) = st.lock() {
            progress.running = false;
            progress.finished = store::now_unix();
            app.av.progress = progress;
            app.av.threats = result;
        }
    });
    Ok(r#"{"ok":true}"#.to_string())
}

fn api_av_cancel(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    app.av.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(r#"{"ok":true}"#.to_string())
}

/// Добавляет путь в исключения и убирает находку из текущего списка.
fn api_av_exclude(state: &Arc<Mutex<App>>, body: &str) -> Result<String, String> {
    let path = json_field(body, "path").ok_or("Не указан путь")?;
    av::add_to_list(&av::exclusions_path(), &path)?;
    if let Ok(mut app) = state.lock() {
        app.av.threats.retain(|t| t.path != path);
        app.av.progress.threats = app.av.threats.len() as u64;
        app.av.exclusions = av::load_list(&av::exclusions_path()).len();
    }
    Ok(J::obj(vec![
        ("ok", J::Bool(true)),
        (
            "message",
            J::s("Файл добавлен в исключения — при следующих проверках он пропускается"),
        ),
    ])
    .to_json())
}

/// Добавляет путь в игнорируемые: файл проверяется, но находка не показывается.
fn api_av_ignore(state: &Arc<Mutex<App>>, body: &str) -> Result<String, String> {
    let path = json_field(body, "path").ok_or("Не указан путь")?;
    av::add_to_list(&av::ignored_path(), &path)?;
    if let Ok(mut app) = state.lock() {
        app.av.threats.retain(|t| t.path != path);
        app.av.progress.threats = app.av.threats.len() as u64;
        app.av.ignored = av::load_list(&av::ignored_path()).len();
    }
    Ok(J::obj(vec![
        ("ok", J::Bool(true)),
        (
            "message",
            J::s("Находка скрыта. Файл остаётся на месте и будет проверяться снова"),
        ),
    ])
    .to_json())
}

/// Открывает папку с файлом и выделяет его в проводнике.
fn api_av_open(body: &str) -> Result<String, String> {
    let path = json_field(body, "path").ok_or("Не указан путь")?;
    if !std::path::Path::new(&path).exists() {
        return Err("Файл уже удалён или перемещён".into());
    }
    let params = format!("/select,\"{path}\"");
    let ok = win::shell_open("explorer.exe", Some(&params));
    Ok(J::obj(vec![
        ("ok", J::Bool(ok)),
        (
            "message",
            J::s(if ok {
                "Открыта папка с файлом"
            } else {
                "Не удалось открыть проводник"
            }),
        ),
    ])
    .to_json())
}

/// Очищает списки исключений и игнорируемых.
fn api_av_clear_lists(state: &Arc<Mutex<App>>) -> Result<String, String> {
    for path in [av::exclusions_path(), av::ignored_path()] {
        let _ = std::fs::remove_file(path);
    }
    if let Ok(mut app) = state.lock() {
        app.av.exclusions = 0;
        app.av.ignored = 0;
    }
    Ok(J::obj(vec![
        ("ok", J::Bool(true)),
        ("message", J::s("Списки исключений и игнорируемых очищены")),
    ])
    .to_json())
}

fn api_kill(body: &str) -> Result<String, String> {
    let pid = num_field(body, "pid").ok_or("Не указан PID")? as u32;
    if pid <= 4 {
        return Ok(J::obj(vec![
            ("ok", J::Bool(false)),
            ("message", J::s("Системный процесс защищён")),
        ])
        .to_json());
    }
    let ok = win::kill(pid);
    Ok(J::obj(vec![
        ("ok", J::Bool(ok)),
        (
            "message",
            J::s(if ok {
                "Процесс завершён"
            } else {
                "Не удалось завершить процесс (нужны права администратора)"
            }),
        ),
    ])
    .to_json())
}

fn api_settings_get(state: &Arc<Mutex<App>>) -> Result<String, String> {
    let app = state.lock().map_err(|e| e.to_string())?;
    let mut pairs: Vec<(String, J)> = Vec::new();
    let mut keys: Vec<&String> = app.settings.keys().collect();
    keys.sort();
    for k in keys {
        pairs.push((k.clone(), J::s(app.settings[k].clone())));
    }
    Ok(J::Obj(pairs).to_json())
}

fn api_settings_set(state: &Arc<Mutex<App>>, body: &str) -> Result<String, String> {
    let mut app = state.lock().map_err(|e| e.to_string())?;
    let mut changed = false;
    for key in ["refresh_ms", "autorun_backup", "scan_on_start", "theme"] {
        if let Some(v) = json_field(body, key) {
            if app.settings.get(key) != Some(&v) {
                app.settings.insert(key.to_string(), v);
                changed = true;
            }
        }
    }
    // Посторонние ключи игнорируются, и без изменений файл не перезаписывается.
    if changed {
        store::save_settings(&app.settings);
    }
    Ok(r#"{"ok":true}"#.to_string())
}

// ---------------- Запуск окна ----------------

fn edge_path() -> Option<String> {
    let pf86 = win::env_var("ProgramFiles(x86)").unwrap_or_default();
    let pf = win::env_var("ProgramFiles").unwrap_or_default();
    let local = win::env_var("LOCALAPPDATA").unwrap_or_default();
    let candidates = [
        format!("{pf86}\\Microsoft\\Edge\\Application\\msedge.exe"),
        format!("{pf}\\Microsoft\\Edge\\Application\\msedge.exe"),
        format!("{local}\\Microsoft\\Edge\\Application\\msedge.exe"),
    ];
    candidates
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
}

fn diagnose() {
    cli!("--- PC Sentinel diag ---");
    let mut probe = sys::NetProbe::new();
    cli!("pdh netprobe: {}", if probe.is_some() { "ok" } else { "нет" });
    if let Some(p) = probe.as_mut() {
        for i in 0..3 {
            std::thread::sleep(std::time::Duration::from_millis(700));
            let (rx, tx) = p.read();
            cli!("  net sample {i}: down={rx:.0} B/s up={tx:.0} B/s");
        }
    }
    let mut s = sys::Sampler::new();
    let _ = s.sample();
    std::thread::sleep(std::time::Duration::from_millis(800));
    // Температура GPU: смотрим, что отдают WDDM-счётчики и меняется ли значение.
    for i in 0..4 {
        let gpu = s.sample().gpu.clone();
        cli!(
            "  gpu {i}: temp={:.1} °C fan={}% usage={:.0}% clock={} МГц",
            gpu.temp,
            gpu.fan,
            gpu.usage,
            gpu.clock
        );
        std::thread::sleep(std::time::Duration::from_millis(1200));
    }
    let snap = s.sample();
    cli!(
        "cpu {:.1}% mem {:.1}% net {:.0}/{:.0} B/s",
        snap.cpu.usage, snap.mem.percent, snap.net.down_bps, snap.net.up_bps
    );
    cli!(
        "  потоки {} дескрипторы {} процессы {}",
        snap.cpu.threads,
        snap.cpu.handles,
        snap.cpu.processes
    );
    cli!(
        "  память: выделено {:.1} ГБ из {:.1} ГБ, кэш {:.1} ГБ, доступно {:.1} ГБ, пулы {:.0}/{:.0} МБ",
        snap.mem.committed as f64 / 1e9,
        snap.mem.commit_limit as f64 / 1e9,
        snap.mem.cached as f64 / 1e9,
        snap.mem.available as f64 / 1e9,
        snap.mem.paged_pool as f64 / 1e6,
        snap.mem.nonpaged_pool as f64 / 1e6
    );
    for d in &snap.disks {
        cli!(
            "  диск {}: активно {:.0}%, чтение {:.0} КБ/с, запись {:.0} КБ/с",
            d.letter,
            d.active,
            d.read_bps / 1024.0,
            d.write_bps / 1024.0
        );
    }
    let sample: Vec<String> = snap
        .procs
        .iter()
        .take(5)
        .map(|p| format!("{} pid={} cpu={:.1} mem={} path={}", p.name, p.pid, p.cpu, p.mem, p.path))
        .collect();
    for line in sample {
        cli!("  {line}");
    }
    let win = win::windows_dir();
    let notepad = format!("{win}\\System32\\notepad.exe");
    cli!("verify notepad rc: {:08X?}", sec::verify_raw(&notepad));
    cli!("signature notepad: {:?}", sec::verify_signature(&notepad));
    cli!(
        "signature chrome: {:?}",
        sec::verify_signature("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
    );
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    cli!("verify self rc: {:08X?}", sec::verify_raw(&self_exe));
    cli!(
        "sha256 notepad: {:?}",
        sec::hash_file(&notepad).map(|h| h.chars().take(16).collect::<String>())
    );
    let rules = rules::load();
    cli!(
        "rules: {} (майнеры {}, аргументы {}, скрипты {}, каталоги {})",
        rules.source,
        rules.miner_names.len(),
        rules.miner_args.len(),
        rules.script_hosts.len(),
        rules.suspicious_dirs.len()
    );
    let autos = sec::autoruns(&rules);
    cli!(
        "autoruns: {} (подозрительных {})",
        autos.len(),
        autos.iter().filter(|a| a.suspicious).count()
    );
    for a in autos.iter().take(3) {
        cli!("  [{}] {} -> {}", a.location, a.name, a.command);
    }
    let mut conns = sec::connections();
    sec::attach_process_names(&mut conns, &snap.procs);
    cli!("connections: {}", conns.len());
    for c in conns.iter().filter(|c| c.state == "ESTABLISHED").take(3) {
        cli!("  {} {} -> {} ({})", c.proc, c.local, c.remote, c.state);
    }
    #[cfg(debug_assertions)]
    {
        let check = fps::selftest_report();
        cli!(
            "fps-формулы (синтетика, в интерфейс не идёт): avg {:.1} p1 {:.1} p0.1 {:.1} stutter {:.2}% кадров {}",
            check.avg_fps,
            check.p1_low,
            check.p01_low,
            check.stutter_ratio * 100.0,
            check.frames
        );
    }
    #[cfg(not(debug_assertions))]
    cli!("fps: сессий в памяти нет (захваты импортируются из интерфейса)");
}

fn open_window(port: u16, dist_ok: bool) {
    let url = format!("http://127.0.0.1:{port}/");
    let profile = store::data_dir().join("webview");
    let _ = std::fs::create_dir_all(&profile);
    if let Some(edge) = edge_path() {
        let args = format!(
            "--app={url} --window-size=1500,960 --user-data-dir=\"{}\" --no-first-run --no-default-browser-check --disable-features=Translate,msEdgeIdentityIntegration --disable-extensions",
            profile.to_string_lossy()
        );
        if let Some(pid) = win::spawn_hidden(&edge, &args) {
            WINDOW_PID.store(pid, Ordering::SeqCst);
            return;
        }
    }
    if !dist_ok {
        eprintln!("Интерфейс не найден. Соберите фронтенд: build.bat");
    }
    win::shell_open(&url, None);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Тесты не должны трогать реальные настройки пользователя: уводим данные
    /// во временный каталог до первого создания App.
    fn isolate_data_dir() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let dir = std::env::temp_dir().join("pc-sentinel-tests");
            let _ = std::fs::create_dir_all(&dir);
            std::env::set_var("PC_SENTINEL_DATA", &dir);
        });
    }

    fn state() -> Arc<Mutex<App>> {
        isolate_data_dir();
        Arc::new(Mutex::new(App::new()))
    }

    fn req(method: &str, path: &str, body: &str) -> http::Req {
        http::Req {
            method: method.into(),
            path: path.into(),
            body: body.into(),
            origin: None,
        }
    }

    fn req_from(origin: &str, method: &str, path: &str) -> http::Req {
        http::Req {
            method: method.into(),
            path: path.into(),
            body: String::new(),
            origin: Some(origin.into()),
        }
    }

    // ---------- Разбор JSON-полей ----------

    #[test]
    fn json_field_reads_string() {
        assert_eq!(
            json_field(r#"{"name":"Cyberpunk 2077"}"#, "name").as_deref(),
            Some("Cyberpunk 2077")
        );
    }

    #[test]
    fn json_field_reads_number_as_text() {
        assert_eq!(json_field(r#"{"pid":1234}"#, "pid").as_deref(), Some("1234"));
    }

    #[test]
    fn json_field_handles_escapes() {
        // Путь Windows приходит с экранированными обратными слэшами.
        let body = r#"{"path":"C:\\Games\\capture.csv"}"#;
        assert_eq!(
            json_field(body, "path").as_deref(),
            Some(r"C:\Games\capture.csv")
        );
    }

    #[test]
    fn json_field_handles_escaped_quote() {
        let body = r#"{"name":"a\"b"}"#;
        assert_eq!(json_field(body, "name").as_deref(), Some("a\"b"));
    }

    #[test]
    fn json_field_missing_key_is_none() {
        assert_eq!(json_field(r#"{"name":"x"}"#, "process"), None);
        assert_eq!(json_field("", "name"), None);
    }

    #[test]
    fn json_field_empty_string_stays_empty() {
        // Пустое значение — это команда «очистить профиль», а не отсутствие поля.
        assert_eq!(json_field(r#"{"name":""}"#, "name").as_deref(), Some(""));
    }

    #[test]
    fn num_field_parses_and_rejects() {
        assert_eq!(num_field(r#"{"pid":42}"#, "pid"), Some(42.0));
        assert_eq!(num_field(r#"{"pid":"abc"}"#, "pid"), None);
        assert_eq!(num_field(r#"{"other":1}"#, "pid"), None);
    }

    // ---------- Маршрутизация ----------

    #[test]
    fn busy_port_is_reported_not_silent() {
        // Порт занят: bind обязан вернуть ошибку, а не падать внутри.
        // На этом ломался запуск — приложение молча не стартовало.
        let first = http::bind(0).expect("не удалось занять свободный порт");
        let port = first.local_addr().expect("нет адреса").port();
        let second = http::bind(port);
        assert!(second.is_err(), "занятый порт не распознан");
        drop(first);
    }

    #[test]
    fn foreign_server_is_not_our_instance() {
        // На порту может отвечать чужая программа: её нельзя принять
        // за уже запущенный PC Sentinel.
        let listener = http::bind(0).expect("порт");
        let port = listener.local_addr().expect("адрес").port();
        std::thread::spawn(move || {
            http::serve_on(listener, |_| http::Body::Json("{\"hello\":1}".into()));
        });
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(!is_our_instance(port), "чужой сервер принят за свой");
    }

    #[test]
    fn unknown_api_route_is_not_found() {
        let st = state();
        match route(&req("GET", "/api/nope", ""), &st, &None) {
            http::Body::Error(400, _) => panic!("неизвестный маршрут не должен быть ошибкой 400"),
            http::Body::NotFound => {}
            _ => panic!("ожидался NotFound"),
        }
    }

    #[test]
    fn api_error_keeps_message() {
        // Импорт без пути — ошибка, и её текст должен дойти до интерфейса.
        let st = state();
        match route(&req("POST", "/api/fps/import", "{}"), &st, &None) {
            http::Body::Error(status, body) => {
                assert_eq!(status, 400);
                assert!(
                    body.contains("Не указан путь"),
                    "текст ошибки потерян: {body}"
                );
            }
            _ => panic!("ожидался Body::Error с текстом"),
        }
    }

    #[test]
    fn static_path_traversal_is_blocked() {
        let st = state();
        let dist = Some(PathBuf::from("D:\\glms\\dist"));
        match route(&req("GET", "/../agent/src/main.rs", ""), &st, &dist) {
            http::Body::NotFound => {}
            _ => panic!("выход за пределы dist должен блокироваться"),
        }
    }

    #[test]
    fn game_endpoint_roundtrip() {
        // Профиль живёт в общем файле настроек — берём блокировку и чистим его.
        let _guard = game::tests::test_lock();
        let st = state();
        st.lock().unwrap().game.clear_profile();
        // Пустой профиль — валидное состояние «ничего не настроено».
        let body = match route(&req("GET", "/api/game", ""), &st, &None) {
            http::Body::Json(text) => text,
            _ => panic!("ожидался JSON"),
        };
        assert!(body.contains("\"profile\":null"), "неожиданный ответ: {body}");
        assert!(body.contains("\"active\":false"));
    }

    #[test]
    fn settings_reject_unknown_keys() {
        let st = state();
        let before = {
            let app = st.lock().unwrap();
            app.settings.len()
        };
        let _ = route(
            &req("POST", "/api/settings", r#"{"evil_key":"1"}"#),
            &st,
            &None,
        );
        let after = {
            let app = st.lock().unwrap();
            app.settings.len()
        };
        assert_eq!(before, after, "посторонний ключ не должен сохраняться");
    }

    // ---------- HTTP-слой ----------

    #[test]
    fn mime_types_are_correct() {
        assert_eq!(http::mime_for("/main.js"), "text/javascript; charset=utf-8");
        assert_eq!(http::mime_for("/styles/app.css"), "text/css; charset=utf-8");
        assert_eq!(http::mime_for("/index.html"), "text/html; charset=utf-8");
        assert_eq!(http::mime_for("/x.bin"), "application/octet-stream");
    }

    // ---------- Защита локального API ----------

    #[test]
    fn origin_check_allows_local_and_absent() {
        assert!(origin_allowed(None));
        assert!(origin_allowed(Some("http://127.0.0.1:47821")));
        assert!(origin_allowed(Some("http://localhost:47821")));
        assert!(origin_allowed(Some("http://127.0.0.1")));
    }

    #[test]
    fn origin_check_rejects_foreign() {
        assert!(!origin_allowed(Some("https://evil.example")));
        assert!(!origin_allowed(Some("http://127.0.0.1.evil.example")));
        assert!(!origin_allowed(Some("null")));
        assert!(!origin_allowed(Some("file://")));
    }

    #[test]
    fn foreign_origin_cannot_call_api() {
        let st = state();
        match route(&req_from("https://evil.example", "POST", "/api/app/quit"), &st, &None) {
            http::Body::Error(403, _) => {}
            _ => panic!("запрос с чужого источника должен отклоняться"),
        }
    }

    #[test]
    fn local_origin_can_call_api() {
        let st = state();
        match route(&req_from("http://127.0.0.1:47821", "GET", "/api/game"), &st, &None) {
            http::Body::Json(_) => {}
            _ => panic!("локальный источник должен проходить"),
        }
    }

    #[test]
    fn server_returns_error_status_and_body() {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        // Отдельный порт, чтобы не мешать запущенному приложению.
        let port = 47991u16;
        std::thread::spawn(move || {
            http::serve(port, |r| {
                if r.path.starts_with("/api/") {
                    http::Body::Error(400, r#"{"error":"проверка"}"#.to_string())
                } else {
                    http::Body::NotFound
                }
            });
        });

        // Сервер поднимается в отдельном потоке — даём ему время на bind.
        let mut stream = None;
        for _ in 0..40 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                stream = Some(s);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let mut stream = stream.expect("сервер не поднялся");
        stream
            .write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "неверная строка статуса: {}",
            response.lines().next().unwrap_or("")
        );
        assert!(response.contains("проверка"), "тело ошибки потеряно");
    }
}
