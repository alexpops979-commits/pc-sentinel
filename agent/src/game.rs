//! Игровой профиль: оптимизация включается только пока запущена выбранная игра.
//!
//! Пользователь вводит название игры, агент запоминает её процесс. Пока процесс
//! жив — включается схема высокой производительности и повышенный приоритет
//! процесса игры. Как только игра закрылась, всё возвращается как было:
//! прежняя схема электропитания восстанавливается, приоритет сбрасывается
//! вместе с завершением процесса.

use crate::json::J;
use crate::store;
use crate::win::*;
use std::ffi::c_void;

/// GUID схемы электропитания.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

/// Схема «Высокая производительность» (SCHEME_MIN).
const HIGH_PERFORMANCE: Guid = Guid {
    data1: 0x8c5e7fda,
    data2: 0xe8bf,
    data3: 0x4a96,
    data4: [0x9a, 0x85, 0xa6, 0xe2, 0x3a, 0x8c, 0x63, 0x5c],
};

const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;
const PROCESS_SET_INFORMATION: u32 = 0x0200;

type PowerGetActiveScheme = unsafe extern "system" fn(*mut c_void, *mut *mut Guid) -> u32;
type PowerSetActiveScheme = unsafe extern "system" fn(*mut c_void, *const Guid) -> u32;
type LocalFreeFn = unsafe extern "system" fn(*mut c_void) -> *mut c_void;

struct PowerApi {
    _lib: DynLib,
    _kernel: DynLib,
    get: PowerGetActiveScheme,
    set: PowerSetActiveScheme,
    free: LocalFreeFn,
}

// Указатели на функции из powrprof.dll безопасно передавать между потоками:
// сами вызовы не держат состояния, а DLL загружена на всё время жизни процесса.
unsafe impl Send for PowerApi {}

impl PowerApi {
    fn new() -> Option<PowerApi> {
        let lib = DynLib::load("powrprof.dll")?;
        // LocalFree живёт в kernel32, а не в powrprof — иначе вся проверка
        // молча падала бы и схема питания не переключалась.
        let kernel = DynLib::load("kernel32.dll")?;
        unsafe {
            let get: PowerGetActiveScheme = std::mem::transmute(lib.sym("PowerGetActiveScheme")?);
            let set: PowerSetActiveScheme = std::mem::transmute(lib.sym("PowerSetActiveScheme")?);
            let free: LocalFreeFn = std::mem::transmute(kernel.sym("LocalFree")?);
            Some(PowerApi {
                _lib: lib,
                _kernel: kernel,
                get,
                set,
                free,
            })
        }
    }

    fn active(&self) -> Option<Guid> {
        let mut ptr: *mut Guid = std::ptr::null_mut();
        let rc = unsafe { (self.get)(std::ptr::null_mut(), &mut ptr) };
        if rc != 0 || ptr.is_null() {
            return None;
        }
        let value = unsafe { *ptr };
        unsafe { (self.free)(ptr as *mut c_void) };
        Some(value)
    }

    fn set(&self, scheme: &Guid) -> bool {
        unsafe { (self.set)(std::ptr::null_mut(), scheme) == 0 }
    }
}

/// Что именно сделано для игры — показывается в интерфейсе.
#[derive(Clone, Default)]
pub struct Applied {
    pub power: bool,
    pub priority: bool,
}

pub struct GameProfile {
    /// Как игру назвал пользователь.
    pub name: String,
    /// Имя процесса, по которому ищем запуск (например, `Cyberpunk2077.exe`).
    pub process: String,
    /// Папка игры, если профиль задан путём. Пусто — профиль задан вручную.
    pub path: String,
}

pub struct GameState {
    pub profile: Option<GameProfile>,
    /// Игра сейчас запущена.
    pub running: bool,
    /// Оптимизация включена прямо сейчас.
    pub active: bool,
    /// Когда включили (unix-время), 0 — не включена.
    pub since: u64,
    pub applied: Applied,
    /// Схема, которая была до включения, — её и восстанавливаем.
    previous_scheme: Option<Guid>,
    /// Последняя ошибка применения, чтобы не врать «всё включено».
    pub error: Option<String>,
    power: Option<PowerApi>,
}

impl GameState {
    pub fn new() -> GameState {
        let profile = load_profile();
        GameState {
            profile,
            running: false,
            active: false,
            since: 0,
            applied: Applied::default(),
            previous_scheme: None,
            error: None,
            power: PowerApi::new(),
        }
    }

    pub fn set_profile(&mut self, name: &str, process: &str) {
        let name = name.trim();
        let process = process.trim();
        if name.is_empty() || process.is_empty() {
            self.clear_profile();
            return;
        }
        // Игра сменилась — сначала честно откатываем прошлую оптимизацию.
        if self.active {
            self.revert();
        }
        self.profile = Some(GameProfile {
            name: name.to_string(),
            process: process.to_string(),
            path: String::new(),
        });
        save_profile(self.profile.as_ref());
        self.error = None;
    }

    /// Профиль по папке игры: исполняемый файл агент находит сам.
    pub fn set_profile_from_path(&mut self, path: &str) -> Result<(), String> {
        let raw = path.trim().trim_matches('"');
        if raw.is_empty() {
            return Err("Укажите папку с игрой".into());
        }
        let dir = std::path::PathBuf::from(raw);
        if !dir.is_dir() {
            return Err(format!("Папка не найдена: {raw}"));
        }
        let exe = find_main_exe(&dir)
            .ok_or_else(|| format!("В папке {raw} не найдено ни одного исполняемого файла"))?;
        // Название берём из имени папки; для корня диска — из имени exe.
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| exe.trim_end_matches(".exe").to_string());

        if self.active {
            self.revert();
        }
        self.profile = Some(GameProfile {
            name,
            process: exe,
            path: raw.to_string(),
        });
        save_profile(self.profile.as_ref());
        self.error = None;
        Ok(())
    }

    pub fn clear_profile(&mut self) {
        if self.active {
            self.revert();
        }
        self.profile = None;
        save_profile(None);
        self.running = false;
        self.error = None;
    }

    /// Вызывается из фонового такта: включает и выключает оптимизацию.
    pub fn tick(&mut self) {
        let profile = match &self.profile {
            Some(p) => p,
            None => {
                self.running = false;
                return;
            }
        };
        let found = find_process(&profile.process);
        self.running = found.is_some();
        match (self.running, self.active) {
            (true, false) => {
                let pid = found.unwrap_or(0);
                self.apply(pid);
            }
            (false, true) => self.revert(),
            _ => {}
        }
    }

    fn apply(&mut self, pid: u32) {
        let mut applied = Applied::default();
        let mut errors: Vec<String> = Vec::new();

        if let Some(power) = &self.power {
            let previous = power.active();
            if power.set(&HIGH_PERFORMANCE) {
                applied.power = true;
                self.previous_scheme = previous;
            } else {
                errors.push("не удалось включить схему высокой производительности".into());
            }
        } else {
            errors.push("служба электропитания недоступна".into());
        }

        if pid != 0 {
            unsafe {
                let h = OpenProcess(PROCESS_SET_INFORMATION, 0, pid);
                if !h.is_null() {
                    let ok = SetPriorityClass(h, HIGH_PRIORITY_CLASS);
                    CloseHandle(h);
                    if ok != 0 {
                        applied.priority = true;
                    } else {
                        errors.push("не удалось поднять приоритет игры".into());
                    }
                } else {
                    errors.push("нет доступа к процессу игры (нужны права администратора)".into());
                }
            }
        }

        self.active = applied.power || applied.priority;
        self.applied = applied;
        self.since = if self.active { store::now_unix() } else { 0 };
        self.error = if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        };
    }

    fn revert(&mut self) {
        if let (Some(power), Some(previous)) = (&self.power, self.previous_scheme) {
            power.set(&previous);
        }
        self.previous_scheme = None;
        self.applied = Applied::default();
        self.active = false;
        self.since = 0;
    }

    pub fn to_json(&self) -> J {
        let profile = match &self.profile {
            Some(p) => J::obj(vec![
                ("name", J::s(p.name.clone())),
                ("process", J::s(p.process.clone())),
                ("path", J::s(p.path.clone())),
            ]),
            None => J::Null,
        };
        J::obj(vec![
            ("profile", profile),
            ("running", J::Bool(self.running)),
            ("active", J::Bool(self.active)),
            ("since", J::Int(self.since as i64)),
            (
                "applied",
                J::obj(vec![
                    ("power", J::Bool(self.applied.power)),
                    ("priority", J::Bool(self.applied.priority)),
                ]),
            ),
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

impl Drop for GameState {
    fn drop(&mut self) {
        // Приложение закрывают во время игры — не оставляем чужую схему питания.
        if self.active {
            self.revert();
        }
    }
}

fn load_profile() -> Option<GameProfile> {
    let settings = store::load_settings();
    let name = settings.get("game_name")?.trim().to_string();
    let process = settings.get("game_process")?.trim().to_string();
    if name.is_empty() || process.is_empty() {
        return None;
    }
    let path = settings.get("game_path").cloned().unwrap_or_default();
    Some(GameProfile {
        name,
        process,
        path,
    })
}

fn save_profile(profile: Option<&GameProfile>) {
    let mut settings = store::load_settings();
    match profile {
        Some(p) => {
            settings.insert("game_name".into(), p.name.clone());
            settings.insert("game_process".into(), p.process.clone());
            if p.path.is_empty() {
                settings.remove("game_path");
            } else {
                settings.insert("game_path".into(), p.path.clone());
            }
        }
        None => {
            settings.remove("game_name");
            settings.remove("game_process");
            settings.remove("game_path");
        }
    }
    store::save_settings(&settings);
}

/// Файлы, которые лежат рядом с игрой, но игрой не являются.
const SKIP_EXE: &[&str] = &[
    "unins",
    "uninstall",
    "setup",
    "install",
    "vcredist",
    "vc_redist",
    "dxsetup",
    "dxwebsetup",
    "dotnet",
    "directx",
    "crashreport",
    "crashhandler",
    "crashpad",
    "report",
    "eula",
    "readme",
    "update",
    "helper",
    "benchmark",
    "service",
    "tracing",
    "elevated",
    "telemetry",
    "diagnostic",
    "notification",
];

/// Суффиксы служебных сборок: `Game_BE.exe` — античит, `chrmstp` — служба
/// обновления. Это не сама игра, хотя бывает крупнее её.
const SKIP_EXE_SUFFIX: &[&str] = &["_be", "stp", "_eac", "_d3d12", "_vulkan"];

/// Ищет главный исполняемый файл игры в папке.
///
/// Сначала пробуем совпадение имени exe с именем папки (так у большинства игр),
/// иначе берём самый крупный `.exe` — он и есть игра, а не установщик.
/// Глубина ограничена, чтобы не обходить весь диск целиком.
pub fn find_main_exe(root: &std::path::Path) -> Option<String> {
    const MAX_DEPTH: usize = 3;
    const MAX_ENTRIES: usize = 6000;

    let folder = root
        .file_name()
        .map(|n| normalize(&n.to_string_lossy()))
        .unwrap_or_default();
    // (имя, размер, глубина вложенности)
    let mut candidates: Vec<(String, u64, usize)> = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;

    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH || visited > MAX_ENTRIES {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_ENTRIES {
                break;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push((entry.path(), depth + 1));
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let lower = name.to_lowercase();
            if !lower.ends_with(".exe") {
                continue;
            }
            if SKIP_EXE.iter().any(|s| lower.contains(s)) {
                continue;
            }
            let stem = lower.trim_end_matches(".exe");
            if SKIP_EXE_SUFFIX.iter().any(|s| stem.ends_with(s)) {
                continue;
            }
            candidates.push((name, meta.len(), depth));
        }
    }

    if candidates.is_empty() {
        return None;
    }
    // Сначала точное совпадение с папкой, затем «имя похоже на папку»,
    // и только потом размер — он надёжен лишь как последний довод.
    let rank = |name: &str| -> u8 {
        let stem = normalize(name);
        if stem.is_empty() || folder.is_empty() {
            return 1;
        }
        if stem == folder {
            return 3;
        }
        if folder.contains(&stem) || stem.contains(&folder) {
            return 2;
        }
        1
    };
    candidates
        .into_iter()
        // Ближе к корню папки — вероятнее главный файл; глубина важнее размера.
        .max_by_key(|(name, size, depth)| (rank(name), usize::MAX - depth, *size))
        .map(|(name, _, _)| name)
}

/// Ищет процесс игры по имени. Сравнение без учёта регистра и без `.exe`,
/// чтобы «Cyberpunk 2077» находил `Cyberpunk2077.exe`.
pub fn find_process(needle: &str) -> Option<u32> {
    let target = normalize(needle);
    if target.is_empty() {
        return None;
    }
    unsafe {
        let snap = CreateToolhelp32Snapshot(0x0000_0002, 0); // TH32CS_SNAPPROCESS
        if snap.is_null() {
            return None;
        }
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut ok = Process32FirstW(snap, &mut entry);
        while ok != 0 {
            let end = entry
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = from_wide(&entry.szExeFile[..end]);
            if normalize(&name) == target {
                found = Some(entry.th32ProcessID);
                break;
            }
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            ok = Process32NextW(snap, &mut entry);
        }
        CloseHandle(snap);
        found
    }
}

/// Приводит имя к сравнимому виду: нижний регистр, без пробелов и `.exe`.
fn normalize(name: &str) -> String {
    let lower = name.trim().to_lowercase();
    let lower = lower.strip_suffix(".exe").unwrap_or(&lower);
    lower.chars().filter(|c| !c.is_whitespace()).collect()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Профиль хранится в общем файле настроек, поэтому тесты, которые его
    /// меняют, должны идти по очереди — иначе они перетирают друг друга.
    pub fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Чистое состояние: чужой профиль из предыдущего теста не должен мешать.
    fn fresh_state() -> GameState {
        let mut state = GameState::new();
        state.clear_profile();
        state
    }

    #[test]
    fn normalize_ignores_case_spaces_and_exe() {
        assert_eq!(normalize("Cyberpunk2077.exe"), "cyberpunk2077");
        assert_eq!(normalize("  CYBERPUNK2077.EXE "), "cyberpunk2077");
        assert_eq!(normalize("Cyberpunk 2077"), "cyberpunk2077");
        assert_eq!(normalize("Cyberpunk 2077.exe"), "cyberpunk2077");
    }

    #[test]
    fn normalize_keeps_other_extensions() {
        // .bat — не .exe, суффикс не отрезаем.
        assert_eq!(normalize("run.bat"), "run.bat");
    }

    #[test]
    fn normalize_empty_is_empty() {
        assert_eq!(normalize(""), "");
        assert_eq!(normalize("   "), "");
    }

    #[test]
    fn find_process_ignores_unknown_name() {
        // Такого процесса нет ни на одной машине — поиск обязан вернуть None,
        // а не первый попавшийся.
        assert_eq!(find_process("pc-sentinel-no-such-process-xyz.exe"), None);
        assert_eq!(find_process(""), None);
    }

    #[test]
    fn find_process_locates_self() {
        // Собственный процесс виден в снимке — проверяем, что поиск работает.
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default();
        if exe.is_empty() {
            return;
        }
        let pid = find_process(&exe);
        assert!(pid.is_some(), "не найден собственный процесс {exe}");
        assert_eq!(pid, Some(std::process::id()));
    }

    // ---------- Поиск исполняемого файла игры ----------

    /// Временная папка, которая удаляется сама: иначе тестовые `.exe` остаются
    /// в `%TEMP%` и попадают в быструю проверку на вирусы.
    struct TempDir(std::path::PathBuf);

    impl std::ops::Deref for TempDir {
        type Target = std::path::PathBuf;
        fn deref(&self) -> &std::path::PathBuf {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Временная папка с заданным набором файлов.
    fn temp_game_dir(name: &str, files: &[(&str, usize)]) -> TempDir {
        let dir = std::env::temp_dir()
            .join("pc-sentinel-tests")
            .join("games")
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (file, size) in files {
            let path = dir.join(file);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, vec![0u8; *size]).unwrap();
        }
        TempDir(dir)
    }

    #[test]
    fn find_main_exe_prefers_folder_name() {
        // Игра называется как папка, хотя рядом лежит файл крупнее.
        let dir = temp_game_dir(
            "Cyberpunk 2077",
            &[
                ("Cyberpunk2077.exe", 100),
                ("bigtool.exe", 5000),
                ("data/pack.bin", 10),
            ],
        );
        assert_eq!(find_main_exe(&dir).as_deref(), Some("Cyberpunk2077.exe"));
    }

    #[test]
    fn find_main_exe_falls_back_to_largest() {
        let dir = temp_game_dir(
            "SomeGame",
            &[("small.exe", 10), ("game.exe", 900), ("readme.txt", 5000)],
        );
        assert_eq!(find_main_exe(&dir).as_deref(), Some("game.exe"));
    }

    #[test]
    fn find_main_exe_skips_installers() {
        // Установщик крупнее игры — его брать нельзя.
        let dir = temp_game_dir(
            "GameWithSetup",
            &[
                ("game.exe", 100),
                ("unins000.exe", 9000),
                ("vcredist_x64.exe", 8000),
                ("dxsetup.exe", 7000),
            ],
        );
        assert_eq!(find_main_exe(&dir).as_deref(), Some("game.exe"));
    }

    #[test]
    fn find_main_exe_skips_service_stubs() {
        // Реальный случай: в папке Chrome служба обновления крупнее браузера.
        let dir = temp_game_dir(
            "Application",
            &[("chrome.exe", 3000), ("chrmstp.exe", 4000)],
        );
        assert_eq!(find_main_exe(&dir).as_deref(), Some("chrome.exe"));
    }

    #[test]
    fn find_main_exe_skips_anticheat() {
        let dir = temp_game_dir(
            "SomeGame",
            &[("SomeGame.exe", 500), ("SomeGame_BE.exe", 900)],
        );
        assert_eq!(find_main_exe(&dir).as_deref(), Some("SomeGame.exe"));
    }

    #[test]
    fn find_main_exe_prefers_name_similar_to_folder() {
        // Папка «Cyberpunk 2077 v2», файл «Cyberpunk2077.exe» — совпадение по имени
        // важнее размера. Имя папки отличается от соседнего теста, иначе они
        // гоняются за один временный каталог.
        let dir = temp_game_dir(
            "Cyberpunk 2077 v2",
            &[("Cyberpunk2077.exe", 100), ("tool.exe", 9000)],
        );
        assert_eq!(find_main_exe(&dir).as_deref(), Some("Cyberpunk2077.exe"));
    }

    #[test]
    fn find_main_exe_searches_subfolders() {
        let dir = temp_game_dir(
            "Nested",
            &[("bin/win64/Game.exe", 300), ("launcher.txt", 10)],
        );
        assert_eq!(find_main_exe(&dir).as_deref(), Some("Game.exe"));
    }

    #[test]
    fn find_main_exe_returns_none_without_exe() {
        let dir = temp_game_dir("NoExe", &[("readme.txt", 10), ("data.pak", 20)]);
        assert_eq!(find_main_exe(&dir), None);
    }

    #[test]
    fn set_profile_from_path_rejects_missing_folder() {
        let _guard = test_lock();
        let mut state = fresh_state();
        let err = state
            .set_profile_from_path("Z:\\no-such-game-folder-xyz")
            .unwrap_err();
        assert!(err.contains("не найдена"), "неожиданная ошибка: {err}");
        assert!(state.profile.is_none());
    }

    #[test]
    fn set_profile_from_path_rejects_empty() {
        let _guard = test_lock();
        let mut state = fresh_state();
        assert!(state.set_profile_from_path("   ").is_err());
    }

    #[test]
    fn set_profile_from_path_fills_name_and_process() {
        let _guard = test_lock();
        let dir = temp_game_dir("Hades", &[("Hades.exe", 400), ("unins000.exe", 900)]);
        let mut state = fresh_state();
        state.set_profile_from_path(&dir.to_string_lossy()).unwrap();
        let profile = state.profile.as_ref().expect("профиль не создан");
        assert_eq!(profile.name, "Hades");
        assert_eq!(profile.process, "Hades.exe");
        assert_eq!(profile.path, dir.to_string_lossy());
        state.clear_profile();
    }
}
