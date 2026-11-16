//! Установка приложения: копирование файлов в LocalAppData и ярлыки.

use crate::shell::{create_shortcut, desktop_dir, start_menu_dir, Shortcut};
use crate::win;
use std::path::{Path, PathBuf};

pub fn app_dir() -> PathBuf {
    crate::store::data_dir().join("app")
}

fn copy_tree(from: &Path, to: &Path) -> Result<usize, String> {
    let mut copied = 0;
    std::fs::create_dir_all(to).map_err(|e| format!("не удалось создать {}: {e}", to.display()))?;

    let entries = std::fs::read_dir(from).map_err(|e| format!("не удалось прочитать {}: {e}", from.display()))?;
    for entry in entries.flatten() {
        let src = entry.path();
        let dst = to.join(entry.file_name());
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            copied += copy_tree(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)
                .map_err(|e| format!("не удалось скопировать {}: {e}", src.display()))?;
            copied += 1;
        }
    }
    Ok(copied)
}

fn copy_file(from: &Path, to: &Path) -> Result<bool, String> {
    if !from.exists() {
        return Ok(false);
    }
    if let (Ok(a), Ok(b)) = (from.canonicalize(), to.canonicalize()) {
        if a == b {
            return Ok(true);
        }
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::copy(from, to).map_err(|e| format!("не удалось скопировать {}: {e}", from.display()))?;
    Ok(true)
}

/// Заменяет файл, даже если он занят работающим процессом.
///
/// Windows не даёт перезаписать запущенный exe, но разрешает его
/// **переименовать**. Поэтому при ошибке «файл занят» старый файл уводится
/// в сторону, новый копируется на освободившееся место, а старый удаляется
/// при следующей установке (сейчас он ещё может быть занят).
fn replace_file(from: &Path, to: &Path) -> Result<bool, String> {
    if !from.exists() {
        return Ok(false);
    }
    if let (Ok(a), Ok(b)) = (from.canonicalize(), to.canonicalize()) {
        if a == b {
            return Ok(true);
        }
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    match std::fs::copy(from, to) {
        Ok(_) => return Ok(true),
        Err(e) if e.raw_os_error() == Some(32) => {}
        Err(e) => return Err(format!("не удалось скопировать {}: {e}", from.display())),
    }

    // Файл занят: уводим старый в сторону и копируем на его место.
    let backup = to.with_extension("old");
    let _ = std::fs::remove_file(&backup);
    std::fs::rename(to, &backup)
        .map_err(|e| format!("не удалось заменить {}: {e}", to.display()))?;
    std::fs::copy(from, to).map_err(|e| {
        // Возвращаем старый файл, чтобы приложение не осталось без exe.
        let _ = std::fs::rename(&backup, to);
        format!("не удалось скопировать {}: {e}", from.display())
    })?;
    // Старый файл ещё держит процесс — удалим при следующей установке.
    let _ = std::fs::remove_file(&backup);
    Ok(true)
}

/// Ищет каталог с ресурсами интерфейса рядом с текущим exe или в проекте.
fn locate_payload() -> Option<(PathBuf, PathBuf)> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            roots.push(dir.to_path_buf());
            if let Some(root) = dir.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
                roots.push(root.to_path_buf());
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd.clone());
        roots.push(cwd.join(".."));
    }

    for root in roots {
        let dist = root.join("dist");
        if dist.join("index.html").exists() {
            return Some((root, dist));
        }
    }
    None
}

pub struct InstallReport {
    pub app_dir: PathBuf,
    pub files: usize,
    pub shortcuts: Vec<String>,
    pub warnings: Vec<String>,
    pub already_installed: bool,
    /// Установщик остановил работавший экземпляр приложения.
    pub stopped_running: bool,
}

pub fn install() -> Result<InstallReport, String> {
    let exe = std::env::current_exe().map_err(|e| format!("не удалось определить путь exe: {e}"))?;
    let (root, dist) = locate_payload()
        .ok_or("не найден каталог dist с интерфейсом — соберите проект (build.bat)")?;

    let target = app_dir();
    std::fs::create_dir_all(&target).map_err(|e| format!("не удалось создать {target:?}: {e}"))?;

    let already_installed = match (exe.canonicalize(), target.join("pc-sentinel.exe").canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };

    // Запущенное приложение держит свой exe открытым, и скопировать поверх
    // нельзя: Windows отвечает «файл занят другим процессом». Поэтому перед
    // установкой останавливаем работающий экземпляр.
    let stopped = stop_running_instance(&target.join("pc-sentinel.exe"));

    let mut files = 0usize;
    if replace_file(&exe, &target.join("pc-sentinel.exe"))? {
        files += 1;
    }
    // Правила детекции лежат рядом с exe или в корне проекта
    for candidate in [root.join("rules.txt"), exe.parent().unwrap_or(Path::new(".")).join("rules.txt")] {
        if copy_file(&candidate, &target.join("rules.txt"))? {
            files += 1;
            break;
        }
    }
    // База подписей для встроенной проверки на вирусы.
    for candidate in [
        root.join("signatures.txt"),
        exe.parent().unwrap_or(Path::new(".")).join("signatures.txt"),
    ] {
        if copy_file(&candidate, &target.join("signatures.txt"))? {
            files += 1;
            break;
        }
    }
    // Правила детекции: эвристики PE и правила в стиле YARA.
    for name in ["heuristics.txt", "yara.txt"] {
        for candidate in [
            root.join(name),
            exe.parent().unwrap_or(Path::new(".")).join(name),
        ] {
            if copy_file(&candidate, &target.join(name))? {
                files += 1;
                break;
            }
        }
    }
    files += copy_tree(&dist, &target.join("dist"))?;

    let installed_exe = target.join("pc-sentinel.exe");
    let mut warnings = Vec::new();
    let mut shortcuts = Vec::new();

    let link = Shortcut {
        path: String::new(),
        target: installed_exe.to_string_lossy().to_string(),
        args: String::new(),
        workdir: target.to_string_lossy().to_string(),
        description: "Диагностика и оптимизация ПК".to_string(),
        icon: Some(installed_exe.to_string_lossy().to_string()),
    };

    let make_link = |dir: Option<String>, name: &str, list: &mut Vec<String>, warn: &mut Vec<String>| {
        let dir = match dir {
            Some(d) => d,
            None => {
                warn.push(format!("не удалось определить папку для ярлыка «{name}»"));
                return;
            }
        };
        let path = Path::new(&dir).join(format!("{name}.lnk"));
        let mut item = Shortcut {
            path: path.to_string_lossy().to_string(),
            target: link.target.clone(),
            args: link.args.clone(),
            workdir: link.workdir.clone(),
            description: link.description.clone(),
            icon: link.icon.clone(),
        };
        // Ярлык уже может существовать — перезаписываем
        match create_shortcut(&item) {
            Ok(()) => list.push(item.path.clone()),
            Err(e) => warn.push(format!("ярлык «{name}»: {e}")),
        }
        item.path.clear();
    };

    make_link(desktop_dir(), "PC Sentinel", &mut shortcuts, &mut warnings);
    make_link(start_menu_dir(), "PC Sentinel", &mut shortcuts, &mut warnings);

    // Запись в «Программы и компоненты»: без неё приложение нельзя удалить
    // штатным способом, и оно выглядит набором файлов, а не программой.
    register_uninstall(&target, &installed_exe, &mut warnings);

    Ok(InstallReport {
        app_dir: target,
        files,
        shortcuts,
        warnings,
        already_installed,
        stopped_running: stopped,
    })
}

/// Раздел реестра, по которому Windows показывает приложение в списке программ.
const UNINSTALL_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PCSentinel";

/// Останавливает запущенный экземпляр приложения, если он держит файл.
///
/// Сначала просим закрыться через API — так приложение успевает сохранить
/// настройки. Если не ответило, завершаем процесс принудительно.
fn stop_running_instance(target_exe: &Path) -> bool {
    let target = crate::win::long_path(&target_exe.to_string_lossy()).to_lowercase();
    let mut sampler = crate::sys::Sampler::new();
    let snap = sampler.sample();
    let pids: Vec<u32> = snap
        .procs
        .iter()
        .filter(|p| {
            // Путь процесса может прийти коротким (8.3) или пустым без прав —
            // тогда ориентируемся на имя файла.
            let path = crate::win::long_path(&p.path).to_lowercase();
            if !path.is_empty() {
                path == target
            } else {
                p.name.eq_ignore_ascii_case("pc-sentinel.exe")
            }
        })
        .map(|p| p.pid)
        .collect();
    if pids.is_empty() {
        return false;
    }

    // Мягкая остановка: приложение само завершится и закроет окно.
    let _ = crate::win::run_system_tool(
        "curl.exe",
        "-s -m 3 -X POST http://127.0.0.1:47821/api/app/quit",
    );
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(150));
        if pids.iter().all(|pid| !crate::win::process_alive(*pid)) {
            return true;
        }
    }
    for pid in &pids {
        crate::win::kill(*pid);
    }
    std::thread::sleep(std::time::Duration::from_millis(400));
    true
}

fn register_uninstall(target: &Path, exe: &Path, warnings: &mut Vec<String>) {
    let root = win::HKEY_CURRENT_USER;
    let exe_str = exe.to_string_lossy().to_string();
    let dir_str = target.to_string_lossy().to_string();
    let size_kb = dir_size(target) / 1024;

    let entries: [(&str, &str); 6] = [
        ("DisplayName", "PC Sentinel"),
        ("DisplayVersion", "1.0.0"),
        ("Publisher", "PC Sentinel"),
        ("DisplayIcon", &exe_str),
        ("InstallLocation", &dir_str),
        (
            "UninstallString",
            &format!("\"{exe_str}\" --uninstall"),
        ),
    ];
    let mut failed = false;
    for (name, value) in entries {
        if !win::reg_write_string(root, UNINSTALL_KEY, name, value) {
            failed = true;
        }
    }
    // EstimatedSize — в килобайтах, так Windows показывает размер программы.
    if !win::reg_write_dword(root, UNINSTALL_KEY, "EstimatedSize", size_kb as u32) {
        failed = true;
    }
    if !win::reg_write_dword(root, UNINSTALL_KEY, "NoModify", 1) {
        failed = true;
    }
    if !win::reg_write_dword(root, UNINSTALL_KEY, "NoRepair", 1) {
        failed = true;
    }
    if failed {
        warnings.push(
            "не удалось записать приложение в список установленных программ".to_string(),
        );
    }
}

/// Суммарный размер каталога в байтах.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            total += dir_size(&entry.path());
        } else {
            total += meta.len();
        }
    }
    total
}

pub fn uninstall() -> (Vec<String>, Vec<String>) {
    let mut removed = Vec::new();
    let mut warnings = Vec::new();

    // Убираем запись из «Программ и компонентов»: иначе после удаления
    // в списке остаётся пункт, который никуда не ведёт.
    if win::reg_delete_tree(win::HKEY_CURRENT_USER, UNINSTALL_KEY) {
        removed.push("запись в списке установленных программ".to_string());
    }

    for (dir, name) in [(desktop_dir(), "PC Sentinel"), (start_menu_dir(), "PC Sentinel")] {
        if let Some(dir) = dir {
            let path = Path::new(&dir).join(format!("{name}.lnk"));
            if path.exists() {
                match std::fs::remove_file(&path) {
                    Ok(()) => removed.push(path.to_string_lossy().to_string()),
                    Err(e) => warnings.push(format!("не удалось удалить {}: {e}", path.display())),
                }
            }
        }
    }

    let app = app_dir();
    if app.exists() {
        match std::fs::remove_dir_all(&app) {
            Ok(()) => removed.push(app.to_string_lossy().to_string()),
            Err(e) => warnings.push(format!("не удалось удалить {}: {e}", app.display())),
        }
    }

    (removed, warnings)
}

/// Завершает агент, когда окно приложения закрыто.
///
/// Следим не за PID процесса-лаунчера Edge, а за наличием самого окна:
/// при передаче запуска уже работающему браузеру лаунчер выходит сразу,
/// и ожидание его PID убивало агент при живом окне.
pub fn watch_window(title: &str) {
    let title = title.to_string();
    std::thread::spawn(move || {
        // Ждём появления окна: Edge поднимает его не мгновенно.
        let mut appeared = false;
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if win::window_with_title_exists(&title) {
                appeared = true;
                break;
            }
        }
        if !appeared {
            // Окно так и не появилось (например, запуск только API) — не мешаем работе.
            return;
        }

        // Окно закрыто, если его нет несколько проверок подряд:
        // так переживаем перерисовку и кратковременные пересоздания окна.
        let mut missing = 0u32;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if win::window_with_title_exists(&title) {
                missing = 0;
            } else {
                missing += 1;
                if missing >= 3 {
                    std::process::exit(0);
                }
            }
        }
    });
}
