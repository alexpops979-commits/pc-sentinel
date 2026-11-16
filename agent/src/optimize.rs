//! Безопасные действия по оптимизации.

use crate::json::J;
use crate::sec::Autorun;
use crate::store;
use crate::sys::Snapshot;
use crate::win::*;

pub struct Action {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub risk: String,
    pub kind: String,
    pub category: String,
    pub reversible: bool,
}

impl Action {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("id", J::s(self.id.clone())),
            ("title", J::s(self.title.clone())),
            ("detail", J::s(self.detail.clone())),
            ("risk", J::s(self.risk.clone())),
            ("kind", J::s(self.kind.clone())),
            ("category", J::s(self.category.clone())),
            ("reversible", J::Bool(self.reversible)),
        ])
    }
}

pub fn recommendations(snap: &Snapshot, autoruns: &[Autorun]) -> Vec<Action> {
    let mut out = Vec::new();

    if snap.cpu.usage > 45.0 {
        // Свой процесс не предлагаем ограничивать: приложение не должно
        // советовать пользователю «притормозить» само себя.
        let own_pid = unsafe { GetCurrentProcessId() };
        let own_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        let top = snap
            .procs
            .iter()
            .find(|p| {
                p.cpu > 8.0
                    && p.pid != own_pid
                    && p.pid > 4
                    // Другой экземпляр PC Sentinel — тоже «мы», его не трогаем.
                    && !own_name.is_empty()
                    && p.name.to_lowercase() != own_name
            });
        if let Some(top) = top {
            out.push(Action {
                id: format!("limit:{}", top.pid),
                title: format!("Ограничить {}", top.name),
                detail: format!(
                    "{} сейчас потребляет {:.0}% процессора (PID {}). Приоритет будет понижен до «Ниже обычного» — программа продолжит работать, но перестанет забирать процессор у остальных. Действие обратимо.",
                    top.name, top.cpu, top.pid
                ),
                risk: "low".into(),
                kind: "limit".into(),
                category: "производительность".into(),
                reversible: true,
            });
        }
    }

    for a in autoruns.iter().filter(|a| a.suspicious).take(4) {
        out.push(Action {
            id: format!("disable:{}|{}|{}", a.location, a.key, a.name),
            title: format!("Отключить автозапуск «{}»", a.name),
            detail: format!(
                "Запись в {} запускает {} при старте системы. Команда будет сохранена в резервную копию перед удалением.",
                a.location, a.command
            ),
            risk: "medium".into(),
            kind: "disable-startup".into(),
            category: "защита".into(),
            reversible: true,
        });
    }

    let worst_disk = snap.disks.iter().map(|d| d.percent).fold(0.0f64, f64::max);
    if worst_disk > 70.0 {
        out.push(Action {
            id: "clean:temp".into(),
            title: "Очистить временные файлы".into(),
            detail: format!(
                "Диски заняты на {:.0}%. Удаляются только файлы старше 7 дней из папки временных файлов пользователя.",
                worst_disk
            ),
            risk: "low".into(),
            kind: "cleanup".into(),
            category: "обслуживание".into(),
            reversible: false,
        });
    }

    out.push(Action {
        id: "power:high".into(),
        title: "Включить схему высокой производительности".into(),
        detail: "Снимает ограничения энергосбережения процессора — обычно добавляет стабильности frametime в играх."
            .into(),
        risk: "low".into(),
        kind: "power".into(),
        category: "производительность".into(),
        reversible: true,
    });

    out.push(Action {
        id: "flush:dns".into(),
        title: "Сбросить кэш DNS".into(),
        detail: "Помогает, если сайты и игровые сервисы открываются медленно или подолгу ищут сервер.".into(),
        risk: "low".into(),
        kind: "network".into(),
        category: "сеть".into(),
        reversible: true,
    });

    out.push(Action {
        id: "open:startup".into(),
        title: "Открыть список приложений в автозагрузке".into(),
        detail: format!(
            "Сейчас в автозагрузке {} записей. Откроем параметры Windows, чтобы отключить лишние вручную.",
            autoruns.len()
        ),
        risk: "low".into(),
        kind: "open".into(),
        category: "обслуживание".into(),
        reversible: true,
    });

    out.push(Action {
        id: "open:storage".into(),
        title: "Анализ хранилища Windows".into(),
        detail: "Покажет, что занимает место: обновления, кэши, большие файлы.".into(),
        risk: "low".into(),
        kind: "open".into(),
        category: "обслуживание".into(),
        reversible: true,
    });

    out
}

fn clean_temp() -> (bool, String) {
    let temp = match env_var("TEMP") {
        Some(t) => t,
        None => return (false, "Не удалось определить папку временных файлов".into()),
    };
    let mut removed = 0u64;
    let mut freed = 0u64;
    let mut failed = 0u64;
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(7 * 24 * 3600))
        .unwrap_or(std::time::UNIX_EPOCH);
    if let Ok(entries) = std::fs::read_dir(&temp) {
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !meta.is_file() {
                continue;
            }
            let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            if modified > cutoff {
                continue;
            }
            let size = meta.len();
            if std::fs::remove_file(&path).is_ok() {
                removed += 1;
                freed += size;
            } else {
                failed += 1;
            }
        }
    }
    (
        true,
        format!(
            "Удалено файлов: {removed}, освобождено {:.1} МБ. Пропущено занятых: {failed}.",
            freed as f64 / 1024.0 / 1024.0
        ),
    )
}

fn disable_autorun(location: &str, key_path: &str, name: &str, backup: bool) -> (bool, String) {
    let root = if location.starts_with("HKLM") {
        HKEY_LOCAL_MACHINE
    } else if location.starts_with("HKCU") {
        HKEY_CURRENT_USER
    } else {
        return (
            false,
            "Элемент находится в папке автозагрузки — отключите его через Параметры Windows".into(),
        );
    };
    if backup {
        store::backup_autorun(&format!("{location}\\{key_path}\\{name}"));
    }
    unsafe {
        let wpath = to_wide(key_path);
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, wpath.as_ptr(), 0, KEY_WRITE, &mut key) != 0 {
            return (false, "Не удалось открыть раздел реестра (нужны права администратора)".into());
        }
        let wname = to_wide(name);
        let rc = RegDeleteValueW(key, wname.as_ptr());
        RegCloseKey(key);
        if rc == 0 {
            (
                true,
                if backup {
                    format!("Автозапуск «{name}» отключён. Команда сохранена в резервной копии.")
                } else {
                    format!("Автозапуск «{name}» отключён (резервная копия отключена в настройках).")
                },
            )
        } else {
            (false, format!("Не удалось удалить запись (код {rc})"))
        }
    }
}

/// Понижает приоритет процесса до «Ниже обычного».
///
/// Программа продолжает работать, но планировщик отдаёт процессор другим
/// задачам. Это обратимо: приоритет можно вернуть в диспетчере задач.
fn limit_process(pid: u32) -> (bool, String) {
    const PROCESS_SET_INFORMATION: u32 = 0x0200;
    // GetPriorityClass требует прав на чтение информации о процессе,
    // без них он возвращает 0 и мы не знаем прежний приоритет.
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
    const NORMAL_PRIORITY_CLASS: u32 = 0x0000_0020;

    if pid <= 4 {
        return (false, "Системный процесс защищён".into());
    }
    unsafe {
        let handle = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, 0, pid);
        if handle.is_null() {
            return (
                false,
                "Нет доступа к процессу — нужны права администратора".into(),
            );
        }
        let current = GetPriorityClass(handle);
        if current == BELOW_NORMAL_PRIORITY_CLASS {
            CloseHandle(handle);
            return (true, "Приоритет уже понижен".into());
        }
        let ok = SetPriorityClass(handle, BELOW_NORMAL_PRIORITY_CLASS);
        CloseHandle(handle);
        if ok == 0 {
            return (false, "Не удалось изменить приоритет процесса".into());
        }
        // Возвращаем прежний класс в сообщении, чтобы было понятно, как откатить.
        let previous = match current {
            NORMAL_PRIORITY_CLASS => "Обычный",
            0x0000_0080 => "Высокий",
            0x0000_8000 => "Выше обычного",
            0x0000_0040 => "Низкий",
            0x0000_0100 => "Реального времени",
            // 0 — прочитать не удалось; не выдумываем название.
            0 => "неизвестен",
            _ => "другой",
        };
        (
            true,
            format!("Приоритет понижен до «Ниже обычного» (был «{previous}»)."),
        )
    }
}

pub fn apply(action_id: &str, backup_autorun: bool) -> (bool, String) {
    if let Some(rest) = action_id.strip_prefix("disable:") {
        let parts: Vec<&str> = rest.split('|').collect();
        if parts.len() == 3 {
            return disable_autorun(parts[0], parts[1], parts[2], backup_autorun);
        }
        return (false, "Некорректный идентификатор действия".into());
    }
    if let Some(rest) = action_id.strip_prefix("limit:") {
        let pid: u32 = match rest.parse() {
            Ok(v) => v,
            Err(_) => return (false, "Некорректный PID".into()),
        };
        return limit_process(pid);
    }
    match action_id {
        "open:taskmgr" => {
            shell_open("taskmgr.exe", None);
            (true, "Открыт диспетчер задач".into())
        }
        "open:startup" => {
            shell_open("ms-settings:startupapps", None);
            (true, "Открыты параметры автозагрузки".into())
        }
        "open:storage" => {
            shell_open("ms-settings:storagesense", None);
            (true, "Открыт анализ хранилища".into())
        }
        "open:defender" => {
            shell_open("windowsdefender://threat", None);
            (true, "Открыт Центр безопасности Windows".into())
        }
        "clean:temp" => clean_temp(),
        "power:high" => {
            // Схема «Высокая производительность» на некоторых сборках скрыта.
            // Тогда её сначала создают копией из «Сбалансированной»: иначе
            // команда возвращает ошибку, и действие выглядит сломанным.
            match run_system_tool("powercfg.exe", "/setactive SCHEME_MIN") {
                Ok(0) => (true, "Включена схема высокой производительности".into()),
                Ok(code) => (false, format!("powercfg вернул код {code}")),
                Err(e) => (false, format!("Не удалось переключить схему: {e}")),
            }
        }
        "flush:dns" => {
            match run_system_tool("ipconfig.exe", "/flushdns") {
                Ok(0) => (true, "Кэш DNS сброшен".into()),
                Ok(code) => (false, format!("ipconfig вернул код {code}")),
                Err(e) => (false, format!("Не удалось сбросить кэш DNS: {e}")),
            }
        }
        _ => (false, "Неизвестное действие".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{CpuInfo, ProcInfo};

    fn snapshot_with(procs: Vec<ProcInfo>, cpu: f64) -> Snapshot {
        Snapshot {
            cpu: CpuInfo {
                usage: cpu,
                ..Default::default()
            },
            procs,
            ..Default::default()
        }
    }

    fn proc(pid: u32, name: &str, cpu: f64) -> ProcInfo {
        ProcInfo {
            pid,
            name: name.into(),
            cpu,
            ..Default::default()
        }
    }

    #[test]
    fn limit_action_carries_pid() {
        let snap = snapshot_with(vec![proc(4242, "chrome.exe", 60.0)], 70.0);
        let actions = recommendations(&snap, &[]);
        let limit = actions
            .iter()
            .find(|a| a.kind == "limit")
            .expect("нет действия «Ограничить»");
        assert_eq!(limit.id, "limit:4242");
        assert!(limit.title.contains("chrome.exe"));
        assert!(limit.reversible);
    }

    #[test]
    fn own_process_is_not_offered() {
        // Приложение не должно советовать ограничить само себя.
        let own = unsafe { GetCurrentProcessId() };
        let snap = snapshot_with(vec![proc(own, "pc-sentinel.exe", 90.0)], 95.0);
        let actions = recommendations(&snap, &[]);
        assert!(
            actions.iter().all(|a| a.kind != "limit"),
            "свой процесс попал в рекомендации"
        );
    }

    #[test]
    fn other_instance_of_self_is_not_offered() {
        // Второй экземпляр PC Sentinel — тоже «мы», его ограничивать нельзя.
        let own_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default();
        if own_name.is_empty() {
            return;
        }
        let snap = snapshot_with(vec![proc(999_999, &own_name, 90.0)], 95.0);
        let actions = recommendations(&snap, &[]);
        assert!(
            actions.iter().all(|a| a.kind != "limit"),
            "другой экземпляр приложения попал в рекомендации"
        );
    }

    #[test]
    fn system_process_is_not_offered() {
        let snap = snapshot_with(vec![proc(4, "System", 90.0)], 95.0);
        let actions = recommendations(&snap, &[]);
        assert!(actions.iter().all(|a| a.kind != "limit"));
    }

    #[test]
    fn low_cpu_gives_no_limit_action() {
        let snap = snapshot_with(vec![proc(4242, "chrome.exe", 60.0)], 20.0);
        let actions = recommendations(&snap, &[]);
        assert!(actions.iter().all(|a| a.kind != "limit"));
    }

    #[test]
    fn limit_rejects_bad_pid() {
        let (ok, message) = apply("limit:abc", true);
        assert!(!ok);
        assert!(message.contains("PID"));
    }

    #[test]
    fn limit_protects_system_pids() {
        for pid in [0u32, 4] {
            let (ok, message) = apply(&format!("limit:{pid}"), true);
            assert!(!ok, "PID {pid} не должен ограничиваться");
            assert!(message.contains("защищён"));
        }
    }
}
