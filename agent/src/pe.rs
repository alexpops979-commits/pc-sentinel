//! Разбор PE-файлов: секции, энтропия, импорты, признаки упаковки.
//!
//! Это статический анализ — то, чем занимается любой антивирус до запуска
//! файла. Мы не эмулируем код (это отдельная большая задача), но разбираем
//! структуру: где лежит код, что файл импортирует, не сжат ли он упаковщиком
//! и не спрятан ли полезный груз после последней секции.
//!
//! Все чтения проверяются по границам: повреждённый файл не должен ронять
//! проверку, он должен просто не разобраться.

/// Секция PE-файла.
#[derive(Clone, Default)]
pub struct Section {
    pub name: String,
    /// Адрес секции в памяти (RVA). Именно по нему, а не по смещению в файле,
    /// адресуются каталоги данных — импорт, TLS, ресурсы.
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
    /// Энтропия содержимого секции, 0..8. Выше 7.2 — сжатие или шифрование.
    pub entropy: f64,
}

impl Section {
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    pub fn is_code(&self) -> bool {
        self.characteristics & 0x0000_0020 != 0
    }
}

/// Импортируемая функция.
#[derive(Clone, Default)]
pub struct Import {
    pub dll: String,
    pub name: String,
}

/// Разобранный PE-файл.
#[derive(Clone, Default)]
pub struct PeInfo {
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub entry_point: u32,
    pub timestamp: u32,
    pub subsystem: u16,
    pub characteristics: u16,
    /// Размер данных после последней секции: там прячут полезный груз.
    pub overlay_size: u64,
    /// Есть TLS-callbacks — код выполняется до точки входа.
    pub has_tls: bool,
    /// Суммарный размер файла.
    pub file_size: u64,
    /// Разобран только начальный фрагмент файла.
    ///
    /// Тогда «нет таблицы импорта» и «данные после секций» ничего не значат:
    /// таблица могла остаться за пределами прочитанного.
    pub truncated: bool,
}

impl PeInfo {
    /// Это библиотека, а не программа.
    ///
    /// Различие важно: у DLL пустая таблица импорта — норма (API-set заглушки,
    /// ресурсные библиотеки), а у запускаемой программы — уже странность.
    pub fn is_dll(&self) -> bool {
        const IMAGE_FILE_DLL: u16 = 0x2000;
        self.characteristics & IMAGE_FILE_DLL != 0
    }
}

/// Найденный признак.
pub struct Signal {
    pub name: String,
    pub severity: &'static str,
    pub reason: String,
}

/// Признак вместе с его весом в общей оценке файла.
pub struct Scored {
    pub signal: Signal,
    pub weight: u32,
}

// Вес признака в общей оценке.
//
// Разделение на уровни — это и есть разница между «файл странный» и «файл
// подозрительный». Слабый признак ничего не решает, средний решает в компании,
// сильный (поведение вроде инъекции кода) — сам по себе.

/// Признак, который встречается у нормальных программ постоянно.
const WEAK: u32 = 1;
/// Признак, который у нормальной программы требует объяснения.
const MEDIUM: u32 = 2;
/// Признак, который сам по себе означает вредоносное поведение: он один
/// добирает сумму до порога.
const STRONG: u32 = 6;
/// Связка API, которая у нормальной программы требует объяснения.
const COMBO_CRITICAL: u32 = 3;
/// Связка API, которая встречается и в обычных программах.
const COMBO_WARNING: u32 = 2;
/// Сумма весов, после которой набор признаков считается находкой.
pub const THRESHOLD: u32 = 6;

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    let bytes = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], off: usize) -> Option<u64> {
    let bytes = data.get(off..off + 8)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Some(u64::from_le_bytes(buf))
}

/// Энтропия Шеннона по байтам, 0..8.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut result = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        result -= p * p.log2();
    }
    result
}

/// Читает строку с завершающим нулём, не выходя за границы.
fn cstr(data: &[u8], off: usize, max: usize) -> Option<String> {
    let end = data.get(off..off + max)?;
    let len = end.iter().position(|b| *b == 0)?;
    Some(String::from_utf8_lossy(&end[..len]).to_string())
}

/// Разбирает PE-файл. `None` — это не PE или файл повреждён.
pub fn parse(data: &[u8]) -> Option<PeInfo> {
    // DOS-заголовок: «MZ» и адрес PE-заголовка.
    if data.get(0..2)? != b"MZ" {
        return None;
    }
    let pe_off = u32_at(data, 0x3C)? as usize;
    if data.get(pe_off..pe_off + 4)? != b"PE\0\0" {
        return None;
    }

    let coff = pe_off + 4;
    let num_sections = u16_at(data, coff + 2)? as usize;
    let timestamp = u32_at(data, coff + 4)?;
    let opt_size = u16_at(data, coff + 16)? as usize;
    let characteristics = u16_at(data, coff + 18)?;

    let opt = coff + 20;
    let magic = u16_at(data, opt)?;
    let is_64 = magic == 0x20B;
    if magic != 0x10B && magic != 0x20B {
        return None;
    }

    let entry_point = u32_at(data, opt + 16)?;
    let subsystem = u16_at(data, opt + 68)?;

    // Каталоги данных: у PE32+ они начинаются на 112, у PE32 — на 96.
    let dirs = if is_64 { opt + 112 } else { opt + 96 };
    let import_rva = u32_at(data, dirs + 8)?;
    let import_size = u32_at(data, dirs + 12)?;
    let tls_rva = u32_at(data, dirs + 9 * 8)?;

    // Таблица секций идёт сразу за необязательным заголовком.
    let sec_off = opt + opt_size;
    let mut sections = Vec::with_capacity(num_sections.min(96));
    for i in 0..num_sections.min(96) {
        let base = sec_off + i * 40;
        let raw_name = data.get(base..base + 8)?;
        let name_end = raw_name.iter().position(|b| *b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..name_end]).to_string();
        let virtual_address = u32_at(data, base + 12)?;
        let virtual_size = u32_at(data, base + 8)?;
        let raw_size = u32_at(data, base + 16)?;
        let raw_offset = u32_at(data, base + 20)?;
        let characteristics = u32_at(data, base + 36)?;

        // Энтропию считаем по реально присутствующим байтам.
        let start = raw_offset as usize;
        let end = start.saturating_add(raw_size as usize).min(data.len());
        let body = if start < end { &data[start..end] } else { &[][..] };

        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
            raw_size,
            raw_offset,
            characteristics,
            entropy: entropy(body),
        });
    }

    // Данные после последней секции.
    let last_end = sections
        .iter()
        .map(|s| s.raw_offset as u64 + s.raw_size as u64)
        .max()
        .unwrap_or(0);
    let overlay_size = (data.len() as u64).saturating_sub(last_end);

    let imports = if import_rva != 0 && import_size != 0 {
        read_imports(data, &sections, import_rva, is_64)
    } else {
        Vec::new()
    };

    Some(PeInfo {
        sections,
        imports,
        entry_point,
        timestamp,
        subsystem,
        characteristics,
        overlay_size,
        has_tls: tls_rva != 0,
        file_size: data.len() as u64,
        truncated: false,
    })
}

/// Переводит RVA в смещение в файле через таблицу секций.
fn rva_to_offset(sections: &[Section], rva: u32) -> Option<usize> {
    for s in sections {
        // Сравнивать нужно с адресом в памяти: RVA отсчитывается от него,
        // а не от смещения секции в файле.
        let start = s.virtual_address;
        let size = s.virtual_size.max(s.raw_size);
        if rva >= start && rva < start.saturating_add(size) {
            let delta = rva - start;
            // Хвост секции, которого нет в файле (неинициализированные данные).
            if delta >= s.raw_size {
                return None;
            }
            return Some((s.raw_offset + delta) as usize);
        }
    }
    None
}

/// Читает таблицу импорта: имена библиотек и функций.
fn read_imports(data: &[u8], sections: &[Section], rva: u32, is_64: bool) -> Vec<Import> {
    let mut out = Vec::new();
    let base = match rva_to_offset(sections, rva) {
        Some(v) => v,
        None => return out,
    };
    // Дескриптор импорта — 20 байт; ограничиваем число, чтобы не зациклиться.
    for i in 0..256 {
        let desc = base + i * 20;
        let original_thunk = match u32_at(data, desc) {
            Some(v) => v,
            None => break,
        };
        let name_rva = match u32_at(data, desc + 12) {
            Some(v) => v,
            None => break,
        };
        let first_thunk = match u32_at(data, desc + 16) {
            Some(v) => v,
            None => break,
        };
        // Нулевой дескриптор — конец таблицы.
        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let dll = match rva_to_offset(sections, name_rva).and_then(|o| cstr(data, o, 256)) {
            Some(v) => v,
            None => continue,
        };
        let thunk_rva = if original_thunk != 0 {
            original_thunk
        } else {
            first_thunk
        };
        let thunk_off = match rva_to_offset(sections, thunk_rva) {
            Some(v) => v,
            None => continue,
        };
        let step = if is_64 { 8 } else { 4 };
        for j in 0..512 {
            let entry = thunk_off + j * step;
            let value = if is_64 {
                match u64_at(data, entry) {
                    Some(v) => v,
                    None => break,
                }
            } else {
                match u32_at(data, entry) {
                    Some(v) => v as u64,
                    None => break,
                }
            };
            if value == 0 {
                break;
            }
            // Старший бит — импорт по номеру, имени в файле нет.
            let by_ordinal = if is_64 {
                value & 0x8000_0000_0000_0000 != 0
            } else {
                value & 0x8000_0000 != 0
            };
            if by_ordinal {
                continue;
            }
            let hint = value as u32;
            if let Some(off) = rva_to_offset(sections, hint) {
                // Первые два байта — hint, дальше имя.
                if let Some(name) = cstr(data, off + 2, 256) {
                    out.push(Import {
                        dll: dll.clone(),
                        name,
                    });
                }
            }
        }
    }
    out
}

/// Проверяет разобранный файл и возвращает найденные признаки.
///
/// Списки упаковщиков и связок API приходят из файла правил: держать имена
/// вроде `VirtualAllocEx` в бинарнике нельзя — антивирус принимает такой exe
/// за дроппер и блокирует запуск.
///
/// Признаки складываются в общую оценку, а не показываются поодиночке. Причина
/// простая: каждый структурный признак по отдельности встречается у совершенно
/// нормальных программ. Упакованные установщики, API-set заглушки без таблицы
/// импорта, сборки с `/Brepro` (дата в заголовке — хеш, часто «из будущего»),
/// TLS-callbacks в рантайме C++ — всё это не вирусы. Находкой становится только
/// набор признаков, который в сумме уже не объясняется обычной сборкой.
pub fn analyze(info: &PeInfo, rules: &crate::heur::Heuristics) -> Vec<Scored> {
    let mut scored: Vec<(Signal, u32)> = Vec::new();

    // 1. Упаковщик по именам секций.
    for section in &info.sections {
        let upper = section.name.to_uppercase();
        if let Some((_, packer)) = rules
            .packers
            .iter()
            .find(|(name, _)| upper == name.to_uppercase())
        {
            scored.push((
                Signal {
                    name: format!("Упакован: {packer}"),
                    severity: "warning",
                    reason: format!(
                        "Секция «{}» принадлежит упаковщику {packer}. Упаковка сама по себе не вирус, но скрывает содержимое от анализа",
                        section.name
                    ),
                },
                MEDIUM,
            ));
            break;
        }
    }

    // 2. Секция одновременно записываемая и исполняемая.
    for section in &info.sections {
        if section.is_writable() && section.is_executable() {
            scored.push((
                Signal {
                    name: "Записываемая и исполняемая секция".into(),
                    severity: "warning",
                    reason: format!(
                        "Секция «{}» помечена и как записываемая, и как исполняемая — так делают самомодифицирующийся код и распаковщики",
                        section.name
                    ),
                },
                MEDIUM,
            ));
            break;
        }
    }

    // 3. Высокая энтропия кода: сжатие или шифрование.
    for section in &info.sections {
        if section.is_code() && section.entropy > 7.2 && section.raw_size > 4096 {
            scored.push((
                Signal {
                    name: "Зашифрованный или сжатый код".into(),
                    severity: "warning",
                    reason: format!(
                        "Энтропия секции «{}» — {:.2} из 8. Так выглядит сжатый или зашифрованный код",
                        section.name, section.entropy
                    ),
                },
                MEDIUM,
            ));
            break;
        }
    }

    // 3a. Дата сборки: ноль или будущее.
    //
    // Само по себе это слабый признак: при сборке с `/Brepro` компоновщик
    // кладёт в это поле хеш, и «дата» легко оказывается в будущем. Поэтому
    // признак только добавляет вес, но никогда не решает сам.
    let now = crate::store::now_unix() as u32;
    if info.timestamp == 0 {
        scored.push((
            Signal {
                name: "Дата сборки обнулена".into(),
                severity: "warning",
                reason: "В заголовке нет даты сборки — так делают, чтобы скрыть происхождение файла".into(),
            },
            WEAK,
        ));
    } else if info.timestamp > now.saturating_add(86_400) {
        scored.push((
            Signal {
                name: "Дата сборки в будущем".into(),
                severity: "warning",
                reason: "Дата в заголовке позже текущей — заголовок изменён вручную".into(),
            },
            WEAK,
        ));
    }

    // 3b. Прямой импорт из ntdll: обход обычных точек контроля API.
    //
    // Импорт `Nt*`/`Rtl*` из ntdll встречается в куче нормальных программ
    // (отладчики, игры, античиты), так что это тоже только вес.
    if info
        .imports
        .iter()
        .any(|i| i.dll.eq_ignore_ascii_case("ntdll.dll"))
    {
        scored.push((
            Signal {
                name: "Прямой импорт из ntdll".into(),
                severity: "warning",
                reason: "Файл вызывает функции ядра напрямую, минуя kernel32 — так обходят перехват API".into(),
            },
            WEAK,
        ));
    }

    // 3c. Нативная подсистема у обычного приложения: так собирают драйверы
    // и низкоуровневые загрузчики, но не программы для пользователя.
    const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
    const IMAGE_FILE_DLL: u16 = 0x2000;
    if info.subsystem == IMAGE_SUBSYSTEM_NATIVE && info.characteristics & IMAGE_FILE_DLL == 0 {
        scored.push((
            Signal {
                name: "Нативная подсистема".into(),
                severity: "warning",
                reason: "Файл собран как нативное приложение, а не обычная программа — так делают драйверы и загрузчики".into(),
            },
            MEDIUM,
        ));
    }

    // 4. Нет таблицы импорта.
    //
    // У библиотек пустой импорт — норма: API-set заглушки (`api-ms-win-*`)
    // вообще не импортируют ничего, они только перенаправляют вызовы. Поэтому
    // признак смотрим лишь у запускаемых файлов и с оговоркой на упаковку.
    if info.imports.is_empty() && info.sections.len() > 1 && !info.is_dll() && !info.truncated {
        scored.push((
            Signal {
                name: "Нет таблицы импорта".into(),
                severity: "warning",
                reason: "Программа не объявляет ни одной импортируемой функции — так бывает после упаковки или при ручной сборке заголовка".into(),
            },
            MEDIUM,
        ));
    }

    // 5. Точка входа вне секций.
    //
    // Ноль означает «точки входа нет» — так бывает у ресурсных библиотек
    // и драйверов печати, это норма, а не искажённый заголовок.
    let inside = info.sections.iter().any(|s| {
        let start = s.virtual_address;
        let end = start.saturating_add(s.virtual_size.max(s.raw_size));
        info.entry_point >= start && info.entry_point < end
    });
    if info.entry_point != 0 && !inside && !info.sections.is_empty() {
        scored.push((
            Signal {
                name: "Точка входа вне секций".into(),
                severity: "warning",
                reason: "Адрес начала кода не попадает ни в одну секцию — признак повреждённого или специально искажённого файла".into(),
            },
            STRONG,
        ));
    }

    // 6. TLS-callbacks: код до точки входа.
    //
    // Рантайм C++ и CRT используют TLS для своих нужд, поэтому один этот
    // признак ничего не значит.
    if info.has_tls {
        scored.push((
            Signal {
                name: "TLS-callbacks".into(),
                severity: "warning",
                reason: "Файл выполняет код до основной точки входа — приём используют для обхода отладки и антивирусов".into(),
            },
            WEAK,
        ));
    }

    // 7. Данные после последней секции.
    if info.overlay_size > 512 * 1024 && !info.truncated {
        scored.push((
            Signal {
                name: "Данные после секций".into(),
                severity: "warning",
                reason: format!(
                    "После последней секции лежит {:.1} МБ данных — там часто прячут второй исполняемый файл",
                    info.overlay_size as f64 / 1024.0 / 1024.0
                ),
            },
            WEAK,
        ));
    }

    // 8. Связки API.
    //
    // Это поведение, а не структура: файл, который умеет писать код в чужой
    // процесс и запускать его, — самодостаточная находка. Критичная связка
    // превышает порог одна, предупреждающая — только вместе с другими.
    let names: Vec<&str> = info.imports.iter().map(|i| i.name.as_str()).collect();
    for combo in &rules.combos {
        if combo
            .functions
            .iter()
            .all(|needle| names.iter().any(|n| *n == needle.as_str()))
        {
            let critical = combo.severity == "critical";
            let weight = match combo.severity.as_str() {
                "critical" => COMBO_CRITICAL,
                // Связка, которая встречается и у нормальных программ:
                // установщики создают службы, бэкапы меняют привилегии.
                "info" => WEAK,
                _ => COMBO_WARNING,
            };
            scored.push((
                Signal {
                    name: combo.name.clone(),
                    severity: if critical { "critical" } else { "warning" },
                    reason: combo.reason.clone(),
                },
                weight,
            ));
        }
    }

    // 9. Подозрительно мало секций при большом размере.
    if info.sections.len() <= 2 && info.file_size > 200 * 1024 {
        scored.push((
            Signal {
                name: "Мало секций".into(),
                severity: "warning",
                reason: "Крупный файл всего с одной-двумя секциями — обычно это результат упаковки".into(),
            },
            WEAK,
        ));
    }

    // Решение по сумме принимает вызывающий: у него есть ещё правила и
    // проверка подписи, и складывать улики нужно в одном месте.
    // Самое весомое — первым: интерфейс показывает одну находку на файл,
    // и это должно быть лучшее объяснение, а не случайный признак.
    scored.sort_by_key(|(_, weight)| std::cmp::Reverse(*weight));
    scored
        .into_iter()
        .map(|(signal, weight)| Scored { signal, weight })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Правила берём из настоящего `heuristics.txt`.
    ///
    /// Держать имена API в тестовом коде нельзя: они попадают в тестовый
    /// бинарник, и антивирус блокирует его запуск.
    fn test_rules() -> crate::heur::Heuristics {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../heuristics.txt");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        crate::heur::parse(&text)
    }

    /// Собирает минимальный корректный PE-файл для тестов.
    fn build_pe(sections: &[(&str, u32, u32, u32)], imports: bool) -> Vec<u8> {
        let pe_off = 0x80usize;
        let opt_size = 0xE0usize;
        let sec_off = pe_off + 4 + 20 + opt_size;
        let data_off = sec_off + sections.len() * 40;
        let mut buf = vec![0u8; data_off + 0x400];

        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

        let coff = pe_off + 4;
        buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        // Точка входа — внутри первой секции (её адрес в памяти, не в файле).
        let first_rva = 0x1000u32;
        buf[opt + 16..opt + 20].copy_from_slice(&(first_rva + 0x10).to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());

        // Каталог импорта.
        let dirs = opt + 96;
        if imports {
            buf[dirs + 8..dirs + 12].copy_from_slice(&0x2000u32.to_le_bytes());
            buf[dirs + 12..dirs + 16].copy_from_slice(&0x100u32.to_le_bytes());
        }

        for (i, (name, vsize, raw_size, raw_off)) in sections.iter().enumerate() {
            let base = sec_off + i * 40;
            let bytes = name.as_bytes();
            buf[base..base + bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
            buf[base + 8..base + 12].copy_from_slice(&vsize.to_le_bytes());
            // Адрес в памяти: у настоящих файлов он почти никогда не совпадает
            // со смещением в файле — именно на этом ломался разбор импорта.
            let va = 0x1000u32 * (i as u32 + 1);
            buf[base + 12..base + 16].copy_from_slice(&va.to_le_bytes());
            buf[base + 16..base + 20].copy_from_slice(&raw_size.to_le_bytes());
            buf[base + 20..base + 24].copy_from_slice(&raw_off.to_le_bytes());
            // Код + чтение + исполнение.
            buf[base + 36..base + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        }
        buf
    }

    /// PE с настоящей таблицей импорта: одна функция `Sleep` из `kernel32.dll`.
    ///
    /// Адрес секции в памяти (0x1000) намеренно не совпадает со смещением в
    /// файле (0x200) — так выглядит любой реальный файл.
    fn build_pe_with_imports() -> Vec<u8> {
        let pe_off = 0x80usize;
        let opt_size = 0xE0usize;
        let coff = pe_off + 4;
        let opt = coff + 20;
        let sec_off = opt + opt_size;
        let data_off = sec_off + 40;
        let mut buf = vec![0u8; 0x600];

        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

        buf[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1010u32.to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());

        // Каталог импорта: RVA 0x1000, секция начинается там же.
        buf[opt + 96 + 8..opt + 96 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 96 + 12..opt + 96 + 16].copy_from_slice(&0x80u32.to_le_bytes());

        // Секция: VA 0x1000, файл 0x200, размер 0x400.
        buf[sec_off..sec_off + 6].copy_from_slice(b".idata");
        buf[sec_off + 8..sec_off + 12].copy_from_slice(&0x400u32.to_le_bytes());
        buf[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec_off + 16..sec_off + 20].copy_from_slice(&0x400u32.to_le_bytes());
        buf[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec_off + 36..sec_off + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

        assert!(data_off < 0x200);
        // Дескриптор импорта: ILT 0x1040, имя библиотеки 0x1060, IAT 0x1040.
        let desc = 0x200;
        buf[desc..desc + 4].copy_from_slice(&0x1040u32.to_le_bytes());
        buf[desc + 12..desc + 16].copy_from_slice(&0x1060u32.to_le_bytes());
        buf[desc + 16..desc + 20].copy_from_slice(&0x1040u32.to_le_bytes());
        // Таблица импортируемых функций: один адрес (hint/name 0x1070), конец.
        buf[0x240..0x244].copy_from_slice(&0x1070u32.to_le_bytes());
        // Имя библиотеки.
        buf[0x260..0x26d].copy_from_slice(b"kernel32.dll\0");
        // hint (2 байта) + имя функции.
        buf[0x270..0x278].copy_from_slice(b"\x21\x00Sleep\0");
        buf
    }

    #[test]
    fn rva_is_mapped_through_virtual_address() {
        let sections = [Section {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_size: 0x400,
            raw_offset: 0x400,
            characteristics: 0x6000_0020,
            entropy: 0.0,
        }];
        // Адрес в памяти 0x1000 → смещение в файле 0x400.
        assert_eq!(rva_to_offset(&sections, 0x1000), Some(0x400));
        assert_eq!(rva_to_offset(&sections, 0x1010), Some(0x410));
        // Адрес за пределами файловой части секции — в файле его нет.
        assert_eq!(rva_to_offset(&sections, 0x1800), None);
        assert_eq!(rva_to_offset(&sections, 0x2000), None);
    }

    #[test]
    fn reads_imports_from_real_layout() {
        let info = parse(&build_pe_with_imports()).expect("PE не разобран");
        assert_eq!(info.imports.len(), 1, "импорт не прочитан");
        assert_eq!(info.imports[0].dll, "kernel32.dll");
        assert_eq!(info.imports[0].name, "Sleep");
    }

    #[test]
    fn rejects_non_pe() {
        assert!(parse(b"not a pe file at all").is_none());
        assert!(parse(b"").is_none());
        assert!(parse(b"MZ").is_none());
    }

    #[test]
    fn parses_minimal_pe() {
        let data = build_pe(&[(".text", 0x1000, 0x400, 0x400)], false);
        let info = parse(&data).expect("PE не разобран");
        assert_eq!(info.sections.len(), 1);
        assert_eq!(info.sections[0].name, ".text");
        assert!(info.sections[0].is_executable());
    }

    /// Секция с заданными свойствами; адрес в памяти — 0x1000.
    fn section(name: &str, characteristics: u32, entropy: f64) -> Section {
        Section {
            name: name.into(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_size: 0x1000,
            raw_offset: 0x400,
            characteristics,
            entropy,
        }
    }

    /// Программа с двумя секциями: код и данные.
    fn exe_with(sections: Vec<Section>) -> PeInfo {
        PeInfo {
            sections,
            entry_point: 0x1010,
            timestamp: 1_700_000_000,
            subsystem: 3,
            characteristics: 0x0102,
            file_size: 300 * 1024,
            ..Default::default()
        }
    }

    /// Общая оценка файла — по ней и принимается решение о находке.
    fn total(signals: &[Scored]) -> u32 {
        signals.iter().map(|s| s.weight).sum()
    }

    #[test]
    fn packer_alone_is_not_a_finding() {
        // Легитимный UPX-файл: упаковка есть, но ничего больше.
        let info = exe_with(vec![
            section("UPX0", 0x4000_0040, 0.0),
            section("UPX1", 0x6000_0020, 7.9),
        ]);
        let signals = analyze(&info, &test_rules());
        assert!(
            total(&signals) < THRESHOLD,
            "упакованный файл без других признаков не должен быть находкой: {:?}",
            signals.iter().map(|s| &s.signal.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn packer_with_encrypted_code_is_a_finding() {
        // Тот же UPX, но секция данных ещё и записываемая+исполняемая.
        let info = exe_with(vec![
            section("UPX0", 0xE000_0080, 0.0),
            section("UPX1", 0x6000_0020, 7.9),
        ]);
        let signals = analyze(&info, &test_rules());
        assert!(
            signals.iter().any(|s| s.signal.name.contains("UPX")),
            "упаковщик не найден: {:?}",
            signals.iter().map(|s| &s.signal.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn writable_executable_section_alone_is_not_a_finding() {
        let info = exe_with(vec![section(".text", 0xE000_0020, 6.0)]);
        let signals = analyze(&info, &test_rules());
        assert!(total(&signals) < THRESHOLD, "один признак — ещё не находка");
    }

    #[test]
    fn missing_imports_alone_is_not_a_finding() {
        let info = exe_with(vec![
            section(".text", 0x6000_0020, 6.0),
            section(".data", 0x4000_0040, 3.0),
        ]);
        let signals = analyze(&info, &test_rules());
        assert!(
            total(&signals) < THRESHOLD,
            "пустой импорт сам по себе не повод: {:?}",
            signals.iter().map(|s| &s.signal.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn missing_imports_with_anomalies_is_a_finding() {
        let info = exe_with(vec![
            section(".text", 0xE000_0020, 6.0),
            section(".data", 0x4000_0040, 3.0),
        ]);
        let signals = analyze(&info, &test_rules());
        assert!(
            signals.iter().any(|s| s.signal.name.contains("Нет таблицы импорта")),
            "набор признаков не распознан: {:?}",
            signals.iter().map(|s| &s.signal.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn truncated_file_does_not_report_missing_imports() {
        // У большого файла прочитано только начало: таблица импорта могла
        // остаться за его пределами, и «импорта нет» было бы ложью.
        let mut info = exe_with(vec![
            section(".text", 0xE000_0020, 6.0),
            section(".data", 0x4000_0040, 3.0),
        ]);
        info.truncated = true;
        let signals = analyze(&info, &test_rules());
        assert!(
            signals.iter().all(|s| !s.signal.name.contains("Нет таблицы импорта")),
            "усечённый файл не должен обвиняться в отсутствии импорта"
        );
    }

    #[test]
    fn api_set_stub_is_clean() {
        // `api-ms-win-crt-*.dll`: библиотека без импорта и с «датой из будущего».
        let mut info = exe_with(vec![
            section(".text", 0x6000_0020, 6.0),
            section(".rdata", 0x4000_0040, 4.0),
        ]);
        info.characteristics = 0x2102; // IMAGE_FILE_DLL
        info.timestamp = u32::MAX;
        let signals = analyze(&info, &test_rules());
        assert!(
            total(&signals) < THRESHOLD,
            "заглушка API-set не должна быть находкой: {:?}",
            signals.iter().map(|s| &s.signal.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn entropy_of_uniform_data_is_zero() {
        assert_eq!(entropy(&[0u8; 1024]), 0.0);
    }

    #[test]
    fn entropy_of_random_data_is_high() {
        // Псевдослучайные байты: энтропия близка к 8.
        let data: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let e = entropy(&data);
        assert!(e > 7.0, "энтропия {e} слишком низкая");
        assert!(e <= 8.0);
    }

    #[test]
    fn entropy_of_half_repeated() {
        let mut data = vec![0u8; 512];
        data.extend(vec![1u8; 512]);
        let e = entropy(&data);
        assert!((e - 1.0).abs() < 0.01, "ожидалась 1.0, получено {e}");
    }

    #[test]
    fn api_combo_detected() {
        let mut info = PeInfo::default();
        info.sections.push(Section {
            name: ".text".into(),
            raw_size: 0x400,
            characteristics: 0x6000_0020,
            ..Default::default()
        });
        info.imports = vec![
            Import { dll: "kernel32.dll".into(), name: "VirtualAllocEx".into() },
            Import { dll: "kernel32.dll".into(), name: "WriteProcessMemory".into() },
            Import { dll: "kernel32.dll".into(), name: "CreateRemoteThread".into() },
        ];
        let signals = analyze(&info, &test_rules());
        assert!(
            signals.iter().any(|s| s.signal.name.contains("Внедрение кода")),
            "связка не найдена"
        );
    }

    #[test]
    fn single_api_is_not_a_combo() {
        let mut info = PeInfo::default();
        info.sections.push(Section {
            name: ".text".into(),
            raw_size: 0x400,
            characteristics: 0x6000_0020,
            ..Default::default()
        });
        info.imports = vec![Import {
            dll: "kernel32.dll".into(),
            name: "VirtualAllocEx".into(),
        }];
        let signals = analyze(&info, &test_rules());
        assert!(signals.iter().all(|s| !s.signal.name.contains("Внедрение кода")));
    }

    #[test]
    fn timestamp_anomaly_alone_is_not_a_finding() {
        // Сборка с `/Brepro`: в поле даты лежит хеш, часто «из будущего».
        let mut info = exe_with(vec![section(".text", 0x6000_0020, 6.0)]);
        info.timestamp = u32::MAX;
        assert!(total(&analyze(&info, &test_rules())) < THRESHOLD);

        info.timestamp = 0;
        assert!(total(&analyze(&info, &test_rules())) < THRESHOLD);
    }

    #[test]
    fn ntdll_import_alone_is_not_a_finding() {
        let mut info = exe_with(vec![section(".text", 0x6000_0020, 6.0)]);
        info.imports = vec![Import {
            dll: "ntdll.dll".into(),
            name: "NtCreateThreadEx".into(),
        }];
        assert!(total(&analyze(&info, &test_rules())) < THRESHOLD);
    }

    #[test]
    fn entry_point_outside_sections_is_a_finding() {
        let mut info = exe_with(vec![section(".text", 0x6000_0020, 6.0)]);
        info.entry_point = 0x9000;
        let signals = analyze(&info, &test_rules());
        assert!(
            signals.iter().any(|s| s.signal.name.contains("Точка входа")),
            "искажённый заголовок не распознан"
        );
    }

    #[test]
    fn zero_entry_point_is_normal_for_resource_dll() {
        // У ресурсных библиотек и драйверов печати точки входа нет вовсе.
        let mut info = exe_with(vec![section(".rsrc", 0x4000_0040, 4.0)]);
        info.entry_point = 0;
        info.characteristics = 0x2102;
        let signals = analyze(&info, &test_rules());
        assert!(
            signals.iter().all(|s| !s.signal.name.contains("Точка входа")),
            "нулевая точка входа — не искажение заголовка"
        );
    }

    #[test]
    fn truncated_pe_does_not_panic() {
        let data = build_pe(&[(".text", 0x1000, 0x400, 0x400)], false);
        // Обрезаем в разных местах: разбор не должен паниковать.
        for cut in [0, 1, 2, 0x40, 0x80, 0x90, 0x100, 0x200] {
            let _ = parse(&data[..cut.min(data.len())]);
        }
    }

    #[test]
    fn garbage_after_mz_does_not_panic() {
        let mut data = vec![0u8; 512];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        assert!(parse(&data).is_none());
    }
}
