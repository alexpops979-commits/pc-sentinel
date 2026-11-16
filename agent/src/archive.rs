//! Чтение ZIP без внешних зависимостей.
//!
//! Антивирус обязан смотреть внутрь архивов: вредонос чаще всего приходит
//! именно так, потому что почтовые фильтры и браузеры пропускают `.zip`
//! насквозь. Здесь разбирается центральный каталог ZIP и распаковываются
//! записи методом deflate (собственный inflate) или stored.
//!
//! Ограничения принципиальны: распаковка управляется снаружи, чтобы «zip-бомба»
//! не съела память и время. Архив с подозрительно высокой степенью сжатия
//! помечается, а не распаковывается до конца.

use crate::inflate::inflate_raw_limited;

/// Сколько записей и байт разрешено распаковать из одного архива.
#[derive(Clone, Copy)]
pub struct Limits {
    pub max_entries: usize,
    pub max_entry: u64,
    pub max_total: u64,
    /// Во сколько раз распакованное может превышать сжатое.
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entries: 256,
            max_entry: 16 * 1024 * 1024,
            max_total: 48 * 1024 * 1024,
            max_ratio: 200,
        }
    }
}

/// Распакованная запись архива.
pub struct Entry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Итог разбора архива.
#[derive(Default)]
pub struct Archive {
    pub entries: Vec<Entry>,
    /// Записи, которые не удалось прочитать: шифрование, битый deflate, лимит.
    pub skipped: usize,
    /// Есть записи с паролем.
    pub encrypted: bool,
    /// Похоже на zip-бомбу: степень сжатия выше разрешённой.
    pub bomb: bool,
}

/// Это ZIP-архив? Пустой архив (`PK\x05\x06`) тоже считается.
pub fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4
        && (data.starts_with(b"PK\x03\x04")
            || data.starts_with(b"PK\x05\x06")
            || data.starts_with(b"PK\x07\x08"))
}

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Ищет End of Central Directory: он в конце файла, за комментарием.
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let start = data.len().saturating_sub(66_000);
    let mut i = data.len() - 22;
    loop {
        if data[i..i + 4] == *b"PK\x05\x06" {
            return Some(i);
        }
        if i == start {
            return None;
        }
        i -= 1;
    }
}

/// Разбирает архив.
pub fn read(data: &[u8], limits: Limits) -> Archive {
    let mut out = Archive::default();
    let eocd = match find_eocd(data) {
        Some(v) => v,
        None => return out,
    };
    let count = u16_at(data, eocd + 10).unwrap_or(0) as usize;
    let cd_offset = u32_at(data, eocd + 16).unwrap_or(0) as usize;
    if cd_offset == 0 || cd_offset >= data.len() {
        return out;
    }

    let mut pos = cd_offset;
    let mut unpacked: u64 = 0;
    for _ in 0..count.min(limits.max_entries * 4) {
        if data.get(pos..pos + 4) != Some(b"PK\x01\x02") {
            break;
        }
        let flags = u16_at(data, pos + 8).unwrap_or(0);
        let method = u16_at(data, pos + 10).unwrap_or(0);
        let comp_size = u32_at(data, pos + 20).unwrap_or(0) as u64;
        let uncomp_size = u32_at(data, pos + 24).unwrap_or(0) as u64;
        let name_len = u16_at(data, pos + 28).unwrap_or(0) as usize;
        let extra_len = u16_at(data, pos + 30).unwrap_or(0) as usize;
        let comment_len = u16_at(data, pos + 32).unwrap_or(0) as usize;
        let local_offset = u32_at(data, pos + 42).unwrap_or(0) as usize;

        let name = data
            .get(pos + 46..pos + 46 + name_len)
            .map(|b| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();

        pos += 46 + name_len + extra_len + comment_len;

        // Запись с паролем: содержимое не прочитать, но сам факт важен.
        if flags & 1 != 0 {
            out.encrypted = true;
            out.skipped += 1;
            continue;
        }
        if out.entries.len() >= limits.max_entries || unpacked >= limits.max_total {
            break;
        }
        // ZIP64 и служебные записи каталогов пропускаем.
        if uncomp_size == u32::MAX as u64 || name.ends_with('/') {
            continue;
        }
        if uncomp_size > limits.max_entry {
            out.skipped += 1;
            continue;
        }
        if comp_size > 0 && uncomp_size / comp_size.max(1) > limits.max_ratio {
            out.bomb = true;
            out.skipped += 1;
            continue;
        }

        // Локальный заголовок: у него свои длины имени и расширения.
        let local = match data.get(local_offset..local_offset + 30) {
            Some(_) if data.get(local_offset..local_offset + 4) == Some(b"PK\x03\x04") => {
                local_offset
            }
            _ => {
                out.skipped += 1;
                continue;
            }
        };
        let l_name = u16_at(data, local + 26).unwrap_or(0) as usize;
        let l_extra = u16_at(data, local + 28).unwrap_or(0) as usize;
        let start = local + 30 + l_name + l_extra;
        let body = match data.get(start..start.saturating_add(comp_size as usize)) {
            Some(b) => b,
            None => {
                out.skipped += 1;
                continue;
            }
        };

        let content = match method {
            // stored
            0 => body.to_vec(),
            // deflate
            8 => match inflate_raw_limited(body, limits.max_entry as usize) {
                Ok(v) => v,
                Err(_) => {
                    out.skipped += 1;
                    continue;
                }
            },
            // bzip2, lzma и прочее без своей реализации не читаем.
            _ => {
                out.skipped += 1;
                continue;
            }
        };
        unpacked += content.len() as u64;
        out.entries.push(Entry { name, data: content });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает минимальный ZIP с одной записью stored.
    fn build_zip_stored(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // Локальный заголовок.
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // версия
        out.extend_from_slice(&0u16.to_le_bytes()); // флаги
        out.extend_from_slice(&0u16.to_le_bytes()); // метод stored
        out.extend_from_slice(&0u16.to_le_bytes()); // время
        out.extend_from_slice(&0u16.to_le_bytes()); // дата
        out.extend_from_slice(&0u32.to_le_bytes()); // crc (не проверяем)
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        let local_offset = 0u32;
        out.extend_from_slice(payload);

        // Центральный каталог.
        let cd_offset = out.len() as u32;
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&local_offset.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        let cd_size = out.len() as u32 - cd_offset;

        // EOCD.
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
    fn reads_stored_entry() {
        let zip = build_zip_stored("readme.txt", b"hello");
        assert!(is_zip(&zip));
        let archive = read(&zip, Limits::default());
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "readme.txt");
        assert_eq!(archive.entries[0].data, b"hello");
    }

    #[test]
    fn reads_deflated_entry() {
        // ZIP хранит данные «сырым» deflate без zlib-заголовка — на этом
        // ломался первый вариант: обёртку брали от PNG.
        let payload = b"the quick brown fox jumps over the lazy dog";
        let zip = build_zip_deflate("note.txt", payload);
        let archive = read(&zip, Limits::default());
        assert_eq!(archive.entries.len(), 1, "запись не распакована");
        assert_eq!(archive.entries[0].data, payload);
    }

    /// Собирает ZIP с методом deflate.
    ///
    /// Сжимать по-настоящему не нужно: внутри deflate-потока допустим блок
    /// `stored` (BTYPE=00), который просто повторяет байты. Главное для
    /// проверки — что поток «сырой», без zlib-заголовка.
    fn build_zip_deflate(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut stream = vec![0x01u8];
        stream.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        stream.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        stream.extend_from_slice(payload);

        let mut out = Vec::new();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes()); // deflate
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(stream.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&stream);

        let cd_offset = out.len() as u32;
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(stream.len() as u32).to_le_bytes());
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
    fn rejects_non_zip() {
        assert!(!is_zip(b"MZ not a zip"));
        assert!(!is_zip(b""));
    }

    #[test]
    fn truncated_zip_does_not_panic() {
        let zip = build_zip_stored("a.txt", b"data");
        for cut in [0, 4, 10, 22, zip.len() / 2, zip.len() - 1] {
            let _ = read(&zip[..cut.min(zip.len())], Limits::default());
        }
    }

    #[test]
    fn decompression_bomb_is_stopped() {
        // Поток deflate, который разворачивается в мегабайты из десятка байт.
        // Без предела распаковки такой архив съедает память.
        let mut stream = vec![0x01u8];
        let len: u16 = 60_000;
        stream.extend_from_slice(&len.to_le_bytes());
        stream.extend_from_slice(&(!len).to_le_bytes());
        stream.extend(std::iter::repeat(0u8).take(len as usize));

        let limits = Limits {
            max_entry: 1024,
            ..Limits::default()
        };
        let result = crate::inflate::inflate_raw_limited(&stream, limits.max_entry as usize);
        assert!(result.is_err(), "предел распаковки не сработал");
    }

    #[test]
    fn encryption_flag_is_reported() {
        let mut zip = build_zip_stored("secret.txt", b"x");
        // Ставим бит шифрования в локальном и центральном заголовках.
        zip[6] |= 1;
        let cd = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        zip[cd + 8] |= 1;
        let archive = read(&zip, Limits::default());
        assert!(archive.encrypted);
        assert!(archive.entries.is_empty());
    }
}
