//! Разбор PNG в RGBA8: сигнатура, IHDR, IDAT, фильтры, базовые цветовые типы.

use crate::inflate::inflate;

pub struct Image {
    pub width: usize,
    pub height: usize,
    /// RGBA8, построчно сверху вниз.
    pub pixels: Vec<u8>,
}

impl Image {
    pub fn pixel(&self, x: usize, y: usize) -> [u8; 4] {
        let idx = (y * self.width + x) * 4;
        [
            self.pixels[idx],
            self.pixels[idx + 1],
            self.pixels[idx + 2],
            self.pixels[idx + 3],
        ]
    }
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

pub fn decode_png(data: &[u8]) -> Result<Image, String> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 8 || data[..8] != SIGNATURE {
        return Err("это не PNG".into());
    }

    let mut pos = 8;
    let mut width = 0usize;
    let mut height = 0usize;
    let mut bit_depth = 0u8;
    let mut color_type = 0u8;
    let mut interlace = 0u8;
    let mut palette: Vec<[u8; 4]> = Vec::new();
    let mut idat: Vec<u8> = Vec::new();
    let mut seen_ihdr = false;

    while pos + 8 <= data.len() {
        let length = be32(data, pos) as usize;
        let kind = &data[pos + 4..pos + 8];
        let start = pos + 8;
        if start + length > data.len() {
            break;
        }
        let chunk = &data[start..start + length];

        match kind {
            b"IHDR" => {
                if length < 13 {
                    return Err("IHDR слишком короткий".into());
                }
                width = be32(chunk, 0) as usize;
                height = be32(chunk, 4) as usize;
                bit_depth = chunk[8];
                color_type = chunk[9];
                interlace = chunk[12];
                seen_ihdr = true;
            }
            b"PLTE" => {
                palette = chunk
                    .chunks_exact(3)
                    .map(|c| [c[0], c[1], c[2], 255])
                    .collect();
            }
            b"tRNS" => {
                // Прозрачность палитры
                for (i, alpha) in chunk.iter().enumerate() {
                    if let Some(entry) = palette.get_mut(i) {
                        entry[3] = *alpha;
                    }
                }
            }
            b"IDAT" => idat.extend_from_slice(chunk),
            b"IEND" => break,
            _ => {}
        }

        pos = start + length + 4; // + CRC
    }

    if !seen_ihdr {
        return Err("в файле нет IHDR".into());
    }
    if interlace != 0 {
        return Err("поддерживается только PNG без чересстрочности (interlace=0)".into());
    }
    if bit_depth != 8 {
        return Err(format!("поддерживается только 8 бит на канал (найдено {bit_depth})"));
    }

    let channels = match color_type {
        0 => 1,
        2 => 3,
        3 => 1,
        4 => 2,
        6 => 4,
        other => return Err(format!("неподдерживаемый тип цвета PNG: {other}")),
    };

    let raw = inflate(&idat)?;
    let stride = width * channels;
    let expected = (stride + 1) * height;
    if raw.len() < expected {
        return Err(format!(
            "данных меньше ожидаемого: {} < {expected}",
            raw.len()
        ));
    }

    let mut lines = vec![0u8; stride * height];
    let mut prev = vec![0u8; stride];

    for y in 0..height {
        let offset = y * (stride + 1);
        let filter = raw[offset];
        let src = &raw[offset + 1..offset + 1 + stride];
        let dst_start = y * stride;
        let (before, after) = lines.split_at_mut(dst_start);
        let _ = before;
        let line = &mut after[..stride];

        for x in 0..stride {
            let a = if x >= channels { line[x - channels] } else { 0 };
            let b = prev[x];
            let c = if x >= channels { prev[x - channels] } else { 0 };
            line[x] = match filter {
                0 => src[x],
                1 => src[x].wrapping_add(a),
                2 => src[x].wrapping_add(b),
                3 => src[x].wrapping_add(((a as u16 + b as u16) / 2) as u8),
                4 => src[x].wrapping_add(paeth(a, b, c)),
                other => return Err(format!("неизвестный фильтр строки: {other}")),
            };
        }
        prev.copy_from_slice(line);
    }

    // Преобразуем в RGBA8
    let mut pixels = vec![0u8; width * height * 4];
    for y in 0..height {
        for x in 0..width {
            let src = y * stride + x * channels;
            let dst = (y * width + x) * 4;
            match color_type {
                6 => pixels[dst..dst + 4].copy_from_slice(&lines[src..src + 4]),
                2 => {
                    pixels[dst] = lines[src];
                    pixels[dst + 1] = lines[src + 1];
                    pixels[dst + 2] = lines[src + 2];
                    pixels[dst + 3] = 255;
                }
                0 => {
                    let g = lines[src];
                    pixels[dst] = g;
                    pixels[dst + 1] = g;
                    pixels[dst + 2] = g;
                    pixels[dst + 3] = 255;
                }
                4 => {
                    let g = lines[src];
                    pixels[dst] = g;
                    pixels[dst + 1] = g;
                    pixels[dst + 2] = g;
                    pixels[dst + 3] = lines[src + 1];
                }
                3 => {
                    let idx = lines[src] as usize;
                    let entry = palette.get(idx).copied().unwrap_or([0, 0, 0, 255]);
                    pixels[dst..dst + 4].copy_from_slice(&entry);
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(Image {
        width,
        height,
        pixels,
    })
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i16 + b as i16 - c as i16;
    let pa = (p - a as i16).abs();
    let pb = (p - b as i16).abs();
    let pc = (p - c as i16).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}
