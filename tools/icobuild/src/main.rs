//! Сборка .ico (BMP-блоки, без сжатия) и проверка иконок через Win32.

mod inflate;
mod png;
mod probe;

use png::Image;
use std::ffi::c_void;

/// Уменьшение методом площадного усреднения — даёт чистые мелкие значки.
fn resize(src: &Image, size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size * size * 4];
    let scale_x = src.width as f64 / size as f64;
    let scale_y = src.height as f64 / size as f64;

    for oy in 0..size {
        let y0 = (oy as f64 * scale_y).floor() as usize;
        let y1 = (((oy + 1) as f64 * scale_y).ceil() as usize).min(src.height);
        for ox in 0..size {
            let x0 = (ox as f64 * scale_x).floor() as usize;
            let x1 = (((ox + 1) as f64 * scale_x).ceil() as usize).min(src.width);

            let mut acc = [0u64; 4];
            let mut count = 0u64;
            for y in y0..y1.max(y0 + 1) {
                for x in x0..x1.max(x0 + 1) {
                    if y >= src.height || x >= src.width {
                        continue;
                    }
                    let p = src.pixel(x, y);
                    for c in 0..4 {
                        acc[c] += p[c] as u64;
                    }
                    count += 1;
                }
            }
            let dst = (oy * size + ox) * 4;
            if count > 0 {
                for c in 0..4 {
                    out[dst + c] = (acc[c] / count) as u8;
                }
            }
        }
    }
    out
}

/// BMP-блок иконки: BITMAPINFOHEADER + BGRA снизу вверх + AND-маска.
fn bmp_block(rgba: &[u8], size: usize) -> Vec<u8> {
    let stride = size * 4;
    let mask_stride = ((size + 31) / 32) * 4;
    let mut out = Vec::with_capacity(40 + stride * size + mask_stride * size);

    // BITMAPINFOHEADER
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(size as i32).to_le_bytes());
    out.extend_from_slice(&((size as i32) * 2).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&((stride * size) as u32).to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    // Пиксели: снизу вверх, BGRA
    for y in (0..size).rev() {
        for x in 0..size {
            let i = (y * size + x) * 4;
            out.push(rgba[i + 2]);
            out.push(rgba[i + 1]);
            out.push(rgba[i]);
            out.push(rgba[i + 3]);
        }
    }

    // AND-маска: для 32bpp с альфой достаточно нулей
    out.resize(out.len() + mask_stride * size, 0);
    out
}

fn build_ico(src: &Image, sizes: &[usize]) -> Vec<u8> {
    let blocks: Vec<(usize, Vec<u8>)> = sizes
        .iter()
        .map(|&size| (size, bmp_block(&resize(src, size), size)))
        .collect();

    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(blocks.len() as u16).to_le_bytes());

    let mut offset = 6 + 16 * blocks.len();
    for (size, data) in &blocks {
        let dim = if *size >= 256 { 0u8 } else { *size as u8 };
        out.push(dim);
        out.push(dim);
        out.push(0);
        out.push(0);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += data.len();
    }
    for (_, data) in &blocks {
        out.extend_from_slice(data);
    }
    out
}

// ---------- Проверка через Win32 ----------

type HWND = *mut c_void;
type HICON = *mut c_void;

const IMAGE_ICON: u32 = 1;
const LR_LOADFROMFILE: u32 = 0x0010;

#[link(name = "user32")]
extern "system" {
    fn LoadImageW(
        instance: *mut c_void,
        name: *const u16,
        kind: u32,
        cx: i32,
        cy: i32,
        flags: u32,
    ) -> HICON;
    fn DestroyIcon(icon: HICON) -> i32;
}

#[link(name = "shell32")]
extern "system" {
    fn ExtractIconExW(
        file: *const u16,
        index: i32,
        large: *mut HICON,
        small: *mut HICON,
        count: u32,
    ) -> u32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Проверяет, что Windows читает файл как иконку.
fn verify_icon_file(path: &str) -> bool {
    let w = wide(path);
    unsafe {
        let icon = LoadImageW(
            std::ptr::null_mut(),
            w.as_ptr(),
            IMAGE_ICON,
            0,
            0,
            LR_LOADFROMFILE,
        );
        if icon.is_null() {
            false
        } else {
            DestroyIcon(icon);
            true
        }
    }
}

/// Проверяет, что в exe есть ресурс иконки, который видит оболочка.
fn verify_exe_icon(path: &str) -> usize {
    let w = wide(path);
    unsafe {
        let mut large: HICON = std::ptr::null_mut();
        let mut small: HICON = std::ptr::null_mut();
        let count = ExtractIconExW(w.as_ptr(), 0, &mut large, &mut small, 1);
        if !large.is_null() {
            DestroyIcon(large);
        }
        if !small.is_null() {
            DestroyIcon(small);
        }
        count as usize
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("использование:");
        eprintln!("  icobuild <input.png> <output.ico>   — собрать иконку");
        eprintln!("  icobuild --check <file|exe>         — проверить иконку");
        std::process::exit(2);
    }

    if args[1] == "--probe" {
        let target = match args.get(2) {
            Some(t) => t.clone(),
            None => {
                eprintln!("не указан файл");
                std::process::exit(2);
            }
        };
        let data = std::fs::read(&target).unwrap_or_default();
        probe::probe(&data);
        return;
    }

    if args[1] == "--check" {
        let target = match args.get(2) {
            Some(t) => t.clone(),
            None => {
                eprintln!("не указан файл");
                std::process::exit(2);
            }
        };
        let is_ico = target.to_ascii_lowercase().ends_with(".ico");
        if is_ico {
            let ok = verify_icon_file(&target);
            println!("{}: {}", if ok { "OK" } else { "ОШИБКА" }, target);
            std::process::exit(if ok { 0 } else { 1 });
        } else {
            let count = verify_exe_icon(&target);
            println!("иконок в exe: {count} ({target})");
            std::process::exit(if count > 0 { 0 } else { 1 });
        }
    }

    let input = &args[1];
    let output = match args.get(2) {
        Some(o) => o.clone(),
        None => {
            eprintln!("не указан выходной файл");
            std::process::exit(2);
        }
    };

    let data = match std::fs::read(input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("не удалось прочитать {input}: {e}");
            std::process::exit(1);
        }
    };

    let image = match png::decode_png(&data) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("ошибка разбора PNG: {e}");
            std::process::exit(1);
        }
    };

    println!("источник: {}×{}", image.width, image.height);

    let mut sizes: Vec<usize> = vec![16, 24, 32, 48, 64, 128, 256];
    sizes.retain(|&s| s <= image.width.max(image.height));
    sizes.sort_unstable();

    let ico = build_ico(&image, &sizes);
    if let Err(e) = std::fs::write(&output, &ico) {
        eprintln!("не удалось записать {output}: {e}");
        std::process::exit(1);
    }

    let ok = verify_icon_file(&output);
    println!(
        "записано {} ({} КБ, размеры: {})",
        output,
        ico.len() / 1024,
        sizes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("проверка Windows: {}", if ok { "OK" } else { "ОШИБКА" });
    if !ok {
        std::process::exit(1);
    }
}
