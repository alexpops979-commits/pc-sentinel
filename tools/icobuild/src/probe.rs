//! Диагностика zlib/PNG: печатает заголовки и первые шаги разбора.

use crate::inflate::BitReader;

pub fn probe(data: &[u8]) {
    if data.len() < 8 || data[..8] != [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        println!("не PNG");
        return;
    }
    if let Ok(image) = crate::png::decode_png(data) {
        let total = image.width * image.height;
        let mut transparent = 0usize;
        let mut partial = 0usize;
        for pixel in image.pixels.chunks_exact(4) {
            match pixel[3] {
                255 => {}
                0 => transparent += 1,
                _ => partial += 1,
            }
        }
        println!(
            "alpha: полностью прозрачных {} ({:.1}%), полупрозрачных {} ({:.1}%), непрозрачных {} ({:.1}%)",
            transparent,
            transparent as f64 / total as f64 * 100.0,
            partial,
            partial as f64 / total as f64 * 100.0,
            total - transparent - partial,
            (total - transparent - partial) as f64 / total as f64 * 100.0
        );
    }
    let mut pos = 8;
    while pos + 8 <= data.len() {
        let length = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
            as usize;
        let kind = String::from_utf8_lossy(&data[pos + 4..pos + 8]).to_string();
        let start = pos + 8;
        println!("chunk {kind} len={length}");
        if kind == "IHDR" && length >= 13 {
            let w = u32::from_be_bytes([data[start], data[start + 1], data[start + 2], data[start + 3]]);
            let h =
                u32::from_be_bytes([data[start + 4], data[start + 5], data[start + 6], data[start + 7]]);
            println!(
                "  {w}x{h} depth={} color={} compression={} filter={} interlace={}",
                data[start + 8],
                data[start + 9],
                data[start + 10],
                data[start + 11],
                data[start + 12]
            );
        }
        if kind == "IDAT" && length > 0 {
            let slice = &data[start..start + length];
            println!("  zlib header: {:02X} {:02X}", slice[0], slice[1]);
            let mut r = BitReader::new(&slice[2..]);
            let last = r.bits(1);
            let btype = r.bits(2);
            println!("  first block: last={last} btype={btype}");
            if btype == 2 {
                let hlit = r.bits(5) as usize + 257;
                let hdist = r.bits(5) as usize + 1;
                let hclen = r.bits(4) as usize + 4;
                println!("  hlit={hlit} hdist={hdist} hclen={hclen}");
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut lengths = [0u8; 19];
                for i in 0..hclen {
                    lengths[ORDER[i]] = r.bits(3) as u8;
                }
                println!("  code-length lengths: {lengths:?}");
            }
            break;
        }
        if kind == "IEND" {
            break;
        }
        pos = start + length + 4;
    }
}
