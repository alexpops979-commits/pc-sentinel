//! Минимальный inflate (RFC 1951) — без внешних зависимостей.

pub struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buf: u32,
    bit_count: u32,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            bit_buf: 0,
            bit_count: 0,
        }
    }

    fn refill(&mut self) {
        while self.bit_count <= 24 {
            if self.pos < self.data.len() {
                self.bit_buf |= (self.data[self.pos] as u32) << self.bit_count;
                self.pos += 1;
                self.bit_count += 8;
            } else {
                break;
            }
        }
    }

    pub fn bits(&mut self, count: u32) -> u32 {
        if count == 0 {
            return 0;
        }
        if self.bit_count < count {
            self.refill();
        }
        let mask = if count >= 32 { u32::MAX } else { (1u32 << count) - 1 };
        let value = self.bit_buf & mask;
        self.bit_buf >>= count;
        self.bit_count = self.bit_count.saturating_sub(count);
        value
    }

    pub fn align(&mut self) {
        // До границы байта остаётся ровно `bit_count % 8` бит текущего байта.
        let drop = self.bit_count % 8;
        self.bit_buf >>= drop;
        self.bit_count -= drop;
    }

    /// Байт из буфера (после align).
    pub fn byte(&mut self) -> u8 {
        if self.bit_count >= 8 {
            let v = (self.bit_buf & 0xFF) as u8;
            self.bit_buf >>= 8;
            self.bit_count -= 8;
            v
        } else if self.pos < self.data.len() {
            let v = self.data[self.pos];
            self.pos += 1;
            v
        } else {
            0
        }
    }

    pub fn u16_le(&mut self) -> u16 {
        let lo = self.byte() as u16;
        let hi = self.byte() as u16;
        lo | (hi << 8)
    }
}

/// Канонические коды Хаффмана.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn build(lengths: &[u8]) -> Option<Huffman> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            counts[len as usize] += 1;
        }
        counts[0] = 0;

        let mut offsets = [0u16; 16];
        for len in 1..16 {
            offsets[len] = offsets[len - 1] + counts[len - 1];
        }

        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len != 0 {
                let idx = offsets[len as usize] as usize;
                if idx >= symbols.len() {
                    return None;
                }
                symbols[idx] = symbol as u16;
                offsets[len as usize] += 1;
            }
        }
        Some(Huffman { counts, symbols })
    }

    fn decode(&self, reader: &mut BitReader) -> Option<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..16 {
            code |= reader.bits(1) as i32;
            let count = self.counts[len] as i32;
            if code - first < count {
                let pos = (index + (code - first)) as usize;
                return self.symbols.get(pos).copied();
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        None
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

pub fn inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    // IDAT содержит zlib-обёртку: 2 байта заголовка перед deflate-потоком.
    if data.len() < 2 {
        return Err("поток короче заголовка zlib".into());
    }
    let method = data[0] & 0x0F;
    if method != 8 {
        return Err(format!("не deflate в zlib-заголовке: {method}"));
    }
    let mut reader = BitReader::new(&data[2..]);
    let mut out: Vec<u8> = Vec::with_capacity(data.len() * 4);

    loop {
        let last = reader.bits(1);
        let btype = reader.bits(2);

        match btype {
            0 => {
                reader.align();
                let len = reader.u16_le();
                let _nlen = reader.u16_le();
                for _ in 0..len {
                    out.push(reader.byte());
                }
            }
            1 => {
                let mut lengths = [0u8; 288];
                for (i, slot) in lengths.iter_mut().enumerate() {
                    *slot = match i {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    };
                }
                let lit = Huffman::build(&lengths).ok_or("fixed literal table")?;
                let dist_lengths = [5u8; 30];
                let dist = Huffman::build(&dist_lengths).ok_or("fixed distance table")?;
                inflate_block(&mut reader, &lit, &dist, &mut out)?;
            }
            2 => {
                let hlit = reader.bits(5) as usize + 257;
                let hdist = reader.bits(5) as usize + 1;
                let hclen = reader.bits(4) as usize + 4;

                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut cl_lengths = [0u8; 19];
                for i in 0..hclen {
                    cl_lengths[ORDER[i]] = reader.bits(3) as u8;
                }
                let cl = Huffman::build(&cl_lengths).ok_or("code-length table")?;

                let mut lengths = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < lengths.len() {
                    let symbol = cl.decode(&mut reader).ok_or("code-length symbol")?;
                    match symbol {
                        0..=15 => {
                            lengths[i] = symbol as u8;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return Err("повтор без предыдущей длины".into());
                            }
                            let prev = lengths[i - 1];
                            let repeat = 3 + reader.bits(2) as usize;
                            for _ in 0..repeat {
                                if i >= lengths.len() {
                                    break;
                                }
                                lengths[i] = prev;
                                i += 1;
                            }
                        }
                        17 => {
                            let repeat = 3 + reader.bits(3) as usize;
                            i = (i + repeat).min(lengths.len());
                        }
                        18 => {
                            let repeat = 11 + reader.bits(7) as usize;
                            i = (i + repeat).min(lengths.len());
                        }
                        _ => return Err("недопустимый символ длины".into()),
                    }
                }

                let lit = Huffman::build(&lengths[..hlit]).ok_or("literal table")?;
                let dist = Huffman::build(&lengths[hlit..]).ok_or("distance table")?;
                inflate_block(&mut reader, &lit, &dist, &mut out)?;
            }
            _ => return Err("недопустимый тип блока".into()),
        }

        if last == 1 {
            break;
        }
    }

    Ok(out)
}

fn inflate_block(
    reader: &mut BitReader,
    lit: &Huffman,
    dist: &Huffman,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    loop {
        let symbol = lit.decode(reader).ok_or("символ литерала")?;
        if symbol < 256 {
            out.push(symbol as u8);
            continue;
        }
        if symbol == 256 {
            return Ok(());
        }
        let idx = (symbol - 257) as usize;
        if idx >= LENGTH_BASE.len() {
            return Err("длина вне диапазона".into());
        }
        let len = LENGTH_BASE[idx] as usize + reader.bits(LENGTH_EXTRA[idx] as u32) as usize;

        let dsym = dist.decode(reader).ok_or("символ расстояния")? as usize;
        if dsym >= DIST_BASE.len() {
            return Err("расстояние вне диапазона".into());
        }
        let distance = DIST_BASE[dsym] as usize + reader.bits(DIST_EXTRA[dsym] as u32) as usize;
        if distance == 0 || distance > out.len() {
            return Err("некорректное расстояние".into());
        }
        let start = out.len() - distance;
        for k in 0..len {
            let byte = out[start + k];
            out.push(byte);
        }
    }
}
