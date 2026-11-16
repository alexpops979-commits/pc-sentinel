//! Анализ frametime: импорт захватов PresentMon / CapFrameX.
//!
//! Демонстрационных данных нет: пока захватов не импортировано, экран
//! показывает пустое состояние, а не выдуманные цифры.

use crate::json::J;

pub struct FpsReport {
    pub app: String,
    pub session: String,
    pub source: String,
    pub duration_s: f64,
    pub frames: usize,
    pub avg_fps: f64,
    pub max_fps: f64,
    pub min_fps: f64,
    pub p1_low: f64,
    pub p5_low: f64,
    pub p01_low: f64,
    pub stutters: usize,
    pub stutter_ratio: f64,
    pub series: Vec<f64>,
    pub moving: Vec<f64>,
    pub thresholds: Vec<(String, f64)>,
    pub histogram: Vec<f64>,
    pub histogram_labels: Vec<String>,
    pub verdict: String,
}

impl FpsReport {
    pub fn to_json(&self) -> J {
        J::obj(vec![
            ("app", J::s(self.app.clone())),
            ("session", J::s(self.session.clone())),
            ("source", J::s(self.source.clone())),
            ("duration", J::num(self.duration_s)),
            ("frames", J::Int(self.frames as i64)),
            ("avgFps", J::num(self.avg_fps)),
            ("maxFps", J::num(self.max_fps)),
            ("minFps", J::num(self.min_fps)),
            ("p1Low", J::num(self.p1_low)),
            ("p5Low", J::num(self.p5_low)),
            ("p01Low", J::num(self.p01_low)),
            ("stutters", J::Int(self.stutters as i64)),
            ("stutterRatio", J::num(self.stutter_ratio * 100.0)),
            (
                "series",
                J::Arr(self.series.iter().map(|v| J::num(*v)).collect()),
            ),
            (
                "moving",
                J::Arr(self.moving.iter().map(|v| J::num(*v)).collect()),
            ),
            (
                "thresholds",
                J::Arr(
                    self.thresholds
                        .iter()
                        .map(|(label, pct)| {
                            J::obj(vec![("label", J::s(label.clone())), ("value", J::num(*pct))])
                        })
                        .collect(),
                ),
            ),
            (
                "histogram",
                J::Arr(self.histogram.iter().map(|v| J::num(*v)).collect()),
            ),
            (
                "histogramLabels",
                J::Arr(self.histogram_labels.iter().map(|v| J::s(v.clone())).collect()),
            ),
            ("verdict", J::s(self.verdict.clone())),
            ("score", J::num(self.score())),
        ])
    }

    pub fn score(&self) -> f64 {
        let mut s = 100.0;
        s -= (55.0 - self.avg_fps.min(55.0)).max(0.0) * 0.8;
        s -= (self.avg_fps - self.p1_low).max(0.0) * 0.9;
        s -= self.stutter_ratio * 120.0;
        s.clamp(0.0, 100.0)
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn slowest_avg(sorted: &[f64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let n = ((sorted.len() as f64 * fraction).ceil() as usize).max(1);
    let slice = &sorted[sorted.len() - n..];
    let sum: f64 = slice.iter().sum();
    1000.0 / (sum / n as f64)
}

fn build_from_frametimes(app: &str, session: &str, source: &str, frametimes: Vec<f64>) -> FpsReport {
    let mut sorted = frametimes.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = frametimes.len().max(1);
    let median = percentile(&sorted, 0.5);
    let total: f64 = frametimes.iter().sum();
    let avg_ft = total / n as f64;
    let stutter_limit = (median * 2.0).max(33.3);
    let stutters = frametimes.iter().filter(|v| **v > stutter_limit).count();

    // График: сжимаем до ~700 точек, сохраняя пики.
    let target = 700usize;
    let step = (frametimes.len() as f64 / target as f64).ceil().max(1.0) as usize;
    let mut series = Vec::new();
    for chunk in frametimes.chunks(step) {
        let mx = chunk.iter().cloned().fold(0.0f64, f64::max);
        series.push(mx);
    }
    let mut moving = Vec::with_capacity(series.len());
    let window = 12usize;
    for i in 0..series.len() {
        let start = i.saturating_sub(window);
        let slice = &series[start..i + 1];
        let sum: f64 = slice.iter().sum();
        moving.push(sum / slice.len() as f64);
    }

    // Пороговая диаграмма: доля кадров с FPS выше порога.
    let thresholds = [10.0, 15.0, 30.0, 45.0, 60.0, 75.0, 90.0, 120.0, 144.0, 240.0];
    let threshold_values = thresholds
        .iter()
        .map(|t| {
            let count = frametimes.iter().filter(|ft| 1000.0 / **ft > *t).count();
            (format!(">{t:.0}"), count as f64 / n as f64 * 100.0)
        })
        .collect();

    // Гистограмма frametime.
    let buckets = [0.0, 8.0, 11.0, 14.0, 16.7, 20.0, 25.0, 33.3, 50.0, 100.0, 1000.0];
    let labels: Vec<String> = buckets.windows(2).map(|w| format!("{:.0}–{:.0}", w[0], w[1])).collect();
    let mut histogram = vec![0.0; buckets.len() - 1];
    for ft in &frametimes {
        for i in 0..buckets.len() - 1 {
            if *ft >= buckets[i] && *ft < buckets[i + 1] {
                histogram[i] += 1.0;
                break;
            }
        }
    }
    let max_bucket = histogram.iter().cloned().fold(1.0f64, f64::max);
    for v in histogram.iter_mut() {
        *v = *v / max_bucket * 100.0;
    }

    let avg_fps = 1000.0 / avg_ft;
    let p1_low = slowest_avg(&sorted, 0.01);
    let p5_low = slowest_avg(&sorted, 0.05);
    let p01_low = slowest_avg(&sorted, 0.001);
    let stutter_ratio = stutters as f64 / n as f64;

    let verdict = if avg_fps < 30.0 {
        "Игра работает ниже комфортного уровня: стоит снизить пресет графики и проверить фоновые процессы.".to_string()
    } else if stutter_ratio > 0.03 {
        "Средний FPS в норме, но есть заметные микрофризы — проверьте фоновые задачи и лимиты энергопотребления.".to_string()
    } else if avg_fps >= 60.0 && stutter_ratio < 0.01 {
        "Стабильная картина: frametime ровный, заметных микрофризов нет.".to_string()
    } else {
        "Приемлемая стабильность: единичные выбросы frametime без системной проблемы.".to_string()
    };

    FpsReport {
        app: app.to_string(),
        session: session.to_string(),
        source: source.to_string(),
        duration_s: total / 1000.0,
        frames: n,
        avg_fps,
        max_fps: 1000.0 / sorted.first().copied().unwrap_or(16.7),
        min_fps: 1000.0 / sorted.last().copied().unwrap_or(16.7),
        p1_low,
        p5_low,
        p01_low,
        stutters,
        stutter_ratio,
        series,
        moving,
        thresholds: threshold_values,
        histogram,
        histogram_labels: labels,
        verdict,
    }
}

/// Проверка формул анализа на синтетическом ряде. Используется только в `--diag`
/// debug-сборки: в интерфейс эти данные никогда не попадают.
#[cfg(debug_assertions)]
pub fn selftest_report() -> FpsReport {
    let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((seed >> 33) as f64) / ((1u64 << 31) as f64)
    };
    let mut frametimes = Vec::with_capacity(4400);
    for i in 0..4380 {
        let wave = (i as f64 * 0.03).sin() * 0.9;
        let jitter = (next() - 0.5) * 3.4;
        let mut ft = 16.1 + wave + jitter;
        let roll = next();
        if roll > 0.995 {
            ft += 12.0 + next() * 26.0;
        } else if roll > 0.975 {
            ft += 3.5 + next() * 6.0;
        }
        if i == 2420 {
            ft = 46.5;
        }
        frametimes.push(ft.clamp(4.5, 70.0));
    }
    build_from_frametimes("selftest", "selftest", "selftest", frametimes)
}

pub fn import_capture(path: &str) -> Result<FpsReport, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Не удалось прочитать файл: {e}"))?;
    let mut lines = content.lines().filter(|l| !l.trim().is_empty());
    let header = lines.next().ok_or("Файл пуст")?;
    let delimiter = if header.contains(';') {
        ';'
    } else if header.contains('\t') {
        '\t'
    } else {
        ','
    };
    let columns: Vec<String> = header
        .split(delimiter)
        .map(|c| c.trim().trim_matches('"').to_ascii_lowercase())
        .collect();
    let time_idx = columns
        .iter()
        .position(|c| c.contains("msbetweenpresents") || c.contains("frametime") || c == "ms");
    let col_idx = match time_idx {
        Some(i) => i,
        None => columns.len().saturating_sub(1),
    };
    let mut frametimes = Vec::new();
    for line in lines {
        let parts: Vec<&str> = line.split(delimiter).collect();
        if let Some(raw) = parts.get(col_idx) {
            let cleaned = raw.trim().trim_matches('"').replace(',', ".");
            if let Ok(v) = cleaned.parse::<f64>() {
                if v > 0.5 && v < 2000.0 {
                    frametimes.push(v);
                }
            }
        }
    }
    if frametimes.len() < 60 {
        return Err("В файле слишком мало кадров для анализа (нужно минимум 60)".to_string());
    }
    let name = std::path::Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "Захват".to_string());
    Ok(build_from_frametimes(&name, &name, "import", frametimes))
}
