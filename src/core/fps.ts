/** Клиентский разбор CSV-захватов frametime (PresentMon / CapFrameX). */

import type { FpsReport } from "./api";

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.round((sorted.length - 1) * p);
  return sorted[Math.min(Math.max(idx, 0), sorted.length - 1)];
}

function slowestAvg(sorted: number[], fraction: number): number {
  if (sorted.length === 0) return 0;
  const n = Math.max(1, Math.ceil(sorted.length * fraction));
  const slice = sorted.slice(sorted.length - n);
  const sum = slice.reduce((a, b) => a + b, 0);
  return 1000 / (sum / n);
}

export function analyzeFrametimes(name: string, frametimes: number[]): FpsReport {
  const sorted = [...frametimes].sort((a, b) => a - b);
  const n = frametimes.length;
  const median = percentile(sorted, 0.5);
  const total = frametimes.reduce((a, b) => a + b, 0);
  const avgFt = total / n;
  const stutterLimit = Math.max(median * 2, 33.3);
  const stutters = frametimes.filter((v) => v > stutterLimit).length;

  const target = 700;
  const step = Math.max(1, Math.ceil(n / target));
  const series: number[] = [];
  for (let i = 0; i < n; i += step) {
    let peak = 0;
    for (let j = i; j < Math.min(i + step, n); j += 1) peak = Math.max(peak, frametimes[j]);
    series.push(peak);
  }
  const moving = series.map((_, i) => {
    const start = Math.max(0, i - 12);
    const slice = series.slice(start, i + 1);
    return slice.reduce((a, b) => a + b, 0) / slice.length;
  });

  const thresholds = [10, 15, 30, 45, 60, 75, 90, 120, 144, 240].map((t) => ({
    label: `>${t}`,
    value: (frametimes.filter((ft) => 1000 / ft > t).length / n) * 100,
  }));

  const buckets = [0, 8, 11, 14, 16.7, 20, 25, 33.3, 50, 100, 1000];
  const labels: string[] = [];
  for (let i = 0; i < buckets.length - 1; i += 1) {
    labels.push(`${Math.round(buckets[i])}–${Math.round(buckets[i + 1])}`);
  }
  const counts = new Array(buckets.length - 1).fill(0);
  for (const ft of frametimes) {
    for (let i = 0; i < buckets.length - 1; i += 1) {
      if (ft >= buckets[i] && ft < buckets[i + 1]) {
        counts[i] += 1;
        break;
      }
    }
  }
  const maxCount = Math.max(...counts, 1);
  const histogram = counts.map((c) => (c / maxCount) * 100);

  const avgFps = 1000 / avgFt;
  const stutterRatio = (stutters / n) * 100;
  let verdict = "Приемлемая стабильность: единичные выбросы frametime без системной проблемы.";
  if (avgFps < 30) {
    verdict = "Игра работает ниже комфортного уровня: стоит снизить пресет графики и проверить фоновые процессы.";
  } else if (stutterRatio > 3) {
    verdict = "Средний FPS в норме, но есть заметные микрофризы — проверьте фоновые задачи и лимиты энергопотребления.";
  } else if (avgFps >= 60 && stutterRatio < 1) {
    verdict = "Стабильная картина: frametime ровный, заметных микрофризов нет.";
  }

  return {
    app: name,
    session: name,
    source: "import",
    duration: total / 1000,
    frames: n,
    avgFps,
    maxFps: 1000 / (sorted[0] ?? 16.7),
    minFps: 1000 / (sorted[sorted.length - 1] ?? 16.7),
    p1Low: slowestAvg(sorted, 0.01),
    p5Low: slowestAvg(sorted, 0.05),
    p01Low: slowestAvg(sorted, 0.001),
    stutters,
    stutterRatio,
    series,
    moving,
    thresholds,
    histogram,
    histogramLabels: labels,
    verdict,
    score: smoothnessScore(avgFps, slowestAvg(sorted, 0.01), stutterRatio),
  };
}

/** Оценка плавности 0–100: та же формула, что в агенте. */
function smoothnessScore(avgFps: number, p1Low: number, stutterPercent: number): number {
  let score = 100;
  score -= Math.max(0, 55 - Math.min(avgFps, 55)) * 0.8;
  score -= Math.max(0, avgFps - p1Low) * 0.9;
  score -= stutterPercent * 120;
  return Math.max(0, Math.min(100, score));
}

/** Разбор CSV/TSV: ищем колонку с frametime (мс). */
export function parseCaptureCsv(text: string, name: string): FpsReport {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) throw new Error("Файл пуст или не содержит данных");
  const header = lines[0];
  const delimiter = header.includes(";") ? ";" : header.includes("\t") ? "\t" : ",";
  const columns = header.split(delimiter).map((c) => c.trim().replace(/^"|"$/g, "").toLowerCase());
  let index = columns.findIndex((c) => c.includes("msbetweenpresents") || c.includes("frametime") || c === "ms");
  if (index < 0) index = columns.length - 1;

  const values: number[] = [];
  for (let i = 1; i < lines.length; i += 1) {
    const cells = lines[i].split(delimiter);
    const raw = cells[index];
    if (!raw) continue;
    const parsed = Number.parseFloat(raw.trim().replace(/^"|"$/g, "").replace(",", "."));
    if (Number.isFinite(parsed) && parsed > 0.5 && parsed < 2000) values.push(parsed);
  }
  if (values.length < 60) throw new Error("Слишком мало кадров для анализа (нужно минимум 60)");
  return analyzeFrametimes(name, values);
}
