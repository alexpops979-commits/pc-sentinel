/** SVG-графики: дуговые датчики, кольца, спарклайны, линейные и столбчатые диаграммы. */

import { esc } from "./dom";

const C = {
  accent: "#4d9bff",
  accentDeep: "#1d4ed8",
  cyan: "#22d3ee",
  ok: "#2ee6a8",
  warn: "#f5b544",
  bad: "#ff5d6c",
  grid: "rgba(126,163,255,0.10)",
  muted: "rgba(126,163,255,0.35)",
};

function polar(cx: number, cy: number, r: number, deg: number): [number, number] {
  const a = (deg * Math.PI) / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

function arc(cx: number, cy: number, r: number, start: number, sweep: number): string {
  const [x0, y0] = polar(cx, cy, r, start);
  const [x1, y1] = polar(cx, cy, r, start + sweep);
  const large = Math.abs(sweep) > 180 ? 1 : 0;
  const dir = sweep >= 0 ? 1 : 0;
  return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${large} ${dir} ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

export function toneColor(tone: "ok" | "warn" | "bad" | "accent"): string {
  if (tone === "ok") return C.ok;
  if (tone === "warn") return C.warn;
  if (tone === "bad") return C.bad;
  return C.accent;
}

/** Пара оттенков для градиента дуги: от тёмного к насыщенному. */
function tonePair(tone: "ok" | "warn" | "bad" | "accent"): [string, string] {
  if (tone === "ok") return ["#0f9d74", "#2ee6a8"];
  if (tone === "warn") return ["#c07f16", "#f5b544"];
  if (tone === "bad") return ["#b62a3a", "#ff5d6c"];
  return [C.accentDeep, C.accent];
}

export interface GaugeOptions {
  value: number;
  max?: number;
  unit?: string;
  caption: string;
  tone?: "ok" | "warn" | "bad" | "accent";
  ticks?: number;
  digits?: number;
}

/** Дуговой датчик (180°) в стиле эталонных дашбордов. */
export function gaugeHtml(opts: GaugeOptions): string {
  const max = opts.max ?? 100;
  const ratio = Math.max(0, Math.min(1, opts.value / max));
  const tone = opts.tone ?? "accent";
  const color = toneColor(tone);
  const ticks = opts.ticks ?? 46;
  const cx = 100;
  const cy = 98;
  const rOuter = 78;
  const state = `g${Math.round(ratio * 1000)}-${tone}`;
  const [dark, bright] = tonePair(tone);

  let tickSvg = "";
  for (let i = 0; i < ticks; i += 1) {
    const pos = i / (ticks - 1);
    const deg = 180 + pos * 180;
    const len = pos <= ratio ? 13 : 8;
    const [x0, y0] = polar(cx, cy, rOuter - len, deg);
    const [x1, y1] = polar(cx, cy, rOuter, deg);
    const active = pos <= ratio;
    const opacity = active ? 0.95 - pos * 0.25 : 0.16;
    const stroke = active ? color : C.muted;
    tickSvg += `<line x1="${x0.toFixed(1)}" y1="${y0.toFixed(1)}" x2="${x1.toFixed(1)}" y2="${y1.toFixed(1)}" stroke="${stroke}" stroke-opacity="${opacity.toFixed(2)}" stroke-width="2" stroke-linecap="round"/>`;
  }

  const track = arc(cx, cy, 60, 180, 180);
  const progress = ratio > 0.002 ? arc(cx, cy, 60, 180, 180 * ratio) : "";

  const value = opts.value;
  const shown = Number.isFinite(value) ? value.toFixed(opts.digits ?? 0) : "—";

  return `
  <div class="gauge" data-state="${state}">
    <svg class="gauge__svg" viewBox="0 0 200 108" role="img" aria-label="${esc(opts.caption)}: ${esc(shown)}">
      <defs>
        <linearGradient id="g-${state}" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="${dark}"/>
          <stop offset="100%" stop-color="${bright}"/>
        </linearGradient>
        <filter id="glow-${state}" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="3.2" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      <path d="${track}" fill="none" stroke="rgba(126,163,255,0.13)" stroke-width="9" stroke-linecap="round"/>
      ${progress ? `<path d="${progress}" fill="none" stroke="url(#g-${state})" stroke-width="9" stroke-linecap="round" filter="url(#glow-${state})"/>` : ""}
      ${tickSvg}
    </svg>
    <div class="gauge__center">
      <span class="gauge__value">${esc(shown)}<span class="gauge__unit">${esc(opts.unit ?? "")}</span></span>
      <span class="gauge__caption">${esc(opts.caption)}</span>
    </div>
  </div>`;
}

/** Кольцевой индикатор общего состояния (270°). */
export function ringHtml(value: number, opts: { caption: string; tone: "ok" | "warn" | "bad" }): string {
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const sweep = 0.75;
  const ratio = Math.max(0, Math.min(1, value / 100));
  const [dark, bright] = tonePair(opts.tone);
  const state = `r${Math.round(ratio * 1000)}`;
  return `
  <div class="ring">
    <svg class="ring__svg" viewBox="0 0 160 160" role="img" aria-label="Оценка ${esc(Math.round(value))}">
      <defs>
        <linearGradient id="ring-${state}" x1="0" y1="1" x2="1" y2="0">
          <stop offset="0%" stop-color="${dark}"/>
          <stop offset="100%" stop-color="${bright}"/>
        </linearGradient>
        <filter id="ringglow-${state}" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="4" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      <circle cx="80" cy="80" r="${radius}" fill="none" stroke="rgba(126,163,255,0.10)" stroke-width="11"
        stroke-linecap="round" stroke-dasharray="${(circumference * sweep).toFixed(2)} ${circumference.toFixed(2)}"
        transform="rotate(135 80 80)"/>
      <circle cx="80" cy="80" r="${radius}" fill="none" stroke="url(#ring-${state})" stroke-width="11"
        stroke-linecap="round" stroke-dasharray="${(circumference * sweep * ratio).toFixed(2)} ${circumference.toFixed(2)}"
        transform="rotate(135 80 80)" filter="url(#ringglow-${state})"/>
    </svg>
    <div class="ring__center">
      <span class="ring__value">${Math.round(value)}</span>
      <span class="ring__caption">${esc(opts.caption)}</span>
    </div>
  </div>`;
}

/** Мини-график тренда. */
export function sparklineHtml(values: number[], tone: "accent" | "ok" | "warn" | "bad" = "accent"): string {
  const data = values.length > 1 ? values.slice(-120) : [0, 0];
  const w = 120;
  const h = 34;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const span = max - min;
  const color = toneColor(tone);
  const id = `sp${Math.round(span * 10)}${data.length}${tone}`;

  // Ровный ряд или слишком мало точек — тонкая линия без заливки,
  // иначе получается сплошной прямоугольник или клин.
  if (span < 0.5 || data.length < 4) {
    const y = (h * 0.55).toFixed(1);
    return `
  <svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
    <line x1="0" y1="${y}" x2="${w}" y2="${y}" stroke="${color}" stroke-opacity="0.45" stroke-width="1.4" stroke-linecap="round" stroke-dasharray="3 4"/>
  </svg>`;
  }

  const step = w / (data.length - 1);
  const points = data.map((v, i) => {
    const x = i * step;
    const y = h - ((v - min) / span) * (h - 6) - 3;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return `
  <svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
    <defs>
      <linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="${color}" stop-opacity="0.28"/>
        <stop offset="100%" stop-color="${color}" stop-opacity="0"/>
      </linearGradient>
    </defs>
    <polygon points="0,${h} ${points.join(" ")} ${w},${h}" fill="url(#${id})"/>
    <polyline points="${points.join(" ")}" fill="none" stroke="${color}" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/>
  </svg>`;
}

export interface LineSeries {
  name: string;
  color: string;
  values: number[];
}

/** Многоканальный график с сеткой и подписями. */
export function lineChartHtml(
  series: LineSeries[],
  opts: { height?: number; max?: number; area?: boolean; dots?: boolean } = {},
): string {
  const h = opts.height ?? 150;
  const w = 600;
  const padL = 30;
  const padR = 8;
  const padT = 8;
  const padB = 20;
  const max = opts.max ?? Math.max(10, ...series.flatMap((s) => s.values), 5);
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const withArea = opts.area ?? series.length === 1;

  let grid = "";
  for (let i = 0; i <= 4; i += 1) {
    const y = padT + (innerH / 4) * i;
    const label = Math.round(max - (max / 4) * i);
    grid += `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="${C.grid}" stroke-width="1"/>`;
    grid += `<text x="${padL - 6}" y="${y + 3}" text-anchor="end" font-size="9" fill="rgba(106,123,152,0.9)">${label}</text>`;
  }

  let paths = "";
  for (const s of series) {
    const data = s.values.length > 1 ? s.values : [0, 0];
    const step = innerW / Math.max(data.length - 1, 1);
    const pts = data.map((v, i) => {
      const x = padL + i * step;
      const y = padT + innerH - (Math.max(0, Math.min(max, v)) / max) * innerH;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });
    const id = `ln${s.name.replace(/[^a-zа-я0-9]/gi, "")}`;
    if (withArea) {
      paths += `<defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${s.color}" stop-opacity="0.26"/>
      <stop offset="100%" stop-color="${s.color}" stop-opacity="0"/>
    </linearGradient></defs>`;
      paths += `<polygon points="${padL},${padT + innerH} ${pts.join(" ")} ${padL + innerW},${padT + innerH}" fill="url(#${id})"/>`;
    }
    paths += `<polyline points="${pts.join(" ")}" fill="none" stroke="${s.color}" stroke-width="1.9" stroke-linejoin="round" stroke-linecap="round"/>`;
    if (opts.dots && data.length <= 60) {
      for (const point of pts) {
        const [px, py] = point.split(",");
        paths += `<circle cx="${px}" cy="${py}" r="2.4" fill="#0b111d" stroke="${s.color}" stroke-width="1.6"/>`;
      }
    }
  }

  return `
  <svg class="chart" viewBox="0 0 ${w} ${h}" role="img">
    ${grid}${paths}
  </svg>`;
}

export interface BarItem {
  label: string;
  value: number;
  suffix?: string;
  tone?: "accent" | "ok" | "warn" | "bad";
}

/** Горизонтальные полосы (статистика FPS). */
export function hbarsHtml(items: BarItem[], max?: number): string {
  const top = max ?? Math.max(...items.map((i) => i.value), 1);
  return `<div class="hbars">${items
    .map((item) => {
      const width = Math.max(1.5, (item.value / top) * 100);
      const color = toneColor(item.tone ?? "accent");
      return `
      <div class="hbar">
        <span class="hbar__label">${esc(item.label)}</span>
        <div class="hbar__track"><span class="hbar__fill" style="width:${width.toFixed(1)}%;background:linear-gradient(90deg,${color}33,${color})"></span></div>
        <span class="hbar__value">${esc(item.value.toFixed(item.suffix === "%" ? 1 : 0))}${esc(item.suffix ?? "")}</span>
      </div>`;
    })
    .join("")}</div>`;
}

/** Вертикальные столбцы с подписями (пороговые диаграммы, гистограммы). */
export function vbarsHtml(items: BarItem[], opts: { height?: number; highlightLast?: boolean } = {}): string {
  const h = opts.height ?? 132;
  const max = Math.max(...items.map((i) => i.value), 1);
  return `<div class="vbars" style="--vbars-h:${h}px">${items
    .map((item) => {
      const pctHeight = Math.max(1, (item.value / max) * 100);
      const color = toneColor(item.tone ?? "accent");
      return `
      <div class="vbar" title="${esc(item.label)}: ${item.value.toFixed(1)}${esc(item.suffix ?? "")}">
        <span class="vbar__value">${item.value.toFixed(item.value >= 10 ? 0 : 1)}${esc(item.suffix ?? "")}</span>
        <div class="vbar__track"><span class="vbar__fill" style="height:${pctHeight.toFixed(1)}%;background:linear-gradient(180deg,${color},${color}44)"></span></div>
        <span class="vbar__label">${esc(item.label)}</span>
      </div>`;
    })
    .join("")}</div>`;
}

/** График frametime с выделением выбросов. */
export function frametimeChartHtml(
  frametimes: number[],
  moving: number[],
  opts: { height?: number; threshold?: number } = {},
): string {
  const h = opts.height ?? 210;
  const w = 760;
  const padL = 34;
  const padR = 10;
  const padT = 10;
  const padB = 22;
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const data = frametimes.length > 1 ? frametimes : [16.7, 16.7];
  const max = Math.max(40, Math.ceil(Math.max(...data) / 10) * 10);
  const threshold = opts.threshold ?? Math.max(33.3, 0);

  let grid = "";
  for (let i = 0; i <= 4; i += 1) {
    const y = padT + (innerH / 4) * i;
    const label = Math.round(max - (max / 4) * i);
    grid += `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="${C.grid}"/>`;
    grid += `<text x="${padL - 6}" y="${y + 3}" text-anchor="end" font-size="9" fill="rgba(106,123,152,0.9)">${label}</text>`;
  }

  const step = innerW / Math.max(data.length - 1, 1);
  const toY = (v: number) => padT + innerH - (Math.max(0, Math.min(max, v)) / max) * innerH;

  const linePts = data.map((v, i) => `${(padL + i * step).toFixed(1)},${toY(v).toFixed(1)}`).join(" ");
  const movingPts = moving.map((v, i) => `${(padL + i * step).toFixed(1)},${toY(v).toFixed(1)}`).join(" ");
  const thresholdY = toY(threshold);

  let spikes = "";
  data.forEach((v, i) => {
    if (v > threshold) {
      const x = padL + i * step;
      spikes += `<circle cx="${x.toFixed(1)}" cy="${toY(v).toFixed(1)}" r="1.9" fill="${C.bad}" fill-opacity="0.9"/>`;
    }
  });

  return `
  <svg class="chart chart--ft" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img">
    <defs>
      <linearGradient id="ftfill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="${C.accent}" stop-opacity="0.30"/>
        <stop offset="100%" stop-color="${C.accent}" stop-opacity="0"/>
      </linearGradient>
    </defs>
    ${grid}
    <line x1="${padL}" y1="${thresholdY.toFixed(1)}" x2="${w - padR}" y2="${thresholdY.toFixed(1)}" stroke="${C.warn}" stroke-opacity="0.45" stroke-dasharray="4 4"/>
    <polygon points="${padL},${padT + innerH} ${linePts} ${padL + innerW},${padT + innerH}" fill="url(#ftfill)"/>
    <polyline points="${linePts}" fill="none" stroke="${C.accent}" stroke-width="1.2" stroke-linejoin="round"/>
    <polyline points="${movingPts}" fill="none" stroke="${C.cyan}" stroke-width="1.6" stroke-opacity="0.85" stroke-linejoin="round"/>
    ${spikes}
  </svg>`;
}

/* ---------- Виджеты с плавным обновлением ---------- */

/*
 * Дашборд опрашивает агента раз в 1.5 с. Если перерисовывать разметку целиком,
 * значения прыгают: дуга «телепортируется», число меняется рывком. Виджеты ниже
 * создают DOM один раз, а обновляют только атрибуты — CSS-переходы дорисовывают
 * промежуточные кадры, а числа доводятся анимацией по rAF.
 */

export type GaugeTone = "ok" | "warn" | "bad" | "accent";

const SVG_NS = "http://www.w3.org/2000/svg";
let widgetSeq = 0;

function svgEl<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string | number>): SVGElementTagNameMap[K] {
  const node = document.createElementNS(SVG_NS, tag) as SVGElementTagNameMap[K];
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  return node;
}

function easeOut(p: number): number {
  return 1 - (1 - p) ** 3;
}

/**
 * Непрерывное сглаживание: значение догоняет цель экспоненциально, кадр за кадром.
 * В отличие от фиксированного «твина» движение не замирает между опросами —
 * показатель всё время ползёт к новому значению, как в живом приборе.
 */
function createSmoother(initial: number, tauMs: number, apply: (v: number) => void): {
  set: (target: number) => void;
  stop: () => void;
} {
  let target = initial;
  let shown = initial;
  let raf = 0;
  let last = 0;

  const frame = (now: number): void => {
    // Первый кадр задаёт точку отсчёта: его отметка и последующие — с одних часов.
    const dt = last === 0 ? 16 : Math.min(64, Math.max(0, now - last));
    last = now;
    const k = 1 - Math.exp(-dt / tauMs);
    shown += (target - shown) * k;
    if (Math.abs(target - shown) < 0.05) shown = target;
    apply(shown);
    if (shown !== target) {
      raf = requestAnimationFrame(frame);
    } else {
      raf = 0;
      last = 0;
    }
  };

  return {
    set(next: number): void {
      target = next;
      if (raf === 0) {
        last = 0;
        raf = requestAnimationFrame(frame);
      }
    },
    stop(): void {
      if (raf !== 0) cancelAnimationFrame(raf);
      raf = 0;
      last = 0;
    },
  };
}

export interface GaugeHandle {
  el: HTMLElement;
  /** Новое значение и, при необходимости, тон/подпись/единица/предел. */
  set(value: number, opts?: Partial<Omit<GaugeOptions, "value">>): void;
}

/** Дуговой датчик, который обновляется на месте, а не перерисовывается. */
export function createGauge(initial: GaugeOptions): GaugeHandle {
  const id = `gw${(widgetSeq += 1)}`;
  const tickCount = initial.ticks ?? 46;
  const cx = 100;
  const cy = 98;
  const rOuter = 78;

  let max = initial.max ?? 100;
  let digits = initial.digits ?? 0;
  let tone: GaugeTone = initial.tone ?? "accent";
  let caption = initial.caption;
  let unit = initial.unit ?? "";

  const el = document.createElement("div");
  el.className = "gauge";
  const [dark, bright] = tonePair(tone);
  el.innerHTML = `
    <svg class="gauge__svg" viewBox="0 0 200 108" role="img" aria-label="${esc(caption)}">
      <defs>
        <linearGradient id="${id}-g" x1="0" y1="0" x2="1" y2="0">
          <stop class="gauge__stop" offset="0%" stop-color="${dark}"/>
          <stop class="gauge__stop" offset="100%" stop-color="${bright}"/>
        </linearGradient>
        <filter id="${id}-glow" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="3.2" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      <path d="${arc(cx, cy, 60, 180, 180)}" fill="none" stroke="rgba(126,163,255,0.13)" stroke-width="9" stroke-linecap="round"/>
      <path class="gauge__progress" d="${arc(cx, cy, 60, 180, 180)}" pathLength="100" fill="none"
        stroke="url(#${id}-g)" stroke-width="9" stroke-linecap="round" filter="url(#${id}-glow)"
        stroke-dasharray="100 100" stroke-dashoffset="100"/>
      <g class="gauge__ticks"></g>
    </svg>
    <div class="gauge__center">
      <span class="gauge__value"><span class="gauge__num"></span><span class="gauge__unit"></span></span>
      <span class="gauge__caption"></span>
    </div>`;

  const svg = el.querySelector("svg")!;
  const progress = el.querySelector<SVGPathElement>(".gauge__progress")!;
  const stopEls = Array.from(el.querySelectorAll<SVGStopElement>(".gauge__stop"));
  const tickGroup = el.querySelector<SVGGElement>(".gauge__ticks")!;
  const numEl = el.querySelector<HTMLElement>(".gauge__num")!;
  const unitEl = el.querySelector<HTMLElement>(".gauge__unit")!;
  const captionEl = el.querySelector<HTMLElement>(".gauge__caption")!;

  const dimTicks: SVGLineElement[] = [];
  const litTicks: SVGLineElement[] = [];
  for (let i = 0; i < tickCount; i += 1) {
    const pos = tickCount === 1 ? 0 : i / (tickCount - 1);
    const deg = 180 + pos * 180;
    const [dx0, dy0] = polar(cx, cy, rOuter - 8, deg);
    const [dx1, dy1] = polar(cx, cy, rOuter, deg);
    const [lx0, ly0] = polar(cx, cy, rOuter - 13, deg);
    const [lx1, ly1] = polar(cx, cy, rOuter, deg);
    const dim = svgEl("line", {
      x1: dx0.toFixed(1),
      y1: dy0.toFixed(1),
      x2: dx1.toFixed(1),
      y2: dy1.toFixed(1),
      stroke: C.muted,
      "stroke-opacity": 0.16,
      "stroke-width": 2,
      "stroke-linecap": "round",
    });
    const lit = svgEl("line", {
      x1: lx0.toFixed(1),
      y1: ly0.toFixed(1),
      x2: lx1.toFixed(1),
      y2: ly1.toFixed(1),
      stroke: toneColor(tone),
      "stroke-width": 2,
      "stroke-linecap": "round",
    });
    lit.style.opacity = "0";
    tickGroup.append(dim, lit);
    dimTicks.push(dim);
    litTicks.push(lit);
  }

  const setTickTone = (): void => {
    const color = toneColor(tone);
    for (const tick of litTicks) tick.setAttribute("stroke", color);
    const [from, to] = tonePair(tone);
    stopEls[0]?.setAttribute("stop-color", from);
    stopEls[1]?.setAttribute("stop-color", to);
  };

  /** Рисует состояние для текущего сглаженного значения. */
  const paint = (value: number): void => {
    const ratio = Math.max(0, Math.min(1, value / max));
    progress.style.strokeDashoffset = (100 - ratio * 100).toFixed(2);
    for (let i = 0; i < litTicks.length; i += 1) {
      const pos = tickCount === 1 ? 0 : i / (tickCount - 1);
      litTicks[i].style.opacity = pos <= ratio ? (0.95 - pos * 0.25).toFixed(2) : "0";
    }
    numEl.textContent = value.toFixed(digits);
  };

  // Постоянная времени подобрана под опрос раз в 1.5 с: движение занимает
  // почти весь интервал, поэтому стрелка не «дёргается и замирает».
  const smoother = createSmoother(Number.isFinite(initial.value) ? initial.value : 0, 260, paint);

  const set = (value: number, opts: Partial<Omit<GaugeOptions, "value">> = {}): void => {
    if (opts.max !== undefined) max = opts.max;
    if (opts.digits !== undefined) digits = opts.digits;
    if (opts.caption !== undefined) caption = opts.caption;
    if (opts.unit !== undefined) unit = opts.unit;
    if (opts.tone !== undefined && opts.tone !== tone) {
      tone = opts.tone;
      setTickTone();
    }

    captionEl.textContent = caption;
    unitEl.textContent = unit;
    svg.setAttribute("aria-label", `${caption}: ${Number.isFinite(value) ? value.toFixed(digits) : "—"}`);

    // Нет данных — не изобретаем число: гасим дугу и ставим прочерк.
    if (!Number.isFinite(value)) {
      smoother.stop();
      progress.style.strokeDashoffset = "100";
      for (const tick of litTicks) tick.style.opacity = "0";
      numEl.textContent = "—";
      return;
    }
    smoother.set(value);
  };

  paint(Number.isFinite(initial.value) ? initial.value : 0);
  set(initial.value, initial);

  return { el, set };
}

export interface RingHandle {
  el: HTMLElement;
  set(value: number, opts?: { caption?: string; tone?: "ok" | "warn" | "bad" }): void;
}

/** Кольцо общего состояния с плавным заполнением. */
export function createRing(initialValue: number, initial: { caption: string; tone: "ok" | "warn" | "bad" }): RingHandle {
  const id = `rg${(widgetSeq += 1)}`;
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const sweep = 0.75;

  let tone = initial.tone;
  let caption = initial.caption;
  const [dark, bright] = tonePair(tone);

  const el = document.createElement("div");
  el.className = "ring";
  el.innerHTML = `
    <svg class="ring__svg" viewBox="0 0 160 160" role="img" aria-label="Оценка ${Math.round(initialValue)}">
      <defs>
        <linearGradient id="${id}-g" x1="0" y1="1" x2="1" y2="0">
          <stop class="ring__stop" offset="0%" stop-color="${dark}"/>
          <stop class="ring__stop" offset="100%" stop-color="${bright}"/>
        </linearGradient>
        <filter id="${id}-glow" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="4" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      <circle cx="80" cy="80" r="${radius}" fill="none" stroke="rgba(126,163,255,0.10)" stroke-width="11"
        stroke-linecap="round" stroke-dasharray="${(circumference * sweep).toFixed(2)} ${circumference.toFixed(2)}"
        transform="rotate(135 80 80)"/>
      <circle class="ring__progress" cx="80" cy="80" r="${radius}" fill="none" stroke="url(#${id}-g)" stroke-width="11"
        stroke-linecap="round" stroke-dasharray="0 ${circumference.toFixed(2)}"
        transform="rotate(135 80 80)" filter="url(#${id}-glow)"/>
    </svg>
    <div class="ring__center">
      <span class="ring__value"></span>
      <span class="ring__caption"></span>
    </div>`;

  const svg = el.querySelector("svg")!;
  const progress = el.querySelector<SVGCircleElement>(".ring__progress")!;
  const stopEls = Array.from(el.querySelectorAll<SVGStopElement>(".ring__stop"));
  const valueEl = el.querySelector<HTMLElement>(".ring__value")!;
  const captionEl = el.querySelector<HTMLElement>(".ring__caption")!;

  const paint = (value: number): void => {
    const ratio = Math.max(0, Math.min(1, value / 100));
    progress.setAttribute(
      "stroke-dasharray",
      `${(circumference * sweep * ratio).toFixed(2)} ${circumference.toFixed(2)}`,
    );
    valueEl.textContent = String(Math.round(value));
  };

  const smoother = createSmoother(Number.isFinite(initialValue) ? initialValue : 0, 300, paint);

  const set = (value: number, opts: { caption?: string; tone?: "ok" | "warn" | "bad" } = {}): void => {
    if (opts.tone && opts.tone !== tone) {
      tone = opts.tone;
      const [from, to] = tonePair(tone);
      stopEls[0]?.setAttribute("stop-color", from);
      stopEls[1]?.setAttribute("stop-color", to);
    }
    if (opts.caption !== undefined) caption = opts.caption;

    svg.setAttribute("aria-label", `Оценка ${Math.round(value)}`);
    captionEl.textContent = caption;
    smoother.set(Number.isFinite(value) ? value : 0);
  };

  paint(Number.isFinite(initialValue) ? initialValue : 0);
  set(initialValue, initial);
  return { el, set };
}

export interface LineChartHandle {
  el: HTMLElement;
  set(series: LineSeries[]): void;
}

/** Многоканальный график, который плавно перетекает к новым значениям. */
export function createLineChart(
  initial: LineSeries[],
  opts: { height?: number; max?: number; area?: boolean; dots?: boolean; duration?: number } = {},
): LineChartHandle {
  const h = opts.height ?? 150;
  const w = 600;
  const padL = 30;
  const padR = 8;
  const padT = 8;
  const padB = 20;
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const withArea = opts.area ?? initial.length === 1;
  const duration = opts.duration ?? 480;

  const el = document.createElement("div");
  el.className = "chart-wrap";
  const svg = svgEl("svg", { class: "chart", viewBox: `0 0 ${w} ${h}`, role: "img" });
  const gridGroup = svgEl("g", { class: "chart__grid" });
  const pathGroup = svgEl("g", { class: "chart__paths" });
  svg.append(gridGroup, pathGroup);
  el.append(svg);

  interface Slot {
    color: string;
    line: SVGElement;
    area?: SVGElement;
  }
  const slots = new Map<string, Slot>();
  const rendered = new Map<string, number[]>();
  let cancel = (): void => undefined;

  const bounds = (series: LineSeries[]): number => opts.max ?? Math.max(10, ...series.flatMap((s) => s.values), 5);

  const drawGrid = (max: number): void => {
    gridGroup.replaceChildren();
    for (let i = 0; i <= 4; i += 1) {
      const y = padT + (innerH / 4) * i;
      gridGroup.append(
        svgEl("line", { x1: padL, y1: y, x2: w - padR, y2: y, stroke: C.grid, "stroke-width": 1 }),
        svgEl("text", {
          x: padL - 6,
          y: y + 3,
          "text-anchor": "end",
          "font-size": 9,
          fill: "rgba(106,123,152,0.9)",
        }),
      );
      (gridGroup.lastChild as SVGTextElement).textContent = String(Math.round(max - (max / 4) * i));
    }
  };

  /** Точки в координатах SVG для набора значений. */
  const toPoints = (values: number[], max: number): string => {
    const step = innerW / Math.max(values.length - 1, 1);
    return values
      .map((v, i) => {
        const x = padL + i * step;
        const y = padT + innerH - (Math.max(0, Math.min(max, v)) / max) * innerH;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  };

  const paint = (max: number): void => {
    for (const [name, slot] of slots) {
      const values = rendered.get(name) ?? [];
      const points = toPoints(values, max);
      slot.line.setAttribute("points", points);
      slot.area?.setAttribute("points", `${padL},${padT + innerH} ${points} ${padL + innerW},${padT + innerH}`);
    }
  };

  const ensureSlots = (series: LineSeries[]): void => {
    for (const s of series) {
      if (slots.has(s.name)) continue;
      const area = withArea
        ? (() => {
            const gradientId = `ln${s.name.replace(/[^a-zа-я0-9]/gi, "")}${widgetSeq}`;
            const defs = svgEl("defs", {});
            const gradient = svgEl("linearGradient", { id: gradientId, x1: 0, y1: 0, x2: 0, y2: 1 });
            gradient.append(
              svgEl("stop", { offset: "0%", "stop-color": s.color, "stop-opacity": 0.26 }),
              svgEl("stop", { offset: "100%", "stop-color": s.color, "stop-opacity": 0 }),
            );
            defs.append(gradient);
            svg.prepend(defs);
            const polygon = svgEl("polygon", { points: "", fill: `url(#${gradientId})` });
            pathGroup.append(polygon);
            return polygon;
          })()
        : undefined;
      const line = svgEl("polyline", {
        points: "",
        fill: "none",
        stroke: s.color,
        "stroke-width": 1.9,
        "stroke-linejoin": "round",
        "stroke-linecap": "round",
      });
      pathGroup.append(line);
      slots.set(s.name, { color: s.color, line, area });
    }
  };

  const set = (series: LineSeries[]): void => {
    ensureSlots(series);
    const max = bounds(series);
    drawGrid(max);

    // Стартовые значения — то, что уже нарисовано; при смене длины ряда
    // (история ещё копится) анимировать нечего, берём новые как есть.
    const pairs = series.map((s) => {
      const current = rendered.get(s.name);
      const target = s.values.length > 1 ? s.values : [0, 0];
      const start = current && current.length === target.length ? current.slice() : target.slice();
      return { name: s.name, start, target };
    });

    // Сразу рисуем стартовое состояние: если обновления придут чаще кадров,
    // график не должен оставаться пустым до первого requestAnimationFrame.
    for (const pair of pairs) rendered.set(pair.name, pair.start);
    paint(max);

    cancel();
    let begin = -1;
    const step = (now: number): void => {
      if (begin < 0) begin = now;
      const p = Math.max(0, Math.min(1, (now - begin) / duration));
      const e = easeOut(p);
      for (const pair of pairs) {
        const values = pair.target.map((v, i) => pair.start[i] + (v - pair.start[i]) * e);
        rendered.set(pair.name, values);
      }
      paint(max);
      if (p < 1) raf = requestAnimationFrame(step);
    };
    let raf = requestAnimationFrame(step);
    cancel = () => cancelAnimationFrame(raf);
  };

  set(initial);
  return { el, set };
}
