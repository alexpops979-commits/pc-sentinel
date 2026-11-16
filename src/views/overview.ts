/** Экран «Обзор». */

import { createGauge, createLineChart, createRing, sparklineHtml } from "../core/charts";
import type { GaugeHandle } from "../core/charts";
import { esc, icon } from "../core/dom";
import { bytes, loadTone, num, pct, procInitials, rate, scoreTone, uptime } from "../core/format";
import { badge, emptyState } from "../core/ui";
import type { Snapshot } from "../core/api";
import type { AppState } from "../core/store";
import type { View, ViewContext } from "./types";

interface TileOptions {
  value: number;
  tone: "ok" | "warn" | "bad" | "accent";
  caption: string;
  unit: string;
  facts: Array<[string, string]>;
  spark: string;
  badge?: { text: string; tone: "ok" | "warn" | "bad" | "accent" | "muted" };
}

/**
 * Плитка создаётся один раз: датчик и число обновляются на месте, поэтому
 * рост нагрузки виден плавно, а не скачком раз в опрос.
 */
function createTile(label: string, iconName: string): { el: HTMLElement; update: (opts: TileOptions) => void } {
  const el = document.createElement("article");
  el.className = "metric";
  el.innerHTML = `
    <div class="metric__top">
      <div class="metric__label"><span class="metric__icon">${icon(iconName, 14)}</span>${esc(label)}</div>
      <span class="metric__badge"></span>
    </div>
    <div class="metric__gauge"></div>
    <div class="metric__facts"></div>
    <div class="metric__spark"></div>`;

  const badgeEl = el.querySelector<HTMLElement>(".metric__badge")!;
  const factsEl = el.querySelector<HTMLElement>(".metric__facts")!;
  const sparkEl = el.querySelector<HTMLElement>(".metric__spark")!;
  const gauge: GaugeHandle = createGauge({ value: 0, caption: "Загрузка", unit: "%", ticks: 40 });
  el.querySelector(".metric__gauge")!.append(gauge.el);

  const update = (opts: TileOptions): void => {
    gauge.set(opts.value, { tone: opts.tone, caption: opts.caption, unit: opts.unit });
    badgeEl.innerHTML = opts.badge ? badge(opts.badge.text, opts.badge.tone) : "";
    factsEl.innerHTML = opts.facts
      .map(([k, v]) => `<div class="fact"><span>${esc(k)}</span><b>${esc(v)}</b></div>`)
      .join("");
    sparkEl.innerHTML = opts.spark;
  };

  return { el, update };
}

function findingsCard(state: AppState): string {
  const report = state.health;
  const issues = report?.issues ?? [];
  const rows =
    issues.length === 0
      ? emptyState("Проблем не найдено", "Все ключевые показатели в норме", "shieldCheck")
      : issues
          .slice(0, 4)
          .map((issue) => {
            const tone = issue.severity === "critical" ? "bad" : issue.severity === "warning" ? "warn" : "accent";
            return `
        <div class="row">
          <span class="dot dot--${tone === "bad" ? "bad" : tone === "warn" ? "warn" : "live"}"></span>
          <div class="row__main">
            <div class="row__title">${esc(issue.title)}</div>
            <div class="row__desc">${esc(issue.detail)}</div>
          </div>
          ${badge(issue.severity === "critical" ? "критично" : "внимание", tone)}
        </div>`;
          })
          .join("");

  const top = (state.snapshot?.procs ?? [])
    .filter((p) => p.cpu > 0.5)
    .slice(0, 4);
  const maxCpu = Math.max(...top.map((p) => p.cpu), 1);
  const topRows =
    top.length === 0
      ? ""
      : top
          .map(
            (p) => `
        <div class="row row--compact">
          <span class="proc-icon">${esc(procInitials(p.name))}</span>
          <div class="row__main">
            <div class="row__title">${esc(p.name)}</div>
            <div class="row__desc mono dim">PID ${p.pid} · ${bytes(p.mem)}</div>
          </div>
          <div class="row__meta load-mini">
            <span class="mono">${p.cpu.toFixed(1)}%</span>
            <span class="load-mini__bar"><i style="width:${Math.min(100, (p.cpu / maxCpu) * 100).toFixed(0)}%"></i></span>
          </div>
        </div>`,
          )
          .join("");

  return `
  <div class="card__head">
    <div class="card__title">${icon("alert", 16)}Что тормозит систему</div>
    <span class="card__sub">${issues.length} ${issues.length === 1 ? "сигнал" : "сигналов"}</span>
  </div>
  <div class="card__body card__body--flush">${rows}</div>
  ${
    topRows
      ? `<div class="card__head card__head--sub">
           <div class="card__title">${icon("layers", 15)}Топ по нагрузке</div>
           <span class="card__sub">CPU</span>
         </div>
         <div class="card__body card__body--flush">${topRows}</div>`
      : ""
  }`;
}

function healthComponentsHtml(report: AppState["health"]): string {
  const components = report?.components ?? [];
  return components
    .map((c) => {
      // Нет данных — показываем прочерк и пустую шкалу, а не выдуманное число.
      if (c.score === null) {
        return `
        <div class="comp comp--empty">
          <div class="comp__head"><span>${esc(c.name)}</span><b>—</b></div>
          <div class="bar bar--empty"></div>
          <div class="comp__detail">${esc(c.detail)}</div>
        </div>`;
      }
      const t = scoreTone(c.score);
      // Для температуры показываем градусы, а шкалу — по самой температуре:
      // балл охлаждения рядом с подписью «Температура» читался бы как градусы.
      const shown = c.value ?? String(Math.round(c.score));
      const fill = Math.max(2, c.ratio ?? c.score);
      return `
        <div class="comp">
          <div class="comp__head"><span>${esc(c.name)}</span><b>${esc(shown)}</b></div>
          <div class="bar"><span class="bar__fill bar__fill--${t}" style="width:${fill.toFixed(1)}%"></span></div>
          <div class="comp__detail">${esc(c.detail)}</div>
        </div>`;
    })
    .join("");
}

export function createOverview(ctx: ViewContext): View {
  const el = document.createElement("section");
  el.className = "view-grid";
  el.innerHTML = `
    <div class="tiles" data-tiles></div>
    <div class="grid grid--2" data-row-health>
      <div class="card card--glow" data-health></div>
      <div class="card" data-findings></div>
    </div>
    <div class="grid grid--2" data-row-live>
      <div class="card" data-live></div>
      <div class="card" data-actions></div>
    </div>`;

  const tiles = el.querySelector<HTMLElement>("[data-tiles]")!;
  const health = el.querySelector<HTMLElement>("[data-health]")!;
  const findings = el.querySelector<HTMLElement>("[data-findings]")!;
  const live = el.querySelector<HTMLElement>("[data-live]")!;
  const actions = el.querySelector<HTMLElement>("[data-actions]")!;
  const rowHealth = el.querySelector<HTMLElement>("[data-row-health]")!;
  const rowLive = el.querySelector<HTMLElement>("[data-row-live]")!;

  // Постоянные узлы: пока данные обновляются на месте, CSS-переходы успевают
  // дорисовать рост показателя вместо телепортации раз в 1.5 с.
  const cpuTile = createTile("Процессор", "cpu");
  const gpuTile = createTile("Видеокарта", "gpu");
  const memTile = createTile("Память", "memory");
  const diskTile = createTile("Накопители", "disk");
  const tileEls = [cpuTile.el, gpuTile.el, memTile.el, diskTile.el];

  health.innerHTML = `
    <div class="card__head">
      <div class="card__title">${icon("shieldCheck", 16)}Здоровье системы</div>
      <span class="card__sub" data-health-sub></span>
    </div>
    <div class="card__body health"><div class="health__ring"></div><div class="health__components"></div></div>`;
  const healthSub = health.querySelector<HTMLElement>("[data-health-sub]")!;
  const healthComponents = health.querySelector<HTMLElement>(".health__components")!;
  const healthRing = createRing(0, { caption: "—", tone: "warn" });
  health.querySelector(".health__ring")!.append(healthRing.el);

  live.innerHTML = `
    <div class="card__head">
      <div class="card__title">${icon("activity", 16)}Нагрузка в реальном времени</div>
      <div class="legend" data-legend></div>
    </div>
    <div class="card__body" data-live-body></div>`;
  const legend = live.querySelector<HTMLElement>("[data-legend]")!;
  const liveChart = createLineChart([], { height: 168, max: 100 });
  live.querySelector("[data-live-body]")!.append(liveChart.el);

  actions.innerHTML = `
    <div class="card__head">
      <div class="card__title">${icon("zap", 16)}Быстрые действия</div>
      <span class="card__sub">один клик</span>
    </div>
    <div class="card__body card__body--flush">
      <button class="row row--action" data-scan>
        <span class="row__icon">${icon("shield", 16)}</span>
        <div class="row__main">
          <div class="row__title">Проверить защиту</div>
          <div class="row__desc">Подписи, майнеры, автозапуск, сеть</div>
        </div>
        <span class="row__chev">${icon("chevronRight", 16)}</span>
      </button>
      <button class="row row--action" data-nav="fps">
        <span class="row__icon">${icon("gauge", 16)}</span>
        <div class="row__main">
          <div class="row__title">Анализ FPS</div>
          <div class="row__desc">Frametime, микрофризы, 1% low</div>
        </div>
        <span class="row__chev">${icon("chevronRight", 16)}</span>
      </button>
      <button class="row row--action" data-nav="optimize">
        <span class="row__icon">${icon("wrench", 16)}</span>
        <div class="row__main">
          <div class="row__title">Оптимизация</div>
          <div class="row__desc">Безопасные действия с объяснением</div>
        </div>
        <span class="row__chev">${icon("chevronRight", 16)}</span>
      </button>
      <button class="row row--action" data-nav="history">
        <span class="row__icon">${icon("clock", 16)}</span>
        <div class="row__main">
          <div class="row__title">История состояния</div>
          <div class="row__desc">Оценка и проблемы во времени</div>
        </div>
        <span class="row__chev">${icon("chevronRight", 16)}</span>
      </button>
    </div>`;

  const offlineTiles = document.createElement("div");
  offlineTiles.className = "card tiles__offline";
  offlineTiles.innerHTML = emptyState(
    "Нет данных: агент не отвечает",
    "Показатели появятся, как только связь восстановится",
    "alert",
  );

  let tilesMode: "data" | "loading" | "offline" | null = null;
  const setTilesMode = (mode: "data" | "loading" | "offline"): void => {
    if (tilesMode === mode) return;
    tilesMode = mode;
    if (mode === "data") {
      tiles.replaceChildren(...tileEls);
    } else if (mode === "loading") {
      tiles.replaceChildren(
        ...Array.from({ length: 4 }, () => {
          const node = document.createElement("div");
          node.className = "metric metric--skeleton";
          return node;
        }),
      );
    } else {
      tiles.replaceChildren(offlineTiles);
    }
  };

  el.addEventListener("click", (event) => {
    const target = (event.target as HTMLElement).closest<HTMLElement>("[data-nav]");
    if (target?.dataset.nav) ctx.navigate(target.dataset.nav as never);
    const scan = (event.target as HTMLElement).closest("[data-scan]");
    if (scan) void ctx.runScan();
  });

  const render = (state: AppState): void => {
    const snap = state.snapshot;
    if (!snap) {
      // Без данных не крутим бесконечные заглушки: показываем причину.
      setTilesMode(state.online ? "loading" : "offline");
      findings.innerHTML = "";
      // Пустые рамки карточек без данных только мешают.
      rowHealth.hidden = true;
      rowLive.hidden = true;
      return;
    }

    setTilesMode("data");
    rowHealth.hidden = false;
    rowLive.hidden = false;

    const series = state.series;
    const cpuSpark = sparklineHtml(series.map((s) => s.cpu), loadTone(snap.cpu.usage));
    const gpuSpark = sparklineHtml(series.map((s) => s.gpu), "accent");
    const memSpark = sparklineHtml(series.map((s) => s.mem), loadTone(snap.mem.percent));
    const diskSpark = sparklineHtml(series.map((s) => s.disk), loadTone(snap.disks[0]?.percent ?? 0));

    const cpuFacts: Array<[string, string]> = [
      ["Ядра", String(snap.cpu.cores)],
      ["Частота", snap.cpu.mhz > 0 ? `${snap.cpu.mhz} МГц` : "—"],
      ["Потоки", num(snap.cpu.threads)],
      ["Процессы", num(snap.cpu.processes)],
      ["Дескрипторы", num(snap.cpu.handles)],
      ["Время работы", uptime(snap.uptime)],
    ];

    const gpuFacts: Array<[string, string]> = snap.gpu.available
      ? [
          // Датчик отдаёт десятые доли — показываем их, иначе на холостом ходу
          // целые градусы выглядят «залипшими».
          ["Температура", `${snap.gpu.temp.toFixed(1)} °C`],
          ["Частота", `${snap.gpu.clock} МГц`],
          ["Кулер", snap.gpu.fan > 0 ? `${snap.gpu.fan}%` : "н/д"],
          ["VRAM", `${bytes(snap.gpu.memUsed)} / ${bytes(snap.gpu.memTotal)}`],
        ]
      : [["Состояние", "датчик недоступен"]];

    const diskFacts: Array<[string, string]> = snap.disks.slice(0, 2).map((d) => [
      `${d.letter} свободно`,
      `${bytes(d.free)} из ${bytes(d.total)}`,
    ]);
    const mainDisk = snap.disks[0];
    if (mainDisk) {
      // Активность и обмен — те же счётчики, что на вкладке «Диски» диспетчера задач.
      diskFacts.push(["Активность", `${mainDisk.active.toFixed(0)}%`]);
      diskFacts.push(["Обмен", `${rate(mainDisk.readBps)} / ${rate(mainDisk.writeBps)}`]);
    }

    cpuTile.update({
      value: snap.cpu.usage,
      tone: loadTone(snap.cpu.usage),
      caption: "Загрузка",
      unit: "%",
      facts: cpuFacts,
      spark: cpuSpark,
      badge: {
        text: snap.cpu.usage < 60 ? "в норме" : snap.cpu.usage < 85 ? "нагрузка" : "перегрузка",
        tone: loadTone(snap.cpu.usage),
      },
    });
    gpuTile.update({
      value: snap.gpu.available ? snap.gpu.usage : 0,
      tone: loadTone(snap.gpu.usage),
      caption: snap.gpu.available ? "Загрузка" : "нет данных",
      unit: snap.gpu.available ? "%" : "",
      facts: gpuFacts,
      spark: gpuSpark,
      badge: snap.gpu.available
        ? { text: `${snap.gpu.temp.toFixed(1)} °C`, tone: snap.gpu.temp > 80 ? "bad" : snap.gpu.temp > 70 ? "warn" : "ok" }
        : undefined,
    });
    memTile.update({
      value: snap.mem.percent,
      tone: loadTone(snap.mem.percent),
      caption: "Занято",
      unit: "%",
      facts: [
        ["Всего", bytes(snap.mem.total)],
        ["Доступно", bytes(snap.mem.available)],
        ["Выделено", bytes(snap.mem.committed)],
        ["Кэш", bytes(snap.mem.cached)],
        ["Процессов", num(snap.cpu.processes)],
        ["Сеть", rate(snap.net.down)],
      ],
      spark: memSpark,
      badge: {
        text: snap.mem.percent < 78 ? "в норме" : snap.mem.percent < 90 ? "мало памяти" : "критично",
        tone: loadTone(snap.mem.percent),
      },
    });
    const diskPercent = snap.disks[0]?.percent ?? 0;
    diskTile.update({
      value: diskPercent,
      tone: loadTone(diskPercent),
      caption: snap.disks[0] ? `${snap.disks[0].letter} занято` : "Диски",
      unit: "%",
      facts: diskFacts,
      spark: diskSpark,
      badge: {
        text: diskPercent < 85 ? "место есть" : "мало места",
        tone: diskPercent < 85 ? "ok" : diskPercent < 93 ? "warn" : "bad",
      },
    });

    const report = state.health;
    const score = snap.health.score ?? report?.score ?? 0;
    const grade = snap.health.grade ?? report?.grade ?? "—";
    healthSub.textContent = `${snap.host} · ${uptime(snap.uptime)}`;
    healthRing.set(score, { caption: grade, tone: scoreTone(score) });
    healthComponents.innerHTML = healthComponentsHtml(report);

    findings.innerHTML = findingsCard(state);

    legend.innerHTML = `
      <span class="legend__item"><i style="background:#4d9bff"></i>CPU ${pct(snap.cpu.usage)}</span>
      <span class="legend__item"><i style="background:#22d3ee"></i>RAM ${pct(snap.mem.percent)}</span>
      <span class="legend__item"><i style="background:#2ee6a8"></i>GPU ${pct(snap.gpu.usage)}</span>`;
    liveChart.set([
      { name: "cpu", color: "#4d9bff", values: series.map((s) => s.cpu) },
      { name: "ram", color: "#22d3ee", values: series.map((s) => s.mem) },
      { name: "gpu", color: "#2ee6a8", values: series.map((s) => s.gpu) },
    ]);
  };

  const unsubscribe = ctx.store.subscribe(render);
  return {
    el,
    destroy: unsubscribe,
    refresh: () => void ctx.store.loadHealth(),
    update: () => undefined,
  };
}

export type { Snapshot };
