/** Экран «История и здоровье»: динамика оценки, проблемы, сравнение. */

import { lineChartHtml } from "../core/charts";
import { esc, icon } from "../core/dom";
import { num, pct, plural, scoreTone, tsDateTime, tsTime } from "../core/format";
import { badge, emptyState } from "../core/ui";
import type { AppState } from "../core/store";
import type { View, ViewContext } from "./types";

export function createHistory(ctx: ViewContext): View {
  const el = document.createElement("section");
  el.className = "view-grid";

  el.innerHTML = `
    <div class="grid grid--sidebar">
      <div class="stack">
        <div class="card" data-score></div>
        <div class="card" data-load></div>
        <div class="card" data-issues></div>
      </div>
      <div class="stack">
        <div class="card" data-summary></div>
        <div class="card" data-compare></div>
      </div>
    </div>`;

  const score = el.querySelector<HTMLElement>("[data-score]")!;
  const load = el.querySelector<HTMLElement>("[data-load]")!;
  const issues = el.querySelector<HTMLElement>("[data-issues]")!;
  const summary = el.querySelector<HTMLElement>("[data-summary]")!;
  const compare = el.querySelector<HTMLElement>("[data-compare]")!;

  const render = (state: AppState): void => {
    const points = state.history;
    const current = state.snapshot?.health.score ?? state.health?.score ?? 0;
    const tone = scoreTone(current);

    // Без связи «история только начинается» вводила бы в заблуждение.
    if (!state.online && points.length === 0) {
      const offline = emptyState(
        "Агент PC Sentinel не отвечает",
        "История и оценка состояния недоступны без связи с агентом",
        "alert",
      );
      score.innerHTML = `<div class="card__head"><div class="card__title">${icon("clock", 16)}История оценки</div></div>${offline}`;
      // Пустые карточки не должны оставаться рамками под сообщением.
      load.innerHTML = "";
      issues.innerHTML = "";
      summary.innerHTML = "";
      compare.innerHTML = "";
      for (const node of [load, issues, summary, compare]) node.hidden = true;
      return;
    }
    for (const node of [load, issues, summary, compare]) node.hidden = false;

    if (points.length < 2) {
      score.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("clock", 16)}История оценки</div>
        </div>
        ${emptyState("История только начинается", "Точки добавляются раз в минуту — график появится после нескольких замеров", "clock")}`;
    } else {
      score.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("clock", 16)}История оценки</div>
          <span class="card__sub">${plural(points.length, "точка", "точки", "точек")} · ${tsDateTime(points[0].ts)} — ${tsDateTime(points[points.length - 1].ts)}</span>
        </div>
        <div class="card__body">
          ${lineChartHtml([{ name: "score", color: "#4d9bff", values: points.map((p) => p.score) }], {
            height: 180,
            max: 100,
            area: false,
            dots: true,
          })}
          <div class="axis-note">
            <span>${tsTime(points[0].ts)}</span>
            <span>${tsTime(points[Math.floor(points.length / 2)].ts)}</span>
            <span>${tsTime(points[points.length - 1].ts)}</span>
          </div>
        </div>`;
    }

    if (points.length < 2) {
      load.innerHTML = `
        <div class="card__head"><div class="card__title">${icon("activity", 16)}Нагрузка</div></div>
        ${emptyState("Недостаточно данных", "Продолжайте работу — график заполнится автоматически", "activity")}`;
    } else {
      load.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("activity", 16)}Нагрузка за сессию</div>
          <div class="legend">
            <span class="legend__item"><i style="background:#4d9bff"></i>CPU</span>
            <span class="legend__item"><i style="background:#22d3ee"></i>RAM</span>
            <span class="legend__item"><i style="background:#f5b544"></i>Диск</span>
          </div>
        </div>
        <div class="card__body">
          ${lineChartHtml(
            [
              { name: "cpu", color: "#4d9bff", values: points.map((p) => p.cpu) },
              { name: "ram", color: "#22d3ee", values: points.map((p) => p.mem) },
              { name: "disk", color: "#f5b544", values: points.map((p) => p.disk) },
            ],
            { height: 168, max: 100 },
          )}
        </div>`;
    }

    const report = state.health;
    const issuesList = report?.issues ?? [];
    issues.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("alert", 16)}История проблем</div>
        <span class="card__sub">${issuesList.length} активных</span>
      </div>
      <div class="card__body card__body--flush">
        ${
          issuesList.length === 0
            ? emptyState("Активных проблем нет", "Система работает в штатном режиме", "check")
            : issuesList
                .map(
                  (issue) => `
            <div class="row">
              <span class="dot dot--${issue.severity === "critical" ? "bad" : "warn"}"></span>
              <div class="row__main">
                <div class="row__title">${esc(issue.title)}</div>
                <div class="row__desc">${esc(issue.detail)}</div>
              </div>
              ${badge(issue.severity === "critical" ? "критично" : "внимание", issue.severity === "critical" ? "bad" : "warn")}
            </div>`,
                )
                .join("")
        }
      </div>`;

    summary.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("shieldCheck", 16)}Текущее состояние</div>
        <span class="badge badge--${tone}">${esc(report?.grade ?? state.snapshot?.health.grade ?? "—")}</span>
      </div>
      <div class="card__body stack--sm">
        <div class="score-big">
          <span class="score-big__value score-big__value--${tone}">${Math.round(current)}</span>
          <span class="score-big__unit">/ 100</span>
        </div>
        <div class="score-big__headline">${esc(report?.headline ?? "—")}</div>
        <p class="muted score-big__summary">${esc(report?.summary ?? "—")}</p>
        <div class="stack--sm">
          ${(report?.components ?? [])
            .map((c) =>
              c.score === null
                ? `
            <div class="comp comp--empty">
              <div class="comp__head"><span>${esc(c.name)}</span><b>—</b></div>
              <div class="bar bar--empty"></div>
            </div>`
                : `
            <div class="comp">
              <div class="comp__head"><span>${esc(c.name)}</span><b>${esc(c.value ?? String(Math.round(c.score)))}</b></div>
              <div class="bar"><span class="bar__fill bar__fill--${scoreTone(c.score)}" style="width:${Math.max(2, c.ratio ?? c.score).toFixed(1)}%"></span></div>
            </div>`,
            )
            .join("")}
        </div>
      </div>`;

    const first = points[0];
    const last = points[points.length - 1];
    const snap = state.snapshot;
    const worstDisk = snap?.disks.length ? Math.max(...snap.disks.map((d) => d.percent)) : undefined;
    compare.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("gauge", 16)}Сравнение</div>
        <span class="card__sub">${first && last ? `${tsTime(first.ts)} → сейчас` : "—"}</span>
      </div>
      <div class="card__body stack--sm">
        ${deltaRow("Оценка здоровья", first?.score, current, 0)}
        ${deltaRow("Загрузка CPU", first?.cpu, snap?.cpu.usage, 1, true)}
        ${deltaRow("Занято RAM", first?.mem, snap?.mem.percent, 1, true)}
        ${deltaRow("Занято диска", first?.disk, worstDisk, 1, true)}
        <div class="stat stat--wide"><span>Процессов сейчас</span><b>${num(snap?.procs.length ?? 0)}</b></div>
      </div>`;
  };

  function deltaRow(
    label: string,
    from: number | undefined,
    to: number | undefined,
    digits: number,
    inverse = false,
  ): string {
    if (from === undefined || to === undefined) {
      return `<div class="stat stat--wide"><span>${esc(label)}</span><b>—</b></div>`;
    }
    const diff = to - from;
    const good = inverse ? diff <= 0 : diff >= 0;
    const arrow = Math.abs(diff) < 0.05 ? "" : diff > 0 ? "▲" : "▼";
    return `
      <div class="stat stat--wide">
        <span>${esc(label)}</span>
        <b>${from.toFixed(digits)} → ${to.toFixed(digits)}
          <em class="${good ? "delta--ok" : "delta--bad"}">${arrow} ${pct(Math.abs(diff), digits)}</em>
        </b>
      </div>`;
  }

  const unsubscribe = ctx.store.subscribe(render);
  return {
    el,
    destroy: unsubscribe,
    refresh: () => {
      void ctx.store.loadHistory();
      void ctx.store.loadHealth();
    },
  };
}
