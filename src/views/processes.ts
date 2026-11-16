/** Экран «Процессы»: живые процессы, автозагрузка, сетевые соединения. */

import { api } from "../core/api";
import type { Autorun, Conn } from "../core/api";
import { esc, icon } from "../core/dom";
import { bytes, num, procInitials, shortPath } from "../core/format";
import { badge, emptyState, modal, toast } from "../core/ui";
import type { AppState } from "../core/store";
import type { View, ViewContext } from "./types";

type Tab = "procs" | "startup" | "net";
type SortKey = "cpu" | "mem" | "name" | "pid";

export function createProcesses(ctx: ViewContext): View {
  const el = document.createElement("section");
  el.className = "view-grid";
  let tab: Tab = "procs";
  let sortKey: SortKey = "cpu";
  let sortDir: 1 | -1 = -1;
  let autoruns: Autorun[] | null = null;
  let conns: { items: Conn[]; established: number; listening: number } | null = null;

  el.innerHTML = `
    <div class="toolbar">
      <div class="tabs" data-tabs>
        <button class="tab is-active" data-tab="procs">Процессы</button>
        <button class="tab" data-tab="startup">Автозагрузка</button>
        <button class="tab" data-tab="net">Соединения</button>
      </div>
      <span class="spacer"></span>
      <span class="chip" data-chip-total></span>
      <span class="chip chip--warn" data-chip-anom></span>
      <button class="btn btn--ghost btn--sm" data-reload>${icon("refresh", 15)}Обновить</button>
    </div>
    <div class="card" data-body></div>`;

  const body = el.querySelector<HTMLElement>("[data-body]")!;
  const chipTotal = el.querySelector<HTMLElement>("[data-chip-total]")!;
  const chipAnom = el.querySelector<HTMLElement>("[data-chip-anom]")!;

  const loadTab = async (): Promise<void> => {
    if (tab === "startup" && !autoruns) {
      try {
        autoruns = (await api.autoruns()).items;
      } catch {
        autoruns = [];
      }
    }
    if (tab === "net" && !conns) {
      try {
        conns = await api.connections();
      } catch {
        conns = { items: [], established: 0, listening: 0 };
      }
    }
    render(ctx.store.state);
  };

  const killProcess = async (pid: number, name: string): Promise<void> => {
    const answer = await modal({
      title: "Завершить процесс",
      body: `<p>Процесс <b>${esc(name)}</b> (PID ${pid}) будет завершён. Несохранённые данные в нём будут потеряны.</p>
             <p class="dim">Системные процессы защищены и не могут быть завершены из приложения.</p>`,
      confirmText: "Завершить",
      tone: "danger",
    });
    if (!answer.ok) return;
    try {
      const res = await api.kill(pid);
      toast(res.ok ? "Процесс завершён" : "Не удалось завершить", res.message, res.ok ? "ok" : "bad");
      await ctx.store.poll();
      render(ctx.store.state);
    } catch (err) {
      toast("Ошибка", err instanceof Error ? err.message : "Не удалось завершить процесс", "bad");
    }
  };

  const disableAutorun = async (entry: Autorun): Promise<void> => {
    const answer = await modal({
      title: "Отключить автозапуск",
      body: `<p>Запись <b>${esc(entry.name)}</b> будет удалена из <span class="mono">${esc(entry.location)}</span>.</p>
             <p class="dim">Команда сохранится в резервной копии, её можно вернуть вручную.</p>`,
      confirmText: "Отключить",
      tone: "danger",
    });
    if (!answer.ok) return;
    try {
      const res = await api.action(`disable:${entry.location}|${entry.key}|${entry.name}`);
      toast(res.ok ? "Автозапуск отключён" : "Не удалось отключить", res.message, res.ok ? "ok" : "warn");
      autoruns = (await api.autoruns()).items;
      render(ctx.store.state);
    } catch (err) {
      toast("Ошибка", err instanceof Error ? err.message : "Действие не выполнено", "bad");
    }
  };

  const procsTable = (state: AppState): string => {
    const query = ctx.search().trim().toLowerCase();
    const all = state.snapshot?.procs ?? [];
    const filtered = query
      ? all.filter((p) => p.name.toLowerCase().includes(query) || p.path.toLowerCase().includes(query))
      : all;
    const sorted = [...filtered].sort((a, b) => {
      if (sortKey === "name") return a.name.localeCompare(b.name) * sortDir;
      if (sortKey === "pid") return (a.pid - b.pid) * sortDir;
      if (sortKey === "mem") return (a.mem - b.mem) * sortDir;
      return (a.cpu - b.cpu) * sortDir;
    });
    const maxCpu = Math.max(...sorted.map((p) => p.cpu), 1);

    const head = (key: SortKey, label: string, numeric = false): string => {
      const active = sortKey === key;
      return `<th class="is-sortable ${numeric ? "is-num" : ""} ${active ? "is-sorted" : ""}" data-sort="${key}">${esc(label)}${
        active ? (sortDir === 1 ? " ↑" : " ↓") : ""
      }</th>`;
    };

    return `
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            ${head("name", "Процесс")}
            ${head("pid", "PID", true)}
            ${head("cpu", "CPU", true)}
            ${head("mem", "Память", true)}
            <th class="is-num">Потоки</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${sorted
            .map((p) => {
              const heavy = p.cpu > 25 && !p.path.toLowerCase().includes("\\windows\\");
              return `
            <tr>
              <td>
                <div class="cell-name">
                  <span class="proc-icon ${heavy ? "proc-icon--warn" : ""}">${esc(procInitials(p.name))}</span>
                  <span>
                    <span>${esc(p.name)}</span>
                    <span class="cell-sub">${esc(shortPath(p.path))}</span>
                  </span>
                </div>
              </td>
              <td class="is-num mono">${p.pid}</td>
              <td class="is-num">
                <div class="cell-load">
                  <span class="mono">${p.cpu.toFixed(1)}%</span>
                  <span class="cell-load__bar"><i style="width:${Math.min(100, (p.cpu / maxCpu) * 100).toFixed(0)}%"></i></span>
                </div>
              </td>
              <td class="is-num">${bytes(p.mem)}</td>
              <td class="is-num">${p.threads}</td>
              <td class="is-num">
                <button class="icon-btn" data-kill="${p.pid}" data-name="${esc(p.name)}" title="Завершить процесс">${icon("power", 15)}</button>
              </td>
            </tr>`;
            })
            .join("")}
        </tbody>
      </table>
    </div>
    ${sorted.length === 0 ? emptyState("Ничего не найдено", "Измените поисковый запрос", "search") : ""}`;
  };

  const startupTable = (): string => {
    const items = autoruns ?? [];
    const query = ctx.search().trim().toLowerCase();
    const filtered = query
      ? items.filter((a) => a.name.toLowerCase().includes(query) || a.command.toLowerCase().includes(query))
      : items;
    if (items.length === 0) {
      return emptyState("Записей автозагрузки не найдено", "Возможно, требуется запуск от администратора", "layers");
    }
    return `
      <div class="card__body card__body--flush">
        ${filtered
          .map(
            (a) => `
          <div class="row">
            <span class="proc-icon ${a.suspicious ? "proc-icon--bad" : ""}">${esc(procInitials(a.name))}</span>
            <div class="row__main">
              <div class="row__title">${esc(a.name)} ${a.suspicious ? badge("проверить", "bad") : badge("подписано", "ok")}</div>
              <div class="row__desc mono">${esc(shortPath(a.command, 78))}</div>
            </div>
            <div class="row__meta">
              <span class="chip">${esc(a.location)}</span>
              <button class="btn btn--ghost btn--sm" data-disable="${esc(a.name)}">Отключить</button>
            </div>
          </div>`,
          )
          .join("")}
      </div>`;
  };

  const netTable = (): string => {
    const data = conns;
    if (!data) return emptyState("Загружаем соединения…", "", "wifi");
    const query = ctx.search().trim().toLowerCase();
    const filtered = query
      ? data.items.filter(
          (c) => c.proc.toLowerCase().includes(query) || c.remote.includes(query) || c.local.includes(query),
        )
      : data.items;
    const top = filtered.slice(0, 220);
    return `
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr><th>Процесс</th><th>Локальный адрес</th><th>Удалённый адрес</th><th>Состояние</th></tr>
          </thead>
          <tbody>
            ${top
              .map(
                (c) => `
              <tr>
                <td><div class="cell-name"><span class="proc-icon">${esc(procInitials(c.proc || "?"))}</span><span>${esc(c.proc || "—")}<span class="cell-sub">PID ${c.pid}</span></span></div></td>
                <td class="mono">${esc(c.local)}</td>
                <td class="mono">${esc(c.remote)}</td>
                <td>${badge(c.state, c.state === "ESTABLISHED" ? "ok" : c.state === "LISTEN" ? "accent" : "muted")}</td>
              </tr>`,
              )
              .join("")}
          </tbody>
        </table>
      </div>
      ${top.length === 0 ? emptyState("Соединений не найдено", "", "wifi") : ""}`;
  };

  const render = (state: AppState): void => {
    const procs = state.snapshot?.procs ?? [];
    const anomalies = procs.filter((p) => p.cpu > 20 && !p.path.toLowerCase().includes("\\windows\\")).length;
    const noData = !state.online && !state.snapshot;
    chipTotal.textContent = noData ? "нет связи" : `Процессов: ${procs.length}`;
    chipAnom.textContent = noData ? "Аномалии: —" : `Аномалии: ${anomalies}`;

    // Без связи пустые таблицы выглядели бы как «ничего не найдено».
    if (noData) {
      body.innerHTML = emptyState(
        "Агент PC Sentinel не отвечает",
        "Список процессов, автозагрузка и соединения недоступны без связи с агентом",
        "alert",
      );
      return;
    }

    if (tab === "procs") {
      body.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("layers", 16)}Активные процессы</div>
          <span class="card__sub">обновляется каждые ${(state.refreshMs / 1000).toFixed(1)} с</span>
        </div>
        ${procsTable(state)}`;
    } else if (tab === "startup") {
      body.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("layers", 16)}Автозагрузка</div>
          <span class="card__sub">${autoruns?.length ?? 0} записей</span>
        </div>
        ${startupTable()}`;
    } else {
      body.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("wifi", 16)}Сетевые соединения</div>
          <span class="card__sub">активных: ${conns?.established ?? 0} · слушают: ${conns?.listening ?? 0}</span>
        </div>
        ${netTable()}`;
    }
  };

  el.addEventListener("click", (event) => {
    const target = event.target as HTMLElement;
    const tabBtn = target.closest<HTMLElement>("[data-tab]");
    if (tabBtn?.dataset.tab) {
      tab = tabBtn.dataset.tab as Tab;
      el.querySelectorAll("[data-tab]").forEach((b) => b.classList.toggle("is-active", b === tabBtn));
      const reload = async (): Promise<void> => {
        if (tab !== "procs") {
          autoruns = tab === "startup" ? null : autoruns;
          conns = tab === "net" ? null : conns;
        }
        await loadTab();
      };
      void reload();
      return;
    }
    const sortBtn = target.closest<HTMLElement>("[data-sort]");
    if (sortBtn?.dataset.sort) {
      const key = sortBtn.dataset.sort as SortKey;
      if (sortKey === key) sortDir = sortDir === 1 ? -1 : 1;
      else {
        sortKey = key;
        sortDir = key === "name" ? 1 : -1;
      }
      render(ctx.store.state);
      return;
    }
    const killBtn = target.closest<HTMLElement>("[data-kill]");
    if (killBtn) {
      void killProcess(Number(killBtn.dataset.kill), killBtn.dataset.name ?? "");
      return;
    }
    const disableBtn = target.closest<HTMLElement>("[data-disable]");
    if (disableBtn) {
      const entry = (autoruns ?? []).find((a) => a.name === disableBtn.dataset.disable);
      if (entry) void disableAutorun(entry);
      return;
    }
    if (target.closest("[data-reload]")) {
      autoruns = null;
      conns = null;
      void ctx.store.poll();
      void loadTab();
    }
  });

  const unsubscribe = ctx.store.subscribe((state) => render(state));
  void loadTab();
  return {
    el,
    destroy: unsubscribe,
    refresh: () => {
      autoruns = null;
      conns = null;
      void loadTab();
    },
  };
}

export { num };
