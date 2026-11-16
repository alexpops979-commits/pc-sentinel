/** Экран «Оптимизация»: безопасные действия с объяснением эффекта. */

import { api, AgentOfflineError } from "../core/api";
import type { ActionItem } from "../core/api";
import { esc, icon } from "../core/dom";
import { badge, emptyState, modal, toast } from "../core/ui";
import type { View, ViewContext } from "./types";

export function createOptimize(ctx: ViewContext): View {
  const el = document.createElement("section");
  el.className = "view-grid";
  let actions: ActionItem[] = [];
  let busy = false;
  /** Причина, по которой список не получен: связь или ошибка агента. */
  let loadError: { offline: boolean; message: string } | null = null;

  el.innerHTML = `
    <div class="toolbar">
      <div class="tabs">
        <button class="tab is-active">Рекомендации</button>
      </div>
      <span class="spacer"></span>
      <span class="chip" data-count></span>
      <button class="btn btn--ghost btn--sm" data-reload>${icon("refresh", 15)}Пересчитать</button>
    </div>
    <div class="grid grid--2" data-list></div>
    <div class="card" data-note></div>`;

  const list = el.querySelector<HTMLElement>("[data-list]")!;
  const count = el.querySelector<HTMLElement>("[data-count]")!;
  const note = el.querySelector<HTMLElement>("[data-note]")!;

  const reload = async (): Promise<void> => {
    try {
      actions = (await api.optimize()).actions;
      loadError = null;
    } catch (err) {
      actions = [];
      loadError = {
        offline: err instanceof AgentOfflineError,
        message: err instanceof Error ? err.message : "Не удалось получить рекомендации",
      };
    }
    render();
  };

  const actionCard = (action: ActionItem): string => {
    const riskTone = action.risk === "medium" ? "warn" : "ok";
    return `
      <article class="action-card">
        <div class="action-card__top">
          <span class="action-card__icon">${icon(action.kind === "disable-startup" ? "shield" : action.kind === "cleanup" ? "trash" : action.kind === "power" ? "zap" : action.kind === "network" ? "wifi" : "wrench", 16)}</span>
          <div class="action-card__head">
            <div class="action-card__title">${esc(action.title)}</div>
            <div class="action-card__cat">${esc(action.category)}</div>
          </div>
        </div>
        <p class="action-card__text">${esc(action.detail)}</p>
        <div class="action-card__foot">
          ${badge(action.risk === "medium" ? "требует подтверждения" : "безопасно", riskTone)}
          ${action.reversible ? badge("обратимо", "muted") : ""}
          <span class="spacer"></span>
          <button class="btn btn--primary btn--sm" data-action="${esc(action.id)}">Выполнить</button>
        </div>
      </article>`;
  };

  const render = (): void => {
    if (loadError) {
      count.textContent = loadError.offline ? "нет связи" : "ошибка";
      list.innerHTML = `<div class="card">${emptyState(
        loadError.offline ? "Агент PC Sentinel не отвечает" : "Не удалось получить рекомендации",
        loadError.offline
          ? "Рекомендации строятся по живым показателям. Закройте окно и запустите приложение снова."
          : loadError.message,
        "alert",
      )}</div>`;
      note.innerHTML = "";
      return;
    }
    count.textContent = `Рекомендаций: ${actions.length}`;
    if (actions.length === 0) {
      list.innerHTML = `<div class="card">${emptyState(
        "Рекомендаций нет",
        "По текущим показателям действий не требуется",
        "check",
      )}</div>`;
    } else {
      list.innerHTML = actions.map(actionCard).join("");
    }
    note.innerHTML = `
      <div class="card__body note">
        <span class="note__icon">${icon("shield", 18)}</span>
        <div>
          <div class="note__title">Как это работает</div>
          <p class="muted">PC Sentinel не удаляет файлы без подтверждения и не меняет системные настройки скрытно.
          Перед отключением автозапуска команда сохраняется в резервную копию в папке данных приложения.
          Действия с диском затрагивают только временные файлы старше 7 дней.</p>
        </div>
      </div>`;
  };

  const run = async (action: ActionItem): Promise<void> => {
    if (busy) return;
    if (action.risk === "medium") {
      const answer = await modal({
        title: action.title,
        body: `<p>${esc(action.detail)}</p><p class="dim">Продолжить?</p>`,
        confirmText: "Выполнить",
        tone: "danger",
      });
      if (!answer.ok) return;
    }
    busy = true;
    try {
      const res = await api.action(action.id);
      toast(res.ok ? "Готово" : "Не выполнено", res.message, res.ok ? "ok" : "warn");
      await reload();
      await ctx.store.poll();
    } catch (err) {
      if (err instanceof AgentOfflineError) {
        // Связь пропала во время действия — показываем это, а не «ошибку действия».
        loadError = { offline: true, message: err.message };
        render();
        toast("Агент PC Sentinel не отвечает", "Действие не выполнено", "bad");
      } else {
        toast("Ошибка", err instanceof Error ? err.message : "Действие не выполнено", "bad");
      }
    } finally {
      busy = false;
    }
  };

  el.addEventListener("click", (event) => {
    const target = event.target as HTMLElement;
    if (target.closest("[data-reload]")) {
      void reload();
      return;
    }
    const btn = target.closest<HTMLElement>("[data-action]");
    if (btn?.dataset.action) {
      const action = actions.find((a) => a.id === btn.dataset.action);
      if (action) void run(action);
    }
  });

  void reload();
  // Когда связь с агентом возвращается, список пересчитывается сам.
  let wasOnline = ctx.store.state.online;
  const unsubscribe = ctx.store.subscribe((state) => {
    if (state.online && !wasOnline) void reload();
    wasOnline = state.online;
  });
  return {
    el,
    destroy: unsubscribe,
    refresh: () => void reload(),
  };
}
