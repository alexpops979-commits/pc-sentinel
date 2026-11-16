/** Экран «Настройки». */

import { api } from "../core/api";
import { esc, icon } from "../core/dom";
import { bytes, num, tsDateTime } from "../core/format";
import { badge, modal, toast } from "../core/ui";
import type { AppState } from "../core/store";
import type { View, ViewContext } from "./types";

export function createSettings(ctx: ViewContext): View {
  const el = document.createElement("section");
  el.className = "view-grid";
  let settings: Record<string, string> = {};
  /** Файл настроек прочитан — значения переключателей известны. */
  let loaded = false;

  el.innerHTML = `
    <div class="grid grid--2">
      <div class="card" data-general></div>
      <div class="card" data-system></div>
    </div>
    <div class="card" data-about></div>`;

  const general = el.querySelector<HTMLElement>("[data-general]")!;
  const systemCard = el.querySelector<HTMLElement>("[data-system]")!;
  const about = el.querySelector<HTMLElement>("[data-about]")!;

  const render = (state: AppState): void => {
    const refresh = Number(settings.refresh_ms ?? state.refreshMs);
    // Настройки хранит агент: без связи их нельзя ни прочитать, ни сохранить.
    const offline = !state.online;
    // Пока файл настроек не прочитан, положение переключателей неизвестно —
    // показывать их включёнными значило бы выдумывать состояние.
    const known = !offline || loaded;
    general.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("settings", 16)}Общие</div>
        <span class="card__sub">${offline ? "нет связи" : ""}</span>
      </div>
      <div class="card__body stack--sm">
        <label class="field">
          <span class="field__label">Частота обновления телеметрии</span>
          <select class="input" data-refresh ${offline ? "disabled" : ""}>
            ${[1000, 1500, 2000, 3000, 5000]
              .map((ms) => `<option value="${ms}" ${refresh === ms ? "selected" : ""}>${(ms / 1000).toFixed(1)} с</option>`)
              .join("")}
          </select>
          <span class="field__hint">${
            offline
              ? "Агент PC Sentinel не отвечает — настройку изменить нельзя."
              : "Чаще — плавнее графики, но выше нагрузка на CPU агента."
          }</span>
        </label>
        <div class="setting-row">
          <div>
            <div class="setting-row__title">Резервная копия автозагрузки</div>
            <div class="setting-row__desc">Сохранять команды перед отключением</div>
          </div>
          <button class="toggle ${known && settings.autorun_backup !== "0" ? "is-on" : ""}" data-toggle="autorun_backup" aria-label="Переключить" ${offline ? "disabled" : ""}></button>
        </div>
        <div class="setting-row">
          <div>
            <div class="setting-row__title">Проверка при запуске</div>
            <div class="setting-row__desc">Запускать сканирование сразу после старта агента</div>
          </div>
          <button class="toggle ${known && settings.scan_on_start === "1" ? "is-on" : ""}" data-toggle="scan_on_start" aria-label="Переключить" ${offline ? "disabled" : ""}></button>
        </div>
      </div>`;

    const snap = state.snapshot;
    systemCard.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("server", 16)}Система</div>
        <span class="card__sub">${esc(state.meta?.host ?? (offline ? "нет связи" : "—"))}</span>
      </div>
      <div class="card__body">
        <dl class="kv">
          <dt>Устройство</dt><dd>${esc(state.meta?.host ?? "—")}</dd>
          <dt>Операционная система</dt><dd>${esc(snap?.os ?? "—")}</dd>
          <dt>Процессор</dt><dd>${esc(snap?.cpu.name ?? state.meta?.cpu ?? "—")}</dd>
          <dt>Потоки</dt><dd>${snap || state.meta ? num(snap?.cpu.cores ?? state.meta?.cores ?? 0) : "—"}</dd>
          <dt>Память</dt><dd>${snap ? bytes(snap.mem.total) : "—"}</dd>
          <dt>Видеокарта</dt><dd>${esc(snap ? (snap.gpu.available ? snap.gpu.name : "датчик NVML недоступен") : "—")}</dd>
          <dt>Аптайм</dt><dd>${snap ? `${Math.floor(snap.uptime / 3600)} ч ${Math.floor((snap.uptime % 3600) / 60)} мин` : "—"}</dd>
          <dt>Агент запущен</dt><dd>${state.meta ? tsDateTime(state.meta.startedAt) : "—"}</dd>
        </dl>
        ${offline ? `<p class="hint">Агент PC Sentinel не отвечает — сведения о системе недоступны.</p>` : ""}
      </div>`;

    about.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("shieldCheck", 16)}О приложении</div>
        ${badge(`v${state.meta?.version ?? "1.0.0"}`, "accent")}
      </div>
      <div class="card__body about">
        <div class="about__text">
          <p><b>PC Sentinel</b> — локальная система диагностики: собирает телеметрию напрямую из Windows
          (CPU, GPU через NVML, память, диски, сеть, процессы), проверяет цифровые подписи файлов,
          анализирует автозапуск и ищет признаки скрытого майнинга.</p>
          <p class="dim">Все данные остаются на этом компьютере. Агент слушает только localhost и не отправляет
          телеметрию в сеть. Интерфейс открывается в отдельном окне WebView2.</p>
        </div>
        <div class="about__actions">
          <button class="btn btn--ghost" data-restart-scan ${offline ? "disabled" : ""}>${icon("shield", 15)}Запустить проверку</button>
          <button class="btn btn--danger" data-quit>${icon("power", 15)}Закрыть приложение</button>
        </div>
      </div>`;
  };

  const save = async (patch: Record<string, string>): Promise<void> => {
    settings = { ...settings, ...patch };
    try {
      await api.saveSettings(patch);
      render(ctx.store.state);
    } catch {
      toast("Не удалось сохранить настройки", "", "bad");
    }
  };

  el.addEventListener("change", (event) => {
    const select = event.target as HTMLSelectElement;
    if (select.matches("[data-refresh]")) {
      const ms = Number(select.value);
      ctx.store.setRefresh(ms);
      void save({ refresh_ms: String(ms) });
      toast("Частота обновления изменена", `${(ms / 1000).toFixed(1)} с`, "ok");
    }
  });

  el.addEventListener("click", (event) => {
    const target = event.target as HTMLElement;
    const toggle = target.closest<HTMLElement>("[data-toggle]");
    if (toggle?.dataset.toggle) {
      const key = toggle.dataset.toggle;
      const current = key === "autorun_backup" ? settings.autorun_backup !== "0" : settings.scan_on_start === "1";
      const next = current ? "0" : "1";
      toggle.classList.toggle("is-on", !current);
      void save({ [key]: next });
      return;
    }
    if (target.closest("[data-restart-scan]")) {
      void ctx.runScan();
      return;
    }
    if (target.closest("[data-quit]")) {
      void modal({
        title: "Закрыть PC Sentinel",
        body: "<p>Агент сбора телеметрии и окно приложения будут закрыты. История и настройки сохранятся.</p>",
        confirmText: "Закрыть",
        tone: "danger",
      }).then(async (answer) => {
        if (!answer.ok) return;
        try {
          await api.quit();
          window.close();
        } catch {
          toast("Агент не отвечает", "Закройте окно вручную", "warn");
        }
      });
    }
  });

  api
    .settings()
    .then((data) => {
      settings = data;
      loaded = true;
      render(ctx.store.state);
    })
    .catch(() => undefined);

  const unsubscribe = ctx.store.subscribe(render);
  return { el, destroy: unsubscribe };
}
