/** Экран «FPS и производительность»: frametime, процентили, микрофризы. */

import { frametimeChartHtml, hbarsHtml, vbarsHtml } from "../core/charts";
import { esc, icon } from "../core/dom";
import { fpsTone, num, plural, scoreTone } from "../core/format";
import { parseCaptureCsv } from "../core/fps";
import { badge, toast } from "../core/ui";
import { api, AgentOfflineError } from "../core/api";
import type { GameStatus } from "../core/api";
import type { AppState } from "../core/store";
import type { View, ViewContext } from "./types";

export function createFps(ctx: ViewContext): View {
  const el = document.createElement("section");
  el.className = "view-grid";

  el.innerHTML = `
    <div class="toolbar">
      <div class="tabs" data-sessions></div>
      <span class="spacer"></span>
      <span class="chip" data-source></span>
      <button class="btn btn--ghost btn--sm" data-import>${icon("upload", 15)}Импорт захвата</button>
    </div>
    <div class="card" data-game></div>
    <div class="card" data-chart></div>
    <div class="grid grid--2">
      <div class="card" data-stats></div>
      <div class="card" data-thresholds></div>
    </div>
    <div class="card" data-verdict></div>`;

  const sessionsBar = el.querySelector<HTMLElement>("[data-sessions]")!;
  const source = el.querySelector<HTMLElement>("[data-source]")!;
  const gameCard = el.querySelector<HTMLElement>("[data-game]")!;
  const chart = el.querySelector<HTMLElement>("[data-chart]")!;
  const stats = el.querySelector<HTMLElement>("[data-stats]")!;
  const thresholds = el.querySelector<HTMLElement>("[data-thresholds]")!;
  const verdict = el.querySelector<HTMLElement>("[data-verdict]")!;

  /* ---------- Игровой профиль ---------- */

  let game: GameStatus | null = null;
  let gameError: { offline: boolean; message: string } | null = null;
  let gameBusy = false;
  /** Черновик формы: не сбрасываем ввод при каждом опросе. */
  let draftPath = "";
  /** Ошибка сохранения профиля (например, в папке нет .exe). */
  let saveError = "";
  /** Подпись состояния: пока она не меняется, разметку не трогаем,
   *  иначе опрос раз в 2 с стирал бы введённый текст. */
  let gameSig = "";

  const gameStatusHtml = (status: GameStatus): string => {
    if (!status.profile) return "";
    if (status.active) {
      const since = status.since
        ? new Date(status.since * 1000).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" })
        : "";
      const items = [
        status.applied.power ? "схема высокой производительности" : "",
        status.applied.priority ? "повышенный приоритет игры" : "",
      ].filter(Boolean);
      return `
        <div class="game__state game__state--on">
          ${badge("оптимизация включена", "ok")}
          <span class="game__state-text">Игра запущена${since ? ` с ${esc(since)}` : ""}. Включено: ${esc(items.join(", ") || "—")}.</span>
        </div>
        ${status.error ? `<div class="game__warn">${esc(status.error)}</div>` : ""}`;
    }
    if (status.running) {
      return `
        <div class="game__state">
          ${badge("применяется", "warn")}
          <span class="game__state-text">Игра запущена, оптимизация включается.</span>
        </div>`;
    }
    return `
      <div class="game__state">
        ${badge("игра не запущена", "muted")}
        <span class="game__state-text">Оптимизация включится сама, как только запустится игра, и отключится после выхода.</span>
      </div>
      ${status.error ? `<div class="game__warn">${esc(status.error)}</div>` : ""}`;
  };

  const renderGame = (): void => {
    const sig = gameError
      ? `err:${gameError.offline}:${gameError.message}`
      : game
        ? `${game.profile?.name ?? ""}|${game.profile?.process ?? ""}|${game.profile?.path ?? ""}|${game.running}|${game.active}|${game.since}|${game.applied.power}|${game.applied.priority}|${game.error ?? ""}|${gameBusy}|${saveError}`
        : "loading";
    if (sig === gameSig) return;
    gameSig = sig;

    if (gameError) {
      gameCard.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("gauge", 16)}Игровой профиль</div>
        </div>
        <div class="card__body">
          <p class="muted">${
            gameError.offline
              ? "Агент PC Sentinel не отвечает — профиль хранится у него, поэтому изменить его сейчас нельзя."
              : esc(gameError.message)
          }</p>
        </div>`;
      return;
    }
    if (!game) {
      gameCard.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("gauge", 16)}Игровой профиль</div>
        </div>
        <div class="card__body"><p class="muted">Загрузка…</p></div>`;
      return;
    }

    if (game.profile) {
      gameCard.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("gauge", 16)}Игровой профиль</div>
          <span class="card__sub">${esc(game.profile.process)}</span>
        </div>
        <div class="card__body game">
          <div class="game__name">${esc(game.profile.name)}</div>
          ${game.profile.path ? `<div class="game__path mono dim">${esc(game.profile.path)}</div>` : ""}
          ${gameStatusHtml(game)}
          <div class="game__foot">
            <span class="dim">${
              game.active
                ? "После выхода из игры настройки вернутся автоматически."
                : "Пока игра не запущена, настройки системы не меняются."
            }</span>
            <span class="spacer"></span>
            <button class="btn btn--ghost btn--sm" data-game-clear ${gameBusy ? "disabled" : ""}>Убрать профиль</button>
          </div>
        </div>`;
      return;
    }

    gameCard.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("gauge", 16)}Игровой профиль</div>
        <span class="card__sub">оптимизация только во время игры</span>
      </div>
      <div class="card__body game">
        <p class="muted">Укажите папку с игрой — исполняемый файл агент найдёт сам. Пока игра запущена,
        PC Sentinel включает схему высокой производительности и поднимает приоритет её процесса.
        После выхода всё возвращается как было.</p>
        <div class="game__form">
          <label class="field">
            <span class="field__label">Папка с игрой</span>
            <input class="input" data-game-path placeholder="D:\\Games\\Cyberpunk 2077" value="${esc(draftPath)}" />
          </label>
          <button class="btn btn--ghost" data-game-pick ${gameBusy ? "disabled" : ""}>Выбрать папку</button>
          <button class="btn btn--primary" data-game-save ${gameBusy ? "disabled" : ""}>Включить профиль</button>
        </div>
        ${saveError ? `<div class="game__warn">${esc(saveError)}</div>` : ""}
        <p class="dim game__hint">Можно указать папку игры или диск целиком — агент просмотрит её
        и выберет главный исполняемый файл.</p>
      </div>`;
  };

  const loadGame = async (): Promise<void> => {
    try {
      game = await api.game();
      gameError = null;
    } catch (err) {
      game = null;
      gameError = {
        offline: err instanceof AgentOfflineError,
        message: err instanceof Error ? err.message : "Не удалось получить профиль",
      };
    }
    renderGame();
  };

  const saveGame = async (): Promise<void> => {
    if (gameBusy) return;
    const pathInput = gameCard.querySelector<HTMLInputElement>("[data-game-path]");
    const path = (pathInput?.value ?? draftPath).trim();
    if (!path) {
      toast("Укажите папку с игрой", "Например, D:\\Games\\Cyberpunk 2077", "warn");
      return;
    }
    gameBusy = true;
    saveError = "";
    try {
      game = await api.setGamePath(path);
      gameError = null;
      draftPath = "";
      toast(
        "Профиль сохранён",
        `Игра: ${game.profile?.name ?? path} · процесс ${game.profile?.process ?? "—"}`,
        "ok",
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : "Не удалось сохранить профиль";
      // Причина (папки нет, нет .exe) должна остаться на экране, а не только в тосте.
      saveError = message;
      toast(err instanceof AgentOfflineError ? "Агент PC Sentinel не отвечает" : "Не удалось сохранить профиль", message, "bad");
    } finally {
      gameBusy = false;
      renderGame();
    }
  };

  const pickFolder = async (): Promise<void> => {
    if (gameBusy) return;
    gameBusy = true;
    renderGame();
    try {
      const picked = await api.pickGameFolder();
      if (picked.path) {
        draftPath = picked.path;
        saveError = "";
        // Сразу применяем выбранную папку — лишний клик ни к чему.
        game = await api.setGamePath(picked.path);
        draftPath = "";
        toast(
          "Профиль сохранён",
          `Игра: ${game.profile?.name ?? picked.path} · процесс ${game.profile?.process ?? "—"}`,
          "ok",
        );
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Не удалось выбрать папку";
      saveError = message;
      toast("Не удалось выбрать папку", message, "bad");
    } finally {
      gameBusy = false;
      renderGame();
    }
  };

  const clearGame = async (): Promise<void> => {
    if (gameBusy) return;
    gameBusy = true;
    try {
      game = await api.setGamePath("");
      toast("Профиль убран", "Оптимизация отключена, настройки восстановлены", "ok");
    } catch (err) {
      toast("Не удалось убрать профиль", err instanceof Error ? err.message : "", "bad");
    } finally {
      gameBusy = false;
      renderGame();
    }
  };

  const render = (state: AppState): void => {
    const sessions = state.sessions;
    const active = state.activeSession ?? sessions[0] ?? null;

    sessionsBar.innerHTML = sessions
      .slice(0, 6)
      .map(
        (s) =>
          `<button class="tab ${active && s.session === active.session ? "is-active" : ""}" data-session="${esc(s.session)}">${esc(s.app)}</button>`,
      )
      .join("");
    // Пустая полоса вкладок висела бы рамкой без единой сессии.
    sessionsBar.hidden = sessions.length === 0;

    if (!active) {
      // Без агента «Захватов пока нет» звучало бы как «вы ничего не записывали»,
      // хотя список захватов просто не удалось получить. Импорт CSV работает локально.
      const offline = !state.online;
      chart.innerHTML = `
        <div class="card__body">
          <div class="empty empty--tall">
            ${icon(offline ? "alert" : "gauge", 30)}
            <div class="empty__title">${offline ? "Агент PC Sentinel не отвечает" : "Захватов пока нет"}</div>
            <div class="empty__text">${
              offline
                ? "Список захватов хранится у агента, поэтому без связи с ним он недоступен. Импорт CSV из PresentMon или CapFrameX работает и без агента — разбор выполняется здесь, файл никуда не отправляется."
                : "PC Sentinel показывает только ваши реальные замеры. Импортируйте CSV из PresentMon или CapFrameX — разбор выполняется локально, файл никуда не отправляется."
            }</div>
            <button class="btn btn--primary" data-import>${icon("upload", 15)}Импортировать захват</button>
          </div>
        </div>`;
      stats.innerHTML = "";
      thresholds.innerHTML = "";
      verdict.innerHTML = "";
      // Пустые карточки не должны висеть рамками под сообщением.
      for (const node of [stats, thresholds, verdict]) node.hidden = true;
      source.textContent = offline ? "нет связи" : "нет захватов";
      return;
    }

    for (const node of [stats, thresholds, verdict]) node.hidden = false;
    source.textContent = `${plural(active.frames, "кадр", "кадра", "кадров")} · ${active.duration.toFixed(0)} с`;

    chart.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("activity", 16)}${esc(active.app)}</div>
        <div class="legend">
          <span class="legend__item"><i style="background:#4d9bff"></i>Frametime, мс</span>
          <span class="legend__item"><i style="background:#22d3ee"></i>Скользящее среднее</span>
          <span class="legend__item"><i style="background:#ff5d6c"></i>Выбросы</span>
        </div>
      </div>
      <div class="card__body">
        ${frametimeChartHtml(active.series, active.moving, { height: 220, threshold: 33.3 })}
        <div class="axis-note">
          <span>0 с</span><span>${(active.duration / 2).toFixed(0)} с</span><span>${active.duration.toFixed(0)} с</span>
        </div>
      </div>`;

    stats.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("gauge", 16)}Статистика кадров</div>
        <span class="card__sub">${num(active.frames)} кадров · ${active.duration.toFixed(0)} с</span>
      </div>
      <div class="card__body">
        ${hbarsHtml(
          [
            { label: "Средний FPS", value: active.avgFps, tone: fpsTone(active.avgFps) },
            { label: "Максимум", value: active.maxFps, tone: "ok" },
            { label: "P95", value: p95(active.series), tone: "accent" },
            { label: "P5", value: active.p5Low, tone: fpsTone(active.p5Low) },
            { label: "1% low", value: active.p1Low, tone: fpsTone(active.p1Low) },
            { label: "0.1% low", value: active.p01Low, tone: fpsTone(active.p01Low) },
          ],
          Math.max(active.maxFps, 120),
        )}
      </div>`;

    thresholds.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("target", 16)}Пороговые значения</div>
        <span class="card__sub">доля времени выше FPS</span>
      </div>
      <div class="card__body">
        ${vbarsHtml(
          active.thresholds.map((t) => ({
            label: t.label,
            value: t.value,
            suffix: "%",
            tone: t.value > 90 ? "ok" : t.value > 40 ? "accent" : "warn",
          })),
          { height: 136 },
        )}
      </div>`;

    const stutterShare = active.stutterRatio;
    const smoothTone = scoreTone(active.score);
    verdict.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("shieldCheck", 16)}Вывод анализа</div>
        <div class="inline">
          <span class="badge badge--${smoothTone}">плавность ${Math.round(active.score)}/100</span>
          <span class="card__sub">${plural(active.stutters, "микрофриз", "микрофриза", "микрофризов")} · ${stutterShare.toFixed(2)}% кадров</span>
        </div>
      </div>
      <div class="card__body stack--sm">
        <p class="verdict">${esc(active.verdict)}</p>
        <div class="grid grid--4">
          <div class="stat"><span>Средний FPS</span><b>${active.avgFps.toFixed(1)}</b></div>
          <div class="stat"><span>1% low</span><b>${active.p1Low.toFixed(1)}</b></div>
          <div class="stat"><span>0.1% low</span><b>${active.p01Low.toFixed(1)}</b></div>
          <div class="stat"><span>Микрофризы</span><b>${active.stutters}</b></div>
        </div>
      </div>`;
  };

  function p95(series: number[]): number {
    if (series.length === 0) return 0;
    const sorted = [...series].sort((a, b) => a - b);
    const value = sorted[Math.floor(sorted.length * 0.05)] ?? sorted[0];
    return value > 0 ? 1000 / value : 0;
  }

  const openImport = (): void => {
    const overlay = document.createElement("div");
    overlay.className = "dropzone-overlay";
    overlay.innerHTML = `
      <div class="dropzone">
        <span class="dropzone__icon">${icon("upload", 26)}</span>
        <div class="dropzone__title">Перетащите CSV-захват сюда</div>
        <div class="dropzone__hint">Подходят экспорты PresentMon и CapFrameX (колонка msBetweenPresents / Frametime)</div>
        <label class="btn btn--primary">
          Выбрать файл
          <input type="file" accept=".csv,.txt,.log" hidden />
        </label>
        <button class="btn btn--ghost" data-cancel>Отмена</button>
      </div>`;
    document.body.append(overlay);
    const input = overlay.querySelector<HTMLInputElement>("input[type=file]")!;

    const close = (): void => overlay.remove();
    const handleFile = async (file: File | null | undefined): Promise<void> => {
      if (!file) return;
      try {
        const text = await file.text();
        const report = parseCaptureCsv(file.name.replace(/\.[^.]+$/, ""), text);
        ctx.store.addSession(report);
        toast("Захват проанализирован", `${report.frames} кадров · средний FPS ${report.avgFps.toFixed(1)}`, "ok");
        close();
      } catch (err) {
        toast("Не удалось разобрать файл", err instanceof Error ? err.message : "Неизвестный формат", "bad");
      }
    };

    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) close();
    });
    overlay.querySelector("[data-cancel]")?.addEventListener("click", close);
    input.addEventListener("change", () => void handleFile(input.files?.[0]));
    overlay.addEventListener("dragover", (event) => {
      event.preventDefault();
      overlay.classList.add("is-over");
    });
    overlay.addEventListener("dragleave", () => overlay.classList.remove("is-over"));
    overlay.addEventListener("drop", (event) => {
      event.preventDefault();
      overlay.classList.remove("is-over");
      void handleFile(event.dataTransfer?.files?.[0]);
    });
    input.click();
  };

  el.addEventListener("click", (event) => {
    const target = event.target as HTMLElement;
    if (target.closest("[data-import]")) {
      openImport();
      return;
    }
    if (target.closest("[data-game-save]")) {
      void saveGame();
      return;
    }
    if (target.closest("[data-game-pick]")) {
      void pickFolder();
      return;
    }
    if (target.closest("[data-game-clear]")) {
      void clearGame();
      return;
    }
    const sessionBtn = target.closest<HTMLElement>("[data-session]");
    if (sessionBtn?.dataset.session) {
      const session = ctx.store.state.sessions.find((s) => s.session === sessionBtn.dataset.session);
      if (session) ctx.store.selectSession(session);
    }
  });

  // Ввод запоминаем в черновике: опрос статуса не должен стирать набранное.
  el.addEventListener("input", (event) => {
    const target = event.target as HTMLInputElement;
    if (target.matches("[data-game-path]")) draftPath = target.value;
  });

  void loadGame();
  const gameTimer = window.setInterval(() => void loadGame(), 2000);

  const unsubscribe = ctx.store.subscribe(render);
  return {
    el,
    destroy: () => {
      window.clearInterval(gameTimer);
      unsubscribe();
    },
    refresh: () => void ctx.store.loadFps(),
  };
}
