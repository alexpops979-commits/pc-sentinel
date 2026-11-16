/** Экран «Защита»: подписи, майнеры, автозапуск, подозрительная сеть. */

import { api } from "../core/api";
import type { Autorun, AvStatus } from "../core/api";
import { esc, icon } from "../core/dom";
import { num, plural, scoreTone, severityLabel, shortPath, tsDateTime } from "../core/format";
import { ringHtml } from "../core/charts";
import { badge, emptyState, modal, toast } from "../core/ui";
import type { AppState } from "../core/store";
import type { View, ViewContext } from "./types";

export function createSecurity(ctx: ViewContext): View {
  const el = document.createElement("section");
  el.className = "view-grid";
  let autoruns: Autorun[] = [];

  el.innerHTML = `
    <div class="grid grid--sidebar">
      <div class="stack">
        <div class="card card--glow" data-hero></div>
        <div class="card" data-av></div>
        <div class="card" data-findings></div>
        <div class="card">
          <div class="card__head">
            <div class="card__title">${icon("target", 16)}Что проверяется</div>
            <span class="card__sub">локально, без облака</span>
          </div>
          <div class="card__body card__body--flush">
            ${[
              ["Цифровые подписи", "WinVerifyTrust: встроенные и каталожные подписи файлов", "shieldCheck"],
              ["Автозапуск", "Разделы Run / RunOnce в HKLM и HKCU, папки Startup", "layers"],
              ["Признаки майнинга", "Шаблоны имён, stratum-параметры, подозрительные пути", "zap"],
              ["Сетевая активность", "TCP-соединения процессов и слушающие порты", "wifi"],
              ["Целостность файлов", "SHA-256 исполняемых файлов подозрительных процессов", "lock"],
            ]
              .map(
                ([title, text, iconName]) => `
              <div class="row row--compact">
                <span class="row__icon">${icon(iconName, 15)}</span>
                <div class="row__main">
                  <div class="row__title">${esc(title)}</div>
                  <div class="row__desc">${esc(text)}</div>
                </div>
              </div>`,
              )
              .join("")}
          </div>
        </div>
      </div>
      <div class="stack">
        <div class="card" data-stats></div>
        <div class="card" data-startup></div>
        <div class="card" data-conns></div>
      </div>
    </div>`;

  const hero = el.querySelector<HTMLElement>("[data-hero]")!;
  const avCard = el.querySelector<HTMLElement>("[data-av]")!;
  const findings = el.querySelector<HTMLElement>("[data-findings]")!;
  const stats = el.querySelector<HTMLElement>("[data-stats]")!;
  const startup = el.querySelector<HTMLElement>("[data-startup]")!;
  const conns = el.querySelector<HTMLElement>("[data-conns]")!;

  /* ---------- Встроенная проверка на вирусы ---------- */

  let av: AvStatus | null = null;
  let avError: string | null = null;
  let avBusy = false;
  /** Подпись состояния: пока не меняется, разметку не трогаем. */
  let avSig = "";

  const avThreatRow = (t: { path: string; name: string; kind: string; severity: string; reason: string }): string => {
    const tone = t.severity === "critical" ? "bad" : "warn";
    const kindLabel =
      t.kind === "signature"
        ? "по базе"
        : t.kind === "test"
          ? "тест"
          : t.kind === "rule"
            ? "правило"
            : t.kind === "pe"
              ? "разбор PE"
              : "эвристика";
    return `
      <div class="row">
        <span class="dot dot--${tone === "bad" ? "bad" : "warn"}"></span>
        <div class="row__main">
          <div class="row__title">${esc(t.name)} ${badge(kindLabel, tone)}</div>
          <div class="row__desc mono">${esc(shortPath(t.path, 74))}</div>
          <div class="row__desc">${esc(t.reason)}</div>
        </div>
        <div class="row__meta av-actions">
          <div class="av-actions__group">
            <button class="btn btn--primary btn--sm" data-av-act="exclude" data-path="${esc(t.path)}">Устранить</button>
            <button class="btn btn--primary btn--sm av-actions__toggle" data-av-menu aria-label="Другие действия" aria-expanded="false">${icon("chevronRight", 14)}</button>
          </div>
          <div class="av-menu" hidden>
            <button class="av-menu__item" data-av-act="exclude" data-path="${esc(t.path)}">${icon("shieldCheck", 15)}Добавить в исключения</button>
            <button class="av-menu__item" data-av-act="ignore" data-path="${esc(t.path)}">${icon("eye", 15)}Игнорировать</button>
            <button class="av-menu__item" data-av-act="open" data-path="${esc(t.path)}">${icon("file", 15)}Открыть папку с файлом</button>
            <button class="av-menu__item" data-av-act="more" data-path="${esc(t.path)}">${icon("alert", 15)}Узнать больше</button>
          </div>
        </div>
      </div>`;
  };

  const renderAv = (): void => {
    const sig = avError
      ? `err:${avError}`
      : av
        ? `${av.running}|${av.mode}|${av.scanned}|${av.threats}|${av.finished}|${av.cancelled}|${av.error ?? ""}|${avBusy}|${av.signatures}`
        : "loading";
    if (sig === avSig) return;
    avSig = sig;

    if (avError) {
      avCard.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("shieldCheck", 16)}Проверка на вирусы</div>
          <span class="card__sub">нет связи</span>
        </div>
        <div class="card__body"><p class="muted">${esc(avError)}</p></div>`;
      return;
    }
    if (!av) {
      avCard.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("shieldCheck", 16)}Проверка на вирусы</div>
        </div>
        <div class="card__body"><p class="muted">Загрузка…</p></div>`;
      return;
    }

    const running = av.running;
    const found = av.found ?? [];
    const finished = av.finished > 0;
    const modeLabel = av.mode === "full" ? "полная" : "быстрая";

    avCard.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("shieldCheck", 16)}Проверка на вирусы</div>
        <span class="card__sub">${av.signatures > 0 ? `подписей: ${num(av.signatures)}` : "эвристики"}${
          av.rules > 0 ? ` · правил: ${num(av.rules)}` : ""
        }</span>
      </div>
      <div class="card__body stack--sm">
        <p class="muted">Быстрая проверка смотрит пользовательские папки и автозапуск,
        полная — <b>каждый файл на всех локальных дисках</b>. Движок сверяет SHA-256 с базой
        подписей, разбирает структуру PE (упаковку, импорты, энтропию), заглядывает внутрь
        ZIP-архивов, ищет макросы в документах Office и вложенные исполняемые файлы.
        Ничего не удаляется и не лечится.</p>
        ${
          running
            ? av.phase === "counting"
              ? `<div class="av-progress">
                 <span class="av-progress__spinner">${icon("refresh", 15)}</span>
                 <span>${modeLabel} проверка · считаем объекты…</span>
               </div>`
              : `<div class="av-progress">
                 <span class="av-progress__spinner">${icon("refresh", 15)}</span>
                 <span>${modeLabel} проверка · ${num(av.percent)}% · файлов ${num(
                   av.scanned + av.cached,
                 )} из ${num(av.total)} · находок ${num(av.threats)}</span>
               </div>
               <div class="av-bar"><span style="width:${Math.min(100, av.percent)}%"></span></div>
               <p class="hint mono">${esc(shortPath(av.current, 78))}</p>`
            : ""
        }
        ${av.error ? `<p class="hint">${icon("alert", 14)} ${esc(av.error)}</p>` : ""}
        ${
          finished && !running
            ? `<div class="av-summary">
                 ${miniStat("Проверено файлов", num(av.scanned), "file")}
                 ${miniStat(
                   "Находок",
                   num(av.threats),
                   av.threats > 0 ? "alert" : "check",
                   av.threats > 0 ? "warn" : "ok",
                 )}
                 ${
                   av.skipped > 0
                     ? miniStat("Не прочитано", num(av.skipped), "alert", "warn")
                     : ""
                 }
                 ${
                   av.cached > 0
                     ? miniStat("Из кеша", num(av.cached), "check", "ok")
                     : ""
                 }
               </div>
               <p class="hint">${modeLabel} проверка${
                 av.cancelled ? " прервана" : " завершена"
               } · ${tsDateTime(av.finished)}${
                 av.skipped > 0
                   ? ` · ${num(av.skipped)} файлов заняты системой или закрыты правами — их содержимое не проверено`
                   : ""
               }</p>`
            : ""
        }
        ${
          found.length > 0
            ? `<div class="av-threats">${found.map(avThreatRow).join("")}</div>`
            : finished && !running && av.threats === 0
              ? emptyState("Угроз не обнаружено", "Проверенные файлы чистые", "shieldCheck")
              : ""
        }
        <div class="inline">
          <button class="btn btn--primary" data-av-scan="quick" ${running || avBusy ? "disabled" : ""}>
            ${icon("zap", 15)} Быстрая проверка
          </button>
          <button class="btn btn--ghost" data-av-scan="full" ${running || avBusy ? "disabled" : ""}>
            ${icon("disk", 15)} Полная проверка
          </button>
          ${
            running
              ? `<button class="btn btn--ghost" data-av-cancel>${icon("x", 15)} Остановить</button>`
              : ""
          }
        </div>
        ${
          av.exclusions > 0 || av.ignored > 0
            ? `<p class="hint">Исключений: ${num(av.exclusions)} · игнорируемых: ${num(av.ignored)}.
               <button class="link-btn" data-av-clear>Очистить списки</button></p>`
            : ""
        }
      </div>`;
  };

  const loadAv = async (): Promise<void> => {
    try {
      av = await api.av();
      avError = null;
    } catch (err) {
      av = null;
      avError = err instanceof Error ? err.message : "Не удалось получить состояние проверки";
    }
    renderAv();
    // Итог проверки упоминается и в шапке — её тоже нужно обновить.
    render(ctx.store.state);
  };

  const startAv = async (mode: "quick" | "full"): Promise<void> => {
    if (avBusy) return;
    avBusy = true;
    try {
      await api.avScan(mode);
      toast(
        mode === "full" ? "Полная проверка запущена" : "Быстрая проверка запущена",
        mode === "full"
          ? "Обход всех локальных дисков может занять десятки минут"
          : "Пользовательские папки и автозапуск — обычно несколько минут",
        "info",
      );
    } catch (err) {
      toast("Не удалось запустить проверку", err instanceof Error ? err.message : "", "bad");
    } finally {
      avBusy = false;
      await loadAv();
    }
  };

  const cancelAv = async (): Promise<void> => {
    try {
      await api.avCancel();
      toast("Проверка останавливается", "Уже найденные объекты останутся в списке", "info");
    } catch (err) {
      toast("Не удалось остановить проверку", err instanceof Error ? err.message : "", "bad");
    }
  };

  /** Действия из меню «Устранить». */
  const runAvAction = async (action: string, path: string): Promise<void> => {
    try {
      if (action === "exclude") {
        const res = await api.avExclude(path);
        toast("Добавлено в исключения", res.message, "ok");
      } else if (action === "ignore") {
        const res = await api.avIgnore(path);
        toast("Находка скрыта", res.message, "info");
      } else if (action === "open") {
        const res = await api.avOpen(path);
        toast(res.ok ? "Открыта папка" : "Не удалось открыть", res.message, res.ok ? "ok" : "warn");
      } else if (action === "more") {
        const threat = av?.found.find((t) => t.path === path);
        await modal({
          title: threat?.name ?? "Находка",
          body: `
            <p class="mono dim">${esc(path)}</p>
            <p>${esc(threat?.reason ?? "")}</p>
            <p class="muted">${
              threat?.kind === "signature"
                ? "Файл совпал с базой подписей — это точное совпадение с известным образцом."
                : threat?.kind === "test"
                  ? "Это тестовый файл EICAR. Он безопасен и нужен только для проверки, что движок работает."
                  : threat?.kind === "rule"
                    ? "Сработало правило поиска характерных строк. Правило смотрит на сочетание признаков, а не на одно слово, но совпадение всё равно косвенное."
                    : threat?.kind === "pe"
                      ? "Файл разобран как PE: движок смотрит на секции, импорты, энтропию и упаковку. Находка складывается из нескольких признаков сразу — по одному они бывают и у нормальных программ."
                      : "Файл похож на вредонос по косвенным признакам. Это не приговор: проверьте, откуда он взялся."
            }</p>
            <p class="muted">PC Sentinel ничего не удаляет сам. Если файл вам не нужен — удалите его вручную
            или откройте папку и проверьте происхождение.</p>`,
          confirmText: "Открыть папку",
          cancelText: "Закрыть",
        }).then((answer) => {
          if (answer.ok) void api.avOpen(path);
        });
        return;
      }
    } catch (err) {
      toast("Действие не выполнено", err instanceof Error ? err.message : "", "bad");
    }
    await loadAv();
  };

  const clearAvLists = async (): Promise<void> => {
    try {
      const res = await api.avClearLists();
      toast("Списки очищены", res.message, "ok");
      await loadAv();
    } catch (err) {
      toast("Не удалось очистить списки", err instanceof Error ? err.message : "", "bad");
    }
  };

  /** Закрывает все открытые меню действий. */
  const closeAvMenus = (): void => {
    for (const menu of el.querySelectorAll<HTMLElement>(".av-menu")) menu.hidden = true;
    for (const btn of el.querySelectorAll<HTMLElement>("[data-av-menu]")) {
      btn.setAttribute("aria-expanded", "false");
    }
  };

  const findingRow = (
    f: { severity: string; title: string; detail: string; path: string; hash: string; pid: number; recommendation: string; signed: boolean | null },
    compact = false,
  ): string => {
    const tone = f.severity === "critical" ? "bad" : f.severity === "warning" ? "warn" : "accent";
    return `
      <div class="row">
        <span class="dot dot--${tone === "bad" ? "bad" : tone === "warn" ? "warn" : "live"}"></span>
        <div class="row__main">
          <div class="row__title">${esc(f.title)} ${badge(severityLabel(f.severity), tone as never)}</div>
          <div class="row__desc">${esc(f.detail)}</div>
          ${
            compact
              ? ""
              : `<div class="row__desc mono dim">${esc(shortPath(f.path, 74))}${f.hash ? ` · SHA-256 ${esc(f.hash.slice(0, 24))}…` : ""}</div>
                 <div class="row__desc recommendation">${esc(f.recommendation)}</div>`
          }
        </div>
        <div class="row__meta">
          ${f.signed === false ? badge("без подписи", "bad") : f.signed === true ? badge("подписано", "ok") : ""}
          ${f.pid ? `<button class="btn btn--ghost btn--sm" data-kill="${f.pid}">Завершить</button>` : ""}
        </div>
      </div>`;
  };

  const render = (state: AppState): void => {
    // Без связи с агентом «проверка не запускалась» читалось бы как «всё чисто»,
    // поэтому экран честно сообщает, что данных нет.
    if (!state.online && !state.scan) {
      hero.innerHTML = `
        <div class="card__body scan-hero">
          <div class="scan-hero__text">
            <span class="eyebrow">Локальная проверка</span>
            <h2>Агент PC Sentinel не отвечает</h2>
            <p class="muted">Подписи, автозапуск и сетевую активность проверяет агент. Без связи с ним
            результаты недоступны — экран не выдаёт отсутствие данных за чистую систему.</p>
            <div class="inline">
              <button class="btn btn--primary" disabled>${icon("shield", 15)}Проверить сейчас</button>
              <button class="btn btn--ghost" disabled>${icon("lock", 15)}Центр безопасности</button>
            </div>
          </div>
        </div>`;
      findings.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("bug", 16)}Находки</div>
          <span class="card__sub">нет связи</span>
        </div>
        ${emptyState("Результаты проверки недоступны", "Агент PC Sentinel не отвечает — находки не собраны", "alert")}`;
      stats.innerHTML = `
        <div class="card__head">
          <div class="card__title">${icon("shieldCheck", 16)}Цифровые подписи</div>
          <span class="card__sub">нет связи</span>
        </div>
        ${emptyState("Нет данных", "Проверка подписей выполняется агентом", "alert")}`;
      startup.innerHTML = "";
      conns.innerHTML = "";
      startup.hidden = true;
      conns.hidden = true;
      return;
    }
    startup.hidden = false;
    conns.hidden = false;

    const healthScore = state.health?.score ?? state.snapshot?.health.score ?? 0;
    // Балл проверки приходит от агента — тот же, что в оценке здоровья.
    const score = state.scan ? state.scan.score : healthScore;
    const coverage = state.scan?.coverage ?? 0;
    const fullCoverage = coverage >= 80;
    const tone = scoreTone(state.scan ? score : healthScore);
    const grade = state.scan
      ? state.scan.threats.length > 0
        ? score >= 60
          ? "Есть находки"
          : "Требуется внимание"
        : fullCoverage
          ? "Чисто"
          : "Проверено частично"
      : "Проверка не запускалась";

    hero.innerHTML = `
      <div class="card__body scan-hero">
        <div class="scan-hero__text">
          <span class="eyebrow">Встроенная проверка</span>
          <h2>${esc(grade)}</h2>
          <p class="muted">${
            state.scan
              ? `Подпись проверена у ${num(state.scan.signed + state.scan.unsigned)} из ${num(state.scan.checked)} процессов (${coverage.toFixed(0)}%) · ${tsDateTime(state.scan.startedAt)}${
                  fullCoverage
                    ? ""
                    : " · остальные системные процессы недоступны без прав администратора"
                }`
              : "Проверяет цифровые подписи, автозапуск, признаки скрытого майнинга и подозрительную сетевую активность. Файлы на диске ищет проверка на вирусы ниже."
          }</p>
          ${
            av && av.finished > 0
              ? `<p class="hint">${icon("shieldCheck", 14)} Проверка файлов: ${
                  av.threats > 0
                    ? `находок — ${num(av.threats)}`
                    : "угроз не обнаружено"
                } (проверено ${num(av.scanned)}).</p>`
              : ""
          }
          ${
            state.online || !state.scan
              ? ""
              : `<p class="hint">${icon("alert", 14)} Связь с агентом потеряна — показаны результаты последней проверки, новая недоступна.</p>`
          }
          <div class="inline">
            <button class="btn btn--primary" data-scan ${state.scanning || !state.online ? "disabled" : ""}>
              ${state.scanning ? icon("refresh", 15) + " Проверяем…" : icon("shield", 15) + " Проверить сейчас"}
            </button>
            <button class="btn btn--ghost" data-defender ${state.online ? "" : "disabled"}>${icon("lock", 15)}Центр безопасности</button>
          </div>
        </div>
        <div class="scan-hero__ring">${ringHtml(state.scan ? score : healthScore, {
          caption: state.scan ? grade : "здоровье ПК",
          tone,
        })}</div>
      </div>`;

    const threats = state.scan?.threats ?? [];
    const suspiciousAutoruns = (state.scan?.autoruns ?? []).filter((a) => a.suspicious).length;
    findings.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("bug", 16)}Находки</div>
        <span class="card__sub">${threats.length === 0 ? "не обнаружено" : `${threats.length} шт.`}</span>
      </div>
      <div class="card__body card__body--flush">
        ${
          threats.length === 0
            ? emptyState(
                state.scan
                  ? fullCoverage
                    ? "Угроз не обнаружено"
                    : "Угроз не обнаружено среди проверенных"
                  : "Встроенная проверка не запускалась",
                state.scan
                  ? suspiciousAutoruns > 0
                    ? `Но в автозагрузке ${plural(suspiciousAutoruns, "подозрительная запись", "подозрительные записи", "подозрительных записей")} — см. справа`
                    : fullCoverage
                      ? "Все проверенные подписи валидны"
                      : "Подписи проверенных файлов валидны, часть процессов недоступна"
                  : "Нажмите «Проверить сейчас» — или запустите проверку на вирусы выше",
                "shieldCheck",
              )
            : threats.map((t) => findingRow(t)).join("")
        }
      </div>`;

    stats.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("shieldCheck", 16)}Цифровые подписи</div>
      </div>
      <div class="card__body stack--sm">
        ${miniStat("Проверено файлов", state.scan ? num(state.scan.checked) : "—", "file")}
        ${miniStat("Валидная подпись", state.scan ? num(state.scan.signed) : "—", "check", "ok")}
        ${miniStat("Без подписи", state.scan ? num(state.scan.unsigned) : "—", "alert", state.scan && state.scan.unsigned > 0 ? "warn" : "muted")}
        ${miniStat("Длительность", state.scan ? `${state.scan.durationMs} мс` : "—", "clock")}
        ${
          state.scan && state.scan.skipped > 0
            ? `<p class="hint">${num(state.scan.skipped)} системных процессов недоступны для проверки без прав администратора.</p>`
            : ""
        }
      </div>`;

    // Автозапуск читается агентом всегда, поэтому показываем его и без полной проверки.
    const allAutoruns = state.scan?.autoruns?.length ? state.scan.autoruns : autoruns;
    const suspicious = allAutoruns.filter((a) => a.suspicious).slice(0, 5);
    startup.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("layers", 16)}Автозапуск</div>
        <span class="card__sub">${
          allAutoruns.length === 0
            ? "—"
            : `${plural(allAutoruns.length, "запись", "записи", "записей")} · ${suspicious.length} подозрительных`
        }</span>
      </div>
      <div class="card__body card__body--flush">
        ${
          suspicious.length === 0
            ? emptyState(
                allAutoruns.length === 0 ? "Автозагрузка не прочитана" : "Подозрительных записей нет",
                allAutoruns.length === 0 ? "Запустите проверку" : "",
                "check",
              )
            : suspicious
                .map(
                  (a) => `
          <div class="row">
            <span class="dot dot--warn"></span>
            <div class="row__main">
              <div class="row__title">${esc(a.name)}</div>
              <div class="row__desc mono">${esc(shortPath(a.command, 52))}</div>
            </div>
            <button class="btn btn--ghost btn--sm" data-disable="${esc(a.name)}">Отключить</button>
          </div>`,
                )
                .join("")
        }
      </div>`;

    const risky = state.scan?.riskyConnections ?? [];
    conns.innerHTML = `
      <div class="card__head">
        <div class="card__title">${icon("wifi", 16)}Сеть</div>
        <span class="card__sub">${risky.length} связей</span>
      </div>
      <div class="card__body card__body--flush">
        ${
          risky.length === 0
            ? emptyState("Подозрительных соединений нет", "", "wifi")
            : risky
                .map(
                  (c) => `
          <div class="row">
            <span class="dot dot--bad"></span>
            <div class="row__main">
              <div class="row__title">${esc(c.proc || `PID ${c.pid}`)}</div>
              <div class="row__desc mono">${esc(c.remote)}</div>
            </div>
            ${badge(c.state, "muted")}
          </div>`,
                )
                .join("")
        }
      </div>`;
  };

  function miniStat(label: string, value: string, iconName: string, tone: "ok" | "warn" | "muted" = "muted"): string {
    return `
      <div class="mini-stat">
        <span class="mini-stat__icon ${tone !== "muted" ? `mini-stat__icon--${tone}` : ""}">${icon(iconName, 15)}</span>
        <span class="mini-stat__label">${esc(label)}</span>
        <b class="mini-stat__value">${esc(value)}</b>
      </div>`;
  }

  el.addEventListener("click", (event) => {
    const target = event.target as HTMLElement;
    if (target.closest("[data-scan]")) {
      void ctx.runScan().then((report) => {
        if (report) {
          toast(
            report.threats.length === 0 ? "Проверка завершена: чисто" : "Обнаружены находки",
            report.threats.length === 0
              ? `Проверено ${report.checked} процессов за ${report.durationMs} мс`
              : `${report.threats.length} подозрительных объектов, из них ${report.unsigned} без подписи`,
            report.threats.length === 0 ? "ok" : "warn",
          );
        }
      });
      return;
    }
    if (target.closest("[data-defender]")) {
      void api.action("open:defender");
      toast("Открываем Центр безопасности Windows", "", "info");
      return;
    }
    const avBtn = target.closest<HTMLElement>("[data-av-scan]");
    if (avBtn) {
      void startAv(avBtn.dataset.avScan === "full" ? "full" : "quick");
      return;
    }
    if (target.closest("[data-av-cancel]")) {
      void cancelAv();
      return;
    }
    if (target.closest("[data-av-clear]")) {
      void clearAvLists();
      return;
    }
    // Раскрыть/свернуть меню действий у находки.
    const menuBtn = target.closest<HTMLElement>("[data-av-menu]");
    if (menuBtn) {
      const group = menuBtn.closest(".av-actions");
      const menu = group?.querySelector<HTMLElement>(".av-menu");
      if (menu) {
        const willOpen = menu.hidden;
        closeAvMenus();
        menu.hidden = !willOpen;
        menuBtn.setAttribute("aria-expanded", String(willOpen));
      }
      return;
    }
    const actBtn = target.closest<HTMLElement>("[data-av-act]");
    if (actBtn?.dataset.avAct && actBtn.dataset.path) {
      closeAvMenus();
      void runAvAction(actBtn.dataset.avAct, actBtn.dataset.path);
      return;
    }
    const killBtn = target.closest<HTMLElement>("[data-kill]");
    if (killBtn) {
      const pid = Number(killBtn.dataset.kill);
      void modal({
        title: "Завершить подозрительный процесс",
        body: `<p>Процесс PID ${pid} будет завершён. Это действие не удаляет файл с диска.</p>`,
        confirmText: "Завершить",
        tone: "danger",
      }).then(async (answer) => {
        if (!answer.ok) return;
        const res = await api.kill(pid);
        toast(res.message, "", res.ok ? "ok" : "bad");
        await ctx.store.runScan();
      });
      return;
    }
    const disableBtn = target.closest<HTMLElement>("[data-disable]");
    if (disableBtn) {
      const name = disableBtn.dataset.disable ?? "";
      const entry = (ctx.store.state.scan?.autoruns ?? []).find((a) => a.name === name);
      if (!entry) return;
      void modal({
        title: "Отключить автозапуск",
        body: `<p>Удалить запись <b>${esc(name)}</b> из <span class="mono">${esc(entry.location)}</span>?</p>`,
        confirmText: "Отключить",
        tone: "danger",
      }).then(async (answer) => {
        if (!answer.ok) return;
        const res = await api.action(`disable:${entry.location}|${entry.key}|${entry.name}`);
        toast(res.message, "", res.ok ? "ok" : "warn");
        await ctx.store.runScan();
      });
    }
  });

  const loadAutoruns = async (): Promise<void> => {
    try {
      autoruns = (await api.autoruns()).items;
      render(ctx.store.state);
    } catch {
      /* агент недоступен */
    }
  };

  const unsubscribe = ctx.store.subscribe(render);
  if (!ctx.store.state.scan) void ctx.store.loadScan();
  void loadAutoruns();
  void loadAv();
  // Опрашиваем всегда, а не только во время проверки: иначе карточка может
  // остаться с устаревшим результатом, если проверка закончилась между опросами.
  // Разметка перерисовывается только при смене состояния, так что это дёшево.
  const avTimer = window.setInterval(() => {
    void loadAv();
  }, 2000);
  // Клик мимо меню закрывает его.
  const onDocClick = (event: MouseEvent): void => {
    const target = event.target as HTMLElement | null;
    if (!target?.closest(".av-actions")) closeAvMenus();
  };
  document.addEventListener("click", onDocClick);
  return {
    el,
    destroy: () => {
      window.clearInterval(avTimer);
      document.removeEventListener("click", onDocClick);
      unsubscribe();
    },
    refresh: () => {
      void ctx.store.loadHealth();
      void loadAutoruns();
      void loadAv();
    },
  };
}
