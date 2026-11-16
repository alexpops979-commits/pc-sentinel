/** Точка входа: навигация, маршрутизация, топбар. */

import { icon } from "./core/dom";
import { store } from "./core/store";
import type { AppState, Route } from "./core/store";
import { toast } from "./core/ui";
import { createFps } from "./views/fps";
import { createHistory } from "./views/history";
import { createOptimize } from "./views/optimize";
import { createOverview } from "./views/overview";
import { createProcesses } from "./views/processes";
import { createSecurity } from "./views/security";
import { createSettings } from "./views/settings";
import type { View, ViewContext } from "./views/types";

interface NavItem {
  route: Route;
  label: string;
  icon: string;
  group: string;
}

const NAV: NavItem[] = [
  { route: "overview", label: "Обзор", icon: "home", group: "мониторинг" },
  { route: "fps", label: "FPS и frametime", icon: "gauge", group: "мониторинг" },
  { route: "processes", label: "Процессы", icon: "layers", group: "мониторинг" },
  { route: "security", label: "Защита", icon: "shield", group: "безопасность" },
  { route: "optimize", label: "Оптимизация", icon: "wrench", group: "безопасность" },
  { route: "history", label: "История", icon: "clock", group: "аналитика" },
  { route: "settings", label: "Настройки", icon: "settings", group: "аналитика" },
];

const TITLES: Record<Route, { title: string; crumb: string }> = {
  overview: { title: "Обзор", crumb: "Мониторинг" },
  fps: { title: "FPS и производительность", crumb: "Мониторинг" },
  processes: { title: "Процесс‑интеллект", crumb: "Мониторинг" },
  security: { title: "Защита от угроз", crumb: "Безопасность" },
  optimize: { title: "Оптимизация", crumb: "Безопасность" },
  history: { title: "История и здоровье", crumb: "Аналитика" },
  settings: { title: "Настройки", crumb: "Аналитика" },
};

const FACTORIES: Record<Route, (ctx: ViewContext) => View> = {
  overview: createOverview,
  fps: createFps,
  processes: createProcesses,
  security: createSecurity,
  optimize: createOptimize,
  history: createHistory,
  settings: createSettings,
};

const viewRoot = document.getElementById("view");
const navRoot = document.getElementById("nav");
const titleNode = document.getElementById("page-title");
const crumbsNode = document.getElementById("crumbs");
const searchInput = document.getElementById("search") as HTMLInputElement | null;
const searchIcon = document.getElementById("search-icon");
const statusPill = document.getElementById("status-pill");
const statusText = document.getElementById("status-text");

if (!viewRoot || !navRoot) throw new Error("Разметка приложения не загружена");
const viewRootEl: HTMLElement = viewRoot;
const navRootEl: HTMLElement = navRoot;

let currentView: View | null = null;
let currentRoute: Route | null = null;
let offlineNotified = false;

function renderNav(active: Route): void {
  let lastGroup = "";
  const parts: string[] = [];
  for (const item of NAV) {
    if (item.group !== lastGroup) {
      lastGroup = item.group;
      parts.push(`<div class="nav__group">${item.group}</div>`);
    }
    parts.push(`
      <a class="nav__item ${item.route === active ? "is-active" : ""}" href="#/${item.route}" data-route="${item.route}">
        ${icon(item.icon, 18)}
        <span>${item.label}</span>
      </a>`);
  }
  navRootEl.innerHTML = parts.join("");
}

function navigate(route: Route): void {
  if (window.location.hash !== `#/${route}`) {
    window.location.hash = `#/${route}`;
  } else {
    mount(route);
  }
}

const ctx: ViewContext = {
  store,
  navigate,
  search: () => store.state.search,
  runScan: async () => {
    const report = await store.runScan();
    if (report) {
      toast(
        report.threats.length === 0 ? "Проверка завершена: чисто" : "Найдены подозрительные объекты",
        report.threats.length === 0
          ? `Проверено ${report.checked} процессов`
          : `${report.threats.length} находок, ${report.unsigned} без подписи`,
        report.threats.length === 0 ? "ok" : "warn",
      );
    } else if (store.state.error) {
      toast("Проверка не выполнена", store.state.error, "bad");
    }
    return report;
  },
};

function mount(route: Route): void {
  if (currentRoute === route) return;
  currentRoute = route;
  if (currentView?.destroy) currentView.destroy();
  const view = FACTORIES[route](ctx);
  currentView = view;
  viewRootEl.replaceChildren(view.el);
  viewRootEl.scrollTop = 0;
  const meta = TITLES[route];
  if (titleNode) titleNode.textContent = meta.title;
  if (crumbsNode) crumbsNode.innerHTML = `<span>PC Sentinel</span><span>/</span><span>${meta.crumb}</span>`;
  renderNav(route);
  view.refresh?.();
  if (searchInput) {
    searchInput.placeholder =
      route === "processes"
        ? "Поиск процесса, пути, порта…"
        : route === "security"
          ? "Поиск по находкам…"
          : "Поиск процесса, файла, порта…";
    searchInput.value = "";
    store.setSearch("");
  }
}

function setupTopbar(): void {
  if (searchIcon) searchIcon.innerHTML = icon("search", 15);
  const settingsBtn = document.getElementById("btn-settings");
  if (settingsBtn) {
    settingsBtn.innerHTML = icon("settings", 16);
    settingsBtn.addEventListener("click", () => navigate("settings"));
  }
  const scanBtn = document.getElementById("btn-scan");
  if (scanBtn) {
    scanBtn.addEventListener("click", () => {
      void ctx.runScan();
    });
  }
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      store.setSearch(searchInput.value);
      currentView?.refresh?.();
    });
    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchInput.focus();
        searchInput.select();
      }
      if (event.key === "Escape" && document.activeElement === searchInput) {
        searchInput.value = "";
        store.setSearch("");
        store.setRoute(store.state.route);
        currentView?.refresh?.();
      }
    });
  }
}

function setupAgentCard(state: AppState): void {
  const hint = document.getElementById("agent-hint");
  const title = document.getElementById("agent-title");
  const dot = document.getElementById("agent-dot");
  if (!hint) return;

  if (!state.online) {
    if (title) title.textContent = "Агент остановлен";
    if (dot) dot.className = "dot dot--bad";
    hint.textContent = "Нет связи с агентом телеметрии";
    return;
  }

  if (title) title.textContent = "Агент активен";
  if (dot) dot.className = "dot dot--live";

  const snap = state.snapshot;
  if (!snap) {
    hint.textContent = "Сбор телеметрии…";
    return;
  }
  const gpu = snap.gpu.available ? snap.gpu.vendor : "GPU без датчика";
  hint.textContent = `${snap.cpu.cores} потоков · ${gpu} · ${snap.procs.length} процессов`;
}

function setupStatus(state: AppState): void {
  if (!statusPill || !statusText) return;
  // Проверку выполняет агент — без связи кнопка в шапке ничего не сделает.
  const scanBtn = document.getElementById("btn-scan") as HTMLButtonElement | null;
  if (scanBtn) scanBtn.disabled = !state.online;
  const dot = statusPill.querySelector<HTMLElement>(".dot");
  if (state.online) {
    statusPill.style.background = "rgba(46, 230, 168, 0.07)";
    statusText.textContent = "Мониторинг активен";
    if (dot) dot.className = "dot dot--live";
    if (offlineNotified) {
      offlineNotified = false;
      toast("Связь восстановлена", "Данные снова обновляются", "ok");
    }
    setOfflineBanner(false);
  } else {
    statusPill.style.background = "rgba(255, 93, 108, 0.1)";
    statusText.textContent = "Агент недоступен";
    if (dot) dot.className = "dot dot--bad";
    setOfflineBanner(true);
    if (!offlineNotified) {
      offlineNotified = true;
      toast("Агент PC Sentinel остановлен", "Окно осталось открытым, но данные не обновляются", "bad");
    }
  }
}

/** Постоянная плашка вместо повторяющихся тостов. */
function setOfflineBanner(show: boolean): void {
  const existing = document.getElementById("offline-banner");
  if (!show) {
    existing?.remove();
    return;
  }
  if (existing) return;
  const banner = document.createElement("div");
  banner.id = "offline-banner";
  banner.className = "offline-banner";
  banner.innerHTML = `
    <span class="offline-banner__icon">${icon("alert", 16)}</span>
    <div class="offline-banner__text">
      <b>Агент PC Sentinel не отвечает</b>
      <span>Данные не обновляются. Закройте это окно и запустите PC Sentinel снова — ярлык на рабочем столе.</span>
    </div>
    <button class="btn btn--ghost btn--sm" data-retry>Повторить</button>`;
  banner.querySelector("[data-retry]")?.addEventListener("click", () => {
    void store.poll();
  });
  document.querySelector(".workspace")?.prepend(banner);
}

function init(): void {
  setupTopbar();
  store.subscribe((state) => {
    setupStatus(state);
    setupAgentCard(state);
    if (state.route !== currentRoute) mount(state.route);
  });
  window.addEventListener("hashchange", () => {
    const raw = window.location.hash.replace(/^#\/?/, "").split("?")[0];
    const route = (NAV.find((n) => n.route === raw)?.route ?? "overview") as Route;
    mount(route);
  });
  mount(store.state.route);
  void store.bootstrap();
}

init();
