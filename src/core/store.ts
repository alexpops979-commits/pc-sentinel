/** Общее состояние приложения и опрос агента. */

import { api, AgentOfflineError } from "./api";
import type {
  FpsReport,
  HealthReport,
  HistoryPoint,
  Meta,
  ScanReport,
  Snapshot,
} from "./api";

export type Route = "overview" | "fps" | "processes" | "security" | "optimize" | "history" | "settings";

export interface SeriesPoint {
  t: number;
  cpu: number;
  mem: number;
  gpu: number;
  /** Заполнение самого полного тома, %. */
  disk: number;
}

export interface AppState {
  route: Route;
  online: boolean;
  meta: Meta | null;
  snapshot: Snapshot | null;
  series: SeriesPoint[];
  history: HistoryPoint[];
  health: HealthReport | null;
  scan: ScanReport | null;
  scanning: boolean;
  sessions: FpsReport[];
  activeSession: FpsReport | null;
  refreshMs: number;
  search: string;
  error: string | null;
  /** Когда агент перестал отвечать (мс), null — связь есть. */
  offlineSince: number | null;
}

type Listener = (state: AppState) => void;

const ROUTES: Route[] = ["overview", "fps", "processes", "security", "optimize", "history", "settings"];

export class AppStore {
  state: AppState = {
    route: "overview",
    online: false,
    meta: null,
    snapshot: null,
    series: [],
    history: [],
    health: null,
    scan: null,
    scanning: false,
    sessions: [],
    activeSession: null,
    refreshMs: 1500,
    search: "",
    error: null,
    offlineSince: null,
  };

  private listeners = new Set<Listener>();
  private timer: number | null = null;
  private lastSeriesPush = 0;

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    fn(this.state);
    return () => this.listeners.delete(fn);
  }

  private emit(): void {
    for (const fn of this.listeners) fn(this.state);
  }

  setRoute(route: Route): void {
    if (!ROUTES.includes(route)) route = "overview";
    this.state.route = route;
    this.emit();
  }

  setSearch(value: string): void {
    this.state.search = value;
    this.emit();
  }

  async bootstrap(): Promise<void> {
    this.applyHash();
    window.addEventListener("hashchange", () => {
      this.applyHash();
    });
    await this.loadMeta();
    await Promise.all([this.poll(), this.loadHistory(), this.loadHealth(), this.loadFps()]);
    this.schedule();
  }

  private applyHash(): void {
    const raw = window.location.hash.replace(/^#\/?/, "").split("?")[0];
    const route = (ROUTES.find((r) => r === raw) ?? "overview") as Route;
    this.setRoute(route);
  }

  private schedule(): void {
    if (this.timer !== null) window.clearTimeout(this.timer);
    this.timer = window.setTimeout(async () => {
      await this.poll();
      this.schedule();
    }, this.state.online ? this.state.refreshMs : 2000);
  }

  setRefresh(ms: number): void {
    this.state.refreshMs = Math.max(700, Math.min(10000, ms));
    this.schedule();
    void api.saveSettings({ refresh_ms: String(this.state.refreshMs) });
  }

  async loadMeta(): Promise<void> {
    try {
      this.state.meta = await api.meta();
      this.emit();
    } catch {
      /* агент ещё не готов */
    }
  }

  async poll(): Promise<void> {
    try {
      const snap = await api.snapshot();
      const wasOffline = this.state.offlineSince !== null;
      this.state.snapshot = snap;
      this.state.online = true;
      this.state.error = null;
      this.state.offlineSince = null;
      if (wasOffline) {
        // Связь вернулась — подтягиваем то, что могло устареть.
        void this.loadHealth();
        void this.loadHistory();
      }
      const now = Date.now();
      if (now - this.lastSeriesPush > 700) {
        this.lastSeriesPush = now;
        const worstDisk = snap.disks.length
          ? Math.max(...snap.disks.map((d) => d.percent))
          : 0;
        this.state.series.push({
          t: now,
          cpu: snap.cpu.usage,
          mem: snap.mem.percent,
          gpu: snap.gpu.available ? snap.gpu.usage : 0,
          disk: worstDisk,
        });
        if (this.state.series.length > 120) this.state.series.shift();
      }
    } catch (err) {
      this.state.online = false;
      this.state.offlineSince ??= Date.now();
      this.state.error =
        err instanceof AgentOfflineError
          ? "Агент PC Sentinel не отвечает"
          : err instanceof Error
            ? err.message
            : "Агент недоступен";
    }
    this.emit();
  }

  async loadHistory(): Promise<void> {
    try {
      const res = await api.history();
      this.state.history = res.points;
      this.emit();
    } catch {
      /* ignore */
    }
  }

  async loadHealth(): Promise<void> {
    try {
      this.state.health = await api.health();
      this.emit();
    } catch {
      /* ignore */
    }
  }

  async loadFps(): Promise<void> {
    try {
      const res = await api.fps();
      this.state.sessions = res.sessions;
      if (!this.state.activeSession && res.sessions.length > 0) {
        this.state.activeSession = res.sessions[0];
      }
      this.emit();
    } catch {
      /* ignore */
    }
  }

  selectSession(session: FpsReport): void {
    this.state.activeSession = session;
    this.emit();
  }

  addSession(session: FpsReport): void {
    this.state.sessions.unshift(session);
    this.state.activeSession = session;
    this.emit();
  }

  async loadScan(): Promise<void> {
    try {
      const report = await api.lastScan();
      if (report.startedAt > 0) {
        this.state.scan = report;
        this.emit();
      }
    } catch {
      /* агент недоступен */
    }
  }

  async runScan(): Promise<ScanReport | null> {
    this.state.scanning = true;
    this.emit();
    try {
      const report = await api.scan();
      this.state.scan = report;
      await this.loadHealth();
      return report;
    } catch (err) {
      if (err instanceof AgentOfflineError) {
        this.state.online = false;
        this.state.offlineSince ??= Date.now();
        this.state.error = "Агент PC Sentinel не отвечает";
      } else {
        this.state.error = err instanceof Error ? err.message : "Не удалось выполнить проверку";
      }
      return null;
    } finally {
      this.state.scanning = false;
      this.emit();
    }
  }

  async importCapture(path: string): Promise<FpsReport | null> {
    try {
      const report = await api.importCapture(path);
      this.state.sessions.unshift(report);
      this.state.activeSession = report;
      this.emit();
      return report;
    } catch (err) {
      this.state.error = err instanceof Error ? err.message : "Не удалось импортировать файл";
      this.emit();
      return null;
    }
  }
}

export const store = new AppStore();
