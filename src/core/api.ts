/** Типы ответов локального агента и HTTP-клиент. */

export interface CpuInfo {
  usage: number;
  cores: number;
  name: string;
  mhz: number;
  /** Всего потоков в системе. */
  threads: number;
  /** Открытых дескрипторов. */
  handles: number;
  /** Число процессов. */
  processes: number;
}

export interface MemInfo {
  total: number;
  used: number;
  percent: number;
  /** Выделено (commit) и предел выделения. */
  committed: number;
  commitLimit: number;
  /** Кэш и доступная память. */
  cached: number;
  available: number;
  pagedPool: number;
  nonPagedPool: number;
}

export interface DiskInfo {
  letter: string;
  label: string;
  total: number;
  free: number;
  percent: number;
  /** Активность диска, % — как «Активное время» в диспетчере задач. */
  active: number;
  readBps: number;
  writeBps: number;
}

export interface NetInfo {
  down: number;
  up: number;
  totalDown: number;
  totalUp: number;
}

export interface GpuInfo {
  available: boolean;
  name: string;
  vendor: string;
  usage: number;
  memUsed: number;
  memTotal: number;
  temp: number;
  clock: number;
  fan: number;
  power: number;
}

export interface ProcInfo {
  pid: number;
  parent: number;
  name: string;
  path: string;
  cpu: number;
  mem: number;
  threads: number;
  user: string;
}

export interface Snapshot {
  ts: number;
  host: string;
  os: string;
  uptime: number;
  cpu: CpuInfo;
  mem: MemInfo;
  disks: DiskInfo[];
  net: NetInfo;
  gpu: GpuInfo;
  procs: ProcInfo[];
  health: { score: number; grade: string };
  threats: number;
  startup: number;
}

export interface Meta {
  app: string;
  version: string;
  startedAt: number;
  gpuAvailable: boolean;
  cpu: string;
  cores: number;
  host: string;
}

export interface Finding {
  id: string;
  severity: "critical" | "warning" | "info" | "ok" | string;
  title: string;
  detail: string;
  path: string;
  pid: number;
  hash: string;
  signed: boolean | null;
  recommendation: string;
  kind: string;
}

export interface Autorun {
  name: string;
  command: string;
  location: string;
  hive: string;
  key: string;
  exists: boolean;
  suspicious: boolean;
}

export interface Conn {
  pid: number;
  proc: string;
  local: string;
  remote: string;
  state: string;
  remoteIp: string;
}

export interface ScanReport {
  startedAt: number;
  durationMs: number;
  checked: number;
  signed: number;
  unsigned: number;
  skipped: number;
  /** Балл проверки, рассчитанный агентом (единый с оценкой здоровья). */
  score: number;
  /** Доля процессов с проверенной подписью, %. */
  coverage: number;
  threats: Finding[];
  autoruns: Autorun[];
  riskyConnections: Conn[];
}

export interface HealthComponent {
  name: string;
  /** null — данных для оценки нет; значение не выдумывается. */
  score: number | null;
  measured: boolean;
  detail: string;
  /** Что показать вместо балла, если балл — не измеренная величина (например, «39.9 °C»). */
  value?: string | null;
  /** Заполнение шкалы 0..100, если оно не совпадает с баллом. */
  ratio?: number | null;
}

export interface HealthReport {
  score: number;
  grade: string;
  headline: string;
  summary: string;
  components: HealthComponent[];
  issues: Finding[];
}

export interface HistoryPoint {
  ts: number;
  score: number;
  cpu: number;
  mem: number;
  disk: number;
}

export interface FpsThreshold {
  label: string;
  value: number;
}

export interface FpsReport {
  app: string;
  session: string;
  source: string;
  duration: number;
  frames: number;
  avgFps: number;
  maxFps: number;
  minFps: number;
  p1Low: number;
  p5Low: number;
  p01Low: number;
  stutters: number;
  stutterRatio: number;
  series: number[];
  moving: number[];
  thresholds: FpsThreshold[];
  histogram: number[];
  histogramLabels: string[];
  verdict: string;
  score: number;
}

export interface ActionItem {
  id: string;
  title: string;
  detail: string;
  risk: string;
  kind: string;
  category: string;
  reversible: boolean;
}

export interface GameProfile {
  name: string;
  process: string;
  /** Папка игры, если профиль задан путём. */
  path: string;
}

export interface GameStatus {
  profile: GameProfile | null;
  /** Игра сейчас запущена. */
  running: boolean;
  /** Оптимизация включена прямо сейчас. */
  active: boolean;
  /** Когда включили (unix-время), 0 — не включена. */
  since: number;
  applied: { power: boolean; priority: boolean };
  error: string | null;
}

/** Находка встроенной проверки на вирусы. */
export interface AvThreat {
  path: string;
  /** Имя по базе подписей или название эвристики. */
  name: string;
  /** signature | heuristic | test */
  kind: string;
  /** critical | warning */
  severity: string;
  /** Почему файл попал в список. */
  reason: string;
}

export interface AvStatus {
  running: boolean;
  /** quick | full */
  mode: string;
  /** Сколько файлов проверено. */
  scanned: number;
  /** Сколько объектов предстоит проверить (для процента). */
  total: number;
  /** Процент выполнения 0–100. */
  percent: number;
  /** counting — идёт подсчёт объектов, scanning — проверка. */
  phase: string;
  /** Сколько находок. */
  threats: number;
  /** Сколько файлов не удалось открыть: заняты системой или закрыты правами. */
  skipped: number;
  /** Сколько файлов пропущено как уже проверенные и не изменившиеся. */
  cached: number;
  /** Файл, который проверяется сейчас. */
  current: string;
  started: number;
  finished: number;
  cancelled: boolean;
  error: string | null;
  /** Сколько подписей загружено. */
  signatures: number;
  /** Сколько правил в стиле YARA загружено. */
  rules: number;
  /** Сколько путей в исключениях. */
  exclusions: number;
  /** Сколько находок скрыто как игнорируемые. */
  ignored: number;
  found: AvThreat[];
}

export interface ProcessResponse {
  items: ProcInfo[];
  count: number;
  anomalies: number;
}

export interface ConnectionsResponse {
  items: Conn[];
  established: number;
  listening: number;
}

export interface AutorunsResponse {
  items: Autorun[];
  count: number;
  suspicious: number;
}

const base = "";

/** Ошибка связи с локальным агентом (процесс остановлен или ещё не поднялся). */
export class AgentOfflineError extends Error {
  constructor() {
    super("Нет связи с локальным агентом PC Sentinel");
    this.name = "AgentOfflineError";
  }
}

async function request<T>(path: string, method: "GET" | "POST" = "GET", body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${base}${path}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    // fetch падает с «Failed to fetch», когда агент не слушает порт.
    throw new AgentOfflineError();
  }
  if (!res.ok) {
    let message = `Ошибка запроса ${path} (${res.status})`;
    try {
      const data = (await res.json()) as { error?: string };
      if (data?.error) message = data.error;
    } catch {
      /* тело не JSON */
    }
    throw new Error(message);
  }
  return (await res.json()) as T;
}

export const api = {
  meta: () => request<Meta>("/api/meta"),
  snapshot: () => request<Snapshot>("/api/snapshot"),
  processes: () => request<ProcessResponse>("/api/processes"),
  autoruns: () => request<AutorunsResponse>("/api/autoruns"),
  connections: () => request<ConnectionsResponse>("/api/connections"),
  scan: () => request<ScanReport>("/api/scan", "POST", {}),
  lastScan: () => request<ScanReport>("/api/scan"),
  health: () => request<HealthReport>("/api/health"),
  history: () => request<{ points: HistoryPoint[] }>("/api/history"),
  fps: () => request<{ sessions: FpsReport[] }>("/api/fps"),
  importCapture: (path: string) => request<FpsReport>("/api/fps/import", "POST", { path }),
  optimize: () => request<{ actions: ActionItem[] }>("/api/optimize"),
  action: (id: string) => request<{ ok: boolean; message: string }>("/api/action", "POST", { id }),
  game: () => request<GameStatus>("/api/game"),
  setGame: (name: string, process: string) =>
    request<GameStatus>("/api/game", "POST", { name, process }),
  /** Профиль по папке игры: исполняемый файл агент находит сам. */
  setGamePath: (path: string) => request<GameStatus>("/api/game", "POST", { path }),
  pickGameFolder: () => request<{ path: string | null }>("/api/game/pick", "POST", {}),
  av: () => request<AvStatus>("/api/av"),
  avScan: (mode: "quick" | "full") => request<{ ok: boolean }>("/api/av/scan", "POST", { mode }),
  avCancel: () => request<{ ok: boolean }>("/api/av/cancel", "POST", {}),
  avExclude: (path: string) =>
    request<{ ok: boolean; message: string }>("/api/av/exclude", "POST", { path }),
  avIgnore: (path: string) =>
    request<{ ok: boolean; message: string }>("/api/av/ignore", "POST", { path }),
  avOpen: (path: string) =>
    request<{ ok: boolean; message: string }>("/api/av/open", "POST", { path }),
  avClearLists: () =>
    request<{ ok: boolean; message: string }>("/api/av/clear-lists", "POST", {}),
  kill: (pid: number) => request<{ ok: boolean; message: string }>("/api/process/kill", "POST", { pid }),
  settings: () => request<Record<string, string>>("/api/settings"),
  saveSettings: (patch: Record<string, string>) =>
    request<{ ok: boolean }>("/api/settings", "POST", patch),
  quit: () => request<{ ok: boolean }>("/api/app/quit", "POST", {}),
};
