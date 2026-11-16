/** Форматирование чисел, размеров и времени. */

export function pct(value: number, digits = 0): string {
  if (!Number.isFinite(value)) return "—";
  return `${value.toFixed(digits)}%`;
}

export function num(value: number, digits = 0): string {
  if (!Number.isFinite(value)) return "—";
  return value.toLocaleString("ru-RU", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

export function bytes(value: number, digits = 1): string {
  if (!Number.isFinite(value) || value <= 0) return "0 Б";
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let v = value;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : digits)} ${units[i]}`;
}

export function rate(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 Б/с";
  return `${bytes(value)}/с`;
}

export function uptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days} д ${hours} ч`;
  if (hours > 0) return `${hours} ч ${mins} мин`;
  return `${mins} мин`;
}

export function tsTime(ts: number): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });
}

export function tsDateTime(ts: number): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function severityLabel(severity: string): string {
  switch (severity) {
    case "critical":
      return "критично";
    case "warning":
      return "внимание";
    case "ok":
      return "норма";
    default:
      return "инфо";
  }
}

export function scoreTone(score: number): "ok" | "warn" | "bad" {
  if (score >= 80) return "ok";
  if (score >= 55) return "warn";
  return "bad";
}

export function loadTone(value: number): "ok" | "warn" | "bad" {
  if (value < 65) return "ok";
  if (value < 85) return "warn";
  return "bad";
}

export function fpsTone(fps: number): "ok" | "warn" | "bad" {
  if (fps >= 60) return "ok";
  if (fps >= 30) return "warn";
  return "bad";
}

export function shortPath(path: string, max = 46): string {
  if (!path) return "—";
  if (path.length <= max) return path;
  const parts = path.split("\\");
  if (parts.length <= 2) return `…${path.slice(-max)}`;
  return `${parts[0]}\\…\\${parts.slice(-2).join("\\")}`;
}

export function procInitials(name: string): string {
  const clean = name.replace(/\.exe$/i, "");
  return (clean[0] ?? "?").toUpperCase();
}

/** Русская плюрализация: 1 точка, 3 точки, 5 точек. */
export function plural(count: number, one: string, few: string, many: string): string {
  const n = Math.abs(Math.round(count));
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return `${n} ${one}`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${n} ${few}`;
  return `${n} ${many}`;
}
