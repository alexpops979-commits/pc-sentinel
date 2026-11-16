/** Тосты, модальные окна и мелкие UI-хелперы. */

import { esc, icon } from "./dom";

let toastId = 0;

export type Tone = "ok" | "warn" | "bad" | "info";

export function toast(title: string, text = "", tone: Tone = "info", ttl = 4200): void {
  const root = document.getElementById("toasts");
  if (!root) return;
  const id = `t${(toastId += 1)}`;
  const node = document.createElement("div");
  node.className = `toast toast--${tone}`;
  node.id = id;
  const iconName = tone === "ok" ? "check" : tone === "bad" ? "alert" : tone === "warn" ? "alert" : "activity";
  node.innerHTML = `
    <span class="toast__icon">${icon(iconName, 16)}</span>
    <div class="toast__body">
      <div class="toast__title">${esc(title)}</div>
      ${text ? `<div class="toast__text">${esc(text)}</div>` : ""}
    </div>`;
  root.append(node);
  window.setTimeout(() => {
    node.classList.add("is-out");
    window.setTimeout(() => node.remove(), 240);
  }, ttl);
}

export interface ModalOptions {
  title: string;
  body: string;
  confirmText?: string;
  cancelText?: string;
  tone?: "primary" | "danger";
  withInput?: { placeholder: string; value?: string };
}

export function modal(opts: ModalOptions): Promise<{ ok: boolean; input: string }> {
  return new Promise((resolve) => {
    const root = document.getElementById("modal-root");
    if (!root) {
      resolve({ ok: false, input: "" });
      return;
    }
    root.innerHTML = `
      <div class="modal" role="dialog" aria-modal="true">
        <div class="modal__head">
          <span class="modal__title">${esc(opts.title)}</span>
          <button class="icon-btn" data-close aria-label="Закрыть">${icon("x", 16)}</button>
        </div>
        <div class="modal__body">
          ${opts.body}
          ${
            opts.withInput
              ? `<label class="field">
                   <span class="field__label">Путь к файлу</span>
                   <input class="input" data-input placeholder="${esc(opts.withInput.placeholder)}" value="${esc(opts.withInput.value ?? "")}" />
                 </label>`
              : ""
          }
        </div>
        <div class="modal__foot">
          <button class="btn btn--ghost" data-close>${esc(opts.cancelText ?? "Отмена")}</button>
          <button class="btn ${opts.tone === "danger" ? "btn--danger" : "btn--primary"}" data-confirm>${esc(opts.confirmText ?? "Подтвердить")}</button>
        </div>
      </div>`;
    root.classList.add("is-open");
    const input = root.querySelector<HTMLInputElement>("[data-input]");
    input?.focus();

    const finish = (ok: boolean): void => {
      root.classList.remove("is-open");
      root.innerHTML = "";
      document.removeEventListener("keydown", onKey);
      resolve({ ok, input: input?.value ?? "" });
    };
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === "Escape") finish(false);
      if (event.key === "Enter") finish(true);
    };
    document.addEventListener("keydown", onKey);
    root.querySelectorAll("[data-close]").forEach((el) => el.addEventListener("click", () => finish(false)));
    root.querySelector("[data-confirm]")?.addEventListener("click", () => finish(true));
    root.addEventListener("click", (event) => {
      if (event.target === root) finish(false);
    });
  });
}

export function badge(text: string, tone: "ok" | "warn" | "bad" | "accent" | "muted" = "muted"): string {
  return `<span class="badge badge--${tone}">${esc(text)}</span>`;
}

export function emptyState(text: string, sub = "", iconName = "activity"): string {
  return `<div class="empty">${icon(iconName, 26)}<div>${esc(text)}</div>${sub ? `<div class="dim">${esc(sub)}</div>` : ""}</div>`;
}

export function sectionTitle(title: string, sub = ""): string {
  return `<div class="section-title"><h2>${esc(title)}</h2>${sub ? `<span class="dim">${esc(sub)}</span>` : ""}</div>`;
}
