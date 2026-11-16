/** Общие типы для экранов. */

import type { AppStore, Route } from "../core/store";
import type { ScanReport } from "../core/api";

export interface ViewContext {
  store: AppStore;
  navigate: (route: Route) => void;
  runScan: () => Promise<ScanReport | null>;
  search: () => string;
}

export interface View {
  el: HTMLElement;
  update?: () => void;
  refresh?: () => void;
  destroy?: () => void;
}
