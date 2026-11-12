// Preferencia de color de las terminales. La fuente de verdad es el núcleo
// (Get/SetPreference); localStorage solo es caché de arranque para evitar parpadeo.
import { useSyncExternalStore } from "react";
import type { CoreAPI } from "./core";
import { DEFAULT_PALETTE, PALETTES } from "./termHighlight";

export interface TermPrefs { palette: string; hl: boolean; srm: boolean }
const KEY = "terminal";
const DEFAULTS: TermPrefs = { palette: DEFAULT_PALETTE, hl: true, srm: false };

// Ids con que se guardaron algunas paletas antes de renombrarlas (igual que legacyIDs en internal/termcolor).
const LEGACY_IDS: Record<string, string> = { "securecrt-dark": "consola-oscura", "securecrt-light": "consola-clara" };

export function parsePrefs(v: string | null | undefined): TermPrefs {
  try {
    const o = JSON.parse(v ?? "");
    o.palette = LEGACY_IDS[o.palette] ?? o.palette;
    return { palette: PALETTES.some((p) => p.id === o.palette) ? o.palette : DEFAULTS.palette, hl: typeof o.hl === "boolean" ? o.hl : DEFAULTS.hl, srm: typeof o.srm === "boolean" ? o.srm : DEFAULTS.srm };
  } catch {
    return DEFAULTS;
  }
}

function cached(): TermPrefs {
  try { return parsePrefs(localStorage.getItem("macuahuitl.terminal")); } catch { return DEFAULTS; }
}

let state = cached();
let touched = false; // el usuario ya eligió algo: la respuesta tardía del núcleo no lo pisa
let backend: Pick<CoreAPI, "getPreference" | "setPreference"> | undefined;
const subs = new Set<() => void>();
const publish = (s: TermPrefs) => { state = s; subs.forEach((f) => f()); };

/** Conecta el núcleo y carga la preferencia guardada (llamar una vez al arrancar). */
export async function setTermBackend(core: Pick<CoreAPI, "getPreference" | "setPreference">) {
  backend = core;
  try {
    const v = await core.getPreference(KEY);
    if (v && !touched) {
      publish(parsePrefs(v));
      try { localStorage.setItem("macuahuitl.terminal", v); } catch { /* sin caché */ }
    }
  } catch { /* sin núcleo: se queda la caché */ }
}

export function setTermPrefs(patch: Partial<TermPrefs>) {
  touched = true;
  const next = parsePrefs(JSON.stringify({ ...state, ...patch }));
  publish(next);
  const v = JSON.stringify(next);
  try { localStorage.setItem("macuahuitl.terminal", v); } catch { /* sin caché */ }
  backend?.setPreference(KEY, v).catch(() => {});
}

/** Solo para pruebas: simula un reinicio de la app. */
export function resetTermPrefs() { backend = undefined; touched = false; publish(cached()); }

export function useTermPrefs(): TermPrefs {
  return useSyncExternalStore((f) => (subs.add(f), () => subs.delete(f)), () => state);
}
