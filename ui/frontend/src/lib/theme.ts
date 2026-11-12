import { useSyncExternalStore } from "react";

// Tema compartido: el selector, la paleta de comandos y la barra de estado ven y cambian el mismo valor.
export type Theme = "system" | "light" | "dark";
const key = "macuahuitl.tema";
const subs = new Set<() => void>();

// El almacenamiento puede fallar (perfil de solo lectura); entonces se sigue al sistema.
function stored(): Theme {
  try {
    const v = localStorage.getItem(key);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

let current: Theme = stored();
apply(current);

function apply(t: Theme) {
  const root = document.documentElement;
  if (t === "system") delete root.dataset.theme;
  else root.dataset.theme = t;
}

export function setTheme(t: Theme) {
  current = t;
  apply(t);
  try { localStorage.setItem(key, t); } catch { /* sin persistencia */ }
  subs.forEach((f) => f());
}

// Solo para pruebas: vuelve a leer lo guardado.
export function resetTheme() { current = stored(); apply(current); subs.forEach((f) => f()); }

export function useTheme(): Theme {
  return useSyncExternalStore((f) => (subs.add(f), () => subs.delete(f)), () => current);
}
