import { useSyncExternalStore } from "react";

// Aviso de que los scripts cambiaron (favorito, alta, edición, borrado o import). La terminal SSH lista los favoritos
// en sus comandos rápidos y, al estar montada aunque oculta, necesita enterarse para no mostrar una lista vieja.
let version = 0;
const subs = new Set<() => void>();

export function scriptsChanged() {
  version++;
  subs.forEach((f) => f());
}

const on = (f: () => void) => (subs.add(f), () => { subs.delete(f); });

export function useScriptsVersion(): number {
  return useSyncExternalStore(on, () => version);
}
