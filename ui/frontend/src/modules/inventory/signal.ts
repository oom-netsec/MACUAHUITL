import { useSyncExternalStore } from "react";

// Aviso de que la libreta de hosts cambió (alta, edición, borrado o import). La terminal SSH ofrece los hosts en su
// formulario y, al estar montada aunque oculta, necesita enterarse para no mostrar una lista vieja.
let version = 0;
const subs = new Set<() => void>();

export function hostsChanged() {
  version++;
  subs.forEach((f) => f());
}

const on = (f: () => void) => (subs.add(f), () => { subs.delete(f); });

export function useHostsVersion(): number {
  return useSyncExternalStore(on, () => version);
}
