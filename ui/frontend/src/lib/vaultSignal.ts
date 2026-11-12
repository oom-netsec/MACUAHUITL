import { useSyncExternalStore } from "react";

// Aviso de que la bóveda cambió (creada, abierta, cerrada, credencial agregada o borrada). Las vistas que listan
// credenciales lo ponen en las dependencias de su carga; sin esto, una vista abierta antes conserva la lista vieja.
let version = 0;
const subs = new Set<() => void>();

export function vaultChanged() {
  version++;
  subs.forEach((f) => f());
}

export const onVaultChanged = (f: () => void) => (subs.add(f), () => { subs.delete(f); });

export function useVaultVersion(): number {
  return useSyncExternalStore(onVaultChanged, () => version);
}
