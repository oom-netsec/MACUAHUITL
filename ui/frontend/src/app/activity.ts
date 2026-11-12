import type { CoreAPI } from "../lib/core";
import { createContext, useContext, useEffect } from "react";

// Cada módulo avisa a la barra lateral si tiene algo corriendo (ping, syslog…).
export const BusyContext = createContext<(busy: boolean) => void>(() => {});

export function useBusy(busy: boolean) {
  const set = useContext(BusyContext);
  useEffect(() => {
    set(busy);
    return () => set(false);
  }, [busy, set]);
}

// Un módulo puede abrir otro y dejarle un dato (p. ej. Captura → PCAP con la ruta del archivo).
// `n` cambia en cada envío, así que mandar la misma ruta dos veces también se recibe.
export type Delivery = { data: string; n: number };
// `channel` entrega el dato en otro buzón del módulo destino (p. ej. «terminal-insert» para texto sin Enter); por omisión, el del propio módulo.
export const NavContext = createContext<{ go: (id: string, data?: string, channel?: string) => void; inbox: Record<string, Delivery> }>({ go: () => {}, inbox: {} });

export const useNav = () => useContext(NavContext).go;

export function useInbox(id: string, receive: (data: string) => void) {
  const d = useContext(NavContext).inbox[id];
  // Solo reacciona a una entrega nueva, no a cada render del receptor.
  useEffect(() => { if (d) receive(d.data); }, [d]);
}

// Id del módulo que contiene a un componente (p. ej. para recordar qué módulo inició una ejecución asistida).
export const ModuleIdContext = createContext("");

// Servicios del núcleo para los componentes compartidos (copiar, guardar, elegir archivo) sin pasar `core` por props.
export const CoreContext = createContext<CoreAPI | null>(null);
