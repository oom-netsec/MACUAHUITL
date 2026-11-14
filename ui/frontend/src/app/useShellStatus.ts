import { useCallback, useEffect, useRef, useState } from "react";
import type { CoreAPI, VaultState } from "../lib/core";
import type { AssistRunInfo } from "../modules/ports/api";
import { onVaultChanged, vaultChanged } from "../lib/vaultSignal";

export interface ShellStatus {
  vault: VaultState | null;
  patrolArmed: number;
  assist: AssistRunInfo | null; // ejecución asistida viva, si hay
}

// Ejecución → módulo que la inició (la UI lo guarda al iniciar; el núcleo no lo sabe).
export const assistOwnerKey = (runId: string) => `macuahuitl.assist.${runId}`;
export function assistOwner(runId: string): string {
  try { return localStorage.getItem(assistOwnerKey(runId)) ?? ""; } catch { return ""; }
}

// Estado global de la barra de estado. Bóveda y Patrol se consultan cada 15 s y al volver a la ventana
// (llamadas baratas al núcleo); el modo asistido además se actualiza con sus eventos.
export function useShellStatus(core: CoreAPI, everyMs = 15_000): ShellStatus {
  const [s, setS] = useState<ShellStatus>({ vault: null, patrolArmed: 0, assist: null });
  const seen = useRef<VaultState | null>(null);

  const refresh = useCallback(() => {
    core.vaultStatus().then((v) => {
      // Un cambio hecho fuera de la app (mctl, cierre por tiempo) también refresca las vistas que listan credenciales.
      if (seen.current !== null && seen.current !== v.state) vaultChanged();
      seen.current = v.state;
      setS((p) => ({ ...p, vault: v.state }));
    }).catch(() => {});
    core.listJobs().then((js) => setS((p) => ({ ...p, patrolArmed: js.filter((j) => j.state === "armed" || j.state === "arming").length }))).catch(() => {});
    core.assistListRuns().then((rs) => setS((p) => ({ ...p, assist: rs.find((r) => r.active) ?? null }))).catch(() => {});
  }, [core]);

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, everyMs);
    window.addEventListener("focus", refresh);
    const offA = core.onAssist((e) => { if (e.kind === "state") refresh(); }); // no por cada línea de salida
    const offD = core.onAssistDone((e) => {
      // El dueño se borra cuando la ejecución ya no está activa en el núcleo (terminó, o el núcleo se reinició y no la tiene). Un done con
      // error con la ejecución viva es solo el corte del stream: se conserva (la vista se vuelve a enganchar). Sin respuesta, decide el error.
      const drop = () => { try { localStorage.removeItem(assistOwnerKey(e.runId)); } catch { /* sin almacenamiento */ } };
      void core.assistListRuns().then((rs) => { if (!rs.some((x) => x.runId === e.runId && x.active)) drop(); }, () => { if (!e.error) drop(); });
      refresh();
    });
    const offV = onVaultChanged(refresh);
    return () => { window.clearInterval(id); window.removeEventListener("focus", refresh); offA(); offD(); offV(); };
  }, [core, refresh, everyMs]);

  return s;
}
