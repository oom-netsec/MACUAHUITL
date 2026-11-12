import { useEffect, useRef, useState } from "react";
import { observeElementRect, useVirtualizer } from "@tanstack/react-virtual";
import type { CoreAPI } from "../../lib/core";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { DeviceMenu } from "../../components/DeviceMenu";
import { Meter, Sparkline } from "../../components/charts/Mini";

export interface Row { state: string; progress: string; detail: string }

// Grilla en vivo por equipo (spec §12.3). Virtualizada: con miles de equipos solo se dibuja lo visible.
// "10.0.0.1:22" -> "10.0.0.1": la dirección que usan el menú de equipo y las métricas.
export const addressOf = (target: string) => target.replace(/:\d+$/, "");

// cpu: CPU de 1 min por ronda, por dirección (de las métricas del trabajo).
export function DeviceGrid({ core, jobId, devices, initial, cpu }: { core: CoreAPI; jobId: string; devices: string[]; initial?: Record<string, Row>; cpu?: Record<string, number[]> }) {
  const t = useT();
  const label = (s: string) => (s.startsWith("DEVICE_STATE_") ? t(`device.${s.slice(13)}` as Key) : s);
  const [rows, setRows] = useState<Record<string, Row>>(initial ?? {});
  const [beat, setBeat] = useState<string>("");
  useEffect(
    () =>
      core.onEvent((e) => {
        if (e.jobId !== jobId) return;
        if (e.heartbeat) setBeat(new Date().toLocaleTimeString());
        const d = e.deviceStateChanged ?? e.commandProgress;
        if (!d) return;
        setRows((r) => {
          const cur = r[d.deviceId] ?? { state: "DEVICE_STATE_QUEUED", progress: "", detail: "" };
          const next = e.deviceStateChanged
            ? { ...cur, state: e.deviceStateChanged.state, detail: e.deviceStateChanged.detail ?? "" }
            : { ...cur, state: "DEVICE_STATE_RUNNING", progress: `${e.commandProgress!.index ?? 0}/${e.commandProgress!.total ?? 0} ${e.commandProgress!.command}` };
          return { ...r, [d.deviceId]: next };
        });
      }),
    [core, jobId],
  );
  const parent = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: devices.length, getScrollElement: () => parent.current, estimateSize: () => 32, overscan: 8,
    initialRect: { width: 900, height: 480 },
    // Un contenedor sin medir (oculto o en pruebas) mide 0: se usa su alto fijo.
    observeElementRect: (inst, cb) => observeElementRect(inst, (r) => cb(r.height ? r : { width: r.width || 900, height: 480 })),
  });
  const items = v.getVirtualItems();
  return (
    <div className="device-grid">
      {beat && <p className="meta" aria-live="polite">{t("patrol.grid.heartbeat", { time: beat })}</p>}
      <div ref={parent} className="grid-scroll">
        <table className="grid" aria-rowcount={devices.length + 1}>
          <thead><tr><th>{t("patrol.grid.device")}</th><th>{t("patrol.grid.state")}</th><th>{t("patrol.grid.cpu")}</th><th>{t("patrol.grid.progress")}</th><th>{t("patrol.grid.detail")}</th></tr></thead>
          <tbody style={{ height: v.getTotalSize() }}>
            {items.map((it) => {
              const dev = devices[it.index];
              const r = rows[dev] ?? { state: "DEVICE_STATE_QUEUED", progress: "", detail: "" };
              return (
                <tr key={dev} aria-rowindex={it.index + 2} data-state={r.state}
                  style={{ transform: `translateY(${it.start}px)` }}>
                  <td className="mono"><DeviceMenu name={dev} address={addressOf(dev)}>{dev}</DeviceMenu></td>
                  <td>{label(r.state)}</td>
                  <td>{cpuCell(cpu?.[addressOf(dev)], t("patrol.grid.cpuLabel", { device: addressOf(dev) }))}</td>
                  <td className="mono">{r.progress}</td>
                  <td>{r.detail}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function cpuCell(v: number[] | undefined, label: string) {
  if (!v?.length) return <span className="meta">—</span>;
  return <span className="cpu-cell"><Sparkline values={v} label={label} unit="%" width={64} height={20} /><Meter value={v[v.length - 1]} warn={60} crit={80} label={label} unit="%" /></span>;
}
