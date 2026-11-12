// Flapping por interfaz como carriles: una fila por interfaz y un tramo por cambio de estado, en orden. Lo que el informe trae
// son los primeros estados y la hora del primero y del último; por eso los tramos no van a escala de tiempo. La tabla de abajo es el equivalente en texto.
import { useT } from "../../lib/i18n";
import type { FlapRow } from "./api";
import "./forensic.css";

const W = 288, H = 22;

export function FlapLanes({ flaps }: { flaps: FlapRow[] }) {
  const t = useT();
  return (
    <div className="flap-lanes">
      <p className="hint">{t("forensic.flap.lanes.hint")}</p>
      <ul aria-label={t("forensic.flap.lanes")}>
        {flaps.map((f) => {
          const states = f.sequence.split(/\s+/).filter(Boolean);
          const w = W / Math.max(1, states.length);
          return (
            <li key={`${f.host}|${f.interface}|${f.layer}`}>
              <span className="lane-name mono">{f.host ? `${f.host} ` : ""}{f.interface}</span>
              <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={t("forensic.flap.lane.aria", { ifc: f.interface, seq: f.sequence })}>
                {states.map((s, i) => {
                  const up = s === "up";
                  return (
                    <g key={i} data-state={up ? "up" : "down"}>
                      <rect x={i * w + 1} y={1} width={Math.max(1, w - 2)} height={H - 2} rx={3} />
                      <text x={i * w + w / 2} y={H / 2 + 4} textAnchor="middle">{up ? "▲" : "▼"}</text>
                    </g>
                  );
                })}
              </svg>
              <span className="lane-range hint">{f.no_time || !f.first ? t("forensic.flap.noTime") : t("forensic.flap.lane.range", { a: new Date(f.first).toLocaleTimeString(), b: new Date(f.last ?? f.first).toLocaleTimeString() })}</span>
            </li>
          );
        })}
      </ul>
      <p className="hint lane-legend"><span className="mono">▲</span> {t("forensic.flap.lane.up")} · <span className="mono">▼</span> {t("forensic.flap.lane.down")}</p>
    </div>
  );
}
