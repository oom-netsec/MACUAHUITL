// Camino entre dos equipos como cadena horizontal: equipo → interfaz (VLAN, siguiente salto, switches L2) → equipo.
// Es una lista ordenada por ruta, así que se lee igual con lector de pantalla.
import { StatusPill } from "../../components/Data";
import { useT } from "../../lib/i18n";
import type { PathHop } from "./api";
import { chains, linkLabel } from "./pathChain";

export function HopChain({ hops }: { hops: PathHop[] }) {
  const t = useT();
  const all = chains(hops);
  return (
    <div className="hop-chains">
      {all.map((c, n) => (
        <div key={n}>
          {all.length > 1 && <p className="hint hop-route">{t("fleet.chain.route", { n: n + 1, total: all.length })}</p>}
          <ol className="hop-chain" aria-label={all.length > 1 ? `${t("fleet.chain.title")} · ${t("fleet.chain.route", { n: n + 1, total: all.length })}` : t("fleet.chain.title")}>
            {c.map((h, i) => {
              const l = i > 0 ? linkLabel(h) : null;
              const bits = l ? [l.iface, l.vlan && t("fleet.chain.vlan", { v: l.vlan }), l.via && t("fleet.chain.next", { ip: l.via }), ...l.l2.map((sw) => t("fleet.chain.l2", { sw }))].filter(Boolean) : [];
              return (
                <li key={h.id} data-status={h.status}>
                  {l && (
                    <span className="hop-link">
                      <span className="hop-label mono">{bits.map((b, k) => <span key={k}>{k > 0 && <span className="sr"> · </span>}{b}</span>)}</span>
                      <span className="hop-arrow" aria-hidden="true">⟶</span>
                    </span>
                  )}
                  <span className="hop-node">
                    <strong className="mono">{h.device}</strong>
                    {h.status === "arrived" && <StatusPill tone="ok" label={t("fleet.chain.arrived")} />}
                    {h.status === "cut" && <StatusPill tone="bad" label={t("fleet.chain.cut")} />}
                    {h.status === "cut" && h.reason && <span className="hint">{h.reason}</span>}
                  </span>
                </li>
              );
            })}
          </ol>
        </div>
      ))}
    </div>
  );
}
