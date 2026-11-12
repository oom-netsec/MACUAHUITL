import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { FrontPort } from "./api";

const STATUSES: FrontPort["status"][] = ["connected", "notconnect", "disabled", "err-disabled", "monitoring"];
// Marca dentro del puerto que no es de acceso: T de troncal, L3 de enrutado (el nombre accesible lo dice completo).
const MARK: Record<string, string> = { trunk: "T", routed: "L3", channel: "Po" };
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
// "Gi1/0/14" -> "Gi1/0": los puertos de un mismo módulo y tipo van juntos.
const groupOf = (name: string) => name.replace(/\/?\d+$/, "");

// Frente del switch: un botón por puerto, coloreado por estado y con la VLAN dentro. Pares abajo, impares arriba, como el equipo.
export function FrontPanel({ ports, selected, onToggle }: { ports: FrontPort[]; selected: Set<string>; onToggle: (name: string) => void }) {
  const t = useT();
  const groups = new Map<string, FrontPort[]>();
  [...ports].sort((a, b) => a.module - b.module || a.slot - b.slot || a.name.localeCompare(b.name, undefined, { numeric: true }))
    .forEach((p) => groups.set(groupOf(p.name), [...(groups.get(groupOf(p.name)) ?? []), p]));
  const status = (s: FrontPort["status"]) => t(`ports.status.${s}` as Key);
  const count = (s: FrontPort["status"]) => ports.filter((p) => p.status === s).length;
  return (
    <div className="front-panel">
      <div className="port-groups" role="group" aria-label={t("ports.panel.label")}>
        {[...groups].map(([g, list]) => (
          <div key={g} className="port-group">
            <span className="port-group-name mono">{g}</span>
            <div className="port-grid">
              {list.map((p) => {
                const access = p.mode === "access";
                const tip = [p.description, p.channel, `${p.speed} ${p.duplex}`.trim(), p.type, p.poeWatts ? `PoE ${p.poeWatts} W` : ""].filter(Boolean).join(" · ");
                return (
                  <button key={p.name} type="button" className="port" data-status={p.status} aria-pressed={selected.has(p.name)} disabled={!access}
                    aria-label={t(`ports.panel.name.${p.mode}` as Key, { name: p.name, status: status(p.status), vlan: p.vlan, channel: p.channel ?? "" })}
                    title={access ? tip : `${tip}${tip ? " · " : ""}${t("ports.panel.fixed")}`} onClick={() => onToggle(p.name)}>
                    <span className="port-no" aria-hidden="true">{p.port}</span>
                    <span className="port-vlan" aria-hidden="true">{access ? p.vlan : MARK[p.mode]}</span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
      <ul className="port-legend" aria-label={t("ports.legend")}>
        {STATUSES.map((s) => (
          <li key={s}><span className="port-swatch" data-status={s} aria-hidden="true" />{t("ports.legend.item", { status: cap(status(s)), n: count(s) })}</li>
        ))}
      </ul>
    </div>
  );
}
