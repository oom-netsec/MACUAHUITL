import { useEffect, useId, useMemo, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field } from "../../components/Field";
import { useT } from "../../lib/i18n";
import type { Host } from "./api";
import { groupByFolder } from "./hostForm";
import { addrPort } from "../../lib/targets";
import { useHostsVersion } from "./signal";

const norm = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();

// La libreta de hosts, al día cuando cambia.
export function useHosts(core: CoreAPI): Host[] {
  const hv = useHostsVersion();
  const [hosts, setHosts] = useState<Host[]>([]);
  useEffect(() => {
    let live = true;
    core.listHosts().then((l) => { if (live) setHosts(l); }, () => { if (live) setHosts([]); });
    return () => { live = false; };
  }, [core, hv]);
  return hosts;
}

// Elegir un host de la libreta (búsqueda + lista agrupada por carpeta) para rellenar equipo y credencial. Escribir a mano sigue valiendo.
// hosts: la lista ya cargada por quien lo usa (evita pedirla dos veces); filter: oculta los que no sirven a esa vista.
export function HostPicker({ core, hosts, filter, onPick, disabled }: { core: CoreAPI; hosts?: Host[]; filter?: (h: Host) => boolean; onPick: (h: Host) => void; disabled?: boolean }) {
  return hosts ? <HostList hosts={hosts} filter={filter} onPick={onPick} disabled={disabled} /> : <Loaded core={core} filter={filter} onPick={onPick} disabled={disabled} />;
}

function Loaded({ core, filter, onPick, disabled }: { core: CoreAPI; filter?: (h: Host) => boolean; onPick: (h: Host) => void; disabled?: boolean }) {
  return <HostList hosts={useHosts(core)} filter={filter} onPick={onPick} disabled={disabled} />;
}

function HostList({ hosts: all, filter, onPick, disabled }: { hosts: Host[]; filter?: (h: Host) => boolean; onPick: (h: Host) => void; disabled?: boolean }) {
  const t = useT();
  const id = useId();
  const hosts = useMemo(() => (filter ? all.filter(filter) : all), [all, filter]);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(""); // el host elegido ("" = ninguno): el select muestra lo elegido y no un valor fijo
  useEffect(() => { setSel((s) => (hosts.some((h) => h.id === s) ? s : "")); }, [hosts]);
  const groups = useMemo(() => {
    const s = norm(q.trim());
    return groupByFolder(hosts.filter((h) => !s || norm([h.name, h.address, h.folder, ...h.tags].join("\n")).includes(s)));
  }, [hosts, q]);
  if (hosts.length === 0) return null;
  return (
    <div className="host-pick field-row">
      <Field label={t("hosts.pick.search")} value={q} onChange={setQ} w="md" />
      <div className="field" data-w="lg">
        <label htmlFor={id}>{t("hosts.pick.label")}</label>
        <select id={id} aria-describedby={`${id}-h`} value={sel} disabled={disabled} onChange={(e) => { setSel(e.target.value); const h = hosts.find((x) => x.id === e.target.value); if (h) onPick(h); }}>
          <option value="">{t("hosts.pick.none")}</option>
          {groups.map(([folder, list]) => (
            <optgroup key={folder || "\0"} label={folder || t("hosts.folder.none")}>
              {list.map((h) => <option key={h.id} value={h.id}>{h.name} · {addrPort(h)}{h.protocol === "telnet" ? " · Telnet" : ""}</option>)}
            </optgroup>
          ))}
        </select>
        <p id={`${id}-h`} className="hint">{t("hosts.pick.hint")}</p>
      </div>
    </div>
  );
}
