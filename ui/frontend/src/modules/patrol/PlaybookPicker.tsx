import { useMemo, useState } from "react";
import { Check, Field } from "../../components/Field";
import { useT } from "../../lib/i18n";
import type { PlaybookInfo } from "./api";

const norm = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
// "L2 · STP" → área "L2"; sin «·» va a "Otros" (el grupo lo nombra la vista).
const areaOf = (name: string) => (name.includes("·") ? name.split("·")[0].trim() : "");
// Dentro de su grupo basta el tema: "L2 · STP" se muestra "STP" bajo "L2".
const topicOf = (name: string) => (name.includes("·") ? name.slice(name.indexOf("·") + 1).trim() : name);

// Selector del catálogo: búsqueda por nombre, id o comando, grupos por área y los comandos a la vista antes de elegir.
// Un elegido que la búsqueda oculta sigue elegido; el resumen dice cuántos van.
export function PlaybookPicker({ playbooks, selected, onChange }: { playbooks: PlaybookInfo[]; selected: string[]; onChange: (ids: string[]) => void }) {
  const t = useT();
  const [q, setQ] = useState("");
  const groups = useMemo(() => {
    const words = norm(q).split(/\s+/).filter(Boolean);
    const hit = (p: PlaybookInfo) => { const hay = norm([p.name, p.id, ...p.commands].join(" ")); return words.every((w) => hay.includes(w)); };
    const m = new Map<string, PlaybookInfo[]>();
    playbooks.filter(hit).forEach((p) => m.set(areaOf(p.name), [...(m.get(areaOf(p.name)) ?? []), p]));
    return [...m].sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b, undefined, { numeric: true })));
  }, [playbooks, q]);
  const toggle = (id: string) => onChange(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id].sort());
  return (
    <div className="pb-picker">
      <div className="field-row end">
        <Field label={t("patrol.pb.search")} type="search" value={q} onChange={setQ} w="lg" />
        <p className="hint count pb-count" aria-live="polite">{t("patrol.pb.selected", { n: selected.length })}</p>
      </div>
      {groups.length === 0 && <p className="empty">{t("patrol.pb.none")}</p>}
      {groups.map(([area, list]) => (
        <fieldset key={area} className="pb-group">
          <legend>{area || t("patrol.pb.other")}</legend>
          {list.map((p) => (
            <div key={p.id} className="pb-item">
              <Check label={topicOf(p.name)} checked={selected.includes(p.id)} onChange={() => toggle(p.id)} />
              <details>
                <summary className="meta">{t("patrol.pb.cmds", { n: p.commands.length })}<span className="sr"> · {p.name}</span></summary>
                <ul className="mono pb-cmds">{p.commands.map((c) => <li key={c}>{c}</li>)}</ul>
              </details>
            </div>
          ))}
        </fieldset>
      ))}
    </div>
  );
}
