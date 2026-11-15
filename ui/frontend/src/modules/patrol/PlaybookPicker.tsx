import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Icon } from "../../components/Icon";
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
  const packLabel = (pack: string) => (pack === "usuario" ? t("patrol.pb.own") : pack === "" ? t("patrol.pb.base") : pack);
  const groups = useMemo(() => {
    const words = norm(q).split(/\s+/).filter(Boolean);
    const hit = (p: PlaybookInfo) => { const hay = norm([p.name, p.id, packLabel(p.pack), ...p.commands].join(" ")); return words.every((w) => hay.includes(w)); };
    const m = new Map<string, PlaybookInfo[]>();
    playbooks.filter(hit).forEach((p) => m.set(areaOf(p.name), [...(m.get(areaOf(p.name)) ?? []), p]));
    return [...m].sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b, undefined, { numeric: true })));
  }, [playbooks, q, t]);
  // Lo que la persona abrió o cerró a mano; una búsqueda nueva lo olvida y vuelve la regla por omisión.
  const [manual, setManual] = useState<{ q: string; v: Record<string, boolean> }>({ q: "", v: {} });
  const open = (area: string, list: PlaybookInfo[]) => (manual.q === q ? manual.v[area] : undefined) ?? (q.trim() !== "" || list.some((p) => selected.includes(p.id)));
  const setOpen = (area: string, v: boolean) => setManual((m) => ({ q, v: { ...(m.q === q ? m.v : {}), [area]: v } }));
  // Elegir o quitar fija el estado visible para que el grupo no se pliegue bajo los dedos al vaciarlo.
  const toggle = (area: string, id: string) => { setOpen(area, true); onChange(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id].sort()); };
  const toggleGroup = (area: string, list: PlaybookInfo[]) => {
    const ids = list.map((p) => p.id);
    setOpen(area, true);
    onChange(ids.every((id) => selected.includes(id)) ? selected.filter((x) => !ids.includes(x)) : [...new Set([...selected, ...ids])].sort());
  };
  return (
    <div className="pb-picker">
      <div className="field-row end">
        <Field label={t("patrol.pb.search")} type="search" value={q} onChange={setQ} w="lg" />
        <p className="hint count pb-count" aria-live="polite">{t("patrol.pb.selected", { n: selected.length })}</p>
      </div>
      {groups.length === 0 && <p className="empty">{t("patrol.pb.none")}</p>}
      {groups.map(([area, list]) => (
        <Group key={area} name={area || t("patrol.pb.other")} list={list} selected={selected} open={open(area, list)}
          onOpen={(v) => setOpen(area, v)} onAll={() => toggleGroup(area, list)}>
          {list.map((p) => (
            <div key={p.id} className="pb-item">
              <Check label={topicOf(p.name)} checked={selected.includes(p.id)} onChange={() => toggle(area, p.id)} />
              <span className="meta">{packLabel(p.pack)}</span>
              <details>
                <summary className="meta">{t("patrol.pb.cmds", { n: p.commands.length })}<span className="sr"> · {p.name}</span></summary>
                <ul className="mono pb-cmds">{p.commands.map((c) => <li key={c}>{c}</li>)}</ul>
              </details>
            </div>
          ))}
        </Group>
      ))}
    </div>
  );
}

// Grupo plegable: botón de plegado (aria-expanded) y, aparte, la casilla que elige o quita lo visible del grupo.
function Group({ name, list, selected, open, onOpen, onAll, children }: { name: string; list: PlaybookInfo[]; selected: string[]; open: boolean; onOpen: (v: boolean) => void; onAll: () => void; children: React.ReactNode }) {
  const t = useT();
  const bodyId = useId();
  const box = useRef<HTMLInputElement>(null);
  const n = list.filter((p) => selected.includes(p.id)).length;
  useEffect(() => { if (box.current) box.current.indeterminate = n > 0 && n < list.length; }, [n, list.length]);
  return (
    <div className="pb-group" role="group" aria-labelledby={`${bodyId}-h`}>
      <div className="pb-head">
        <input ref={box} type="checkbox" checked={n === list.length} aria-label={t("patrol.pb.selectAll", { group: name })} onChange={onAll} />
        <button type="button" id={`${bodyId}-h`} className="pb-toggle" aria-expanded={open} aria-controls={bodyId} onClick={() => onOpen(!open)}>
          <Icon name="chevron" size={14} />
          <span className="pb-name">{name}</span>
          <span className="meta">{t("patrol.pb.groupCount", { n, total: list.length })}</span>
        </button>
      </div>
      {open && <div id={bodyId}>{children}</div>}
    </div>
  );
}
