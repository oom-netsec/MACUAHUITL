import { useEffect, useId, useRef, useState } from "react";
import { Glyph } from "../components/Glyph";
import { Icon } from "../components/Icon";
import { useT } from "../lib/i18n";
import { groups, modules, type ModuleDef } from "../modules";

// Al pasar el puntero o enfocar una entrada se descarga su vista: abrirla no espera al fallback y el arranque no paga nada.
const warm = (m: ModuleDef) => { void m.view.preload().catch(() => {}); };

type Entry = { kind: "item"; mod: ModuleDef } | { kind: "group"; id: keyof typeof groups; items: ModuleDef[] };

// Arriba los módulos en el orden del registro; los de un mismo grupo se juntan donde aparece el primero.
function entries(): Entry[] {
  const out: Entry[] = [];
  for (const m of modules.filter((m) => !m.bottom)) {
    if (!m.group) { out.push({ kind: "item", mod: m }); continue; }
    const g = out.find((e) => e.kind === "group" && e.id === m.group);
    if (g?.kind === "group") g.items.push(m);
    else out.push({ kind: "group", id: m.group, items: [m] });
  }
  return out;
}

interface Props { current: string; busy: Set<string>; onSelect: (id: string) => void; collapsed: boolean; onToggle: () => void }

export function Sidebar({ current, busy, onSelect, collapsed, onToggle }: Props) {
  const t = useT();
  const [open, setOpen] = useState<string | null>(null);
  const busyId = useId();
  const select = (id: string) => { setOpen(null); onSelect(id); };
  return (
    <aside className="sidebar">
      <div className="brand"><Glyph size={20} /><span>MACUAHUITL</span></div>
      <span id={busyId} hidden>{t("shell.busy")}</span>
      <nav aria-label={t("shell.sections")}>
        <ul>
          {entries().map((e) =>
            e.kind === "item"
              ? <li key={e.mod.id}><Item mod={e.mod} current={current} busy={busy} busyId={busyId} onSelect={select} /></li>
              : <li key={e.id}><Group id={e.id} items={e.items} current={current} busy={busy} busyId={busyId} open={open === e.id} setOpen={setOpen} onSelect={select} /></li>,
          )}
        </ul>
        <ul className="bottom">
          {modules.filter((m) => m.bottom).map((m) => <li key={m.id}><Item mod={m} current={current} busy={busy} busyId={busyId} onSelect={select} /></li>)}
        </ul>
      </nav>
      <button className="nav-item sidebar-toggle" aria-label={t("shell.sidebar.collapse")} aria-expanded={!collapsed} onClick={onToggle}>
        <Icon name="sidebar" />
      </button>
    </aside>
  );
}

type ItemProps = { mod: ModuleDef; current: string; busy: Set<string>; busyId: string; onSelect: (id: string) => void };

function Item({ mod, current, busy, busyId, onSelect }: ItemProps) {
  const t = useT();
  const on = busy.has(mod.id);
  return (
    <button className="nav-item" aria-current={current === mod.id ? "page" : undefined} aria-describedby={on ? busyId : undefined} onClick={() => onSelect(mod.id)}
      onPointerEnter={() => warm(mod)} onFocus={() => warm(mod)}>
      {mod.icon && <Icon name={mod.icon} />}
      <span className="nav-label">{t(mod.label)}</span>
      {on && <span className="busy" aria-hidden="true" />}
    </button>
  );
}

type GroupProps = Omit<ItemProps, "mod"> & { id: keyof typeof groups; items: ModuleDef[]; open: boolean; setOpen: (f: (o: string | null) => string | null) => void };

function Group({ id, items, current, busy, busyId, open, setOpen, onSelect }: GroupProps) {
  const t = useT();
  const label = t(groups[id].label);
  const icon = groups[id].icon;
  const wrap = useRef<HTMLDivElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const timer = useRef<number | undefined>(undefined);
  const focusFirst = useRef(false);
  const panelId = useId();
  const active = items.find((m) => m.id === current);
  const anyBusy = items.some((m) => busy.has(m.id));

  const show = () => { window.clearTimeout(timer.current); setOpen(() => id); };
  const close = () => setOpen((o) => (o === id ? null : o));
  // Pequeña espera al salir: cruzar el hueco entre la barra y el panel no lo cierra.
  const hideSoon = () => { timer.current = window.setTimeout(close, 180); };
  useEffect(() => () => window.clearTimeout(timer.current), []);

  useEffect(() => {
    if (!open) return;
    if (focusFirst.current) { panel.current?.querySelector("button")?.focus(); focusFirst.current = false; }
    const outside = (e: PointerEvent) => { if (!wrap.current?.contains(e.target as Node)) close(); };
    document.addEventListener("pointerdown", outside);
    return () => document.removeEventListener("pointerdown", outside);
  }, [open]);

  const onButtonKey = (e: React.KeyboardEvent) => {
    if (e.key !== "ArrowRight") return;
    e.preventDefault();
    focusFirst.current = true;
    if (open) panel.current?.querySelector("button")?.focus();
    else show();
  };
  const onPanelKey = (e: React.KeyboardEvent) => {
    const btns = [...(panel.current?.querySelectorAll("button") ?? [])];
    const i = btns.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      btns[(i + (e.key === "ArrowDown" ? 1 : -1) + btns.length) % btns.length]?.focus();
    } else if (e.key === "Escape" || e.key === "ArrowLeft") {
      e.preventDefault();
      close();
      btn.current?.focus();
    }
  };

  return (
    <div ref={wrap} className="nav-group" onMouseEnter={() => { show(); items.forEach(warm); }} onMouseLeave={hideSoon}
      onBlur={(e) => { if (!wrap.current?.contains(e.relatedTarget as Node)) close(); }}>
      <button ref={btn} className="nav-item" aria-expanded={open} aria-controls={open ? panelId : undefined}
        aria-current={active ? "page" : undefined} aria-describedby={anyBusy ? busyId : undefined}
        onClick={show} onKeyDown={onButtonKey}>
        <Icon name={icon} />
        <span className="nav-label">{label}{active && <> <small>{t(active.label)}</small></>}</span>
        {anyBusy && <span className="busy" aria-hidden="true" />}
        <span className="chev"><Icon name="chevron" size={14} /></span>
      </button>
      {open && (
        <div ref={panel} id={panelId} className="flyout" role="group" aria-label={label} onKeyDown={onPanelKey}>
          {items.map((m) => (
            <button key={m.id} className="flyout-item" aria-current={current === m.id ? "page" : undefined}
              aria-describedby={busy.has(m.id) ? busyId : undefined} onClick={() => onSelect(m.id)} onFocus={() => warm(m)}>
              {t(m.label)}
              {busy.has(m.id) && <span className="busy" aria-hidden="true" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
