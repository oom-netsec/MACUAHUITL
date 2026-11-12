// Menú de equipo (ADR 0009): botón ⋯ o clic derecho sobre cualquier equipo. Cada acción lleva a su módulo
// con la dirección como dato de entrada (NavContext); el módulo la recibe con useInbox.
import { createPortal } from "react-dom";
import { useContext, useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { CoreContext, NavContext } from "../app/activity";
import { useT } from "../lib/i18n";
import type { Key } from "../lib/i18n/es";

const ACTIONS: [string, Key][] = [
  ["terminal", "device.ssh"], ["console", "device.console"], ["ping", "nav.ping"], ["traceroute", "nav.traceroute"],
  ["backup", "device.backup"], ["fleet", "device.fleet"],
];

// Menú en el body con posición fija (ni el scroll ni el transform de las filas virtuales lo recortan o desplazan): abajo del botón, o arriba si no cabe.
// (no la recorta ningún contenedor con scroll): abajo del botón, o arriba si abajo no cabe.
export function placeMenu(r: { top: number; bottom: number; left: number }, h: number, vh: number, vw: number, w = 180) {
  const below = r.bottom + 4, up = r.top - 4 - h;
  const top = below + h <= vh - 4 || up < 4 ? Math.max(4, Math.min(below, vh - h - 4)) : up;
  return { top, left: Math.max(4, Math.min(r.left, vw - w - 4)) };
}

export function DeviceMenu({ name, address, children }: { name: string; address: string; children?: ReactNode }) {
  const t = useT();
  const { go } = useContext(NavContext);
  const core = useContext(CoreContext);
  const [open, setOpen] = useState(false);
  const menu = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const box = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number }>();
  const pop = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (!open || !btn.current || !pop.current) return;
    const place = () => btn.current && pop.current && setPos(placeMenu(btn.current.getBoundingClientRect(), pop.current.offsetHeight, window.innerHeight, window.innerWidth, pop.current.offsetWidth));
    place(); // el menú sigue a su botón si algo se desplaza o cambia el tamaño
    window.addEventListener("resize", place);
    document.addEventListener("scroll", place, true);
    return () => { window.removeEventListener("resize", place); document.removeEventListener("scroll", place, true); };
  }, [open]);
  const close = (focus = true) => { setOpen(false); if (focus) btn.current?.focus(); };
  useEffect(() => {
    if (!open) return;
    pop.current?.querySelector<HTMLButtonElement>("[role=menuitem]")?.focus({ preventScroll: true });
    const out = (e: PointerEvent) => { if (!box.current?.contains(e.target as Node) && !pop.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("pointerdown", out);
    return () => document.removeEventListener("pointerdown", out);
  }, [open]);
  const onKey = (e: React.KeyboardEvent) => {
    const items = [...(pop.current?.querySelectorAll<HTMLButtonElement>("[role=menuitem]") ?? [])];
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); items[(i + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length]?.focus(); }
    else if (e.key === "Escape") { e.preventDefault(); close(); }
  };
  const label = t("device.actions", { name });
  return (
    <span className="device-menu" ref={box} onKeyDown={onKey} onContextMenu={(e) => { e.preventDefault(); setOpen(true); }}>
      {children}
      <button ref={btn} type="button" className="quiet icon sm" aria-label={label} aria-haspopup="menu" aria-expanded={open}
        aria-controls={open ? menu : undefined} onClick={() => setOpen((o) => !o)}>⋯</button>
      {open && createPortal(
        <div ref={pop} className="popover menu fixed" style={pos} role="menu" id={menu} aria-label={label}>
          {ACTIONS.map(([id, k]) => <button key={id} role="menuitem" className="quiet" onClick={() => { close(false); go(id, address); }}>{t(k)}</button>)}
          <button role="menuitem" className="quiet" onClick={() => { close(); void core?.copyText(address); }}>{t("device.copyIp")}</button>
        </div>, document.body)}
    </span>
  );
}
