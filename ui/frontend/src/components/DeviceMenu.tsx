// Menú de equipo (ADR 0009): botón ⋯ o clic derecho sobre cualquier equipo. Cada acción lleva a su módulo
// con la dirección como dato de entrada (NavContext); el módulo la recibe con useInbox.
import { useContext, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { CoreContext, NavContext } from "../app/activity";
import { useT } from "../lib/i18n";
import type { Key } from "../lib/i18n/es";

const ACTIONS: [string, Key][] = [
  ["terminal", "device.ssh"], ["console", "device.console"], ["ping", "nav.ping"], ["traceroute", "nav.traceroute"],
  ["backup", "device.backup"], ["fleet", "device.fleet"],
];

export function DeviceMenu({ name, address, children }: { name: string; address: string; children?: ReactNode }) {
  const t = useT();
  const { go } = useContext(NavContext);
  const core = useContext(CoreContext);
  const [open, setOpen] = useState(false);
  const menu = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const box = useRef<HTMLSpanElement>(null);
  const close = (focus = true) => { setOpen(false); if (focus) btn.current?.focus(); };
  useEffect(() => {
    if (!open) return;
    box.current?.querySelector<HTMLButtonElement>("[role=menuitem]")?.focus();
    const out = (e: PointerEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("pointerdown", out);
    return () => document.removeEventListener("pointerdown", out);
  }, [open]);
  const onKey = (e: React.KeyboardEvent) => {
    const items = [...(box.current?.querySelectorAll<HTMLButtonElement>("[role=menuitem]") ?? [])];
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
      {open && (
        <div className="popover menu" role="menu" id={menu} aria-label={label}>
          {ACTIONS.map(([id, k]) => <button key={id} role="menuitem" className="quiet" onClick={() => { close(false); go(id, address); }}>{t(k)}</button>)}
          <button role="menuitem" className="quiet" onClick={() => { close(); void core?.copyText(address); }}>{t("device.copyIp")}</button>
        </div>
      )}
    </span>
  );
}
