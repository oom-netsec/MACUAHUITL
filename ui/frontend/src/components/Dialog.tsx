import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useT } from "../lib/i18n";

// Diálogo modal accesible: role="dialog" + aria-modal con título asociado, el foco entra en él, Escape y «cerrar» lo cierran y el foco
// vuelve a quien lo abrió. Va en un portal al <body> y el resto de la página queda inert (no recibe foco ni clics) mientras está abierto.
export function Dialog({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const t = useT();
  const id = useId();
  const close = useRef<HTMLButtonElement>(null);
  const scrim = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    // Escape se escucha en window (fase de captura): funciona aunque el foco haya quedado en <body> tras un clic en el texto o un Tab.
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); onCloseRef.current(); } };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, []);
  useEffect(() => {
    const back = document.activeElement as HTMLElement | null;
    const others = [...document.body.children].filter((e): e is HTMLElement => e instanceof HTMLElement && e !== scrim.current && !e.inert);
    others.forEach((e) => { e.inert = true; });
    close.current?.focus();
    return () => { others.forEach((e) => { e.inert = false; }); back?.focus?.(); };
  }, []);
  return createPortal(
    <div ref={scrim} className="scrim dialog-scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby={id} tabIndex={-1}>
        <div className="panel-head">
          <h3 id={id}>{title}</h3>
          <div className="panel-actions"><button ref={close} type="button" className="quiet sm" onClick={onClose}>{t("dialog.close")}</button></div>
        </div>
        <div className="dialog-body">{children}</div>
      </div>
    </div>,
    document.body,
  );
}

// Botón «Ver detalles» con su diálogo: lo largo de una tarjeta (tablas, notas) vive detrás de él.
export function DetailsButton({ label, title, children }: { label: string; title: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="quiet" aria-haspopup="dialog" aria-label={`${label} · ${title}`} onClick={() => setOpen(true)}>{label}</button>
      {open && <Dialog title={title} onClose={() => setOpen(false)}>{children}</Dialog>}
    </>
  );
}
