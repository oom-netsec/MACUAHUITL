import { useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { useT } from "../lib/i18n";

// Opciones con valor por defecto: cerradas, salvo que haya un error de campo dentro (forceOpen).
// forceOpen puede ser un contador de intentos: cada intento fallido vuelve a abrir aunque el usuario lo haya cerrado.
// Se abre en el DOM en un efecto de diseño, antes de los useEffect del padre: así el foco al campo inválido ya lo encuentra
// visible (WebKit no enfoca dentro de un details cerrado).
// changed dice en el summary cuántas se apartan del valor por defecto, para no enviar a ciegas algo que no se ve.
export function Advanced({ children, label, forceOpen, changed = 0 }: { children: ReactNode; label?: string; forceOpen?: boolean | number; changed?: number }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDetailsElement>(null);
  useLayoutEffect(() => {
    if (!forceOpen) return;
    if (ref.current) ref.current.open = true;
    setOpen(true);
  }, [forceOpen]);
  const base = label ?? t("common.advanced");
  return (
    <details ref={ref} className="adv" open={open} onToggle={(e) => setOpen(e.currentTarget.open)}>
      {/* forceOpen booleano = hay un error ahora mismo dentro: el summary lo dice, por si el usuario lo cierra (el botón sigue bloqueado). */}
      <summary>{changed > 0 ? t("common.advanced.changed", { label: base, n: changed }) : base}{forceOpen === true && <span className="adv-error"> · {t("common.advanced.error")}</span>}</summary>
      {children}
    </details>
  );
}
