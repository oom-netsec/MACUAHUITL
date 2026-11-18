import { useEffect, useState, type ReactNode } from "react";
import { useT } from "../lib/i18n";

// Opciones con valor por defecto: cerradas, salvo que haya un error de campo dentro (forceOpen).
// changed dice en el summary cuántas se apartan del valor por defecto, para no enviar a ciegas algo que no se ve.
export function Advanced({ children, label, forceOpen, changed = 0 }: { children: ReactNode; label?: string; forceOpen?: boolean; changed?: number }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  useEffect(() => { if (forceOpen) setOpen(true); }, [forceOpen]);
  const base = label ?? t("common.advanced");
  return (
    <details className="adv" open={open} onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary>{changed > 0 ? t("common.advanced.changed", { label: base, n: changed }) : base}</summary>
      {children}
    </details>
  );
}
