import type { ReactNode } from "react";
import { Notice } from "./Field";
import { CopyButton } from "./Data";
import { useT } from "../lib/i18n";

// Página de releases donde están los .mpack oficiales. Solo se muestra y se copia: la app nunca descarga nada.
export const RELEASES_URL = "https://github.com/oom-netsec/MACUAHUITL/releases/latest";

// Instalación nueva sin paquetes de contenido (Patrol y Ajustes → Paquetes): qué falta y dónde conseguirlo.
export function NoPacks({ text, action }: { text?: string; action?: ReactNode }) {
  const t = useT();
  return (
    <Notice kind="info">
      {text ?? t("packs.none")} <span className="mono url">{RELEASES_URL}</span> <CopyButton value={RELEASES_URL} label={t("packs.none.link")} /> {action}
    </Notice>
  );
}
