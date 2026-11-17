import type { ReactNode } from "react";
import { EmptyState, ResultPanel } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { useT } from "../../lib/i18n";

export const list = (s: string) => s.split(/[\s,;]+/).filter(Boolean);

// Salida de una prueba: sin ejecutar muestra qué hacer primero; después, el panel con el texto o el error del núcleo.
// bare: los hijos arman sus propios paneles (tarjetas); el error sigue saliendo en el panel de salida.
export function Outcome({ r, empty, bare, children }: { r: { busy: boolean; data: unknown; error: string }; empty?: string; bare?: boolean; children: ReactNode }) {
  const t = useT();
  if (r.busy) return null;
  if (!r.data && !r.error) return empty ? <EmptyState icon="shield" title={t("security.empty.title")}>{empty}</EmptyState> : null;
  if (bare && r.data) return <>{children}</>;
  return <ResultPanel title={t("common.output")} error={r.error}>{children}</ResultPanel>;
}

// Salida cruda cuando el texto no tiene la forma de un informe del núcleo.
export function Raw({ text }: { text: string }) {
  const t = useT();
  return <ResultPanel title={t("common.output")}><Terminal text={text} aria-label={t("common.output")} /></ResultPanel>;
}

// Resultado de una prueba: el informe estructurado y, si no lo hay o llega sin texto (doble de pruebas), el texto de siempre.
// Un error del informe NO cae al texto: repetiría la prueba contra el servidor (dos intentos de autenticación).
export interface Probe<R> { text: string; report?: R }
export async function probe<A, R extends { text: string }>(report: ((a: A) => Promise<R>) | undefined, plain: (a: A) => Promise<string>, arg: A): Promise<Probe<R>> {
  const rep = report && await report(arg);
  return rep?.text ? { text: rep.text, report: rep } : { text: await plain(arg) };
}

export const kbd = <kbd aria-hidden="true">Ctrl ↵</kbd>;
