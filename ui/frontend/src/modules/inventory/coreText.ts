import { useLang, useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";

// El núcleo contesta siempre en español. En español se muestra su texto tal cual; en inglés, un texto traducido genérico
// (cuando el núcleo entregue reason/metadata, fase 30a, se vuelve detallado en los dos idiomas).
export function useCoreText() {
  const lang = useLang();
  const t = useT();
  return (core: string, generic: Key) => (lang === "es" ? core : t(generic));
}

// Avisos de la vista previa que la vista conoce por su texto; el resto cae en el genérico.
export function knownWarning(w: string): "nosum" | "cred" | "" {
  if (/suma de verificaci[oó]n/i.test(w)) return "nosum";
  if (/credencial/i.test(w)) return "cred";
  return "";
}
