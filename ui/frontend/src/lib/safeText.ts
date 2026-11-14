// Texto que viene de fuera (equipos, respaldos, nombres) antes de mostrarlo para confirmar o de sugerirlo como archivo.

// Bidi y de ancho cero: cambian cómo se ve una línea sin cambiar sus bytes.
const INVISIBLE = "؜​-‏‪-‮⁠-⁩﻿";
const CONTROL = "\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f"; // sin \t ni \n
const HIDDEN = new RegExp(`[${CONTROL}${INVISIBLE}]`, "gu");

// Pegar en la terminal pide confirmación con saltos de línea y con cualquier otro control (Ctrl+Z, ESC…): un equipo los ejecuta igual.
export const pasteNeedsConfirm = (s: string): boolean => /[\x00-\x08\x0a-\x1f\x7f-\x9f]/.test(s);

// Hace visibles los controles y los caracteres invisibles: «⟦U+202E⟧».
export const showHidden = (s: string): string =>
  s.replace(HIDDEN, (c) => `⟦U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟧`);

// Nombre sugerido en el diálogo de guardar: sin carpetas, controles ni invisibles, y sin empezar con punto.
export const safeFileName = (name: string): string =>
  name.replace(new RegExp(`[/\\\\\\t\\n${CONTROL}${INVISIBLE}]`, "gu"), "_").replace(/^\.+/, "_");
