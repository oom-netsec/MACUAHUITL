// Texto que viene de fuera (equipos, respaldos, nombres) antes de mostrarlo para confirmar o de sugerirlo como archivo.

// Bidi y de ancho cero: cambian cómo se ve una línea sin cambiar sus bytes.
// También guion suave, separadores de línea, rellenos Hangul, anotación interlineal, etiquetas (contrabando ASCII) y surrogates sueltos.
const INVISIBLE = "\\u00ad\\u061c\\u115f\\u1160\\u180e\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\u3164\\ufeff\\ufff9-\\ufffb\\u{e0000}-\\u{e007f}\\p{Cs}";
const CONTROL = "\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f"; // sin \t ni \n
const HIDDEN = new RegExp(`[${CONTROL}${INVISIBLE}]`, "gu");

// Pegar en la terminal pide confirmación con saltos de línea y con cualquier otro control (Ctrl+Z, ESC…): un equipo los ejecuta igual.
export const pasteNeedsConfirm = (s: string): boolean => /[\x00-\x08\x0a-\x1f\x7f-\x9f]/.test(s);

// Vista previa del diálogo de pegar: hasta 5 líneas de 80 caracteres con lo oculto marcado, y aparte los códigos ocultos
// de todo el texto (el que motivó la pregunta puede quedar fuera de la vista previa).
export function pastePreview(text: string): { n: number; preview: string; controls: string } {
  const lines = text.replace(/[\r\n]+$/, "").split(/\r\n|\r|\n/);
  const preview = lines.slice(0, 5).map((l) => showHidden(l.length > 80 ? `${l.slice(0, 80)}…` : l)).join("\n") + (lines.length > 5 ? "\n…" : "");
  const controls = [...new Set(lines.join("").match(HIDDEN) ?? [])].map(showHidden).join(" ");
  return { n: lines.length, preview, controls };
}

// Hace visibles los controles y los caracteres invisibles: «⟦U+202E⟧».
export const showHidden = (s: string): string =>
  s.replace(HIDDEN, (c) => `⟦U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟧`);

// Nombre sugerido en el diálogo de guardar: sin carpetas, controles ni invisibles, y sin empezar con punto.
export const safeFileName = (name: string): string =>
  name.replace(new RegExp(`[/\\\\\\t\\n${CONTROL}${INVISIBLE}]`, "gu"), "_").replace(/^\.+/, "_");

// Secuencias de terminal de la salida de una herramienta: en un <pre> se verían como basura («ESC[31m»). El texto queda igual.
// CSI (7 y 8 bits, con parámetros «0-?» e intermedios), OSC/DCS/SOS/PM/APC (ESC ] P X ^ _ o C1 \x90 \x98 \x9d-\x9f) hasta BEL, ESC\ o ST (\x9c), y las de 2 o 3 bytes (ESC 7, ESC ( B).
export const stripAnsi = (s: string): string =>
  s.replace(/\x1b\[[0-?]*[ -/]*[@-~]|\x9b[0-?]*[ -/]*[@-~]|(?:\x1b[\]P_^X]|[\x90\x98\x9d-\x9f])[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)?|\x1b[ -/]*[0-~]/g, "");
