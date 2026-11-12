// Resaltado de palabras clave sobre la salida viva del terminal (xterm): convierte las categorías de
// termHighlight en color ANSI de primer plano (… 39), sin tocar fondo ni atributos.
// Los roles con ranura ANSI propia se escriben por índice: el tema de xterm los resuelve, así que al cambiar `options.theme`
// xterm repinta también lo ya escrito (historial incluido). El resto lleva el RGB de la paleta (24 bits): la paleta
// extendida de xterm (16-255) no se toca porque equipos Linux usan esos índices con sus propios colores.
import { classify, type Palette } from "./termHighlight";

// Ranura de cada rol (la misma que llena xtermTheme): rojo 31, verde 32, amarillo 33, azul 34, magenta 35, cian 36,
// brillantes 93 (num), 94 (info), 95 (str), 97 (prompt), 90 (dim) y blanco 37 (uprompt: el fg del tema, legible en claro y oscuro).
const SLOT: Record<string, number> = { bad: 31, ok: 32, warn: 33, kw: 34, addr: 35, iface: 36, num: 93, info: 94, str: 95, prompt: 97, dim: 90, uprompt: 37 };
const rgb = (hex: string) => `38;2;${parseInt(hex.slice(1, 3), 16)};${parseInt(hex.slice(3, 5), 16)};${parseInt(hex.slice(5, 7), 16)}`;
const color = (cat: string, p: Palette) => { const hex = (p as unknown as Record<string, string>)[cat]; const c = SLOT[cat] ?? (hex && rgb(hex)); return c ? `\x1b[${c}m` : ""; };
// El prompt y el --More-- van en negrita (SGR 1 … 22), como en las terminales de escritorio; el resto solo cambia el color.
const BOLD = new Set(["prompt", "uprompt"]);
const paint = (cat: string, text: string, p: Palette) => (BOLD.has(cat) ? `\x1b[1m${color(cat, p)}${text}\x1b[39m\x1b[22m` : `${color(cat, p)}${text}\x1b[39m`);

function colorLine(line: string, p: Palette): string {
  if (line.includes("\x1b")) return line; // el equipo ya la coloreó o es una pantalla completa
  const cr = line.endsWith("\r") ? "\r" : "";
  const body = cr ? line.slice(0, -1) : line;
  const spans = classify(body);
  if (spans.length === 0) return line;
  let out = ""; let pos = 0;
  for (const s of spans) {
    if (!color(s.cat, p)) continue; // sin color en esta paleta: se deja como está
    out += body.slice(pos, s.start) + paint(s.cat, body.slice(s.start, s.end), p);
    pos = s.end;
  }
  return out + body.slice(pos) + cr;
}

/** Línea parcial al inicio de renglón (prompt que espera tecleo, --More--): solo se pinta lo que empieza en la columna 0. */
export function ansiPrompt(text: string, p: Palette): string {
  if (!text || text.includes("\x1b")) return text;
  const s = classify(text).find((x) => x.start === 0 && (x.cat === "prompt" || x.cat === "uprompt"));
  return s && color(s.cat, p) ? paint(s.cat, text.slice(0, s.end), p) + text.slice(s.end) : text;
}

/** Colorea las líneas completas (terminadas en \n) de `text`; la parcial del final queda igual. */
export function ansiHighlight(text: string, p: Palette): string {
  const i = text.lastIndexOf("\n");
  if (i < 0) return text;
  return text.slice(0, i).split("\n").map((l) => colorLine(l, p)).join("\n") + text.slice(i);
}

export const HOLD_MS = 40;

/**
 * Escritor de una sesión: lo que llega del equipo pasa por aquí antes de xterm.
 * - Sin salto de línea (eco de teclas, prompt): se escribe al instante.
 * - Con salto de línea: las líneas completas se escriben ya, resaltadas; la parcial final se retiene hasta HOLD_MS
 *   o el siguiente chunk, para que una línea partida entre chunks también se resalte.
 * `palette()` devuelve null con el resaltado apagado.
 */
export function createLiveWriter(write: (d: string) => void, palette: () => Palette | null) {
  let held = "";
  let bol = true; // lo último escrito cerró un renglón: lo que llegue sin \n es un prompt o un --More--
  let timer: ReturnType<typeof setTimeout> | undefined;
  const out = (s: string, partial: boolean) => { const p = partial && bol ? palette() : null; write(p ? ansiPrompt(s, p) : s); bol = s.endsWith("\n"); };
  const release = () => { clearTimeout(timer); timer = undefined; if (held) { const h = held; held = ""; out(h, true); } };
  return {
    push(chunk: string) {
      const p = palette();
      if (!p) { release(); out(chunk, false); return; }
      const all = held + chunk;
      const i = all.lastIndexOf("\n");
      if (i < 0) { if (!held) { out(chunk, true); return; } held = all; return; } // sigue el plazo del primer retenido
      held = all.slice(i + 1);
      clearTimeout(timer); timer = undefined;
      out(ansiHighlight(all.slice(0, i + 1), p), false);
      if (held) timer = setTimeout(release, HOLD_MS);
    },
    flush: release,
    dispose: release,
  };
}
