import type { ITerminalOptions, ITheme } from "@xterm/xterm";
import type { Palette } from "../../lib/termHighlight";

// Paleta de la app (internal/termcolor/palettes.json) a tema de xterm: los 16 colores ANSI salen de los roles del resaltado
// (bad=rojo, ok=verde, warn=ámbar, kw=azul, addr=magenta, iface=cian) para que lo que pinte el propio equipo, o una pantalla completa,
// combine con el resto. La selección es un velo del azul de las palabras clave: se lee sobre cualquier fondo, oscuro o claro.
export function xtermTheme(p: Palette): ITheme {
  return {
    background: p.bg, foreground: p.fg, cursor: p.fg, cursorAccent: p.bg, selectionBackground: `${p.kw}55`, selectionInactiveBackground: `${p.kw}30`,
    black: p.dim, red: p.bad, green: p.ok, yellow: p.warn, blue: p.kw, magenta: p.addr, cyan: p.iface, white: p.fg,
    brightBlack: p.dim, brightRed: p.bad, brightGreen: p.ok, brightYellow: p.num, brightBlue: p.info, brightMagenta: p.str, brightCyan: p.iface, brightWhite: p.prompt,
  };
}

export const FONT = '"JetBrains Mono", ui-monospace, "DejaVu Sans Mono", monospace';
export const FONT_PROBE = '14px "JetBrains Mono"'; // fuerza la descarga de la fuente antes de medir la celda

// Aspecto de un emulador de terminal de escritorio: 14 px sin interlineado extra, cursor de bloque que parpadea y mucho historial.
export const TERM_OPTIONS: ITerminalOptions = {
  fontFamily: FONT, fontSize: 14, lineHeight: 1, letterSpacing: 0, fontWeight: "400", fontWeightBold: "700",
  cursorStyle: "block", cursorBlink: true, cursorInactiveStyle: "outline",
  scrollback: 20000, allowProposedApi: true, // el addon de búsqueda marca coincidencias con decoraciones (API propuesta)
  linkHandler: { activate: () => {} }, // un equipo no decide qué se abre: sus hipervínculos OSC 8 no navegan
  // Un equipo no decide qué se abre: los hipervínculos OSC 8 que mande no navegan ni abren nada.
};

export const MARK = { matchBackground: "#2f6f62", activeMatchBackground: "#45c9ad", matchOverviewRuler: "#2f6f62", activeMatchColorOverviewRuler: "#45c9ad" };
