import type { ITerminalOptions, ITheme } from "@xterm/xterm";
import type { Palette } from "../../lib/termHighlight";

// Paleta de la app (internal/termcolor/palettes.json) a tema de xterm: los 16 colores ANSI salen de los roles del resaltado
// (bad=rojo, ok=verde, warn=ámbar, kw=azul, addr=magenta, iface=cian) para que lo que pinte el propio equipo, o una pantalla completa,
// combine con el resto. La selección es un velo del azul de las palabras clave: se lee sobre cualquier fondo, oscuro o claro.
// Si la paleta trae "ansi" (16 colores) y "selection", se usan tal cual.
export function xtermTheme(p: Palette): ITheme {
  const a = p.ansi;
  if (a?.length === 16) {
    return {
      background: p.bg, foreground: p.fg, cursor: p.fg, cursorAccent: p.bg, selectionBackground: p.selection ?? `${p.kw}55`, selectionInactiveBackground: `${p.selection ?? p.kw}80`,
      black: a[0], red: a[1], green: a[2], yellow: a[3], blue: a[4], magenta: a[5], cyan: a[6], white: a[7],
      brightBlack: a[8], brightRed: a[9], brightGreen: a[10], brightYellow: a[11], brightBlue: a[12], brightMagenta: a[13], brightCyan: a[14], brightWhite: a[15],
    };
  }
  return {
    background: p.bg, foreground: p.fg, cursor: p.fg, cursorAccent: p.bg, selectionBackground: `${p.kw}55`, selectionInactiveBackground: `${p.kw}30`,
    black: p.dim, red: p.bad, green: p.ok, yellow: p.warn, blue: p.kw, magenta: p.addr, cyan: p.iface, white: p.fg,
    brightBlack: p.dim, brightRed: p.bad, brightGreen: p.ok, brightYellow: p.num, brightBlue: p.info, brightMagenta: p.str, brightCyan: p.iface, brightWhite: p.prompt,
  };
}

export const FONT = '"JetBrains Mono", "Symbols Nerd Font Mono", ui-monospace, "DejaVu Sans Mono", monospace';
// Fuerzan la descarga de las fuentes antes de medir la celda; el glifo de prueba cae en el rango de la fuente de símbolos (U+F315, Raspberry Pi).
export const FONT_PROBES: [string, string][] = [['16px "JetBrains Mono"', "A"], ['16px "Symbols Nerd Font Mono"', "\uF315"]];

// Aspecto del Ghostty del dueño: 12 pt (= 16 px CSS), interlineado 1.2, cursor de barra que parpadea y mucho historial.
export const TERM_OPTIONS: ITerminalOptions = {
  fontFamily: FONT, fontSize: 16, lineHeight: 1.2, letterSpacing: 0, fontWeight: "400", fontWeightBold: "700",
  cursorStyle: "bar", cursorBlink: true, cursorInactiveStyle: "outline",
  scrollback: 20000, allowProposedApi: true, // el addon de búsqueda marca coincidencias con decoraciones (API propuesta)
  linkHandler: { activate: () => {} }, // un equipo no decide qué se abre: sus hipervínculos OSC 8 no navegan
  // Un equipo no decide qué se abre: los hipervínculos OSC 8 que mande no navegan ni abren nada.
};

export const MARK = { matchBackground: "#2f6f62", activeMatchBackground: "#45c9ad", matchOverviewRuler: "#2f6f62", activeMatchColorOverviewRuler: "#45c9ad" };
