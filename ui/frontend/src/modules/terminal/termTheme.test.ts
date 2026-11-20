import { PALETTES } from "../../lib/termHighlight";
import { DEFAULT_PALETTE } from "../../lib/termHighlight";
import { FONT, TERM_OPTIONS, xtermTheme } from "./termTheme";

describe.each(PALETTES.filter((p) => !p.ansi).map((p) => [p.id, p] as const))("xtermTheme %s", (_id, p) => {
  test("las ranuras ANSI salen de los roles de la paleta y no toca la paleta extendida (16-255)", () => {
    const t = xtermTheme(p);
    expect(t).toMatchObject({ red: p.bad, green: p.ok, yellow: p.warn, blue: p.kw, magenta: p.addr, cyan: p.iface, white: p.fg, brightYellow: p.num, brightBlue: p.info, brightMagenta: p.str, brightWhite: p.prompt, brightBlack: p.dim });
    expect(t.extendedAnsi).toBeUndefined();
  });
});

test("los hipervínculos OSC 8 de un equipo no abren nada", () => {
  const open = vi.spyOn(window, "open").mockImplementation(() => null);
  expect(TERM_OPTIONS.linkHandler).toBeTruthy();
  TERM_OPTIONS.linkHandler!.activate(new MouseEvent("click"), "https://ejemplo.invalido", { start: { x: 1, y: 1 }, end: { x: 2, y: 1 } });
  expect(open).not.toHaveBeenCalled();
  open.mockRestore();
});

test("una paleta con ansi explícito lo usa tal cual, con su selección", () => {
  const p = PALETTES.find((x) => x.id === "tokyonight")!;
  const t = xtermTheme(p);
  expect(t).toMatchObject({ background: "#1a1b26", foreground: "#c0caf5", cursor: "#c0caf5", selectionBackground: "#33467c", black: "#15161e", red: "#f7768e", white: "#a9b1d6", brightBlack: "#414868", brightWhite: "#c0caf5" });
  expect(xtermTheme({ ...p, ansi: undefined, selection: undefined })).toMatchObject({ red: p.bad, selectionBackground: `${p.kw}55` });
});

test("la paleta predeterminada es Tokyo Night", () => {
  expect(DEFAULT_PALETTE).toBe("tokyonight");
});

test("la fuente cae a la de símbolos Nerd Font tras JetBrains Mono, con cursor de barra", () => {
  expect(FONT.indexOf('"JetBrains Mono"')).toBeGreaterThanOrEqual(0);
  expect(FONT.indexOf('"Symbols Nerd Font Mono"')).toBeGreaterThan(FONT.indexOf('"JetBrains Mono"'));
  expect(TERM_OPTIONS).toMatchObject({ cursorStyle: "bar", cursorBlink: true, lineHeight: 1.2, fontSize: 16 });
});
