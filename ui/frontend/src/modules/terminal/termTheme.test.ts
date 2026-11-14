import { PALETTES } from "../../lib/termHighlight";
import { TERM_OPTIONS, xtermTheme } from "./termTheme";

describe.each(PALETTES.map((p) => [p.id, p] as const))("xtermTheme %s", (_id, p) => {
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
