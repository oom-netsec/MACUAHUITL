import { PALETTES } from "../../lib/termHighlight";
import { xtermTheme } from "./termTheme";

describe.each(PALETTES.map((p) => [p.id, p] as const))("xtermTheme %s", (_id, p) => {
  test("las ranuras ANSI salen de los roles de la paleta y no toca la paleta extendida (16-255)", () => {
    const t = xtermTheme(p);
    expect(t).toMatchObject({ red: p.bad, green: p.ok, yellow: p.warn, blue: p.kw, magenta: p.addr, cyan: p.iface, white: p.fg, brightYellow: p.num, brightBlue: p.info, brightMagenta: p.str, brightWhite: p.prompt, brightBlack: p.dim });
    expect(t.extendedAnsi).toBeUndefined();
  });
});
