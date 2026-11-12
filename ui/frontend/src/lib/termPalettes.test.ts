import { PALETTES } from "./termHighlight";

// Las paletas tiñen fondo y texto (fósforo, ámbar…), pero cada rol del resaltado debe conservar su tono propio:
// si no, "up" y "down" o una IP y una interfaz se ven del mismo color y el resaltado no sirve.
const ROLES = ["bad", "num", "warn", "ok", "iface", "kw", "info", "addr", "str"] as const;
const MIN_HUE = 20; // grados de separación entre roles
const MIN_SAT = 0.35;

const rgb = (hex: string) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
function lum(hex: string) {
  const [r, g, b] = rgb(hex).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
const ratio = (a: string, b: string) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
function hs(hex: string) {
  const [r, g, b] = rgb(hex);
  const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
  const l = (mx + mn) / 2;
  const s = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));
  let h = 0;
  if (d) h = mx === r ? ((g - b) / d) % 6 : mx === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return { h: (h * 60 + 360) % 360, s };
}
const gap = (a: number, b: number) => { const d = Math.abs(a - b) % 360; return Math.min(d, 360 - d); };

describe.each(PALETTES.map((p) => [p.id, p] as const))("paleta %s", (_id, p) => {
  const c = p as unknown as Record<string, string>;

  test("los roles del resaltado tienen tonos distintos entre sí", () => {
    for (const a of ROLES) {
      expect(hs(c[a]).s, `${a} sin color`).toBeGreaterThanOrEqual(MIN_SAT);
      for (const b of ROLES) if (a < b) expect(gap(hs(c[a]).h, hs(c[b]).h), `${a} vs ${b}`).toBeGreaterThanOrEqual(MIN_HUE);
    }
  });

  test("error rojo, aviso ámbar, ok verde, interfaz cian, dirección magenta, palabra clave azul", () => {
    const near = (role: string, hue: number, tol: number) => expect(gap(hs(c[role]).h, hue), role).toBeLessThanOrEqual(tol);
    near("bad", 0, 20); near("warn", 48, 20); near("ok", 135, 30); near("iface", 184, 25); near("addr", 300, 30); near("kw", 218, 25);
  });

  test("todos los colores se leen sobre el fondo (≥ 4.5:1)", () => {
    for (const k of Object.keys(c)) if (/^#[0-9a-f]{6}$/i.test(c[k]) && k !== "bg") expect(ratio(c[k], c.bg), k).toBeGreaterThanOrEqual(4.5);
  });
});
