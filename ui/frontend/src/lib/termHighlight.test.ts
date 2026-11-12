import cases from "../../../../internal/termcolor/cases.json";
import { CATEGORIES, PALETTES, classify } from "./termHighlight";

// Los mismos casos que prueba Go (internal/termcolor/termcolor_test.go).
test.each(cases)("clasifica: $line", ({ line, spans }) => {
  expect(classify(line).map((s) => [line.slice(s.start, s.end), s.cat])).toEqual(spans);
});

function lum(hex: string) {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
const ratio = (a: string, b: string) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

test("cada paleta define todas las categorías con contraste AA sobre su fondo", () => {
  expect(PALETTES.length).toBeGreaterThanOrEqual(5);
  for (const p of PALETTES) {
    for (const c of ["fg", ...CATEGORIES] as const) {
      expect(p[c as keyof typeof p], `${p.id}.${c}`).toBeTruthy();
      expect(ratio(p[c as keyof typeof p] as string, p.bg), `${p.id}.${c}`).toBeGreaterThanOrEqual(4.5);
    }
  }
});

test("una línea gigante no se analiza", () => {
  expect(classify("up ".repeat(5000))).toEqual([]);
});
