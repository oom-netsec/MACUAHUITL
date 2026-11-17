// Vitest procesa los .css y ?raw sale vacío: se leen como texto desde disco (sin @types/node, de ahí el ts-expect-error).
// @ts-expect-error node:fs sin tipos en este proyecto
import { readFileSync } from "node:fs";

const read = (n: string): string => readFileSync(`src/styles/${n}.css`, "utf8");
const base = read("base"), components = read("components"), shell = read("shell");

// Cuerpo del bloque @media (forced-colors: active) de un archivo (hasta la llave que lo cierra).
function forced(css: string): string {
  const i = css.indexOf("@media (forced-colors: active)");
  if (i < 0) return "";
  let depth = 0;
  for (let j = css.indexOf("{", i); j < css.length; j++) {
    if (css[j] === "{") depth++;
    if (css[j] === "}" && --depth === 0) return css.slice(i, j);
  }
  return "";
}

test("alto contraste de Windows: casilla, radio, punto del radio y segmented usan colores del sistema", () => {
  const b = forced(base);
  expect(b).toContain('input[type="checkbox"]:checked');
  expect(b).toContain('input[type="radio"]:checked');
  expect(b).toContain('input[type="radio"]::after');
  expect(b).toMatch(/Highlight\b/);
  expect(b).toContain("HighlightText");
  expect(b).toContain("forced-color-adjust: none");
  expect(b).toMatch(/:focus-visible[^}]*Highlight/);
  const c = forced(components);
  expect(c).toContain(".segmented input:checked + span");
  expect(c).toContain('.tabs [role="tab"][aria-selected="true"]');
  const s = forced(shell);
  expect(s).toContain('.nav-item[aria-current="page"]');
  expect(s).toContain('.palette-item[aria-selected="true"]');
});

test("las flechas de input[type=number] se ocultan igual en WebKitGTK y Chromium", () => {
  expect(base).toMatch(/input\[type="number"\]::-webkit-inner-spin-button[^{]*::-webkit-outer-spin-button\s*\{[^}]*appearance: none;[^}]*margin: 0/);
  expect(base).toMatch(/input\[type="number"\]\s*\{[^}]*appearance: textfield/);
});

test("las barras de desplazamiento tienen la variante ::-webkit-scrollbar con los mismos selectores acotados", () => {
  expect(base).toMatch(/\.content::-webkit-scrollbar/);
  expect(base).not.toMatch(/(^|\n)\*::-webkit-scrollbar/);
  // scrollbar-width/color anulan ::-webkit-scrollbar en WebKitGTK y no se aplican: no deben volver.
  expect(base).not.toMatch(/scrollbar-(width|color):/);
});
