/// <reference types="vite/client" />
// Guardia estática: el texto que viene de equipos o del núcleo solo se muestra como nodos de texto de React.
// Ninguna fuente de la app (sin pruebas) puede construir HTML a mano ni apuntar href/src a algo dinámico sin estar justificada aquí.
const sources = import.meta.glob<string>(["../**/*.{ts,tsx}", "!../**/*.test.{ts,tsx}", "!../test-*.ts", "!../**/gen/**"], { query: "?raw", import: "default", eager: true });

const HTML_SINKS = /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML|insertAdjacentHTML|document\.write\b/;
export const findSinks = (src: string) => src.split("\n").flatMap((l, i) => (HTML_SINKS.test(l) ? [`${i + 1}: ${l.trim()}`] : []));

// href=/src= con valor dinámico ({…}); la lista blanca dice por qué cada uno es seguro.
const DYNAMIC_URL = /\b(?:href|src)=\{/;
export const findDynamicUrls = (src: string) => src.split("\n").flatMap((l, i) => (DYNAMIC_URL.test(l) ? [`${i + 1}: ${l.trim()}`] : []));
const ALLOWED: [file: string, fragment: string, why: string][] = [
  ["modules/visibility/VisibilityView.tsx", "src={svgURL}", "SVG de topología como <img src=data:…>: en una imagen no corren scripts ni se cargan recursos externos"],
  ["modules/fleet/FleetView.tsx", 'src={"data:image/svg+xml;charset=utf-8," + encodeURIComponent(', "ídem: URI data: armada aquí con encodeURIComponent, nunca una URL del equipo"],
];

test("la guardia detecta lo que debe (si falla, la guardia no sirve)", () => {
  expect(findSinks("<div dangerouslySetInnerHTML={{ __html: x }} />").length).toBe(1);
  for (const s of ["el.innerHTML = x", "el.outerHTML", "el.insertAdjacentHTML('a', x)", "document.write(x)"]) expect(findSinks(s), s).toHaveLength(1);
  expect(findDynamicUrls("<a href={u}>x</a>")).toHaveLength(1);
  expect(findDynamicUrls('<img src={"data:" + x} />')).toHaveLength(1);
  expect(findDynamicUrls('<a href="https://x">x</a>')).toHaveLength(0);
});

test("ninguna fuente arma HTML a mano", () => {
  expect(Object.keys(sources).length).toBeGreaterThan(100);
  expect(Object.entries(sources).flatMap(([f, s]) => findSinks(s).map((x) => `${f}:${x}`))).toEqual([]);
});

test("href y src dinámicos: solo los de la lista blanca", () => {
  const found = Object.entries(sources).flatMap(([f, s]) => findDynamicUrls(s).map((x) => ({ f: f.replace("../", ""), x })));
  const bad = found.filter(({ f, x }) => !ALLOWED.some(([af, frag]) => f === af && x.includes(frag)));
  expect(bad).toEqual([]);
  // Cada permiso de la lista sigue usándose: si el código cambia, se revisa la excepción en vez de dejarla suelta.
  for (const [af, frag, why] of ALLOWED) expect(found.some(({ f, x }) => f === af && x.includes(frag)), why).toBe(true);
});
