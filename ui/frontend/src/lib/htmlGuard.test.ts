/// <reference types="vite/client" />
// Guardia estática: el texto que viene de equipos o del núcleo solo se muestra como nodos de texto de React.
// Ninguna fuente de la app (sin pruebas) puede construir HTML o código a mano, navegar ni apuntar href/src a algo dinámico sin estar justificada aquí.
// Recorre .ts/.tsx/.js/.jsx de src y las páginas HTML de la raíz (index.html, preview.html).
const sources = import.meta.glob<string>(
  ["../**/*.{ts,tsx,js,jsx}", "../../*.html", "!../**/*.test.{ts,tsx,js,jsx}", "!../test-*.ts", "!../**/gen/**"],
  { query: "?raw", import: "default", eager: true },
);

// Cualquier mención se revisa a mano: es más seguro que intentar entender el contexto.
export const HTML_SINKS = new RegExp([
  String.raw`dangerouslySetInnerHTML`, String.raw`\b(?:inner|outer)HTML\b`, String.raw`insertAdjacentHTML`, String.raw`document\.write`,
  String.raw`setHTMLUnsafe`, String.raw`createContextualFragment`, String.raw`parseFromString`, String.raw`srcdoc`, String.raw`<iframe`,
  String.raw`\beval\(`, String.raw`new\s+Function\b`, String.raw`window\.open`, String.raw`\blocation\.(?:assign|replace|href)\b`,
  String.raw`setAttribute\(\s*["'\x60](?:href|src|xlink:href|on)`,
].join("|"), "i");
export const findSinks = (src: string) => src.split("\n").flatMap((l, i) => (HTML_SINKS.test(l) ? [`${i + 1}: ${l.trim()}`] : []));

// Atributos de URL con valor dinámico ({…}) y asignaciones .href/.src. «action» y «data» solo cuentan en <form> y <object>/<embed>:
// en un componente (action={<button/>}, data={() => …}) son props de la app, no URLs.
export const DYNAMIC_URL = new RegExp([
  String.raw`\b(?:href|src|srcSet|xlinkHref|poster|formAction)\s*=\s*\{`,
  String.raw`<form\b[^>]*\baction\s*=\s*\{`, String.raw`<(?:object|embed)\b[^>]*\bdata\s*=\s*\{`,
  String.raw`\.(?:href|src)\s*=[^=]`,
].join("|"));
export const findDynamicUrls = (src: string) => src.split("\n").flatMap((l, i) => (DYNAMIC_URL.test(l) ? [`${i + 1}: ${l.trim()}`] : []));
const ALLOWED: [file: string, fragment: string, why: string][] = [
  ["modules/visibility/VisibilityView.tsx", "src={svgURL}", "SVG de topología como <img src=data:…>: en una imagen no corren scripts ni se cargan recursos externos"],
  ["modules/fleet/FleetView.tsx", 'src={"data:image/svg+xml;charset=utf-8," + encodeURIComponent(', "ídem: URI data: armada aquí con encodeURIComponent, nunca una URL del equipo"],
  ["modules/transfer/client.ts", "e.src = ", "«e» es el objeto de errores del formulario (clave «src»), no un elemento del DOM"],
];

test("la guardia detecta cada variante (si falla, la guardia no sirve)", () => {
  for (const s of [
    "<div dangerouslySetInnerHTML={{ __html: x }} />", "el.innerHTML = x", "x.outerHTML", "el.insertAdjacentHTML('a', x)", "document.write(x)", "document.write (x)",
    "el.setHTMLUnsafe(x)", "range.createContextualFragment(x)", "new DOMParser().parseFromString(x, 'text/html')", "<iframe srcDoc={x} />", "f.srcdoc = x", "<IFRAME src=a>",
    "eval(x)", "new Function('a', x)", "window.open(u)", "location.assign(u)", "location.replace(u)", "location.href = u", "el.setAttribute('href', u)",
    'el.setAttribute("src", u)', "el.setAttribute(`onclick`, u)", 'el.setAttribute("onerror", u)',
  ]) expect(findSinks(s), s).toHaveLength(1);
  for (const s of ["const x = a.location.search", "e.setAttribute('aria-label', l)", "evaluate(x)", "{ text: 'ok' }"]) expect(findSinks(s), s).toHaveLength(0);
  for (const s of [
    "<a href={u}>x</a>", '<img src={"data:" + x} />', "<img srcSet={s} />", "<use xlinkHref={h} />", "<video poster={p} />", "<button formAction={a} />",
    "<form method='post' action={u}>", "<object data={u} />", "<embed data={u} />", "a.href = u", "img.src = u", "a.href=u",
  ]) expect(findDynamicUrls(s), s).toHaveLength(1);
  for (const s of ['<a href="https://x">x</a>', "<Empty action={<button />} />", "<Download data={() => d} />", "if (a.href === u)", "x.srcs = 1"]) expect(findDynamicUrls(s), s).toHaveLength(0);
});

test("las páginas HTML y los .js/.jsx entran en el recorrido", () => {
  const names = Object.keys(sources);
  expect(names.length).toBeGreaterThan(100);
  expect(names.some((n) => n.endsWith("/index.html"))).toBe(true);
  expect(names.some((n) => n.endsWith("/preview.html"))).toBe(true);
});

test("ninguna fuente arma HTML o código a mano ni navega", () => {
  expect(Object.entries(sources).flatMap(([f, s]) => findSinks(s).map((x) => `${f}:${x}`))).toEqual([]);
});

test("href y src dinámicos: solo los de la lista blanca", () => {
  const found = Object.entries(sources).flatMap(([f, s]) => findDynamicUrls(s).map((x) => ({ f: f.replace("../", ""), x })));
  const bad = found.filter(({ f, x }) => !ALLOWED.some(([af, frag]) => f === af && x.includes(frag)));
  expect(bad).toEqual([]);
  // Cada permiso de la lista sigue usándose: si el código cambia, se revisa la excepción en vez de dejarla suelta.
  for (const [af, frag, why] of ALLOWED) expect(found.some(({ f, x }) => f === af && x.includes(frag)), why).toBe(true);
});
