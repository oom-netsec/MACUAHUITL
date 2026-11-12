import html from "../index.html?raw";

// La CSP de index.html es estricta y así se queda: nada en línea ni de fuera. La terminal dibuja con WebGL
// precisamente para no necesitar estilos en línea (ver modules/terminal/XTermPane.tsx).
const csp = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1] ?? "";
const directive = (name: string) => csp.split(";").map((d) => d.trim()).find((d) => d.startsWith(`${name} `)) ?? "";

test("la CSP no permite nada en línea ni de fuera: estilos, scripts, red e imágenes solo de la app", () => {
  expect(directive("default-src")).toBe("default-src 'self'");
  expect(directive("script-src")).toBe("script-src 'self'");
  expect(directive("style-src")).toBe("style-src 'self'");
  expect(directive("connect-src")).toBe("connect-src 'self'");
  expect(directive("img-src")).toBe("img-src 'self' data:");
  expect(directive("object-src")).toBe("object-src 'none'");
});
