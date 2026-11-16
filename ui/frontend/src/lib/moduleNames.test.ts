/// <reference types="vite/client" />
// En Windows (y macOS) el sistema de archivos no distingue mayúsculas: con TlsChain.tsx y tlsChain.ts en la misma
// carpeta, `import "./TlsChain"` prueba .ts antes que .tsx y recibe el otro módulo (el componente llega undefined).
// Ningún par de módulos puede compartir nombre sin contar mayúsculas ni extensión (tampoco Foo.ts junto a Foo.tsx).
// Las colisiones de cualquier archivo del repo las revisa `git ls-files` en dev.sh y en el job ui-windows.
test("no hay dos módulos cuyo nombre difiera solo en mayúsculas o en la extensión", () => {
  const paths = Object.keys(import.meta.glob("/src/**/*.{ts,tsx}"));
  expect(paths.length).toBeGreaterThan(100); // si el glob dejara de encontrar archivos, la prueba no revisaría nada
  const byKey = new Map<string, string[]>();
  for (const p of paths) {
    const key = p.replace(/\.tsx?$/, "").toLowerCase();
    byKey.set(key, [...(byKey.get(key) ?? []), p]);
  }
  expect([...byKey.values()].filter((l) => l.length > 1).map((l) => l.join(" / "))).toEqual([]);
});
