/// <reference types="vite/client" />
// En Windows (y macOS) el sistema de archivos no distingue mayúsculas: con TlsChain.tsx y tlsChain.ts en la misma
// carpeta, `import "./TlsChain"` prueba .ts antes que .tsx y recibe el otro módulo (el componente llega undefined).
// Ningún par de módulos puede diferir solo en mayúsculas (sin contar la extensión).
test("no hay dos módulos cuyo nombre difiera solo en mayúsculas", () => {
  const byKey = new Map<string, Set<string>>();
  for (const p of Object.keys(import.meta.glob("/src/**/*.{ts,tsx}"))) {
    const name = p.replace(/\.tsx?$/, "");
    byKey.set(name.toLowerCase(), (byKey.get(name.toLowerCase()) ?? new Set()).add(name));
  }
  expect([...byKey.values()].filter((s) => s.size > 1).map((s) => [...s].join(" / "))).toEqual([]);
});
