import { render } from "@testing-library/react";
import { useState } from "react";
import { findFiberState } from "./test-utils";

const Holder = ({ v }: { v: unknown }) => { useState(v); return <p>x</p>; };
const find = (v: unknown, m = "MARCA") => { const { container } = render(<Holder v={v} />); return findFiberState(container, m); };

test("encuentra el marcador guardado en useState", () => { expect(find("xx-MARCA-xx")).toBe(true); });
test("sin marcador devuelve false", () => { expect(find({ a: "nada" })).toBe(false); });
test("un objeto visto cerca del límite de profundidad se vuelve a explorar si aparece más arriba", () => {
  const shared = { a: { c: "MARCA" } };
  const wrap = (k: number) => Array.from({ length: k }).reduce<unknown>((acc) => ({ n: acc }), shared);
  // De la cadena más larga a la más corta: una de ellas deja a shared justo en el límite (marcador fuera de alcance) y la última lo pone arriba.
  const v: Record<string, unknown> = {};
  for (let k = 8; k >= 0; k--) v[`k${k}`] = wrap(k);
  expect(find(v)).toBe(true);
});
