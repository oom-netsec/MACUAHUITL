import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DiffView, diffLines } from "./DiffView";

const before = ["hostname SW1", "!", "interface Gi1/0/1", " switchport access vlan 10", " no shutdown", "!", ...Array.from({ length: 20 }, (_, i) => `ip route 10.${i}.0.0 255.255.0.0 10.0.0.1`), "interface Gi1/0/2", " shutdown", "end"];
const after = ["hostname SW1", "!", "interface Gi1/0/1", " switchport access vlan 20", " no shutdown", "!", ...Array.from({ length: 20 }, (_, i) => `ip route 10.${i}.0.0 255.255.0.0 10.0.0.1`), "interface Gi1/0/2", " no shutdown", " description CAJA-07", "end"];

test("diffLines encuentra el cambio mínimo línea por línea", () => {
  const d = diffLines(["a", "b", "c"], ["a", "x", "c", "d"]);
  expect(d.map((x) => `${x.op}${x.text}`)).toEqual([" a", "-b", "+x", " c", "+d"]);
  expect(diffLines([], [])).toEqual([]);
});

test("DiffView unificado: resume, pliega lo que no cambió y salta entre cambios", async () => {
  render(<DiffView before={before.join("\n")} after={after.join("\n")} label="running-config" />);
  const region = screen.getByRole("region", { name: "running-config" });
  expect(region).toHaveTextContent("2 cambios · 3 líneas agregadas · 2 quitadas");
  expect(within(region).getByRole("button", { name: /Mostrar 1[0-9] líneas sin cambios/ })).toBeInTheDocument();
  expect(region.querySelectorAll("[data-op='+']").length).toBe(3);
  const next = within(region).getByRole("button", { name: "Siguiente cambio" });
  await userEvent.click(next);
  expect(within(region).getByRole("status")).toHaveTextContent("Cambio 1 de 2");
  await userEvent.click(next);
  expect(within(region).getByRole("status")).toHaveTextContent("Cambio 2 de 2");
  await userEvent.click(within(region).getByRole("button", { name: /Mostrar 1[0-9] líneas sin cambios/ }));
  expect(within(region).queryByRole("button", { name: /líneas sin cambios/ })).not.toBeInTheDocument();
});

test("DiffView lado a lado alinea antes y después", async () => {
  render(<DiffView before={before.join("\n")} after={after.join("\n")} label="cfg" />);
  await userEvent.click(screen.getByRole("radio", { name: "Lado a lado" }));
  const region = screen.getByRole("region", { name: "cfg" });
  expect(within(region).getByRole("table")).toBeInTheDocument();
  expect(within(region).getAllByRole("columnheader").map((c) => c.textContent)).toEqual(["Antes", "Después"]);
});

test("sin diferencias lo dice", () => {
  render(<DiffView before={"a\nb"} after={"a\nb"} label="x" />);
  expect(screen.getByText("Sin diferencias.")).toBeInTheDocument();
  act(() => {});
});

test("diffLines: el camino es mínimo (igual al LCS) y reconstruye ambos textos", () => {
  const lcs = (a: string[], b: string[]) => {
    const t = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
    for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--) t[i][j] = a[i] === b[j] ? t[i + 1][j + 1] + 1 : Math.max(t[i + 1][j], t[i][j + 1]);
    return t[0][0];
  };
  let seed = 7;
  const rnd = (n: number) => { seed = (seed * 1103515245 + 12345) % 2 ** 31; return seed % n; };
  for (let c = 0; c < 300; c++) {
    const a = Array.from({ length: rnd(12) }, () => "abc"[rnd(3)]), b = Array.from({ length: rnd(12) }, () => "abc"[rnd(3)]);
    const d = diffLines(a, b);
    expect(d.filter((l) => l.op !== "+").map((l) => l.text)).toEqual(a);
    expect(d.filter((l) => l.op !== "-").map((l) => l.text)).toEqual(b);
    expect(d.filter((l) => l.op === " ").length).toBe(lcs(a, b));
    d.forEach((l) => { if (l.a) expect(a[l.a - 1]).toBe(l.text); if (l.b) expect(b[l.b - 1]).toBe(l.text); });
  }
});

test("diffLines: con demasiados cambios no se congela y marca el resultado como aproximado", () => {
  const a = Array.from({ length: 3000 }, (_, i) => `a${i}`), b = Array.from({ length: 3000 }, (_, i) => `b${i}`);
  const t0 = performance.now();
  const d = diffLines(["hostname R1", ...a, "end"], ["hostname R1", ...b, "end"]);
  expect(performance.now() - t0).toBeLessThan(3000);
  expect(d.coarse).toBe(true);
  expect(d[0]).toEqual({ op: " ", text: "hostname R1", a: 1, b: 1 });
  expect(d.filter((l) => l.op === "-")).toHaveLength(3000);
  expect(d.at(-1)).toEqual({ op: " ", text: "end", a: 3002, b: 3002 });
});

test("DiffView avisa cuando el diff es aproximado", () => {
  const a = Array.from({ length: 2500 }, (_, i) => `a${i}`).join("\n"), b = Array.from({ length: 2500 }, (_, i) => `b${i}`).join("\n");
  render(<DiffView before={a} after={b} label="Comparación" />);
  expect(screen.getByText(/demasiadas diferencias/)).toBeInTheDocument();
});
