import { chains, linkLabel } from "./pathChain";
import type { PathHop } from "./api";

const at = "2026-11-06T18:00:00Z";
const hop = (id: number, parent: number, device: string, extra: Partial<PathHop> = {}): PathHop => ({ id, parent, device, status: "ok", at, ...extra });

test("una cadena por hoja, de la raíz al final", () => {
  const hops = [hop(0, -1, "A"), hop(1, 0, "B"), hop(2, 1, "C", { status: "arrived" })];
  expect(chains(hops).map((c) => c.map((h) => h.device))).toEqual([["A", "B", "C"]]);
});

test("las rutas ECMP salen como cadenas separadas que comparten el inicio", () => {
  const hops = [hop(0, -1, "A"), hop(1, 0, "B", { ecmp: true }), hop(2, 0, "C", { ecmp: true }), hop(3, 1, "D", { status: "arrived" })];
  expect(chains(hops).map((c) => c.map((h) => h.device))).toEqual([["A", "C"], ["A", "B", "D"]]); // en orden de la hoja
});

test("sin saltos, o con un padre que no existe, no se rompe", () => {
  expect(chains([])).toEqual([]);
  expect(chains([hop(5, 9, "Z")]).map((c) => c.map((h) => h.device))).toEqual([["Z"]]);
});

test("la etiqueta del enlace junta interfaz, VLAN, siguiente salto y switches L2 intermedios", () => {
  const h = hop(1, 0, "B", { via: "10.0.0.2", out_if: "Gi1/0/24", segment: { interface: "Vlan10", vlan: "10", l2: [{ device: "SW9", port: "Gi0/1", source: "x", at }] } });
  expect(linkLabel(h)).toEqual({ iface: "Gi1/0/24", vlan: "10", via: "10.0.0.2", l2: ["SW9 Gi0/1"] });
  expect(linkLabel(hop(1, 0, "B", { segment: { interface: "Te1/1/1" } }))).toEqual({ iface: "Te1/1/1", vlan: "", via: "", l2: [] });
});
