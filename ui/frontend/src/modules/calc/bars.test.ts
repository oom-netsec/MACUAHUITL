import { expect, it } from "vitest";
import type { CalcResult } from "./api";
import { subnetFacts, vlsmFacts } from "./bars";

// Fase 30b: con claves estables las barras no dependen del idioma del texto; sin ellas se lee el español de antes.
const k = (key: string) => ({ key });

it("subred en inglés: las filas se leen por clave, no por etiqueta", () => {
  const r: CalcResult = {
    text: "", notes: [],
    tables: [{
      title: "Subnet 10.0.0.0/24", head: ["Field", "Value"], titleKey: "calc.title.subnet", titleArgs: { prefix: "10.0.0.0/24" },
      rows: [["Network", "10.0.0.0"], ["Broadcast", "10.0.0.255"], ["First usable", "10.0.0.1"], ["Last usable", "10.0.0.254"], ["Addresses", "256"], ["Usable hosts", "254"]],
      rowLabels: ["network", "broadcast", "first_usable", "last_usable", "addresses", "usable_hosts"].map((n) => k(`calc.row.${n}`)),
    }],
  };
  expect(subnetFacts(r)).toMatchObject({ title: "10.0.0.0/24", network: "10.0.0.0", broadcast: "10.0.0.255", first: "10.0.0.1", last: "10.0.0.254", total: 256, usable: 254 });
});

it("una tabla con clave de otro cálculo no es una subred", () => {
  const names = ["network", "first_usable", "last_usable", "addresses", "usable_hosts"];
  const r: CalcResult = { text: "", notes: [], tables: [{ title: "Subred x", head: ["a", "b"], titleKey: "calc.title.conversion", rowLabels: names.map((n) => k(`calc.row.${n}`)),
    rows: [["x", "10.0.0.0"], ["x", "10.0.0.1"], ["x", "10.0.0.2"], ["x", "4"], ["x", "2"]] }] };
  expect(subnetFacts(r)).toBeNull();
});

it("vlsm en inglés: título, columnas y espacio libre por clave", () => {
  const r: CalcResult = {
    text: "", notesStructured: [k("calc.note.vlsm_unplaced"), { key: "calc.note.vlsm_free", args: { free: "10.0.0.96/27 10.0.0.128/25" } }], notes: ["x", "y"],
    tables: [{
      title: "VLSM over 10.0.0.0/24", head: ["Name", "Hosts", "Prefix"], titleKey: "calc.title.vlsm", titleArgs: { parent: "10.0.0.0/24" },
      columns: [k("calc.col.name"), k("calc.col.hosts"), k("calc.col.prefix")], rows: [["LAN", "50", "10.0.0.0/26"], ["", "10", "10.0.0.64/28"]],
    }],
  };
  expect(vlsmFacts(r)).toEqual({ parent: "10.0.0.0/24", parentLen: 24, allocations: [{ name: "LAN", prefix: "10.0.0.0/26" }, { name: "10.0.0.64/28", prefix: "10.0.0.64/28" }], free: ["10.0.0.96/27", "10.0.0.128/25"] });
});

it("sin claves cae al español de siempre", () => {
  const r: CalcResult = { text: "", notes: ["Espacio libre: 10.0.0.64/26"], tables: [{ title: "VLSM sobre 10.0.0.0/24", head: ["Nombre", "Prefijo"], rows: [["A", "10.0.0.0/26"]] }] };
  expect(vlsmFacts(r)?.free).toEqual(["10.0.0.64/26"]);
  const s: CalcResult = { text: "", notes: [], tables: [{ title: "Subred 10.0.0.0/30", head: ["Campo", "Valor"], rows: [["Red", "10.0.0.0"], ["Primera usable", "10.0.0.1"], ["Última usable", "10.0.0.2"], ["Direcciones", "4"], ["Hosts usables", "2"]] }] };
  expect(subnetFacts(s)?.title).toBe("10.0.0.0/30");
});
