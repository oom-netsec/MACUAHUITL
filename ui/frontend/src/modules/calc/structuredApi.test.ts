import { expect, it } from "vitest";
import type { CalcResult } from "./api";
import { subnetFacts } from "./bars";

// Fase 30b: la forma con claves convive con la de antes; las barras siguen leyendo el texto hasta que la vista migre.
it("un resultado con claves sigue siendo un CalcResult y bars.ts lo lee igual", () => {
  const r: CalcResult = {
    text: "", notes: [], notesStructured: [{ key: "calc.note.p2p_v4" }],
    tables: [{
      title: "Subred 10.0.0.0/24", head: ["Campo", "Valor"], titleKey: "calc.title.subnet", titleArgs: { prefix: "10.0.0.0/24" },
      columns: [{ key: "calc.col.field" }, { key: "calc.col.value" }],
      rows: [["Red", "10.0.0.0"], ["Primera usable", "10.0.0.1"], ["Última usable", "10.0.0.254"], ["Direcciones", "256"], ["Hosts usables", "254"]],
      rowLabels: [{ key: "calc.row.network" }, { key: "calc.row.first_usable" }, { key: "calc.row.last_usable" }, { key: "calc.row.addresses" }, { key: "calc.row.usable_hosts" }],
    }],
  };
  expect(subnetFacts(r)?.network).toBe("10.0.0.0");
  expect(r.tables[0].rowLabels).toHaveLength(r.tables[0].rows.length);
});
