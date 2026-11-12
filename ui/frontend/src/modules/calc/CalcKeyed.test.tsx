import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CalcView } from "./CalcView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";

// Fase 30b: con claves estables, el rótulo de copiar y las barras no dependen del idioma del texto del núcleo.
test("copiar con claves: el rótulo sale de la fila aunque el texto de las columnas esté en inglés", async () => {
  const keyed = {
    text: "", notes: [],
    tables: [{ title: "Subnet 10.0.0.0/24", head: ["Field", "Value"], titleKey: "calc.title.subnet", titleArgs: { prefix: "10.0.0.0/24" }, columns: [{ key: "calc.col.field" }, { key: "calc.col.value" }],
      rows: [["Network", "10.0.0.0"], ["First usable", "10.0.0.1"], ["Last usable", "10.0.0.254"], ["Addresses", "256"], ["Usable hosts", "254"], ["Mask", "255.255.255.0"]],
      rowLabels: ["network", "first_usable", "last_usable", "addresses", "usable_hosts", "mask"].map((n) => ({ key: `calc.row.${n}` })) }],
  };
  const core = fakeCore({ calc: vi.fn(async () => keyed) });
  render(<CoreContext.Provider value={core}><CalcView core={core} /></CoreContext.Provider>);
  await userEvent.type(screen.getByLabelText(/^Prefijo/), "10.0.0.0/24");
  await userEvent.click(screen.getByRole("button", { name: "Calcular" }));
  const table = await screen.findByRole("table", { name: "Subnet 10.0.0.0/24" });
  expect(within(table).getByRole("button", { name: "Copiar Mask" })).toBeInTheDocument();
  expect(screen.getByRole("list", { name: "Reparto de la subred 10.0.0.0/24" })).toBeInTheDocument();
});
