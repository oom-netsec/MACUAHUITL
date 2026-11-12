import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CoreContext } from "../app/activity";
import { fakeCore } from "../lib/fake";
import type { CoreAPI } from "../lib/core";
import { DataTable, type Column } from "./DataTable";

interface Dev { name: string; ip: string; state: string; cpu: number }
const cols: Column<Dev>[] = [
  { id: "name", header: "Equipo", value: (d) => d.name },
  { id: "ip", header: "IP", value: (d) => d.ip, mono: true },
  { id: "state", header: "Estado", value: (d) => d.state },
  { id: "cpu", header: "CPU", value: (d) => d.cpu, mono: true },
];
const rows: Dev[] = [
  { name: "SW1", ip: "10.0.0.1", state: "up", cpu: 12 },
  { name: "SW2", ip: "10.0.0.2", state: "down", cpu: 3 },
  { name: "R1", ip: "10.0.0.9", state: "up", cpu: 71 },
];
const table = () => screen.getByRole("table", { name: "Equipos" });
const bodyRows = () => within(table()).getAllByRole("row").slice(1);

test("busca en todas las columnas", async () => {
  render(<DataTable label="Equipos" columns={cols} rows={rows} rowKey={(d) => d.name} />);
  expect(bodyRows()).toHaveLength(3);
  await userEvent.type(screen.getByLabelText("Buscar en la tabla"), "10.0.0.9");
  expect(bodyRows()).toHaveLength(1);
  expect(bodyRows()[0]).toHaveTextContent("R1");
  expect(screen.getByText("1 de 3 filas")).toBeInTheDocument();
});

test("ordena al pulsar el encabezado y lo anuncia con aria-sort", async () => {
  render(<DataTable label="Equipos" columns={cols} rows={rows} rowKey={(d) => d.name} />);
  const cpu = within(table()).getByRole("columnheader", { name: /CPU/ });
  await userEvent.click(within(cpu).getByRole("button"));
  expect(cpu).toHaveAttribute("aria-sort", "ascending");
  expect(bodyRows().map((r) => r.textContent)).toEqual([expect.stringContaining("SW2"), expect.stringContaining("SW1"), expect.stringContaining("R1")]);
  await userEvent.click(within(cpu).getByRole("button"));
  expect(cpu).toHaveAttribute("aria-sort", "descending");
  expect(bodyRows()[0]).toHaveTextContent("R1");
});

test("filtra por columna y oculta columnas", async () => {
  render(<DataTable label="Equipos" columns={cols} rows={rows} rowKey={(d) => d.name} />);
  await userEvent.click(screen.getByRole("button", { name: "Filtros por columna" }));
  await userEvent.type(screen.getByLabelText("Filtrar Estado"), "down");
  expect(bodyRows()).toHaveLength(1);
  await userEvent.click(screen.getByRole("button", { name: "Columnas" }));
  await userEvent.click(screen.getByRole("checkbox", { name: "IP" }));
  expect(within(table()).queryByRole("columnheader", { name: /^IP/ })).not.toBeInTheDocument();
});

test("selección múltiple con barra de acciones", async () => {
  const act = vi.fn();
  render(<DataTable label="Equipos" columns={cols} rows={rows} rowKey={(d) => d.name}
    selectable actions={(sel) => <button onClick={() => act(sel.map((d) => d.name))}>Respaldar</button>} />);
  await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar SW1" }));
  await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar R1" }));
  const bar = screen.getByRole("toolbar", { name: "Acciones de la selección" });
  expect(bar).toHaveTextContent("2 seleccionadas");
  await userEvent.click(within(bar).getByRole("button", { name: "Respaldar" }));
  expect(act).toHaveBeenCalledWith(["SW1", "R1"]);
  await userEvent.click(screen.getByRole("checkbox", { name: "Seleccionar todas" }));
  expect(bar).toHaveTextContent("3 seleccionadas");
});

test("exporta a CSV lo que se ve, con el nombre sugerido", async () => {
  const core = fakeCore();
  render(<CoreContext.Provider value={core as unknown as CoreAPI}>
    <DataTable label="Equipos" columns={cols} rows={rows} rowKey={(d) => d.name} exportName="equipos" />
  </CoreContext.Provider>);
  await userEvent.type(screen.getByLabelText("Buscar en la tabla"), "up");
  await userEvent.click(screen.getByRole("button", { name: "Exportar CSV" }));
  expect(core.saveFile).toHaveBeenCalledWith("equipos.csv", "Equipo,IP,Estado,CPU\nSW1,10.0.0.1,up,12\nR1,10.0.0.9,up,71", "utf8");
});

test("con miles de filas virtualiza e ir a la fila la muestra", async () => {
  const many = Array.from({ length: 2000 }, (_, i) => ({ name: `SW${i + 1}`, ip: `10.0.${i >> 8}.${i & 255}`, state: "up", cpu: i % 100 }));
  render(<DataTable label="Equipos" columns={cols} rows={many} rowKey={(d) => d.name} />);
  expect(bodyRows().length).toBeLessThan(80);
  await userEvent.type(screen.getByLabelText("Ir a la fila"), "1500{Enter}");
  expect(within(table()).getByRole("row", { name: /SW1500\b/ })).toBeInTheDocument();
});

test("el campo de ir a la fila tiene etiqueta visible", () => {
  render(<DataTable label="Equipos" columns={cols} rows={rows} rowKey={(d) => d.name} />);
  const label = screen.getByText("Ir a la fila");
  expect(label.tagName).toBe("LABEL");
  expect(label).toContainElement(screen.getByLabelText("Ir a la fila"));
});
