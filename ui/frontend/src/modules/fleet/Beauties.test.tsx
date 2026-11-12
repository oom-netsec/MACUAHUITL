import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FleetView } from "./FleetView";
import { fakeCore } from "../../lib/fake";

const at = new Date(Date.now() - 3600 * 1000).toISOString();

test("el camino se dibuja como lista ordenada equipo → interfaz → equipo con VLAN y siguiente salto", async () => {
  const core = fakeCore({ fleetPath: vi.fn(async () => ({ svg: "", result: { src: "a", dst: "b", arrived: true, warnings: [], hops: [
    { id: 0, parent: -1, device: "ACC1", status: "ok" as const, source: "show ip route", at },
    { id: 1, parent: 0, device: "CORE1", via: "10.0.0.1", out_if: "Gi1/0/24", segment: { interface: "Vlan10", vlan: "10" }, status: "ok" as const, at },
    { id: 2, parent: 1, device: "EDGE1", via: "10.0.1.1", out_if: "Te1/1/1", status: "arrived" as const, reason: "destino conectado", at },
  ] } })) });
  render(<FleetView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Camino" }));
  await userEvent.type(screen.getByLabelText("Origen (IP o equipo)"), "a");
  await userEvent.type(screen.getByLabelText("Destino (IP o equipo)"), "b");
  await userEvent.click(screen.getByRole("button", { name: "Trazar camino" }));
  const chain = await screen.findByRole("list", { name: "Ruta salto a salto" });
  const hops = within(chain).getAllByRole("listitem");
  expect(hops.map((h) => h.textContent)).toEqual([
    expect.stringMatching(/^ACC1$/),
    expect.stringMatching(/Gi1\/0\/24 · VLAN 10 · siguiente salto 10\.0\.0\.1.*CORE1/),
    expect.stringMatching(/Te1\/1\/1 · siguiente salto 10\.0\.1\.1.*EDGE1.*Llegó/),
  ]);
});

test("un corte en el camino se marca con texto en la cadena", async () => {
  const core = fakeCore({ fleetPath: vi.fn(async () => ({ svg: "", result: { src: "a", dst: "b", arrived: false, warnings: [], hops: [
    { id: 0, parent: -1, device: "CORE1", status: "ok" as const, at },
    { id: 1, parent: 0, device: "10.255.0.254", out_if: "Gi1/0/24", status: "cut" as const, reason: "sin evidencia", at: "0001-01-01T00:00:00Z" },
  ] } })) });
  render(<FleetView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Camino" }));
  await userEvent.type(screen.getByLabelText("Origen (IP o equipo)"), "a");
  await userEvent.type(screen.getByLabelText("Destino (IP o equipo)"), "b");
  await userEvent.click(screen.getByRole("button", { name: "Trazar camino" }));
  const chain = await screen.findByRole("list", { name: "Ruta salto a salto" });
  expect(within(chain).getAllByRole("listitem")[1]).toHaveTextContent(/Corte/);
});

test("salud: mapa de calor equipo × problema con el texto en cada celda y leyenda", async () => {
  const core = fakeCore({ fleetHealth: vi.fn(async () => ({ devices: 2, warnings: [], issues: [
    { device: "ACC1", port: "Gi1/0/9", severity: "critica" as const, problems: [{ kind: "err-disabled", evidence: "x" }], source: "show interfaces status", at },
    { device: "ACC1", port: "Gi1/0/10", severity: "media" as const, problems: [{ kind: "crc", value: 12, evidence: "y" }], source: "show interfaces", at },
    { device: "DIST1", port: "Te1/1/1", severity: "alta" as const, problems: [{ kind: "crc", value: 90, evidence: "z" }], source: "show interfaces", at },
  ] })) });
  render(<FleetView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Salud" }));
  const heat = await screen.findByRole("table", { name: "Mapa de calor de salud" });
  expect(within(heat).getAllByRole("columnheader").map((c) => c.textContent)).toEqual(["Equipo", "CRC", "err-disabled"]);
  const acc = within(heat).getByRole("rowheader", { name: "ACC1" }).closest<HTMLElement>("tr")!;
  expect(within(acc).getAllByRole("cell").map((c) => c.textContent)).toEqual(["1 puerto · media", "1 puerto · crítica"]);
  const dist = within(heat).getByRole("rowheader", { name: "DIST1" }).closest<HTMLElement>("tr")!;
  expect(within(dist).getAllByRole("cell").map((c) => c.textContent)).toEqual(["1 puerto · alta", "—"]);
  expect(screen.getByRole("list", { name: "Leyenda" })).toHaveTextContent("sin hallazgo");
  // El detalle sigue en la tabla de datos, con búsqueda y exportación.
  expect(screen.getByRole("table", { name: "Salud" })).toBeInTheDocument();
  expect(screen.getByRole("textbox", { name: "Buscar en la tabla" })).toBeInTheDocument();
});

test("tablero: mapa de calor equipo × revisión con el valor de la alerta", async () => {
  const core = fakeCore({ fleetSummary: vi.fn(async () => ({ devices: 2, checked: { cpu: 2, ntp: 2 }, warnings: [], rows: [
    { device: "SW1", check: "cpu", value: "92 %", source: "show processes cpu", at },
    { device: "SW2", check: "ntp", value: "no sincronizado", source: "show ntp status", at },
  ] })) });
  render(<FleetView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Tablero" }));
  const heat = await screen.findByRole("table", { name: "Mapa de calor del tablero" });
  expect(within(heat).getAllByRole("columnheader").map((c) => c.textContent)).toEqual(["Equipo", "CPU", "NTP"]);
  expect(within(within(heat).getByRole("rowheader", { name: "SW1" }).closest<HTMLElement>("tr")!).getAllByRole("cell").map((c) => c.textContent)).toEqual(["92 %", "—"]);
});
