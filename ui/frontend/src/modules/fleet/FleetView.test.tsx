import { render, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FleetView, age } from "./FleetView";
import { fakeCore } from "../../lib/fake";
import { NavContext } from "../../app/activity";
import { useT } from "../../lib/i18n";

const at = new Date(Date.now() - 3 * 3600 * 1000).toISOString();
const old = new Date(Date.now() - 3 * 86400 * 1000).toISOString();

test("la antigüedad se escribe legible", () => {
  const now = Date.parse("2026-11-05T09:00:00Z");
  const t = renderHook(() => useT()).result.current;
  expect(age("2026-11-05T08:30:00Z", t, now)).toBe("hace 30 min");
  expect(age("2026-11-05T05:00:00Z", t, now)).toBe("hace 4 h");
  expect(age("2026-11-02T09:00:00Z", t, now)).toBe("hace 3 d");
  expect(age("basura", t, now)).toBe("hora desconocida");
});

test("la caja de búsqueda llama al núcleo y muestra equipo, puerto, VLAN, fuente y hora", async () => {
  const core = fakeCore({
    fleetFind: vi.fn(async () => ({ query: "aabb.cc00.0a01", mode: "mac", devices: 3, warnings: ["ACC1 · show ip arp: formato inesperado"],
      hits: [{ kind: "mac-table", device: "ACC1", port: "Gi1/0/5", vlan: "10", mac: "aabb.cc00.0a01", source: "show mac address-table", at: old }] })),
  });
  render(<FleetView core={core} />);
  await userEvent.type(screen.getByRole("searchbox", { name: "Buscar IP, MAC o nombre" }), "AA:BB:CC:00:0A:01{Enter}");
  expect(core.fleetFind).toHaveBeenCalledWith("AA:BB:CC:00:0A:01");
  const row = (await screen.findByText("Gi1/0/5")).closest<HTMLElement>("[role=row]")!;
  expect(within(row).getByText("ACC1")).toBeInTheDocument();
  expect(within(row).getByText(/show mac address-table · .*hace 3 d.*DATO VIEJO/)).toBeInTheDocument();
  expect(screen.getByText(/Aviso: ACC1 · show ip arp: formato inesperado/)).toBeInTheDocument();
});

test("con miles de coincidencias solo se dibujan las filas visibles", async () => {
  const hits = Array.from({ length: 2000 }, (_, i) => ({ kind: "mac-table", device: `SW${i}`, port: "Gi1/0/1", vlan: "10", mac: "aabb.cc00.0a01", source: "show mac address-table", at }));
  const core = fakeCore({ fleetFind: vi.fn(async () => ({ query: "aabb", mode: "mac", devices: 2000, warnings: [], hits })) });
  render(<FleetView core={core} />);
  expect(screen.getByText("Sin búsquedas todavía")).toBeInTheDocument();
  await userEvent.type(screen.getByRole("searchbox", { name: "Buscar IP, MAC o nombre" }), "aabb{Enter}");
  const table = await screen.findByRole("table", { name: "Búsqueda" });
  expect(table).toHaveAttribute("aria-rowcount", "2001");
  const rendered = within(table).getAllByRole("row").length;
  expect(rendered).toBeGreaterThan(5);
  expect(rendered).toBeLessThan(100);
});

test("el rastreo muestra el puerto de acceso o avisa que no llegó", async () => {
  const hop = { device: "ACC1", port: "Gi1/0/5", vlan: "10", note: "puerto de acceso", source: "show mac address-table", at };
  const core = fakeCore({ fleetTrace: vi.fn().mockResolvedValueOnce({ query: "10.1.10.20", mac: "aabb.cc00.0a01", hops: [hop], end: "access", access: hop, warnings: [] })
    .mockResolvedValueOnce({ query: "x", hops: [], end: "loop", warnings: ["bucle en el seguimiento"] }) });
  render(<FleetView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Rastreo L2" }));
  await userEvent.type(screen.getByLabelText("MAC o IP del equipo final"), "10.1.10.20");
  await userEvent.click(screen.getByRole("button", { name: "Rastrear" }));
  expect(await screen.findByText("Puerto de acceso: ACC1 Gi1/0/5 VLAN 10")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Rastrear" }));
  // Un rastreo que no llega al acceso es un resultado, no un fallo: aviso (role=status), no alerta.
  expect((await screen.findByText(/No se llegó al puerto de acceso \(loop\)/)).closest("[role=status]")).not.toBeNull();
  expect(screen.getByText(/bucle en el seguimiento/)).toBeInTheDocument();
});

test("el camino marca el corte y dibuja el grafo", async () => {
  const core = fakeCore({ fleetPath: vi.fn(async () => ({ svg: "<svg/>", result: { src: "a", dst: "b", arrived: false, warnings: [], hops: [
    { id: 0, parent: -1, device: "CORE1", route: "S* 0.0.0.0/0", status: "ok" as const, source: "show ip route", at },
    { id: 1, parent: 0, device: "10.255.0.254", via: "10.255.0.254", out_if: "Gi1/0/24", status: "cut" as const, reason: "sin evidencia del siguiente equipo", at: "0001-01-01T00:00:00Z" },
  ] } })) });
  render(<FleetView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Camino" }));
  await userEvent.type(screen.getByLabelText("Origen (IP o equipo)"), "10.1.10.20");
  await userEvent.type(screen.getByLabelText("Destino (IP o equipo)"), "172.31.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Trazar camino" }));
  expect(core.fleetPath).toHaveBeenCalledWith("10.1.10.20", "172.31.0.1");
  expect(await screen.findByText(/CORTE: sin evidencia del siguiente equipo/)).toBeInTheDocument();
  expect(screen.getByText(/se corta antes del destino/).closest("[role=status]")).not.toBeNull();
  expect(screen.getByAltText("Grafo del camino")).toBeInTheDocument();
});

test("salud, tablero, flash e inventario cargan al abrir y muestran la antigüedad", async () => {
  const core = fakeCore({
    fleetHealth: vi.fn(async () => ({ devices: 1, warnings: [], issues: [{ device: "ACC1", port: "Gi1/0/9", severity: "critica" as const, problems: [{ kind: "err-disabled", evidence: "Gi1/0/9 err-disabled" }], source: "show interfaces status", at }] })),
    fleetSummary: vi.fn(async () => ({ devices: 3, checked: { ntp: 3 }, warnings: [], rows: [{ device: "ACC1", check: "ntp", value: "no sincronizado", source: "show ntp status", at: old }] })),
    fleetCapacity: vi.fn(async (n: string) => ({ devices: 1, warnings: [], dram: [], flash: [{ device: "DIST1", fs: "flash:", total: 11 << 30, free: 300 << 20, used_pct: 97, fits: n ? false : undefined, at }] })),
    fleetInventory: vi.fn(async () => ({ csv: "Equipo\n", markdown: "| a |", result: { devices: 1, warnings: [], rows: [{ device: "CORE1", kind: "equipo", model: "C9500", serial: "FCW1", source: "show version", at }] } })),
  });
  render(<FleetView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Salud" }));
  expect(await screen.findByText("Gi1/0/9")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Tablero" }));
  expect(await screen.findByText("NTP sin sincronizar")).toBeInTheDocument();
  expect(screen.getByText(/DATO VIEJO/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Flash y DRAM" }));
  await screen.findByText("97 %");
  await userEvent.type(screen.getByLabelText(/Tamaño que debe caber/), "1G");
  await userEvent.click(screen.getByRole("button", { name: "Calcular" }));
  await waitFor(() => expect(core.fleetCapacity).toHaveBeenLastCalledWith("1G"));
  expect(await screen.findByText("No")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Inventario" }));
  expect(await screen.findByText("FCW1")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Descargar CSV" })).toHaveAttribute("download", "inventario.csv");
});

test("el menú de equipo precarga la búsqueda con la dirección", () => {
  render(<NavContext.Provider value={{ go: () => {}, inbox: { fleet: { data: "10.20.3.11", n: 1 } } }}><FleetView core={fakeCore()} /></NavContext.Provider>);
  expect(screen.getByRole("searchbox", { name: "Buscar IP, MAC o nombre" })).toHaveValue("10.20.3.11");
});

test("buscar espera a que haya una consulta", async () => {
  render(<FleetView core={fakeCore()} />);
  expect(screen.getByRole("button", { name: /^Buscar/ })).toBeDisabled();
  await userEvent.type(screen.getByRole("searchbox", { name: "Buscar IP, MAC o nombre" }), "SW1");
  expect(screen.getByRole("button", { name: /^Buscar/ })).toBeEnabled();
});
