import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdhocView, parseTarget } from "./AdhocView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";

const cred = { id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false };
const report = { commands: ["show clock"], devices: 2, rows: [
  { device: "SW1", address: "192.0.2.1", command: "show clock", ok: true, output: "10:00:00" },
  { device: "SW2", address: "192.0.2.2", command: "show clock", ok: false, output: "", note: "tiempo agotado" },
] };

test("el destino acepta host y host:puerto", () => {
  expect(parseTarget("192.0.2.1")).toEqual({ address: "192.0.2.1", port: 0 });
  expect(parseTarget("sw1:2222")).toEqual({ address: "sw1", port: 2222 });
  expect(parseTarget("2001:db8::1")).toEqual({ address: "2001:db8::1", port: 0 });
  // IPv6 con puerto: la forma entre corchetes.
  expect(parseTarget("[2001:db8::1]:2222")).toEqual({ address: "2001:db8::1", port: 2222 });
  expect(parseTarget("[2001:db8::1]")).toEqual({ address: "2001:db8::1", port: 0 });
});

test("ejecuta el lote, espera el resultado y muestra por equipo, tabla, CSV y Markdown", async () => {
  const adhocResult = vi.fn().mockResolvedValueOnce({ state: "armed", done: false, report: null, text: "", csv: "", markdown: "" })
    .mockResolvedValueOnce({ state: "completed", done: true, report, text: "== SW1 (192.0.2.1) ==\n10:00:00", csv: "equipo,direccion\nSW1,192.0.2.1\n", markdown: "| Equipo |" });
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocResult });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1 sw2:2222");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  await userEvent.click(await screen.findByRole("button", { name: "Por equipo" }));
  expect(await screen.findByText(/== SW1/)).toBeInTheDocument();
  expect(core.adhocStart).toHaveBeenCalledWith([{ address: "192.0.2.1", port: 0 }, { address: "sw2", port: 2222 }], "c1", expect.stringContaining("show version"), []);
  expect(adhocResult).toHaveBeenCalledTimes(2);
  await userEvent.click(screen.getByRole("button", { name: "Tabla" }));
  expect(screen.getByText("tiempo agotado")).toBeInTheDocument();
  expect(screen.getByText("sin salida")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "CSV" }));
  expect(screen.getByLabelText("CSV")).toHaveValue("equipo,direccion\nSW1,192.0.2.1\n");
  await userEvent.click(screen.getByRole("button", { name: "Markdown" }));
  expect(screen.getByLabelText("Markdown")).toHaveValue("| Equipo |");
});

const matrixReport = { commands: ["show clock", "show version"], devices: 2, rows: [
  { device: "SW1", address: "192.0.2.1", command: "show clock", ok: true, output: "10:00:00.123 UTC" },
  { device: "SW1", address: "192.0.2.1", command: "show version", ok: true, output: "" },
  { device: "SW2", address: "192.0.2.2", command: "show clock", ok: false, output: "", note: "tiempo agotado" },
  { device: "SW2", address: "192.0.2.2", command: "show version", ok: true, output: "Cisco IOS XE 17.9" },
] };

async function runMatrix() {
  const core = fakeCore({
    listCredentials: vi.fn(async () => [cred]),
    adhocResult: vi.fn(async () => ({ state: "completed", done: true, report: matrixReport, text: "", csv: "equipo,comando\nSW1,show clock\n", markdown: "| Equipo | Comando |" })),
  });
  render(<CoreContext.Provider value={core}><AdhocView core={core} pollMs={1} /></CoreContext.Provider>);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1 192.0.2.2");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  return { core, grid: await screen.findByRole("table", { name: "Matriz de equipos por comando" }) };
}

test("la matriz muestra un estado por equipo y comando, con texto además del color", async () => {
  const { grid } = await runMatrix();
  expect(within(grid).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Equipo", "show clock", "show version"]);
  expect(within(grid).getByRole("button", { name: "SW1 show clock: Correcto" })).toBeInTheDocument();
  expect(within(grid).getByRole("button", { name: "SW1 show version: Vacío" })).toBeInTheDocument();
  expect(within(grid).getByRole("button", { name: "SW2 show clock: Error" })).toBeInTheDocument();
});

test("elegir una celda abre su salida en la terminal; un error muestra la nota del equipo", async () => {
  const { grid } = await runMatrix();
  expect(screen.getByText("Elegir una celda de la matriz para ver su salida.")).toBeInTheDocument();
  await userEvent.click(within(grid).getByRole("button", { name: "SW2 show version: Correcto" }));
  const out = screen.getByRole("region", { name: "SW2 · show version" });
  expect(within(out).getByLabelText("Salida de SW2 · show version")).toHaveTextContent("Cisco IOS XE 17.9");
  await userEvent.click(within(grid).getByRole("button", { name: "SW2 show clock: Error" }));
  expect(within(screen.getByRole("region", { name: "SW2 · show clock" })).getByLabelText("Salida de SW2 · show clock")).toHaveTextContent("tiempo agotado");
});

test("la matriz se exporta a CSV y Markdown con lo que entregó el núcleo", async () => {
  const { core } = await runMatrix();
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "CSV (.csv)" }));
  expect(core.saveFile).toHaveBeenCalledWith("lote.csv", "equipo,comando\nSW1,show clock\n", "utf8");
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "Markdown (.md)" }));
  expect(core.saveFile).toHaveBeenLastCalledWith("lote.md", "| Equipo | Comando |", "utf8");
});

test("un lote sin armar explica por qué y manda las huellas aceptadas al reintentar", async () => {
  const adhocStart = vi.fn().mockResolvedValueOnce({ jobId: "j9", armed: false, detail: "Login Test falló: llave de host SHA256:abc" })
    .mockResolvedValueOnce({ jobId: "j10", armed: true, detail: "" });
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocStart });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  expect(await screen.findByRole("status")).toHaveTextContent("Login Test falló");
  await userEvent.type(screen.getByLabelText(/Huellas SHA256 aceptadas/), "SHA256:abc");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  await screen.findByRole("button", { name: "Tabla" });
  expect(adhocStart).toHaveBeenLastCalledWith([{ address: "192.0.2.1", port: 0 }], "c1", expect.any(String), ["SHA256:abc"]);
});

test("el rechazo del núcleo (comando que no es de lectura) se muestra como alerta", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocStart: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = comando no permitido en una recolección (solo lectura)"); }) });
  render(<AdhocView core={core} pollMs={1} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("solo lectura");
});

async function runBatch(core: ReturnType<typeof fakeCore>, props: { pollMs: number; maxWaitMs?: number }) {
  render(<AdhocView core={core} {...props} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  await userEvent.type(screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar lote" }));
}

test("si el núcleo termina con error, lo muestra y deja de preguntar", async () => {
  const adhocResult = vi.fn(async () => ({ state: "completed", done: true, report: null, text: "", csv: "", markdown: "", error: "patrol: disco lleno" }));
  await runBatch(fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocResult }), { pollMs: 1 });
  expect(await screen.findByRole("alert")).toHaveTextContent("patrol: disco lleno");
  expect(adhocResult).toHaveBeenCalledTimes(1);
});

test("el bucle de consulta tiene tope de tiempo y lo dice", async () => {
  const adhocResult = vi.fn(async () => ({ state: "completed", done: false, report: null, text: "", csv: "", markdown: "" }));
  await runBatch(fakeCore({ listCredentials: vi.fn(async () => [cred]), adhocResult }), { pollMs: 1, maxWaitMs: 30 });
  expect(await screen.findByRole("alert")).toHaveTextContent(/sigue sin resultado/);
  const n = adhocResult.mock.calls.length;
  await new Promise((ok) => setTimeout(ok, 30));
  expect(adhocResult.mock.calls.length).toBe(n);
  expect(screen.getByRole("button", { name: "Ejecutar lote" })).toBeEnabled();
});
