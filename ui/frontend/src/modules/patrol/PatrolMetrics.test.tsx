import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CoreContext } from "../../app/activity";
import type { CoreAPI } from "../../lib/core";
import { fakeCore } from "../../lib/fake";
import { sampleMetrics } from "./fake";

// jsdom no tiene canvas: se sustituye uPlot y se revisan las opciones que recibe.
const made: { opts: { cursor: { sync?: { key: string } }; series: { label?: string }[] }; data: unknown[][] }[] = [];
vi.mock("uplot", () => ({
  default: class {
    constructor(opts: never, data: never) { made.push({ opts, data }); }
    setSize() {} destroy() {} setData() {}
    get ctx() { return { canvas: { toDataURL: () => "" } }; }
  },
}));

import { PatrolView } from "./PatrolView";

const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();
const armed = { id: "j9", name: "nocturno", state: "armed", armedAt: ago(90), round: 6, rounds: 12, devicesTotal: 3, devicesOk: 3, devicesFailed: 0, outputDir: "/home/u/out/j9" };

async function open(over: Record<string, unknown> = {}, job: object = armed) {
  const core = fakeCore({
    listJobs: vi.fn(async () => [job as never]),
    jobMetrics: vi.fn(async () => sampleMetrics()),
    getRun: vi.fn(async () => [{ target: "10.0.0.1:22", state: "DEVICE_STATE_COMPLETED", detail: "" }, { target: "10.0.0.2:22", state: "DEVICE_STATE_COMPLETED", detail: "" }]),
    ...over,
  });
  render(<CoreContext.Provider value={core as unknown as CoreAPI}><PatrolView core={core} /></CoreContext.Provider>);
  await userEvent.click(await screen.findByRole("button", { name: new RegExp((job as { name: string }).name) }));
  return core;
}
const tab = (name: string) => screen.findByRole("tab", { name });
const fig = (name: string) => screen.findByRole("figure", { name });

beforeEach(() => { made.length = 0; });

test("pide las métricas del trabajo y muestra las pestañas con el resumen del primer equipo", async () => {
  const core = await open();
  const tabs = await screen.findByRole("tablist", { name: "Vistas de métricas" });
  expect(within(tabs).getAllByRole("tab").map((x) => x.textContent)).toEqual(["Resumen", "CPU y memoria", "Interfaces", "Errores"]);
  expect(core.jobMetrics).toHaveBeenCalledWith({ job: "j9", maxInterfaces: 64 });
  const select = screen.getByLabelText("Equipo de las gráficas");
  expect(within(select).getAllByRole("option").map((o) => o.textContent)).toEqual(["sw-core-1 (10.0.0.1)", "sw-dist-2 (10.0.0.2)", "sw-acc-3 (10.0.0.3)"]);
  const stats = screen.getByRole("region", { name: "Resumen de sw-core-1" });
  expect(stats).toHaveTextContent("Pico de CPU (5 s)97 % · ronda 4");
  expect(stats).toHaveTextContent("Interfaces con CRC creciente1");
});

test("un trabajo sin armar no pide métricas", async () => {
  const core = await open({}, { id: "j1", name: "borrador", state: "created" });
  await screen.findByRole("heading", { name: "borrador" });
  expect(core.jobMetrics).not.toHaveBeenCalled();
  expect(screen.queryByRole("tablist", { name: "Vistas de métricas" })).not.toBeInTheDocument();
});

test("si el trabajo aún no tiene rondas lo dice", async () => {
  await open({ jobMetrics: vi.fn(async () => ({ devices: [], warnings: [] })) });
  expect(await screen.findByText(/aparecen al terminar la primera ronda/)).toBeInTheDocument();
});

test("CPU y memoria: tres series con el mismo syncKey del trabajo y una gráfica por pool", async () => {
  await open();
  await userEvent.click(await tab("CPU y memoria"));
  const cpu = await fig("CPU de sw-core-1");
  expect(cpu).toHaveTextContent("CPU 5 s: mín 22 %, prom 37 %, máx 97 %");
  expect(within(cpu).getByText("CPU 5 min: mín 16 %, prom 25 %, máx 55 %, último 16 %")).toBeInTheDocument();
  await fig("Memoria Processor de sw-core-1");
  await fig("Memoria I/O de sw-core-1");
  await waitFor(() => expect(made).toHaveLength(3));
  expect(new Set(made.map((m) => m.opts.cursor.sync?.key))).toEqual(new Set(["patrol-j9"]));
  expect(made[0].opts.series.map((s) => s.label)).toEqual(["Hora", "CPU 5 s", "CPU 1 min", "CPU 5 min"]);
  expect(made[0].data[0]).toHaveLength(6); // una muestra por ronda
});

test("cambiar de equipo cambia las gráficas", async () => {
  await open();
  await userEvent.click(await tab("CPU y memoria"));
  await userEvent.selectOptions(await screen.findByLabelText("Equipo de las gráficas"), "10.0.0.2");
  const cpu = await fig("CPU de sw-dist-2");
  expect(cpu).toHaveTextContent("máx 37 %");
});

test("Interfaces: por defecto las 5 de mayor pico y se pueden quitar", async () => {
  await open();
  await userEvent.click(await tab("Interfaces"));
  const group = await screen.findByRole("group", { name: "Interfaces a graficar" });
  expect(within(group).getAllByRole("checkbox")).toHaveLength(4);
  expect(within(group).getAllByRole("checkbox").every((c) => (c as HTMLInputElement).checked)).toBe(true);
  const inbound = await fig("Entrada de sw-core-1");
  expect(inbound).toHaveTextContent("Te1/1/1: mín");
  expect(inbound).toHaveTextContent("Gi1/0/24:");
  await fig("Salida de sw-core-1");
  await fig("Utilización de sw-core-1 (% del ancho de banda)");
  await userEvent.click(within(group).getByRole("checkbox", { name: "Gi1/0/24" }));
  expect(within(await fig("Entrada de sw-core-1")).queryByText(/Gi1\/0\/24:/)).not.toBeInTheDocument();
});

test("Errores: diferencias entre rondas solo de las interfaces que crecieron", async () => {
  await open();
  await userEvent.click(await tab("Errores"));
  const crc = await fig("CRC de sw-core-1 por ronda");
  expect(crc).toHaveTextContent("Gi1/0/2: mín 2, prom 29.6, máx 80, último 80"); // 0,2,9,30,68,148 -> 2,7,21,38,80
  expect(within(crc).queryByText(/Te1\/1\/1/)).not.toBeInTheDocument();
  expect(await fig("Descartes de sw-core-1 por ronda")).toHaveTextContent("Te1/1/1");
  expect(await fig("Reinicios de sw-core-1 por ronda")).toHaveTextContent("Sin crecimiento entre rondas en este contador.");
});

test("la grilla muestra CPU con tendencia y barra, y el menú de equipo", async () => {
  await open();
  const row = await screen.findByRole("row", { name: /10\.0\.0\.1:22/ });
  await waitFor(() => expect(within(row).getByRole("img", { name: /CPU 10\.0\.0\.1/ })).toBeInTheDocument());
  expect(within(row).getByRole("meter", { name: "CPU 10.0.0.1" })).toHaveAttribute("aria-valuenow", "18");
  expect(within(row).getByRole("button", { name: "Acciones de 10.0.0.1:22" })).toBeInTheDocument();
  const other = screen.getByRole("row", { name: /10\.0\.0\.2:22/ });
  expect(within(other).getByRole("meter", { name: "CPU 10.0.0.2" })).toBeInTheDocument();
});

test("un trabajo terminado con carpeta de salida la muestra con copiar", async () => {
  const core = await open({}, { ...armed, state: "completed" });
  const sec = await screen.findByRole("region", { name: "Paquete de salida" });
  expect(sec).toHaveTextContent("/home/u/out/j9");
  await userEvent.click(within(sec).getByRole("button", { name: "Copiar ruta del paquete" }));
  expect(core.copyText).toHaveBeenCalledWith("/home/u/out/j9");
});

test("un trabajo armado todavía no ofrece el paquete", async () => {
  await open();
  await screen.findByRole("tablist", { name: "Vistas de métricas" });
  expect(screen.queryByRole("region", { name: "Paquete de salida" })).not.toBeInTheDocument();
});
