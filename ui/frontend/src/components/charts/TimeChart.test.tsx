import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CoreContext } from "../../app/activity";
import { fakeCore } from "../../lib/fake";
import type { CoreAPI } from "../../lib/core";

// jsdom no tiene canvas: se sustituye uPlot y se revisan las opciones que recibe.
const made: { opts: Record<string, unknown>; data: unknown[] }[] = [];
const setData = vi.fn();
vi.mock("uplot", () => ({
  default: class {
    constructor(opts: Record<string, unknown>, data: unknown[]) { made.push({ opts, data }); }
    setSize() {} destroy() {} setData(d: unknown) { setData(d); }
    get ctx() { return { canvas: { toDataURL: () => "data:image/png;base64,QUJD" } }; }
  },
}));

import TimeChart, { toCSV } from "./TimeChart";

const t0 = Date.UTC(2026, 10, 6, 18, 0) / 1000;
const times = [t0, t0 + 60, t0 + 120, t0 + 180];
const series = [
  { label: "CPU 5 s", values: [12, 40, 91, 30] },
  { label: "CPU 1 min", values: [10, 22, 48, null] },
];

beforeEach(() => { made.length = 0; setData.mockClear(); });

test("arma uPlot con cursor sincronizado, zoom, umbral y marcas de ronda", () => {
  render(<TimeChart title="CPU de SW1" unit="%" times={times} series={series} syncKey="patrol-j1"
    thresholds={[{ value: 80, label: "Umbral 80 %" }]} marks={[{ at: t0 + 60, label: "Ronda 2" }]} fileName="cpu-sw1" />);
  expect(made).toHaveLength(1);
  const o = made[0].opts as { series: { label?: string }[]; cursor: { sync: { key: string }; drag: { x: boolean } } };
  expect(o.series.map((s) => s.label)).toEqual(["Hora", "CPU 5 s", "CPU 1 min"]);
  expect(o.cursor.sync.key).toBe("patrol-j1");
  expect(o.cursor.drag.x).toBe(true);
  expect(made[0].data).toEqual([times, [12, 40, 91, 30], [10, 22, 48, null]]);
});

test("el eje X lleva segundos en rangos cortos, sin repetir marcas, y las marcas de ronda tienen franja propia", () => {
  render(<TimeChart title="RTT" unit="ms" times={[t0, t0 + 1, t0 + 2]} series={[{ label: "RTT", values: [1, 2, 3] }]} marks={[{ at: t0 + 1, label: "R1" }]} fileName="rtt" />);
  const o = made[0].opts as { padding: (number | null)[]; axes: { incrs: number[]; values: (u: unknown, v: number[], a: number, s: number, incr: number) => string[] }[] };
  expect(Math.min(...o.axes[0].incrs)).toBe(1);
  expect(o.padding[0]).toBeGreaterThan(0);
  const [short] = o.axes[0].values(null, [t0], 0, 0, 1);
  const [long] = o.axes[0].values(null, [t0], 0, 0, 300);
  expect(short.length).toBeGreaterThan(long.length);
});

test("tiene un resumen en texto por serie y la tabla de datos equivalente", async () => {
  render(<TimeChart title="CPU de SW1" unit="%" times={times} series={series} fileName="cpu-sw1" />);
  const fig = screen.getByRole("figure", { name: "CPU de SW1" });
  expect(fig).toHaveTextContent("CPU 5 s: mín 12 %, prom 43.3 %, máx 91 %, último 30 %");
  expect(fig).toHaveTextContent("CPU 1 min: mín 10 %, prom 26.7 %, máx 48 %, último 48 %");
  await userEvent.click(within(fig).getByText("Ver los datos"));
  const table = within(fig).getByRole("table");
  expect(within(table).getAllByRole("columnheader").map((c) => c.textContent)).toEqual(["Hora", "CPU 5 s (%)", "CPU 1 min (%)"]);
  expect(within(table).getAllByRole("row")).toHaveLength(5);
});

test("exporta CSV y PNG con el nombre sugerido", async () => {
  const core = fakeCore();
  render(<CoreContext.Provider value={core as unknown as CoreAPI}>
    <TimeChart title="CPU" unit="%" times={times} series={series} fileName="cpu-sw1" />
  </CoreContext.Provider>);
  await userEvent.click(screen.getByRole("button", { name: "Exportar CSV" }));
  expect(core.saveFile).toHaveBeenCalledWith("cpu-sw1.csv", toCSV(times, series), "utf8");
  await userEvent.click(screen.getByRole("button", { name: "Exportar PNG" }));
  expect(core.saveFile).toHaveBeenCalledWith("cpu-sw1.png", "QUJD", "base64");
});

test("toCSV usa hora ISO y deja vacío lo que falta", () => {
  expect(toCSV(times.slice(0, 2), [{ label: "a,b", values: [1, null] }]).split("\n")).toEqual([
    'hora,"a,b"', "2026-11-06T18:00:00.000Z,1", "2026-11-06T18:01:00.000Z,",
  ]);
});

test("sin datos lo dice en vez de dibujar un lienzo vacío", () => {
  render(<TimeChart title="CPU" times={[]} series={[]} fileName="x" />);
  expect(screen.getByText("Sin datos en este intervalo.")).toBeInTheDocument();
  expect(made).toHaveLength(0);
});

test("con la misma estructura, datos nuevos solo actualizan la gráfica (setData)", () => {
  const { rerender } = render(<TimeChart title="RTT" unit="ms" times={times} series={series} fileName="rtt" />);
  const next = [{ ...series[0], values: [1, 2, 3, 4] }, series[1]];
  rerender(<TimeChart title="RTT" unit="ms" times={times} series={next} fileName="rtt" />);
  expect(made).toHaveLength(1);
  expect(setData).toHaveBeenLastCalledWith([times, [1, 2, 3, 4], [10, 22, 48, null]]);
  rerender(<TimeChart title="RTT" unit="ms" times={times} series={next} thresholds={[{ value: 5, label: "5 ms" }]} fileName="rtt" />);
  expect(made).toHaveLength(2); // cambió la estructura: se rehace
});

test("el eje de tiempo y la leyenda usan la hora en el idioma de la app", () => {
  render(<TimeChart title="CPU" unit="%" times={times} series={series} fileName="cpu" />);
  const o = made[0].opts as { axes: { values: (u: unknown, v: number[]) => string[] }[]; series: { value?: (u: unknown, v: number | null) => string }[] };
  const want = new Date(times[0] * 1000).toLocaleTimeString("es", { hour: "2-digit", minute: "2-digit" });
  expect(o.axes[0].values(null, [times[0]])).toEqual([want]);
  expect(o.series[0].value?.(null, times[0])).toBe(want);
});
