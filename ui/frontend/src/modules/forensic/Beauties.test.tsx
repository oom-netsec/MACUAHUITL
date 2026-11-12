import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ForensicView } from "./ForensicView";
import { fakeCore } from "../../lib/fake";
import type { FlappingReport, LeaksReport } from "./api";

const flapRep: FlappingReport = {
  source: "texto", interfaces: 2, transitions: 10, count: 3, window: "1m0s", counter_jumps: [],
  flaps: [
    { host: "SW1", interface: "Gi0/3", layer: "link", total: 6, peak: 6, episodes: 1, first: "2026-11-06T18:00:00Z", last: "2026-11-06T18:00:40Z", sequence: "down up down up" },
    { host: "SW2", interface: "Gi0/9", layer: "link", total: 4, peak: 0, episodes: 0, sequence: "down down", no_time: true },
  ],
};

test("flapping: carriles por interfaz con el estado en símbolo y texto, y la tabla equivalente", async () => {
  const core = fakeCore({ forensicFlapping: vi.fn(async () => flapRep) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Flapping" }));
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "capture");
  await userEvent.click(screen.getByRole("button", { name: "Buscar flapping" }));
  const lanes = await screen.findByRole("list", { name: "Secuencia de estados por interfaz" });
  const items = within(lanes).getAllByRole("listitem");
  expect(items).toHaveLength(2);
  expect(within(items[0]).getByRole("img", { name: "Gi0/3: down up down up" })).toBeInTheDocument();
  expect(items[0]).toHaveTextContent("▼▲▼▲");
  expect(items[1]).toHaveTextContent("sin hora");
  expect(screen.getByRole("table", { name: "Interfaces con flapping" })).toBeInTheDocument();
});

const leakRep: LeaksReport = { job: "/o/job", processes: 3, min_rounds: 3, min_growth: 1, leaks: [
  { host: "SW1", process: "BGP Router", pid: 312, rounds: 3, from_round: 1, to_round: 3, series: [10485760, 12582912, 15728640], growth: 5242880, per_hour: 2621440 },
] };

test("memoria: cada proceso trae su curva de crecimiento con descripción en texto", async () => {
  const core = fakeCore({ forensicLeaks: vi.fn(async () => leakRep) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Memoria" }));
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), "j1");
  await userEvent.click(screen.getByRole("button", { name: "Buscar fugas" }));
  const table = await screen.findByRole("table", { name: "Procesos con memoria creciente" });
  expect(within(table).getByRole("img", { name: /BGP Router.*10.*15/ })).toBeInTheDocument();
  expect(within(table).getByRole("columnheader", { name: /Curva/ })).toBeInTheDocument();
});

test("las tablas de Forense usan la tabla compartida con búsqueda", async () => {
  const core = fakeCore({ forensicLeaks: vi.fn(async () => leakRep) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Memoria" }));
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), "j1");
  await userEvent.click(screen.getByRole("button", { name: "Buscar fugas" }));
  await screen.findByRole("table", { name: "Procesos con memoria creciente" });
  await userEvent.type(screen.getByRole("textbox", { name: "Buscar en la tabla" }), "zzz");
  expect(screen.getByText("Sin filas que coincidan.")).toBeInTheDocument();
});
