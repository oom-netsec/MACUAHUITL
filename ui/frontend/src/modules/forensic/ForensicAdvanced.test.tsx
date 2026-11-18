import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ForensicView } from "./ForensicView";
import { fakeCore } from "../../lib/fake";

const det = (l: string | RegExp) => screen.getByLabelText(l).closest("details")!;
const sum = (d: HTMLElement) => d.querySelector("summary")!;
const tab = (n: string) => userEvent.click(screen.getByRole("tab", { name: n }));

test("syslog: los umbrales van plegados, cuentan y se siguen enviando", async () => {
  const core = fakeCore({ forensicPatterns: vi.fn(async () => ({ entries: 0, patterns: [], source: "", warnings: [] }) as never) });
  render(<ForensicView core={core} />);
  await tab("Syslog");
  const d = det("Ráfaga: mensajes");
  expect(d.open).toBe(false);
  expect(sum(d)).toHaveTextContent("Umbrales");
  expect(d).toContainElement(screen.getByLabelText("Ráfaga: en segundos"));
  expect(d).not.toContainElement(screen.getByLabelText("Texto (show logging o syslog)"));
  await userEvent.type(screen.getByLabelText("Texto (show logging o syslog)"), "x");
  await userEvent.type(screen.getByLabelText("Ráfaga: mensajes"), "0");
  expect(sum(d)).toHaveTextContent("Umbrales · cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Agrupar" }));
  expect(core.forensicPatterns).toHaveBeenCalledWith({ text: "x" }, 50, 60);
});

test("flapping: los umbrales van plegados, cuentan y se siguen enviando", async () => {
  const core = fakeCore({ forensicFlapping: vi.fn(async () => ({ interfaces: 0, transitions: 0, source: "", flaps: [], counter_jumps: [] }) as never) });
  render(<ForensicView core={core} />);
  await tab("Flapping");
  const d = det("Flapping: transiciones");
  expect(d.open).toBe(false);
  expect(sum(d)).toHaveTextContent("Umbrales");
  expect(d).not.toContainElement(screen.getByLabelText("Trabajo (ID o carpeta)"));
  await userEvent.type(screen.getByLabelText("Trabajo (ID o carpeta)"), "/o/j");
  await userEvent.type(screen.getByLabelText("Salto de contador: al menos"), "5");
  await userEvent.type(screen.getByLabelText("Flapping: en segundos"), "5");
  expect(sum(d)).toHaveTextContent("cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Buscar flapping" }));
  expect(core.forensicFlapping).toHaveBeenCalledWith(expect.anything(), 3, 605, 35);
});

test("debugs: ruido y umbrales van plegados; texto y botón quedan fuera; se envían", async () => {
  const core = fakeCore({ forensicDebugs: vi.fn(async () => ({ lines: 0, blank: 0, hidden: 0, noise: [], groups_total: 0, groups: [], anomalies: [] }) as never) });
  render(<ForensicView core={core} />);
  await tab("Debugs");
  const d = det("Ruido a ocultar (un texto por línea)");
  expect(d.open).toBe(false);
  expect(d).toContainElement(screen.getByLabelText("Familia frecuente: líneas"));
  expect(d).toContainElement(screen.getByLabelText("Rara: apariciones como máximo"));
  expect(d).not.toContainElement(screen.getByLabelText("Texto del debug"));
  expect(d).not.toContainElement(screen.getByRole("button", { name: "Filtrar" }));
  await userEvent.type(screen.getByLabelText("Texto del debug"), "x");
  await userEvent.type(screen.getByLabelText("Ruido a ocultar (un texto por línea)"), "ntp");
  await userEvent.type(screen.getByLabelText("Rara: apariciones como máximo"), "0");
  expect(sum(d)).toHaveTextContent("cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
  expect(core.forensicDebugs).toHaveBeenCalledWith("x", "", ["ntp"], 20, 20, 0);
});

test("memoria: rondas y crecimiento van plegados bajo Umbrales; trabajo queda fuera; se envían", async () => {
  const core = fakeCore({ forensicLeaks: vi.fn(async () => ({ processes: 0, leaks: [] }) as never) });
  render(<ForensicView core={core} />);
  await tab("Memoria");
  const d = det("Rondas seguidas sin bajar");
  expect(d.open).toBe(false);
  expect(sum(d)).toHaveTextContent("Umbrales");
  expect(d).toContainElement(screen.getByLabelText("Crecimiento mínimo (KiB)"));
  expect(d).not.toContainElement(screen.getByLabelText("Trabajo o carpeta"));
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), "/o/j");
  await userEvent.type(screen.getByLabelText("Crecimiento mínimo (KiB)"), "5");
  expect(sum(d)).toHaveTextContent("Umbrales · cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Buscar fugas" }));
  expect(core.forensicLeaks).toHaveBeenCalledWith("/o/j", "", 3, 10245);
});
