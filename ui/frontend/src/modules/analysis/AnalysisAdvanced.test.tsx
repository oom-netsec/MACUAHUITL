import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AnalysisView } from "./AnalysisView";
import { fakeCore } from "../../lib/fake";

const sum = (d: HTMLElement) => d.querySelector("summary")!;

test("hallazgos: la ronda va plegada, cuenta y se sigue enviando; trabajo y equipo quedan fuera", async () => {
  const core = fakeCore({ analysisRun: vi.fn(async () => ({ dir: "", devices: [], rounds: [], missing: [], warnings: [], findings: [] })) });
  render(<AnalysisView core={core} />);
  const d = screen.getByLabelText("Ronda (0 = todas)").closest("details")!;
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText("Trabajo (ID o carpeta)"));
  expect(d).not.toContainElement(screen.getByLabelText("Equipo (opcional)"));
  await userEvent.type(screen.getByLabelText("Trabajo (ID o carpeta)"), "/o/lab");
  await userEvent.clear(screen.getByLabelText("Ronda (0 = todas)"));
  await userEvent.type(screen.getByLabelText("Ronda (0 = todas)"), "2");
  expect(sum(d)).toHaveTextContent("cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  expect(core.analysisRun).toHaveBeenCalledWith("/o/lab", 2, "");
});

test("línea de tiempo: ventana y captura van plegadas, cuentan y se siguen enviando; «Alrededor de» queda fuera", async () => {
  const core = fakeCore({ analysisTimeline: vi.fn(async () => ({ events: [], warnings: [] }) as never) });
  render(<AnalysisView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: /Línea de tiempo/ }));
  const d = screen.getByLabelText("Ventana (s)").closest("details")!;
  expect(d.open).toBe(false);
  expect(d).toContainElement(screen.getByLabelText(/^Captura pcap/));
  expect(d).not.toContainElement(screen.getByLabelText(/^Alrededor de/));
  await userEvent.type(screen.getByLabelText("Trabajo (ID o carpeta)"), "/o/lab");
  await userEvent.type(screen.getByLabelText(/^Captura pcap/), "/c.pcap");
  await userEvent.clear(screen.getByLabelText("Ventana (s)"));
  await userEvent.type(screen.getByLabelText("Ventana (s)"), "60");
  expect(sum(d)).toHaveTextContent("cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Ver línea de tiempo" }));
  expect(core.analysisTimeline).toHaveBeenCalledWith("/o/lab", "", 60, "", "/c.pcap");
});
