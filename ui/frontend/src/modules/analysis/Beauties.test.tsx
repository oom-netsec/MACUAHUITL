import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AnalysisView } from "./AnalysisView";
import { CoreContext } from "../../app/activity";
import { fakeCore } from "../../lib/fake";
import type { AnalysisReport, CoreAPI, TimelineReport } from "../../lib/core";

const finding = { rule: "cpu-alta", title: "CPU alta", severity: "alta" as const, device: "SW1_10.0.0.1", round: 3, at: "2026-11-04T10:20:05Z", command: "show processes cpu sorted",
  evidence: ["CPU utilization for five seconds: 95%/4%"], detail: "5 min: 91%, \"alto\"", explanation: "x", action: "Revisa los procesos." };
const report: AnalysisReport = { dir: "/o/lab", devices: ["SW1_10.0.0.1"], rounds: [3], missing: [], warnings: [], findings: [finding] };

const withCore = (core: ReturnType<typeof fakeCore>) => render(<CoreContext.Provider value={core as unknown as CoreAPI}><AnalysisView core={core} /></CoreContext.Provider>);

test("el comando de cada hallazgo se copia con un clic", async () => {
  const core = fakeCore({ analysisRun: vi.fn(async () => report) });
  withCore(core);
  await userEvent.type(screen.getByLabelText("Trabajo (ID o carpeta)"), "/o/lab");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  await userEvent.click(await screen.findByRole("button", { name: "Copiar show processes cpu sorted" }));
  expect(core.copyText).toHaveBeenCalledWith("show processes cpu sorted");
});

test("los hallazgos se exportan a CSV y Markdown", async () => {
  const core = fakeCore({ analysisRun: vi.fn(async () => report) });
  withCore(core);
  await userEvent.type(screen.getByLabelText("Trabajo (ID o carpeta)"), "/o/lab");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  await userEvent.click(await screen.findByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "CSV (.csv)" }));
  const [name, data] = vi.mocked(core.saveFile).mock.lastCall!;
  expect(name).toBe("hallazgos.csv");
  expect(String(data).split("\n")).toEqual([
    "Severidad,Equipo,Ronda,Hallazgo,Regla,Detalle,Comando,Qué hacer",
    'Alta,SW1_10.0.0.1,3,CPU alta,cpu-alta,"5 min: 91%, ""alto""",show processes cpu sorted,Revisa los procesos.',
  ]);
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "Markdown (.md)" }));
  expect(vi.mocked(core.saveFile).mock.lastCall![0]).toBe("hallazgos.md");
});

test("la línea de tiempo es una tabla con búsqueda, hora exacta y hora relativa", async () => {
  const tl: TimelineReport = { dir: "/o/lab", warnings: [], events: [
    { at: "2026-11-04T10:09:18.64Z", source: "log-equipo", device: "RTR2", severity: "baja", text: "%BGP-5-ADJCHANGE: neighbor Down" },
    { at: "2026-11-04T10:09:19Z", source: "syslog", device: "RTR2", text: "otro evento" },
  ] };
  const core = fakeCore({ analysisTimeline: vi.fn(async () => tl) });
  withCore(core);
  await userEvent.click(screen.getByRole("tab", { name: "Línea de tiempo" }));
  await userEvent.type(screen.getByLabelText("Trabajo (ID o carpeta)"), "/o/lab");
  await userEvent.click(screen.getByRole("button", { name: "Ver línea de tiempo" }));
  const table = await screen.findByRole("table", { name: "Línea de tiempo" });
  const rows = within(table).getAllByRole("row");
  expect(rows).toHaveLength(3);
  expect(within(rows[1]).getAllByRole("cell")[0]).toHaveTextContent(/2026-11-04T10:09:18\.64Z.*hace/);
  await userEvent.type(screen.getByRole("textbox", { name: "Buscar en la tabla" }), "otro");
  expect(within(table).getAllByRole("row")).toHaveLength(2);
});
