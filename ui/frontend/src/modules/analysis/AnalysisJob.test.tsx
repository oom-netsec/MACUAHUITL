import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AnalysisView } from "./AnalysisView";
import { fakeCore } from "../../lib/fake";

const jobs = [{ id: "j-new", name: "Lab nuevo", state: "completed", finishedAt: "2026-11-17T10:00:00Z" }];
const rep = { dir: "/o", devices: [], rounds: [], missing: [], warnings: [], findings: [] };

test("análisis: la cabecera elige un trabajo y envía su ID; «Otra carpeta…» envía la ruta", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => jobs), analysisRun: vi.fn(async () => rep) });
  render(<AnalysisView core={core} />);
  await screen.findByRole("option", { name: /Lab nuevo/ });
  await userEvent.selectOptions(screen.getByLabelText("Trabajo (ID o carpeta)"), "j-new");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  expect(core.analysisRun).toHaveBeenLastCalledWith("j-new", 0, "");
  await userEvent.selectOptions(screen.getByLabelText("Trabajo (ID o carpeta)"), "Otra carpeta…");
  await userEvent.clear(screen.getByLabelText("ID o ruta del trabajo"));
  await userEvent.type(screen.getByLabelText("ID o ruta del trabajo"), "/o/lab");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  expect(core.analysisRun).toHaveBeenLastCalledWith("/o/lab", 0, "");
});
