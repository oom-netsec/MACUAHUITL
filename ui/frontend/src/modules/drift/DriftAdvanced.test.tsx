import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DriftView } from "./DriftView";
import { fakeCore } from "../../lib/fake";

test("drift: ronda y equipo van plegados, cuentan y se siguen enviando; el trabajo queda fuera", async () => {
  const core = fakeCore({ driftRun: vi.fn(async () => ({ dir: "", from: 1, to: 2, warnings: [], devices: [] })) });
  render(<DriftView core={core} />);
  const d = screen.getByLabelText("Ronda (0 = la última)").closest("details")!;
  expect(d.open).toBe(false);
  expect(d).toContainElement(screen.getByLabelText("Equipo (opcional)"));
  expect(d).not.toContainElement(screen.getByLabelText("Trabajo o carpeta"));
  expect(d).not.toContainElement(screen.getByRole("button", { name: "Comparar" }));
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), "/o/job");
  await userEvent.clear(screen.getByLabelText("Ronda (0 = la última)"));
  await userEvent.type(screen.getByLabelText("Ronda (0 = la última)"), "2");
  await userEvent.type(screen.getByLabelText("Equipo (opcional)"), "SW1");
  expect(d.querySelector("summary")).toHaveTextContent("cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  expect(core.driftRun).toHaveBeenCalledWith("/o/job", 2, "SW1");
});
