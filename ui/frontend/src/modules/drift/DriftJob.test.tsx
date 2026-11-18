import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DriftView } from "./DriftView";
import { fakeCore } from "../../lib/fake";

const jobs = [
  { id: "j-old", name: "Lab viejo", state: "completed", finishedAt: "2026-11-10T10:00:00Z" },
  { id: "j-new", name: "Lab nuevo", state: "armed", armedAt: "2026-11-17T10:00:00Z" },
];
async function setup() {
  const core = fakeCore({ listJobs: vi.fn(async () => jobs), driftRun: vi.fn(async () => ({ dir: "/o", from: 1, to: 2, warnings: [], devices: [] })) });
  render(<DriftView core={core} />);
  await screen.findByRole("option", { name: /Lab nuevo/ });
  return core;
}

test("drift: «Trabajo o carpeta» lista los trabajos recientes primero y «Otra carpeta…»", async () => {
  await setup();
  const names = within(screen.getByLabelText("Trabajo o carpeta")).getAllByRole("option").map((o) => o.textContent?.split(" · ")[0]);
  expect(names).toEqual(["Seleccionar…", "Lab nuevo", "Lab viejo", "Otra carpeta…"]);
});

test("drift: elegir un trabajo envía su ID, igual que escribirlo", async () => {
  const core = await setup();
  await userEvent.selectOptions(screen.getByLabelText("Trabajo o carpeta"), "j-new");
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  expect(core.driftRun).toHaveBeenLastCalledWith("j-new", 0, "");
});

test("drift: «Otra carpeta…» envía la ruta escrita, recortada como antes", async () => {
  const core = await setup();
  await userEvent.selectOptions(screen.getByLabelText("Trabajo o carpeta"), "Otra carpeta…");
  await userEvent.type(screen.getByLabelText("ID o ruta del trabajo"), " /o/job ");
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  expect(core.driftRun).toHaveBeenLastCalledWith("/o/job", 0, "");
});
