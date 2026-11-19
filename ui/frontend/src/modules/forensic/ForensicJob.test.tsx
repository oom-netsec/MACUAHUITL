import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ForensicView } from "./ForensicView";
import { fakeCore } from "../../lib/fake";

const jobs = [{ id: "j-new", name: "Lab nuevo", state: "completed", finishedAt: "2026-11-17T10:00:00Z" }];
const prep = { kb: {}, source: "", entries: 0, with_time: 0, patterns: [], burst_count: 5, burst_window: "1m0s", warnings: [], stats: { lines: 0, parsed: 0, with_time: 0, skipped: 0 } };
const leaks = { job: "j-new", processes: 0, min_rounds: 3, min_growth: 1, warnings: [], leaks: [] };

test("forense, fuente «trabajo»: elige el trabajo y envía su ID con el equipo; «Otra carpeta…» envía la ruta", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => jobs), forensicPatterns: vi.fn(async () => prep as never) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Syslog" }));
  await userEvent.selectOptions(screen.getByLabelText("Fuente"), "job");
  await screen.findByRole("option", { name: /Lab nuevo/ });
  await userEvent.selectOptions(screen.getByLabelText("Trabajo (ID o carpeta)"), "j-new");
  await userEvent.type(screen.getByLabelText("Equipo (opcional)"), "sw1");
  await userEvent.click(screen.getByRole("button", { name: "Agrupar" }));
  expect(core.forensicPatterns).toHaveBeenLastCalledWith({ job: "j-new", device: "sw1" }, 5, 60);
  await userEvent.selectOptions(screen.getByLabelText("Trabajo (ID o carpeta)"), "Otra carpeta…");
  await userEvent.clear(screen.getByLabelText("ID o ruta del trabajo"));
  await userEvent.type(screen.getByLabelText("ID o ruta del trabajo"), "/o/j");
  await userEvent.click(screen.getByRole("button", { name: "Agrupar" }));
  expect(core.forensicPatterns).toHaveBeenLastCalledWith({ job: "/o/j", device: "sw1" }, 5, 60);
});

test("forense, Memoria: elegir un trabajo envía su ID", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => jobs), forensicLeaks: vi.fn(async () => leaks as never) });
  render(<ForensicView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Memoria" }));
  await screen.findByRole("option", { name: /Lab nuevo/ });
  await userEvent.selectOptions(screen.getByLabelText("Trabajo o carpeta"), "j-new");
  await userEvent.click(screen.getByRole("button", { name: "Buscar fugas" }));
  expect(core.forensicLeaks).toHaveBeenLastCalledWith("j-new", "", 3, 1024);
});
