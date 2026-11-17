import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PatrolView } from "./PatrolView";
import { fakeCore } from "../../lib/fake";
import type { Job } from "../../lib/core";

const jobs: Job[] = [
  { id: "j0", name: "Respaldo activo", state: "armed", armedAt: new Date().toISOString(), outputDir: "/ev/activo" },
  { id: "j1", name: "Caso de hoy", state: "completed", finishedAt: new Date().toISOString(), outputDir: "/ev/hoy" },
  { id: "j2", name: "Caso viejo", state: "failed", finishedAt: "2026-11-10T10:00:00Z", past: true, outputDir: "/ev/viejo" },
];
const setup = (over: Record<string, unknown> = {}) => {
  const removeJobs = vi.fn(async () => ({ removed: 1, removedIds: ["j1"] }));
  const listJobs = vi.fn(async () => jobs);
  const core = fakeCore({ listJobs, removeJobs, ...over } as never);
  render(<PatrolView core={core} />);
  return { core, removeJobs, listJobs };
};
const list = () => within(screen.getByRole("region", { name: "Trabajos" }));

test("activos arriba, terminados hoy y los pasados en una sección plegada", async () => {
  const { listJobs } = setup();
  await screen.findByText("Caso de hoy");
  expect(listJobs).toHaveBeenCalledWith({ includePast: true });
  const past = screen.getByText("Trabajos pasados (1)").closest("details")!;
  expect(past).not.toHaveAttribute("open");
  expect(past).toContainElement(screen.getByText("Caso viejo"));
  expect(past).not.toContainElement(screen.getByText("Caso de hoy"));
  const names = list().getAllByRole("button").map((b) => b.textContent ?? "");
  expect(names.findIndex((n) => n.includes("Respaldo activo"))).toBeLessThan(names.findIndex((n) => n.includes("Caso de hoy")));
  expect(past).toHaveTextContent(/7 días/);
});

test("«Solo activos» oculta terminados y pasados", async () => {
  setup();
  await screen.findByText("Caso de hoy");
  await userEvent.click(screen.getByLabelText("Solo activos"));
  expect(screen.queryByText("Caso de hoy")).toBeNull();
  expect(screen.queryByText("Caso viejo")).toBeNull();
  expect(list().getByText("Respaldo activo")).toBeInTheDocument();
});

test("quitar uno: la confirmación dice que la evidencia no se borra y muestra la carpeta; cancelar no llama", async () => {
  const { removeJobs, listJobs } = setup();
  await userEvent.click(await list().findByText("Caso de hoy"));
  await userEvent.click(screen.getByRole("button", { name: "Quitar del historial" }));
  const dlg = screen.getByRole("dialog");
  expect(dlg).toHaveTextContent(/no se borra/);
  expect(dlg).toHaveTextContent("/ev/hoy");
  expect(within(dlg).getByRole("button", { name: /ruta del paquete/ })).toBeInTheDocument();
  await userEvent.click(within(dlg).getByRole("button", { name: "Cancelar" }));
  expect(removeJobs).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Quitar del historial" }));
  listJobs.mockClear();
  await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Quitar" }));
  await waitFor(() => expect(removeJobs).toHaveBeenCalledWith({ jobIds: ["j1"] }));
  await waitFor(() => expect(listJobs).toHaveBeenCalled());
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(await screen.findByLabelText("Nombre del trabajo")).toBeInTheDocument(); // el elegido se quitó: vuelve el formulario
});

test("un trabajo activo no tiene «Quitar del historial»", async () => {
  setup();
  await screen.findByText("Caso de hoy");
  expect(screen.queryByRole("button", { name: "Quitar del historial" })).toBeNull();
});

test("limpiar terminados: cuenta, carpetas de todos y llamada en bloque", async () => {
  const { removeJobs } = setup();
  await userEvent.click(await screen.findByRole("button", { name: "Limpiar terminados (2)" }));
  const dlg = screen.getByRole("dialog");
  expect(dlg).toHaveTextContent(/conserva su carpeta/);
  expect(dlg).toHaveTextContent("/ev/hoy");
  expect(dlg).toHaveTextContent("/ev/viejo");
  expect(dlg).not.toHaveTextContent("/ev/activo");
  await userEvent.click(within(dlg).getByRole("button", { name: "Quitar" }));
  await waitFor(() => expect(removeJobs).toHaveBeenCalledWith({ allFinished: true }));
});

test("si el núcleo rechaza por trabajo activo, el diálogo lo dice con los ids", async () => {
  const removeJobs = vi.fn(async () => { throw Object.assign(new Error("x"), { cause: { code: "FailedPrecondition", reason: "patrol.job_active", metadata: { job_ids: "j0" } } }); });
  setup({ removeJobs });
  await userEvent.click(await screen.findByRole("button", { name: "Limpiar terminados (2)" }));
  await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Quitar" }));
  expect(await within(screen.getByRole("dialog")).findByRole("alert")).toHaveTextContent(/activos.*j0/);
});
