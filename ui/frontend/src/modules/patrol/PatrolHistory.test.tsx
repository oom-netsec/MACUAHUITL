import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PatrolView } from "./PatrolView";
import { fakePatrol } from "./fake";
import { fakeCore } from "../../lib/fake";
import type { Job } from "../../lib/core";

const now = new Date().toISOString();
const jobs: Job[] = [
  { id: "j0", name: "Respaldo activo", state: "armed", kind: "backup", armedAt: now, outputDir: "/ev/activo" },
  { id: "j1", name: "Caso de hoy", state: "completed", kind: "patrol", finishedAt: now, outputDir: "/ev/hoy" },
  { id: "j2", name: "Caso viejo", state: "failed", kind: "patrol", finishedAt: "2026-11-10T10:00:00Z", past: true, outputDir: "/ev/viejo" },
  { id: "j3", name: "Sin armar", state: "created", kind: "backup", outputDir: "/ev/sin-armar" },
];
const setup = (list: Job[] = jobs, over: Record<string, unknown> = {}) => {
  const patrol = fakePatrol(list);
  const core = fakeCore({ ...patrol, ...over } as never);
  render(<PatrolView core={core} />);
  return patrol;
};
const list = () => within(screen.getByRole("region", { name: "Trabajos" }));
const openPast = () => userEvent.click(screen.getByText(/Trabajos pasados/));
const dialog = () => within(screen.getByRole("dialog"));

test("activos arriba y los pasados en una sección plegada que no monta su contenido hasta abrirse", async () => {
  const p = setup();
  await screen.findByText("Caso de hoy");
  expect(p.listJobs).toHaveBeenCalledWith({ includePast: true });
  const det = screen.getByText("Trabajos pasados (1)").closest("details")!;
  expect(det).not.toHaveAttribute("open");
  expect(screen.queryByText("Caso viejo")).toBeNull();
  const names = list().getAllByRole("button").map((b) => b.textContent ?? "");
  expect(names.findIndex((n) => n.includes("Respaldo activo"))).toBeLessThan(names.findIndex((n) => n.includes("Caso de hoy")));
  await openPast();
  expect(det).toHaveAttribute("open");
  expect(det).toContainElement(screen.getByText("Caso viejo"));
  expect(det).toHaveTextContent(/7 días/);
});

test("con un trabajo pasado elegido, la sección se puede plegar de nuevo", async () => {
  setup();
  await screen.findByText("Caso de hoy");
  await openPast();
  await userEvent.click(screen.getByText("Caso viejo"));
  await openPast();
  expect(screen.getByText(/Trabajos pasados/).closest("details")).not.toHaveAttribute("open");
  expect(list().queryByText("Caso viejo")).toBeNull();
});

test("«Solo activos» muestra solo los vivos: no los terminados, pasados ni sin armar", async () => {
  setup();
  await screen.findByText("Caso de hoy");
  await userEvent.click(screen.getByLabelText("Solo activos"));
  expect(screen.queryByText("Caso de hoy")).toBeNull();
  expect(screen.queryByText("Sin armar")).toBeNull();
  expect(screen.queryByText(/Trabajos pasados/)).toBeNull();
  expect(list().getByText("Respaldo activo")).toBeInTheDocument();
});

test("filtros combinados: tipo + solo activos; lista vacía dice que no hay con ese filtro; el conteo de limpiar sigue lo visible", async () => {
  setup();
  await screen.findByText("Caso de hoy");
  expect(screen.getByRole("button", { name: "Limpiar terminados (3)" })).toBeInTheDocument(); // hoy, sin armar y el pasado
  await userEvent.click(screen.getByRole("radio", { name: "Patrol" }));
  expect(screen.getByRole("button", { name: "Limpiar terminados (2)" })).toBeInTheDocument(); // hoy y pasado
  await userEvent.click(screen.getByLabelText("Solo activos"));
  expect(list().getByText("No hay trabajos con este filtro.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Limpiar terminados (0)" })).toBeDisabled();
});

test("quitar uno: confirmación con carpeta; cancelar no llama; al confirmar desaparece, vuelve el formulario y el foco va a «Nuevo trabajo»", async () => {
  const p = setup();
  await userEvent.click(await list().findByText("Caso de hoy"));
  await userEvent.click(screen.getByRole("button", { name: "Quitar del historial" }));
  expect(dialog().getByText(/no se borra/)).toBeInTheDocument();
  expect(screen.getByRole("dialog")).toHaveTextContent("/ev/hoy");
  expect(dialog().getByRole("button", { name: "Copiar carpeta de evidencia de Caso de hoy" })).toBeInTheDocument();
  await userEvent.click(dialog().getByRole("button", { name: "Cancelar" }));
  expect(p.removeJobs).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Quitar del historial" }));
  await userEvent.click(dialog().getByRole("button", { name: "Quitar" }));
  await waitFor(() => expect(p.removeJobs).toHaveBeenCalledWith({ jobIds: ["j1"] }));
  expect(await screen.findByLabelText("Nombre del trabajo")).toBeInTheDocument();
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(list().queryByText("Caso de hoy")).toBeNull();
  await waitFor(() => expect(screen.getByRole("button", { name: "Nuevo trabajo" })).toHaveFocus());
});

test("un trabajo sin armar se puede quitar; uno armado no", async () => {
  setup();
  await userEvent.click(await list().findByText("Sin armar"));
  expect(screen.getByRole("button", { name: "Quitar del historial" })).toBeInTheDocument();
  await userEvent.click(list().getByText("Respaldo activo"));
  expect(screen.queryByRole("button", { name: "Quitar del historial" })).toBeNull();
});

test("un trabajo sin carpeta registrada lo dice y no promete «sigue en esta carpeta»", async () => {
  setup([{ id: "j1", name: "Sin ruta", state: "completed", finishedAt: now }]);
  await userEvent.click(await list().findByText("Sin ruta"));
  await userEvent.click(screen.getByRole("button", { name: "Quitar del historial" }));
  const d = screen.getByRole("dialog");
  expect(d).toHaveTextContent("no hay carpeta de salida registrada");
  expect(d).not.toHaveTextContent(/Sigue en esta carpeta/);
  expect(within(d).queryByRole("button", { name: /Copiar/ })).toBeNull();
});

test("con la llamada en curso el diálogo no se cierra: Cancelar deshabilitado y Escape ignorado", async () => {
  let done!: (r: { removed: number; removedIds: string[] }) => void;
  const removeJobs = vi.fn(() => new Promise<{ removed: number; removedIds: string[] }>((r) => { done = r; }));
  setup(jobs, { removeJobs });
  await userEvent.click(await list().findByText("Caso de hoy"));
  await userEvent.click(screen.getByRole("button", { name: "Quitar del historial" }));
  await userEvent.click(dialog().getByRole("button", { name: "Quitar" }));
  expect(dialog().getByRole("button", { name: "Cancelar" })).toBeDisabled();
  await userEvent.keyboard("{Escape}");
  expect(screen.getByRole("dialog")).toBeInTheDocument();
  await act(async () => done({ removed: 1, removedIds: ["j1"] }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
});

test("limpiar terminados manda exactamente los ids que mostró el diálogo (incluido el pasado), sin allFinished", async () => {
  const p = setup();
  await userEvent.click(await screen.findByRole("button", { name: "Limpiar terminados (3)" }));
  const d = screen.getByRole("dialog");
  expect(d).toHaveTextContent(/conserva su carpeta/);
  for (const dir of ["/ev/hoy", "/ev/viejo", "/ev/sin-armar"]) expect(d).toHaveTextContent(dir);
  expect(d).not.toHaveTextContent("/ev/activo");
  await userEvent.click(dialog().getByRole("button", { name: "Quitar" }));
  await waitFor(() => expect(p.removeJobs).toHaveBeenCalledWith({ jobIds: ["j3", "j1", "j2"] }));
  expect(await screen.findByRole("button", { name: "Limpiar terminados (0)" })).toBeDisabled();
});

test("limpiar con un terminado seleccionado vuelve al formulario", async () => {
  setup();
  await userEvent.click(await list().findByText("Caso de hoy"));
  await userEvent.click(screen.getByRole("button", { name: "Limpiar terminados (3)" }));
  await userEvent.click(dialog().getByRole("button", { name: "Quitar" }));
  expect(await screen.findByLabelText("Nombre del trabajo")).toBeInTheDocument();
});

test("skipped: el diálogo sigue abierto y dice por nombre y motivo; un id desconocido y un motivo nuevo tienen respaldo", async () => {
  const removeJobs = vi.fn(async () => ({ removed: 1, removedIds: ["j1"], skipped: [
    { jobId: "j3", reason: "change_pre" }, { jobId: "j2", reason: "adhoc_unread" }, { jobId: "zz", reason: "raro" }] }));
  setup(jobs, { removeJobs });
  await userEvent.click(await screen.findByRole("button", { name: "Limpiar terminados (3)" }));
  await userEvent.click(dialog().getByRole("button", { name: "Quitar" }));
  const d = await screen.findByRole("dialog");
  await waitFor(() => expect(d).toHaveTextContent("No se quitaron 3 trabajos:"));
  expect(d).toHaveTextContent("Sin armar: es el estado previo de un cambio");
  expect(d).toHaveTextContent("Caso viejo: su resultado ad hoc aún no se ha leído");
  expect(d).toHaveTextContent("zz: el núcleo no lo pudo quitar (raro)");
  expect(d).not.toHaveTextContent("j3");
});

// 46c2: un trabajo created cuyo arranque falló muestra el motivo y deja Login Test, Armar (directo) y Quitar.
test("arranque fallido: estado «No arrancó», motivo de la última fase y Armar sin Login Test previo", async () => {
  const failed: Job = { id: "jf", name: "Adhoc caído", state: "created", kind: "adhoc", phases: [
    { at: now, kind: "JOB_PHASE_KIND_CREATED" },
    { at: now, kind: "JOB_PHASE_KIND_ARM_FAILED", reason: "patrol.svc.no_devices_left", detail: "no quedan equipos" },
  ] };
  const armJob = vi.fn(async () => ({ windowEndsAt: now, missingInhibitors: [] }));
  setup([failed, jobs[3]], { armJob });
  await userEvent.click(await list().findByText("Adhoc caído"));
  expect(list().getByText("No arrancó")).toBeInTheDocument();
  expect(list().getByText("Creado")).toBeInTheDocument(); // un created normal no cambia
  const detail = within(screen.getByRole("region", { name: "Adhoc caído" }));
  expect(detail.getByText("No arrancó")).toBeInTheDocument();
  expect(detail.getByRole("status")).toHaveTextContent("No se pudo arrancar: no quedan equipos. Resuelve el motivo");
  expect(detail.queryByRole("alert")).toBeNull(); // estado del trabajo, no una alerta en cada selección
  expect(detail.getAllByText("No arrancó (antes de armar)").length).toBe(1); // la fase en la línea de tiempo
  expect(detail.getByRole("button", { name: "Ejecutar Login Test" })).toBeInTheDocument();
  expect(detail.getByRole("button", { name: "Quitar del historial" })).toBeInTheDocument();
  await userEvent.click(detail.getByRole("button", { name: "Armar trabajo" }));
  await waitFor(() => expect(armJob).toHaveBeenCalledWith("jf", [], [], []));
});

test("arranque fallido sin motivo: texto de respaldo, sin «: .»; el aviso se oculta mientras se reintenta", async () => {
  const j: Job = { id: "jh", name: "Sin motivo", state: "created", kind: "adhoc", phases: [{ at: now, kind: "JOB_PHASE_KIND_ARM_FAILED" }] };
  let finish: (v: unknown) => void = () => {};
  const armJob = vi.fn(() => new Promise((r) => { finish = r; }));
  setup([j], { armJob });
  await userEvent.click(await list().findByText("Sin motivo"));
  const detail = within(screen.getByRole("region", { name: "Sin motivo" }));
  expect(detail.getByRole("status")).toHaveTextContent(/^No se pudo arrancar\. Resuelve/);
  await userEvent.click(detail.getByRole("button", { name: "Armar trabajo" }));
  expect(screen.queryByText(/No se pudo arrancar/)).toBeNull();
  await act(async () => finish({ windowEndsAt: now, missingInhibitors: [] }));
});

test("un created que falló antes y luego tiene otra fase ya no se marca como fallido", async () => {
  const j: Job = { id: "jg", name: "Reintentado", state: "created", kind: "adhoc", phases: [
    { at: now, kind: "JOB_PHASE_KIND_ARM_FAILED", detail: "dial tcp: timeout" },
    { at: now, kind: "JOB_PHASE_KIND_LOGIN_TEST_DONE" },
  ] };
  setup([j]);
  await userEvent.click(await list().findByText("Reintentado"));
  expect(list().getByText("Creado")).toBeInTheDocument();
  expect(screen.queryByText(/No se pudo arrancar/)).toBeNull();
  expect(screen.queryByRole("button", { name: "Armar trabajo" })).toBeNull();
});
