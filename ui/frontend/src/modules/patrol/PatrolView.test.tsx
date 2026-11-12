import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PatrolView, parseTargets } from "./PatrolView";
import { DeviceGrid } from "./DeviceGrid";
import { activeMs, elapsed } from "./format";
import { fakeCore } from "../../lib/fake";

test("parseTargets normaliza comas, espacios, saltos y CIDR sin duplicados", () => {
  expect(parseTargets("10.0.0.1, 10.0.0.2\n10.0.1.0/30  sw1\n10.0.0.1")).toEqual(["10.0.0.1", "10.0.0.2", "10.0.1.0/30", "sw1"]);
  expect(parseTargets("  \n , ")).toEqual([]);
});

test("elapsed resume duraciones de forma legible", () => {
  const t = (s: number) => elapsed(s * 1000);
  expect(t(20)).toBe("< 1 min");
  expect(t(5 * 60)).toBe("5 min");
  expect(t(2 * 3600 + 15 * 60)).toBe("2 h 15 min");
  expect(t(26 * 3600)).toBe("1 d 2 h");
});

const creds = [{ id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false }];
const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();

async function fillForm(core: ReturnType<typeof fakeCore>) {
  render(<PatrolView core={core} />);
  await userEvent.type(await screen.findByLabelText("Nombre del trabajo"), "caso-1");
  await userEvent.type(screen.getByLabelText("Equipos"), "10.0.0.1 10.0.0.2");
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.type(screen.getByLabelText("Comandos"), "show version");
  await userEvent.type(screen.getByLabelText("Carpeta de salida"), "/home/u/out");
}

test("valores por defecto seguros y aviso al apagar el enmascarado", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  render(<PatrolView core={core} />);
  const mask = await screen.findByLabelText("Enmascarar secretos en las salidas");
  const accept = screen.getByLabelText("Aceptar llaves de host cambiadas en rondas desatendidas");
  expect(mask).toBeChecked();
  expect(accept).not.toBeChecked();
  await userEvent.click(mask);
  expect(screen.getByRole("alert")).toHaveTextContent(/incluirán los secretos/);
  await userEvent.click(accept);
  expect(screen.getAllByRole("alert").some((a) => /intermediario/.test(a.textContent ?? ""))).toBe(true);
});

test("no crea el trabajo si faltan datos y dice cuáles", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  render(<PatrolView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Crear trabajo" }));
  expect(screen.getByRole("alert")).toHaveTextContent("Datos incompletos: nombre del trabajo, equipos, credencial, un playbook o comandos, carpeta de salida.");
  expect(core.createJob).not.toHaveBeenCalled();
});

test("la carpeta de salida se elige con el diálogo nativo de carpetas", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), pickPath: vi.fn(async () => "/home/u/evidencia") });
  render(<PatrolView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Examinar… Carpeta de salida" }));
  expect(core.pickPath).toHaveBeenCalledWith(expect.objectContaining({ directory: true }));
  expect(screen.getByLabelText("Carpeta de salida")).toHaveValue("/home/u/evidencia");
});

test("crear y ejecutar el Login Test son pasos separados; armar con avisos", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    listJobs: vi.fn(async () => [{ id: "j1", name: "caso-1", state: "created", phases: [{ at: ago(0), kind: "JOB_PHASE_KIND_CREATED" }] }]),
    loginTest: vi.fn(async () => [
      { target: "10.0.0.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "llave desconocida", platform: "", fingerprint: "SHA256:abc" },
      { target: "10.0.0.2:22", passed: true, failedStep: "", detail: "", platform: "ios-xe", fingerprint: "" },
    ]),
    armJob: vi.fn(async () => ({ windowEndsAt: "2026-11-04T10:00:00Z", missingInhibitors: ["sleep"] })),
  });
  await fillForm(core);
  await userEvent.click(screen.getByRole("button", { name: "Crear trabajo" }));
  await waitFor(() => expect(core.createJob).toHaveBeenCalled());
  const spec = vi.mocked(core.createJob).mock.calls[0][0];
  expect(spec.targets.map((t: { address: string }) => t.address)).toEqual(["10.0.0.1", "10.0.0.2"]);
  expect(spec.disableMasking).toBe(false);
  expect(spec.acceptChangedHostKeys).toBe(false);

  expect(await screen.findByRole("heading", { name: "caso-1" })).toBeInTheDocument();
  expect(within(screen.getByRole("list", { name: "Fases" })).getByText("Trabajo creado")).toBeInTheDocument();
  expect(core.loginTest).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar Login Test" }));
  await waitFor(() => expect(core.loginTest).toHaveBeenCalledWith("j1"));

  const row = await screen.findByRole("row", { name: /10\.0\.0\.1:22/ });
  expect(within(row).getByText(/Llave de host/)).toBeInTheDocument();
  await userEvent.click(within(row).getByLabelText("Confiar en SHA256:abc"));
  expect(screen.getByText(/permanecerá en memoria/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Armar trabajo" }));
  await waitFor(() => expect(core.armJob).toHaveBeenCalledWith("j1", ["SHA256:abc"], []));
  expect(await screen.findByText(/podría suspenderse/)).toBeInTheDocument();
  expect(core.subscribe).toHaveBeenCalledWith(["j1"]);
});

test("el panel de trabajos muestra estado, tiempo, ronda y equipos", async () => {
  const core = fakeCore({
    listJobs: vi.fn(async () => [
      { id: "j9", name: "nocturno", state: "armed", armedAt: ago(135), round: 2, rounds: 6, devicesTotal: 10, devicesOk: 8, devicesFailed: 1 },
      { id: "j8", name: "previo", state: "completed" },
    ]),
  });
  render(<PatrolView core={core} />);
  const panel = await screen.findByRole("region", { name: "Trabajos" });
  const job = await within(panel).findByRole("button", { name: /nocturno/ });
  expect(job).toHaveTextContent("Armado");
  expect(job).toHaveTextContent("2 h 15 min");
  expect(job).toHaveTextContent("Ronda 2 de 6");
  expect(job).toHaveTextContent("correctos: 8 · con fallas: 1 · 10 equipos");
  expect(within(panel).getByRole("button", { name: /previo/ })).toHaveTextContent("Finalizado");
  expect(core.subscribe).toHaveBeenCalledWith(["j9"]);
});

test("la línea de fases combina el historial y los eventos en vivo", async () => {
  const core = fakeCore({
    listJobs: vi.fn(async () => [{
      id: "j9", name: "nocturno", state: "armed", armedAt: ago(10), round: 1, rounds: 0,
      phases: [
        { at: ago(12), kind: "JOB_PHASE_KIND_CREATED" },
        { at: ago(11), kind: "JOB_PHASE_KIND_LOGIN_TEST_DONE", detail: "2 correctos, 0 con fallas" },
        { at: ago(10.5), kind: "JOB_PHASE_KIND_ARM_CHECK_DONE", detail: "2 correctos, 0 con fallas" },
        { at: ago(10), kind: "JOB_PHASE_KIND_ARMED" },
        { at: ago(9), kind: "JOB_PHASE_KIND_ROUND_FINISHED", round: 1, detail: "2 correctos, 0 con fallas" },
      ],
    }]),
  });
  render(<PatrolView core={core} />);
  const phases = await screen.findByRole("list", { name: "Fases" });
  expect(within(phases).getByText("Login Test completado")).toBeInTheDocument();
  expect(within(phases).getByText("Login Test al armar")).toBeInTheDocument();
  expect(within(phases).getAllByText("2 correctos, 0 con fallas")).toHaveLength(3);
  expect(within(phases).getByText("Ronda 1 finalizada")).toBeInTheDocument();
  expect(screen.getByText("Hasta el fin de la ventana")).toBeInTheDocument();
  act(() => core.emitEvent({ jobId: "j9", phaseAdded: { at: new Date().toISOString(), kind: "JOB_PHASE_KIND_ROUND_STARTED", round: 2 } }));
  expect(within(phases).getByText("Ronda 2 iniciada")).toBeInTheDocument();
});

test("si la bóveda no existe, Patrol lo indica y lleva a crearla", async () => {
  const core = fakeCore({ vaultStatus: vi.fn(async () => ({ state: "absent" as const, armedJobs: [] })) });
  render(<PatrolView core={core} />);
  expect(await screen.findByRole("status")).toHaveTextContent("No existe una bóveda");
  expect(screen.getByRole("button", { name: "Crear bóveda" })).toBeInTheDocument();
});

test("la grilla virtualiza 1000 equipos y un evento actualiza solo su fila", async () => {
  const core = fakeCore();
  const devices = Array.from({ length: 1000 }, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250}:22`);
  render(<DeviceGrid core={core} jobId="j1" devices={devices} />);
  expect(screen.getAllByRole("row").length).toBeLessThan(50);
  expect(screen.queryByRole("columnheader", { name: "Progreso" })).not.toBeInTheDocument(); // sin datos de avance no hay columna
  act(() => core.emitEvent({ jobId: "j1", deviceStateChanged: { deviceId: devices[0], state: "DEVICE_STATE_RUNNING" } }));
  act(() => core.emitEvent({ jobId: "j1", commandProgress: { deviceId: devices[0], command: "show version", index: 1, total: 3 } }));
  const row = screen.getByRole("row", { name: new RegExp(devices[0].replace(/\./g, "\\.")) });
  expect(within(row).getByText("Ejecutando")).toBeInTheDocument();
  expect(within(row).getByText("1/3 show version")).toBeInTheDocument();
  expect(screen.getByRole("columnheader", { name: "Progreso" })).toBeInTheDocument();
  act(() => core.emitEvent({ jobId: "otro", deviceStateChanged: { deviceId: devices[1], state: "DEVICE_STATE_FAILED" } }));
  expect(screen.queryByText("Fallido")).not.toBeInTheDocument();
});

test("al reabrir con un trabajo armado se selecciona y se ve su grilla", async () => {
  const core = fakeCore({
    listJobs: vi.fn(async () => [{ id: "j9", name: "nocturno", state: "armed" }]),
    getRun: vi.fn(async () => [{ target: "10.0.0.5:22", state: "DEVICE_STATE_COMPLETED", detail: "" }]),
  });
  render(<PatrolView core={core} />);
  expect(await screen.findByRole("heading", { name: "nocturno" })).toBeInTheDocument();
  const row = await screen.findByRole("row", { name: /10\.0\.0\.5:22/ });
  expect(within(row).getByText("Completado")).toBeInTheDocument();
});

test("si el Login Test falla se puede repetir o cancelar el trabajo", async () => {
  let calls = 0;
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    listJobs: vi.fn(async () => [{ id: "j1", name: "caso-1", state: "created" }]),
    loginTest: vi.fn(async () => {
      if (calls++ === 0) throw new Error("rpc error: code = DeadlineExceeded desc = tardó demasiado");
      return [{ target: "10.0.0.1:22", passed: true, failedStep: "", detail: "", platform: "ios-xe", fingerprint: "" }];
    }),
  });
  await fillForm(core);
  await userEvent.click(screen.getByRole("button", { name: "Crear trabajo" }));
  await userEvent.click(await screen.findByRole("button", { name: "Ejecutar Login Test" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("tardó demasiado");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar Login Test" }));
  expect(await screen.findByRole("button", { name: "Armar trabajo" })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Cancelar trabajo" }));
  expect(core.cancelJob).not.toHaveBeenCalled(); // cancelar pide una segunda confirmación
  await userEvent.click(screen.getByRole("button", { name: "Confirmar cancelación" }));
  await waitFor(() => expect(core.cancelJob).toHaveBeenCalledWith("j1"));
});

test("con los datos reales del núcleo: sin próxima ronda pasada ni conteos antes de la primera ronda", async () => {
  const ahead = new Date(Date.now() + 30 * 60_000).toISOString();
  const core = fakeCore({
    listJobs: vi.fn(async () => [
      { id: "j1", name: "en-curso", state: "armed", armedAt: ago(5), nextRoundAt: ago(1), windowEndsAt: ahead, round: 1, rounds: 3, devicesTotal: 4, devicesOk: 1, devicesFailed: 0, outputDir: "/o", phases: [] },
      { id: "j2", name: "nuevo", state: "created", armedAt: "", nextRoundAt: "", windowEndsAt: "", round: 0, rounds: 1, devicesTotal: 2, devicesOk: 0, devicesFailed: 0, outputDir: "", phases: [] },
    ]),
  });
  render(<PatrolView core={core} />);
  expect(await screen.findByRole("heading", { name: "en-curso" })).toBeInTheDocument();
  expect(screen.queryByText("Próxima ronda")).not.toBeInTheDocument();
  expect(screen.getByText("Fin de la ventana")).toBeInTheDocument();
  const panel = screen.getByRole("region", { name: "Trabajos" });
  expect(within(panel).getByRole("button", { name: /nuevo/ })).not.toHaveTextContent("equipos");
});

test("la lista ordena activos primero y luego por actividad reciente", async () => {
  const core = fakeCore({
    listJobs: vi.fn(async () => [
      { id: "a", name: "viejo", state: "completed", phases: [{ at: ago(300), kind: "JOB_PHASE_KIND_COMPLETED" }] },
      { id: "b", name: "reciente", state: "completed", phases: [{ at: ago(10), kind: "JOB_PHASE_KIND_COMPLETED" }] },
      { id: "c", name: "armado", state: "armed", phases: [{ at: ago(60), kind: "JOB_PHASE_KIND_ARMED" }] },
      { id: "d", name: "borrador", state: "created", phases: [{ at: ago(1), kind: "JOB_PHASE_KIND_CREATED" }] },
    ]),
  });
  render(<PatrolView core={core} />);
  const panel = await screen.findByRole("region", { name: "Trabajos" });
  await within(panel).findByText("viejo");
  const names = within(panel).getAllByRole("button", { name: /viejo|reciente|armado|borrador/ }).map((b) => b.textContent?.match(/^(viejo|reciente|armado|borrador)/)?.[1]);
  expect(names).toEqual(["armado", "borrador", "reciente", "viejo"]);
});

test("se eligen playbooks del catálogo y van en playbookIds; sin comandos pegados también vale", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  render(<PatrolView core={core} />);
  await userEvent.type(await screen.findByLabelText("Nombre del trabajo"), "caso-2");
  await userEvent.type(screen.getByLabelText("Equipos"), "10.0.0.1");
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.click(await screen.findByRole("checkbox", { name: "STP" }));
  await userEvent.type(screen.getByLabelText("Carpeta de salida"), "/home/u/out");
  await userEvent.click(screen.getByRole("button", { name: "Crear trabajo" }));
  await waitFor(() => expect(core.createJob).toHaveBeenCalled());
  expect(vi.mocked(core.createJob).mock.calls[0][0]).toMatchObject({ playbookIds: ["ios-xe/l2-stp"], customCommands: "" });
});

test("si el núcleo no da el catálogo, se avisa y los comandos pegados siguen funcionando", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), listPlaybooks: vi.fn().mockRejectedValue(new Error("unimplemented")) });
  await fillForm(core);
  expect(await screen.findByText(/No se pudo leer el catálogo/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Crear trabajo" }));
  await waitFor(() => expect(core.createJob).toHaveBeenCalled());
});

test("el catálogo que falló se puede reintentar", async () => {
  const listPlaybooks = vi.fn().mockRejectedValueOnce(new Error("núcleo arrancando")).mockResolvedValue([{ id: "ios-xe/l2-stp", platform: "ios-xe", name: "L2 · STP", commands: [] }]);
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), listPlaybooks });
  render(<PatrolView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Reintentar" }));
  expect(await screen.findByRole("checkbox", { name: "STP" })).toBeInTheDocument();
});

test("el tiempo activo se detiene en la fase de cierre", () => {
  const phases = [{ at: "2026-11-12T10:42:00Z", kind: "JOB_PHASE_KIND_COMPLETED" }];
  expect(activeMs("2026-11-12T10:40:00Z", "completed", phases, Date.parse("2026-11-12T12:00:00Z"))).toBe(120_000);
  expect(activeMs("2026-11-12T10:40:00Z", "armed", [], Date.parse("2026-11-12T10:50:00Z"))).toBe(600_000);
});

test("un equipo se cuenta en singular", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => [{ id: "j1", name: "uno", state: "completed", round: 1, devicesTotal: 1, devicesOk: 1, devicesFailed: 0 }]) });
  render(<PatrolView core={core} />);
  const panel = await screen.findByRole("region", { name: "Trabajos" });
  expect(await within(panel).findByRole("button", { name: /uno/ })).toHaveTextContent("correctos: 1 · con fallas: 0 · 1 equipo");
  expect(panel).not.toHaveTextContent("1 equipos");
});

test("filtra la lista por tipo de trabajo", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => [
    { id: "a", name: "uno-adhoc", state: "completed", kind: "adhoc" },
    { id: "b", name: "dos-resp", state: "completed", kind: "backup" },
  ]) });
  render(<PatrolView core={core} />);
  const panel = await screen.findByRole("region", { name: "Trabajos" });
  await within(panel).findByRole("button", { name: /uno-adhoc/ });
  expect(within(panel).getByLabelText("Todos")).toBeChecked();
  await userEvent.click(within(panel).getByLabelText("Respaldo"));
  expect(within(panel).queryByRole("button", { name: /uno-adhoc/ })).toBeNull();
  expect(within(panel).getByRole("button", { name: /dos-resp/ })).toBeInTheDocument();
});

test("la grilla aparece cuando un trabajo seleccionado pasa a armado", async () => {
  let state = "created";
  const core = fakeCore({
    listJobs: vi.fn(async () => [{ id: "j1", name: "nocturno", state, round: 1, rounds: 0 }]),
    getRun: vi.fn(async () => [{ target: "10.0.0.1", state: "DEVICE_STATE_RUNNING", detail: "" }]),
  });
  render(<PatrolView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: /nocturno/ }));
  expect(screen.queryByText("10.0.0.1")).toBeNull();
  state = "armed";
  act(() => core.emitEvent({ jobId: "j1", jobStateChanged: { state: "armed" } }));
  expect(await screen.findByText("10.0.0.1")).toBeInTheDocument();
});

test("un evento de fase repetido por la suscripción no duplica la línea", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => [{ id: "j9", name: "n", state: "armed", armedAt: ago(5), round: 2, rounds: 0, phases: [] }]) });
  render(<PatrolView core={core} />);
  await screen.findByText("Activo: 5 min"); // lista cargada
  const ev = { jobId: "j9", phaseAdded: { at: ago(1), kind: "JOB_PHASE_KIND_ROUND_STARTED", round: 2 } };
  act(() => core.emitEvent(ev));
  act(() => core.emitEvent(ev));
  const phases = await screen.findByRole("list", { name: "Fases" });
  expect(within(phases).getAllByText("Ronda 2 iniciada")).toHaveLength(1);
});

test("la grilla de un trabajo armado sale de la ronda anterior si la actual va vacía y no se borra al empezar otra ronda", async () => {
  let round = 2;
  const getRun = vi.fn(async (_id: string, r: number) => (r === 1 ? [{ target: "10.0.0.7:22", state: "DEVICE_STATE_COMPLETED", detail: "" }] : []));
  const core = fakeCore({ listJobs: vi.fn(async () => [{ id: "j7", name: "noche", state: "armed", round, rounds: 0, phases: [] }]), getRun });
  render(<PatrolView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: /noche/ }));
  expect(await screen.findByText("10.0.0.7:22")).toBeInTheDocument();
  round = 3; // una ronda nueva arranca vacía en el núcleo: la grilla viva no se reemplaza por una vacía
  act(() => core.emitEvent({ jobId: "j7", phaseAdded: { at: new Date().toISOString(), kind: "JOB_PHASE_KIND_ROUND_STARTED", round: 3 } }));
  await act(async () => {});
  expect(screen.getByText("10.0.0.7:22")).toBeInTheDocument();
});

test("al reabrir a mitad de ronda la grilla trae todos los equipos, no solo los que ya terminaron", async () => {
  const getRun = vi.fn(async (_id: string, r: number) => (r === 1
    ? [{ target: "10.0.0.1:22", state: "DEVICE_STATE_COMPLETED", detail: "" }, { target: "10.0.0.2:22", state: "DEVICE_STATE_COMPLETED", detail: "" }]
    : [{ target: "10.0.0.1:22", state: "DEVICE_STATE_COMPLETED", detail: "" }]));
  const core = fakeCore({ listJobs: vi.fn(async () => [{ id: "j8", name: "parcial", state: "armed", round: 2, rounds: 0, phases: [] }]), getRun });
  render(<PatrolView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: /parcial/ }));
  expect(await screen.findByText("10.0.0.1:22")).toBeInTheDocument();
  expect(screen.getByText("10.0.0.2:22")).toBeInTheDocument();
});

test("el rechazo de la carpeta de salida se ve traducido, con la orden chmod", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    createJob: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = prefs.outputs.permisos: la carpeta /home/u/ev tiene modo 0755 y debe ser 0700; corrígelo con: chmod 700 /home/u/ev"); }),
  });
  await fillForm(core);
  await userEvent.click(screen.getByRole("button", { name: "Crear trabajo" }));
  const alert = await screen.findByText(/más abiertos que 0700/);
  expect(alert).toHaveTextContent("chmod 700 /home/u/ev");
  expect(screen.queryByText(/prefs\.outputs/)).toBeNull();
});
