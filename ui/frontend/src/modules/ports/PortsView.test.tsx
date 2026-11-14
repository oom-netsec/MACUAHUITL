import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PortsView } from "./PortsView";
import { fakeCore } from "../../lib/fake";
import { ModuleIdContext } from "../../app/activity";
import { START, clickWhenReady, confirmStep, lineText } from "../../lib/assistTestkit";

const creds = [{ id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false }];

async function plan(core: ReturnType<typeof fakeCore>) {
  render(<PortsView core={core} />);
  await userEvent.type(await screen.findByLabelText("Equipo (IP o nombre[:puerto])"), "10.0.0.5:2222");
  await userEvent.type(screen.getByLabelText("Interfaces"), "GigabitEthernet1/0/1");
  await userEvent.type(screen.getByLabelText("VLAN de acceso"), "20");
  await userEvent.click(screen.getByRole("button", { name: "Planear (solo lectura)" }));
  await screen.findByRole("region", { name: "Reversa" });
}

const start = async () => {
  await userEvent.click(screen.getByLabelText("Activar el modo asistido para esta ejecución"));
  await userEvent.click(screen.getByRole("button", { name: START }));
};

test("planear solo lee: manda la petición, muestra lo que se aplica y la reversa, y no hay aviso de modo activo", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  expect(core.assistPlanPorts).toHaveBeenCalledWith({
    target: { name: "10.0.0.5:2222", address: "10.0.0.5", port: 2222, credentialId: "c1" },
    interfaces: ["GigabitEthernet1/0/1"], vlan: 20,
  });
  const apply = within(screen.getByRole("region", { name: "Se aplicará" }));
  expect(apply.getByText(lineText("switchport access vlan 20"))).toBeInTheDocument();
  const back = within(screen.getByRole("region", { name: "Reversa" }));
  expect(back.getByText(lineText("switchport access vlan 10"))).toBeInTheDocument();
  expect(core.assistStart).not.toHaveBeenCalled();
  expect(screen.queryByText(/MODO ASISTIDO ACTIVO/)).not.toBeInTheDocument();
  // Sin la casilla de esta ejecución no se puede iniciar.
  expect(screen.getByRole("button", { name: START })).toBeDisabled();
});

test("ejecución asistida: aviso rojo permanente, un botón por paso y la casilla no se recuerda", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  await start();
  expect(core.assistStart).toHaveBeenCalledWith("p1", true);
  const banner = await screen.findByRole("alert");
  expect(banner).toHaveTextContent("MODO ASISTIDO ACTIVO");
  expect(banner).toHaveClass("assist-banner");

  act(() => core.emitAssist({ runId: "otra", kind: "pending", step: { id: "apply-9", kind: "apply", device: "X", lines: ["x"] } }));
  expect(screen.queryByText(/apply-9/)).not.toBeInTheDocument();

  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "apply-1", kind: "apply", device: "SW1", lines: ["interface GigabitEthernet1/0/1", "switchport access vlan 20"] } }));
  const step = within(await screen.findByRole("region", { name: "Paso pendiente apply-1" }));
  expect(step.getByText(lineText("switchport access vlan 20"))).toBeInTheDocument();
  expect(core.assistConfirm).not.toHaveBeenCalled();
  await clickWhenReady(step.getByRole("button", { name: confirmStep("apply-1") }));
  expect(core.assistConfirm).toHaveBeenCalledWith("r1", "apply-1");

  act(() => core.emitAssist({ runId: "r1", kind: "state", state: "done" }));
  await act(async () => core.emitAssistDone({ runId: "r1" }));
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(await screen.findByText(/Listo: el cambio/)).toBeInTheDocument();

  // Una ejecución nueva vuelve a pedir la casilla.
  await userEvent.click(screen.getByRole("button", { name: "Planear (solo lectura)" }));
  await screen.findByRole("region", { name: "Reversa" });
  expect(screen.getByLabelText("Activar el modo asistido para esta ejecución")).not.toBeChecked();
});

test("un fallo mantiene el aviso, muestra el motivo y ofrece la reversa o abortar", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  await start();
  act(() => core.emitAssist({ runId: "r1", kind: "fail", state: "failed", text: "el equipo SW1 rechazó \"description x\": % Invalid input" }));
  expect(await screen.findByText(/% Invalid input/)).toBeInTheDocument();
  // El fallo también se anuncia como alerta; el aviso rojo del modo sigue ahí.
  expect(screen.getAllByRole("alert").some((a) => /MODO ASISTIDO ACTIVO/.test(a.textContent ?? ""))).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Proponer la reversa" }));
  expect(core.assistRollback).toHaveBeenCalledWith("r1");
  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "rollback-1", kind: "rollback", device: "SW1", lines: ["switchport access vlan 10"] } }));
  await clickWhenReady(await screen.findByRole("button", { name: confirmStep("rollback-1") }));
  expect(core.assistConfirm).toHaveBeenCalledWith("r1", "rollback-1");
  await userEvent.click(screen.getByRole("button", { name: "Abortar" }));
  expect(core.assistAbort).toHaveBeenCalledWith("r1");
});

test("un error del núcleo al planear se muestra y no deja iniciar nada", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), assistPlanPorts: vi.fn(async () => { throw new Error("rpc error: code = FailedPrecondition desc = es trunk"); }) });
  render(<PortsView core={core} />);
  await userEvent.type(await screen.findByLabelText("Equipo (IP o nombre[:puerto])"), "10.0.0.5");
  await userEvent.type(screen.getByLabelText("Interfaces"), "Gi1/0/1");
  await userEvent.type(screen.getByLabelText("VLAN de acceso"), "20");
  await userEvent.click(screen.getByRole("button", { name: "Planear (solo lectura)" }));
  expect(await screen.findByText("es trunk")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: START })).not.toBeInTheDocument();
});

// Hallazgo 7: un fallo que llega antes de que la vista conozca el id de la ejecución no se pierde.
test("un fallo inmediato al iniciar se muestra aunque el evento llegue antes de conocer el id", async () => {
  const ref: { core?: ReturnType<typeof fakeCore> } = {};
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    assistStart: vi.fn(async () => {
      ref.core!.emitAssist({ runId: "r1", kind: "fail", state: "failed", text: "pre-check de SW1: el equipo no responde" }); // llega antes del retorno
      return "r1";
    }),
  });
  ref.core = core;
  await plan(core);
  await start();
  expect(await screen.findByText(/el equipo no responde/)).toBeInTheDocument();
  expect(core.assistWatch).toHaveBeenCalledWith("r1");
  await act(async () => core.emitAssistDone({ runId: "r1" }));
  expect(await screen.findByText(/La ejecución se detuvo por un error/)).toBeInTheDocument();
});

// Hallazgo 6: al abrir el módulo se vuelve a la ejecución que quedó viva, con su aviso rojo y sus botones.
test("al montarse se engancha a una ejecución viva y pide la confirmación pendiente", async () => {
  const step = { id: "save-1", kind: "save", device: "SW1", lines: ["write memory"] };
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    assistListRuns: vi.fn().mockResolvedValueOnce([{ runId: "r9", state: "waiting-confirm", active: true, waiting: true, canRollback: true, pending: step, changed: ["SW1"] }])
      .mockResolvedValue([{ runId: "r9", state: "done", active: false }]), // al terminar, el núcleo ya no la tiene activa
  });
  render(<PortsView core={core} />);
  const banner = await screen.findByRole("alert");
  expect(banner).toHaveTextContent("MODO ASISTIDO ACTIVO");
  expect(core.assistWatch).toHaveBeenCalledWith("r9");
  const region = within(await screen.findByRole("region", { name: "Paso pendiente save-1" }));
  await clickWhenReady(region.getByRole("button", { name: confirmStep("save-1") }));
  expect(core.assistConfirm).toHaveBeenCalledWith("r9", "save-1");
  // Los eventos del historial que repite el núcleo no duplican nada: el estado final queda bien.
  act(() => core.emitAssist({ runId: "r9", kind: "state", state: "done", changed: ["SW1"] }));
  await act(async () => core.emitAssistDone({ runId: "r9" }));
  expect(await screen.findByText(/Listo: el cambio/)).toBeInTheDocument();
});

// Un assist:done de más (el watch se reemplazó en el mismo instante) con la ejecución todavía viva no cierra la vista.
test("un done de más con la ejecución aún activa en el núcleo deja el paso pendiente a la vista", async () => {
  const step = { id: "save-1", kind: "save", device: "SW1", lines: ["write memory"] };
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    assistListRuns: vi.fn(async () => [{ runId: "r9", state: "waiting-confirm", active: true, waiting: true, canRollback: true, pending: step, changed: ["SW1"] }]),
  });
  render(<PortsView core={core} />);
  await screen.findByRole("region", { name: "Paso pendiente save-1" });
  await act(async () => core.emitAssistDone({ runId: "r9" }));
  expect(screen.getByRole("region", { name: "Paso pendiente save-1" })).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("MODO ASISTIDO ACTIVO");
});

test("al montarse con una ejecución detenida por fallo ofrece la reversa o abortar", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    assistListRuns: vi.fn(async () => [{ runId: "r9", state: "failed", active: true, waiting: true, canRollback: true, failReason: "reversa de SW1: el equipo cerró la sesión", changed: ["SW1"] }]),
  });
  render(<PortsView core={core} />);
  expect(await screen.findByText(/el equipo cerró la sesión/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Proponer la reversa" }));
  expect(core.assistRollback).toHaveBeenCalledWith("r9");
});

test("sin ejecuciones vivas el módulo abre limpio", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  render(<PortsView core={core} />);
  await screen.findByLabelText("Equipo (IP o nombre[:puerto])");
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(core.assistWatch).not.toHaveBeenCalled();
});

// Hallazgo 8: abortar, fallar o abandonar con equipos ya cambiados lo dice.
test("abortar con un equipo ya cambiado dice que quedó cambiado", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  await start();
  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "save-1", kind: "save", device: "SW1", lines: ["write memory"] }, changed: ["SW1"] }));
  act(() => core.emitAssist({ runId: "r1", kind: "state", state: "aborted", changed: ["SW1"] }));
  await act(async () => core.emitAssistDone({ runId: "r1" }));
  expect(await screen.findByText(/Ejecución abortada/)).toBeInTheDocument();
  expect(screen.getByText(/El equipo SW1 quedó cambiado/)).toBeInTheDocument();
});

test("abandonada: lo dice y lista los equipos cambiados", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  await start();
  act(() => core.emitAssist({ runId: "r1", kind: "state", state: "abandoned", changed: ["SW1", "SW2"] }));
  await act(async () => core.emitAssistDone({ runId: "r1" }));
  expect(await screen.findByText(/se abandonó/)).toBeInTheDocument();
  expect(screen.getByText(/Los equipos SW1, SW2 quedaron cambiados/)).toBeInTheDocument();
});

test("abortar sin cambios no avisa de equipos cambiados", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  await start();
  act(() => core.emitAssist({ runId: "r1", kind: "state", state: "aborted" }));
  await act(async () => core.emitAssistDone({ runId: "r1" }));
  expect(await screen.findByText(/Ejecución abortada/)).toBeInTheDocument();
  expect(screen.queryByText(/quedó cambiado|quedaron cambiados/)).not.toBeInTheDocument();
});

test("Aplicar no se puede pulsar por inercia: arranca deshabilitado, sin foco, y se habilita al rato", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  await start();
  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "apply-1", kind: "apply", device: "SW1", lines: ["interface GigabitEthernet1/0/1", "switchport access vlan 20"] } }));
  const step = within(await screen.findByRole("region", { name: "Paso pendiente apply-1" }));
  const apply = step.getByRole("button", { name: "Aplicar 2 líneas en SW1 (apply-1)" });
  expect(apply).toBeDisabled();
  expect(apply).not.toHaveFocus();
  expect(step.getByRole("status")).toHaveTextContent("Revisar las líneas antes de aplicar.");
  await userEvent.keyboard("{Enter}");
  expect(core.assistConfirm).not.toHaveBeenCalled();
  await clickWhenReady(apply);
  expect(core.assistConfirm).toHaveBeenCalledWith("r1", "apply-1");
});

test("sin write memory el último paso es «Terminar sin guardar»: dejar el cambio o revertir en todos los equipos", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  await start();
  // protojson: el paso close no trae device ni lines
  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "close", kind: "close" }, changed: ["SW1", "SW2"] }));
  const region = within(await screen.findByRole("region", { name: "Paso pendiente close" }));
  expect(region.getByRole("heading", { name: "Terminar sin guardar" })).toBeInTheDocument();
  expect(region.getByText(/no se guardó en NVRAM/)).toBeInTheDocument();
  expect(region.getByText("Equipos cambiados: SW1, SW2")).toBeInTheDocument();
  await userEvent.click(region.getByRole("button", { name: "Revertir en todos los equipos" }));
  expect(core.assistRollback).toHaveBeenCalledWith("r1");
  await clickWhenReady(region.getByRole("button", { name: "Dejar el cambio en la configuración en ejecución" }));
  expect(core.assistConfirm).toHaveBeenCalledWith("r1", "close");
});

test("tras «Terminar sin guardar» el final recuerda que el cambio no está en NVRAM", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  await start();
  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "close", kind: "close" }, changed: ["SW1"] }));
  await screen.findByRole("region", { name: "Paso pendiente close" });
  act(() => core.emitAssist({ runId: "r1", kind: "state", state: "done", changed: ["SW1"] }));
  await act(async () => core.emitAssistDone({ runId: "r1" }));
  expect(await screen.findByText(/quedó solo en la configuración en ejecución de SW1/)).toBeInTheDocument();
});

test("revertir desde «Terminar sin guardar» termina en rolled-back sin el aviso de cambio sin guardar", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await plan(core);
  await start();
  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "close", kind: "close" }, changed: ["SW1"] }));
  await screen.findByRole("region", { name: "Paso pendiente close" });
  act(() => core.emitAssist({ runId: "r1", kind: "state", state: "rolled-back", changed: [] }));
  await act(async () => core.emitAssistDone({ runId: "r1" }));
  await waitFor(() => expect(screen.queryByRole("region", { name: "Paso pendiente close" })).not.toBeInTheDocument());
  expect(screen.queryByText(/quedó solo en la configuración en ejecución/)).not.toBeInTheDocument();
});

test("una ejecución viva retomada con el paso close sin lines ni device no rompe la vista, y en save también se puede revertir", async () => {
  const core = fakeCore({
    listCredentials: vi.fn(async () => creds),
    assistListRuns: vi.fn(async () => [{ runId: "r9", state: "waiting-confirm", active: true, waiting: true, canRollback: true, pending: { id: "close", kind: "close" }, changed: ["SW1"] }]),
  });
  render(<PortsView core={core} />);
  expect(await screen.findByRole("heading", { name: "Terminar sin guardar" })).toBeInTheDocument();
  act(() => core.emitAssist({ runId: "r9", kind: "pending", state: "waiting-confirm", step: { id: "save-1", kind: "save", device: "SW1" }, changed: ["SW1"] }));
  const save = within(await screen.findByRole("region", { name: "Paso pendiente save-1" }));
  await userEvent.click(save.getByRole("button", { name: "Revertir lo ya cambiado" }));
  expect(core.assistRollback).toHaveBeenCalledWith("r9");
});

// Auditoría 21h: solo el módulo dueño engancha la ejecución viva; los demás no abren otro watch.
const owned = () => fakeCore({
  listCredentials: vi.fn(async () => creds),
  assistListRuns: vi.fn(async () => [{ runId: "r9", state: "running", active: true }]),
});
afterEach(() => localStorage.removeItem("macuahuitl.assist.r9"));

test("un módulo que no inició la ejecución viva no se engancha a ella", async () => {
  localStorage.setItem("macuahuitl.assist.r9", "snippets");
  const core = owned();
  render(<ModuleIdContext.Provider value="ports"><PortsView core={core} /></ModuleIdContext.Provider>);
  await waitFor(() => expect(core.assistListRuns).toHaveBeenCalled());
  await act(async () => {}); // que resuelva la lista antes de mirar
  expect(core.assistWatch).not.toHaveBeenCalled();
});

test("una ejecución viva sin dueño la toma el primer módulo que la ve y queda como su dueño", async () => {
  const core = owned();
  render(<ModuleIdContext.Provider value="ports"><PortsView core={core} /></ModuleIdContext.Provider>);
  await waitFor(() => expect(core.assistWatch).toHaveBeenCalledWith("r9"));
  expect(localStorage.getItem("macuahuitl.assist.r9")).toBe("ports");
});

test("el módulo dueño se engancha y un seq repetido no duplica la salida", async () => {
  localStorage.setItem("macuahuitl.assist.r9", "ports");
  const core = owned();
  render(<ModuleIdContext.Provider value="ports"><PortsView core={core} /></ModuleIdContext.Provider>);
  await waitFor(() => expect(core.assistWatch).toHaveBeenCalledWith("r9"));
  act(() => core.emitAssist({ runId: "r9", seq: 1, kind: "output", device: "SW1", text: "linea-unica" }));
  act(() => core.emitAssist({ runId: "r9", seq: 1, kind: "output", device: "SW1", text: "linea-unica" }));
  expect((document.body.textContent ?? "").match(/linea-unica/g)).toHaveLength(1);
});
