import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PendingRollbacks } from "./PendingRollbacks";
import { fakeCore } from "../lib/fake";
import { START, lineText } from "../lib/assistTestkit";
import { vaultChanged } from "../lib/vaultSignal";
import type { PendingRollback } from "../modules/ports/api";

const rb = (over: Partial<PendingRollback> = {}): PendingRollback => ({
  runId: "a", kind: "ports", devices: [{ device: "SW1", rollbackLines: ["interface Gi1/0/1", "switchport access vlan 10"] }],
  endedUnix: Math.floor(Date.now() / 1000) - (over.ageSeconds ?? 7200), ageSeconds: 7200, writeMemory: false, unreadable: false, generatedSecret: false, ...over,
});
const coreWith = (list: PendingRollback[]) => fakeCore({ assistListPendingRollbacks: vi.fn(async () => list) });
const fail = (reason: string) => Object.assign(new Error("x"), { cause: { code: "FailedPrecondition", reason, metadata: {} } });
const OLD = 25 * 3600;

async function openApply(core: ReturnType<typeof fakeCore>) {
  render(<PendingRollbacks core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Aplicar reversa" }));
}
const armAndStart = async () => {
  await userEvent.click(screen.getByLabelText("Activar el modo asistido para esta ejecución"));
  await userEvent.click(screen.getByRole("button", { name: START }));
};

test("lista: equipo, tipo, antigüedad, líneas y aviso de write memory", async () => {
  render(<PendingRollbacks core={coreWith([rb({ writeMemory: true })])} />);
  const s = within(await screen.findByRole("region", { name: "Reversa de la ejecución a" }));
  expect(s.getByText("SW1")).toBeInTheDocument();
  expect(s.getByText("Tipo: Puertos")).toBeInTheDocument();
  expect(s.getByText("Hace 2 h")).toBeInTheDocument();
  expect(s.getByText(lineText("switchport access vlan 10"))).toBeInTheDocument();
  expect(s.getByText(/no hace write memory/)).toBeInTheDocument();
});

test("sin write memory no hay aviso", async () => {
  render(<PendingRollbacks core={coreWith([rb()])} />);
  await screen.findByText("Tipo: Puertos");
  expect(screen.queryByText(/no hace write memory/)).not.toBeInTheDocument();
});

test("menos de 24 h: sin casilla de antigüedad y acceptAge=false", async () => {
  const core = coreWith([rb()]);
  await openApply(core);
  expect(screen.queryByLabelText(/Acepto aplicar una reversa/)).not.toBeInTheDocument();
  await armAndStart();
  expect(core.assistStartPendingRollback).toHaveBeenCalledWith("a", false, true);
  expect(core.assistWatch).toHaveBeenCalledWith("rb1");
});

test("más de 24 h: no se puede iniciar sin la casilla y se manda acceptAge=true", async () => {
  const core = coreWith([rb({ ageSeconds: OLD })]);
  await openApply(core);
  expect(screen.getByLabelText("Acepto aplicar una reversa de hace 1 d")).not.toBeChecked();
  expect(screen.queryByRole("button", { name: START })).not.toBeInTheDocument();
  await userEvent.click(screen.getByLabelText("Acepto aplicar una reversa de hace 1 d"));
  await armAndStart();
  expect(core.assistStartPendingRollback).toHaveBeenCalledWith("a", true, true);
});

test("reversa_vieja del núcleo muestra la casilla", async () => {
  const core = coreWith([rb()]);
  vi.mocked(core.assistStartPendingRollback).mockRejectedValueOnce(fail("assist.svc.reversa_vieja"));
  await openApply(core);
  await armAndStart();
  expect(await screen.findByLabelText(/Acepto aplicar una reversa de hace/)).toBeInTheDocument();
  expect(screen.getByText(/más de 24 h/)).toBeInTheDocument();
});

test("no_state dice que hay que revertir a mano", async () => {
  const core = coreWith([rb()]);
  vi.mocked(core.assistStartPendingRollback).mockRejectedValueOnce(fail("assist.pending.no_state"));
  await openApply(core);
  await armAndStart();
  expect(await screen.findByText(/revierte a mano/)).toBeInTheDocument();
});

test("descartar pide confirmación y refresca", async () => {
  const core = coreWith([rb()]);
  render(<PendingRollbacks core={core} />);
  const btn = await screen.findByRole("button", { name: "Descartar" });
  await userEvent.click(btn);
  expect(core.assistDiscardPendingRollback).not.toHaveBeenCalled();
  vi.mocked(core.assistListPendingRollbacks).mockClear();
  await userEvent.click(screen.getByRole("button", { name: "Confirmar: descartar" }));
  expect(core.assistDiscardPendingRollback).toHaveBeenCalledWith("a");
  await waitFor(() => expect(core.assistListPendingRollbacks).toHaveBeenCalled());
});

test("ilegible: solo runId y Descartar, sin Aplicar", async () => {
  render(<PendingRollbacks core={coreWith([rb({ unreadable: true, devices: [], kind: "" })])} />);
  const s = within(await screen.findByRole("region", { name: "Reversa de la ejecución a" }));
  expect(s.getByRole("button", { name: "Descartar" })).toBeInTheDocument();
  expect(s.queryByRole("button", { name: "Aplicar reversa" })).not.toBeInTheDocument();
});

test("bóveda bloqueada: solo el aviso", async () => {
  const core = fakeCore({ assistListPendingRollbacks: vi.fn(async () => { throw fail("assist.svc.abre_la_boveda_el_modo"); }) });
  render(<PendingRollbacks core={core} />);
  expect(await screen.findByText(/bóveda está cerrada/)).toBeInTheDocument();
  expect(screen.queryByRole("button")).not.toBeInTheDocument();
});

test("al terminar una ejecución asistida la lista se refresca", async () => {
  const core = coreWith([]);
  render(<PendingRollbacks core={core} />);
  await screen.findByText("No hay reversas pendientes.");
  vi.mocked(core.assistListPendingRollbacks).mockClear();
  act(() => core.emitAssistDone({ runId: "z" }));
  await waitFor(() => expect(core.assistListPendingRollbacks).toHaveBeenCalled());
});

test("el aviso de equipo cambiado de una ejecución ofrece su reversa", async () => {
  const { AssistExecution } = await import("./AssistRun");
  const { samplePlan } = await import("../modules/ports/fake");
  const onActive = vi.fn();
  const core = coreWith([rb({ runId: "r1" }), rb({ runId: "otra" })]);
  render(<AssistExecution core={core} plan={samplePlan} onStarted={() => {}} onActive={onActive} onError={() => {}} />);
  await userEvent.click(screen.getByLabelText("Activar el modo asistido para esta ejecución"));
  await userEvent.click(screen.getByRole("button", { name: START }));
  await screen.findByText(/Ejecución r1|r1/);
  act(() => core.emitAssist({ runId: "r1", kind: "fail", text: "boom", changed: ["SW1"] }));
  act(() => core.emitAssistDone({ runId: "r1" }));
  expect(await screen.findByRole("region", { name: "Reversa de la ejecución r1" })).toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Reversa de la ejecución otra" })).not.toBeInTheDocument();
  vi.mocked(core.assistStartPendingRollback).mockResolvedValueOnce("rbx");
  onActive.mockClear();
  await userEvent.click(screen.getByRole("button", { name: "Aplicar reversa" }));
  await armStartIn("r1");
  await waitFor(() => expect(onActive).toHaveBeenLastCalledWith(true));
});

const regionOf = (id: string) => within(screen.getByRole("region", { name: `Reversa de la ejecución ${id}` }));
const armStartIn = async (id: string) => {
  const r = regionOf(id);
  await userEvent.click(r.getByLabelText("Activar el modo asistido para esta ejecución"));
  await userEvent.click(r.getByRole("button", { name: START }));
};
const applyIn = async (id: string) => userEvent.click(regionOf(id).getByRole("button", { name: "Aplicar reversa" }));

test("dos entradas aplicando: ninguna se reengancha a una ejecución viva ajena y cada una arranca la suya", async () => {
  const core = coreWith([rb({ runId: "a" }), rb({ runId: "b" })]);
  vi.mocked(core.assistListRuns).mockResolvedValue([{ runId: "x", active: true, state: "running" }]);
  vi.mocked(core.assistStartPendingRollback).mockResolvedValueOnce("ra").mockResolvedValueOnce("rbb");
  render(<PendingRollbacks core={core} />);
  await screen.findByRole("region", { name: "Reversa de la ejecución b" });
  await applyIn("a"); await applyIn("b");
  await armStartIn("a"); await armStartIn("b");
  expect(core.assistStartPendingRollback).toHaveBeenNthCalledWith(1, "a", false, true);
  expect(core.assistStartPendingRollback).toHaveBeenNthCalledWith(2, "b", false, true);
  expect(core.assistWatch).not.toHaveBeenCalledWith("x");
  expect(core.assistWatch).toHaveBeenCalledWith("ra");
  expect(core.assistWatch).toHaveBeenCalledWith("rbb");
});

test("la reversa viva avisa al anfitrión con onActive", async () => {
  const core = coreWith([rb()]);
  const onActive = vi.fn();
  render(<PendingRollbacks core={core} onActive={onActive} />);
  await userEvent.click(await screen.findByRole("button", { name: "Aplicar reversa" }));
  await armAndStart();
  await waitFor(() => expect(onActive).toHaveBeenLastCalledWith(true));
});

test("con reversa pendiente no se dibuja el plan del núcleo: solo la nota de revertir", async () => {
  await openApply(coreWith([rb()]));
  expect(screen.queryByRole("region", { name: "Reversa" })).not.toBeInTheDocument();
  expect(screen.queryByText("Lo que se espera")).not.toBeInTheDocument();
  expect(screen.getByText(/Revertir durante la reversa vuelve a aplicar el cambio original/)).toBeInTheDocument();
});

test("tras una reversa fallida se ofrece reintentar y descartar; mientras vive no hay acciones", async () => {
  const core = coreWith([rb()]);
  render(<PendingRollbacks core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Aplicar reversa" }));
  await armAndStart();
  expect(screen.queryByRole("button", { name: "Aplicar reversa" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Descartar" })).not.toBeInTheDocument();
  act(() => core.emitAssist({ runId: "rb1", kind: "fail", text: "boom", changed: ["SW1"] }));
  act(() => core.emitAssistDone({ runId: "rb1" }));
  await userEvent.click(await screen.findByRole("button", { name: "Aplicar reversa" }));
  expect(screen.getByRole("button", { name: "Descartar" })).toBeInTheDocument();
  await armAndStart();
  expect(core.assistStartPendingRollback).toHaveBeenCalledTimes(2);
});

test("reversa_vieja: se marca la casilla, se reintenta y sale acceptAge=true", async () => {
  const core = coreWith([rb()]);
  vi.mocked(core.assistStartPendingRollback).mockRejectedValueOnce(fail("assist.svc.reversa_vieja"));
  await openApply(core);
  await armAndStart();
  await userEvent.click(await screen.findByLabelText(/Acepto aplicar una reversa de hace/));
  await armAndStart();
  expect(core.assistStartPendingRollback).toHaveBeenLastCalledWith("a", true, true);
});

test("la casilla de antigüedad de una entrada no afecta a la otra", async () => {
  const core = coreWith([rb({ runId: "a", ageSeconds: OLD }), rb({ runId: "b", ageSeconds: OLD })]);
  render(<PendingRollbacks core={core} />);
  await screen.findByRole("region", { name: "Reversa de la ejecución b" });
  await applyIn("a"); await applyIn("b");
  await userEvent.click(regionOf("a").getByLabelText(/Acepto aplicar una reversa/));
  expect(regionOf("a").getByRole("button", { name: START })).toBeInTheDocument();
  expect(regionOf("b").queryByRole("button", { name: START })).not.toBeInTheDocument();
});

test("la antigüedad sale de endedUnix y la hora actual, no de ageSeconds congelado", async () => {
  const core = coreWith([rb({ ageSeconds: 60, endedUnix: Math.floor(Date.now() / 1000) - OLD })]);
  await openApply(core);
  expect(screen.getByLabelText(/Acepto aplicar una reversa de hace 1 d/)).toBeInTheDocument();
});

test("bóveda cerrada por su reason: aviso junto a lo ya arrancado, y se refresca al abrirla", async () => {
  const core = coreWith([]);
  vi.mocked(core.assistListPendingRollbacks).mockRejectedValueOnce(fail("assist.svc.abre_la_boveda_el_modo"));
  render(<PendingRollbacks core={core} />);
  expect(await screen.findByText(/bóveda está cerrada/)).toBeInTheDocument();
  vi.mocked(core.assistListPendingRollbacks).mockResolvedValue([rb()]);
  act(() => vaultChanged());
  expect(await screen.findByRole("region", { name: "Reversa de la ejecución a" })).toBeInTheDocument();
  expect(screen.queryByText(/bóveda está cerrada/)).not.toBeInTheDocument();
});

test("otro FailedPrecondition al listar no se toma por bóveda cerrada", async () => {
  const core = fakeCore({ assistListPendingRollbacks: vi.fn(async () => { throw fail("otra.cosa"); }) });
  render(<PendingRollbacks core={core} />);
  expect(await screen.findByRole("alert")).toBeInTheDocument();
  expect(screen.queryByText(/bóveda está cerrada/)).not.toBeInTheDocument();
});

test("descartar: reversa_aplicandose tiene texto propio y reversa_no_existe solo refresca", async () => {
  const core = coreWith([rb()]);
  vi.mocked(core.assistDiscardPendingRollback).mockRejectedValueOnce(fail("assist.svc.reversa_aplicandose"));
  render(<PendingRollbacks core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Descartar" }));
  await userEvent.click(screen.getByRole("button", { name: "Confirmar: descartar" }));
  expect(await screen.findByText(/se está aplicando/)).toBeInTheDocument();
  vi.mocked(core.assistDiscardPendingRollback).mockRejectedValueOnce(fail("assist.svc.reversa_no_existe"));
  vi.mocked(core.assistListPendingRollbacks).mockClear();
  await userEvent.click(screen.getByRole("button", { name: "Descartar" }));
  await userEvent.click(screen.getByRole("button", { name: "Confirmar: descartar" }));
  await waitFor(() => expect(core.assistListPendingRollbacks).toHaveBeenCalled());
  expect(screen.queryByText(/se está aplicando/)).not.toBeInTheDocument();
});

test("el tipo se muestra legible y uno desconocido tal cual", async () => {
  render(<PendingRollbacks core={coreWith([rb({ runId: "a", kind: "restore-diff" }), rb({ runId: "b", kind: "algo-nuevo" })])} />);
  expect(await screen.findByText("Tipo: Restauración de respaldo")).toBeInTheDocument();
  expect(screen.getByText("Tipo: algo-nuevo")).toBeInTheDocument();
});

test("una reversa que terminó bien (el núcleo ya no la lista) queda con su resultado, sin Aplicar ni Descartar", async () => {
  const list = [rb()];
  const core = fakeCore({ assistListPendingRollbacks: vi.fn(async () => [...list]) });
  render(<PendingRollbacks core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Aplicar reversa" }));
  await armAndStart();
  list.length = 0; // el núcleo la borra al terminar en done
  act(() => core.emitAssist({ runId: "rb1", kind: "state", state: "done" }));
  act(() => core.emitAssistDone({ runId: "rb1" }));
  await waitFor(() => expect(core.assistListPendingRollbacks).toHaveBeenCalledTimes(2));
  expect(await screen.findByText(/el cambio se aplicó y pasó el post-check/)).toBeInTheDocument(); // terminó: su resultado sigue a la vista
  expect(screen.getByText(/SW1/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Aplicar reversa" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Descartar" })).not.toBeInTheDocument();
});

test("al desmontarse no deja al anfitrión con el aviso de reversa viva encendido", async () => {
  const onActive = vi.fn();
  const core = coreWith([rb()]);
  const { unmount } = render(<PendingRollbacks core={core} onActive={onActive} />);
  await userEvent.click(await screen.findByRole("button", { name: "Aplicar reversa" }));
  await armAndStart();
  await waitFor(() => expect(onActive).toHaveBeenLastCalledWith(true));
  unmount();
  expect(onActive).toHaveBeenLastCalledWith(false);
});

// ---- Fase 24a ----
test("un snippet sin clave propia muestra el nombre de su plantilla; sin plantilla, el id", async () => {
  render(<PendingRollbacks core={coreWith([rb({ runId: "a", kind: "snippet-snmp-trap-host" }), rb({ runId: "b", kind: "snippet-inexistente" })])} />);
  expect(await screen.findByText("Tipo: Snippet: Destino de traps SNMP")).toBeInTheDocument();
  expect(screen.getByText("Tipo: snippet-inexistente")).toBeInTheDocument();
});

test("dentro de una reversa pendiente el botón de revertir dice que reaplica el cambio original", async () => {
  const core = coreWith([rb()]);
  render(<PendingRollbacks core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Aplicar reversa" }));
  await armAndStart();
  act(() => core.emitAssist({ runId: "rb1", kind: "pending", state: "waiting-confirm", step: { id: "apply-1", kind: "apply", device: "SW1", lines: ["x"] } }));
  expect(await screen.findByRole("button", { name: "Reaplicar el cambio original" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Revertir lo ya cambiado" })).not.toBeInTheDocument();
});

test("dentro de una reversa pendiente detenida se ofrece «Proponer reaplicar el cambio original»", async () => {
  const core = coreWith([rb()]);
  render(<PendingRollbacks core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Aplicar reversa" }));
  await armAndStart();
  act(() => core.emitAssist({ runId: "rb1", kind: "fail", state: "failed", text: "boom", changed: ["SW1"] }));
  expect(await screen.findByRole("button", { name: "Proponer reaplicar el cambio original" })).toBeInTheDocument();
});

test("descartar una rotación avisa que la bóveda queda con la contraseña anterior y exige escribir el nombre del equipo", async () => {
  const core = coreWith([rb({ kind: "credrotate", devices: [{ device: "SW1", rollbackLines: ["username admin secret ⟦oculto⟧"] }] })]);
  render(<PendingRollbacks core={core} />);
  expect(await screen.findByText(/puede dejar a SW1 con la contraseña nueva/)).toBeInTheDocument();
  expect(screen.getByText(/Si la bóveda guarda la credencial de ese usuario/)).toBeInTheDocument(); // texto general: reversa sin usuario rotado
  expect(screen.queryByText(/nadie la conoce/)).toBeNull(); // la escribió la persona
  const discardBtn = () => screen.getByRole("button", { name: "Descartar" });
  expect(discardBtn()).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Escribe SW1 para confirmar que descartas"), "SW");
  expect(discardBtn()).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Escribe SW1 para confirmar que descartas"), "1");
  await userEvent.click(discardBtn());
  await userEvent.click(screen.getByRole("button", { name: "Confirmar: descartar" }));
  await waitFor(() => expect(core.assistDiscardPendingRollback).toHaveBeenCalledWith("a"));
});

test("con el secreto generado por la app, el aviso dice que nadie lo conoce", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", generatedSecret: true })])} />);
  expect(await screen.findByText(/nadie la conoce/)).toBeInTheDocument();
});

test("parsePendingRollbacks lee generatedSecret (ausente = false)", async () => {
  const { parsePendingRollbacks } = await import("../modules/ports/api");
  expect(parsePendingRollbacks('{"rollbacks":[{"runId":"a","kind":"credrotate","generatedSecret":true},{"runId":"b","kind":"ports"}]}').map((r) => r.generatedSecret)).toEqual([true, false]);
});

test("una reversa que no es rotación no pide el nombre del equipo", async () => {
  render(<PendingRollbacks core={coreWith([rb()])} />);
  await screen.findByRole("button", { name: "Aplicar reversa" });
  expect(screen.queryByLabelText(/para confirmar que descartas/)).toBeNull();
  expect(screen.getByRole("button", { name: "Descartar" })).toBeEnabled();
});

test("rotación sin equipos: se pide el id de la ejecución (escribir nada no habilita Descartar)", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", devices: [] })])} />);
  expect(await screen.findByLabelText("Escribe a para confirmar que descartas")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Descartar" })).toBeDisabled();
});

test("nombres con espacios alrededor se comparan recortados", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", devices: [{ device: " SW1 ", rollbackLines: [] }] })])} />);
  await userEvent.type(await screen.findByLabelText("Escribe SW1 para confirmar que descartas"), "SW1 ");
  expect(screen.getByRole("button", { name: "Descartar" })).toBeEnabled();
});

test("con el usuario rotado y su credencial de bóveda, el aviso los nombra", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", rotatedUser: "netops", updateCredentialId: "c1" })])} />);
  expect(await screen.findByText(/contraseña nueva de netops/)).toBeInTheDocument();
  expect(screen.getByText(/La credencial de netops en la bóveda conserva la anterior/)).toBeInTheDocument();
});

test("sin credencial de bóveda asociada, el aviso lo dice en vez de hablar de desfase", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", rotatedUser: "netops", updateCredentialId: "" })])} />);
  expect(await screen.findByText(/No se eligió una credencial de la bóveda.*alguna de netops/)).toBeInTheDocument();
  expect(screen.queryByText(/si no la actualizaste a mano/)).toBeNull();
});

test("un equipo provisional avisa que pudo quedar con parte del cambio (cualquier tipo de reversa)", async () => {
  render(<PendingRollbacks core={coreWith([rb({ devices: [{ device: "SW1", rollbackLines: ["x"], provisional: true }] })])} />);
  expect(await screen.findByText(/a mitad de la configuración en SW1/)).toBeInTheDocument();
});

test("sin equipos provisionales no hay aviso de corte a mitad de la configuración", async () => {
  render(<PendingRollbacks core={coreWith([rb()])} />);
  await screen.findByRole("button", { name: "Aplicar reversa" });
  expect(screen.queryByText(/a mitad de la configuración/)).toBeNull();
});

test("secreto generado con usuario rotado: sin «si no la actualizaste a mano» y con «nadie la conoce»", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", rotatedUser: "netops", updateCredentialId: "c1", generatedSecret: true })])} />);
  expect(await screen.findByText(/La credencial de netops en la bóveda conserva la anterior y ya no entra/)).toBeInTheDocument();
  expect(screen.queryByText(/si no la actualizaste a mano/)).toBeNull();
  expect(screen.getByText(/nadie la conoce/)).toBeInTheDocument();
});

// Auditoría 2: si la rotación guardó (write memory) y la reversa no guarda, un reinicio vuelve a cargar la contraseña nueva.
test("rotación con write memory y secreto generado: aplicar la reversa pide guardar después", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", generatedSecret: true, writeMemory: true })])} />);
  const n = await screen.findByText(/nadie la conoce/);
  expect(n).toHaveTextContent(/apliques esta reversa y después guardes la configuración \(write memory\)/);
  expect(n).toHaveTextContent(/tras un reinicio el equipo volvería a cargar la contraseña nueva/);
  expect(n).not.toHaveTextContent(/Para volver a la contraseña anterior/); // una sola frase, no las dos
});

test("rotación con write memory sin secreto generado: una frase pide guardar después de la reversa", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", rotatedUser: "netops", updateCredentialId: "c1", writeMemory: true })])} />);
  expect(await screen.findByText(/Para volver a la contraseña anterior, aplica la reversa y después guarda la configuración \(write memory\)\. La reversa no la guarda/)).toBeInTheDocument();
  expect(screen.queryByText(/nadie la conoce/)).toBeNull();
});

test("rotación sin write memory: el aviso no pide guardar", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", generatedSecret: true })])} />);
  expect(await screen.findByText(/nadie la conoce/)).not.toHaveTextContent(/write memory/);
  expect(screen.queryByText(/La reversa no la guarda/)).toBeNull();
});

test("rotación sin write memory ni secreto generado: tampoco pide guardar", async () => {
  render(<PendingRollbacks core={coreWith([rb({ kind: "credrotate", rotatedUser: "netops", updateCredentialId: "c1" })])} />);
  expect(await screen.findByText(/contraseña nueva de netops/)).toBeInTheDocument();
  expect(screen.queryByText(/La reversa no la guarda/)).toBeNull();
});
