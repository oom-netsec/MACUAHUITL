import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PendingRollbacks } from "./PendingRollbacks";
import { fakeCore } from "../lib/fake";
import { START, lineText } from "../lib/assistTestkit";
import type { PendingRollback } from "../modules/ports/api";

const rb = (over: Partial<PendingRollback> = {}): PendingRollback => ({
  runId: "a", kind: "ports", devices: [{ device: "SW1", rollbackLines: ["interface Gi1/0/1", "switchport access vlan 10"] }],
  endedUnix: 1700000000, ageSeconds: 7200, writeMemory: false, unreadable: false, ...over,
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
  expect(s.getByText("Tipo: ports")).toBeInTheDocument();
  expect(s.getByText("Hace 2 h")).toBeInTheDocument();
  expect(s.getByText(lineText("switchport access vlan 10"))).toBeInTheDocument();
  expect(s.getByText(/no hace write memory/)).toBeInTheDocument();
});

test("sin write memory no hay aviso", async () => {
  render(<PendingRollbacks core={coreWith([rb()])} />);
  await screen.findByText("Tipo: ports");
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
  const core = fakeCore({ assistListPendingRollbacks: vi.fn(async () => { throw fail("vault.locked"); }) });
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
  const core = coreWith([rb({ runId: "r1" }), rb({ runId: "otra" })]);
  render(<AssistExecution core={core} plan={samplePlan} onStarted={() => {}} onActive={() => {}} onError={() => {}} />);
  await userEvent.click(screen.getByLabelText("Activar el modo asistido para esta ejecución"));
  await userEvent.click(screen.getByRole("button", { name: START }));
  await screen.findByText(/Ejecución r1|r1/);
  act(() => core.emitAssist({ runId: "r1", kind: "fail", text: "boom", changed: ["SW1"] }));
  act(() => core.emitAssistDone({ runId: "r1" }));
  expect(await screen.findByRole("region", { name: "Reversa de la ejecución r1" })).toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Reversa de la ejecución otra" })).not.toBeInTheDocument();
});
