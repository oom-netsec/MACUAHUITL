import { act, renderHook } from "@testing-library/react";
import { useShellStatus, assistOwnerKey } from "./useShellStatus";
import { fakeCore } from "../lib/fake";
import { fakePorts } from "../modules/ports/fake";

test("al terminar una ejecución asistida se borra su dueño de localStorage y las demás claves siguen", async () => {
  localStorage.setItem(assistOwnerKey("r1"), "backup");
  localStorage.setItem(assistOwnerKey("r2"), "ports");
  const ports = fakePorts();
  const core = fakeCore(ports);
  renderHook(() => useShellStatus(core));
  await act(async () => { ports.emitAssistDone({ runId: "r1" }); });
  expect(localStorage.getItem(assistOwnerKey("r1"))).toBeNull();
  expect(localStorage.getItem(assistOwnerKey("r2"))).toBe("ports");
});

// El dueño se borra cuando el núcleo ya no tiene activa la ejecución; un corte del stream (done con error) con la ejecución viva lo conserva.
const live = (runId: string) => vi.fn(async () => [{ runId, state: "running", active: true }]);
const setupDone = (listRuns: () => Promise<{ runId: string; state: string; active: boolean }[]>) => {
  const ports = fakePorts();
  const core = fakeCore({ ...ports, assistListRuns: listRuns }); // fuera del render: un core nuevo por render reiniciaría el efecto sin fin
  renderHook(() => useShellStatus(core));
  return ports;
};

test("un assist:done con error y la ejecución viva conserva el dueño", async () => {
  localStorage.setItem(assistOwnerKey("r3"), "snippets");
  const ports = setupDone(live("r3"));
  await act(async () => { ports.emitAssistDone({ runId: "r3", error: "stream cortado" }); });
  expect(localStorage.getItem(assistOwnerKey("r3"))).toBe("snippets");
});

test("un assist:done con error de una ejecución que el núcleo ya no tiene borra el dueño", async () => {
  localStorage.setItem(assistOwnerKey("r5"), "snippets");
  const ports = setupDone(vi.fn(async () => []));
  await act(async () => { ports.emitAssistDone({ runId: "r5", error: "núcleo reiniciado" }); });
  expect(localStorage.getItem(assistOwnerKey("r5"))).toBeNull();
});

test("si no se puede preguntar al núcleo, un done sin error borra el dueño y uno con error lo conserva", async () => {
  localStorage.setItem(assistOwnerKey("r6"), "ports");
  localStorage.setItem(assistOwnerKey("r7"), "ports");
  const ports = setupDone(vi.fn(async () => { throw new Error("x"); }));
  await act(async () => { ports.emitAssistDone({ runId: "r6" }); ports.emitAssistDone({ runId: "r7", error: "corte" }); });
  expect(localStorage.getItem(assistOwnerKey("r6"))).toBeNull();
  expect(localStorage.getItem(assistOwnerKey("r7"))).toBe("ports");
});

// Un done sin error con la ejecución todavía activa no se produce en el puente, pero si llegara no borra al dueño.
test("un assist:done con la ejecución aún activa en el núcleo conserva el dueño", async () => {
  localStorage.setItem(assistOwnerKey("r4"), "ports");
  const ports = setupDone(live("r4"));
  await act(async () => { ports.emitAssistDone({ runId: "r4" }); });
  expect(localStorage.getItem(assistOwnerKey("r4"))).toBe("ports");
});
