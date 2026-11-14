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

// assist:done con error es un corte del stream del watch, no el fin de la ejecución: el dueño sigue haciendo falta (franja «Ir», reenganche).
test("un assist:done con error conserva el dueño", () => {
  localStorage.setItem(assistOwnerKey("r3"), "snippets");
  const ports = fakePorts();
  renderHook(() => useShellStatus(fakeCore(ports)));
  act(() => ports.emitAssistDone({ runId: "r3", error: "stream cortado" }));
  expect(localStorage.getItem(assistOwnerKey("r3"))).toBe("snippets");
});

// Un done de más (watch reemplazado en el mismo instante) con la ejecución todavía viva no borra al dueño.
test("un assist:done con la ejecución aún activa en el núcleo conserva el dueño", async () => {
  localStorage.setItem(assistOwnerKey("r4"), "ports");
  const ports = fakePorts();
  const core = fakeCore({ ...ports, assistListRuns: vi.fn(async () => [{ runId: "r4", state: "running", active: true }]) });
  renderHook(() => useShellStatus(core));
  await act(async () => { ports.emitAssistDone({ runId: "r4" }); });
  expect(localStorage.getItem(assistOwnerKey("r4"))).toBe("ports");
});
