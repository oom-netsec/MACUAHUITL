import { act, renderHook } from "@testing-library/react";
import { useShellStatus, assistOwnerKey } from "./useShellStatus";
import { fakeCore } from "../lib/fake";
import { fakePorts } from "../modules/ports/fake";

test("al terminar una ejecución asistida se borra su dueño de localStorage y las demás claves siguen", () => {
  localStorage.setItem(assistOwnerKey("r1"), "backup");
  localStorage.setItem(assistOwnerKey("r2"), "ports");
  const ports = fakePorts();
  const core = fakeCore(ports);
  renderHook(() => useShellStatus(core));
  act(() => ports.emitAssistDone({ runId: "r1" }));
  expect(localStorage.getItem(assistOwnerKey("r1"))).toBeNull();
  expect(localStorage.getItem(assistOwnerKey("r2"))).toBe("ports");
});
