import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DiagView } from "./DiagView";
import { fakeCore } from "../../lib/fake";

async function run() {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<DiagView core={core} tool="ping" />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  return core;
}

test("la salida con HTML y scripts se ve literal: no crea elementos ni ejecuta nada", async () => {
  const core = await run();
  const evil = '<img src=x onerror="window.__pwn=1"> <script>window.__pwn=2</script> <b>x</b>';
  act(() => core.emitDiag({ runId: "r1", line: evil }));
  const log = screen.getByRole("log", { name: "Salida" });
  await waitFor(() => expect(log.textContent).toContain(evil));
  expect(log.querySelector("img, script, b")).toBeNull();
});

test("los colores ANSI de la herramienta no se ven como basura; el texto queda", async () => {
  const core = await run();
  act(() => core.emitDiag({ runId: "r1", line: "\u001b[31m64 bytes\u001b[0m from \u001b[1;32m10.0.0.1\u001b[0m \u001b]0;titulo\u0007ok" }));
  const log = screen.getByRole("log", { name: "Salida" });
  await waitFor(() => expect(log.textContent).toContain("64 bytes from 10.0.0.1 ok"));
  expect(log.textContent).not.toMatch(/\u001b|\[31m|titulo/);
});
