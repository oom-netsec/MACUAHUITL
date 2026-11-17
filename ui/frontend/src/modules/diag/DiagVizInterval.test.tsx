import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { fakeCore } from "../../lib/fake";

const made: unknown[][] = [];
vi.mock("uplot", () => ({
  default: class {
    constructor(_o: unknown, d: unknown[][]) { made.push(d); }
    setSize() {} destroy() {} setData() {}
    get ctx() { return { canvas: { toDataURL: () => "" } }; }
  },
}));

import { DiagView } from "./DiagView";

test("el eje de tiempo del ping escala con el intervalo elegido", async () => {
  const core = fakeCore({ diagRun: vi.fn(async () => "r1") });
  render(<DiagView core={core} tool="ping" />);
  await userEvent.type(screen.getByLabelText("Destino"), "10.0.0.1");
  await userEvent.click(screen.getByText("Opciones extendidas"));
  await userEvent.type(screen.getByLabelText("Intervalo (0.2-60 s)"), "5");
  await userEvent.click(screen.getByRole("button", { name: "Ejecutar" }));
  await waitFor(() => expect(core.diagRun).toHaveBeenCalled());
  act(() => ["1", "2", "3"].forEach((q) => core.emitDiag({ runId: "r1", line: `64 bytes from 10.0.0.1: icmp_seq=${q} ttl=64 time=0.4 ms` })));
  await screen.findByRole("figure", { name: "RTT por paquete" });
  const times = made.at(-1)![0] as number[];
  expect(times.map((x) => x - times[0])).toEqual([0, 5, 10]);
});
