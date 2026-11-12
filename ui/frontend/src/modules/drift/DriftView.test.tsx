import { termText } from "../../test-utils";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DriftView } from "./DriftView";
import { fakeCore } from "../../lib/fake";

const report = { dir: "/o/job", from: 1, to: 2, warnings: ["SW3: sin dos rondas con running-config (tiene [2])"], devices: [
  { device: "SW1_192.0.2.1", from: 1, to: 2, added: 1, removed: 1, ignored: ["ntp clock-period 17179870"], changes: [
    { op: "-" as const, path: "interface Gi1/0/1", line: "description PC-01" },
    { op: "+" as const, path: "interface Gi1/0/1", line: "description PC-01-NUEVA" },
  ] },
  { device: "SW2_192.0.2.2", from: 1, to: 2, added: 0, removed: 0, ignored: [], changes: [] },
] };

test("compara y muestra los cambios por equipo, lo ignorado y los avisos", async () => {
  const core = fakeCore({ driftRun: vi.fn(async () => report) });
  render(<DriftView core={core} />);
  const btn = screen.getByRole("button", { name: "Comparar" });
  expect(btn).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), " /o/job ");
  await userEvent.clear(screen.getByLabelText("Ronda (0 = la última)"));
  await userEvent.type(screen.getByLabelText("Ronda (0 = la última)"), "2");
  await userEvent.click(btn);
  expect(core.driftRun).toHaveBeenCalledWith("/o/job", 2, "");
  const sw1 = await screen.findByRole("region", { name: "SW1_192.0.2.1" });
  expect(within(sw1).getByText("2 cambio(s): 1 agregada(s), 1 quitada(s).")).toBeInTheDocument();
  expect(within(sw1).getByText(termText(/^- interface Gi1\/0\/1 › description PC-01$/))).toBeInTheDocument();
  expect(within(sw1).getByText(termText(/^\+ interface Gi1\/0\/1 › description PC-01-NUEVA$/))).toBeInTheDocument();
  expect(within(sw1).getByText(/Ignoradas por volátiles: ntp clock-period 17179870/)).toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "SW2_192.0.2.2" })).getByText("Sin deriva.")).toBeInTheDocument();
  expect(screen.getByText(/Aviso: SW3/)).toBeInTheDocument();
});

test("avisa en la pantalla cuando el trabajo enmascaró secretos", async () => {
  const core = fakeCore({ driftRun: vi.fn().mockResolvedValueOnce({ ...report, masked: true }).mockResolvedValueOnce(report) });
  render(<DriftView core={core} />);
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), "j1");
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  expect(await screen.findByText(/los cambios en secretos no son visibles porque el trabajo enmascara secretos/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  await screen.findByRole("region", { name: "SW1_192.0.2.1" });
  expect(screen.queryByText(/enmascara secretos/)).not.toBeInTheDocument();
});

test("el error del núcleo se muestra como alerta y borra el resultado anterior", async () => {
  const core = fakeCore({ driftRun: vi.fn().mockResolvedValueOnce(report).mockRejectedValueOnce(new Error("rpc error: code = FailedPrecondition desc = ningún equipo tiene dos rondas")) });
  render(<DriftView core={core} />);
  await userEvent.type(screen.getByLabelText("Trabajo o carpeta"), "j1");
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  await screen.findByRole("region", { name: "SW1_192.0.2.1" });
  await userEvent.click(screen.getByRole("button", { name: "Comparar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("ningún equipo tiene dos rondas");
  expect(screen.queryByRole("region", { name: "SW1_192.0.2.1" })).not.toBeInTheDocument();
});
