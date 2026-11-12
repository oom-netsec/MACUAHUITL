import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BackupView } from "./BackupView";
import { fakeCore } from "../../lib/fake";
import { sampleEntry, sampleRestore } from "./fake";
import { START, clickWhenReady, confirmStep } from "../../lib/assistTestkit";

const clear = sampleEntry({ id: "SW1_192.0.2.1/20261106T110000Z-running", at: "2026-11-06T11:00:00Z", masked: false });
const masked = sampleEntry();
const cred = { id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false };

async function open(over = {}) {
  const core = fakeCore({
    listCredentials: vi.fn(async () => [cred]),
    backupList: vi.fn(async () => ({ backups: [clear, masked], masked: true })),
    ...over,
  });
  render(<BackupView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: `Restaurar ${clear.id}` }));
  return core;
}
const planBtn = () => screen.getByRole("button", { name: "Planear (solo lectura)" });

test("un respaldo enmascarado no se puede restaurar: el botón está apagado y dice por qué", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), backupList: vi.fn(async () => ({ backups: [masked], masked: true })) });
  render(<BackupView core={core} />);
  const b = await screen.findByRole("button", { name: `Restaurar ${masked.id}` });
  expect(b).toBeDisabled();
  expect(b).toHaveAttribute("title", expect.stringContaining("Enmascarado"));
});

test("planear solo lee: manda el respaldo, muestra el plan con su reversa y no inicia nada", async () => {
  const core = await open();
  expect(screen.getByLabelText("Equipo (IP o nombre[:puerto])")).toHaveValue("192.0.2.1");
  expect(screen.getByText(/Esto cambia la configuración de un equipo real/)).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText(/Interfaz de gestión/), "Vlan1");
  await userEvent.click(planBtn());
  expect(core.assistPlanRestore).toHaveBeenCalledWith({
    target: { name: "192.0.2.1", address: "192.0.2.1", credentialId: "c1" }, backupId: clear.id, managementInterface: "Vlan1", maxLines: 200, allowPartial: false, writeMemory: false,
  });
  expect(await screen.findByRole("region", { name: "Reversa" })).toHaveTextContent("description PC-ventas");
  expect(screen.getByRole("region", { name: "Se aplicará" })).toHaveTextContent("ntp server 10.0.0.2");
  expect(screen.getByText(/interface GigabitEthernet1\/0\/1 > description PC-contabilidad/)).toBeInTheDocument(); // el separador interno no se ve
  expect(core.assistStart).not.toHaveBeenCalled();
});

test("el plan rechazado lista lo que hay que hacer a mano y no ofrece ejecutar", async () => {
  const core = await open({
    assistPlanRestore: vi.fn(async () => ({ reason: "el diff toca 1 cosas que no se restauran con seguridad", refused: [{ path: "", line: "vtp mode client", why: "vtp: se propaga a otros equipos" }] })),
  });
  await userEvent.click(planBtn());
  expect(await screen.findByText(/Plan rechazado: el diff toca 1 cosas/)).toBeInTheDocument();
  const list = screen.getByRole("region", { name: "No se restaura" });
  expect(within(list).getByText((_, el) => el?.tagName === "LI" && /^vtp mode client/.test(el.textContent ?? ""))).toBeInTheDocument();
  expect(within(list).getByText(/vtp: se propaga/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: START })).not.toBeInTheDocument();
  expect(core.assistStart).not.toHaveBeenCalled();
});

test("plan parcial: manda allowPartial y muestra lo que se deja fuera junto al plan", async () => {
  const core = await open({ assistPlanRestore: vi.fn(async () => ({ ...sampleRestore, refused: [{ line: "snmp-server community <oculto>", why: "secreto" }] })) });
  await userEvent.click(screen.getByLabelText(/Plan parcial/));
  await userEvent.click(planBtn());
  expect(core.assistPlanRestore).toHaveBeenCalledWith(expect.objectContaining({ allowPartial: true }));
  expect(await screen.findByRole("region", { name: "No se restaura" })).toHaveTextContent("plan parcial");
  expect(screen.getByRole("region", { name: "Reversa" })).toBeInTheDocument();
});

test("ejecución asistida: la casilla es por ejecución, aviso rojo y confirmación por paso", async () => {
  const core = await open({ assistStart: vi.fn(async () => "r1") });
  await userEvent.click(planBtn());
  await screen.findByRole("region", { name: "Reversa" });
  const start = screen.getByRole("button", { name: START });
  expect(start).toBeDisabled();
  await userEvent.click(screen.getByLabelText("Activar el modo asistido para esta ejecución"));
  await userEvent.click(start);
  expect(core.assistStart).toHaveBeenCalledWith("rs1", true);
  expect(await screen.findByRole("alert")).toHaveTextContent("MODO ASISTIDO ACTIVO");
  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "apply-1", kind: "apply", device: "192.0.2.1", lines: sampleRestore.plan!.devices[0].apply } }));
  await clickWhenReady(await screen.findByRole("button", { name: confirmStep("apply-1") }));
  expect(core.assistConfirm).toHaveBeenCalledWith("r1", "apply-1");
  // El plan se usó una vez: planear de nuevo exige otra casilla.
  act(() => core.emitAssist({ runId: "r1", kind: "state", state: "done" }));
  expect(screen.queryByRole("button", { name: START })).not.toBeInTheDocument();
});
