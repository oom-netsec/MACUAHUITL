import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CredRotateView } from "./CredRotateView";
import { fakeCore } from "../../lib/fake";
import { START, clickWhenReady, confirmStep } from "../../lib/assistTestkit";

const creds = [
  { id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false },
  { id: "c2", label: "tech", username: "tech", hasEnable: false, hasSshKey: false },
];
const NEW = "Nuev0-Secreto.2026";

async function open(core: ReturnType<typeof fakeCore>) {
  render(<CredRotateView core={core} />);
  await userEvent.type(await screen.findByLabelText("Equipo (IP o nombre[:puerto])"), "10.0.0.5");
  await userEvent.type(screen.getByLabelText("Usuario a rotar"), "tech");
}

const planBtn = () => screen.getByRole("button", { name: "Planear (solo lectura)" });

test("el secreto viaja una vez, el campo se borra y nunca aparece en pantalla", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await open(core);
  expect(planBtn()).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Secreto nuevo"), NEW);
  expect(screen.getByLabelText("Secreto nuevo")).toHaveAttribute("type", "password");
  await userEvent.selectOptions(screen.getByLabelText("Credencial de la bóveda que recibe el secreto nuevo"), "c2");
  await userEvent.click(planBtn());
  expect(core.assistPlanCredRotate).toHaveBeenCalledWith({
    target: { name: "10.0.0.5", address: "10.0.0.5", credentialId: "c1" }, user: "tech", newSecret: NEW, updateCredentialId: "c2", writeMemory: true,
  });
  expect(await screen.findByRole("region", { name: "Reversa" })).toBeInTheDocument();
  expect(screen.getByLabelText("Secreto nuevo")).toHaveValue("");
  expect(document.body.textContent).not.toContain(NEW);
  expect(screen.getAllByText(/<oculto>/).length).toBeGreaterThan(0);
  expect(core.assistStart).not.toHaveBeenCalled();
});

test("write memory es obligatorio: no hay casilla y el aviso explica la bóveda y la credencial anterior", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await open(core);
  expect(screen.queryByLabelText(/write memory/i)).not.toBeInTheDocument();
  expect(screen.getByText(/write memory es obligatorio/)).toHaveTextContent(/\(anterior\)/);
  expect(screen.getByText(/write memory es obligatorio/)).toHaveTextContent(/se propone la reversa/);
  await userEvent.type(screen.getByLabelText("Secreto nuevo"), NEW);
  await userEvent.click(planBtn());
  expect((core.assistPlanCredRotate as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0]).toMatchObject({ writeMemory: true });
});

test("generar: no manda secreto y exige la credencial de la bóveda que lo recibe", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await open(core);
  await userEvent.click(screen.getByLabelText(/Que el núcleo genere el secreto/));
  expect(screen.queryByLabelText("Secreto nuevo")).not.toBeInTheDocument();
  expect(planBtn()).toBeDisabled();
  await userEvent.selectOptions(screen.getByLabelText("Credencial de la bóveda que recibe el secreto nuevo"), "c2");
  await userEvent.click(planBtn());
  const req = (core.assistPlanCredRotate as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0] as Record<string, unknown>;
  expect(req.newSecret).toBeUndefined();
  expect(req.updateCredentialId).toBe("c2");
});

test("ejecución asistida: aviso rojo, confirmación por paso y la sesión nueva que no entra ofrece la reversa", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  await open(core);
  await userEvent.type(screen.getByLabelText("Secreto nuevo"), NEW);
  await userEvent.click(planBtn());
  await screen.findByRole("region", { name: "Reversa" });
  await userEvent.click(screen.getByLabelText("Activar el modo asistido para esta ejecución"));
  await userEvent.click(screen.getByRole("button", { name: START }));
  expect(core.assistStart).toHaveBeenCalledWith("c1", true);
  expect(await screen.findByRole("alert")).toHaveTextContent("MODO ASISTIDO ACTIVO");
  act(() => core.emitAssist({ runId: "r1", kind: "pending", state: "waiting-confirm", step: { id: "apply-1", kind: "apply", device: "SW1", lines: ["username tech privilege 15 algorithm-type scrypt secret <oculto>"] } }));
  await clickWhenReady(await screen.findByRole("button", { name: confirmStep("apply-1") }));
  expect(core.assistConfirm).toHaveBeenCalledWith("r1", "apply-1");
  act(() => core.emitAssist({ runId: "r1", kind: "fail", state: "failed", text: "la credencial nueva no entró a SW1 con una sesión nueva: acceso denegado", changed: ["SW1"] }));
  expect(await screen.findByText(/no entró a SW1/)).toBeInTheDocument();
  expect(screen.getByText(/El equipo SW1 quedó cambiado/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Proponer la reversa" }));
  expect(core.assistRollback).toHaveBeenCalledWith("r1");
  expect(document.body.textContent).not.toContain(NEW);
});

test("el núcleo rechaza al usuario de la sesión y el módulo lo dice", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), assistPlanCredRotate: vi.fn(async () => { throw new Error("rpc error: code = FailedPrecondition desc = el usuario \"admin\" es el de la sesión que ejecuta el cambio"); }) });
  await open(core);
  await userEvent.type(screen.getByLabelText("Secreto nuevo"), NEW);
  await userEvent.click(planBtn());
  expect(await screen.findByText(/es el de la sesión que ejecuta el cambio/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: START })).not.toBeInTheDocument();
  expect(document.body.textContent).not.toContain(NEW);
});
