import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PatrolView } from "./PatrolView";
import { fakeCore } from "../../lib/fake";
import { scriptsChanged } from "../scripts/signal";

const creds = [{ id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false }];
const pbMac = { id: "ios-xe/rastreo-mac", platform: "ios-xe", name: "TAC · Rastreo MAC", commands: ["show mac address-table address {mac}"], params: [{ name: "mac", kind: "mac" as const }] };
const pbMac2 = { id: "ios-xe/rastreo-mac2", platform: "ios-xe", name: "TAC · Rastreo MAC 2", commands: ["show mac address-table address {mac}"], params: [{ name: "mac", kind: "mac" as const }, { name: "iface", kind: "interface" as const }] };
const pbPlain = { id: "ios-xe/l2-stp", platform: "ios-xe", name: "L2 · STP", commands: ["show spanning-tree"], params: [] };

async function setup(playbooks: unknown[], extra: Record<string, unknown> = {}) {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), listPlaybooks: vi.fn(async () => playbooks as never), ...extra });
  render(<PatrolView core={core} />);
  await userEvent.type(await screen.findByLabelText("Nombre del trabajo"), "caso-3");
  await userEvent.type(screen.getByLabelText("Equipos"), "10.0.0.1");
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "c1");
  await userEvent.type(screen.getByLabelText("Carpeta de salida"), "/home/u/out");
  return core;
}
const create = () => userEvent.click(screen.getByRole("button", { name: "Crear trabajo" }));

test("un playbook con datos pide sus campos, los exige sin vacíos y los manda en params (un campo por nombre)", async () => {
  const core = await setup([pbMac, pbMac2, pbPlain]);
  await userEvent.click(await screen.findByRole("checkbox", { name: "STP" }));
  expect(screen.queryByLabelText(/\(mac\)/)).toBeNull();
  await userEvent.click(screen.getByRole("checkbox", { name: "Rastreo MAC" }));
  const mac = screen.getByLabelText(/\(mac\)/);
  expect(mac).toHaveAttribute("autocomplete", "off");
  await userEvent.type(mac, "   ");
  await create();
  expect(core.createJob).not.toHaveBeenCalled();
  expect(mac).toBeInvalid();
  expect(screen.getByText("Obligatorio.")).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("Revisa los datos que piden los playbooks elegidos.");
  await userEvent.type(mac, "aa:bb:cc:dd:ee:ff ");
  await userEvent.click(screen.getByRole("checkbox", { name: "Rastreo MAC 2" }));
  expect(screen.getAllByLabelText(/\(mac\)/)).toHaveLength(1);
  await userEvent.type(screen.getByLabelText(/\(iface\)/), "Gi1/0/1");
  await userEvent.click(screen.getByRole("checkbox", { name: "Rastreo MAC 2" }));
  expect(screen.queryByLabelText(/\(iface\)/)).toBeNull();
  await create();
  await waitFor(() => expect(core.createJob).toHaveBeenCalled());
  expect(vi.mocked(core.createJob).mock.calls[0][0].params).toEqual({ mac: "aa:bb:cc:dd:ee:ff" });
});

test("desmarcar el playbook quita el dato y el JobSpec no lleva params", async () => {
  const core = await setup([pbMac, pbPlain]);
  await userEvent.click(await screen.findByRole("checkbox", { name: "Rastreo MAC" }));
  await userEvent.type(screen.getByLabelText(/\(mac\)/), "aa:bb:cc:dd:ee:ff");
  await userEvent.click(screen.getByRole("checkbox", { name: "Rastreo MAC" }));
  await userEvent.click(screen.getByRole("checkbox", { name: "STP" }));
  await create();
  await waitFor(() => expect(core.createJob).toHaveBeenCalled());
  expect(vi.mocked(core.createJob).mock.calls[0][0]).not.toHaveProperty("params");
});

test("el rechazo del núcleo de un dato sale junto a su campo", async () => {
  const cause = { code: "InvalidArgument", reason: "playbook.err.param_invalid", metadata: { field: "params", name: "mac", kind: "mac" } };
  await setup([pbMac], { createJob: vi.fn(async () => { throw Object.assign(new Error("rpc error: code = InvalidArgument desc = patrol: params: MAC inválida"), { cause }); }) });
  await userEvent.click(await screen.findByRole("checkbox", { name: "Rastreo MAC" }));
  await userEvent.type(screen.getByLabelText(/\(mac\)/), "zz");
  await create();
  await waitFor(() => expect(screen.getByLabelText(/\(mac\)/)).toBeInvalid());
  expect(screen.getByText("MAC inválida")).toBeInTheDocument(); // sin el prefijo interno «patrol: params:»
  expect(screen.getByRole("alert")).toHaveTextContent("Revisa los datos");
  expect(screen.getByLabelText(/\(mac\)/)).toHaveAccessibleName("Dirección MAC (mac)");
});

test("un rechazo de un dato que el formulario no muestra queda en el aviso general", async () => {
  const cause = { code: "InvalidArgument", reason: "playbook.err.param_missing", metadata: { field: "params", name: "otro", kind: "ip" } };
  await setup([pbMac], { createJob: vi.fn(async () => { throw Object.assign(new Error("rpc error: code = InvalidArgument desc = patrol: params: falta el dato otro"), { cause }); }) });
  await userEvent.click(await screen.findByRole("checkbox", { name: "Rastreo MAC" }));
  await userEvent.type(screen.getByLabelText(/\(mac\)/), "aa:bb:cc:dd:ee:ff");
  await create();
  expect(await screen.findByRole("alert")).toHaveTextContent("falta el dato otro");
});

// Patrol sigue montada (oculta) mientras se instala un paquete en Ajustes: el catálogo se vuelve a pedir.
test("el catálogo de playbooks se vuelve a pedir cuando cambia el contenido (paquete instalado o importado)", async () => {
  const core = await setup([pbPlain]);
  await screen.findByRole("checkbox", { name: "STP" });
  const before = vi.mocked(core.listPlaybooks).mock.calls.length;
  act(() => scriptsChanged());
  await waitFor(() => expect(vi.mocked(core.listPlaybooks).mock.calls.length).toBeGreaterThan(before));
});
