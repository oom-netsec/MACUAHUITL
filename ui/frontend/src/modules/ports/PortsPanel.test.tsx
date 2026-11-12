import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PortsView } from "./PortsView";
import { fakeCore } from "../../lib/fake";
import type { FrontPort } from "./api";
import type { PortInfo } from "../metrics/api";
import { samplePorts } from "./fake";
import { samplePorts as coreSample } from "../metrics/fake";

// El frente de ejemplo con la forma que entrega el núcleo (core.portStatus).
const info = (p: FrontPort): PortInfo => ({
  name: p.name, kind: p.name.slice(0, 2), module: p.module, stack: p.slot, number: p.port, description: p.description, status: p.status, vlan: p.vlan,
  duplex: p.duplex, speed: p.speed, duplexMode: "", speedMbps: 0, autoNegotiated: false, type: p.type, trunk: p.mode === "trunk", trunkNative: "", channel: "", channelFlags: "",
});
const live = { source: "live" as const, address: "10.0.0.5", hostname: "SW5", atMs: 0, ports: samplePorts().map(info), channels: [], warnings: [] };

const creds = [{ id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false }];

async function read(over: Record<string, unknown> = {}) {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), portStatus: vi.fn(async () => live), ...over });
  render(<PortsView core={core} />);
  const btn = await screen.findByRole("button", { name: "Leer puertos (solo lectura)" });
  expect(btn).toBeDisabled(); // falta el equipo
  await userEvent.type(screen.getByLabelText("Equipo (IP o nombre[:puerto])"), "10.0.0.5:2222");
  await userEvent.click(btn);
  return core;
}
const port = (name: string) => screen.findByRole("button", { name: new RegExp(`^${name.replace(/\//g, "\\/")},`) });

test("leer puertos manda el equipo y la credencial y dibuja el frente con un botón por puerto", async () => {
  const core = await read();
  expect(core.portStatus).toHaveBeenCalledWith({ device: "10.0.0.5", port: 2222, credentialId: "c1", acceptedHostKeys: [] });
  expect(await screen.findByRole("button", { name: "Gi1/0/14, conectado, VLAN 20" })).toHaveAttribute("aria-pressed", "false");
  expect(screen.getByRole("button", { name: "Gi1/0/3, sin conexión, VLAN 10" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Gi1/0/9, deshabilitado, VLAN 30" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Gi1/0/11, err-disabled, VLAN 20" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Gi1/0/12, monitoreo, VLAN 20" })).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: /^(Gi|Te)\d/ })).toHaveLength(samplePorts().length);
});

test("la leyenda explica cada estado con texto y cuenta los puertos", async () => {
  await read();
  await port("Gi1/0/14");
  const legend = screen.getByRole("list", { name: "Leyenda de estados" });
  expect(within(legend).getByText("Conectado (22)")).toBeInTheDocument();
  expect(within(legend).getByText("Sin conexión (3)")).toBeInTheDocument();
  expect(within(legend).getByText("Deshabilitado (1)")).toBeInTheDocument();
  expect(within(legend).getByText("Err-disabled (1)")).toBeInTheDocument();
  expect(within(legend).getByText("Monitoreo (1)")).toBeInTheDocument();
});

test("clic, Enter y Espacio alternan el puerto en el campo Interfaces", async () => {
  await read();
  const gi14 = await port("Gi1/0/14");
  await userEvent.click(gi14);
  expect(gi14).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByLabelText("Interfaces")).toHaveValue("Gi1/0/14");
  const gi3 = await port("Gi1/0/3");
  gi3.focus();
  await userEvent.keyboard("{Enter}");
  expect(screen.getByLabelText("Interfaces")).toHaveValue("Gi1/0/14, Gi1/0/3");
  await userEvent.keyboard(" ");
  expect(screen.getByLabelText("Interfaces")).toHaveValue("Gi1/0/14");
  expect(gi3).toHaveAttribute("aria-pressed", "false");
  await userEvent.click(gi14);
  expect(screen.getByLabelText("Interfaces")).toHaveValue("");
});

test("lo que se escribe en Interfaces también marca los puertos", async () => {
  await read();
  await userEvent.type(screen.getByLabelText("Interfaces"), "Gi1/0/5 Gi1/0/6");
  expect(await port("Gi1/0/5")).toHaveAttribute("aria-pressed", "true");
  expect(await port("Gi1/0/7")).toHaveAttribute("aria-pressed", "false");
});

test("los puertos troncal o enrutados se ven pero no se pueden elegir para el cambio", async () => {
  await read();
  const te = await screen.findByRole("button", { name: "Te1/1/1, conectado, troncal" });
  expect(te).toBeDisabled();
  expect(screen.getByRole("button", { name: "Te1/1/4, conectado, enrutado" })).toBeDisabled();
});

test("si la lectura falla lo dice y no dibuja el frente", async () => {
  await read({ portStatus: vi.fn().mockRejectedValue(new Error("rpc error: code = Unavailable desc = sin ruta al equipo")) });
  expect(await screen.findByRole("alert")).toHaveTextContent("sin ruta al equipo");
  expect(screen.queryByRole("list", { name: "Leyenda de estados" })).not.toBeInTheDocument();
});

test("con la respuesta del núcleo: miembros de un port-channel fijos y avisos visibles", async () => {
  await read({ portStatus: vi.fn(async () => ({ ...coreSample, warnings: ["falta show interfaces trunk: la VLAN nativa no se conoce"] })) });
  const member = coreSample.ports.find((p) => p.channel)!;
  expect(await screen.findByRole("button", { name: new RegExp(`^${member.name.replace(/\//g, "\\/")}, .*miembro de ${member.channel}`) })).toBeDisabled();
  expect(screen.getByText(/falta show interfaces trunk/)).toBeInTheDocument();
});
