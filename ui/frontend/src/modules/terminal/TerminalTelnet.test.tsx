import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TerminalView } from "./TerminalView";
import { fakeCore } from "../../lib/fake";
import { FakeTerm } from "./xtermMock";

vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xtermMock")).FakeTerm }));
vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xtermMock")).FakeFit }));
vi.mock("@xterm/addon-search", async () => ({ SearchAddon: (await import("./xtermMock")).FakeSearch }));
vi.mock("@xterm/addon-webgl", async () => ({ WebglAddon: (await import("./xtermMock")).FakeWebgl }));

const cred = { id: "c".repeat(32), label: "admin lab", username: "admin", kind: "password" as const, hasEnable: false, hasSshKey: false };
const fp = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";
beforeEach(() => {
  FakeTerm.all.length = 0;
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(800);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(400);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

const calls = (core: ReturnType<typeof fakeCore>) => (core.terminalOpen as ReturnType<typeof vi.fn>).mock.calls;
async function openTelnet(core: ReturnType<typeof fakeCore>, dev: string) {
  await userEvent.selectOptions(await screen.findByLabelText("Protocolo"), "Telnet");
  await userEvent.type(screen.getByLabelText(/^Equipo/), dev);
  await userEvent.click(screen.getByRole("button", { name: /Abrir/ }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
}

test("Telnet manda protocolo, dirección y puerto, sin usuario, credencial, host ni huellas aunque se hubieran elegido antes", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await userEvent.selectOptions(await screen.findByLabelText("Credencial"), "Escribir usuario y contraseña al conectar");
  await userEvent.type(screen.getByLabelText("Usuario (opcional)"), "admin");
  await userEvent.type(screen.getByLabelText(/Huellas aceptadas/), fp);
  await openTelnet(core, "192.0.2.1");
  expect(calls(core)[0][0]).toEqual({ name: "192.0.2.1", protocol: "telnet", address: "192.0.2.1", port: 0, accept: [], rows: expect.any(Number), cols: expect.any(Number) });
});

test("Telnet con credencial elegida tampoco manda credentialId; con :2323 manda 2323; SSH sigue sin protocol", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await screen.findByRole("option", { name: /admin lab/ });
  await openTelnet(core, "sw1:2323");
  const r = calls(core)[0][0];
  expect(r).toMatchObject({ protocol: "telnet", address: "sw1", port: 2323 });
  expect(r).not.toHaveProperty("credentialId");
  expect(r).not.toHaveProperty("username");
  expect(r).not.toHaveProperty("hostId");
});

test("SSH no cambia: sin protocol y con su credencial", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await screen.findByRole("option", { name: /admin lab/ });
  await userEvent.type(screen.getByLabelText(/^Equipo/), "sw1");
  await userEvent.click(screen.getByRole("button", { name: /Abrir/ }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
  expect(calls(core)[0][0]).toMatchObject({ address: "sw1", port: 0, credentialId: cred.id });
  expect(calls(core)[0][0]).not.toHaveProperty("protocol");
});

test("al elegir Telnet sale el aviso de texto claro y se ocultan credencial, usuario, huellas y libreta", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  expect(await screen.findByLabelText("Credencial")).toBeInTheDocument();
  expect(screen.queryByText(/texto claro/)).toBeNull();
  await userEvent.selectOptions(screen.getByLabelText("Protocolo"), "Telnet");
  expect(screen.getByText(/todo viaja en texto claro/)).toBeInTheDocument();
  expect(screen.queryByLabelText("Credencial")).toBeNull();
  expect(screen.queryByLabelText("Usuario (opcional)")).toBeNull();
  expect(screen.queryByLabelText(/Huellas aceptadas/)).toBeNull();
  expect(screen.queryByRole("button", { name: "Conectar a LAB-CORE" })).toBeNull();
  expect(screen.getByText("Puerto por omisión: 23.")).toBeInTheDocument();
});

test("un error de huella en una pestaña Telnet no ofrece «Confiar y reintentar»", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await openTelnet(core, "sw1");
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: "x", errorInfo: { code: "FailedPrecondition", reason: "transport.hostkey.unknown", metadata: { host: "sw1:23", fingerprint: `SHA256:${fp}`, key_type: "ssh-ed25519" } } }); });
  await screen.findByRole("tab", { name: /sw1/ });
  expect(screen.queryByRole("button", { name: /Confiar/ })).toBeNull();
});

test("la línea de estado de una pestaña Telnet lo dice", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await openTelnet(core, "sw1");
  act(() => { core.emitTerminal({ runId: "t1", opened: "sw1:23" }); });
  expect(await screen.findByText(/Telnet · conectado a sw1:23/)).toBeInTheDocument();
});

test("reintentar una huella de una pestaña SSH sigue siendo SSH aunque el formulario ya diga Telnet", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await screen.findByRole("option", { name: /admin lab/ });
  await userEvent.type(screen.getByLabelText(/^Equipo/), "sw1");
  await userEvent.click(screen.getByRole("button", { name: /Abrir/ }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: "x", errorInfo: { code: "FailedPrecondition", reason: "transport.hostkey.unknown", metadata: { host: "sw1:22", fingerprint: `SHA256:${fp}`, key_type: "ssh-ed25519" } } }); });
  await userEvent.selectOptions(screen.getByLabelText("Protocolo"), "Telnet");
  await userEvent.click(await screen.findByRole("button", { name: /Confiar y reintentar/ }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(2));
  expect(calls(core)[1][0]).not.toHaveProperty("protocol");
  expect(calls(core)[1][0]).toMatchObject({ address: "sw1", credentialId: cred.id });
});
