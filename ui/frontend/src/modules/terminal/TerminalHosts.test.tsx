import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TerminalView } from "./TerminalView";
import { fakeCore } from "../../lib/fake";
import { FakeTerm } from "./xtermMock";
import { sampleHosts } from "../inventory/fake";

vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xtermMock")).FakeTerm }));
vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xtermMock")).FakeFit }));
vi.mock("@xterm/addon-search", async () => ({ SearchAddon: (await import("./xtermMock")).FakeSearch }));
vi.mock("@xterm/addon-webgl", async () => ({ WebglAddon: (await import("./xtermMock")).FakeWebgl }));

const cred = { id: "c".repeat(32), label: "admin lab", username: "admin", kind: "password" as const, hasEnable: false, hasSshKey: false };
beforeEach(() => {
  FakeTerm.all.length = 0;
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(800);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(400);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

test("conectar con un clic manda hostId y no dirección ni credencial", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Conectar a LAB-CORE" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
  const req = (core.terminalOpen as ReturnType<typeof vi.fn>).mock.calls[0][0];
  expect(req).toEqual({ name: "LAB-CORE", hostId: sampleHosts[0].id, expectedStartupCommand: "", accept: [], rows: expect.any(Number), cols: expect.any(Number) });
  expect(req).not.toHaveProperty("address");
  expect(req).not.toHaveProperty("credentialId");
});

test("un host sin credencial queda deshabilitado y dice por qué", async () => {
  render(<TerminalView core={fakeCore({ listCredentials: vi.fn(async () => [cred]) })} />);
  const b = await screen.findByRole("button", { name: "Conectar a LAB-AP" });
  expect(b).toBeDisabled();
  expect(b).toHaveAccessibleDescription(/no tiene credencial/);
});

test("la huella de la primera vez se confirma igual y el reintento sigue usando hostId", async () => {
  const fp = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Conectar a LAB-CORE" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: `transport: llave de host desconocida de 10.9.0.1:22: SHA256:${fp}` }); });
  expect(await screen.findByText(`SHA256:${fp}`)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Aceptar esta huella y reintentar" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(2));
  // Exacto: sin dirección, puerto ni credencial.
  expect((core.terminalOpen as ReturnType<typeof vi.fn>).mock.calls[1][0]).toEqual({ name: "LAB-CORE", hostId: sampleHosts[0].id, expectedStartupCommand: "", accept: [`SHA256:${fp}`], rows: expect.any(Number), cols: expect.any(Number) });
});

test("junto al botón se ve la orden de inicio y viaja como expectedStartupCommand (también al reintentar con la huella)", async () => {
  const fp = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), listHosts: vi.fn(async () => [{ ...sampleHosts[0], startCommand: "tmux attach -t main", platform: "linux" as const }]) });
  render(<TerminalView core={core} />);
  const btn = await screen.findByRole("button", { name: "Conectar a LAB-CORE" });
  expect(btn.closest("li")).toHaveTextContent("tmux attach -t main");
  await userEvent.click(btn);
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
  const calls = () => (core.terminalOpen as ReturnType<typeof vi.fn>).mock.calls;
  expect(calls()[0][0]).toMatchObject({ hostId: sampleHosts[0].id, expectedStartupCommand: "tmux attach -t main" });
  expect(calls()[0][0]).not.toHaveProperty("address");
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: "x", errorInfo: { code: "FailedPrecondition", reason: "transport.hostkey.unknown", metadata: { host: "10.9.0.1:22", fingerprint: `SHA256:${fp}`, key_type: "ssh-ed25519" } } }); });
  await userEvent.click(await screen.findByRole("button", { name: "Aceptar esta huella y reintentar" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(2));
  expect(calls()[1][0]).toMatchObject({ expectedStartupCommand: "tmux attach -t main", accept: [`SHA256:${fp}`] }); // la misma orden que se mostró
});

test("si el núcleo no conecta porque la orden cambió, lo dice claro", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), terminalOpen: vi.fn(async () => { throw Object.assign(new Error("terminal: la orden de inicio cambió"), { cause: { code: "FailedPrecondition", reason: "terminal.err.startup_changed", metadata: {} } }); }) });
  render(<TerminalView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Conectar a LAB-CORE" }));
  expect(await screen.findByText(/terminal: la orden de inicio cambió/)).toBeVisible();
});

test("la huella de la primera vez muestra host:puerto, tipo de llave y la orden ssh-keygen para Linux y Windows", async () => {
  const fp = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Conectar a LAB-CORE" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: "x", errorInfo: { code: "FailedPrecondition", reason: "transport.hostkey.unknown", metadata: { host: "10.9.0.1:22", fingerprint: `SHA256:${fp}`, key_type: "ecdsa-sha2-nistp256" } } }); });
  expect(await screen.findByText("10.9.0.1:22")).toBeVisible();
  expect(screen.getByText("ecdsa-sha2-nistp256")).toBeVisible();
  expect(screen.getByText(`SHA256:${fp}`)).toBeVisible();
  expect(screen.getByText("ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub")).toBeVisible();
  expect(screen.getByText("ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_ecdsa_key.pub")).toBeVisible();
});
