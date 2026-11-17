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

test("si el núcleo no conecta porque la orden cambió, lo dice claro y recarga los hosts guardados", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Conectar a LAB-CORE" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
  const lists = (core.listHosts as ReturnType<typeof vi.fn>).mock.calls.length;
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: "terminal: la orden de inicio cambió", errorInfo: { code: "FailedPrecondition", reason: "terminal.err.startup_changed", metadata: {} } }); });
  expect(await screen.findByText(/La orden de inicio cambió desde que la viste/)).toBeVisible();
  await waitFor(() => expect((core.listHosts as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThan(lists));
});

const keyCred = { id: "k".repeat(32), label: "llave lab", username: "netops", kind: "key" as const, hasEnable: false, hasSshKey: true };

test("la conexión manual no ofrece credenciales de llave ni las deja por omisión", async () => {
  render(<TerminalView core={fakeCore({ listCredentials: vi.fn(async () => [keyCred, cred]) })} />);
  const sel = await screen.findByLabelText("Credencial");
  await waitFor(() => expect(sel).toHaveValue(cred.id));
  expect(screen.queryByRole("option", { name: /llave lab/ })).toBeNull();
});

test("un host con credencial de llave elegido en la libreta se abre por hostId", async () => {
  const hosts = sampleHosts.map((h, i) => (i === 0 ? { ...h, credentialId: keyCred.id } : h));
  const core = fakeCore({ listCredentials: vi.fn(async () => [keyCred, cred]), listHosts: vi.fn(async () => hosts) });
  render(<TerminalView core={core} />);
  await screen.findByRole("button", { name: "Conectar a LAB-CORE" });
  await userEvent.selectOptions(screen.getByLabelText(/Host de la libreta/i), hosts[0].id);
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
  const req = (core.terminalOpen as ReturnType<typeof vi.fn>).mock.calls[0][0];
  expect(req).toMatchObject({ hostId: hosts[0].id });
  expect(req).not.toHaveProperty("credentialId");
});

test("el botón del host anuncia su orden de inicio", async () => {
  const hosts = sampleHosts.map((h, i) => (i === 0 ? { ...h, startCommand: "tmux attach -t main" } : h));
  render(<TerminalView core={fakeCore({ listCredentials: vi.fn(async () => [cred]), listHosts: vi.fn(async () => hosts) })} />);
  expect(await screen.findByRole("button", { name: "Conectar a LAB-CORE" })).toHaveAccessibleDescription(/tmux attach -t main/);
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

// Así responde el núcleo real por hostId: la apertura misma se rechaza (FailedPrecondition), sin pestaña ni stream.
test.each([
  ["nueva", "unknown", "Aceptar esta huella y reintentar"],
  ["cambiada", "changed", "Aceptar esta huella y reintentar"],
])("si la apertura por hostId se rechaza por llave de host %s, se ofrece aceptarla y reintenta con hostId y la huella", async (_n, kind, accept) => {
  const fp = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";
  const open = vi.fn().mockRejectedValueOnce(new Error(`rpc error: code = FailedPrecondition desc = transport: ${kind} host key from 192.168.3.61:22: SHA256:${fp}`)).mockResolvedValue("t2");
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), terminalOpen: open });
  render(<TerminalView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Conectar a LAB-CORE" }));
  expect(await screen.findByText(`SHA256:${fp}`)).toBeInTheDocument();
  if (kind === "changed") expect(screen.getByText(/cambi/i)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: accept }));
  await waitFor(() => expect(open).toHaveBeenCalledTimes(2));
  expect(open.mock.calls[1][0]).toEqual({ name: "LAB-CORE", hostId: sampleHosts[0].id, expectedStartupCommand: "", accept: [`SHA256:${fp}`], rows: expect.any(Number), cols: expect.any(Number) });
  await waitFor(() => expect(screen.queryByText(`SHA256:${fp}`)).toBeNull()); // el aviso se va al reintentar
});
