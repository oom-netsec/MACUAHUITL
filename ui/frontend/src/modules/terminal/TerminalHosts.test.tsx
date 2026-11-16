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
  expect(req).toEqual({ name: "LAB-CORE", hostId: sampleHosts[0].id, accept: [], rows: expect.any(Number), cols: expect.any(Number) });
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
  expect(core.terminalOpen).toHaveBeenLastCalledWith(expect.objectContaining({ hostId: sampleHosts[0].id, accept: [`SHA256:${fp}`] }));
  expect((core.terminalOpen as ReturnType<typeof vi.fn>).mock.calls[1][0]).not.toHaveProperty("address");
});
