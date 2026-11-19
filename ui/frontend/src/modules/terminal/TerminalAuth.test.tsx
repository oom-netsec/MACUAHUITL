import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TerminalView } from "./TerminalView";
import { fakeCore } from "../../lib/fake";
import { FakeTerm, FakeWebgl } from "./xtermMock";

vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xtermMock")).FakeTerm }));
vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xtermMock")).FakeFit }));
vi.mock("@xterm/addon-search", async () => ({ SearchAddon: (await import("./xtermMock")).FakeSearch }));
vi.mock("@xterm/addon-webgl", async () => ({ WebglAddon: (await import("./xtermMock")).FakeWebgl }));

const cred = { id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false };
const SECRET = "Zx9-SECRETO-marcador";
const OTP = "OTP-493817-marcador";
beforeEach(() => {
  FakeTerm.all.length = 0;
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(800);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(400);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); FakeWebgl.all.length = 0; localStorage.clear(); sessionStorage.clear(); });

const prompt = { runId: "t1", seq: 1, name: "MFA <b>x</b>", instruction: "Enter password\nand code \x1b[31m", prompts: [{ text: "Verification code: ", echo: true }, { text: "Password: ", echo: false }] };
const typedSetup = async (over = {}) => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), ...over });
  render(<TerminalView core={core} />);
  await userEvent.selectOptions(await screen.findByLabelText("Credencial"), "Escribir usuario y contraseña al conectar");
  return core;
};
const abrir = async (host: string) => {
  await userEvent.clear(screen.getByLabelText(/Equipo/));
  await userEvent.type(screen.getByLabelText(/Equipo/), host);
  await userEvent.click(screen.getByRole("button", { name: "Abrir pestaña" }));
};
// Todo lugar donde el marcador no debe quedar.
const leaks = (marker: string, core: { terminalSend: unknown }) => [
  document.body.innerHTML.includes(marker) ? "DOM" : "",
  [...document.querySelectorAll("input")].some((i) => i.value.includes(marker)) ? "input" : "",
  FakeTerm.all.some((x) => (x.write as ReturnType<typeof vi.fn>).mock.calls.some((c) => String(c[0]).includes(marker))) ? "terminal" : "",
  JSON.stringify((core.terminalSend as ReturnType<typeof vi.fn>).mock.calls).includes(marker) ? "terminalSend" : "",
  JSON.stringify({ ...localStorage, ...sessionStorage }).includes(marker) ? "storage" : "",
].filter(Boolean);

test("sin credencial se abre en modo tecleado: credencial vacía y el usuario opcional (vacío = «login as:»)", async () => {
  const core = await typedSetup();
  await userEvent.type(screen.getByLabelText(/Usuario \(opcional\)/), "  admin ");
  await abrir("192.0.2.1");
  expect(core.terminalOpen).toHaveBeenLastCalledWith(expect.objectContaining({ address: "192.0.2.1", credentialId: "", username: "admin" }));
  await userEvent.click(screen.getByText("Nueva sesión"));
  await userEvent.clear(screen.getByLabelText(/Usuario \(opcional\)/));
  await userEvent.click(screen.getByRole("button", { name: "Abrir pestaña" }));
  expect(core.terminalOpen).toHaveBeenLastCalledWith(expect.objectContaining({ credentialId: "", username: "" }));
});

test("con credencial guardada no se pide ni se manda usuario", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<TerminalView core={core} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  expect(screen.queryByLabelText(/Usuario \(opcional\)/)).toBeNull();
  await abrir("192.0.2.1");
  expect((core.terminalOpen as ReturnType<typeof vi.fn>).mock.calls[0][0]).not.toHaveProperty("username");
});

test("una pregunta del equipo abre un panel de texto plano, con foco en el primer campo y password si no hay eco", async () => {
  const core = await typedSetup();
  await abrir("192.0.2.1");
  await term();
  act(() => core.emitTerminal(prompt));
  const form = await screen.findByRole("form");
  expect(form).toHaveTextContent("MFA <b>x</b>"); // texto, no HTML
  expect(form.querySelector("b")).toBeNull();
  expect(form).toHaveTextContent("⟦U+001B⟧[31m"); // el ESC se ve, no actúa
  const code = screen.getByLabelText("Verification code:");
  const pw = screen.getByLabelText("Password:");
  expect(code).toHaveAttribute("type", "text");
  expect(pw).toHaveAttribute("type", "password");
  expect(code).toHaveFocus();
});
const term = async () => { await waitFor(() => expect(FakeTerm.all.length).toBeGreaterThan(0)); return FakeTerm.all[0]; };

test("con echo=false lo tecleado no está en el DOM como texto ni llega a la terminal ni a terminalSend", async () => {
  const core = await typedSetup();
  await abrir("192.0.2.1");
  await term();
  act(() => core.emitTerminal(prompt));
  await userEvent.type(await screen.findByLabelText("Password:"), SECRET);
  expect(screen.getByLabelText("Password:")).toHaveAttribute("type", "password");
  expect(document.body.textContent).not.toContain(SECRET);
  expect(document.body.innerHTML).not.toContain(SECRET); // tampoco como atributo (value=…)
  expect(leaks(SECRET, core).filter((x) => x !== "input")).toEqual([]);
});

test("al enviar: las respuestas salen por terminalAnswer y no queda ni una en el DOM, inputs, terminal, almacenamiento ni logs", async () => {
  const logs = [vi.spyOn(console, "log"), vi.spyOn(console, "error"), vi.spyOn(console, "warn"), vi.spyOn(console, "info")];
  const core = await typedSetup();
  let release = () => {};
  (core.terminalAnswer as ReturnType<typeof vi.fn>).mockImplementationOnce(() => new Promise<void>((r) => { release = r; })); // la llamada sigue en vuelo
  await abrir("192.0.2.1");
  const x = await term();
  act(() => core.emitTerminal(prompt));
  await userEvent.type(await screen.findByLabelText("Verification code:"), OTP);
  await userEvent.type(screen.getByLabelText("Password:"), `${SECRET}{Enter}`);
  expect(core.terminalAnswer).toHaveBeenCalledWith("t1", 1, [OTP, SECRET]);
  // Ya, en el mismo handler: sin esperar a la respuesta del puente.
  expect(screen.queryByRole("form")).toBeNull();
  expect(screen.queryByLabelText("Password:")).toBeNull();
  for (const m of [OTP, SECRET]) expect(leaks(m, core)).toEqual([]);
  expect(JSON.stringify(logs.map((l) => l.mock.calls))).not.toContain(SECRET);
  expect(x.write).not.toHaveBeenCalled();
  release();
  await act(async () => {});
  expect(document.body.textContent).not.toContain(SECRET);
});

test("si la respuesta falla, el error no lleva lo tecleado", async () => {
  const core = await typedSetup();
  (core.terminalAnswer as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error("sesión cerrada"));
  await abrir("192.0.2.1");
  await term();
  act(() => core.emitTerminal(prompt));
  await userEvent.type(await screen.findByLabelText("Password:"), `${SECRET}{Enter}`);
  expect(await screen.findByText(/sesión cerrada/)).toBeInTheDocument();
  expect(document.body.innerHTML).not.toContain(SECRET);
});

test("una segunda ronda llega con campos vacíos", async () => {
  const core = await typedSetup();
  await abrir("192.0.2.1");
  await term();
  act(() => core.emitTerminal(prompt));
  await userEvent.type(await screen.findByLabelText("Password:"), `${SECRET}{Enter}`);
  act(() => core.emitTerminal({ ...prompt, seq: 2 }));
  expect(await screen.findByLabelText("Password:")).toHaveValue("");
  expect(screen.getByLabelText("Verification code:")).toHaveValue("");
});

test("«Confiar y reintentar» reenvía el usuario y el par {host, huella}, nunca respuestas", async () => {
  const fp = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";
  const core = await typedSetup();
  await userEvent.type(screen.getByLabelText(/Usuario \(opcional\)/), "admin");
  await abrir("192.0.2.1:2222");
  await term();
  act(() => core.emitTerminal(prompt));
  await userEvent.type(await screen.findByLabelText("Password:"), `${SECRET}{Enter}`);
  act(() => core.emitTerminal({ runId: "t1", done: true, error: "x", errorInfo: { code: "FailedPrecondition", reason: "transport.hostkey.unknown", metadata: { host: "192.0.2.1:2222", fingerprint: `SHA256:${fp}`, key_type: "ssh-ed25519" } } }));
  await userEvent.click(await screen.findByRole("button", { name: "Aceptar esta huella y reintentar" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(2));
  const req = (core.terminalOpen as ReturnType<typeof vi.fn>).mock.calls[1][0];
  expect(req).toMatchObject({ address: "192.0.2.1", port: 2222, credentialId: "", username: "admin", acceptedKeys: [{ host: "192.0.2.1:2222", fingerprint: `SHA256:${fp}` }] });
  expect(JSON.stringify(req)).not.toContain(SECRET);
  expect(Object.keys(req).sort()).toEqual(["acceptedKeys", "accept", "address", "cols", "credentialId", "name", "port", "rows", "username"].sort());
  expect(core.terminalAnswer).toHaveBeenCalledTimes(1); // el reintento no responde nada: el equipo vuelve a preguntar
});

test("cerrar la pestaña con una pregunta abierta cierra la sesión en el núcleo (aborta) y no deja el panel", async () => {
  const core = await typedSetup();
  await abrir("192.0.2.1");
  await term();
  act(() => core.emitTerminal(prompt));
  await userEvent.type(await screen.findByLabelText("Password:"), SECRET);
  await userEvent.click(screen.getByRole("button", { name: /Cerrar/ }));
  expect(core.terminalClose).toHaveBeenCalledWith("t1");
  expect(core.terminalAnswer).not.toHaveBeenCalled();
  expect(screen.queryByRole("form")).toBeNull();
  expect(document.body.innerHTML).not.toContain(SECRET);
});

test("al terminar la sesión la pregunta pendiente desaparece", async () => {
  const core = await typedSetup();
  await abrir("192.0.2.1");
  await term();
  act(() => core.emitTerminal(prompt));
  await screen.findByRole("form");
  act(() => core.emitTerminal({ runId: "t1", done: true, error: "x", errorInfo: { code: "DeadlineExceeded", reason: "terminal.err.auth_timeout", metadata: {} } }));
  await waitFor(() => expect(screen.queryByRole("form")).toBeNull());
});
