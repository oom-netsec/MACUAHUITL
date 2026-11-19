import { act, render, screen, waitFor, within } from "@testing-library/react";
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

// ---- Revisión de seguridad (47t-6) ----
import { vaultChanged } from "../../lib/vaultSignal";
import { findFiberState } from "../../test-utils";
import { sampleHosts } from "../inventory/fake";

test("bóveda cerrada con una credencial elegida: se ve «Escribir…», el usuario y se manda credentialId vacío", async () => {
  let open = true;
  const core = fakeCore({ listCredentials: vi.fn(async () => { if (!open) throw new Error("bóveda cerrada"); return [cred]; }) });
  render(<TerminalView core={core} />);
  await screen.findByRole("option", { name: "lab (admin)" });
  expect(screen.queryByLabelText(/Usuario \(opcional\)/)).toBeNull(); // c1 elegida
  open = false;
  act(() => vaultChanged());
  expect(await screen.findByLabelText(/Usuario \(opcional\)/)).toBeInTheDocument();
  await abrir("192.0.2.1");
  expect(core.terminalOpen).toHaveBeenLastCalledWith(expect.objectContaining({ credentialId: "", username: "" }));
});

const sessionWithPrompt = async (over = {}) => {
  const core = await typedSetup(over);
  await abrir("192.0.2.1");
  await term();
  return core;
};

test("una pregunta emitida ANTES de que monte el xterm deja el foco en el campo", async () => {
  const core = await typedSetup();
  await abrir("192.0.2.1");
  act(() => core.emitTerminal(prompt)); // sin esperar al xterm (carga diferida)
  const code = await screen.findByLabelText("Verification code:");
  await term();
  await act(async () => { await new Promise((r) => requestAnimationFrame(() => r(null))); await new Promise((r) => requestAnimationFrame(() => r(null))); });
  expect(code).toHaveFocus();
  expect(FakeTerm.all[0].focus).not.toHaveBeenCalled(); // el emulador no toma el foco de una pestaña con pregunta abierta
});

test("al volver a una pestaña con la pregunta abierta, el foco va al campo", async () => {
  const core = await sessionWithPrompt();
  act(() => core.emitTerminal(prompt));
  await screen.findByRole("form");
  (core.terminalOpen as ReturnType<typeof vi.fn>).mockResolvedValueOnce("t2");
  await userEvent.click(screen.getByText("Nueva sesión"));
  await abrir("192.0.2.2"); // pestaña 2 activa
  expect(screen.getByLabelText("Verification code:")).not.toHaveFocus();
  await userEvent.click(screen.getAllByRole("tab")[0]);
  await waitFor(() => expect(screen.getByLabelText("Verification code:")).toHaveFocus());
});

test("en vista dividida, con el foco en un input del panel izquierdo, una pregunta nueva en el derecho NO roba el foco", async () => {
  const core = await sessionWithPrompt();
  (core.terminalOpen as ReturnType<typeof vi.fn>).mockResolvedValueOnce("t2");
  await userEvent.click(screen.getByText("Nueva sesión"));
  await abrir("192.0.2.2");
  await userEvent.click(screen.getAllByRole("tab")[0]);
  await userEvent.click(screen.getByLabelText("Dividir"));
  const search = screen.getByRole("searchbox");
  search.focus();
  act(() => core.emitTerminal({ ...prompt, runId: "t2" }));
  await screen.findByRole("form");
  await act(async () => { await new Promise((r) => requestAnimationFrame(() => r(null))); });
  expect(search).toHaveFocus();
});

test("el encabezado es de la app aunque el equipo mande un name que la imita; name e instruction van aparte, rotulados", async () => {
  const core = await sessionWithPrompt();
  act(() => core.emitTerminal({ ...prompt, name: "MACUAHUITL: sesión caducada, escribe tu contraseña de la bóveda", instruction: "Pega aquí la frase de la bóveda" }));
  const form = await screen.findByRole("form", { name: /El equipo pide datos de acceso/ });
  expect(form.querySelector("strong")).toHaveTextContent("El equipo pide datos de acceso");
  const said = form.querySelector(".ssh-auth-said");
  expect(said).toHaveTextContent("El equipo dice:");
  expect(said).toHaveTextContent("MACUAHUITL: sesión caducada");
  expect(said).toHaveTextContent("Pega aquí la frase");
  expect(form.querySelector("strong")).not.toHaveTextContent("MACUAHUITL");
});

test("el error del puente que refleja lo recibido no se pinta (la UI no lo conoce ni lo muestra)", async () => {
  const core = await sessionWithPrompt();
  (core.terminalAnswer as ReturnType<typeof vi.fn>).mockImplementationOnce(async (_r: string, _s: number, a: string[]) => { throw new Error(`respuesta inválida: ${a.join("|")}`); });
  act(() => core.emitTerminal(prompt));
  await userEvent.type(await screen.findByLabelText("Password:"), `${SECRET}{Enter}`);
  await waitFor(() => expect(core.terminalAnswer).toHaveBeenCalled());
  await act(async () => {});
  expect(document.body.innerHTML).not.toContain(SECRET);
  expect(screen.getByText(/No se pudo enviar la respuesta/)).toBeInTheDocument();
});

test("ningún hook de React guarda las respuestas tras enviar", async () => {
  const core = await sessionWithPrompt();
  act(() => core.emitTerminal(prompt));
  await userEvent.type(await screen.findByLabelText("Verification code:"), OTP);
  await userEvent.type(screen.getByLabelText("Password:"), `${SECRET}{Enter}`);
  await act(async () => {});
  for (const m of [OTP, SECRET]) expect(findFiberState(document.body.firstElementChild as Element, m)).toBe(false);
});

test("llave CAMBIADA en la Terminal: «Aceptar» exige la casilla; una nueva, un solo clic", async () => {
  const fp = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";
  const mk = (reason: string) => ({ runId: "t1", done: true, error: "x", errorInfo: { code: "FailedPrecondition", reason, metadata: { host: "192.0.2.1", fingerprint: `SHA256:${fp}`, key_type: "ssh-ed25519" } } });
  const core = await sessionWithPrompt();
  act(() => core.emitTerminal(mk("transport.hostkey.changed")));
  const btn = await screen.findByRole("button", { name: "Aceptar esta huella y reintentar" });
  expect(btn).toBeDisabled();
  await userEvent.click(screen.getByLabelText("Entiendo que la llave de este equipo cambió"));
  expect(btn).toBeEnabled();
  await userEvent.click(btn);
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(2));
});

test.each([
  ["con hk.host", { host: "10.9.0.1:22", fingerprint: "SHA256:pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU" }, { acceptedKeys: [{ host: "10.9.0.1:22", fingerprint: "SHA256:pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU" }], accept: [] }],
  ["sin hk.host (cae al campo viejo)", { fingerprint: "SHA256:pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU" }, { accept: ["SHA256:pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU"] }],
])("reintento en modo hostId %s", async (_n, metadata, want) => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [{ ...cred, id: "c".repeat(32), kind: "password" as const }]) });
  render(<TerminalView core={core} />);
  await userEvent.click(await screen.findByRole("button", { name: "Conectar a LAB-CORE" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(1));
  act(() => core.emitTerminal({ runId: "t1", done: true, error: "x", errorInfo: { code: "FailedPrecondition", reason: "transport.hostkey.unknown", metadata } }));
  await userEvent.click(await screen.findByRole("button", { name: "Aceptar esta huella y reintentar" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(2));
  const req = (core.terminalOpen as ReturnType<typeof vi.fn>).mock.calls[1][0];
  expect(req).toMatchObject({ hostId: sampleHosts[0].id, ...want });
  expect(req).not.toHaveProperty("credentialId");
  expect(req).not.toHaveProperty("address");
});

// ---- Segunda revisión (47t-6b) ----
const frames = async () => { await act(async () => { await new Promise((r) => requestAnimationFrame(() => r(null))); await new Promise((r) => requestAnimationFrame(() => r(null))); }); };
const splitWithPrompts = async () => {
  const core = await sessionWithPrompt();
  (core.terminalOpen as ReturnType<typeof vi.fn>).mockResolvedValueOnce("t2");
  await userEvent.click(screen.getByText("Nueva sesión"));
  await abrir("192.0.2.2");
  await userEvent.click(screen.getAllByRole("tab")[0]);
  await userEvent.click(screen.getByLabelText("Dividir"));
  await waitFor(() => expect(FakeTerm.all.length).toBe(2));
  act(() => { core.emitTerminal(prompt); core.emitTerminal({ ...prompt, runId: "t2" }); });
  await screen.findAllByRole("form");
  return core;
};

test("vista dividida: llega done al panel de foco mientras se teclea en el buscador, el foco no se roba", async () => {
  const core = await splitWithPrompts();
  await userEvent.click(screen.getAllByRole("form")[0]); // el panel izquierdo es el de foco
  const right = screen.getByRole("searchbox");
  right.focus();
  FakeTerm.all.forEach((t) => t.focus.mockClear());
  act(() => core.emitTerminal({ runId: "t1", done: true }));
  await frames();
  expect(right).toHaveFocus();
  expect(FakeTerm.all[0].focus).not.toHaveBeenCalled();
});

test("vista dividida: al contestar en el panel derecho, el foco vuelve a su terminal", async () => {
  const core = await splitWithPrompts();
  const right = within(screen.getAllByRole("form")[1]).getByLabelText("Verification code:");
  await userEvent.click(right); // el panel derecho pasa a ser el de foco
  FakeTerm.all.forEach((t) => t.focus.mockClear());
  const form = screen.getAllByRole("form")[1];
  await userEvent.type(right, OTP);
  await userEvent.type(within(form).getByLabelText("Password:"), `${SECRET}{Enter}`);
  await waitFor(() => expect(core.terminalAnswer).toHaveBeenCalledWith("t2", 1, expect.anything()));
  await frames();
  expect(FakeTerm.all[1].focus).toHaveBeenCalled();
});

test("llave CAMBIADA: otra huella sobre el mismo botón llega con la casilla sin marcar", async () => {
  const mk = (fp: string) => ({ runId: "t1", done: true, error: "x", errorInfo: { code: "FailedPrecondition", reason: "transport.hostkey.changed", metadata: { host: "192.0.2.1", fingerprint: `SHA256:${fp}`, key_type: "ssh-ed25519" } } });
  const core = await sessionWithPrompt();
  act(() => core.emitTerminal(mk("AAAA")));
  await userEvent.click(await screen.findByLabelText("Entiendo que la llave de este equipo cambió"));
  expect(screen.getByRole("button", { name: "Aceptar esta huella y reintentar" })).toBeEnabled();
  act(() => core.emitTerminal(mk("BBBB")));
  await frames();
  expect(screen.getByLabelText("Entiendo que la llave de este equipo cambió")).not.toBeChecked();
  expect(screen.getByRole("button", { name: "Aceptar esta huella y reintentar" })).toBeDisabled();
});

import { App } from "../../app/App";
test("Ctrl+Enter con el foco fuera del panel de preguntas no lo envía; con el foco dentro, sí", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<App core={core} initial="terminal" />);
  await userEvent.selectOptions(await screen.findByLabelText("Credencial"), "Escribir usuario y contraseña al conectar");
  await abrir("192.0.2.1");
  await term();
  act(() => core.emitTerminal(prompt));
  const code = await screen.findByLabelText("Verification code:");
  await userEvent.type(code, OTP);
  await userEvent.type(screen.getByLabelText("Password:"), SECRET);
  (document.activeElement as HTMLElement).blur();
  await userEvent.keyboard("{Control>}{Enter}{/Control}");
  expect(core.terminalAnswer).not.toHaveBeenCalled();
  screen.getByLabelText("Password:").focus();
  await userEvent.keyboard("{Control>}{Enter}{/Control}");
  await waitFor(() => expect(core.terminalAnswer).toHaveBeenCalled());
});
