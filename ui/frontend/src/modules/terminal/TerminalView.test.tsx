import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TerminalView } from "./TerminalView";
import { fakeCore } from "../../lib/fake";
import { vaultChanged } from "../../lib/vaultSignal";
import { FakeTerm, FakeWebgl } from "./xtermMock";
import { setTermPrefs } from "../../lib/termPrefs";

vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xtermMock")).FakeTerm }));
vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xtermMock")).FakeFit }));
vi.mock("@xterm/addon-search", async () => ({ SearchAddon: (await import("./xtermMock")).FakeSearch }));
vi.mock("@xterm/addon-webgl", async () => ({ WebglAddon: (await import("./xtermMock")).FakeWebgl }));

const cred = { id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false };
beforeEach(() => {
  FakeTerm.all.length = 0;
  // jsdom no mide: el contenedor de la terminal «mide» lo suficiente para que el ajuste corra.
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(800);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(400);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); FakeWebgl.all.length = 0; FakeWebgl.fail = false; });

const setup = (over = {}) => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), ...over });
  render(<TerminalView core={core} />);
  return core;
};
const abrir = async (host: string) => {
  await userEvent.clear(screen.getByLabelText(/Equipo/));
  await userEvent.type(screen.getByLabelText(/Equipo/), host);
  await userEvent.click(await screen.findByRole("button", { name: "Abrir pestaña" }));
};
// El emulador se carga bajo demanda: espera a que la pestaña n tenga el suyo.
const term = async (n = 0) => { await waitFor(() => expect(FakeTerm.all.length).toBeGreaterThan(n)); return FakeTerm.all[n]; };

test("avisa que lo tecleado va directo al equipo y que no se graba la contraseña", () => {
  setup();
  expect(screen.getByRole("status")).toHaveTextContent(/va directo al equipo, sin modo asistido/);
  expect(screen.getByRole("status")).toHaveTextContent(/salvo lo que se escriba en un prompt de contraseña o secreto/);
});

test("abre con el tamaño estimado, escribe la salida del equipo en el emulador y manda las teclas en crudo", async () => {
  const core = setup();
  await abrir("192.0.2.1:2222");
  expect(core.terminalOpen).toHaveBeenCalledWith({ name: "192.0.2.1:2222", address: "192.0.2.1", port: 2222, credentialId: "c1", accept: [], rows: expect.any(Number), cols: expect.any(Number) });
  const x = await term();
  act(() => {
    core.emitTerminal({ runId: "t1", opened: "admin@192.0.2.1:2222", recording: "/o/terminal/x.log" });
    core.emitTerminal({ runId: "t1", data: "\r\nSW1>" });
    core.emitTerminal({ runId: "otra", data: "ajeno" });
  });
  // La línea completa sale ya; el prompt parcial se retiene un instante (≤ 40 ms) por si la línea sigue en el chunk siguiente.
  expect(x.write).toHaveBeenCalledWith("\r\n");
  await waitFor(() => expect(x.write).toHaveBeenLastCalledWith(expect.stringMatching(/SW1>/)));
  expect(x.write).toHaveBeenCalledTimes(2);
  expect(await screen.findByText(/grabando en \/o\/terminal\/x.log/)).toBeInTheDocument();
  // Tab, flechas, ? y Ctrl-teclas llegan tal cual: así funcionan la ayuda, el completado y los paginadores.
  for (const k of ["show ver", "\t", "?", "\x1b[A", "\x03", "\x1a", " ", "\r"]) { x.type(k); await act(async () => {}); } // uno por uno: la cola envía de a una llamada
  expect((core.terminalSend as ReturnType<typeof vi.fn>).mock.calls).toEqual([["t1", "show ver"], ["t1", "\t"], ["t1", "?"], ["t1", "\x1b[A"], ["t1", "\x03"], ["t1", "\x1a"], ["t1", " "], ["t1", "\r"]]);
});

test("el tamaño ajustado se avisa al núcleo con terminalResize", async () => {
  const core = setup();
  await abrir("sw1");
  await term();
  await waitFor(() => expect(core.terminalResize).toHaveBeenCalledWith("t1", 24, 80));
});

test("la paleta elegida se aplica como tema del emulador", async () => {
  setup();
  await abrir("sw1");
  const x = await term();
  expect(x.options.theme).toMatchObject({ background: "#0d1117", foreground: "#d6dbe3", red: "#f15350", green: "#50f179" });
});

test("eventos que llegan antes de que la pestaña y su emulador existan no se pierden", async () => {
  const core = setup();
  (core.terminalOpen as ReturnType<typeof vi.fn>).mockImplementationOnce(async () => {
    core.emitTerminal({ runId: "tx", opened: "admin@h", recording: "/o/r.log" });
    core.emitTerminal({ runId: "tx", data: "temprano>" });
    return "tx";
  });
  await abrir("h");
  const x = await term();
  await waitFor(() => expect(x.write).toHaveBeenCalledWith(expect.stringMatching(/temprano>/)));
  expect(screen.getByText(/conectado a admin@h/)).toBeInTheDocument();
});

test("varias pestañas: cada una tiene su emulador y cerrar una cierra su sesión", async () => {
  const core = setup();
  await abrir("sw1");
  await abrir("sw2");
  const [a, b] = [await term(0), await term(1)];
  act(() => { core.emitTerminal({ runId: "t1", data: "uno>" }); core.emitTerminal({ runId: "t2", data: "dos>" }); });
  expect(a.write).toHaveBeenCalledWith(expect.stringMatching(/uno>/));
  expect(a.write).not.toHaveBeenCalledWith(expect.stringMatching(/dos>/));
  expect(b.write).toHaveBeenCalledWith(expect.stringMatching(/dos>/));
  b.type("x");
  expect(core.terminalSend).toHaveBeenLastCalledWith("t2", "x");
  await userEvent.click(screen.getByRole("tab", { name: "sw1" }));
  await userEvent.click(screen.getByRole("button", { name: "Cerrar pestaña sw1" }));
  expect(core.terminalClose).toHaveBeenCalledWith("t1");
  expect(a.dispose).toHaveBeenCalled();
  expect(b.dispose).not.toHaveBeenCalled();
  expect(screen.queryByRole("tab", { name: "sw1" })).not.toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "sw2" })).toBeInTheDocument();
});

test("el equipo corta: la pestaña queda cerrada y el emulador deja de aceptar teclas", async () => {
  const core = setup();
  await abrir("sw1");
  const x = await term();
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: "rpc error: code = Unavailable desc = conexión perdida: EOF" }); });
  expect(await screen.findByRole("tab", { name: "sw1 (cerrada)" })).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("conexión perdida");
  await waitFor(() => expect(x.options.disableStdin).toBe(true));
  await userEvent.click(screen.getByRole("button", { name: "Cerrar pestaña sw1" }));
  expect(core.terminalClose).not.toHaveBeenCalled(); // ya estaba cerrada
});

test("copiar y pegar son Ctrl+Mayús+C/V con el portapapeles de la app; Ctrl+C sigue siendo ^C para el equipo", async () => {
  const core = setup({ pasteText: vi.fn(async () => "texto pegado") });
  await abrir("sw1");
  const x = await term();
  const key = (init: KeyboardEventInit & { key: string }) => x.keyHandler(new KeyboardEvent("keydown", { cancelable: true, ...init }));
  expect(key({ key: "c", ctrlKey: true })).toBe(true); // xterm lo manda como \x03
  x.getSelection.mockReturnValue("interface Gi1/0/1");
  expect(key({ key: "C", ctrlKey: true, shiftKey: true })).toBe(false);
  expect(core.copyText).toHaveBeenCalledWith("interface Gi1/0/1");
  expect(key({ key: "V", ctrlKey: true, shiftKey: true })).toBe(false); // WebKitGTK no manda paste: se lee el portapapeles
  await waitFor(() => expect(x.paste).toHaveBeenCalledWith("texto pegado"));
});

test("las teclas salen en orden: un envío en vuelo a la vez y lo tecleado mientras se junta en una sola llamada", async () => {
  const core = setup();
  let libera: () => void = () => {};
  (core.terminalSend as ReturnType<typeof vi.fn>).mockImplementationOnce(() => new Promise<void>((r) => { libera = r; }));
  await abrir("sw1");
  const x = await term();
  for (const k of ["a", "b", "c"]) x.type(k);
  expect(core.terminalSend).toHaveBeenCalledTimes(1);
  expect(core.terminalSend).toHaveBeenCalledWith("t1", "a");
  await act(async () => { libera(); });
  await waitFor(() => expect(core.terminalSend).toHaveBeenCalledTimes(2));
  expect(core.terminalSend).toHaveBeenLastCalledWith("t1", "bc");
});

test("los eventos tardíos de una pestaña cerrada se descartan en vez de acumularse", async () => {
  const core = setup();
  await abrir("sw1");
  await userEvent.click(screen.getByRole("button", { name: "Cerrar pestaña sw1" }));
  act(() => { core.emitTerminal({ runId: "t1", data: "tarde" }); core.emitTerminal({ runId: "t1", done: true }); });
  // Un id repetido (solo en la prueba) recibiría lo guardado en «early»: no debe recibir nada.
  (core.terminalOpen as ReturnType<typeof vi.fn>).mockImplementationOnce(async () => "t1");
  await abrir("sw2");
  const x = await term(1);
  expect(x.write).not.toHaveBeenCalledWith("tarde");
  expect(screen.queryByRole("tab", { name: /cerrada/ })).not.toBeInTheDocument();
});

test("el modo lector de pantalla del emulador sigue la preferencia (apagado por defecto)", async () => {
  setTermPrefs({ srm: false });
  setup();
  await abrir("sw1");
  const x = await term();
  expect(x.options.screenReaderMode).toBe(false);
  act(() => setTermPrefs({ srm: true }));
  await waitFor(() => expect(x.options.screenReaderMode).toBe(true));
  act(() => setTermPrefs({ srm: false }));
});

test("Ctrl+Mayús+K saca el foco de la terminal hacia la pestaña", async () => {
  setup();
  await abrir("sw1");
  const x = await term();
  expect(x.keyHandler(new KeyboardEvent("keydown", { key: "K", ctrlKey: true, shiftKey: true, cancelable: true }))).toBe(false);
  expect(x.blur).toHaveBeenCalled();
  expect(screen.getByRole("tab", { name: "sw1" })).toHaveFocus();
});

test("una llave de host nueva muestra la huella para aceptarla", async () => {
  setup({ terminalOpen: vi.fn().mockRejectedValue(new Error("rpc error: code = FailedPrecondition desc = llave de host desconocida: SHA256:abc")) });
  await abrir("sw1");
  expect(await screen.findByRole("alert")).toHaveTextContent("SHA256:abc");
  expect(screen.queryByRole("tab")).not.toBeInTheDocument();
});

test("al salir del módulo se cierran las sesiones vivas", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  const { unmount } = render(<TerminalView core={core} />);
  await abrir("sw1");
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalled());
  unmount();
  expect(core.terminalClose).toHaveBeenCalledWith("t1");
});

test("si la vista se desmonta con terminalOpen en vuelo, la sesión que llega después se cierra", async () => {
  let resolve!: (id: string) => void;
  const terminalOpen = vi.fn(() => new Promise<string>((r) => { resolve = r; }));
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), terminalOpen });
  const { unmount } = render(<TerminalView core={core} />);
  await abrir("sw1");
  await waitFor(() => expect(terminalOpen).toHaveBeenCalled());
  unmount();
  expect(core.terminalClose).not.toHaveBeenCalled();
  await act(async () => { resolve("t9"); });
  expect(core.terminalClose).toHaveBeenCalledWith("t9");
});

test("una credencial creada después de abrir la vista aparece sin reabrirla", async () => {
  const cred = { id: "c9", label: "Sw", username: "admin", hasEnable: false, hasSshKey: false };
  const listCredentials = vi.fn().mockResolvedValueOnce([]).mockResolvedValue([cred]);
  render(<TerminalView core={fakeCore({ listCredentials })} />);
  await waitFor(() => expect(listCredentials).toHaveBeenCalledTimes(1));
  expect(screen.queryByRole("option", { name: "Sw (admin)" })).not.toBeInTheDocument();
  act(() => vaultChanged()); // la bóveda avisa: creada, credencial agregada
  expect(await screen.findByRole("option", { name: "Sw (admin)" })).toBeInTheDocument();
  expect(screen.getByLabelText("Credencial")).toHaveValue("c9");
});

test("una llave de host nueva ofrece aceptar la huella y reintenta con ella; la huella sin prefijo también vale", async () => {
  const fp = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";
  const core = setup();
  await userEvent.type(screen.getByLabelText(/Huellas aceptadas/), "AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIIIjjjjKKK"); // otra huella, sin prefijo
  await abrir("192.168.3.2");
  expect(core.terminalOpen).toHaveBeenLastCalledWith(expect.objectContaining({ accept: ["SHA256:AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIIIjjjjKKK"] }));
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: `transport: llave de host desconocida de 192.168.3.2:22: SHA256:${fp}` }); });
  expect(await screen.findByText(`SHA256:${fp}`)).toBeInTheDocument();
  await userEvent.clear(screen.getByLabelText(/Equipo/));
  await userEvent.type(screen.getByLabelText(/Equipo/), "10.9.9.9"); // otro equipo en el campo: la huella no se le manda
  await userEvent.click(screen.getByRole("button", { name: "Aceptar esta huella y reintentar" }));
  await waitFor(() => expect(core.terminalOpen).toHaveBeenCalledTimes(2));
  expect(core.terminalOpen).toHaveBeenLastCalledWith(expect.objectContaining({ address: "192.168.3.2", accept: ["SHA256:AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIIIjjjjKKK", `SHA256:${fp}`] }));
});

test("la pestaña y la línea de estado muestran el punto de la conexión: conectando, viva y cerrada con error", async () => {
  const core = setup();
  await abrir("sw1");
  await term();
  const state = () => document.querySelector(".ssh-tab")!.getAttribute("data-state");
  expect(state()).toBe("connecting");
  act(() => { core.emitTerminal({ runId: "t1", opened: "admin@sw1:22", recording: "/o/terminal/x.log" }); });
  expect(state()).toBe("live");
  expect(document.querySelector(".ssh-status")).toHaveAttribute("data-state", "live");
  expect(document.querySelector(".ssh-status")).toHaveTextContent(/conectado a admin@sw1:22/);
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: "conexión perdida" }); });
  expect(state()).toBe("error");
});

test("el emulador se abre como un emulador de terminal de escritorio: cursor de bloque que parpadea, sin interlineado extra y mucho historial", async () => {
  setup();
  await abrir("sw1");
  const x = await term();
  expect(x.options).toMatchObject({ cursorStyle: "block", cursorBlink: true, lineHeight: 1, fontSize: 14, scrollback: 20000 });
  expect(String(x.options.fontFamily)).toMatch(/^"JetBrains Mono"/);
});

test("con una sesión abierta el formulario se pliega en una línea y el aviso se va: la terminal se queda con la pantalla", async () => {
  setup();
  expect(screen.getByText(/Terminal manual/)).toBeInTheDocument();
  await abrir("sw1");
  await term();
  expect(screen.queryByText(/Terminal manual/)).not.toBeInTheDocument();
  const plegado = screen.getByText("Nueva sesión").closest("details");
  expect(plegado).not.toBeNull();
  expect(plegado!.open).toBe(false);
});

test("Ctrl+Enter no abre otra sesión desde el formulario plegado, que no está a la vista", async () => {
  const { App } = await import("../../app/App");
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  render(<App core={core} initial="terminal" />);
  await waitFor(() => expect(screen.getByLabelText(/Equipo/)).toBeInTheDocument());
  await abrir("sw1");
  await term();
  screen.getByRole("tab", { name: /sw1/ }).focus();
  await userEvent.keyboard("{Control>}{Enter}{/Control}");
  await act(async () => {});
  expect(core.terminalOpen).toHaveBeenCalledTimes(1);
});

test("la terminal dibuja con WebGL: la CSP estricta rechaza los estilos en línea del renderizador DOM", async () => {
  FakeWebgl.all.length = 0; FakeWebgl.fail = false;
  setup();
  await abrir("sw1");
  const x = await term();
  await waitFor(() => expect(FakeWebgl.all).toHaveLength(1));
  expect(x.loadAddon).toHaveBeenCalledWith(FakeWebgl.all[0]);
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

test("sin WebGL, o si se pierde el contexto, se avisa en vez de mostrar la terminal rota", async () => {
  FakeWebgl.all.length = 0; FakeWebgl.fail = true;
  setup();
  await abrir("sw1");
  await term();
  expect(await screen.findByRole("alert")).toHaveTextContent(/no obtuvo WebGL/);
  FakeWebgl.fail = false;
  await abrir("sw2");
  await term(1);
  await waitFor(() => expect(FakeWebgl.all).toHaveLength(1));
  act(() => FakeWebgl.all[0].lost?.());
  await waitFor(() => expect(screen.getAllByRole("alert", { hidden: true })).toHaveLength(2));
  expect(FakeWebgl.all[0].dispose).toHaveBeenCalled();
});

test("solo el panel a la vista tiene contexto WebGL: al ocultarse lo suelta y al volver lo crea de nuevo", async () => {
  setup();
  await abrir("sw1");
  await term();
  await waitFor(() => expect(FakeWebgl.all).toHaveLength(1));
  await abrir("sw2");
  await term(1);
  await waitFor(() => expect(FakeWebgl.all).toHaveLength(2));
  expect(FakeWebgl.all[0].dispose).toHaveBeenCalled(); // sw1 quedó oculta
  expect(FakeWebgl.all[1].dispose).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("tab", { name: "sw1" }));
  await waitFor(() => expect(FakeWebgl.all).toHaveLength(3)); // sw1 a la vista otra vez: contexto nuevo
  expect(FakeWebgl.all[1].dispose).toHaveBeenCalled();
});

test("elegir un host de la libreta rellena equipo, puerto y credencial; sin credencial limpia la anterior y obliga a elegir", async () => {
  const lab = { id: "c".repeat(32), label: "admin lab", username: "root", hasEnable: false, hasSshKey: false };
  const core = setup({ listCredentials: vi.fn(async () => [cred, lab]) });
  const pick = await screen.findByLabelText("Host de la libreta");
  // Agrupado por carpeta: Lab, Oficina.
  expect(within(pick).getAllByRole("group").map((g) => g.getAttribute("label"))).toEqual(["Lab", "Oficina"]);
  await userEvent.selectOptions(pick, "a".repeat(32)); // LAB-CORE, puerto 22, credencial «admin lab»
  expect(screen.getByLabelText(/Equipo/)).toHaveValue("10.9.0.1");
  expect(screen.getByLabelText("Credencial")).toHaveValue(lab.id);
  expect(pick).toHaveValue("a".repeat(32)); // el selector muestra el host elegido
  await userEvent.selectOptions(pick, "b".repeat(32)); // LAB-AP, puerto 2222, sin credencial: no deja la anterior
  expect(screen.getByLabelText(/Equipo/)).toHaveValue("ap1.lab:2222");
  expect(screen.getByLabelText("Credencial")).toHaveValue("");
  expect(screen.getByText("Este host no tiene credencial en la bóveda: elige una")).toBeVisible();
  expect(screen.getByRole("button", { name: "Abrir pestaña" })).toBeDisabled();
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), lab.id);
  expect(screen.queryByText("Este host no tiene credencial en la bóveda: elige una")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Abrir pestaña" }));
  expect(core.terminalOpen).toHaveBeenCalledWith(expect.objectContaining({ address: "ap1.lab", port: 2222, credentialId: lab.id }));
});

test("un host con credencial borrada de la bóveda tampoco hereda la anterior", async () => {
  setup({ listHosts: vi.fn(async () => [{ id: "e".repeat(32), name: "HUERFANO", address: "10.1.1.1", port: 22, platform: "", folder: "", tags: [], credentialId: "f".repeat(32), credentialLabel: "", notes: "" }]) });
  await userEvent.selectOptions(await screen.findByLabelText("Host de la libreta"), "e".repeat(32));
  expect(screen.getByLabelText("Credencial")).toHaveValue("");
  expect(screen.getByText("Este host no tiene credencial en la bóveda: elige una")).toBeVisible();
});

test("un host IPv6 con puerto distinto de 22 abre la sesión en ese puerto", async () => {
  const v6 = { id: "e".repeat(32), name: "V6", address: "fe80::1", port: 2222, platform: "", folder: "", tags: [], credentialId: cred.id, credentialLabel: "lab", notes: "" };
  const core = setup({ listHosts: vi.fn(async () => [v6]) });
  await userEvent.selectOptions(await screen.findByLabelText("Host de la libreta"), v6.id);
  expect(screen.getByLabelText(/Equipo/)).toHaveValue("[fe80::1]:2222");
  await userEvent.click(screen.getByRole("button", { name: "Abrir pestaña" }));
  expect(core.terminalOpen).toHaveBeenCalledWith(expect.objectContaining({ address: "fe80::1", port: 2222, credentialId: cred.id }));
});

test("la búsqueda del selector de hosts filtra la lista", async () => {
  setup();
  await userEvent.type(await screen.findByLabelText("Buscar en la libreta"), "oficina");
  const pick = screen.getByLabelText("Host de la libreta");
  expect(within(pick).getAllByRole("option").map((o) => o.textContent)).toEqual(["Elegir un host…", "OFI-SW · 10.8.0.1:22"]);
});

// Con la interfaz en otro idioma la huella sale del errorInfo del evento terminal:done, no del texto.
test("una llave de host cambiada llega por errorInfo y ofrece aceptarla aunque el texto no sea el esperado", async () => {
  const fp = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";
  const core = setup();
  await abrir("192.168.3.2");
  act(() => { core.emitTerminal({ runId: "t1", done: true, error: "transport: clé d'hôte modifiée", errorInfo: { code: "FailedPrecondition", reason: "transport.hostkey.changed", metadata: { fingerprint: `SHA256:${fp}` } } }); });
  expect(await screen.findByText(`SHA256:${fp}`)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Aceptar esta huella y reintentar" })).toBeInTheDocument();
});
