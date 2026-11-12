import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TerminalView } from "./TerminalView";
import { fakeCore } from "../../lib/fake";
import { NavContext, type Delivery } from "../../app/activity";
import { scriptsChanged } from "../scripts/signal";
import { encodeInsert } from "../scripts/text";
import type { ScriptItem } from "../scripts/api";
import { FakeTerm } from "./xtermMock";

vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xtermMock")).FakeTerm }));
vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xtermMock")).FakeFit }));
vi.mock("@xterm/addon-search", async () => ({ SearchAddon: (await import("./xtermMock")).FakeSearch }));
vi.mock("@xterm/addon-webgl", async () => ({ WebglAddon: (await import("./xtermMock")).FakeWebgl }));

const cred = { id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false };
beforeEach(() => {
  FakeTerm.all.length = 0;
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(800);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(400);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

const fav = (name: string, commands: string[], readOnly = true): ScriptItem => ({
  id: name, name, tech: "l3", platform: "ios-xe", description: "", commands, tags: [], origin: "usuario", createdMs: 0, updatedMs: 0, readOnly, favorite: true, pinned: false, collections: ["favoritos"],
});
const OSPF = fav("Mi OSPF", ["show ip ospf neighbor"]);
const MULTI = fav("Vecinos", ["show cdp neighbors", "! comentario", "show lldp neighbors"]);
const CFG = fav("Config NTP", ["configure terminal", "ntp server 192.0.2.10", "end"], false);
const CFG1 = fav("Un comando", ["clear counters"], false);
const NO_CFG = /Los scripts de configuración no se envían a la terminal: cada salto de línea ejecutaría una línea\. Aplícalos con un snippet en modo asistido o pégalos tú\./;
const CLEAR = "\x15"; // Ctrl+U: borra lo que hubiera a medio teclear antes del texto

const tree = (core: ReturnType<typeof fakeCore>, inbox: Record<string, Delivery> = {}) => (
  <NavContext.Provider value={{ go: vi.fn(), inbox }}><TerminalView core={core} /></NavContext.Provider>
);
const setup = (over = {}, inbox: Record<string, Delivery> = {}) => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), listPinnedScripts: vi.fn(async () => [OSPF, MULTI, CFG, CFG1]), ...over });
  const view = render(tree(core, inbox));
  const send = (text: string, name = "Script", readOnly = true, n = 1) =>
    view.rerender(tree(core, { "terminal-insert": { data: encodeInsert({ name, text, readOnly }), n } }));
  return { core, send };
};
const abrir = async (host = "sw1") => {
  await userEvent.clear(screen.getByLabelText(/Equipo/));
  await userEvent.type(screen.getByLabelText(/Equipo/), host);
  await userEvent.click(await screen.findByRole("button", { name: "Abrir pestaña" }));
};
const term = async (n = 0) => { await waitFor(() => expect(FakeTerm.all.length).toBeGreaterThan(n)); };
const flush = () => act(async () => {});
const sent = (core: ReturnType<typeof fakeCore>) => (core.terminalSend as ReturnType<typeof vi.fn>).mock.calls;
const favBtn = (name: string) => screen.findByRole("button", { name: new RegExp(`script «${name}»`) });

describe("fijados en los comandos rápidos", () => {
  test("aparecen en el orden de fijado tras los comandos fijos, antes de «Scripts ▾»; los de una línea se insertan sin Enter", async () => {
    const { core } = setup();
    await abrir(); await term();
    const group = screen.getByRole("group", { name: "Comandos rápidos" });
    expect(core.listPinnedScripts).toHaveBeenCalled();
    await waitFor(() => expect(within(group).getAllByRole("button").map((b) => b.textContent)).toEqual(["show running-config", "show version", "show ip interface brief", "show interfaces status", "Mi OSPF", "Vecinos", "Config NTP", "Un comando", "Scripts ▾"]));
    await userEvent.click(await favBtn("Mi OSPF"));
    await waitFor(() => expect(sent(core)).toEqual([["t1", CLEAR + "show ip ospf neighbor"]]));
  });

  test("uno de varias líneas de solo lectura confirma con su nombre y el equipo; manda las líneas tal cual (también «!») y la última sin Enter", async () => {
    const { core } = setup();
    await abrir(); await term();
    await userEvent.click(await favBtn("Vecinos"));
    await waitFor(() => expect(core.confirmPaste).toHaveBeenCalledWith("show cdp neighbors\n! comentario\nshow lldp neighbors", "sw1", "Vecinos"));
    await waitFor(() => expect(sent(core)).toEqual([["t1", CLEAR + "show cdp neighbors\r! comentario\rshow lldp neighbors"]]));
  });

  test("si la persona rechaza la confirmación no se envía nada", async () => {
    const { core } = setup({ confirmPaste: vi.fn(async () => false) });
    await abrir(); await term();
    await userEvent.click(await favBtn("Vecinos"));
    await waitFor(() => expect(core.confirmPaste).toHaveBeenCalled());
    await flush();
    expect(sent(core)).toEqual([]);
  });

  test("uno de configuración de varias líneas no se envía: el botón copia y avisa", async () => {
    const { core } = setup();
    await abrir(); await term();
    const b = await screen.findByRole("button", { name: /Copiar el script «Config NTP»/ });
    await userEvent.click(b);
    await waitFor(() => expect(core.copyText).toHaveBeenCalledWith("configure terminal\nntp server 192.0.2.10\nend"));
    expect(await screen.findByText(NO_CFG)).toBeInTheDocument();
    await flush();
    expect(core.confirmPaste).not.toHaveBeenCalled();
    expect(sent(core)).toEqual([]);
  });

  test("uno de configuración de una sola línea se inserta sin Enter", async () => {
    const { core } = setup();
    await abrir(); await term();
    await userEvent.click(await favBtn("Un comando"));
    await waitFor(() => expect(sent(core)).toEqual([["t1", CLEAR + "clear counters"]]));
    expect(core.copyText).not.toHaveBeenCalled();
  });

  test("la lista se refresca cuando cambian los scripts", async () => {
    const list = vi.fn(async () => [OSPF]);
    setup({ listPinnedScripts: list });
    await abrir(); await term();
    await favBtn("Mi OSPF");
    list.mockImplementation(async () => []);
    act(() => scriptsChanged());
    await waitFor(() => expect(screen.queryByRole("button", { name: /script «Mi OSPF»/ })).not.toBeInTheDocument());
  });

  test("si el núcleo no responde no hay fijados y los comandos fijos siguen", async () => {
    setup({ listPinnedScripts: vi.fn(async () => { throw new Error("bóveda cerrada"); }) });
    await abrir(); await term();
    expect(within(screen.getByRole("group", { name: "Comandos rápidos" })).getAllByRole("button").map((b) => b.textContent)).toEqual(["show running-config", "show version", "show ip interface brief", "show interfaces status", "Scripts ▾"]);
  });
});

describe("enviar a la terminal desde Scripts (canal terminal-insert)", () => {
  test("una línea se inserta en la sesión activa sin Enter, tras borrar lo que hubiera en el prompt", async () => {
    const { core, send } = setup();
    await abrir(); await term();
    send("show clock");
    await waitFor(() => expect(sent(core)).toEqual([["t1", CLEAR + "show clock"]]));
    expect(core.confirmPaste).not.toHaveBeenCalled();
  });

  test("varias líneas de solo lectura piden confirmación con el nombre; las intermedias salen con salto y la última sin Enter", async () => {
    const { core, send } = setup();
    await abrir(); await term();
    send("show a\nshow b\nshow c", "Tres");
    await waitFor(() => expect(core.confirmPaste).toHaveBeenCalledWith("show a\nshow b\nshow c", "sw1", "Tres"));
    await waitFor(() => expect(sent(core)).toEqual([["t1", CLEAR + "show a\rshow b\rshow c"]]));
  });

  test("varias líneas de configuración que lleguen por el canal tampoco se envían", async () => {
    const { core, send } = setup();
    await abrir(); await term();
    send("conf t\nshutdown\nend", "Peligro", false);
    expect(await screen.findByText(NO_CFG)).toBeInTheDocument();
    await flush();
    expect(core.confirmPaste).not.toHaveBeenCalled();
    expect(sent(core)).toEqual([]);
  });

  test("varias líneas rechazadas no se envían", async () => {
    const { core, send } = setup({ confirmPaste: vi.fn(async () => false) });
    await abrir(); await term();
    send("a\nb");
    await waitFor(() => expect(core.confirmPaste).toHaveBeenCalled());
    await flush();
    expect(sent(core)).toEqual([]);
  });

  test("si la sesión se cierra mientras el diálogo está abierto, no se envía", async () => {
    let answer: (v: boolean) => void = () => {};
    const { core, send } = setup({ confirmPaste: vi.fn(() => new Promise<boolean>((r) => { answer = r; })) });
    await abrir(); await term();
    send("a\nb");
    await waitFor(() => expect(core.confirmPaste).toHaveBeenCalled());
    act(() => { core.emitTerminal({ runId: "t1", done: true }); });
    await act(async () => { answer(true); });
    await flush();
    expect(sent(core)).toEqual([]);
  });

  test("sin sesión abierta avisa y no envía nada", async () => {
    const { core, send } = setup();
    send("show clock");
    expect(await screen.findByText(/No hay una sesión SSH abierta donde insertar el script/)).toBeInTheDocument();
    await flush();
    expect(sent(core)).toEqual([]);
  });

  test("si ya llegó cuando la vista se monta, también avisa", async () => {
    const { core } = setup({}, { "terminal-insert": { data: encodeInsert({ name: "X", text: "show clock", readOnly: true }), n: 1 } });
    expect(await screen.findByText(/No hay una sesión SSH abierta/)).toBeInTheDocument();
    await flush();
    expect(sent(core)).toEqual([]);
  });

  test("con la sesión cerrada avisa y no envía", async () => {
    const { core, send } = setup();
    await abrir(); await term();
    act(() => { core.emitTerminal({ runId: "t1", done: true }); });
    send("show clock");
    expect(await screen.findByText(/No hay una sesión SSH abierta/)).toBeInTheDocument();
    await flush();
    expect(sent(core)).toEqual([]);
  });

  test("dos envíos del mismo texto se reciben los dos", async () => {
    const { core, send } = setup();
    await abrir(); await term();
    send("show clock", "X", true, 1);
    await waitFor(() => expect(sent(core)).toHaveLength(1));
    send("show clock", "X", true, 2);
    await waitFor(() => expect(sent(core)).toHaveLength(2));
  });

  test("con pantalla dividida inserta en la sesión del panel con foco y le da el foco a su emulador, no al primero del DOM", async () => {
    const { core, send } = setup();
    await abrir("sw1"); await term();
    await abrir("sw2"); await term(1);
    await userEvent.click(await screen.findByRole("checkbox", { name: "Dividir" })); // activa sw2; sw1 es el segundo panel
    const panes = [...document.querySelectorAll<HTMLElement>(".ssh-pane")]; // en el orden de las pestañas: sw1, sw2
    expect(panes).toHaveLength(2);
    // jsdom no monta xterm de verdad: cada panel recibe su textarea de ayuda.
    const areas = panes.map((p) => { const a = document.createElement("textarea"); a.className = "xterm-helper-textarea"; p.appendChild(a); return a; });
    send("show clock", "X", true, 1); // sin clic: la herramienta sigue a la pestaña activa (sw2, segundo en el DOM)
    await waitFor(() => expect(sent(core)).toEqual([["t2", CLEAR + "show clock"]]));
    await waitFor(() => expect(document.activeElement).toBe(areas[1]));
    await userEvent.click(panes[0]); // el foco lógico pasa al panel de sw1
    send("show version", "X", true, 2);
    await waitFor(() => expect(sent(core)).toHaveLength(2));
    expect(sent(core)[1]).toEqual(["t1", CLEAR + "show version"]);
    await waitFor(() => expect(document.activeElement).toBe(areas[0]));
  });
});

describe("«Scripts ▾»: menú por colección", () => {
  const col = (id: string, name: string, order: number, scriptIds: string[]) => ({ id, name, description: "", order, scriptIds, createdMs: 0, updatedMs: 0 });
  const menuSetup = (over = {}) => setup({
    listPinnedScripts: vi.fn(async () => []),
    listScripts: vi.fn(async () => [OSPF, MULTI, CFG, CFG1]),
    // «Redes» va antes que «Favoritos» en el orden del núcleo: el menú pone favoritos primero.
    listCollections: vi.fn(async () => [col("r", "Redes", 0, [MULTI.id, OSPF.id]), col("favoritos", "Favoritos", 1, [CFG.id, "lib-borrado"])]),
    ...over,
  });
  const abrirMenu = async () => { await abrir(); await term(); await userEvent.click(await screen.findByRole("button", { name: "Scripts ▾" })); return screen.findByRole("menu", { name: "Scripts por colección" }); };

  test("agrupa por colección con favoritos primero, respeta el orden de cada una y omite lo que ya no existe", async () => {
    menuSetup();
    const menu = await abrirMenu();
    await waitFor(() => expect(within(menu).getAllByRole("group").map((g) => g.getAttribute("aria-label"))).toEqual(["Favoritos", "Redes"]));
    const names = (g: string) => within(within(menu).getByRole("group", { name: g })).getAllByRole("menuitem").map((b) => b.textContent);
    expect(names("Favoritos")).toEqual(["Config NTP (se copia)"]);
    expect(names("Redes")).toEqual(["Vecinos", "Mi OSPF"]);
  });

  test("escribir filtra (también en comandos) y oculta los grupos vacíos; sin coincidencias avisa", async () => {
    menuSetup();
    const menu = await abrirMenu();
    await within(menu).findByRole("menuitem", { name: "Mi OSPF" });
    const q = screen.getByRole("searchbox", { name: "Filtrar scripts" });
    expect(q).toHaveFocus();
    await userEvent.keyboard("ospf neighbor");
    await waitFor(() => expect(within(menu).getAllByRole("menuitem").map((b) => b.textContent)).toEqual(["Mi OSPF"]));
    expect(within(menu).getAllByRole("group")).toHaveLength(1);
    await userEvent.clear(q);
    await userEvent.type(q, "zzz");
    expect(await within(menu).findByText("Ningún script coincide.")).toBeInTheDocument();
  });

  test("las flechas recorren, Enter elige una línea sin Enter final y Escape devuelve el foco al botón", async () => {
    const { core } = menuSetup();
    const menu = await abrirMenu();
    await within(menu).findByRole("menuitem", { name: "Mi OSPF" });
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu", { name: "Scripts por colección" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Scripts ▾" })).toHaveFocus();
    await userEvent.keyboard("{Enter}"); // reabre con el teclado
    const m2 = await screen.findByRole("menu", { name: "Scripts por colección" });
    await within(m2).findByRole("menuitem", { name: "Mi OSPF" });
    await userEvent.keyboard("ospf{ArrowDown}");
    expect(within(m2).getByRole("menuitem", { name: "Mi OSPF" })).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    await waitFor(() => expect(sent(core)).toEqual([["t1", CLEAR + "show ip ospf neighbor"]]));
    expect(screen.queryByRole("menu", { name: "Scripts por colección" })).not.toBeInTheDocument();
  });

  test("Enter en el buscador elige el primer resultado", async () => {
    const { core } = menuSetup();
    const menu = await abrirMenu();
    await within(menu).findByRole("menuitem", { name: "Mi OSPF" });
    await userEvent.keyboard("ospf{Enter}");
    await waitFor(() => expect(sent(core)).toEqual([["t1", CLEAR + "show ip ospf neighbor"]]));
  });

  test("varias líneas de solo lectura piden confirmación con el nombre; configuración de varias líneas se copia y avisa sin enviar", async () => {
    const { core } = menuSetup({ listCollections: vi.fn(async () => [col("r", "Redes", 0, [MULTI.id, CFG.id])]) });
    const menu = await abrirMenu();
    await userEvent.click(await within(menu).findByRole("menuitem", { name: "Vecinos" }));
    await waitFor(() => expect(core.confirmPaste).toHaveBeenCalledWith("show cdp neighbors\n! comentario\nshow lldp neighbors", "sw1", "Vecinos"));
    await waitFor(() => expect(sent(core)).toHaveLength(1));
    await userEvent.click(screen.getByRole("button", { name: "Scripts ▾" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Config NTP (se copia)" }));
    await waitFor(() => expect(core.copyText).toHaveBeenCalledWith("configure terminal\nntp server 192.0.2.10\nend"));
    expect(await screen.findByText(NO_CFG)).toBeInTheDocument();
    expect(core.confirmPaste).toHaveBeenCalledTimes(1);
    expect(sent(core)).toHaveLength(1);
  });

  test("sin colecciones con scripts el menú lo dice", async () => {
    menuSetup({ listCollections: vi.fn(async () => []) });
    const menu = await abrirMenu();
    expect(await within(menu).findByText(/Aún no hay colecciones con scripts/)).toBeInTheDocument();
  });
});

describe("«Scripts ▾»: foco de vuelta", () => {
  const col = (id: string, name: string, order: number, scriptIds: string[]) => ({ id, name, description: "", order, scriptIds, createdMs: 0, updatedMs: 0 });

  test("si el resultado es solo copiar, o se cancela la confirmación, el foco vuelve al botón «Scripts ▾»", async () => {
    const { core } = setup({
      listPinnedScripts: vi.fn(async () => []),
      listScripts: vi.fn(async () => [MULTI, CFG]),
      listCollections: vi.fn(async () => [col("r", "Redes", 0, [MULTI.id, CFG.id])]),
      confirmPaste: vi.fn(async () => false),
    });
    await abrir(); await term();
    await userEvent.click(await screen.findByRole("button", { name: "Scripts ▾" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Config NTP (se copia)" }));
    await waitFor(() => expect(core.copyText).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByRole("button", { name: "Scripts ▾" })).toHaveFocus());
    await userEvent.click(screen.getByRole("button", { name: "Scripts ▾" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Vecinos" }));
    await waitFor(() => expect(core.confirmPaste).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByRole("button", { name: "Scripts ▾" })).toHaveFocus());
    expect(sent(core)).toEqual([]);
  });
});
