import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TerminalView } from "./TerminalView";
import { fakeCore } from "../../lib/fake";
import { setTermPrefs, resetTermPrefs } from "../../lib/termPrefs";
import { PALETTES } from "../../lib/termHighlight";
import { paletteName } from "../../components/Terminal";
import { tr } from "../../lib/i18n";
import { FakeSearch, FakeTerm } from "./xtermMock";

vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xtermMock")).FakeTerm }));
vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xtermMock")).FakeFit }));
vi.mock("@xterm/addon-search", async () => ({ SearchAddon: (await import("./xtermMock")).FakeSearch }));
vi.mock("@xterm/addon-webgl", async () => ({ WebglAddon: (await import("./xtermMock")).FakeWebgl }));

const cred = { id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false };
beforeEach(() => {
  FakeTerm.all.length = 0; FakeSearch.all.length = 0;
  localStorage.clear(); resetTermPrefs(); setTermPrefs({ palette: "classic", hl: true });
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(800);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(400);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });

const setup = (over = {}) => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]), ...over });
  const view = render(<TerminalView core={core} />);
  return { core, ...view };
};
const abrir = async (host: string) => {
  await userEvent.clear(screen.getByLabelText(/Equipo/));
  await userEvent.type(screen.getByLabelText(/Equipo/), host);
  await userEvent.click(await screen.findByRole("button", { name: "Abrir pestaña" }));
};
const term = async (n = 0) => { await waitFor(() => expect(FakeTerm.all.length).toBeGreaterThan(n)); return FakeTerm.all[n]; };
const plain = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
const ok = "\x1b[32m"; // «ok» es la ranura verde del tema, no un RGB

describe("resaltado", () => {
  test("las líneas completas llegan coloreadas al emulador", async () => {
    const { core } = setup();
    await abrir("sw1");
    const x = await term();
    act(() => { core.emitTerminal({ runId: "t1", data: "Vlan10 is up\r\n" }); });
    expect(x.write).toHaveBeenCalledTimes(1);
    expect(x.write.mock.calls[0][0]).toContain(`${ok}up\x1b[39m`);
    expect(plain(x.write.mock.calls[0][0])).toBe("Vlan10 is up\r\n");
  });

  test("lo tecleado (sin salto de línea) se escribe al instante y sin cambios", async () => {
    const { core } = setup();
    await abrir("sw1");
    const x = await term();
    act(() => { core.emitTerminal({ runId: "t1", data: "up" }); });
    expect(x.write).toHaveBeenCalledWith("up");
  });

  test("apagar «Resaltar palabras clave» deja la salida sin colores y se guarda con las preferencias", async () => {
    const { core } = setup();
    await abrir("sw1");
    const x = await term();
    const box = screen.getByRole("checkbox", { name: "Resaltar palabras clave" });
    expect(box).toBeChecked();
    await userEvent.click(box);
    expect(JSON.parse(localStorage.getItem("macuahuitl.terminal")!)).toMatchObject({ hl: false });
    act(() => { core.emitTerminal({ runId: "t1", data: "Vlan10 is up\r\n" }); });
    expect(x.write).toHaveBeenCalledWith("Vlan10 is up\r\n");
  });
});

describe("registro en archivo", () => {
  const registro = async (core: ReturnType<typeof fakeCore>) => {
    await userEvent.type(screen.getByLabelText(/Equipo/), "sw1");
    await userEvent.click(screen.getByRole("button", { name: "Elegir archivo…" }));
    await waitFor(() => expect(core.pickSavePath).toHaveBeenCalled());
    expect(await screen.findByDisplayValue(/\/home\/u\/Descargas\/sw1-.*\.log/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Abrir pestaña" }));
  };
  const ruta = async (core: ReturnType<typeof fakeCore>) => (core.pickSavePath as ReturnType<typeof vi.fn>).mock.results[0].value as Promise<string>;

  test("el archivo elegido es solo de esa sesión: la siguiente pestaña no lo hereda", async () => {
    const { core } = setup();
    await registro(core);
    await term();
    expect(screen.getByLabelText(/Guardar la sesión en/)).toHaveValue("");
    await abrir("sw2");
    await term(1);
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(2));
    expect(screen.queryByText(/Guardando la sesión en/)).not.toBeInTheDocument(); // sw2, activa, sin archivo
    await userEvent.click(screen.getByRole("tab", { name: /sw1/ }));
    expect(await screen.findByText(/Guardando la sesión en/)).toBeInTheDocument();
  });

  test("una ruta que ya usa otra sesión abierta se rechaza", async () => {
    const path = "/home/u/Descargas/compartido.log";
    const { core } = setup({ pickSavePath: vi.fn(async () => path) });
    await userEvent.type(screen.getByLabelText(/Equipo/), "sw1");
    await userEvent.click(screen.getByRole("button", { name: "Elegir archivo…" }));
    expect(await screen.findByDisplayValue(path)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Abrir pestaña" }));
    await term();
    await userEvent.clear(screen.getByLabelText(/Equipo/));
    await userEvent.type(screen.getByLabelText(/Equipo/), "sw2");
    await userEvent.click(screen.getByRole("button", { name: "Elegir archivo…" }));
    await userEvent.click(screen.getByRole("button", { name: "Abrir pestaña" }));
    expect(await screen.findByText("Ese archivo ya lo usa otra sesión abierta: elige otro.")).toBeInTheDocument();
    expect(core.terminalOpen).toHaveBeenCalledTimes(1);
  });

  test("sugiere <equipo>-<fecha>-<hora>.log y muestra dónde guarda", async () => {
    const { core } = setup();
    await registro(core);
    expect((core.pickSavePath as ReturnType<typeof vi.fn>).mock.calls[0][0]).toMatch(/^sw1-\d{8}-\d{6}\.log$/);
    expect(await screen.findByText(/Guardando la sesión en \/home\/u\/Descargas\/sw1-/)).toBeInTheDocument();
    expect(screen.getByText(/aún sin guardar/)).toBeInTheDocument();
  });

  test("cada 30 s escribe el texto limpio (sin códigos de color) con overwrite y muestra la hora", async () => {
    const si = vi.spyOn(globalThis, "setInterval");
    const { core } = setup();
    await registro(core);
    await term();
    act(() => { core.emitTerminal({ runId: "t1", data: "Vlan10 is up\r\n" }); });
    expect(core.writeFile).not.toHaveBeenCalled();
    const tick = si.mock.calls.find((c) => c[1] === 30_000)![0] as () => void; // el temporizador de 30 s
    act(() => tick());
    await waitFor(() => expect(core.writeFile).toHaveBeenCalledWith(expect.stringMatching(/sw1-.*\.log$/), "Vlan10 is up\n", "utf8", true));
    expect(await screen.findByText(/último guardado a las/)).toBeInTheDocument();
    act(() => tick()); // sin salida nueva no se vuelve a escribir
    expect(core.writeFile).toHaveBeenCalledTimes(1);
  });

  test("al cerrar la sesión el equipo hace una escritura final", async () => {
    const { core } = setup();
    await registro(core);
    await term();
    act(() => { core.emitTerminal({ runId: "t1", data: "uno\r\n" }); core.emitTerminal({ runId: "t1", done: true }); });
    const path = await ruta(core);
    await waitFor(() => expect(core.writeFile).toHaveBeenCalledWith(path, "uno\n", "utf8", true));
    expect(await screen.findByText(/último guardado a las/)).toBeInTheDocument();
  });

  test("cerrar la pestaña guarda", async () => {
    const { core } = setup();
    await registro(core);
    await term();
    act(() => { core.emitTerminal({ runId: "t1", data: "tres\r\n" }); });
    await userEvent.click(screen.getByRole("button", { name: "Cerrar pestaña sw1" }));
    await waitFor(() => expect(core.writeFile).toHaveBeenCalledWith(expect.any(String), "tres\n", "utf8", true));
  });

  test("salir del módulo también guarda", async () => {
    const { core, unmount } = setup();
    await registro(core);
    await term();
    act(() => { core.emitTerminal({ runId: "t1", data: "dos\r\n" }); });
    unmount();
    await waitFor(() => expect(core.writeFile).toHaveBeenCalledWith(expect.any(String), "dos\n", "utf8", true));
  });

  test("lo tecleado no entra al registro (la contraseña no se repite)", async () => {
    const { core } = setup();
    await registro(core);
    const x = await term();
    x.type("secreto");
    act(() => { core.emitTerminal({ runId: "t1", data: "Password: \r\n" }); core.emitTerminal({ runId: "t1", done: true }); });
    await waitFor(() => expect(core.writeFile).toHaveBeenCalled());
    expect((core.writeFile as ReturnType<typeof vi.fn>).mock.calls.every((c) => !String(c[1]).includes("secreto"))).toBe(true);
  });

  test("si la escritura falla se ve el error", async () => {
    const writeFile = vi.fn().mockRejectedValue(new Error("disco lleno"));
    const { core } = setup({ writeFile });
    await registro(core);
    await term();
    act(() => { core.emitTerminal({ runId: "t1", data: "x\r\n" }); core.emitTerminal({ runId: "t1", done: true }); });
    expect(await screen.findByText(/No se pudo guardar la sesión en .*disco lleno/)).toBeInTheDocument();
  });

  test("sin archivo elegido no se escribe nada", async () => {
    const { core } = setup();
    await abrir("sw1");
    await term();
    act(() => { core.emitTerminal({ runId: "t1", data: "x\r\n" }); core.emitTerminal({ runId: "t1", done: true }); });
    expect(core.writeFile).not.toHaveBeenCalled();
    expect(screen.queryByText(/Guardando la sesión en/)).not.toBeInTheDocument();
  });
});

describe("pantalla dividida", () => {
  test("«Dividir» solo aparece con dos pestañas o más", async () => {
    setup();
    await abrir("sw1");
    expect(screen.queryByRole("checkbox", { name: "Dividir" })).not.toBeInTheDocument();
    await abrir("sw2");
    expect(await screen.findByRole("checkbox", { name: "Dividir" })).toBeInTheDocument(); // la segunda pestaña llega tras la llamada al núcleo
  });

  test("muestra la activa a la izquierda y la elegida a la derecha, cada una con su emulador (sin recrearlos)", async () => {
    const { core } = setup();
    await abrir("sw1"); await abrir("sw2"); await abrir("sw3");
    const [, b, c] = [await term(0), await term(1), await term(2)];
    await userEvent.click(screen.getByRole("tab", { name: "sw1" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Dividir" }));
    expect(FakeTerm.all).toHaveLength(3); // dividir no crea emuladores nuevos
    expect(screen.getByRole("group", { name: "Panel izquierdo: sw1" })).toBeVisible();
    expect(screen.getByRole("group", { name: "Panel derecho: sw2" })).toBeVisible();
    await userEvent.selectOptions(screen.getByLabelText("Segundo panel"), "sw3");
    expect(screen.getByRole("group", { name: "Panel derecho: sw3" })).toBeVisible();
    expect(screen.queryByRole("group", { name: "Panel derecho: sw2" })).not.toBeInTheDocument();
    // cada panel manda sus teclas a su sesión y recibe solo su salida
    act(() => { core.emitTerminal({ runId: "t3", data: "tres>" }); });
    expect(c.write).toHaveBeenCalledWith(expect.stringMatching(/tres>/));
    expect(b.write).not.toHaveBeenCalled();
    c.type("x");
    expect(core.terminalSend).toHaveBeenLastCalledWith("t3", "x");
  });

  test("cada panel avisa su tamaño al núcleo y los comandos rápidos siguen al panel con el foco", async () => {
    const { core } = setup();
    await abrir("sw1"); await abrir("sw2");
    await term(0); await term(1);
    await userEvent.click(screen.getByRole("tab", { name: "sw1" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Dividir" }));
    await waitFor(() => { expect(core.terminalResize).toHaveBeenCalledWith("t1", 24, 80); expect(core.terminalResize).toHaveBeenCalledWith("t2", 24, 80); });
    const rapido = screen.getByRole("button", { name: "show version" });
    await userEvent.click(rapido);
    expect(core.terminalSend).toHaveBeenLastCalledWith("t1", "show version\r");
    await userEvent.click(within(screen.getByRole("group", { name: "Panel derecho: sw2" }).parentElement!).getByRole("group")); // clic en el panel derecho
    await userEvent.click(rapido);
    expect(core.terminalSend).toHaveBeenLastCalledWith("t2", "show version\r");
  });

  test("al desactivar vuelve a un solo panel con los mismos emuladores", async () => {
    setup();
    await abrir("sw1"); await abrir("sw2");
    const a = await term(0); await term(1);
    await userEvent.click(screen.getByRole("checkbox", { name: "Dividir" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Dividir" }));
    expect(screen.queryByLabelText("Segundo panel")).not.toBeInTheDocument();
    expect(a.dispose).not.toHaveBeenCalled();
    expect(FakeTerm.all).toHaveLength(2);
  });
});

describe("búsqueda y comandos rápidos con varias pestañas", () => {
  test("el conteo lo da solo la pestaña visible; vaciar la búsqueda apaga ↑/↓", async () => {
    setup();
    await abrir("sw1"); await abrir("sw2");
    await waitFor(() => expect(FakeSearch.all).toHaveLength(2));
    const [oculta, visible] = FakeSearch.all;
    await userEvent.type(await screen.findByRole("searchbox", { name: "Buscar en la sesión" }), "ip");
    await waitFor(() => expect(visible.findNext).toHaveBeenCalled());
    expect(oculta.findNext).not.toHaveBeenCalled();
    act(() => visible.report(0, 3));
    act(() => oculta.report(4, 9)); // una pestaña oculta no pisa el conteo
    expect(screen.getByRole("status", { name: "Resultado de la búsqueda" })).toHaveTextContent("1 de 3");
    expect(screen.getByRole("button", { name: "Coincidencia siguiente" })).toBeEnabled();
    await userEvent.clear(screen.getByRole("searchbox", { name: "Buscar en la sesión" }));
    expect(screen.getByRole("button", { name: "Coincidencia siguiente" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Coincidencia anterior" })).toBeDisabled();
  });

  test("con dos paneles la búsqueda sigue al panel con el foco y cada sesión tiene su cola de envío", async () => {
    const { core } = setup();
    await abrir("sw1"); await abrir("sw2");
    const [a, b] = [await term(0), await term(1)];
    await userEvent.click(screen.getByRole("tab", { name: "sw1" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Dividir" }));
    await waitFor(() => expect(FakeSearch.all).toHaveLength(2));
    const der = screen.getByRole("group", { name: "Panel derecho: sw2" });
    await userEvent.click(der.closest(".ssh-pane") as HTMLElement); // el foco pasa al panel derecho
    await userEvent.type(screen.getByRole("searchbox", { name: "Buscar en la sesión" }), "x");
    await waitFor(() => expect(FakeSearch.all[1].findNext).toHaveBeenCalled());
    act(() => FakeSearch.all[0].report(0, 7)); // el panel izquierdo ya no es el de las herramientas
    act(() => FakeSearch.all[1].report(1, 2));
    expect(screen.getByRole("status", { name: "Resultado de la búsqueda" })).toHaveTextContent("2 de 2");
    // un envío en vuelo en una sesión no frena a la otra
    let libera: () => void = () => {};
    (core.terminalSend as ReturnType<typeof vi.fn>).mockImplementationOnce(() => new Promise<void>((r) => { libera = r; }));
    a.type("1");
    b.type("2");
    expect(core.terminalSend).toHaveBeenCalledWith("t1", "1");
    expect(core.terminalSend).toHaveBeenCalledWith("t2", "2");
    a.type("3"); a.type("4");
    expect(core.terminalSend).toHaveBeenCalledTimes(2);
    await act(async () => { libera(); });
    await waitFor(() => expect(core.terminalSend).toHaveBeenLastCalledWith("t1", "34"));
  });

  test("los comandos rápidos van antes de la terminal en el DOM (se alcanzan con Tab)", async () => {
    setup();
    await abrir("sw1");
    const quick = screen.getByRole("group", { name: "Comandos rápidos" });
    const terms = document.querySelector(".ssh-terms")!;
    expect(quick.compareDocumentPosition(terms) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});

describe("cambiar tema", () => {
  const abrirMenu = async () => {
    setup();
    await abrir("sw1");
    await term();
    const btn = screen.getByRole("button", { name: "Cambiar tema" });
    await userEvent.click(btn);
    return { btn, menu: screen.getByRole("menu", { name: "Cambiar tema" }) };
  };

  test("el botón abre un menú con todas las paletas y marca la actual", async () => {
    const { btn, menu } = await abrirMenu();
    expect(btn).toHaveAttribute("aria-haspopup", "menu");
    expect(btn).toHaveAttribute("aria-expanded", "true");
    const items = within(menu).getAllByRole("menuitemradio");
    expect(items).toHaveLength(PALETTES.length);
    PALETTES.forEach((p, i) => expect(items[i]).toHaveAccessibleName(paletteName(tr, p)));
    expect(items.filter((i) => i.getAttribute("aria-checked") === "true").map((i) => i.querySelector(".theme-name")?.textContent)).toEqual(["Clásica"]);
  });

  test("elegir una paleta la aplica al instante, cierra el menú y devuelve el foco al botón", async () => {
    const { btn, menu } = await abrirMenu();
    await userEvent.click(within(menu).getByRole("menuitemradio", { name: "Medianoche" }));
    expect(JSON.parse(localStorage.getItem("macuahuitl.terminal")!)).toMatchObject({ palette: "medianoche" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(btn).toHaveFocus();
    expect(btn).toHaveAttribute("aria-expanded", "false");
  });

  test("flechas, Inicio y Fin mueven el foco; Escape cierra y devuelve el foco al botón; clic fuera cierra", async () => {
    const { btn, menu } = await abrirMenu();
    const items = within(menu).getAllByRole("menuitemradio");
    expect(items[0]).toHaveFocus();
    await userEvent.keyboard("{ArrowDown}");
    expect(items[1]).toHaveFocus();
    await userEvent.keyboard("{End}");
    expect(items[items.length - 1]).toHaveFocus();
    await userEvent.keyboard("{ArrowDown}");
    expect(items[0]).toHaveFocus();
    await userEvent.keyboard("{ArrowUp}");
    expect(items[items.length - 1]).toHaveFocus();
    await userEvent.keyboard("{Home}");
    expect(items[0]).toHaveFocus();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).toBeNull();
    expect(btn).toHaveFocus();
    await userEvent.click(btn);
    await userEvent.click(document.body);
    expect(screen.queryByRole("menu")).toBeNull();
  });
});

describe("clic derecho: copia o pega", () => {
  const group = () => screen.getAllByRole("group").find((g) => g.classList.contains("ssh-xterm"))!;

  test("con selección la copia y la limpia", async () => {
    const { core } = setup();
    await abrir("sw1");
    const x = await term();
    x.getSelection.mockReturnValue("interface Gi1/0/1");
    const ev = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    act(() => { group().dispatchEvent(ev); });
    expect(ev.defaultPrevented).toBe(true);
    expect(core.copyText).toHaveBeenCalledWith("interface Gi1/0/1");
    expect(x.clearSelection).toHaveBeenCalledTimes(1);
    expect(x.paste).not.toHaveBeenCalled();
  });

  test("sin selección pega el portapapeles", async () => {
    const { core } = setup({ pasteText: vi.fn(async () => "texto pegado") });
    await abrir("sw1");
    const x = await term();
    const ev = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    act(() => { group().dispatchEvent(ev); });
    expect(ev.defaultPrevented).toBe(true);
    await waitFor(() => expect(x.paste).toHaveBeenCalledWith("texto pegado"));
    expect(core.copyText).not.toHaveBeenCalled();
    expect(x.clearSelection).not.toHaveBeenCalled();
  });

  test("con una app remota controlando el mouse (tmux, vim) el clic derecho es suyo; con Mayús sigue copiando y pegando", async () => {
    const { core } = setup({ pasteText: vi.fn(async () => "texto pegado") });
    await abrir("sw1");
    const x = await term();
    x.modes.mouseTrackingMode = "any";
    const ev = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    act(() => { group().dispatchEvent(ev); });
    expect(ev.defaultPrevented).toBe(false);
    expect(core.pasteText).not.toHaveBeenCalled();
    const sh = new MouseEvent("contextmenu", { bubbles: true, cancelable: true, shiftKey: true });
    act(() => { group().dispatchEvent(sh); });
    expect(sh.defaultPrevented).toBe(true);
    await waitFor(() => expect(x.paste).toHaveBeenCalledWith("texto pegado"));
  });
});

describe("pegado de varias líneas", () => {
  const group = () => screen.getAllByRole("group").find((g) => g.classList.contains("ssh-xterm"))!;
  const menu = () => act(() => { group().dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true })); });
  const ctrlV = (x: FakeTerm) => x.keyHandler(new KeyboardEvent("keydown", { key: "V", ctrlKey: true, shiftKey: true, cancelable: true }));

  test("pide confirmación con el equipo y el texto; si se cancela no pega nada (clic derecho y Ctrl+Mayús+V)", async () => {
    const { core } = setup({ pasteText: vi.fn(async () => "conf t\nshutdown\nend\n"), confirmPaste: vi.fn(async () => false) });
    await abrir("sw1");
    const x = await term();
    menu();
    await waitFor(() => expect(core.confirmPaste).toHaveBeenCalledWith("conf t\nshutdown\nend\n", "sw1"));
    ctrlV(x);
    await waitFor(() => expect(core.confirmPaste).toHaveBeenCalledTimes(2));
    expect(x.paste).not.toHaveBeenCalled();
  });

  test("si se acepta, se pega completo", async () => {
    setup({ pasteText: vi.fn(async () => "a\nb"), confirmPaste: vi.fn(async () => true) });
    await abrir("sw1");
    const x = await term();
    ctrlV(x);
    await waitFor(() => expect(x.paste).toHaveBeenCalledWith("a\nb"));
  });

  test("una sola línea se pega directo, sin preguntar", async () => {
    const { core } = setup({ pasteText: vi.fn(async () => "show version") });
    await abrir("sw1");
    const x = await term();
    menu();
    await waitFor(() => expect(x.paste).toHaveBeenCalledWith("show version"));
    expect(core.confirmPaste).not.toHaveBeenCalled();
  });
});
