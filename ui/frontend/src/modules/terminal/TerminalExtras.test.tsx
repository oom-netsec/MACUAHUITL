import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CoreContext, ModuleIdContext, NavContext, type Delivery } from "../../app/activity";
import type { CoreAPI } from "../../lib/core";
import { fakeCore } from "../../lib/fake";
import { ConsoleView } from "../console/ConsoleView";
import { TerminalView } from "./TerminalView";
import { FakeSearch, FakeTerm } from "./xtermMock";

vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xtermMock")).FakeTerm }));
vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xtermMock")).FakeFit }));
vi.mock("@xterm/addon-search", async () => ({ SearchAddon: (await import("./xtermMock")).FakeSearch }));
vi.mock("@xterm/addon-webgl", async () => ({ WebglAddon: (await import("./xtermMock")).FakeWebgl }));

const cred = { id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false };
beforeEach(() => {
  FakeTerm.all.length = 0; FakeSearch.all.length = 0;
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
});
afterEach(() => vi.unstubAllGlobals());

async function session(inbox: Record<string, Delivery> = {}) {
  const core = fakeCore({ listCredentials: vi.fn(async () => [cred]) });
  const ui = (inb: Record<string, Delivery>) => (
    <CoreContext.Provider value={core as unknown as CoreAPI}>
      <NavContext.Provider value={{ go: () => {}, inbox: inb }}>
        <ModuleIdContext.Provider value="terminal"><TerminalView core={core} /></ModuleIdContext.Provider>
      </NavContext.Provider>
    </CoreContext.Provider>
  );
  const view = render(ui(inbox));
  return { core, view, ui };
}
const abrir = async (host: string) => {
  await userEvent.clear(screen.getByLabelText(/Equipo/));
  await userEvent.type(screen.getByLabelText(/Equipo/), host);
  await userEvent.click(await screen.findByRole("button", { name: "Abrir pestaña" }));
};

test("el menú de equipo rellena el equipo de SSH, y una nueva entrega lo cambia", async () => {
  const { view, ui } = await session({ terminal: { data: "10.1.1.1", n: 1 } });
  expect(await screen.findByLabelText(/Equipo/)).toHaveValue("10.1.1.1");
  view.rerender(ui({ terminal: { data: "10.2.2.2", n: 2 } }));
  expect(screen.getByLabelText(/Equipo/)).toHaveValue("10.2.2.2");
});

test("una entrega para otro módulo no se toma", async () => {
  await session({ ping: { data: "10.1.1.1", n: 1 } });
  expect(await screen.findByLabelText(/Equipo/)).toHaveValue("");
});

test("los comandos rápidos mandan el comando con retorno de carro", async () => {
  const { core } = await session();
  await abrir("sw1");
  const group = await screen.findByRole("group", { name: "Comandos rápidos" });
  expect(within(group).getAllByRole("button").map((b) => b.textContent)).toEqual(["show running-config", "show version", "show ip interface brief", "show interfaces status", "Scripts ▾"]);
  await userEvent.click(within(group).getByRole("button", { name: "show ip interface brief" }));
  expect(core.terminalSend).toHaveBeenCalledWith("t1", "show ip interface brief\r");
});

test("buscar usa el addon de xterm: escribir busca, Enter y Mayús+Enter saltan y el conteo es el del addon", async () => {
  await session();
  await abrir("sw1");
  await waitFor(() => expect(FakeSearch.all).toHaveLength(1));
  const s = FakeSearch.all[0];
  const box = await screen.findByRole("searchbox", { name: "Buscar en la sesión" });
  await userEvent.type(box, "interface");
  await waitFor(() => expect(s.findNext).toHaveBeenLastCalledWith("interface", expect.anything()));
  act(() => s.report(0, 2));
  expect(screen.getByRole("status", { name: "Resultado de la búsqueda" })).toHaveTextContent("1 de 2");
  const nexts = s.findNext.mock.calls.length;
  await userEvent.keyboard("{Enter}");
  await waitFor(() => expect(s.findNext.mock.calls.length).toBe(nexts + 1));
  await userEvent.keyboard("{Shift>}{Enter}{/Shift}");
  await waitFor(() => expect(s.findPrevious).toHaveBeenLastCalledWith("interface", expect.anything()));
  act(() => s.report(-1, 0));
  expect(screen.getByRole("status", { name: "Resultado de la búsqueda" })).toHaveTextContent("Sin coincidencias");
  await userEvent.clear(box);
  await waitFor(() => expect(s.clearDecorations).toHaveBeenCalled());
});

test("Descargar sesión guarda el texto de la pestaña como equipo-fecha.txt", async () => {
  const { core } = await session();
  await abrir("192.0.2.1:2222");
  act(() => core.emitTerminal({ runId: "t1", data: "SW1#show version\nCisco IOS XE\n" }));
  await userEvent.click(screen.getByRole("button", { name: "Descargar sesión" }));
  const today = new Date().toISOString().slice(0, 10);
  expect(core.saveFile).toHaveBeenCalledWith(`192.0.2.1_2222-${today}.txt`, "SW1#show version\nCisco IOS XE\n", "utf8");
});

test("Consola serie: una dirección del menú de equipo se avisa y una ruta de puerto se toma", async () => {
  const core = fakeCore();
  const ui = (inbox: Record<string, Delivery>) => (
    <NavContext.Provider value={{ go: () => {}, inbox }}>
      <ModuleIdContext.Provider value="console"><ConsoleView core={core} /></ModuleIdContext.Provider>
    </NavContext.Provider>
  );
  const { rerender } = render(ui({ console: { data: "10.9.9.9", n: 1 } }));
  expect(await screen.findByText(/10\.9\.9\.9/)).toBeInTheDocument();
  rerender(ui({ console: { data: "/dev/ttyUSB1", n: 2 } }));
  expect(screen.getByLabelText("Puerto")).toHaveValue("/dev/ttyUSB1");
});
