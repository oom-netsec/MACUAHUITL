import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CoreContext, NavContext } from "../app/activity";
import { fakeCore } from "../lib/fake";
import type { CoreAPI } from "../lib/core";
import { DeviceMenu } from "./DeviceMenu";
import { ErrorState } from "./Page";

function setup() {
  const go = vi.fn();
  const core = fakeCore();
  render(<CoreContext.Provider value={core as unknown as CoreAPI}><NavContext.Provider value={{ go, inbox: {} }}>
    <DeviceMenu name="SW1-ACC-03" address="10.20.3.11"><span>SW1-ACC-03</span></DeviceMenu>
  </NavContext.Provider></CoreContext.Provider>);
  return { go, core };
}

test("el botón ⋯ abre las acciones del equipo y lleva al módulo con la dirección", async () => {
  const { go } = setup();
  await userEvent.click(screen.getByRole("button", { name: "Acciones de SW1-ACC-03" }));
  const menu = screen.getByRole("menu", { name: "Acciones de SW1-ACC-03" });
  expect(menu).toBeInTheDocument();
  expect(screen.getAllByRole("menuitem").map((m) => m.textContent)).toEqual(["Abrir SSH", "Consola serie", "Ping", "Traceroute", "Respaldar", "Abrir en Flota", "Copiar IP"]);
  expect(screen.getAllByRole("menuitem")[0]).toHaveFocus();
  await userEvent.keyboard("{ArrowDown}{ArrowDown}{Enter}");
  expect(go).toHaveBeenCalledWith("ping", "10.20.3.11");
  expect(screen.queryByRole("menu")).not.toBeInTheDocument();
});

test("clic derecho sobre el equipo abre el mismo menú; copiar IP usa el portapapeles", async () => {
  const { core } = setup();
  fireEvent.contextMenu(screen.getByText("SW1-ACC-03"));
  await userEvent.click(screen.getByRole("menuitem", { name: "Copiar IP" }));
  expect(core.copyText).toHaveBeenCalledWith("10.20.3.11");
});

test("Escape cierra el menú y devuelve el foco", async () => {
  setup();
  const b = screen.getByRole("button", { name: "Acciones de SW1-ACC-03" });
  await userEvent.click(b);
  await userEvent.keyboard("{Escape}");
  expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  expect(b).toHaveFocus();
});

test("ErrorState dice qué pasó y ofrece la acción siguiente", () => {
  render(<ErrorState title="No se pudo cargar la flota" action={<button>Reintentar</button>}>El núcleo no respondió a tiempo.</ErrorState>);
  expect(screen.getByRole("alert")).toHaveTextContent("No se pudo cargar la flota");
  expect(screen.getByRole("button", { name: "Reintentar" })).toBeInTheDocument();
});
