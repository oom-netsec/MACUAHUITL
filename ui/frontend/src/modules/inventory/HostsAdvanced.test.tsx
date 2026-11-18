import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HostsView } from "./HostsView";
import { fakeInventory } from "./fake";
import { fakeCore } from "../../lib/fake";
import { I18nProvider } from "../../lib/i18n";

const setup = () => {
  const inv = fakeInventory();
  render(<I18nProvider><HostsView core={fakeCore({ ...inv })} /></I18nProvider>);
  return inv;
};
const open = async () => {
  await screen.findByRole("table", { name: "Hosts de la libreta" });
  await userEvent.click(screen.getByRole("button", { name: /Nuevo host/ }));
  return screen.getByLabelText("Puerto").closest("details")!;
};
const fill = async () => {
  await userEvent.type(screen.getByLabelText("Nombre"), "NUEVO");
  await userEvent.type(screen.getByLabelText("Dirección (IP o nombre DNS)"), "10.0.0.9");
};

test("host: puerto, etiquetas y notas van plegados; lo esencial queda fuera; se siguen guardando y contando", async () => {
  const inv = setup();
  const d = await open();
  expect(d.open).toBe(false);
  expect(d).toContainElement(screen.getByLabelText("Etiquetas"));
  expect(d).toContainElement(screen.getByLabelText("Notas"));
  for (const l of ["Nombre", "Dirección (IP o nombre DNS)", "Plataforma", "Credencial"]) expect(d).not.toContainElement(screen.getByLabelText(l));
  expect(d).not.toContainElement(screen.getAllByLabelText("Carpeta")[0]!);
  expect(d).not.toContainElement(screen.getByRole("button", { name: "Guardar host" }));
  await fill();
  await userEvent.clear(screen.getByLabelText("Puerto"));
  await userEvent.type(screen.getByLabelText("Puerto"), "2200");
  await userEvent.type(screen.getByLabelText("Etiquetas"), "core");
  await userEvent.type(screen.getByLabelText("Notas"), "rack 4");
  expect(d.querySelector("summary")).toHaveTextContent("cambiadas: 3");
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(inv.saveHost).toHaveBeenCalledWith(expect.objectContaining({ port: 2200, tags: ["core"], notes: "rack 4" }));
});

test("host: «Orden de inicio» de Linux queda a la vista", async () => {
  setup();
  const d = await open();
  await userEvent.selectOptions(screen.getByLabelText("Plataforma"), "linux");
  expect(d).not.toContainElement(screen.getByLabelText("Orden de inicio"));
});

test("host: un puerto inválido abre Avanzado en cada intento fallido, aunque se haya cerrado", async () => {
  const inv = setup();
  const d = await open();
  await fill();
  await userEvent.clear(screen.getByLabelText("Puerto"));
  await userEvent.type(screen.getByLabelText("Puerto"), "99999");
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(inv.saveHost).not.toHaveBeenCalled();
  expect(d.open).toBe(true);
  await userEvent.click(d.querySelector("summary")!);
  expect(d.open).toBe(false);
  await userEvent.click(screen.getByRole("button", { name: "Guardar host" }));
  expect(d.open).toBe(true);
});
