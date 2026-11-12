import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Dialog, DetailsButton } from "./Dialog";
import { I18nProvider } from "../lib/i18n";

const setup = () => render(
  <I18nProvider>
    <button type="button">Antes</button>
    <DetailsButton label="Ver detalles" title="Detalles · Prueba"><p>Contenido largo</p></DetailsButton>
  </I18nProvider>,
);
beforeEach(() => localStorage.clear());

test("abre un diálogo modal con título, mueve el foco y deja la página inert", async () => {
  const { container } = setup();
  expect(screen.queryByRole("dialog")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: /^Ver detalles/ }));
  const d = screen.getByRole("dialog", { name: "Detalles · Prueba" });
  expect(d).toHaveAttribute("aria-modal", "true");
  expect(screen.getByText("Contenido largo")).toBeVisible();
  expect(screen.getByRole("button", { name: "Cerrar" })).toHaveFocus();
  expect(container).toHaveProperty("inert", true);
});

test("Escape cierra, devuelve el foco al botón y quita lo inert", async () => {
  const { container } = setup();
  const open = screen.getByRole("button", { name: /^Ver detalles/ });
  await userEvent.click(open);
  await userEvent.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(open).toHaveFocus();
  expect(container).toHaveProperty("inert", false);
});

test("el botón Cerrar cierra y devuelve el foco", async () => {
  setup();
  const open = screen.getByRole("button", { name: /^Ver detalles/ });
  await userEvent.click(open);
  await userEvent.click(screen.getByRole("button", { name: "Cerrar" }));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(open).toHaveFocus();
});

test("Escape cierra aunque el foco haya quedado fuera del diálogo (clic en el texto o Tab)", async () => {
  const onClose = vi.fn();
  render(<I18nProvider><Dialog title="Detalles" onClose={onClose}><p>texto</p></Dialog></I18nProvider>);
  (document.activeElement as HTMLElement).blur(); // el foco cae en <body>
  await userEvent.keyboard("{Escape}");
  expect(onClose).toHaveBeenCalledTimes(1);
});
