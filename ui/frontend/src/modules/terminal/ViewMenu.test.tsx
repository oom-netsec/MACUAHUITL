import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../../lib/i18n";
import { PALETTES } from "../../lib/termHighlight";
import { ViewMenu } from "./ViewMenu";

afterEach(() => localStorage.clear());

test("con el idioma en inglés el menú muestra los nombres de las paletas en inglés, y cada paleta tiene el suyo", async () => {
  localStorage.setItem("macuahuitl.lang", "en");
  render(<I18nProvider><ViewMenu /></I18nProvider>);
  await userEvent.click(screen.getByRole("button", { name: "View" }));
  const names = within(screen.getByRole("group", { name: "Theme" })).getAllByRole("menuitemradio").map((i) => i.querySelector(".theme-name")!.textContent);
  expect(names).toHaveLength(PALETTES.length);
  expect(names).toContain("Midnight");
  expect(names).toContain("Dark console");
  expect(names).not.toContain("Medianoche");
  names.forEach((n, i) => expect(n, PALETTES[i].id).not.toMatch(/^term\.palette\./)); // una clave que falta se vería como la clave
});

test("Tab cierra el menú y deja el foco en el botón para que siga al siguiente control", async () => {
  localStorage.setItem("macuahuitl.lang", "es");
  render(<I18nProvider><ViewMenu /><button>siguiente</button></I18nProvider>);
  await userEvent.click(screen.getByRole("button", { name: "Vista" }));
  await userEvent.tab();
  expect(screen.queryByRole("menu")).toBeNull();
  expect(screen.getByRole("button", { name: "siguiente" })).toHaveFocus();
});

test("con split el menú ofrece «Dividir» como casilla y la acción recibe el valor nuevo", async () => {
  localStorage.setItem("macuahuitl.lang", "es");
  const onChange = vi.fn();
  render(<I18nProvider><ViewMenu split={{ checked: false, onChange }} /></I18nProvider>);
  await userEvent.click(screen.getByRole("button", { name: "Vista" }));
  await userEvent.click(screen.getByRole("menuitemcheckbox", { name: "Dividir" }));
  expect(onChange).toHaveBeenCalledWith(true);
});

test("sin split no hay «Dividir»; Escape cierra y devuelve el foco al botón", async () => {
  localStorage.setItem("macuahuitl.lang", "es");
  render(<I18nProvider><ViewMenu /></I18nProvider>);
  const btn = screen.getByRole("button", { name: "Vista" });
  await userEvent.click(btn);
  expect(screen.queryByRole("menuitemcheckbox", { name: "Dividir" })).toBeNull();
  await userEvent.keyboard("{Escape}");
  expect(screen.queryByRole("menu")).toBeNull();
  expect(btn).toHaveFocus();
});
