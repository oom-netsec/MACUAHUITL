import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../../lib/i18n";
import { PALETTES } from "../../lib/termHighlight";
import { ThemeMenu } from "./ThemeMenu";

afterEach(() => localStorage.clear());

test("con el idioma en inglés el menú muestra los nombres de las paletas en inglés, y cada paleta tiene el suyo", async () => {
  localStorage.setItem("macuahuitl.lang", "en");
  render(<I18nProvider><ThemeMenu /></I18nProvider>);
  await userEvent.click(screen.getByRole("button", { name: "Change theme" }));
  const names = within(screen.getByRole("menu")).getAllByRole("menuitemradio").map((i) => i.querySelector(".theme-name")!.textContent);
  expect(names).toHaveLength(PALETTES.length);
  expect(names).toContain("Midnight");
  expect(names).toContain("Console dark");
  expect(names).not.toContain("Medianoche");
  names.forEach((n, i) => expect(n, PALETTES[i].id).not.toMatch(/^term\.palette\./)); // una clave que falta se vería como la clave
});

test("Tab cierra el menú y deja el foco en el botón para que siga al siguiente control", async () => {
  localStorage.setItem("macuahuitl.lang", "es");
  render(<I18nProvider><ThemeMenu /><button>siguiente</button></I18nProvider>);
  await userEvent.click(screen.getByRole("button", { name: "Cambiar tema" }));
  await userEvent.tab();
  expect(screen.queryByRole("menu")).toBeNull();
  expect(screen.getByRole("button", { name: "siguiente" })).toHaveFocus();
});
