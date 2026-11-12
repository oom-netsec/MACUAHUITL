import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ThemeSwitch } from "./ThemeSwitch";
import { resetTheme } from "../lib/theme";

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
  resetTheme();
});

test("por defecto sigue al sistema y no fija tema", () => {
  render(<ThemeSwitch />);
  expect(screen.getByRole("radio", { name: "Sistema" })).toBeChecked();
  expect(document.documentElement.dataset.theme).toBeUndefined();
});

test("elegir oscuro lo aplica y lo recuerda; volver a sistema lo quita", async () => {
  const { unmount } = render(<ThemeSwitch />);
  await userEvent.click(screen.getByRole("radio", { name: "Oscuro" }));
  expect(document.documentElement.dataset.theme).toBe("dark");
  unmount();

  render(<ThemeSwitch />);
  expect(screen.getByRole("radio", { name: "Oscuro" })).toBeChecked();
  await userEvent.click(screen.getByRole("radio", { name: "Sistema" }));
  expect(document.documentElement.dataset.theme).toBeUndefined();
});

test("un valor guardado inválido cae a sistema", () => {
  localStorage.setItem("macuahuitl.tema", "neon");
  render(<ThemeSwitch />);
  expect(screen.getByRole("radio", { name: "Sistema" })).toBeChecked();
});
