import { render, screen } from "@testing-library/react";
import { RunButton } from "./RunButton";

test("sin datos faltantes el botón está habilitado y no hay descripción", () => {
  render(<RunButton missing={[false, undefined, ""]} onClick={() => {}} primary kbd>Ejecutar</RunButton>);
  const b = screen.getByRole("button", { name: /Ejecutar/ });
  expect(b).toBeEnabled();
  expect(b).toHaveClass("primary");
  expect(b).not.toHaveAccessibleDescription();
});

test("con datos faltantes se deshabilita y los nombra; los valores falsos se descartan", () => {
  render(<RunButton missing={["elegir una credencial", false, "indicar los equipos"]} onClick={() => {}}>Ejecutar</RunButton>);
  const b = screen.getByRole("button", { name: "Ejecutar" });
  expect(b).toBeDisabled();
  expect(b).toHaveAccessibleDescription("Falta: elegir una credencial, indicar los equipos.");
});

test("ocupado deshabilita sin explicar y un disabled extra no inventa faltantes", () => {
  const { rerender } = render(<RunButton missing={["x"]} busy onClick={() => {}}>Go</RunButton>);
  expect(screen.getByRole("button")).toBeDisabled();
  expect(screen.getByRole("button")).toHaveAttribute("aria-busy", "true");
  expect(screen.getByRole("button")).not.toHaveAccessibleDescription();
  rerender(<RunButton missing={[]} disabled onClick={() => {}}>Go</RunButton>);
  expect(screen.getByRole("button")).toBeDisabled();
  expect(screen.getByRole("button")).not.toHaveAccessibleDescription();
});
