import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Advanced } from "./Advanced";

const details = () => screen.getByText("x").closest("details")!;

test("cerrado por omisión; el summary lo abre y lo cierra", async () => {
  render(<Advanced><p>x</p></Advanced>);
  expect(details().open).toBe(false);
  await userEvent.click(screen.getByText("Opciones avanzadas"));
  expect(details().open).toBe(true);
  await userEvent.click(screen.getByText("Opciones avanzadas"));
  expect(details().open).toBe(false);
});

test("forceOpen lo abre y lo deja abierto; el label reemplaza el título", () => {
  const { rerender } = render(<Advanced label="Más"><p>x</p></Advanced>);
  expect(details().open).toBe(false);
  rerender(<Advanced label="Más" forceOpen><p>x</p></Advanced>);
  expect(details().open).toBe(true);
  rerender(<Advanced label="Más"><p>x</p></Advanced>);
  expect(details().open).toBe(true);
});

test("el contador aparece solo con opciones cambiadas", () => {
  const { rerender } = render(<Advanced changed={0}><p>x</p></Advanced>);
  expect(screen.getByText("Opciones avanzadas")).toBeInTheDocument();
  rerender(<Advanced changed={2}><p>x</p></Advanced>);
  expect(screen.getByText("Opciones avanzadas · cambiadas: 2")).toBeInTheDocument();
});
