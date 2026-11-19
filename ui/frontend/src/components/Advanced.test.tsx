import { useEffect } from "react";
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

test("con un contador, cada intento fallido lo reabre aunque el usuario lo haya cerrado", async () => {
  const { rerender } = render(<Advanced forceOpen={1}><p>x</p></Advanced>);
  expect(details().open).toBe(true);
  await userEvent.click(screen.getByText("Opciones avanzadas"));
  expect(details().open).toBe(false);
  rerender(<Advanced forceOpen={2}><p>x</p></Advanced>);
  expect(details().open).toBe(true);
});

test("ya está abierto en el DOM cuando corren los efectos del padre (el foco al campo inválido lo encuentra visible)", () => {
  let seen: boolean | undefined;
  function Parent({ n }: { n: number }) {
    useEffect(() => { if (n) seen = document.querySelector("details")!.open; }, [n]);
    return <Advanced forceOpen={n}><input aria-label="campo" /></Advanced>;
  }
  const { rerender } = render(<Parent n={0} />);
  rerender(<Parent n={1} />);
  expect(seen).toBe(true);
});

test("con un error presente (forceOpen booleano) el summary lo dice aunque el usuario lo cierre", async () => {
  render(<Advanced forceOpen><p>x</p></Advanced>);
  await userEvent.click(screen.getByText(/Opciones avanzadas/));
  expect(details().open).toBe(false);
  expect(details().querySelector("summary")).toHaveTextContent("Opciones avanzadas · hay un error dentro");
});

test("un contador de intentos no marca error (puede estar ya corregido)", () => {
  render(<Advanced forceOpen={3}><p>x</p></Advanced>);
  expect(details().querySelector("summary")).toHaveTextContent(/^Opciones avanzadas$/);
});
