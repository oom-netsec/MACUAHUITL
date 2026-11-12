import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { ConfirmButton, Console, Field, Notice, PathField } from "./Field";

test("la ayuda de un campo queda asociada como descripción", () => {
  render(<Field label="Destino" hint="Nombre de host o dirección IP." value="" onChange={() => {}} />);
  expect(screen.getByLabelText("Destino")).toHaveAccessibleDescription("Nombre de host o dirección IP.");
});

test("Examinar llena la ruta con lo elegido y cancelar no la borra", async () => {
  const pick = vi.fn(async () => "/home/u/cap.pcapng");
  function Host() {
    const [v, setV] = useState("/previa");
    return <PathField label="Archivo de captura" value={v} onChange={setV} pick={pick} />;
  }
  render(<Host />);
  await userEvent.click(screen.getByRole("button", { name: "Examinar… Archivo de captura" }));
  expect(screen.getByLabelText("Archivo de captura")).toHaveValue("/home/u/cap.pcapng");
  pick.mockResolvedValueOnce("");
  await userEvent.click(screen.getByRole("button", { name: /Examinar/ }));
  expect(screen.getByLabelText("Archivo de captura")).toHaveValue("/home/u/cap.pcapng");
});

test("los errores se anuncian como alerta y los avisos como estado", () => {
  render(<><Notice kind="error">falló</Notice><Notice kind="ok">listo</Notice></>);
  expect(screen.getByRole("alert")).toHaveTextContent("falló");
  expect(screen.getByRole("status")).toHaveTextContent("listo");
});

test("eliminar pide un segundo click y se arrepiente solo", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const onConfirm = vi.fn();
  render(<ConfirmButton label="Eliminar Core" confirmLabel="Confirmar eliminación de Core" onConfirm={onConfirm} />);
  await userEvent.click(screen.getByRole("button", { name: "Eliminar Core" }));
  expect(onConfirm).not.toHaveBeenCalled();
  act(() => vi.advanceTimersByTime(5000));
  await userEvent.click(screen.getByRole("button", { name: "Eliminar Core" }));
  await userEvent.click(screen.getByRole("button", { name: "Confirmar eliminación de Core" }));
  expect(onConfirm).toHaveBeenCalledTimes(1);
  vi.useRealTimers();
});

test("la consola copia y limpia su contenido", async () => {
  const copy = vi.fn(async () => {});
  const onClear = vi.fn();
  render(<Console label="Salida" text={"línea 1\nlínea 2"} copy={copy} onClear={onClear} />);
  expect(screen.getByRole("log", { name: "Salida" })).toHaveTextContent("línea 1");
  await userEvent.click(screen.getByRole("button", { name: "Copiar" }));
  expect(copy).toHaveBeenCalledWith("línea 1\nlínea 2");
  expect(await screen.findByRole("button", { name: "Copiado" })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Limpiar" }));
  expect(onClear).toHaveBeenCalled();
});
