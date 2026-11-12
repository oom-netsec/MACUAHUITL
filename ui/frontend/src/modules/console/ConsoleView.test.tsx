import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConsoleView } from "./ConsoleView";
import { fakeCore } from "../../lib/fake";

test("la consola abre el puerto detectado, muestra su salida y envía comandos", async () => {
  const core = fakeCore({ fieldPorts: vi.fn(async () => ["/dev/ttyUSB0"]) });
  render(<ConsoleView core={core} />);
  await waitFor(() => expect(screen.getByLabelText("Puerto")).toHaveValue("/dev/ttyUSB0"));
  await userEvent.selectOptions(screen.getByLabelText("Velocidad"), "115200");
  await userEvent.click(screen.getByRole("button", { name: "Abrir" }));
  expect(core.consoleOpen).toHaveBeenCalledWith({ port: "/dev/ttyUSB0", baud: 115200, dataBits: 8, parity: "none", stopBits: 1, flow: "none" });
  act(() => {
    core.emitConsole({ runId: "c1", opened: "/dev/ttyUSB0 115200 8N1", outputPath: "/o/console/c.log" });
    core.emitConsole({ runId: "c1", data: "\r\nSwitch>" });
    core.emitConsole({ runId: "otra", data: "ajeno" });
  });
  expect(await screen.findByText(/Switch>/)).toBeInTheDocument();
  expect(screen.getByText(/grabando en \/o\/console\/c.log/)).toBeInTheDocument();
  expect(screen.queryByText(/ajeno/)).not.toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Comando"), "show version{Enter}");
  expect(core.consoleSend).toHaveBeenCalledWith("c1", "show version\r");
  expect(screen.getByLabelText("Comando")).toHaveValue("");
  await userEvent.click(screen.getByRole("button", { name: "Ctrl-C" }));
  expect(core.consoleSend).toHaveBeenCalledWith("c1", "\x03");
  await userEvent.click(screen.getByRole("button", { name: "BREAK" }));
  expect(core.consoleBreak).toHaveBeenCalledWith("c1");
  await userEvent.click(screen.getByRole("button", { name: "Cerrar" }));
  expect(core.consoleClose).toHaveBeenCalledWith("c1");
  act(() => core.emitConsole({ runId: "c1", done: true }));
  expect(await screen.findByRole("button", { name: "Abrir" })).toBeEnabled();
});

test("la consola muestra el error de permisos de forma legible", async () => {
  const core = fakeCore({ consoleOpen: vi.fn(async () => { throw new Error("rpc error: code = PermissionDenied desc = sin permiso sobre el puerto serie /dev/ttyUSB0: agrega tu usuario al grupo dialout"); }) });
  render(<ConsoleView core={core} />);
  await userEvent.type(screen.getByLabelText("Puerto"), "/dev/ttyUSB0");
  await userEvent.click(screen.getByRole("button", { name: "Abrir" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/^sin permiso.*dialout$/);
});

test("la consola sigue abierta al volver a renderizar y se puede cerrar", async () => {
  const core = fakeCore();
  const { rerender } = render(<ConsoleView core={core} />);
  await userEvent.type(screen.getByLabelText("Puerto"), "/dev/ttyUSB0");
  await userEvent.click(screen.getByRole("button", { name: "Abrir" }));
  act(() => core.emitConsole({ runId: "c1", opened: "/dev/ttyUSB0 9600 8N1", outputPath: "/o/c.log" }));
  rerender(<ConsoleView core={core} />);
  expect(screen.getByText(/conectado a \/dev\/ttyUSB0/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Cerrar" }));
  expect(core.consoleClose).toHaveBeenCalledWith("c1");
});

test("salir de la consola serie la cierra para no dejar el puerto tomado", async () => {
  const core = fakeCore();
  const { unmount } = render(<ConsoleView core={core} />);
  await userEvent.type(screen.getByLabelText("Puerto"), "/dev/ttyUSB0");
  await userEvent.click(screen.getByRole("button", { name: "Abrir" }));
  await waitFor(() => expect(core.consoleOpen).toHaveBeenCalled());
  unmount();
  await waitFor(() => expect(core.consoleClose).toHaveBeenCalledWith("c1"));
});
