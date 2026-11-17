import { termText } from "../../test-utils";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FieldView } from "./FieldView";
import { fakeCore } from "../../lib/fake";
import { sampleRejections } from "../transfer/fake";
import { NavContext } from "../../app/activity";

test("el servidor publica las rutas indicadas y muestra transferencias en vivo", async () => {
  const core = fakeCore({ serveStart: vi.fn(async () => "s1") });
  render(<FieldView core={core} />);
  await userEvent.type(screen.getByLabelText("IP de escucha (la de la interfaz hacia el equipo)"), "10.0.0.5");
  await userEvent.type(screen.getByLabelText(/Archivos/), "/img/c9300.bin, /cfg/r1.cfg");
  await userEvent.click(screen.getByRole("button", { name: "Servir" }));
  expect(core.serveStart).toHaveBeenCalledWith({ protocol: "tftp", addr: "10.0.0.5", files: ["/img/c9300.bin", "/cfg/r1.cfg"], allowAny: false, seconds: 3600 });
  act(() => {
    core.emitServe({ runId: "s1", listening: "10.0.0.5:69", hint: "copy tftp://10.0.0.5/c9300.bin flash:" });
    core.emitServe({ runId: "s1", transfer: JSON.stringify({ Client: "10.0.0.9:50000", File: "c9300.bin", Bytes: 1024, Duration: 2e9, Result: "ok" }) });
  });
  expect(await screen.findByText(/sirviendo en 10.0.0.5:69/)).toBeInTheDocument();
  expect(screen.getByText(termText(/copy tftp:\/\/10.0.0.5\/c9300.bin/))).toBeInTheDocument();
  expect(screen.getByText(termText(/10.0.0.9:50000.*c9300.bin.*1024 bytes.*correcta/))).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Detener" }));
  expect(core.diagCancel).toHaveBeenCalledWith("s1");
});

test("con serverId en el primer evento muestra el panel en vivo y lo oculta al terminar", async () => {
  const transferSessions = vi.fn(async () => ({ sessions: [], rejections: sampleRejections(Date.now()) }));
  const core = fakeCore({ serveStart: vi.fn(async () => "s1"), transferSessions });
  render(<FieldView core={core} />);
  await userEvent.type(screen.getByLabelText("IP de escucha (la de la interfaz hacia el equipo)"), "10.0.0.5");
  await userEvent.type(screen.getByLabelText(/Archivos/), "/img/c9300.bin");
  await userEvent.click(screen.getByRole("button", { name: "Servir" }));
  act(() => core.emitServe({ runId: "s1", serverId: "sv1", listening: "10.0.0.5:6969" }));
  expect(await screen.findByRole("heading", { name: "Rechazos" })).toBeInTheDocument();
  expect(transferSessions).toHaveBeenCalledWith("sv1");
  act(() => core.emitServe({ runId: "s1", done: true }));
  await waitFor(() => expect(screen.queryByRole("heading", { name: "Rechazos" })).toBeNull());
});

test("sin serverId no hay panel en vivo", async () => {
  const transferSessions = vi.fn(async () => ({ sessions: [], rejections: [] }));
  const core = fakeCore({ serveStart: vi.fn(async () => "s1"), transferSessions });
  render(<FieldView core={core} />);
  await userEvent.type(screen.getByLabelText("IP de escucha (la de la interfaz hacia el equipo)"), "10.0.0.5");
  await userEvent.type(screen.getByLabelText(/Archivos/), "/img/c9300.bin");
  await userEvent.click(screen.getByRole("button", { name: "Servir" }));
  act(() => core.emitServe({ runId: "s1", listening: "10.0.0.5:6969" }));
  await screen.findByText(/sirviendo en/);
  expect(screen.queryByRole("region", { name: "En vivo" })).toBeNull();
  expect(transferSessions).not.toHaveBeenCalled();
});

test("el hash avisa si no coincide con el publicado", async () => {
  const core = fakeCore({ fieldHash: vi.fn(async () => ({ text: "MD5 abc  NO COINCIDE", ok: false })) });
  render(<FieldView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Hash" }));
  await userEvent.type(screen.getByLabelText("Ruta de la imagen"), "/img/c9300.bin");
  await userEvent.type(screen.getByLabelText("MD5 publicado (opcional)"), "abc");
  await userEvent.click(screen.getByRole("button", { name: "Calcular" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/no instales esta imagen/);
  expect(screen.getByText(/NO COINCIDE/)).toBeInTheDocument();
  expect(core.fieldHash).toHaveBeenCalledWith("/img/c9300.bin", "abc", "");
});

test("salir de la pestaña Campo detiene el servidor", async () => {
  const core = fakeCore();
  const { unmount } = render(<FieldView core={core} />);
  await userEvent.type(screen.getByLabelText("IP de escucha (la de la interfaz hacia el equipo)"), "10.0.0.5");
  await userEvent.type(screen.getByLabelText(/Archivos/), "/img/a.bin");
  await userEvent.click(screen.getByRole("button", { name: "Servir" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Detener" })).toBeEnabled());
  unmount();
  expect(core.diagCancel).toHaveBeenCalledWith("s1");
});

test("el servidor rápido remite a Transferencias para otros protocolos y puertos", async () => {
  const go = vi.fn();
  render(<NavContext.Provider value={{ go, inbox: {} }}><FieldView core={fakeCore()} /></NavContext.Provider>);
  await userEvent.click(screen.getByRole("button", { name: "Ir a Transferencias" }));
  expect(go).toHaveBeenCalledWith("transfer");
});
