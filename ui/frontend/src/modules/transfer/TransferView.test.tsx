import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TransferView } from "./TransferView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";
import type { TransferReady } from "./api";
import { setOSForTests } from "../../lib/platform";

const ifaces = [{ name: "eth0", up: true, loopback: false, addresses: ["192.0.2.10/24"], hardwareAddr: "" }];
const setup = (over = {}) => {
  const core = fakeCore({ listInterfaces: vi.fn(async () => ifaces), ...over });
  render(<CoreContext.Provider value={core}><TransferView core={core} /></CoreContext.Provider>);
  return core;
};
const ready = (o: Partial<TransferReady> = {}): TransferReady => ({
  serverId: "s1", protocol: "tftp", listening: "192.0.2.10:6969", hint: "", user: "", password: "", fingerprints: null, recvDir: "", fromDir: "/srv/img", files: ["c4.bin"], ...o,
});

async function openServer(core: ReturnType<typeof setup>, dir = "/srv/img") {
  await screen.findByRole("option", { name: /192.0.2.10/ });
  await userEvent.selectOptions(screen.getByLabelText("IP de escucha"), "192.0.2.10");
  await userEvent.type(screen.getByLabelText(/Carpeta de envío/, { selector: "input" }), dir);
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  return core;
}

test("el formulario inválido no abre nada y el válido usa el puerto estándar por omisión", async () => {
  const core = setup();
  expect(screen.getByRole("button", { name: "Abrir servidor" })).toBeDisabled(); // sin IP ni carpeta o archivos
  expect(core.transferServe).not.toHaveBeenCalled();
  await openServer(core);
  expect(core.transferServe).toHaveBeenCalledWith({
    protocol: "tftp", listen: "192.0.2.10:69", allowAny: false, files: [], fromDir: "/srv/img", write: false, recvDir: "", allow: [], seconds: 1800, legacySsh: false,
  });
});

test("el puerto cambia con el protocolo y uno fuera de rango se rechaza", async () => {
  const core = setup();
  await userEvent.selectOptions(screen.getByLabelText("Protocolo"), "scp");
  expect(screen.getByLabelText("Puerto")).toHaveValue(22);
  await userEvent.selectOptions(screen.getByLabelText("IP de escucha"), "192.0.2.10");
  await userEvent.type(screen.getByLabelText(/Carpeta de envío/, { selector: "input" }), "/srv/img");
  await userEvent.clear(screen.getByLabelText("Puerto"));
  await userEvent.type(screen.getByLabelText("Puerto"), "0");
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("entre 1 y 65535");
  expect(core.transferServe).not.toHaveBeenCalled();
});

test("las carpetas se eligen con el diálogo nativo", async () => {
  const core = setup({ pickPath: vi.fn(async () => "/home/u/recibidos") });
  await userEvent.click(screen.getByLabelText("Permitir recibir (el equipo puede copiar archivos hacia esta máquina)"));
  await userEvent.click(screen.getByRole("button", { name: /Examinar.*Carpeta de recepción/ }));
  expect(core.pickPath).toHaveBeenCalledWith({ title: "Carpeta de recepción", directory: true });
  expect(screen.getByLabelText("Carpeta de recepción", { selector: "input" })).toHaveValue("/home/u/recibidos");
});

test("la tarjeta de TFTP muestra el comando de IOS y la redirección para copiar", async () => {
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", ready: ready() }));
  const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:6969" });
  expect(within(card).getByRole("log", { name: "Comandos de IOS" })).toHaveTextContent("copy tftp://192.0.2.10/c4.bin flash:");
  expect(await within(card).findByRole("log", { name: "Regla de redirección (nftables)" })).toHaveTextContent(/redirect to :6969/);
  expect(core.transferHint).toHaveBeenCalledWith("tftp", "192.0.2.10", 6969);
  const copies = within(card).getAllByRole("button", { name: "Copiar" });
  await userEvent.click(copies[copies.length - 2]); // la regla; el último copia cómo quitarla
  expect(core.copyText).toHaveBeenCalledWith(expect.stringContaining("redirect to :6969"));
});

test("la tarjeta de FTP avisa del texto en claro y da usuario y contraseña", async () => {
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ protocol: "ftp", listening: "192.0.2.10:2121", user: "mac", password: "s3cret-pass" }) }));
  const card = await screen.findByRole("group", { name: "FTP 192.0.2.10:2121" });
  expect(within(card).getByRole("log", { name: "Comandos de IOS" })).toHaveTextContent("copy ftp://mac:s3cret-pass@192.0.2.10/c4.bin flash:");
  expect(within(card).getAllByText(/FTP manda usuario, contraseña y archivos en claro/).length).toBeGreaterThan(0);
  await userEvent.click(within(card).getByRole("button", { name: "Copiar Contraseña" }));
  expect(core.copyText).toHaveBeenCalledWith("s3cret-pass");
});

test("la tarjeta de SCP muestra las huellas de las llaves de host", async () => {
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ protocol: "scp", listening: "192.0.2.10:2222", user: "mac", password: "pw", fingerprints: ["SHA256:aaa", "SHA256:bbb"] }) }));
  const card = await screen.findByRole("group", { name: "SCP 192.0.2.10:2222" });
  expect(within(card).getByRole("log", { name: "Comandos de IOS" })).toHaveTextContent("copy scp://mac@192.0.2.10/c4.bin flash:");
  expect(within(card).getByText("SHA256:aaa")).toBeInTheDocument();
  expect(within(card).getByText("SHA256:bbb")).toBeInTheDocument();
});

test("el registro en vivo, Detener y la lista que sobrevive al cambiar de pestaña", async () => {
  const core = await openServer(setup());
  act(() => {
    core.emitTransfer({ runId: "r1", ready: ready({ recvDir: "/o/recibidos/x" }) });
    core.emitTransfer({ runId: "r1", line: { Proto: "tftp", Client: "192.0.2.1", File: "r1-config.txt", Bytes: 2048, Duration: 1e9, Result: "ok", Dir: "write-text", dirCode: "write", SHA256: "f".repeat(64) } });
    core.emitTransfer({ runId: "r1", line: { Proto: "tftp", Client: "192.0.2.9", File: "x", Bytes: 0, Duration: 0, Result: "error", Rejected: true, Error: "no publicado" } });
  });
  const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:6969" });
  await waitFor(() => expect(within(card).getByRole("table")).toBeInTheDocument()); // las líneas pasan por lotes
  const rows = within(within(card).getByRole("table")).getAllByRole("row");
  expect(rows[1]).toHaveTextContent("192.0.2.1");
  expect(rows[1]).toHaveTextContent("r1-config.txt");
  expect(rows[1]).toHaveTextContent("2048");
  expect(rows[1]).toHaveTextContent("f".repeat(64));
  expect(rows[1]).toHaveTextContent("recibido");
  expect(rows[1]).toHaveTextContent("correcta");
  expect(rows[2]).toHaveTextContent("rechazada");
  expect(within(card).getByRole("log", { name: "Comandos de IOS" })).toHaveTextContent("copy running-config tftp://192.0.2.10/r1-config.txt");
  // Otra pestaña y de vuelta: el servidor sigue ahí.
  await userEvent.click(screen.getByRole("tab", { name: "Cliente" }));
  await userEvent.click(screen.getByRole("tab", { name: "Servidor" }));
  expect(screen.getByRole("group", { name: "TFTP 192.0.2.10:6969" })).toBeInTheDocument();
  await userEvent.click(within(card).getByRole("button", { name: "Detener" }));
  expect(core.transferStop).toHaveBeenCalledWith("s1");
  act(() => core.emitTransfer({ runId: "r1", done: true }));
  expect(await within(card).findByText("cerrado")).toBeInTheDocument();
  await userEvent.click(within(card).getByRole("button", { name: "Quitar" }));
  expect(screen.queryByRole("group", { name: /TFTP/ })).not.toBeInTheDocument();
});

test("un servidor que no llega a abrir muestra el error del núcleo", async () => {
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", done: true, error: "rpc error: code = InvalidArgument desc = carpeta sensible" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("carpeta sensible");
});

test("el puerto estándar negado por el sistema muestra la orden de sysctl para copiar, sin aplicarla", async () => {
  const cmd = "echo 'net.ipv4.ip_unprivileged_port_start=21' | sudo tee /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl --system";
  const denied = Object.assign(new Error("rpc error: code = FailedPrecondition desc = Linux no deja abrir el puerto 69"), {
    cause: { code: "FailedPrecondition", reason: "fileserve.err.port_denied", metadata: { port: "69", min_port: "21", cmd } },
  });
  const core = await openServer(setup({ transferServe: vi.fn(async () => { throw denied; }) }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Linux no deja abrir el puerto 69");
  expect(screen.getByText(cmd)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /Copiar/ }));
  expect(core.copyText).toHaveBeenCalledWith(cmd);
  expect(screen.getByLabelText("Puerto")).not.toBeDisabled(); // se puede elegir otro puerto en lugar de aplicar la orden
  // Un intento siguiente que falla por otra causa no deja la orden vieja a la vista.
  vi.mocked(core.transferServe).mockRejectedValueOnce(new Error("puerto en uso"));
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  await waitFor(() => expect(screen.queryByText(cmd)).toBeNull());
});

test("el bind negado llega por el evento de cierre (StartServer es un stream) y también muestra la orden", async () => {
  const cmd = "echo 'net.ipv4.ip_unprivileged_port_start=69' | sudo tee /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl --system";
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", done: true, error: "rpc error: code = FailedPrecondition desc = Linux no deja abrir el puerto 69",
    errorInfo: { code: "FailedPrecondition", reason: "fileserve.err.port_denied", metadata: { port: "69", min_port: "69", cmd } } }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Linux no deja abrir el puerto 69");
  expect(screen.getByText(cmd)).toBeInTheDocument();
  // Solo el error de puerto negado trae orden para copiar: otro motivo con metadata.cmd no la muestra.
  act(() => core.emitTransfer({ runId: "r2", done: true, error: "otra cosa", errorInfo: { code: "Internal", reason: "fileserve.err.otro", metadata: { cmd: "rm -rf /" } } }));
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("otra cosa"));
  expect(screen.queryByText("rm -rf /")).toBeNull();
  expect(screen.queryByText(cmd)).toBeNull();
});

test("la carpeta de recepción abierta a otros muestra la orden exacta para copiar, sin aplicarla", async () => {
  const cmd = "chmod o-w /srv/recibidos";
  const open = Object.assign(new Error("fileserve: la carpeta de recepción /srv/recibidos la pueden escribir otros (escritura para otros usuarios); quítales la escritura con: chmod o-w /srv/recibidos"), {
    cause: { code: "FailedPrecondition", reason: "fileserve.err.recv_dir_open", metadata: { dir: "/srv/recibidos", who: "sys.who.others", cmd } },
  });
  const core = await openServer(setup({ transferServe: vi.fn(async () => { throw open; }) }));
  expect(await screen.findByRole("alert")).toHaveTextContent("la pueden escribir otros");
  expect(screen.getByText(cmd)).toBeInTheDocument();
  expect(screen.getByText(/Orden para quitar la escritura ajena/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /Copiar/ }));
  expect(core.copyText).toHaveBeenCalledWith(cmd);
  // La variante sin orden (Windows sin icacls seguro) no muestra consola.
  const bare = Object.assign(new Error("fileserve: la carpeta de recepción X la pueden escribir otros"), { cause: { code: "FailedPrecondition", reason: "fileserve.err.recv_dir_open", metadata: { dir: "X", who: "sys.who.others" } } });
  vi.mocked(core.transferServe).mockRejectedValueOnce(bare);
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  await waitFor(() => expect(screen.queryByText(cmd)).toBeNull());
  expect(screen.queryByRole("button", { name: /Copiar/ })).toBeNull();
});

test("con note (ruta del programa insegura) el hint es texto: sin consola de regla ni orden para copiar", async () => {
  const note = "La ruta de macuahuitld.exe no se puede citar con seguridad: crea a mano la regla de entrada del Firewall.";
  const core = await openServer(setup({ transferHint: vi.fn(async () => ({ standardPort: 69, nftables: "", remove: "", note, noteCode: "fileserve.hint.win_rule_manual" })) }));
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ listening: "192.0.2.10:6969" }) }));
  setOSForTests("windows"); // la nota solo llega en Windows
  try {
  const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:6969" });
  const el = await within(card).findByText(note);
  expect(el.closest('[role="log"]')).toBeNull();
  expect(within(card).queryByRole("log", { name: /redirección/i })).toBeNull();
  expect(within(card).queryAllByRole("log")).toHaveLength(1); // solo la orden de IOS
  } finally { setOSForTests(undefined); }
});

test("sin note, la regla sigue siendo una orden para copiar y no aparece texto de nota", async () => {
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ listening: "192.0.2.10:6969" }) }));
  const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:6969" });
  expect(await within(card).findByRole("log", { name: "Regla de redirección (nftables)" })).toBeInTheDocument();
  expect(within(card).queryByText(/macuahuitld\.exe/)).toBeNull();
});

test("en Linux, con el puerto estándar no hay regla de redirección que mostrar", async () => {
  const core = await openServer(setup({ transferHint: vi.fn(async () => ({ standardPort: 69, nftables: "", remove: "" })) }));
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ listening: "192.0.2.10:69" }) }));
  const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:69" });
  await waitFor(() => expect(core.transferHint).toHaveBeenCalled());
  await act(async () => {});
  expect(within(card).queryByRole("log", { name: "Regla de redirección (nftables)" })).toBeNull();
  expect(within(card).queryByText(/Firewall de Windows/)).toBeNull();
});

test("en Linux, en el puerto estándar avisa de una redirección nft vieja con la orden para quitarla (no se puede detectar sin privilegios)", async () => {
  const core = await openServer(setup({ transferHint: vi.fn(async () => ({ standardPort: 69, nftables: "", remove: "" })) }));
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ listening: "192.0.2.10:69" }) }));
  const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:69" });
  expect(await within(card).findByRole("log", { name: /redirección nft/i })).toHaveTextContent("sudo nft delete table ip macuahuitl_tftp_6969");
  setOSForTests("windows");
  try {
    act(() => core.emitTransfer({ runId: "r2", ready: ready({ serverId: "s2", listening: "192.0.2.10:69" }) }));
    const win = (await screen.findAllByRole("group", { name: "TFTP 192.0.2.10:69" }))[1];
    await waitFor(() => expect(core.transferHint).toHaveBeenCalledTimes(2)); // la pista de r2 ya llegó
    await act(async () => {});
    expect(within(win).queryByRole("log", { name: /redirección nft/i })).toBeNull();
  } finally { setOSForTests(undefined); }
  // Con el servidor cerrado ya no hay tráfico que perder: la ayuda se va.
  act(() => core.emitTransfer({ runId: "r1", done: true }));
  await waitFor(() => expect(within(card).queryByRole("log", { name: /redirección nft/i })).toBeNull());
});

const client = async (core: ReturnType<typeof setup>, url: string) => {
  await userEvent.click(screen.getByRole("tab", { name: "Cliente" }));
  await userEvent.click(screen.getByLabelText("Pegar una URL"));
  await userEvent.paste(url);
  return core;
};

test("el cliente descarga con el hash esperado y muestra MD5, SHA-256 y verificación", async () => {
  const sha = "b".repeat(64);
  const core = setup({ transferGet: vi.fn(async () => ({ path: "/o/c4.bin", bytes: 10, md5: "a".repeat(32), sha256: sha, verified: "ok", seconds: 1, report: "" })) });
  await client(core, "tftp://192.0.2.1/c4.bin");
  await userEvent.type(screen.getByLabelText("Hash esperado (opcional)"), sha);
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(core.transferGet).toHaveBeenCalledWith({ url: "tftp://192.0.2.1/c4.bin", destDir: "", credentialId: "", acceptedHostKeys: [], insecure: false, legacySsh: false, sha256: sha });
  expect(await screen.findByText(/verificada contra el hash esperado/)).toBeInTheDocument();
  expect(screen.getByRole("log", { name: "Resultado" })).toHaveTextContent(`SHA-256: ${sha}`);
  expect(screen.getByRole("log", { name: "Resultado" })).toHaveTextContent("MD5: " + "a".repeat(32));
});

test("el cliente avisa cuando el hash no coincide", async () => {
  const core = setup({ transferGet: vi.fn(async () => { throw new Error("rpc error: code = Unknown desc = transfer: el resumen no coincide (SHA-256 aaa, MD5 bbb): se descartó el archivo"); }) });
  await client(core, "http://192.0.2.1/c4.bin");
  await userEvent.type(screen.getByLabelText("Hash esperado (opcional)"), "c".repeat(64));
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("El hash no coincide con el esperado: el archivo se descartó.");
  expect(alert).toHaveTextContent("se descartó el archivo");
  expect(screen.queryByRole("log", { name: "Resultado" })).not.toBeInTheDocument();
});

test("el cliente rechaza datos inválidos antes de llamar al núcleo", async () => {
  const core = setup();
  await client(core, "ftp://mac:pw@192.0.2.1/x");
  expect(screen.getByLabelText("Pegar una URL")).toHaveAccessibleDescription(/No pongas la contraseña en la URL/);
  expect((screen.getByLabelText("URL que se enviará") as HTMLInputElement).value).not.toMatch(/pw/); // la contraseña nunca llega a los campos
  expect(screen.getByLabelText("Pegar una URL")).toHaveValue(""); // se borra: la contraseña no se queda en pantalla
  await userEvent.click(screen.getByLabelText("Pegar una URL"));
  await userEvent.paste("scp://mac@192.0.2.1/x");
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(await screen.findByText("Elige la credencial de la bóveda para SCP o SFTP.")).toBeInTheDocument();
  expect(core.transferGet).not.toHaveBeenCalled();
});

test("una llave de host nueva pide aceptar la huella y reintenta con ella", async () => {
  const get = vi.fn()
    .mockRejectedValueOnce(new Error("rpc error: code = FailedPrecondition desc = transport: llave de host desconocida de 192.0.2.1:22: SHA256:AbC123+/x"))
    .mockResolvedValueOnce({ path: "/o/x", bytes: 1, md5: "a".repeat(32), sha256: "b".repeat(64), verified: "", seconds: 0, report: "" });
  const core = setup({ transferGet: get, listCredentials: vi.fn(async () => [{ id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false }]) });
  await client(core, "scp://admin@192.0.2.1/ios.bin");
  await userEvent.selectOptions(await screen.findByLabelText("Credencial"), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(await screen.findByText("SHA256:AbC123+/x")).toBeInTheDocument();
  expect(get).toHaveBeenCalledTimes(1);
  expect(get.mock.calls[0][0]).toMatchObject({ credentialId: "c1", acceptedHostKeys: [] });
  await userEvent.click(screen.getByRole("button", { name: "Aceptar esta huella y reintentar" }));
  await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
  expect(get.mock.calls[1][0]).toMatchObject({ acceptedHostKeys: ["SHA256:AbC123+/x"] });
  expect(await screen.findByText("Transferencia terminada.")).toBeInTheDocument();
});

test("el envío separa carpeta y nombre del archivo elegido con el diálogo", async () => {
  const core = setup({ pickPath: vi.fn(async () => "/home/u/cfg/r1.txt") });
  await client(core, "tftp://192.0.2.1/r1.txt");
  await userEvent.click(screen.getByLabelText("Enviar (put)"));
  await userEvent.click(screen.getByRole("button", { name: /Examinar.*Archivo de origen/ }));
  await userEvent.click(screen.getByRole("button", { name: "Enviar" }));
  await waitFor(() => expect(core.transferPut).toHaveBeenCalledWith({ url: "tftp://192.0.2.1/r1.txt", fromDir: "/home/u/cfg", name: "r1.txt", credentialId: "", acceptedHostKeys: [], legacySsh: false }));
});

// ---- revisión de seguridad: avisos y opciones nuevas ----

test("0.0.0.0 no se ofrece en la lista; «todas las interfaces» es una opción avanzada que siempre exige la lista de IP", async () => {
  const core = setup();
  await screen.findByRole("option", { name: /192.0.2.10/ });
  expect(screen.queryByRole("option", { name: /0\.0\.0\.0/ })).not.toBeInTheDocument();
  await userEvent.type(screen.getByLabelText(/Carpeta de envío/, { selector: "input" }), "/srv/img");
  await userEvent.click(screen.getByLabelText(/Escuchar en todas las interfaces/));
  expect(screen.getByText(/Cualquier equipo de las redes conectadas/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Para escuchar en todas las interfaces indica las IP permitidas.");
  expect(core.transferServe).not.toHaveBeenCalled();
  await userEvent.type(screen.getByLabelText(/IP permitidas/), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  expect(core.transferServe).toHaveBeenCalledWith(expect.objectContaining({ listen: "0.0.0.0:69", allowAny: true, allow: ["192.0.2.1"] }));
});

test("recibir por TFTP exige la lista de IP y avisa que en UDP no autentica", async () => {
  const core = setup();
  await screen.findByRole("option", { name: /192.0.2.10/ });
  await userEvent.selectOptions(screen.getByLabelText("IP de escucha"), "192.0.2.10");
  await userEvent.click(screen.getByLabelText(/Permitir recibir/));
  expect(screen.getAllByText(/En UDP la lista de IP no autentica/).length).toBeGreaterThan(0);
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Recibir por TFTP exige la lista de IP permitidas");
  expect(core.transferServe).not.toHaveBeenCalled();
  await userEvent.type(screen.getByLabelText(/IP permitidas/), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  expect(core.transferServe).toHaveBeenCalledWith(expect.objectContaining({ write: true, allow: ["192.0.2.1"] }));
});

test("la carpeta de recepción avisa de lo que no se acepta", async () => {
  setup();
  await userEvent.click(screen.getByLabelText(/Permitir recibir/));
  expect(screen.getByText(/tu carpeta personal completa/)).toBeInTheDocument();
  expect(screen.getByText(/nombres que empiezan con punto/)).toBeInTheDocument();
});

test("la compatibilidad con IOS antiguo está apagada por omisión, se explica y se envía a pedido", async () => {
  const core = setup();
  await userEvent.selectOptions(screen.getByLabelText("Protocolo"), "scp");
  const box = screen.getByLabelText("Compatibilidad con IOS antiguo");
  expect(box).not.toBeChecked();
  expect(screen.getByText(/aes128-cbc, 3des-cbc, diffie-hellman-group14-sha1, hmac-sha1 y ssh-rsa/)).toBeInTheDocument();
  await openServer(core);
  expect(core.transferServe).toHaveBeenLastCalledWith(expect.objectContaining({ protocol: "scp", legacySsh: false }));
  await userEvent.click(box);
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  expect(core.transferServe).toHaveBeenLastCalledWith(expect.objectContaining({ protocol: "scp", legacySsh: true }));
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ protocol: "scp", listening: "192.0.2.10:2222", user: "mac", password: "pw" }) }));
  const card = await screen.findByRole("group", { name: "SCP 192.0.2.10:2222" });
  expect(within(card).getByText(/ofrece algoritmos SSH débiles/)).toBeInTheDocument();
});

test("la regla de redirección es estrecha, trae cómo quitarla y el cierre la repite", async () => {
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", ready: ready() }));
  const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:6969" });
  expect(await within(card).findByRole("log", { name: "Quitar la regla al terminar" })).toHaveTextContent("sudo nft delete table ip macuahuitl_tftp_6969");
  expect(within(card).getByText(/solo lo dirigido a la IP de escucha/)).toBeInTheDocument();
  act(() => core.emitTransfer({ runId: "r1", done: true, cleanup: "sudo nft delete table ip macuahuitl_tftp_6969" }));
  expect(await within(card).findByText("cerrado")).toBeInTheDocument();
  expect(within(card).getByText(/Si aplicaste la regla de redirección, quítala/)).toBeInTheDocument();
});

test("la tarjeta de FTP sugiere borrar la credencial del equipo al terminar", async () => {
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ protocol: "ftp", listening: "192.0.2.10:2121", user: "mac", password: "pw" }) }));
  const card = await screen.findByRole("group", { name: "FTP 192.0.2.10:2121" });
  expect(within(card).getAllByText(/no ip ftp password/).length).toBeGreaterThan(0);
});

test("dos clics seguidos en Abrir servidor no abren dos servidores", async () => {
  const core = setup({ transferServe: vi.fn(() => new Promise<void>(() => {})) });
  await openServer(core);
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  expect(core.transferServe).toHaveBeenCalledTimes(1);
});

// Con la interfaz en inglés el texto del núcleo no dice «no coincide»: el aviso sale del reason.
test("el cliente avisa del hash distinto por el reason, aunque el texto venga en inglés", async () => {
  const err = Object.assign(new Error("transfer: the digest does not match (SHA-256 aaa, MD5 bbb): the file was discarded"), { cause: { code: "Unavailable", reason: "xfer.err.digest", metadata: {} } });
  const core = setup({ transferGet: vi.fn(async () => { throw err; }) });
  await client(core, "http://192.0.2.1/c4.bin");
  await userEvent.type(screen.getByLabelText("Hash esperado (opcional)"), "c".repeat(64));
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("El hash no coincide con el esperado: el archivo se descartó.");
});

test("el aviso de hash distinto también sale con el SHA-512 publicado (por reason)", async () => {
  const err = Object.assign(new Error("the SHA-512 does not match the published one"), { cause: { code: "Unavailable", reason: "transfer.svc.sha512", metadata: {} } });
  const core = setup({ transferGet: vi.fn(async () => { throw err; }) });
  await client(core, "http://192.0.2.1/c4.bin");
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("El hash no coincide con el esperado");
});

test("una llave de host nueva en inglés, con reason, también pide aceptar la huella", async () => {
  const cause = { code: "FailedPrecondition", reason: "transport.hostkey.unknown", metadata: { host: "192.0.2.1:22", fingerprint: "SHA256:AbC123+/x" } };
  const get = vi.fn().mockRejectedValueOnce(Object.assign(new Error("transport: unknown host key from 192.0.2.1:22: SHA256:AbC123+/x"), { cause }));
  const core = setup({ transferGet: get, listCredentials: vi.fn(async () => [{ id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false }]) });
  await client(core, "scp://admin@192.0.2.1/ios.bin");
  await userEvent.selectOptions(await screen.findByLabelText("Credencial"), "c1");
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(await screen.findByRole("button", { name: "Aceptar esta huella y reintentar" })).toBeInTheDocument();
});

test("al cerrarse el servidor, la contraseña efímera y los comandos de IOS (que la llevan en la URL) dejan de verse", async () => {
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ protocol: "ftp", listening: "192.0.2.10:2121", user: "mac", password: "s3cret-pass" }) }));
  const card = await screen.findByRole("group", { name: "FTP 192.0.2.10:2121" });
  expect(within(card).getByText("s3cret-pass")).toBeInTheDocument();
  act(() => core.emitTransfer({ runId: "r1", done: true }));
  await waitFor(() => expect(within(card).queryByText("s3cret-pass")).toBeNull());
  expect(within(card).queryByRole("log", { name: "Comandos de IOS" })).toBeNull();
  expect(card.textContent).not.toContain("s3cret-pass");
});

// ADR 0012 (h): en Windows el servidor escucha en el estándar (69) y la regla de firewall se muestra siempre.
test("Windows: TFTP por omisión en el 69, puerto 1-65535 y la regla de firewall aunque sea el puerto estándar", async () => {
  setOSForTests("windows");
  try {
    const rule = 'New-NetFirewallRule -DisplayName "MACUAHUITL UDP 69" -Direction Inbound -Program "C:\\m\\macuahuitld.exe" -LocalAddress 192.0.2.10 -Protocol UDP -LocalPort 69 -Action Allow';
    const core = setup({ transferHint: vi.fn(async () => ({ standardPort: 69, nftables: rule, remove: 'Remove-NetFirewallRule -DisplayName "MACUAHUITL UDP 69"' })) });
    expect(screen.getByLabelText("Puerto")).toHaveValue(69);
    expect(screen.getByLabelText("Puerto")).toHaveAccessibleDescription(/De 1 a 65535/);
    await openServer(core, "C:\\srv\\img");
    expect(core.transferServe).toHaveBeenCalledWith(expect.objectContaining({ listen: "192.0.2.10:69" }));
    act(() => core.emitTransfer({ runId: "r1", ready: ready({ listening: "192.0.2.10:69" }) }));
    const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:69" });
    expect(await within(card).findByRole("log", { name: "Regla de firewall (PowerShell, como administrador)" })).toHaveTextContent(/New-NetFirewallRule/);
    expect(within(card).getByText(/una vez, como administrador/)).toBeInTheDocument();
    expect(within(card).getByText(/escucha ahí/)).toBeInTheDocument(); // puerto estándar: sin «IOS usa el 69; escucha en el 69»
    expect(within(card).getByText(/CANCELAS/)).toBeInTheDocument();
    expect(within(card).queryByText(/nftables/)).not.toBeInTheDocument();
    expect(core.transferHint).toHaveBeenCalledWith("tftp", "192.0.2.10", 69);
  } finally { setOSForTests(undefined); }
});

test("Windows: con un puerto distinto del estándar el texto dice que IOS necesita abrirlo en el estándar", async () => {
  setOSForTests("windows");
  try {
    const core = setup({ transferHint: vi.fn(async () => ({ standardPort: 69, nftables: "New-NetFirewallRule x", remove: "Remove-NetFirewallRule x" })) });
    await openServer(core);
    act(() => core.emitTransfer({ runId: "r1", ready: ready() }));
    const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:6969" });
    expect(await within(card).findByText(/ábrelo en el estándar/)).toBeInTheDocument();
  } finally { setOSForTests(undefined); }
});

test("done vacía el lote pendiente: ninguna línea se pierde y el orden se conserva", async () => {
  const core = await openServer(setup());
  act(() => {
    core.emitTransfer({ runId: "r1", ready: ready() });
    for (let i = 0; i < 3; i++) core.emitTransfer({ runId: "r1", line: { Proto: "tftp", Client: `192.0.2.${i + 1}`, File: `f${i}`, Bytes: 1, Duration: 1, Result: "ok", Dir: "write-text", dirCode: "write", SHA256: "a".repeat(64) } });
    core.emitTransfer({ runId: "r1", done: true });
  });
  const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:6969" });
  const rows = within(within(card).getByRole("table")).getAllByRole("row");
  expect(rows).toHaveLength(4);
  expect(rows[1]).toHaveTextContent("f0");
  expect(rows[3]).toHaveTextContent("f2");
});

// 43d-2b: los avisos de carpeta de ServerReady.warnings: el texto como aviso y la orden en una consola copiable.
test("avisos de carpeta del servidor: texto como aviso y orden aparte; sin orden no hay consola; cerrado, sin orden", async () => {
  const core = await openServer(setup());
  act(() => core.emitTransfer({ runId: "r1", ready: ready({ warnings: [
    { code: "fileserve.hint.warn_from_writable", message: "Otros usuarios pueden escribir en /srv/img.", cmd: "chmod go-w '/srv/img'" },
    { code: "fileserve.hint.warn_unverified", message: "No se pudieron revisar los permisos de /srv/img.", cmd: "" },
  ] }) }));
  const card = await screen.findByRole("group", { name: "TFTP 192.0.2.10:6969" });
  const notes = within(card).getAllByRole("status").map((n) => n.textContent);
  expect(notes).toContain("Otros usuarios pueden escribir en /srv/img.");
  expect(notes).toContain("No se pudieron revisar los permisos de /srv/img.");
  expect(notes.join("")).not.toContain("chmod"); // la orden nunca va dentro del texto del aviso
  const fix = within(card).getByRole("log", { name: "Orden para corregir la carpeta" });
  expect(fix).toHaveTextContent("chmod go-w '/srv/img'");
  expect(within(card).getAllByRole("log", { name: "Orden para corregir la carpeta" })).toHaveLength(1);
  act(() => core.emitTransfer({ runId: "r1", done: true }));
  await waitFor(() => expect(within(card).queryByRole("log", { name: "Orden para corregir la carpeta" })).toBeNull());
  expect(within(card).getByText("Otros usuarios pueden escribir en /srv/img.")).toBeInTheDocument();
});

test("con «todas las interfaces» el selector de IP no se muestra y el envío usa 0.0.0.0", async () => {
  const core = setup();
  await screen.findByRole("option", { name: /192.0.2.10/ });
  await userEvent.click(screen.getByLabelText(/Escuchar en todas las interfaces/));
  expect(screen.queryByLabelText("IP de escucha")).toBeNull();
  await userEvent.type(screen.getByLabelText(/Carpeta de envío/, { selector: "input" }), "/srv/img");
  await userEvent.type(screen.getByLabelText(/IP permitidas/), "192.0.2.5");
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  await waitFor(() => expect(core.transferServe).toHaveBeenCalledWith(expect.objectContaining({ listen: "0.0.0.0:69", allowAny: true })));
  await userEvent.click(screen.getByLabelText(/Escuchar en todas las interfaces/));
  expect(screen.getByLabelText("IP de escucha")).toBeInTheDocument();
});

test("servidor: puerto, duración, todas las interfaces e IP permitidas van plegados; cuentan los cambios y un error ahí abre el panel", async () => {
  setup();
  await screen.findByRole("option", { name: /192.0.2.10/ });
  const det = screen.getByLabelText("Puerto").closest("details")!;
  expect(det.open).toBe(false);
  for (const l of ["Puerto", /Duración/, /Escuchar en todas las interfaces/, /IP permitidas/]) expect(det).toContainElement(screen.getByLabelText(l));
  await userEvent.click(screen.getByLabelText(/Escuchar en todas las interfaces/));
  expect(det.querySelector("summary")).toHaveTextContent("Opciones avanzadas · cambiadas: 1");
  expect(screen.getByText(/Cualquier equipo de las redes conectadas/)).toBeInTheDocument(); // el aviso sigue fuera
  expect(det).not.toContainElement(screen.getByText(/Cualquier equipo de las redes conectadas/));
  expect(det.open).toBe(false);
  await userEvent.type(screen.getByLabelText(/Carpeta de envío/, { selector: "input" }), "/srv/img");
  await userEvent.click(screen.getByRole("button", { name: "Abrir servidor" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("indica las IP permitidas");
  expect(det.open).toBe(true);
});

test("servidor: recibir por TFTP deja «IP permitidas» a la vista, fuera de Avanzado", async () => {
  setup();
  await screen.findByRole("option", { name: /192.0.2.10/ });
  await userEvent.click(screen.getByLabelText(/Permitir recibir/));
  expect(screen.getByLabelText(/IP permitidas/).closest("details")).toBeNull();
});
