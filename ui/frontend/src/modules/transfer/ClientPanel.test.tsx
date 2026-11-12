import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ClientPanel } from "./ClientPanel";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";

const creds = [{ id: "c1", label: "lab", username: "admin", hasEnable: false, hasSshKey: false }];
const setup = (over = {}) => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), ...over });
  render(<CoreContext.Provider value={core}><ClientPanel core={core} /></CoreContext.Provider>);
  return core;
};
const url = () => (screen.getByLabelText("URL que se enviará") as HTMLInputElement).value;
const proto = (name: string) => screen.getByRole("radio", { name });

test("la URL se arma sola desde protocolo, equipo, puerto y ruta, y se puede copiar", async () => {
  const core = setup();
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "2001:db8::1");
  await userEvent.type(screen.getByLabelText("Ruta remota"), "/imagenes/c4.bin");
  expect(url()).toBe("tftp://[2001:db8::1]/imagenes/c4.bin");
  await userEvent.click(proto("SFTP"));
  expect(screen.getByLabelText("Puerto remoto")).toHaveValue("22");
  await userEvent.clear(screen.getByLabelText("Puerto remoto"));
  await userEvent.type(screen.getByLabelText("Puerto remoto"), "2200");
  expect(url()).toBe("sftp://[2001:db8::1]:2200//imagenes/c4.bin");
  await userEvent.click(screen.getByRole("button", { name: /Copiar URL que se enviará/ }));
  expect(core.copyText).toHaveBeenCalledWith("sftp://[2001:db8::1]:2200//imagenes/c4.bin");
});

test("el puerto por omisión sigue al protocolo solo mientras no se haya editado", async () => {
  setup();
  const port = screen.getByLabelText("Puerto remoto");
  expect(port).toHaveValue("69");
  await userEvent.click(proto("HTTPS"));
  expect(port).toHaveValue("443");
  await userEvent.clear(port);
  await userEvent.type(port, "8443");
  await userEvent.click(proto("HTTP"));
  expect(port).toHaveValue("8443");
});

test("una URL pegada llena protocolo, equipo, puerto y ruta", async () => {
  setup();
  await userEvent.click(screen.getByLabelText("Pegar una URL"));
  await userEvent.paste("scp://admin@[2001:db8::2]:2200/ios/c4.bin");
  expect(proto("SCP")).toBeChecked();
  expect(screen.getByLabelText("Equipo remoto")).toHaveValue("2001:db8::2");
  expect(screen.getByLabelText("Puerto remoto")).toHaveValue("2200");
  expect(screen.getByLabelText("Ruta remota")).toHaveValue("ios/c4.bin"); // SCP sin / inicial: relativa al home
  expect(url()).toBe("scp://[2001:db8::2]:2200/ios/c4.bin");
});

test("enviar oculta HTTP y HTTPS, y vuelve a TFTP si estaba en uno de ellos", async () => {
  setup();
  await userEvent.click(proto("HTTPS"));
  await userEvent.click(screen.getByLabelText("Enviar (put)"));
  expect(screen.queryByRole("radio", { name: "HTTP" })).not.toBeInTheDocument();
  expect(screen.queryByRole("radio", { name: "HTTPS" })).not.toBeInTheDocument();
  expect(proto("TFTP")).toBeChecked();
  expect(proto("SFTP")).toBeInTheDocument();
});

test("los errores salen junto a cada campo y no se llama al núcleo", async () => {
  const core = setup();
  await userEvent.click(proto("SCP"));
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "192.0.2.1");
  await userEvent.clear(screen.getByLabelText("Puerto remoto"));
  await userEvent.type(screen.getByLabelText("Puerto remoto"), "70000");
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(screen.getByLabelText("Puerto remoto")).toHaveAccessibleDescription(/entre 1 y 65535/);
  expect(screen.getByLabelText("Ruta remota")).toHaveAccessibleDescription(/Escribe la ruta/);
  expect(screen.getByLabelText("Credencial de la bóveda")).toHaveAccessibleDescription(/Elige la credencial/);
  expect(screen.getByLabelText("Equipo remoto")).not.toHaveAttribute("aria-invalid");
  expect(core.transferGet).not.toHaveBeenCalled();
});

test("la descarga manda credencial, huellas, tiempo, tamaño, hash por largo y SSH antiguo", async () => {
  const core = setup();
  await userEvent.click(proto("SCP"));
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "192.0.2.1");
  await userEvent.type(screen.getByLabelText("Ruta remota"), "/c4.bin");
  await userEvent.selectOptions(await screen.findByRole("option", { name: /lab/ }).then(() => screen.getByLabelText("Credencial de la bóveda")), "c1");
  await userEvent.type(screen.getByLabelText(/Huellas SHA256 aceptadas/), "SHA256:abc");
  await userEvent.type(screen.getByLabelText("Tamaño máximo (MB, opcional)"), "2");
  await userEvent.type(screen.getByLabelText("Tiempo límite (minutos, opcional)"), "3");
  await userEvent.type(screen.getByLabelText("Nombre local (opcional)"), "x.bin");
  await userEvent.type(screen.getByLabelText("Hash esperado (opcional)"), "a".repeat(32));
  await userEvent.click(screen.getByLabelText(/Permitir algoritmos SSH antiguos/));
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(core.transferGet).toHaveBeenCalledWith({
    url: "scp://192.0.2.1//c4.bin", destDir: "", credentialId: "c1", acceptedHostKeys: ["SHA256:abc"], insecure: false, legacySsh: true,
    name: "x.bin", maxBytes: 2097152, seconds: 180, md5: "a".repeat(32),
  });
});

test("HTTPS sin verificar certificado avisa que queda auditado y se manda insecure", async () => {
  const core = setup();
  await userEvent.click(proto("HTTPS"));
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "srv.example");
  await userEvent.type(screen.getByLabelText("Ruta remota"), "/a.bin");
  expect(screen.queryByText(/registrada en la bitácora de auditoría/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByLabelText(/No verificar el certificado TLS/));
  expect(screen.getByText(/registrada en la bitácora de auditoría/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(core.transferGet).toHaveBeenCalledWith(expect.objectContaining({ url: "https://srv.example/a.bin", insecure: true }));
});

test("el envío por FTP sin credencial es anónimo y manda el tiempo límite", async () => {
  const core = setup({ pickPath: vi.fn(async () => "/home/u/r1.txt") });
  await userEvent.click(screen.getByLabelText("Enviar (put)"));
  await userEvent.click(proto("FTP"));
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "192.0.2.1");
  await userEvent.type(screen.getByLabelText("Ruta remota"), "/r1.txt");
  await userEvent.type(screen.getByLabelText("Tiempo límite (minutos, opcional)"), "2");
  await userEvent.click(screen.getByRole("button", { name: /Examinar.*Archivo de origen/ }));
  await userEvent.click(screen.getByRole("button", { name: "Enviar" }));
  expect(core.transferPut).toHaveBeenCalledWith({ url: "ftp://192.0.2.1/r1.txt", fromDir: "/home/u", name: "r1.txt", credentialId: "", acceptedHostKeys: [], legacySsh: false, seconds: 120 });
});

const adv = () => screen.getByText("Opciones avanzadas").closest("details")!;

test("un error dentro de Opciones avanzadas cerradas las abre, enfoca el campo y avisa con una alerta", async () => {
  const core = setup();
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "192.0.2.1");
  await userEvent.type(screen.getByLabelText("Ruta remota"), "/c4.bin");
  await userEvent.type(screen.getByLabelText("Hash esperado (opcional)"), "xyz"); // escrito con el panel cerrado
  expect(adv().open).toBe(false);
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(adv().open).toBe(true);
  expect(screen.getByLabelText("Hash esperado (opcional)")).toHaveFocus();
  expect(await screen.findByRole("alert")).toHaveTextContent("corrige los campos marcados");
  expect(core.transferGet).not.toHaveBeenCalled();
});

test("un error fuera de las avanzadas enfoca ese campo y deja el panel como estaba", async () => {
  setup();
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "192.0.2.1");
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(screen.getByLabelText("Ruta remota")).toHaveFocus();
  expect(adv().open).toBe(false);
});

test("la URL pegada se interpreta al pegar y al salir del campo, no en cada tecla", async () => {
  setup();
  const box = screen.getByLabelText("Pegar una URL");
  await userEvent.type(box, "sftp://192.0.2.9/a.bin");
  expect(screen.getByLabelText("Equipo remoto")).toHaveValue(""); // todavía no
  await userEvent.tab();
  expect(screen.getByLabelText("Equipo remoto")).toHaveValue("192.0.2.9");
  expect(proto("SFTP")).toBeChecked();
});

test("una URL pegada con contraseña se borra del campo y se avisa", async () => {
  setup();
  const box = screen.getByLabelText("Pegar una URL");
  await userEvent.click(box);
  await userEvent.paste("ftp://mac:pw@192.0.2.1/x");
  expect(box).toHaveValue("");
  expect(box).toHaveAccessibleDescription(/No pongas la contraseña en la URL/);
  expect(screen.getByLabelText("Equipo remoto")).toHaveValue("");
});

test("el equipo con puerto pegado y la ruta de envío incompleta dan error junto al campo", async () => {
  setup();
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "10.0.0.1:2222");
  await userEvent.click(screen.getByRole("button", { name: "Descargar" }));
  expect(screen.getByLabelText("Equipo remoto")).toHaveAccessibleDescription(/El puerto va en su campo/);
});

test("la ayuda de la ruta dice cómo se interpreta en SCP y SFTP", async () => {
  setup();
  expect(screen.getByLabelText("Ruta remota")).not.toHaveAccessibleDescription(/relativa al home/);
  await userEvent.click(proto("SFTP"));
  expect(screen.getByLabelText("Ruta remota")).toHaveAccessibleDescription(/Absoluta con \/ inicial; sin \/ es relativa al home/);
  await userEvent.type(screen.getByLabelText("Ruta remota"), "/tmp/x.bin");
  await userEvent.type(screen.getByLabelText("Equipo remoto"), "192.0.2.1");
  expect(url()).toBe("sftp://192.0.2.1//tmp/x.bin");
});
