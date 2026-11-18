import { shown } from "../../test-utils";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SecurityView } from "./SecurityView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";

const creds = [{ id: "c1", label: "ise-secreto", username: "-", hasEnable: false, hasSshKey: false }];

test("radius con secreto escrito y usuario de prueba", async () => {
  const core = fakeCore({ secRadius: vi.fn(async () => "Access-Accept en 3.1 ms") });
  render(<SecurityView core={core} />);
  await userEvent.type(screen.getByRole("textbox", { name: "Servidor" }), "10.0.0.20");
  await userEvent.type(shown("Secreto compartido"), "s3cr3t");
  await userEvent.type(shown("Usuario de prueba"), "alice");
  await userEvent.type(shown("Contraseña de prueba"), "pw");
  await userEvent.selectOptions(screen.getByLabelText("Método"), "mschapv2");
  await userEvent.click(screen.getByLabelText(/Accounting/));
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
  expect(await screen.findByText((_, el) => el?.tagName === "PRE" && /Access-Accept/.test(el.textContent ?? ""))).toBeInTheDocument(); // la terminal reparte la línea en spans
  expect(core.secRadius).toHaveBeenCalledWith(expect.objectContaining({ host: "10.0.0.20", authPort: 1812, secret: "s3cr3t", secretCredId: "", username: "alice",
    password: "pw", method: "mschapv2", accounting: true, statusServer: false }));
  expect(shown("Secreto compartido")).toHaveAttribute("type", "password");
});

test("radius toma el secreto de la bóveda", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds) });
  render(<SecurityView core={core} />);
  await waitFor(() => expect(screen.getAllByRole("option", { name: /ise-secreto/ }).length).toBeGreaterThan(0));
  await userEvent.selectOptions(screen.getByLabelText("Secreto desde"), "c1");
  expect(screen.queryByLabelText("Secreto compartido")).not.toBeInTheDocument();
  await userEvent.type(screen.getByRole("textbox", { name: "Servidor" }), "ise01");
  await userEvent.click(screen.getByLabelText(/Solo Status-Server/));
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
  await waitFor(() => expect(core.secRadius).toHaveBeenCalledWith(expect.objectContaining({ secretCredId: "c1", secret: "", statusServer: true })));
});

test("tacacs autoriza show running-config por defecto", async () => {
  const core = fakeCore({ secTacacs: vi.fn(async () => "PASS_ADD") });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "TACACS+" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Servidor" }), "10.0.0.21");
  await userEvent.type(shown("Secreto compartido"), "tk");
  await userEvent.type(shown("Usuario de prueba"), "admin");
  await userEvent.type(shown("Contraseña de prueba"), "pw");
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
  expect(await screen.findByText("PASS_ADD")).toBeInTheDocument();
  expect(core.secTacacs).toHaveBeenCalledWith(expect.objectContaining({ host: "10.0.0.21", port: 49, command: "show running-config", authenType: "ascii" }));
});

test("csr con SAN y llave nueva sellada", async () => {
  const core = fakeCore({ secPkiCsr: vi.fn(async () => ({ pem: "-----BEGIN CERTIFICATE REQUEST-----", key: "-----BEGIN MACUAHUITL SEALED PRIVATE KEY-----", text: "CSR: CN=ise01" })) });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  await userEvent.type(screen.getByLabelText("CN"), "ise01.lab");
  await userEvent.type(screen.getByLabelText(/SAN DNS/), "ise01.lab, ise01");
  await userEvent.type(screen.getByLabelText(/SAN IP/), "10.0.0.10");
  await userEvent.type(screen.getByLabelText("Contraseña de la llave"), "kpw");
  await userEvent.click(screen.getByRole("button", { name: "Generar CSR" }));
  expect(await screen.findByDisplayValue(/BEGIN CERTIFICATE REQUEST/)).toBeInTheDocument();
  expect(screen.getByDisplayValue(/SEALED PRIVATE KEY/)).toBeInTheDocument();
  expect(core.secPkiCsr).toHaveBeenCalledWith(expect.objectContaining({ cn: "ise01.lab", dns: ["ise01.lab", "ise01"], ips: ["10.0.0.10"], algorithm: "p256", keyPassword: "kpw", sealedKey: "" }));
});

test("la CA de laboratorio avisa y firma con lo que acaba de crear", async () => {
  const core = fakeCore({
    secPkiCaInit: vi.fn(async () => ({ pem: "CA-PEM", key: "CA-KEY", text: "CA SOLO DE LABORATORIO" })),
    secPkiCaSign: vi.fn(async () => ({ pem: "CERT-PEM", key: "", text: "serverAuth" })),
  });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  expect(screen.getByText(/solo de laboratorio/i)).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Nombre de la CA"), "Lab CA");
  await userEvent.type(screen.getByLabelText("Contraseña de la llave de la CA"), "capw");
  await userEvent.click(screen.getByRole("button", { name: "Crear CA" }));
  await screen.findByDisplayValue("CA-PEM");
  await userEvent.type(screen.getByLabelText("CSR a firmar"), "CSR");
  await userEvent.click(screen.getByRole("button", { name: "Firmar" }));
  expect(await screen.findByDisplayValue("CERT-PEM")).toBeInTheDocument();
  expect(core.secPkiCaSign).toHaveBeenCalledWith("CA-PEM", "CA-KEY", "capw", "CSR", "server", 365);
});

test("exportar exige ruta y decodificar muestra el resumen", async () => {
  const core = fakeCore({ secPkiExport: vi.fn(async () => "/home/x/ise.p12"), secPkiDecode: vi.fn(async () => "SHA-256 ABC") });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  expect(screen.getByRole("button", { name: "Exportar" })).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Certificado (PEM)"), "C");
  await userEvent.type(screen.getByLabelText(/Ruta de salida/), "/home/x/ise.p12");
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  expect(await screen.findByText(/ise.p12/)).toBeInTheDocument();
  expect(core.secPkiExport).toHaveBeenCalledWith(expect.objectContaining({ format: "p12", cert: "C", path: "/home/x/ise.p12", plainKey: false }));
  await userEvent.type(screen.getByLabelText("Certificado o CSR a decodificar"), "PEM");
  await userEvent.click(screen.getByRole("button", { name: "Decodificar certificado" }));
  expect(await screen.findByText(/SHA-256 ABC/)).toBeInTheDocument();
});

test("ike decodifica lo pegado", async () => {
  const core = fakeCore({ secIkeDecode: vi.fn(async () => "Fase 1: falló") });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "IKE/IPsec" }));
  await userEvent.type(screen.getByLabelText(/Salida de debug/), "ISAKMP");
  await userEvent.click(screen.getByRole("button", { name: "Decodificar" }));
  expect(await screen.findByText("Fase 1: falló")).toBeInTheDocument();
  expect(core.secIkeDecode).toHaveBeenCalledWith("ISAKMP");
});

const radiusText = `Servidor RADIUS 10.0.0.20:1812 (método PAP)

access-request: Access-Reject en 3.1 ms (intento 2, Message-Authenticator válido)
  Reply-Message              Usuario desconocido

status-server: Access-Accept en 1.2 ms (intento 1, Message-Authenticator válido)

Hallazgos:
  [aviso] access-request: la respuesta no trae Message-Authenticator
`;

async function fillRadius(core: ReturnType<typeof fakeCore>) {
  render(<SecurityView core={core} />);
  await userEvent.type(screen.getByRole("textbox", { name: "Servidor" }), "10.0.0.20");
  await userEvent.type(shown("Secreto compartido"), "s3cr3t");
  await userEvent.type(shown("Usuario de prueba"), "alice");
  await userEvent.type(shown("Contraseña de prueba"), "pw");
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
}

test("radius: cada intercambio es una tarjeta con Accept o Reject en texto, latencia y atributos", async () => {
  await fillRadius(fakeCore({ secRadius: vi.fn(async () => radiusText) }));
  const req = await screen.findByRole("region", { name: "Access-Request" });
  expect(within(req).getByText("Access-Reject")).toBeInTheDocument();
  expect(within(req).getByText("3 ms")).toBeInTheDocument();
  expect(within(within(req).getByRole("table", { name: "Atributos de Access-Request" })).getByRole("cell", { name: "Usuario desconocido" })).toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "Status-Server" })).getByText("Access-Accept")).toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "Hallazgos" })).getByText(/no trae Message-Authenticator/)).toBeInTheDocument();
});

test("tacacs: un paso por tarjeta con su estado, latencia y pares enviados y recibidos", async () => {
  const text = `Servidor TACACS+ 10.0.0.21:49

authentication: PASS en 12.4 ms

authorization: FAIL en 8.0 ms
  enviado  cmd=show running-config
  recibido priv-lvl=1
`;
  const core = fakeCore({ secTacacs: vi.fn(async () => text) });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "TACACS+" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Servidor" }), "10.0.0.21");
  await userEvent.type(shown("Secreto compartido"), "tk");
  await userEvent.type(shown("Usuario de prueba"), "admin");
  await userEvent.type(shown("Contraseña de prueba"), "pw");
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
  const authz = await screen.findByRole("region", { name: "Autorización" });
  expect(within(authz).getByText("FAIL")).toBeInTheDocument();
  expect(within(authz).getByText("8 ms")).toBeInTheDocument();
  const t = within(authz).getByRole("table", { name: "Atributos de Autorización" });
  expect(within(t).getByRole("cell", { name: "cmd=show running-config" })).toBeInTheDocument();
  expect(within(t).getByRole("cell", { name: "priv-lvl=1" })).toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "Autenticación" })).getByText("PASS")).toBeInTheDocument();
});

const pkiText = `certificado: CN=ise01.lab,O=Lab
  Emisor           CN=Lab CA
  Validez          2026-01-01T00:00:00Z → 2027-01-01T00:00:00Z (20 días)
  Llave            ECDSA P-256
  SHA-256          CC:DD:EE

certificado: CN=Lab CA
  Emisor           CN=Lab CA
  Validez          2020-01-01T00:00:00Z → 2026-10-01T00:00:00Z (-36 días)
  CA               sí
  SHA-256          11:22:33
`;

test("pki: la cadena es una lista con cuenta regresiva (aviso a 30 días, vencido) y huellas copiables", async () => {
  const core = fakeCore({ secPkiDecode: vi.fn(async () => pkiText) });
  render(<CoreContext.Provider value={core}><SecurityView core={core} /></CoreContext.Provider>);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  await userEvent.type(screen.getByLabelText("Certificado o CSR a decodificar"), "PEM");
  await userEvent.click(screen.getByRole("button", { name: "Decodificar certificado" }));
  const chain = await screen.findByRole("list", { name: "Cadena de certificados" });
  const [leaf, ca] = within(chain).getAllByRole("listitem");
  expect(leaf).toHaveTextContent("CN=ise01.lab,O=Lab");
  expect(within(leaf).getByText("Vence en 20 días")).toBeInTheDocument();
  expect(within(leaf).getByRole("meter", { name: "Vigencia consumida" })).toBeInTheDocument();
  expect(within(ca).getByText("Vencido hace 36 días")).toBeInTheDocument();
  await userEvent.click(within(leaf).getByRole("button", { name: "Copiar huella SHA-256" }));
  expect(core.copyText).toHaveBeenCalledWith("CC:DD:EE");
});

// Auditoría 21h: los secretos escritos se borran de la pantalla una vez enviados.
test("radius vacía el secreto y la contraseña de prueba al probar", async () => {
  const core = fakeCore({ secRadius: vi.fn(async () => "Access-Accept") });
  render(<SecurityView core={core} />);
  await userEvent.type(screen.getByRole("textbox", { name: "Servidor" }), "10.0.0.20");
  await userEvent.type(shown("Secreto compartido"), "s3cr3t");
  await userEvent.type(shown("Usuario de prueba"), "alice");
  await userEvent.type(shown("Contraseña de prueba"), "pw");
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
  await waitFor(() => expect(core.secRadius).toHaveBeenCalledWith(expect.objectContaining({ secret: "s3cr3t", password: "pw" })));
  expect(shown("Secreto compartido")).toHaveValue("");
  expect(shown("Contraseña de prueba")).toHaveValue("");
});

test("pki: la contraseña de la llave y las del export se vacían tras enviarse", async () => {
  const core = fakeCore({
    secPkiCsr: vi.fn(async () => ({ pem: "P", key: "K", text: "t" })),
    secPkiExport: vi.fn(async () => "/home/x/a.p12"),
  });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  await userEvent.type(screen.getByLabelText("CN"), "ise01.lab");
  await userEvent.type(screen.getByLabelText("Contraseña de la llave"), "kpw");
  await userEvent.click(screen.getByRole("button", { name: "Generar CSR" }));
  await waitFor(() => expect(core.secPkiCsr).toHaveBeenCalled());
  expect(screen.getByLabelText("Contraseña de la llave")).toHaveValue("");
  await userEvent.type(screen.getByLabelText("Certificado (PEM)"), "C");
  await userEvent.type(screen.getByLabelText(/Ruta de salida/), "/home/x/a.p12");
  await userEvent.type(screen.getByLabelText("Contraseña del PKCS#12"), "epw");
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await waitFor(() => expect(core.secPkiExport).toHaveBeenCalledWith(expect.objectContaining({ exportPassword: "epw" })));
  expect(screen.getByLabelText("Contraseña del PKCS#12")).toHaveValue("");
});

test("radius con Status-Server no manda lo que la UI oculta", async () => {
  const core = fakeCore({ secRadius: vi.fn(async () => "ok") });
  render(<SecurityView core={core} />);
  await userEvent.type(screen.getByRole("textbox", { name: "Servidor" }), "ise01");
  await userEvent.type(shown("Secreto compartido"), "s3");
  await userEvent.type(shown("Usuario de prueba"), "alice");
  await userEvent.type(shown("Contraseña de prueba"), "pw");
  await userEvent.selectOptions(screen.getByLabelText("Método"), "chap");
  await userEvent.type(screen.getByLabelText("NAS-IP-Address"), "1.1.1.1");
  await userEvent.click(screen.getByLabelText(/Accounting/));
  await userEvent.click(screen.getByLabelText(/Solo Status-Server/));
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
  await waitFor(() => expect(core.secRadius).toHaveBeenCalled());
  expect(core.secRadius).toHaveBeenCalledWith(expect.objectContaining({ secret: "s3", statusServer: true, method: "", nasIp: "", nasId: "", portType: "", serviceType: "", called: "", calling: "",
    accounting: false, acctPort: 0, credId: "", username: "", password: "" }));
});

test("radius sin accounting no manda el puerto de accounting", async () => {
  const core = fakeCore({ secRadius: vi.fn(async () => "ok") });
  render(<SecurityView core={core} />);
  await userEvent.type(screen.getByRole("textbox", { name: "Servidor" }), "ise01");
  await userEvent.type(shown("Secreto compartido"), "s3");
  await userEvent.type(shown("Usuario de prueba"), "alice");
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
  await waitFor(() => expect(core.secRadius).toHaveBeenCalledWith(expect.objectContaining({ acctPort: 0, method: "pap", accounting: false })));
});

test("exportar DER manda solo el certificado", async () => {
  const core = fakeCore({ secPkiExport: vi.fn(async () => "/x") });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  await userEvent.type(screen.getByLabelText("Certificado (PEM)"), "C");
  await userEvent.type(screen.getByLabelText("Cadena (PEM, opcional)"), "CHAIN");
  await userEvent.type(screen.getByLabelText("Llave sellada a exportar"), "SEALED");
  await userEvent.type(screen.getByLabelText("Contraseña de la llave a exportar"), "kp");
  await userEvent.type(screen.getByLabelText("Contraseña del PKCS#12"), "ep");
  await userEvent.type(screen.getByLabelText(/Ruta de salida/), "/x");
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "der");
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await waitFor(() => expect(core.secPkiExport).toHaveBeenCalledWith({ format: "der", cert: "C", chain: "", sealedKey: "", keyPassword: "", exportPassword: "", plainKey: false, path: "/x" }));
});

test("exportar PEM con llave en claro manda llave y contraseña de llave, sin contraseña de p12", async () => {
  const core = fakeCore({ secPkiExport: vi.fn(async () => "/x") });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  await userEvent.type(screen.getByLabelText("Certificado (PEM)"), "C");
  await userEvent.type(screen.getByLabelText("Contraseña del PKCS#12"), "ep");
  await userEvent.type(screen.getByLabelText(/Ruta de salida/), "/x");
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "pem");
  await userEvent.click(screen.getByLabelText(/SIN cifrar/));
  await userEvent.type(screen.getByLabelText("Llave sellada a exportar"), "SEALED");
  await userEvent.type(screen.getByLabelText("Contraseña de la llave a exportar"), "kp");
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await waitFor(() => expect(core.secPkiExport).toHaveBeenCalledWith({ format: "pem", cert: "C", chain: "", sealedKey: "SEALED", keyPassword: "kp", exportPassword: "", plainKey: true, path: "/x" }));
});

test("exportar PEM sin llave en claro no manda llave ni plainKey de otro formato", async () => {
  const core = fakeCore({ secPkiExport: vi.fn(async () => "/x") });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  await userEvent.type(screen.getByLabelText("Certificado (PEM)"), "C");
  await userEvent.type(screen.getByLabelText("Llave sellada a exportar"), "SEALED");
  await userEvent.type(screen.getByLabelText("Contraseña de la llave a exportar"), "kp");
  await userEvent.type(screen.getByLabelText(/Ruta de salida/), "/x");
  await userEvent.selectOptions(screen.getByLabelText("Formato"), "pem");
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await waitFor(() => expect(core.secPkiExport).toHaveBeenCalledWith(expect.objectContaining({ format: "pem", sealedKey: "", keyPassword: "", plainKey: false })));
});

test("csr con llave sellada no manda el algoritmo oculto", async () => {
  const core = fakeCore({ secPkiCsr: vi.fn(async () => ({ pem: "P", key: "K", text: "t" })) });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  await userEvent.type(screen.getByLabelText("CN"), "ise01.lab");
  await userEvent.type(screen.getByLabelText(/Llave sellada existente/), "SEALED");
  await userEvent.type(screen.getByLabelText("Contraseña de la llave"), "kpw");
  await userEvent.click(screen.getByRole("button", { name: "Generar CSR" }));
  await waitFor(() => expect(core.secPkiCsr).toHaveBeenCalledWith(expect.objectContaining({ sealedKey: "SEALED", algorithm: "" })));
});

test("las subpestañas conservan lo escrito al cambiar y volver", async () => {
  render(<SecurityView core={fakeCore()} />);
  await userEvent.type(screen.getByRole("textbox", { name: "Servidor" }), "10.0.0.20");
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  await userEvent.click(screen.getByRole("tab", { name: "RADIUS" }));
  expect(screen.getByRole("textbox", { name: "Servidor" })).toHaveValue("10.0.0.20");
});

const summaryOf = (el: HTMLElement) => el.closest("details")!.querySelector("summary")!;

test("radius: atributos y accounting van plegados, cuentan los cambios y Status-Server los oculta", async () => {
  render(<SecurityView core={fakeCore()} />);
  const det = screen.getByLabelText("Método").closest("details")!;
  expect(det.open).toBe(false);
  for (const l of ["Método", "NAS-Port-Type", "Service-Type", "NAS-IP-Address", "NAS-Identifier", "Called-Station-Id", /Calling-Station-Id/, /Accounting/]) expect(det).toContainElement(screen.getByLabelText(l));
  expect(summaryOf(screen.getByLabelText("Método"))).toHaveTextContent(/^Atributos RADIUS$/);
  await userEvent.selectOptions(screen.getByLabelText("Método"), "chap");
  await userEvent.type(screen.getByLabelText("NAS-IP-Address"), "1.1.1.1");
  expect(summaryOf(screen.getByLabelText("Método"))).toHaveTextContent("Atributos RADIUS · cambiadas: 2");
  await userEvent.click(screen.getByLabelText(/Solo Status-Server/));
  expect(screen.queryByLabelText("Método")).not.toBeInTheDocument();
});

test("tacacs: autenticación, comando y accounting van plegados y cuentan los cambios", async () => {
  render(<SecurityView core={fakeCore()} />);
  await userEvent.click(screen.getByRole("tab", { name: "TACACS+" }));
  const det = screen.getByLabelText("Autenticación").closest("details")!;
  expect(det.open).toBe(false);
  for (const l of ["Autenticación", /Comando a autorizar/, /Accounting/]) expect(det).toContainElement(screen.getByLabelText(l));
  expect(det).not.toContainElement(screen.getByLabelText("Servidor"));
  await userEvent.click(screen.getByLabelText(/Accounting/)); // por omisión está activo
  expect(det.querySelector("summary")).toHaveTextContent("Autorización y accounting · cambiadas: 1");
});

test("csr: los datos del sujeto van plegados y cuentan los llenos; CN, SAN y contraseña quedan a la vista", async () => {
  render(<SecurityView core={fakeCore()} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  const det = screen.getByLabelText("OU").closest("details")!;
  expect(det.open).toBe(false);
  for (const l of ["O", "OU", "L", "ST", /^C \(/]) expect(det).toContainElement(screen.getByLabelText(l));
  for (const l of ["CN", /SAN DNS/, /SAN IP/, "Contraseña de la llave"]) expect(det).not.toContainElement(screen.getByLabelText(l));
  expect(det.querySelector("summary")).toHaveTextContent(/^Datos del sujeto$/);
  await userEvent.type(screen.getByLabelText("O"), "Lab");
  await userEvent.type(screen.getByLabelText("ST"), "CDMX");
  expect(det.querySelector("summary")).toHaveTextContent("Datos del sujeto · cambiadas: 2");
});
