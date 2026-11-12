import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SecurityView } from "./SecurityView";
import { fakeCore } from "../../lib/fake";
import type { RadiusReportData, TacacsReportData, PkiReportData } from "./api";

// Fase 30b: las tarjetas salen del informe estructurado; si el método nuevo falla, del texto de siempre.
async function fillRadius() {
  await userEvent.type(screen.getByLabelText("Servidor"), "10.0.0.20");
  await userEvent.type(screen.getByLabelText("Secreto compartido"), "s");
  await userEvent.type(screen.getByLabelText("Usuario de prueba"), "a");
  await userEvent.type(screen.getByLabelText("Contraseña de prueba"), "p");
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
}

const radius: RadiusReportData = {
  text: "texto cualquiera", server: "10.0.0.20:1812", method: "PAP",
  exchanges: [{ kind: "access-request", code: "Access-Accept", rttMs: 3, attempts: 1, messageAuthenticator: "invalid", attrs: [] }],
  findings: [{ code: "no_response", severity: "warning", message: "The server did not answer" }],
};

test("radius usa el informe estructurado: severidad y Message-Authenticator por código", async () => {
  const core = fakeCore({ secRadiusReport: vi.fn(async () => radius), secRadius: vi.fn(async () => "no debe llamarse") });
  render(<SecurityView core={core} />);
  await fillRadius();
  expect(await screen.findByText("The server did not answer")).toBeInTheDocument();
  expect(screen.getByText("Aviso")).toBeInTheDocument();
  expect(screen.getByText(/Message-Authenticator inválido/)).toBeInTheDocument();
  expect(core.secRadius).not.toHaveBeenCalled();
});

// Un error del informe se muestra y NO se repite con el método de texto: serían dos intentos de autenticación contra el servidor.
test("radius: si el informe falla se muestra el error y la prueba no se repite", async () => {
  const core = fakeCore({ secRadiusReport: vi.fn(async () => { throw new Error("rpc error: code = Unavailable desc = sin respuesta del servidor"); }),
    secRadius: vi.fn(async () => "no debe llamarse") });
  render(<SecurityView core={core} />);
  await fillRadius();
  expect(await screen.findByText(/sin respuesta del servidor/)).toBeInTheDocument();
  expect(core.secRadiusReport).toHaveBeenCalledTimes(1);
  expect(core.secRadius).not.toHaveBeenCalled();
});

test("radius cae al texto si el informe llega sin texto", async () => {
  const core = fakeCore({ secRadius: vi.fn(async () => "Servidor RADIUS 10.0.0.20:1812\n\naccess-request: Access-Accept en 3.0 ms (intento 1, Message-Authenticator válido)\n") });
  const report = vi.spyOn(core, "secRadiusReport");
  render(<SecurityView core={core} />);
  await fillRadius();
  expect((await screen.findAllByText(/Message-Authenticator válido/)).length).toBeGreaterThan(0);
  expect(report).toHaveBeenCalled();
});

test("tacacs usa el informe estructurado", async () => {
  const rep: TacacsReportData = { text: "t", server: "h:49", steps: [{ kind: "authentication", status: "PASS", rttMs: 5, prompts: [], avPairs: [{ direction: "sent", value: "service=shell" }] }], findings: [] };
  const core = fakeCore({ secTacacsReport: vi.fn(async () => rep), secTacacs: vi.fn(async () => "no debe llamarse") });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "TACACS+" }));
  await userEvent.type(screen.getByLabelText("Servidor"), "h");
  await userEvent.type(screen.getByLabelText("Secreto compartido"), "s");
  await userEvent.type(screen.getByLabelText("Usuario de prueba"), "a");
  await userEvent.type(screen.getByLabelText("Contraseña de prueba"), "p");
  await userEvent.click(screen.getByRole("button", { name: "Probar" }));
  expect(await screen.findByText("service=shell")).toBeInTheDocument();
  expect(core.secTacacs).not.toHaveBeenCalled();
});

test("decodificar certificado usa el informe estructurado y muestra autofirmado y usos", async () => {
  const rep: PkiReportData = { text: "t", certificates: [{ kind: "certificate", subject: "CN=lab", key: { algorithm: "RSA", bits: 2048, description: "RSA 2048" }, signature: { algorithm: "SHA256-RSA" },
    san: [], keyUsage: ["digitalSignature"], extKeyUsage: ["serverAuth"], isCa: false, selfSigned: true, warnings: [] }] };
  const core = fakeCore({ secPkiDecodeReport: vi.fn(async () => rep), secPkiDecode: vi.fn(async () => "no debe llamarse") });
  render(<SecurityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "PKI" }));
  await userEvent.type(screen.getByLabelText("Certificado o CSR a decodificar"), "PEM");
  await userEvent.click(screen.getByRole("button", { name: "Decodificar certificado" }));
  expect(await screen.findByText("Autofirmado")).toBeInTheDocument();
  expect(screen.getByText("digitalSignature, serverAuth")).toBeInTheDocument();
  expect(core.secPkiDecode).not.toHaveBeenCalled();
});
