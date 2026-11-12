import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DnsPanel, TlsPanel } from "./ToolsView";
import { fakeCore } from "../../lib/fake";
import { dnsTraceSample, tlsSample } from "./samples";

test("la traza DNS se muestra como árbol por niveles y deja el JSON en la terminal", async () => {
  const core = fakeCore({ toolsDns: vi.fn(async () => dnsTraceSample) });
  render(<DnsPanel core={core} />);
  await userEvent.selectOptions(screen.getByLabelText("Modo"), "trace");
  await userEvent.type(screen.getByLabelText("Nombre"), "www.example.com");
  await userEvent.click(screen.getByLabelText(/Modo profundo/));
  await userEvent.click(screen.getByRole("button", { name: "Consultar" }));
  const tree = await screen.findByRole("list", { name: "Traza desde la raíz" });
  const steps = within(tree).getAllByRole("listitem");
  expect(steps).toHaveLength(3);
  expect(steps[0]).toHaveTextContent("Raíz");
  expect(steps[0]).toHaveTextContent("a.root-servers.net.");
  expect(steps[0]).toHaveTextContent("18 ms");
  expect(steps[0]).toHaveTextContent("Delega a com.");
  expect(within(steps[0]).getByRole("button", { name: "Copiar 198.41.0.4" })).toBeInTheDocument();
  expect(steps[1]).toHaveTextContent("TLD");
  expect(steps[2]).toHaveTextContent("Autoritativo");
  expect(steps[2]).toHaveTextContent("93.184.216.34");
  expect(screen.getByRole("log", { name: "Informe completo" })).toBeInTheDocument();
});

test("los otros modos DNS siguen en la terminal", async () => {
  const core = fakeCore({ toolsDns: vi.fn(async () => dnsTraceSample) });
  render(<DnsPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Nombre"), "example.com");
  await userEvent.click(screen.getByRole("button", { name: "Consultar" }));
  expect(await screen.findByRole("log", { name: "Salida" })).toBeInTheDocument();
  expect(screen.queryByRole("list", { name: "Traza desde la raíz" })).not.toBeInTheDocument();
});

test("la cadena TLS va del servidor a la raíz con días restantes en texto y huella copiable", async () => {
  const core = fakeCore({ toolsTls: vi.fn(async () => tlsSample) });
  render(<TlsPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Host"), "ise.lab");
  await userEvent.click(screen.getByRole("button", { name: "Inspeccionar" }));
  const chain = await screen.findByRole("list", { name: "Cadena de certificados" });
  const certs = within(chain).getAllByRole("listitem");
  expect(certs).toHaveLength(3);
  expect(certs[0]).toHaveTextContent("Servidor");
  expect(certs[0]).toHaveTextContent("CN=ise.lab");
  expect(certs[0]).toHaveTextContent("19 días");
  expect(certs[0]).toHaveTextContent("CN=Lab Issuing CA");
  expect(within(certs[0]).getByRole("button", { name: "Copiar Huella SHA-256" })).toBeInTheDocument();
  expect(certs[1]).toHaveTextContent("Intermedio");
  expect(certs[2]).toHaveTextContent("Raíz");
  expect(screen.getByText("Cadena verificada")).toBeInTheDocument();
  expect(screen.getByRole("log", { name: "Informe completo" })).toBeInTheDocument();
});

test("un certificado vencido lo dice con texto", async () => {
  const old = JSON.stringify({ Verified: false, VerifyError: "x509: certificate has expired", Chain: [{ Subject: "CN=a", Issuer: "CN=b", NotAfter: new Date(Date.now() - 5.5 * 864e5).toISOString() }] });
  const core = fakeCore({ toolsTls: vi.fn(async () => old) });
  render(<TlsPanel core={core} />);
  await userEvent.type(screen.getByLabelText("Host"), "a.lab");
  await userEvent.click(screen.getByRole("button", { name: "Inspeccionar" }));
  expect(await screen.findByText("Vencido hace 6 días")).toBeInTheDocument();
  expect(screen.getByText("Cadena no verificada")).toBeInTheDocument();
});
