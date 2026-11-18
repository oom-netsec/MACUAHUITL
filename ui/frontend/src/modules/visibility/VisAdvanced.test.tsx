import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { VisibilityView } from "./VisibilityView";
import { fakeCore } from "../../lib/fake";

const det = (l: string | RegExp) => screen.getByLabelText(l).closest("details")!;
const sum = (d: HTMLElement) => d.querySelector("summary")!;
const tab = (n: string) => userEvent.click(screen.getByRole("tab", { name: n }));

test("snmp: el puerto va plegado, cuenta y se sigue enviando; equipo queda fuera", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => [{ id: "c1", label: "snmp-lab", username: "snmp", hasEnable: false, hasSshKey: false }]), snmpGet: vi.fn(async () => "ok") });
  render(<VisibilityView core={core} />);
  await tab("SNMP");
  const d = det("Puerto");
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText("Equipo"));
  await userEvent.type(screen.getByLabelText("Equipo"), "10.0.0.1");
  await userEvent.clear(screen.getByLabelText("Puerto"));
  await userEvent.type(screen.getByLabelText("Puerto"), "1161");
  expect(sum(d)).toHaveTextContent("cambiadas: 1");
  await screen.findByRole("option", { name: "snmp-lab (snmp)" });
  await userEvent.selectOptions(screen.getByLabelText(/Credencial/), "c1");
  await userEvent.type(screen.getByLabelText(/OID/), "1.3.6");
  await userEvent.click(screen.getByRole("button", { name: "Get" }));
  expect(core.snmpGet).toHaveBeenCalledWith(expect.objectContaining({ port: 1161 }), expect.anything());
});

test("gnmi: puerto y CA propia van plegados, cuentan y se siguen enviando", async () => {
  const core = fakeCore({ gnmiGet: vi.fn(async () => "[]") });
  render(<VisibilityView core={core} />);
  await tab("gNMI");
  const d = det("Puerto");
  expect(d.open).toBe(false);
  expect(d).toContainElement(screen.getByLabelText(/^CA propia en PEM/));
  expect(d).not.toContainElement(screen.getByLabelText("Equipo"));
  await userEvent.type(screen.getByLabelText("Equipo"), "10.0.0.9");
  await userEvent.type(screen.getByLabelText(/^CA propia en PEM/), "/etc/ca.pem");
  await userEvent.clear(screen.getByLabelText("Puerto"));
  await userEvent.type(screen.getByLabelText("Puerto"), "50051");
  expect(sum(d)).toHaveTextContent("cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Get" }));
  expect(core.gnmiGet).toHaveBeenCalledWith(expect.objectContaining({ port: 50051, caPath: "/etc/ca.pem" }), expect.anything(), "");
});

test("flujos: «Elementos por tabla» va plegado y cuenta; la dirección queda fuera", async () => {
  const core = fakeCore({ flowsStart: vi.fn(async () => "f1") });
  render(<VisibilityView core={core} />);
  await tab("Flujos");
  const d = det(/^Elementos por tabla/);
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText(/^Dirección de escucha/));
  await userEvent.clear(screen.getByLabelText(/^Elementos por tabla/));
  await userEvent.type(screen.getByLabelText(/^Elementos por tabla/), "25");
  expect(sum(d)).toHaveTextContent("cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
  expect(core.flowsStart).toHaveBeenCalledWith("127.0.0.1:2055", false, false, 25, expect.anything());
});

test("topología: la captura CDP/LLDP va plegada y se sigue enviando; la carpeta queda fuera", async () => {
  const core = fakeCore({ topoBuild: vi.fn(async () => ({ svg: "<svg/>", json: "{}", text: "" })) });
  render(<VisibilityView core={core} />);
  const d = det(/^Captura con CDP\/LLDP/);
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText(/^Trabajo o carpeta/));
  await userEvent.type(screen.getByLabelText(/^Trabajo o carpeta/), "/o");
  await userEvent.type(screen.getByLabelText(/^Captura con CDP\/LLDP/), "/c.pcap");
  expect(sum(d)).toHaveTextContent("cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: /^Construir/ }));
  expect(core.topoBuild).toHaveBeenCalledWith("/o", "/c.pcap");
});
