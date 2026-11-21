import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CalcView } from "./CalcView";
import { fakeCore } from "../../lib/fake";

const result = { text: "", tables: [], notes: [] };
const det = (el: HTMLElement) => el.closest("details")!;

test("BGP: los atributos extra de cada ruta van plegados, cuentan cambios y se siguen enviando", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Enrutamiento" }));
  const igp = screen.getAllByLabelText("Métrica IGP al next-hop")[0]!;
  const d = det(igp);
  expect(d.open).toBe(false);
  expect(d.querySelector("summary")).toHaveTextContent("Más atributos");
  for (const l of ["Router-ID", "Originator-ID", "Dirección del vecino", "Edad (s)", "Longitud de CLUSTER_LIST", "Next-hop inaccesible"]) expect(d).toContainElement(screen.getAllByLabelText(l)[0]!);
  for (const l of ["Originada localmente", "eBGP"]) {
    expect(screen.getAllByLabelText(l)[0]).toBeVisible();
    expect(d).not.toContainElement(screen.getAllByLabelText(l)[0]!);
  }
  for (const l of ["Weight (vacío = 0; 32768 si es local)", "Local-pref", "MED", "Origin", "AS_PATH"]) expect(d).not.toContainElement(screen.getAllByLabelText(l)[0]!);
  await userEvent.type(igp, "20");
  await userEvent.click(screen.getAllByLabelText("eBGP")[0]!);
  await userEvent.click(screen.getAllByLabelText("Originada localmente")[0]!);
  expect(d.querySelector("summary")).toHaveTextContent("Más atributos · cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Elegir mejor ruta" }));
  expect(core.calc).toHaveBeenCalledWith("bgp", expect.objectContaining({ routes: [expect.objectContaining({ igpMetric: 20, ebgp: true, locallyOriginated: true }), expect.anything()] }));
});

test("BGP: las opciones de selección globales van plegadas y siguen viajando", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Enrutamiento" }));
  const mp = screen.getByLabelText(/^maximum-paths/);
  const d = det(mp);
  expect(d.open).toBe(false);
  expect(d.querySelector("summary")).toHaveTextContent("Opciones de selección");
  expect(d).toContainElement(screen.getByLabelText(/^bgp always-compare-med/));
  expect(d).not.toContainElement(screen.getByRole("button", { name: "Elegir mejor ruta" }));
  await userEvent.type(mp, "4");
  await userEvent.click(screen.getByLabelText(/^bgp deterministic-med/));
  expect(d.querySelector("summary")).toHaveTextContent("cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Elegir mejor ruta" }));
  expect(core.calc).toHaveBeenCalledWith("bgp", expect.objectContaining({ maximumPaths: 4, deterministicMed: true }));
});

test("óptica: pérdidas y margen van plegados; Tx, Rx, distancia y fibra quedan fuera (y la saturación Rx junto al transceptor)", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Capa física" }));
  const margin = screen.getByLabelText(/^Margen exigido/);
  const d = det(margin);
  expect(d.open).toBe(false);
  for (const l of [/^Pérdida por km/, /^Conectores/, /^Pérdida por conector/, /^Empalmes/, /^Pérdida por empalme/]) expect(d).toContainElement(screen.getByLabelText(l));
  for (const l of [/^Tx mínima/, /^Sensibilidad Rx/, /^Saturación Rx/, /^Distancia/, "Fibra"]) expect(d).not.toContainElement(screen.getByLabelText(l));
  await userEvent.type(screen.getByLabelText(/^Tx mínima/), "-3");
  await userEvent.type(screen.getByLabelText(/^Sensibilidad Rx/), "-14");
  await userEvent.type(screen.getByLabelText(/^Distancia/), "10");
  await userEvent.clear(margin); await userEvent.type(margin, "5");
  await userEvent.type(screen.getByLabelText(/^Empalmes/), "1");
  expect(d.querySelector("summary")).toHaveTextContent("cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Calcular presupuesto" }));
  expect(core.calc).toHaveBeenCalledWith("optics", expect.objectContaining({ marginDb: 5, splices: 1 }));
});

test("TCP: ventana, pérdida y MSS van plegados y se envían", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Transporte y QoS" }));
  await userEvent.click(screen.getByRole("tab", { name: "TCP" }));
  const mss = screen.getByLabelText(/^MSS/);
  const d = det(mss);
  expect(d.open).toBe(false);
  expect(d).toContainElement(screen.getByLabelText(/^Ventana en bytes/));
  expect(d).toContainElement(screen.getByLabelText(/^Pérdida/));
  expect(d).not.toContainElement(screen.getByLabelText(/^Ancho de banda/));
  await userEvent.type(screen.getByLabelText(/^Ancho de banda/), "1g");
  await userEvent.type(screen.getByLabelText("RTT (ms)"), "20");
  await userEvent.type(mss, "1400");
  await userEvent.type(screen.getByLabelText(/^Ventana en bytes/), "64k");
  expect(d.querySelector("summary")).toHaveTextContent("cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Calcular rendimiento" }));
  expect(core.calc).toHaveBeenCalledWith("tcp", expect.objectContaining({ mss: 1400, window: "64k" }));
});

test("DSCP: «Campo» va plegado y se envía", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Transporte y QoS" }));
  await userEvent.click(screen.getByRole("tab", { name: "DSCP" }));
  const f = screen.getByLabelText("Campo");
  const d = det(f);
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText(/^Buscar/));
  await userEvent.selectOptions(f, "cos");
  expect(d.querySelector("summary")).toHaveTextContent("cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: "Buscar" }));
  expect(core.calc).toHaveBeenCalledWith("dscp", { query: "", field: "cos" });
});
