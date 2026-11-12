import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CalcView } from "./CalcView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";

const result = {
  text: "",
  tables: [{ title: "Subred 10.0.0.0/31", head: ["Campo", "Valor"], rows: [["Hosts usables", "2"]] }],
  notes: ["/31 punto a punto (RFC 3021)"],
};

test("subred: envía el prefijo y muestra la tabla y las notas", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.type(screen.getByLabelText(/^Prefijo/), "10.0.0.1/31");
  await userEvent.click(screen.getByRole("button", { name: "Calcular" }));
  const table = await screen.findByRole("table", { name: "Subred 10.0.0.0/31" });
  expect(within(table).getByRole("columnheader", { name: "Valor" })).toBeInTheDocument();
  expect(within(table).getByRole("cell", { name: "2" })).toBeInTheDocument();
  expect(screen.getByText(/RFC 3021/)).toBeInTheDocument();
  expect(core.calc).toHaveBeenCalledWith("subnet", { prefix: "10.0.0.1/31" });
});

test("los errores del núcleo se leen sin el prefijo de gRPC", async () => {
  const core = fakeCore({ calc: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = longitud /33 fuera de rango"); }) });
  render(<CalcView core={core} />);
  await userEvent.type(screen.getByLabelText(/^Prefijo/), "10.0.0.0/33");
  await userEvent.click(screen.getByRole("button", { name: "Calcular" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/^longitud \/33 fuera de rango$/);
});

test("vlsm: convierte nombre=hosts en necesidades", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "VLSM" }));
  await userEvent.type(screen.getByLabelText("Red"), "10.0.0.0/24");
  await userEvent.type(screen.getByLabelText(/^Necesidades/), "ventas=50, 20");
  await userEvent.click(screen.getByRole("button", { name: "Repartir" }));
  await waitFor(() => expect(core.calc).toHaveBeenCalledWith("vlsm", { network: "10.0.0.0/24", needs: [{ name: "ventas", hosts: 50 }, { name: "", hosts: 20 }] }));
});

test("mtu: arma la pila de capas en orden y permite quitar", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "MTU/MSS" }));
  const add = screen.getByRole("button", { name: "Agregar capa" });
  await userEvent.selectOptions(screen.getByLabelText("Capa"), "nat-t");
  await userEvent.click(add);
  await userEvent.selectOptions(screen.getByLabelText("Capa"), "esp-tunnel");
  await userEvent.selectOptions(screen.getByLabelText("Cifrado"), "aes-cbc");
  await userEvent.selectOptions(screen.getByLabelText("Autenticación"), "sha256");
  await userEvent.click(add);
  await userEvent.selectOptions(screen.getByLabelText("Capa"), "mpls");
  await userEvent.clear(screen.getByLabelText("Etiquetas"));
  await userEvent.type(screen.getByLabelText("Etiquetas"), "3");
  await userEvent.click(add);
  await userEvent.click(screen.getByRole("button", { name: "Quitar nat-t" }));
  await userEvent.click(screen.getByLabelText(/IPv6/));
  await userEvent.click(screen.getByRole("button", { name: "Calcular MTU" }));
  await waitFor(() => expect(core.calc).toHaveBeenCalledWith("mtu", { physical: 1500, layers: ["esp-tunnel:aes-cbc:sha256", "mpls:3"], innerIpv6: true }));
});

test("bgp: manda solo los atributos escritos y las opciones", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "BGP" }));
  const a = screen.getByRole("group", { name: "Ruta 1" });
  await userEvent.type(within(a).getByLabelText("Local-pref"), "200");
  await userEvent.type(within(a).getByLabelText("AS_PATH"), "65001 65002");
  await userEvent.click(within(a).getByLabelText("eBGP"));
  await userEvent.click(screen.getByRole("button", { name: "Agregar ruta" }));
  const c = screen.getByRole("group", { name: "Ruta 3" });
  await userEvent.type(within(c).getByLabelText("MED"), "5");
  await userEvent.click(screen.getByLabelText(/deterministic-med/));
  await userEvent.click(screen.getByRole("button", { name: "Elegir mejor ruta" }));
  await waitFor(() => expect(core.calc).toHaveBeenCalled());
  const [kind, req] = (core.calc as ReturnType<typeof vi.fn>).mock.calls[0];
  expect(kind).toBe("bgp");
  expect(req.routes).toHaveLength(3);
  expect(req.routes[0]).toMatchObject({ name: "A", localPref: 200, asPath: "65001 65002", ebgp: true });
  expect(req.routes[0]).not.toHaveProperty("med");
  expect(req.routes[2]).toMatchObject({ name: "C", med: 5 });
  expect(req).toMatchObject({ deterministicMed: true, alwaysCompareMed: false });
});

test("óptica: presupuesto y conversión", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Óptica" }));
  await userEvent.type(screen.getByLabelText("Tx mínima (dBm)"), "-8.2");
  await userEvent.type(screen.getByLabelText("Sensibilidad Rx (dBm)"), "-14.4");
  await userEvent.type(screen.getByLabelText("Distancia (km)"), "10");
  await userEvent.click(screen.getByRole("button", { name: "Calcular presupuesto" }));
  await waitFor(() => expect(core.calc).toHaveBeenCalledWith("optics", expect.objectContaining({ txDbm: -8.2, rxSensitivityDbm: -14.4, km: 10, fiber: "smf-1310", connectors: 2, marginDb: 3 })));
  expect((core.calc as ReturnType<typeof vi.fn>).mock.calls[0][1]).not.toHaveProperty("rxOverloadDbm");
  await userEvent.type(screen.getByLabelText(/^Potencia/), "-3dBm");
  await userEvent.click(screen.getByRole("button", { name: "Convertir" }));
  await waitFor(() => expect(core.calc).toHaveBeenCalledWith("optics", { convert: "-3dBm" }));
});

test("dscp, tcp, wildcard, ipv6 y sumarización envían sus campos", async () => {
  const core = fakeCore({ calc: vi.fn(async () => result) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "DSCP" }));
  await userEvent.click(screen.getByRole("button", { name: "Buscar" }));
  await waitFor(() => expect(core.calc).toHaveBeenLastCalledWith("dscp", { query: "", field: "" }));
  await userEvent.click(screen.getByRole("tab", { name: "TCP" }));
  await userEvent.type(screen.getByLabelText(/^Ancho de banda/), "1g");
  await userEvent.type(screen.getByLabelText("RTT (ms)"), "50");
  await userEvent.click(screen.getByRole("button", { name: "Calcular rendimiento" }));
  await waitFor(() => expect(core.calc).toHaveBeenLastCalledWith("tcp", { bandwidth: "1g", rttMs: 50, window: "", lossPercent: 0, mss: 0 }));
  await userEvent.click(screen.getByRole("tab", { name: "Wildcard" }));
  await userEvent.type(screen.getByLabelText(/^Dirección de la ACL/), "10.0.0.0");
  await userEvent.type(screen.getByLabelText(/^Prefijo, máscara o wildcard/), "0.0.254.255");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  await waitFor(() => expect(core.calc).toHaveBeenLastCalledWith("wildcard", { address: "10.0.0.0", value: "0.0.254.255" }));
  await userEvent.click(screen.getByRole("tab", { name: "IPv6" }));
  await userEvent.type(screen.getByLabelText(/^MAC/), "0050.56ab.cdef");
  await userEvent.click(screen.getByRole("button", { name: "Calcular" }));
  await waitFor(() => expect(core.calc).toHaveBeenLastCalledWith("ipv6", { address: "", mac: "0050.56ab.cdef" }));
  await userEvent.click(screen.getByRole("tab", { name: "Sumarización" }));
  await userEvent.type(screen.getByLabelText(/^Prefijos/), "10.0.0.0/24, 10.0.1.0/24");
  await userEvent.click(screen.getByRole("button", { name: "Sumarizar" }));
  await waitFor(() => expect(core.calc).toHaveBeenLastCalledWith("summarize", { prefixes: ["10.0.0.0/24", "10.0.1.0/24"] }));
});

const subnet24 = {
  text: "", notes: [],
  tables: [{ title: "Subred 10.0.0.0/24", head: ["Campo", "Valor"], rows: [["Red", "10.0.0.0"], ["Broadcast", "10.0.0.255"], ["Primera usable", "10.0.0.1"], ["Última usable", "10.0.0.254"],
    ["Direcciones", "256"], ["Hosts usables", "254"], ["Prefijo", "/24"], ["Máscara", "255.255.255.0"], ["Wildcard", "0.0.0.255"]] }],
};

async function calcSubnet(res = subnet24) {
  const core = fakeCore({ calc: vi.fn(async () => res) });
  render(<CoreContext.Provider value={core}><CalcView core={core} /></CoreContext.Provider>);
  await userEvent.type(screen.getByLabelText(/^Prefijo/), "10.0.0.0/24");
  await userEvent.click(screen.getByRole("button", { name: "Calcular" }));
  return { core, table: await screen.findByRole("table", { name: "Subred 10.0.0.0/24" }) };
}

test("subred: la barra reparte red, usables y broadcast, y la leyenda lo dice en texto", async () => {
  await calcSubnet();
  const legend = screen.getByRole("list", { name: "Reparto de la subred 10.0.0.0/24" });
  expect(within(legend).getAllByRole("listitem").map((i) => i.textContent)).toEqual([
    "Red: 10.0.0.0 · 1 dirección (0.4 %)",
    "Usables: 10.0.0.1 – 10.0.0.254 · 254 direcciones (99.2 %)",
    "Broadcast: 10.0.0.255 · 1 dirección (0.4 %)",
  ]);
});

test("subred /31 sin broadcast: una sola franja de usables", async () => {
  await calcSubnet({ text: "", notes: [], tables: [{ title: "Subred 10.0.0.0/24", head: ["Campo", "Valor"], rows: [["Red", "10.0.0.0"], ["Primera usable", "10.0.0.0"], ["Última usable", "10.0.0.1"], ["Direcciones", "2"], ["Hosts usables", "2"]] }] });
  const items = within(screen.getByRole("list", { name: "Reparto de la subred 10.0.0.0/24" })).getAllByRole("listitem");
  expect(items.map((i) => i.textContent)).toEqual(["Usables: 10.0.0.0 – 10.0.0.1 · 2 direcciones (100 %)"]);
});

test("copiar: la máscara, el wildcard y las direcciones del resultado tienen su botón", async () => {
  const { core, table } = await calcSubnet();
  await userEvent.click(within(table).getByRole("button", { name: "Copiar Máscara" }));
  expect(core.copyText).toHaveBeenCalledWith("255.255.255.0");
  await userEvent.click(within(table).getByRole("button", { name: "Copiar Wildcard" }));
  expect(core.copyText).toHaveBeenLastCalledWith("0.0.0.255");
  expect(within(table).queryByRole("button", { name: "Copiar Hosts usables" })).not.toBeInTheDocument();
});

test("vlsm: franjas apiladas por subred con su proporción, y el espacio libre", async () => {
  const core = fakeCore({ calc: vi.fn(async () => ({ text: "", notes: ["Espacio libre: 10.0.0.96/27 10.0.0.128/25"], tables: [{ title: "VLSM sobre 10.0.0.0/24",
    head: ["Nombre", "Hosts", "Prefijo", "Máscara", "Primera", "Última", "Broadcast", "Capacidad", "Sobrante"],
    rows: [["ventas", "50", "10.0.0.0/26", "255.255.255.192", "10.0.0.1", "10.0.0.62", "10.0.0.63", "62", "12"], ["voz", "20", "10.0.0.64/27", "255.255.255.224", "10.0.0.65", "10.0.0.94", "10.0.0.95", "30", "10"]] }] })) });
  render(<CalcView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "VLSM" }));
  await userEvent.type(screen.getByLabelText("Red"), "10.0.0.0/24");
  await userEvent.type(screen.getByLabelText(/^Necesidades/), "ventas=50, voz=20");
  await userEvent.click(screen.getByRole("button", { name: "Repartir" }));
  const bar = await screen.findByRole("list", { name: "Reparto del bloque 10.0.0.0/24" });
  const segs = within(bar).getAllByRole("listitem");
  expect(segs).toHaveLength(4);
  expect(segs[0]).toHaveTextContent("ventas10.0.0.0/26 · 25 %");
  expect(segs[0]).toHaveStyle({ flexBasis: "25%" });
  expect(segs[1]).toHaveTextContent("voz10.0.0.64/27 · 12.5 %");
  expect(segs[2]).toHaveTextContent("Libre10.0.0.96/27 · 12.5 %");
  expect(segs[3]).toHaveTextContent("Libre10.0.0.128/25 · 50 %");
  expect(segs[3]).toHaveStyle({ flexBasis: "50%" });
  // La tabla del núcleo sigue siendo el equivalente en texto.
  expect(screen.getByRole("table", { name: "VLSM sobre 10.0.0.0/24" })).toBeInTheDocument();
});
