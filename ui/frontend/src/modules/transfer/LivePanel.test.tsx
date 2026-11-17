import { act, render, screen } from "@testing-library/react";
import { LivePanel } from "./LivePanel";
import { sampleRejections, sampleSessions } from "./fake";
import type { TransferRejection, TransferSession } from "./api";

type Fn = () => Promise<{ sessions: TransferSession[]; rejections: TransferRejection[] }>;
// Las pruebas viejas pasan solo la lista de sesiones; las nuevas pasan el objeto completo.
const wrap = (fn: () => Promise<TransferSession[]>): Fn => async () => ({ sessions: await fn(), rejections: [] });
const mount = (fn: () => Promise<TransferSession[]>, open = true) => render(<LivePanel serverId="s1" open={open} fetchSessions={wrap(fn)} />);
const mountFull = (fn: Fn) => render(<LivePanel serverId="s1" open fetchSessions={fn} />);
const tick = async (ms = 1000) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); };

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-11-16T12:00:00Z")); });
afterEach(() => vi.useRealTimers());

test("muestra transfiriendo, clientes, barra y recientes con la causa de la falla", async () => {
  mount(async () => sampleSessions(Date.now()));
  await tick();
  expect(screen.getByText("Transfiriendo")).toBeInTheDocument();
  expect(screen.getAllByText("192.0.2.21").length).toBeGreaterThan(0);
  expect(screen.getAllByText("[2001:db8::22]").length).toBeGreaterThan(0);
  expect(screen.queryByText(/50123/)).toBeNull();
  const bar = screen.getByRole("progressbar", { name: /c9300/ });
  expect(bar).toHaveAttribute("aria-valuenow", "35");
  expect(screen.getByText(/running-SW1\.cfg/)).toBeInTheDocument();
  expect(screen.getByText("Fallida")).toBeInTheDocument();
  expect(screen.getByText("tiempo agotado")).toBeInTheDocument();
});

test("sin sesiones activas dice En espera y total desconocido no lleva aria-valuenow", async () => {
  const s = sampleSessions(Date.now()).filter((x) => x.state !== "active");
  mount(async () => s);
  await tick();
  expect(screen.getByText("En espera")).toBeInTheDocument();
  expect(screen.getByRole("progressbar", { name: /backup\.cfg/ })).not.toHaveAttribute("aria-valuenow");
});

test("al cerrarse deja de encuestar pero conserva la última lectura", async () => {
  const fn = vi.fn(async () => ({ sessions: sampleSessions(Date.now()).slice(1, 2), rejections: sampleRejections(Date.now()) }));
  const { rerender } = mountFull(fn);
  await tick();
  const n = fn.mock.calls.length;
  rerender(<LivePanel serverId="s1" open={false} fetchSessions={fn} />);
  await tick(2000);
  expect(fn).toHaveBeenCalledTimes(n);
  expect(screen.getByText(/running-SW1\.cfg/)).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Rechazos" })).toBeInTheDocument();
});

test("encuesta cada segundo, no con la pestaña oculta ni cerrado, y limpia al desmontar", async () => {
  const fn = vi.fn(async () => []);
  const { unmount } = mount(fn);
  await tick(3000);
  expect(fn).toHaveBeenCalledTimes(4);
  const hidden = vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
  await tick(2000);
  expect(fn).toHaveBeenCalledTimes(4);
  hidden.mockRestore();
  unmount();
  await tick(2000);
  expect(fn).toHaveBeenCalledTimes(4);
});

test("si la llamada falla el panel no se muestra", async () => {
  const { container } = mount(async () => { throw new Error("unimplemented"); });
  await tick();
  expect(container).toBeEmptyDOMElement();
});

test("la región en vivo solo anuncia cambios de estado", async () => {
  let list = sampleSessions(Date.now());
  mount(async () => list);
  await tick();
  const live = screen.getByRole("status");
  const first = live.textContent;
  await tick(); // mismo estado, otro tick
  expect(live.textContent).toBe(first);
  list = list.map((x) => (x.id === "t1" ? { ...x, state: "done" as const, ended: Date.now() } : x));
  await tick();
  expect(live.textContent).toMatch(/c9300.*Completa/);
});

test("en pantalla se muestran a lo más 20 recientes", async () => {
  const base = sampleSessions(Date.now())[1];
  const many = Array.from({ length: 25 }, (_, i) => ({ ...base, id: `d${i}`, name: `f${i}.cfg`, ended: Date.now() - i }));
  mount(async () => many);
  await tick();
  expect(screen.getAllByRole("progressbar")).toHaveLength(20);
});

test("la causa de una fallida es el error ya traducido; sin él, causa desconocida", async () => {
  const f = { ...sampleSessions(Date.now())[2], errorCode: "fileserve.reason.no_reply", error: "el equipo no respondió" };
  mount(async () => [f, { ...f, id: "x", name: "otro.cfg", error: "" }]);
  await tick();
  expect(screen.getByText("el equipo no respondió")).toBeInTheDocument();
  expect(screen.getByText("Causa desconocida")).toBeInTheDocument();
});

test("un estado desconocido se trata como fallida, sin clave cruda", async () => {
  const f = { ...sampleSessions(Date.now())[2], state: "raro" as never };
  mount(async () => [f]);
  await tick();
  expect(screen.getByText("Fallida")).toBeInTheDocument();
  expect(screen.queryByText(/transfer\.live/)).toBeNull();
});

test("no lanza otra llamada mientras la anterior sigue pendiente", async () => {
  let release = () => {};
  const fn = vi.fn(() => new Promise<TransferSession[]>((r) => { release = () => r([]); }));
  mount(fn);
  await tick(3000);
  expect(fn).toHaveBeenCalledTimes(1);
  await act(async () => { release(); });
  await tick();
  expect(fn).toHaveBeenCalledTimes(2);
});

test("con Unimplemented deja de encuestar", async () => {
  const fn = vi.fn(async () => { throw Object.assign(new Error("rpc error: code = Unimplemented desc = unknown method"), { cause: { code: "Unimplemented" } }); });
  mount(fn);
  await tick(5000);
  expect(fn).toHaveBeenCalledTimes(1);
});

test("la causa de una fallida no es una alerta, la barra no pasa de 100 y un cliente raro no rompe la lista", async () => {
  const base = sampleSessions(Date.now());
  const act0 = base.find((s) => s.state === "active")!;
  mount(async () => [...base, { ...act0, id: "x", name: "grande.bin", bytes: 300, total: 100, client: "[2001:db8::9" }, { ...act0, id: "y", name: "vacio.bin", client: "" }]);
  await tick();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.getByRole("progressbar", { name: /grande\.bin/ })).toHaveAttribute("aria-valuenow", "100");
  expect(screen.getAllByText(/\[2001:db8::9/).length).toBeGreaterThan(0);
  const line = screen.getByText((_, el) => el?.tagName === "P" && /^Clientes/.test(el.textContent ?? "")).textContent ?? "";
  expect(line).toContain("192.0.2.21");
  expect(line).not.toMatch(/, ,|, $|: ,/); // el cliente vacío no deja un hueco
});

test("los rechazos se muestran agrupados con causa traducida, nombre, conteo y sin alerta", async () => {
  mountFull(async () => ({ sessions: [], rejections: sampleRejections(Date.now()) }));
  await tick();
  expect(screen.getByRole("heading", { name: "Rechazos" })).toBeInTheDocument();
  expect(screen.getByText("192.0.2.50")).toBeInTheDocument();
  expect(screen.getByText("r2-confg")).toBeInTheDocument();
  expect(screen.getByText("×4")).toBeInTheDocument();
  expect(screen.getByText(/Archivo no publicado o inexistente/)).toBeInTheDocument();
  expect(screen.getByText(/Origen fuera de los permitidos/)).toBeInTheDocument();
  expect(screen.queryByRole("alert")).toBeNull();
});

test("TFTP muestra la IP como «llegó desde» con la nota de origen no verificado; otros protocolos no", async () => {
  mountFull(async () => ({ sessions: [], rejections: sampleRejections(Date.now()) }));
  await tick();
  expect(screen.getAllByText(/llegó desde/)).toHaveLength(1);
  expect(screen.getByText(/puede estar falsificado/)).toBeInTheDocument();
});

test("causa other o desconocida muestra el reason del núcleo", async () => {
  const [a] = sampleRejections(Date.now());
  mountFull(async () => ({ sessions: [], rejections: [{ ...a, cause: "other", reason: "motivo del núcleo" }, { ...a, ip: "192.0.2.51", cause: "nueva", reason: "causa nueva" }] }));
  await tick();
  expect(screen.getByText(/motivo del núcleo/)).toBeInTheDocument();
  expect(screen.getByText(/causa nueva/)).toBeInTheDocument();
});

test("sin rechazos no hay sección; solo un grupo nuevo se anuncia, no cada rechazo", async () => {
  let rej: TransferRejection[] = [];
  mountFull(async () => ({ sessions: [], rejections: rej }));
  await tick();
  expect(screen.queryByRole("heading", { name: "Rechazos" })).toBeNull();
  const live = screen.getByRole("status");
  rej = sampleRejections(Date.now());
  await tick();
  expect(live.textContent).toBe("Rechazos nuevos: 2");
  rej = rej.map((r) => ({ ...r, count: r.count + 50 })); // flood: sube el total, mismo grupo
  await tick();
  expect(live.textContent).toBe("Rechazos nuevos: 2");
  rej = [...rej, { ...rej[0], ip: "192.0.2.99" }];
  await tick();
  expect(live.textContent).toBe("Rechazos nuevos: 1");
});

test("estados y rechazos nuevos en la misma lectura se anuncian juntos", async () => {
  let d = { sessions: sampleSessions(Date.now()), rejections: [] as TransferRejection[] };
  mountFull(async () => d);
  await tick();
  d = { sessions: d.sessions.map((x) => (x.id === "t1" ? { ...x, state: "done" as const, ended: Date.now() } : x)), rejections: sampleRejections(Date.now()) };
  await tick();
  expect(screen.getByRole("status").textContent).toMatch(/c9300.*Completa\. Rechazos nuevos: 2/);
});

test("causa fuera del conjunto conocido muestra reason, aunque exista una clave parecida", async () => {
  const [a] = sampleRejections(Date.now());
  mountFull(async () => ({ sessions: [], rejections: [{ ...a, cause: "tftpNote", reason: "motivo crudo" }] }));
  await tick();
  expect(screen.getByText(/motivo crudo/)).toBeInTheDocument();
});

test("con NotFound deja de encuestar", async () => {
  const fn = vi.fn(async () => { throw new Error("rpc error: code = NotFound desc = no such server"); });
  mountFull(fn);
  await tick(5000);
  expect(fn).toHaveBeenCalledTimes(1);
});

test("la sección lleva un nombre único por servidor y la hora sale en el idioma de la app", async () => {
  render(<LivePanel serverId="s1" open label="TFTP 10.0.0.5:69" fetchSessions={async () => ({ sessions: [], rejections: sampleRejections(Date.now()) })} />);
  await tick();
  expect(screen.getByRole("region", { name: "En vivo · TFTP 10.0.0.5:69" })).toBeInTheDocument();
  const spy = vi.spyOn(Date.prototype, "toLocaleTimeString");
  await tick();
  expect(spy).toHaveBeenCalledWith("es");
  spy.mockRestore();
});
