import { act, render, screen } from "@testing-library/react";
import { LivePanel } from "./LivePanel";
import { sampleSessions } from "./fake";
import type { TransferSession } from "./api";

const mount = (fn: () => Promise<TransferSession[]>, open = true) =>
  render(<LivePanel serverId="s1" open={open} fetchSessions={fn} />);
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

test("errorCode con clave i18n se localiza; sin clave se muestra error", async () => {
  const f = { ...sampleSessions(Date.now())[2], errorCode: "timeout" };
  mount(async () => [f, { ...f, id: "x", name: "otro.cfg", errorCode: "inexistente", error: "causa cruda" }]);
  await tick();
  expect(screen.getByText("Se agotó el tiempo de espera")).toBeInTheDocument();
  expect(screen.getByText("causa cruda")).toBeInTheDocument();
});
